//! Debian binary packages (`.deb`, `.udeb`): an `ar` archive holding
//! `debian-binary`, `control.tar[.gz|.xz|.zst|.bz2]` and `data.tar[…]`.
//! The control file gives name, version, architecture, maintainer,
//! installed size, section, priority, homepage, description and the
//! relationships (depends, pre-depends, recommends, suggests, conflicts,
//! breaks, provides, replaces); maintainer scripts (`preinst`, `postinst`,
//! `prerm`, `postrm`, `config`) are install-time scripts; `md5sums` and
//! `conffiles` are counted. The data archive is listed as the payload and
//! its `usr/share/doc/<package>/copyright` gives the licence (machine-
//! readable DEP-5, else the licence text). `_gpg*` members are signatures
//! (`debsigs` / `dpkg-sig`).
//!
//! Specifications: `deb(5)`, `deb-control(5)`, Debian Policy §5 and §7,
//! DEP-5 (machine-readable copyright format 1.0).

use super::{Package, Tarball, bare, field, fields, person, text, unwrap};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, identify_license,
};

/// Extractor for Debian packages.
pub struct Deb;

static META: ExtractorMeta = ExtractorMeta {
    id: "package.deb",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "deb",
            name: "Debian package",
            family: "package",
            mimes: &["application/vnd.debian.binary-package"],
            extensions: &["deb"],
            magic: &[Magic::prefix(b"!<arch>\ndebian-binary")],
            parent: None,
        },
        FormatSpec {
            id: "udeb",
            name: "Debian installer package",
            family: "package",
            mimes: &["application/vnd.debian.binary-package"],
            extensions: &["udeb"],
            magic: &[Magic::prefix(b"!<arch>\ndebian-binary")],
            parent: None,
        },
    ],
};

/// Members read at most (a package has three or four).
const MAX_MEMBERS: usize = 64;
/// Maintainer scripts run by dpkg.
const SCRIPTS: [&str; 5] = ["preinst", "postinst", "prerm", "postrm", "config"];
/// Relationship fields, in report order.
const RELATIONS: [(&str, &str); 7] = [
    ("Pre-Depends", "pre_depends"),
    ("Recommends", "recommends"),
    ("Suggests", "suggests"),
    ("Enhances", "enhances"),
    ("Breaks", "breaks"),
    ("Conflicts", "conflicts"),
    ("Replaces", "replaces"),
];

/// One `ar` member: name, data offset, size.
struct Member {
    name: String,
    at: u64,
    size: u64,
}

fn members(src: &mut dyn Source) -> Result<Vec<Member>, ExtractError> {
    let len = src.len();
    let mut out = Vec::new();
    let mut at = 8u64;
    while out.len() < MAX_MEMBERS && at + 60 <= len {
        let h = src.read_vec(at, 60)?;
        if &h[58..60] != b"`\n" {
            break;
        }
        let name = String::from_utf8_lossy(&h[..16]).trim_end().trim_end_matches('/').to_string();
        let size: u64 = std::str::from_utf8(&h[48..58])
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| ExtractError::malformed("ar member size"))?;
        out.push(Member { name, at: at + 60, size });
        at = (at + 60).saturating_add(size).saturating_add(size % 2);
    }
    Ok(out)
}

/// `"libc6 (>= 2.34), foo | bar"` → `[("libc6", ">= 2.34"), ("foo | bar", "*")]`.
fn relations(v: &str) -> Vec<(String, String)> {
    v.split(',')
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(|d| {
            if d.contains('|') {
                return (d.split_whitespace().collect::<Vec<_>>().join(" "), "*".to_string());
            }
            let name = d.split(['(', '[', '<']).next().unwrap_or(d).trim();
            let constraint = d.split_once('(').and_then(|(_, r)| r.split_once(')')).map_or("*", |(c, _)| c.trim());
            (name.to_string(), constraint.to_string())
        })
        .collect()
}

/// The licence a `copyright` file states: the `License:` of the DEP-5
/// paragraph for `Files: *`, else the first one, else the text's licence.
fn copyright_license(t: &str) -> Option<String> {
    if t.starts_with("Format:") {
        let mut first: Option<String> = None;
        let mut rest = t;
        for _ in 0..256 {
            let (f, after) = fields(rest, "\n");
            if f.is_empty() {
                break;
            }
            if let Some(l) = field(&f, "License") {
                let l = l.lines().next().unwrap_or(l).trim().to_string();
                if field(&f, "Files").is_some_and(|files| files.split_whitespace().any(|x| x == "*")) {
                    return Some(l);
                }
                first.get_or_insert(l);
            }
            rest = after;
        }
        if first.is_some() {
            return first;
        }
    }
    identify_license(t).map(str::to_string)
}

impl Extractor for Deb {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        probe
            .head
            .get(8..21)
            .filter(|m| *m == b"debian-binary")
            .map(|_| Sniff { format: if probe.extension == Some("udeb") { "udeb" } else { "deb" }, confidence: 0.97 })
    }

    #[allow(clippy::too_many_lines)] // members, control, scripts, payload
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let members = members(src)?;
        let mut pkg = Package::new("debian");
        let mut control_text: Option<String> = None;
        let mut data: Option<&Member> = None;
        let mut signatures = Vec::new();
        for m in &members {
            match m.name.as_str() {
                "debian-binary" => {
                    let v = src.read_vec(m.at, usize::try_from(m.size.min(16)).unwrap_or(0))?;
                    pkg.set("format_version", text(&v).trim());
                }
                n if n.starts_with("control.tar") => {
                    pkg.set("control_archive", n);
                    let raw = src.read_vec(m.at, usize::try_from(m.size.min(64 << 20)).unwrap_or(0))?;
                    let (tar, _, _) = unwrap(cx, raw)?;
                    let control = Tarball::read(cx, n, tar, |p| {
                        let p = bare(p);
                        p == "control" || p == "md5sums" || p == "conffiles" || SCRIPTS.contains(&p)
                    })?;
                    for (path, body) in &control.files {
                        let p = bare(path);
                        match p {
                            "control" => control_text = Some(text(body)),
                            "md5sums" => {
                                pkg.set("listed_files", text(body).lines().filter(|l| !l.is_empty()).count());
                            }
                            "conffiles" => {
                                pkg.set("conffiles", text(body).lines().filter(|l| !l.is_empty()).count());
                            }
                            s if !body.trim_ascii().is_empty() => pkg.scripts.push(s.to_string()),
                            _ => {}
                        }
                    }
                }
                n if n.starts_with("data.tar") => {
                    pkg.set("data_archive", n);
                    data = Some(m);
                }
                n if n.starts_with("_gpg") => signatures.push(n.to_string()),
                _ => {}
            }
        }
        let control = control_text.ok_or_else(|| ExtractError::malformed("no control file"))?;
        let (f, _) = fields(&control, "\n");
        pkg.name = field(&f, "Package").map(str::to_string);
        pkg.version = field(&f, "Version").map(str::to_string);
        pkg.architecture = field(&f, "Architecture").map(str::to_string);
        pkg.homepage = field(&f, "Homepage").map(str::to_string);
        if let Some(d) = field(&f, "Description") {
            let (summary, long) = d.split_once('\n').unwrap_or((d, ""));
            pkg.summary = Some(summary.trim().to_string());
            pkg.description = Some(long.trim().to_string()).filter(|l| !l.is_empty());
        }
        pkg.authors.extend(field(&f, "Maintainer").and_then(person));
        for (name, constraint) in field(&f, "Depends").map(relations).unwrap_or_default() {
            pkg.depend(&name, &constraint);
        }
        pkg.signed = Some(!signatures.is_empty());
        if !signatures.is_empty() {
            pkg.signatures = signatures;
        }
        for (key, out) in [("Source", "source"), ("Section", "section"), ("Priority", "priority")] {
            if let Some(v) = field(&f, key) {
                pkg.set(out, v);
            }
        }
        if let Some(kib) = field(&f, "Installed-Size").and_then(|v| v.parse::<u64>().ok()) {
            pkg.set("installed_size_bytes", kib * 1024);
        }
        for (key, out) in [("Essential", "essential"), ("Multi-Arch", "multi_arch")] {
            if let Some(v) = field(&f, key) {
                pkg.set(out, v);
            }
        }
        for (key, out) in RELATIONS {
            if let Some(v) = field(&f, key) {
                let names: Vec<String> = relations(v).into_iter().map(|(n, _)| n).collect();
                pkg.set(out, names);
            }
        }
        if let Some(p) = field(&f, "Provides") {
            let names: Vec<String> = relations(p).into_iter().map(|(n, _)| n).collect();
            pkg.set("provides", names);
        }
        let Some(data) = data else {
            pkg.write(cx);
            return Ok(());
        };
        // The payload: listed, its copyright file read for the licence.
        let raw = src.read_vec(data.at, usize::try_from(data.size.min(cx.parse_limit() as u64)).unwrap_or(0))?;
        let (tar, codec, cut) = unwrap(cx, raw)?;
        if cut {
            pkg.set("payload_truncated", true);
        }
        if let Some(c) = codec {
            pkg.set("payload_compression", c);
        }
        let doc = pkg.name.as_ref().map(|n| format!("usr/share/doc/{n}/copyright"));
        let payload = Tarball::read(cx, "data.tar", tar, |p| doc.as_deref() == Some(bare(p)))?;
        if let Some(t) = payload.files.first().map(|(_, d)| text(d)) {
            pkg.license = copyright_license(&t);
        }
        pkg.write(cx);
        payload.finish(cx, src.len())
    }
}

crate::register_extractor!(Deb);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_lists() {
        let r = relations("libc6 (>= 2.34), python3:any, foo | bar (<< 2), baz [amd64]");
        assert_eq!(r[0], ("libc6".into(), ">= 2.34".into()));
        assert_eq!(r[1], ("python3:any".into(), "*".into()));
        assert_eq!(r[2].0, "foo | bar (<< 2)");
        assert_eq!(r[3], ("baz".into(), "*".into()));
    }

    #[test]
    fn dep5() {
        let t = "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\nFiles: debian/*\nLicense: GPL-2+\n\nFiles: *\nCopyright: 2025 Saltmere\nLicense: MIT\n Permission is hereby granted\n";
        assert_eq!(copyright_license(t).as_deref(), Some("MIT"));
    }

    crate::fixture_tests!("deb", "udeb");
}
