//! RPM packages (binary and source): the lead, the signature header
//! (OpenPGP signatures, digests, sizes) and the main header — name,
//! epoch, version, release, architecture, summary, description, licence,
//! vendor, packager, group, URL, build time and host, source package,
//! installed size, requires / provides / conflicts / obsoletes /
//! recommends / suggests, scriptlets (`%pre`, `%post`, `%preun`,
//! `%postun`, `%pretrans`, `%posttrans`, triggers) and the payload's
//! format and compressor. The file list comes from the header (names,
//! sizes, modes, times, link targets); the cpio payload is decompressed to
//! hand its files on.
//!
//! Specification: the RPM file format (rpm.org, "RPM v4 package format";
//! `rpmtag.h` for tag numbers).

use super::archive::{Entry, Inventory, Kind, cpio, stored_children, unix_time};
use super::{Package, unwrap};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, latin1_or_utf8,
};

/// Extractor for RPM packages.
pub struct Rpm;

static META: ExtractorMeta = ExtractorMeta {
    id: "package.rpm",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "rpm",
        name: "RPM package",
        family: "package",
        mimes: &["application/x-rpm"],
        extensions: &["rpm", "srpm"],
        magic: &[Magic::prefix(b"\xed\xab\xee\xdb")],
        parent: None,
    }],
};

/// Index entries read per header at most.
const MAX_INDEX: usize = 1 << 16;
/// Largest header store read.
const MAX_STORE: u64 = 64 << 20;

/// A header value.
#[derive(Debug, Clone)]
enum Val {
    Ints(Vec<u64>),
    Strs(Vec<String>),
    Bin(usize),
}

/// A parsed header: `(tag, value)` in index order.
#[derive(Debug, Default)]
struct Header {
    tags: Vec<(u32, Val)>,
}

impl Header {
    fn get(&self, tag: u32) -> Option<&Val> {
        self.tags.iter().find(|(t, _)| *t == tag).map(|(_, v)| v)
    }

    fn has(&self, tag: u32) -> bool {
        self.get(tag).is_some()
    }

    fn str(&self, tag: u32) -> Option<&str> {
        match self.get(tag)? {
            Val::Strs(s) => s.first().map(String::as_str).filter(|s| !s.is_empty()),
            _ => None,
        }
    }

    fn strs(&self, tag: u32) -> &[String] {
        match self.get(tag) {
            Some(Val::Strs(s)) => s,
            _ => &[],
        }
    }

    fn ints(&self, tag: u32) -> &[u64] {
        match self.get(tag) {
            Some(Val::Ints(v)) => v,
            _ => &[],
        }
    }

    fn int(&self, tag: u32) -> Option<u64> {
        self.ints(tag).first().copied()
    }
}

/// Read the header structure at `at`; returns it and the offset after it.
fn header(src: &mut dyn Source, at: u64) -> Result<(Header, u64), ExtractError> {
    let h = src.read_vec(at, 16)?;
    if h.len() < 16 || h[..3] != [0x8e, 0xad, 0xe8] {
        return Err(ExtractError::malformed(format!("no header structure at offset {at}")));
    }
    let be = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let count = be(&h[8..12]) as usize;
    let size = u64::from(be(&h[12..16]));
    if count > MAX_INDEX || size > MAX_STORE {
        return Err(ExtractError::malformed("header too large"));
    }
    let index = src.read_vec(at + 16, count * 16)?;
    let store = src.read_vec(at + 16 + count as u64 * 16, usize::try_from(size).unwrap_or(0))?;
    let mut out = Header::default();
    for e in index.as_chunks::<16>().0 {
        let (tag, ty, off, n) = (be(&e[0..4]), be(&e[4..8]), be(&e[8..12]) as usize, be(&e[12..16]) as usize);
        let Some(data) = store.get(off..) else { continue };
        let n = n.min(1 << 20);
        let val = match ty {
            2..=5 => {
                let w = [1usize, 2, 4, 8][ty as usize - 2];
                let ints =
                    data.chunks_exact(w).take(n).map(|c| c.iter().fold(0u64, |a, &b| a << 8 | u64::from(b))).collect();
                Val::Ints(ints)
            }
            6 | 8 | 9 => {
                let take = if ty == 6 { 1 } else { n };
                let strs = data.split(|&b| b == 0).take(take).map(latin1_or_utf8).collect();
                Val::Strs(strs)
            }
            7 => Val::Bin(n),
            _ => continue,
        };
        out.tags.push((tag, val));
    }
    Ok((out, at + 16 + count as u64 * 16 + size))
}

// Main header tags (rpmtag.h).
const NAME: u32 = 1000;
const VERSION: u32 = 1001;
const RELEASE: u32 = 1002;
const EPOCH: u32 = 1003;
const SUMMARY: u32 = 1004;
const DESCRIPTION: u32 = 1005;
const BUILDTIME: u32 = 1006;
const BUILDHOST: u32 = 1007;
const SIZE: u32 = 1009;
const DISTRIBUTION: u32 = 1010;
const VENDOR: u32 = 1011;
const LICENSE: u32 = 1014;
const PACKAGER: u32 = 1015;
const GROUP: u32 = 1016;
const URL: u32 = 1020;
const OS: u32 = 1021;
const ARCH: u32 = 1022;
const FILESIZES: u32 = 1028;
const FILEMODES: u32 = 1030;
const FILEMTIMES: u32 = 1034;
const FILELINKTOS: u32 = 1036;
const SOURCERPM: u32 = 1044;
const PROVIDENAME: u32 = 1047;
const REQUIREFLAGS: u32 = 1048;
const REQUIRENAME: u32 = 1049;
const REQUIREVERSION: u32 = 1050;
const CONFLICTNAME: u32 = 1054;
const OBSOLETENAME: u32 = 1090;
const SOURCEPACKAGE: u32 = 1106;
const OLDFILENAMES: u32 = 1027;
const DIRINDEXES: u32 = 1116;
const BASENAMES: u32 = 1117;
const DIRNAMES: u32 = 1118;
const PAYLOADFORMAT: u32 = 1124;
const PAYLOADCOMPRESSOR: u32 = 1125;
const LONGFILESIZES: u32 = 5008;
const LONGSIZE: u32 = 5009;
const RECOMMENDNAME: u32 = 5046;
const SUGGESTNAME: u32 = 5049;
/// Scriptlets, by tag.
const SCRIPTS: [(u32, &str); 7] = [
    (1151, "pretrans"),
    (1023, "pre"),
    (1024, "post"),
    (1025, "preun"),
    (1026, "postun"),
    (1152, "posttrans"),
    (1065, "triggers"),
];
// Signature header tags.
const SIG_DSA: u32 = 267;
const SIG_RSA: u32 = 268;
const SIG_SHA1: u32 = 269;
const SIG_SHA256: u32 = 273;
const SIG_PGP: u32 = 1002;
const SIG_MD5: u32 = 1004;
const SIG_GPG: u32 = 1005;
const SIG_FILESIGNATURES: u32 = 274;

/// `">= 1.2"` from RPMSENSE flags and a version.
fn constraint(flags: u64, version: &str) -> String {
    if version.is_empty() {
        return "*".into();
    }
    let op = match flags & 0xe {
        2 => "<",
        4 => ">",
        8 => "=",
        10 => "<=",
        12 => ">=",
        _ => "",
    };
    if op.is_empty() { version.to_string() } else { format!("{op} {version}") }
}

/// The file list the header carries.
fn file_entries(h: &Header) -> Vec<Entry> {
    let names: Vec<String> = if h.has(BASENAMES) {
        let dirs = h.strs(DIRNAMES);
        let idx = h.ints(DIRINDEXES);
        h.strs(BASENAMES)
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let d = idx.get(i).and_then(|&j| dirs.get(usize::try_from(j).ok()?)).map_or("", String::as_str);
                format!("{d}{b}")
            })
            .collect()
    } else {
        h.strs(OLDFILENAMES).to_vec()
    };
    let sizes = if h.has(LONGFILESIZES) { h.ints(LONGFILESIZES) } else { h.ints(FILESIZES) };
    let (modes, times, links) = (h.ints(FILEMODES), h.ints(FILEMTIMES), h.strs(FILELINKTOS));
    names
        .into_iter()
        .enumerate()
        .map(|(i, path)| {
            let mode = modes.get(i).map(|&m| (m & 0xffff) as u32);
            let kind = mode.map_or(Kind::File, Kind::from_mode);
            let size = if kind == Kind::File { sizes.get(i).copied() } else { Some(0) };
            Entry {
                // Packages install under `/`: relative to it, as the payload stores them.
                path: path.trim_start_matches('/').to_string(),
                kind,
                size,
                compressed: None,
                modified: times.get(i).and_then(|&t| unix_time(i64::try_from(t).ok()?)),
                mode: mode.map(|m| m & 0o7777),
                link: links.get(i).filter(|l| !l.is_empty() && kind == Kind::Symlink).cloned(),
                ..Entry::default()
            }
        })
        .collect()
}

impl Extractor for Rpm {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // lead, two headers, payload
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let lead = src.read_vec(0, 96)?;
        if lead.len() < 96 {
            return Err(ExtractError::malformed("short lead"));
        }
        let (sig, end) = header(src, 96)?;
        let (h, payload_at) = header(src, end.div_ceil(8) * 8)?;
        let source = lead[6..8] == [0, 1] || (!h.has(SOURCERPM) && h.has(SOURCEPACKAGE));
        let mut pkg = Package::new("rpm");
        pkg.name = h.str(NAME).map(str::to_string);
        pkg.version = h.str(VERSION).map(|v| match h.int(EPOCH) {
            Some(e) => format!("{e}:{v}"),
            None => v.to_string(),
        });
        pkg.release = h.str(RELEASE).map(str::to_string);
        pkg.architecture = if source { Some("src".into()) } else { h.str(ARCH).map(str::to_string) };
        pkg.summary = h.str(SUMMARY).map(str::to_string);
        pkg.description = h.str(DESCRIPTION).map(str::to_string);
        pkg.license = h.str(LICENSE).map(str::to_string);
        pkg.homepage = h.str(URL).map(str::to_string);
        pkg.authors.extend(h.str(PACKAGER).and_then(super::person));
        let (names, flags, versions) = (h.strs(REQUIRENAME), h.ints(REQUIREFLAGS), h.strs(REQUIREVERSION));
        for (i, n) in names.iter().enumerate() {
            // `rpmlib(…)` features describe rpm itself, not the package.
            if n.starts_with("rpmlib(") {
                continue;
            }
            let v = versions.get(i).map_or("", String::as_str);
            pkg.depend(n, &constraint(flags.get(i).copied().unwrap_or(0), v));
        }
        for (tag, name) in SCRIPTS {
            if h.has(tag) {
                pkg.scripts.push(name.to_string());
            }
        }
        let mut sigs = Vec::new();
        for (tag, name) in [(SIG_RSA, "rsa"), (SIG_DSA, "dsa"), (SIG_PGP, "pgp"), (SIG_GPG, "gpg")] {
            if sig.has(tag) {
                sigs.push(name.to_string());
            }
        }
        pkg.signed = Some(!sigs.is_empty());
        pkg.signatures = sigs;
        let digests: Vec<&str> = [(SIG_SHA256, "sha256"), (SIG_SHA1, "sha1"), (SIG_MD5, "md5")]
            .into_iter()
            .filter(|(t, _)| sig.has(*t))
            .map(|(_, n)| n)
            .collect();
        if !digests.is_empty() {
            pkg.set("digests", digests);
        }
        if sig.has(SIG_FILESIGNATURES) {
            pkg.set("file_signatures", true);
        }
        pkg.set("source_package", source);
        pkg.set("lead_version", format!("{}.{}", lead[4], lead[5]));
        for (tag, key) in [
            (VENDOR, "vendor"),
            (DISTRIBUTION, "distribution"),
            (GROUP, "group"),
            (OS, "os"),
            (SOURCERPM, "source_rpm"),
            (BUILDHOST, "build_host"),
        ] {
            if let Some(v) = h.str(tag) {
                pkg.set(key, v);
            }
        }
        if let Some(n) = h.int(LONGSIZE).or_else(|| h.int(SIZE)) {
            pkg.set("installed_size_bytes", n);
        }
        for (tag, key) in [
            (PROVIDENAME, "provides"),
            (CONFLICTNAME, "conflicts"),
            (OBSOLETENAME, "obsoletes"),
            (RECOMMENDNAME, "recommends"),
            (SUGGESTNAME, "suggests"),
        ] {
            let v = h.strs(tag);
            if !v.is_empty() {
                pkg.set(key, v.iter().take(200).cloned().collect::<Vec<_>>());
            }
        }
        let format = h.str(PAYLOADFORMAT).unwrap_or("cpio").to_string();
        pkg.set("payload_format", format.clone());
        if let Some(c) = h.str(PAYLOADCOMPRESSOR) {
            pkg.set("payload_compressor", c);
        }
        if let Some(Val::Bin(n)) = sig.get(SIG_RSA).or_else(|| sig.get(SIG_PGP)) {
            pkg.set("signature_bytes", *n as u64);
        }
        if let Some(t) = h.int(BUILDTIME).and_then(|t| unix_time(i64::try_from(t).ok()?)) {
            pkg.set("build_time", t.clone());
            cx.temporal().content_date(DateField::Created, t, true);
        }
        pkg.write(cx);

        let mut inv = Inventory::new();
        for e in file_entries(&h) {
            inv.push(e);
        }
        inv.report(cx, src.len());
        // The payload: decompressed only to hand its files on.
        if cx.child_room() == 0 || format != "cpio" || payload_at >= src.len() {
            return Ok(());
        }
        let n = (src.len() - payload_at).min(cx.parse_limit() as u64);
        let raw = src.read_vec(payload_at, usize::try_from(n).unwrap_or(0))?;
        let (cpio_data, _, _) = unwrap(cx, raw)?;
        let mut payload = cx.memory_source("payload.cpio", cpio_data);
        let Ok((_, pending)) = cpio::list(&mut payload, cx) else { return Ok(()) };
        stored_children(&mut payload, cx, pending)
    }
}

crate::register_extractor!(Rpm);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constraints() {
        assert_eq!(constraint(12, "2.0"), ">= 2.0");
        assert_eq!(constraint(8, "1.2-3"), "= 1.2-3");
        assert_eq!(constraint(0, ""), "*");
        assert_eq!(constraint(0x4000, "1"), "1");
    }

    crate::fixture_tests!("rpm");
}
