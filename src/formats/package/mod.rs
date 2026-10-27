//! `package` extractors (feature `common`): software packages and
//! installers. Each reads the package's own metadata (control file, spec
//! header, manifest, core metadata …) into the same [`Package`] facts —
//! ecosystem, name, version, release, architecture, summary, description,
//! licence, authors or maintainer, homepage, dependencies, install-time
//! scripts, signatures — plus what is particular to the format (Android
//! permissions, the iOS bundle id, MSI product codes …), and lists the
//! payload with the archive [`Inventory`](super::archive::Inventory), so
//! the archive risk signals (paths that leave the target folder, links
//! out, bombs) apply to packages too. Payload files are handed on as
//! children within the limits, as for archives.

pub(crate) mod android;
pub(crate) mod apple;
pub(crate) mod asar;
pub(crate) mod deb;
pub(crate) mod dmg;
pub(crate) mod java;
pub(crate) mod linux;
pub(crate) mod msi;
pub(crate) mod rpm;
pub(crate) mod tarball;
pub(crate) mod xar;
pub(crate) mod zipped;

use serde_json::{Map, Value, json};

// Readers shared with the archive, code, data and document extractors.
use super::archive::{self, Inventory};
use super::code::manifest;
use super::data::{known, yaml};
use super::doc::xml::{self, Ev, Flow, Tag, walk};
use crate::plugin::{Codec, Context, End, ExtractError, Source, TextRole, Zip, truncate_chars};

/// Dependencies listed per package.
const MAX_DEPS: usize = 200;
/// Metadata files read at most (control files, manifests …).
const MAX_META: usize = 4 << 20;

/// The facts every package format reports.
#[derive(Debug, Default)]
pub(crate) struct Package {
    pub ecosystem: &'static str,
    pub name: Option<String>,
    pub version: Option<String>,
    /// Packaging release (RPM release, Debian revision kept in `version`).
    pub release: Option<String>,
    pub architecture: Option<String>,
    /// One-line summary.
    pub summary: Option<String>,
    /// Longer description.
    pub description: Option<String>,
    pub license: Option<String>,
    /// Authors, maintainer or vendor.
    pub authors: Vec<String>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    /// `(name, constraint)`; `*` for none.
    pub dependencies: Vec<(String, String)>,
    /// Scripts that run when the package is installed or removed.
    pub scripts: Vec<String>,
    /// Whether the package carries a signature (`None`: not known).
    pub signed: Option<bool>,
    /// Signature kinds found (`v2`, `gpg`, `pkcs7` …).
    pub signatures: Vec<String>,
    /// Format-specific facts, written after the common ones.
    pub extra: Map<String, Value>,
}

impl Package {
    pub fn new(ecosystem: &'static str) -> Self {
        Self { ecosystem, ..Self::default() }
    }

    /// Set a format-specific fact.
    pub fn set(&mut self, key: &str, value: impl Into<Value>) {
        self.extra.insert(key.to_string(), value.into());
    }

    /// Add a dependency, ignoring blanks.
    pub fn depend(&mut self, name: &str, constraint: &str) {
        let name = name.trim();
        if !name.is_empty() {
            let c = constraint.trim();
            self.dependencies.push((name.to_string(), if c.is_empty() { "*".into() } else { c.to_string() }));
        }
    }

    /// Write the package facts into the report.
    pub fn write(&self, cx: &mut Context<'_>) {
        let source = format!("{}.metadata", self.ecosystem);
        if let Some(n) = &self.name {
            let title = match &self.version {
                Some(v) => format!("{n} {v}"),
                None => n.clone(),
            };
            cx.content().source(source.clone()).title(title.clone());
            cx.emit_text(TextRole::Title, &title);
        }
        let about = self.summary.as_deref().or(self.description.as_deref());
        if let Some(d) = about {
            cx.content().source(source.clone()).description(truncate_chars(d, 1000));
        }
        for text in [&self.summary, &self.description].into_iter().flatten() {
            cx.emit_text(TextRole::Body, text);
        }
        if let Some(l) = &self.license {
            cx.rights().source(source.clone()).license(Some(l), None);
        }
        for a in &self.authors {
            cx.content().source(source.clone()).author(a.clone());
            cx.rights().source(source.clone()).creator(a.clone());
        }
        let f = cx.format();
        f.insert("ecosystem".into(), json!(self.ecosystem));
        for (k, v) in [
            ("name", &self.name),
            ("version", &self.version),
            ("release", &self.release),
            ("architecture", &self.architecture),
            ("license", &self.license),
            ("homepage", &self.homepage),
            ("repository", &self.repository),
        ] {
            if let Some(v) = v {
                f.insert(k.into(), json!(v));
            }
        }
        if !self.authors.is_empty() {
            f.insert("authors".into(), json!(self.authors));
        }
        if !self.dependencies.is_empty() {
            let listed: Map<String, Value> =
                self.dependencies.iter().take(MAX_DEPS).map(|(n, c)| (n.clone(), json!(c))).collect();
            f.insert("dependencies".into(), Value::Object(listed));
            f.insert("dependencies_count".into(), json!(self.dependencies.len()));
        }
        if !self.scripts.is_empty() {
            f.insert("install_scripts".into(), json!(self.scripts));
        }
        if !self.signatures.is_empty() {
            f.insert("signatures".into(), json!(self.signatures));
        }
        for (k, v) in &self.extra {
            f.insert(k.clone(), v.clone());
        }
        if let Some(s) = self.signed {
            cx.security().signed(s);
        }
        if !self.scripts.is_empty() {
            let detail = self.scripts.join(", ");
            cx.security().active_content("install_scripts").risk("install_script", Some(detail));
        }
    }
}

/// `"Ada Lovelace <ada@example.org>"` → `Ada Lovelace` (an address alone is kept).
pub(crate) fn person(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let name = raw.split(['<', '(']).next().unwrap_or(raw).trim().trim_matches('"');
    let name = if name.is_empty() { raw.trim_matches(['<', '>']) } else { name };
    (!name.is_empty()).then(|| name.to_string())
}

/// RFC 822-style fields (`Key: value` with indented continuation lines),
/// as Debian control files, Python core metadata and JAR manifests write
/// them; `join` goes between a value and its continuation lines (`"\n"`,
/// or `""` for JAR manifests, which wrap at 72 bytes). Debian's `" ."`
/// continuation is an empty line. Stops at the first blank line; returns
/// the fields and the text after it (Python's description body).
pub(crate) fn fields<'t>(text: &'t str, join: &str) -> (Vec<(String, String)>, &'t str) {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        at += line.len();
        let line = line.trim_end_matches(['\n', '\r']);
        if line.trim().is_empty() {
            if out.is_empty() {
                continue;
            }
            return (out, &text[at..]);
        }
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = out.last_mut() {
                let cont = if join.is_empty() { &line[1..] } else { line.trim() };
                v.push_str(join);
                v.push_str(if cont == "." { "" } else { cont });
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    (out, "")
}

/// The first value of `key` (case-insensitive) in [`fields`] output.
pub(crate) fn field<'f>(fields: &'f [(String, String)], key: &str) -> Option<&'f str> {
    fields.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
}

/// Every value of `key` (case-insensitive).
pub(crate) fn field_all<'f>(fields: &'f [(String, String)], key: &'f str) -> impl Iterator<Item = &'f str> + 'f {
    fields.iter().filter(move |(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_str())
}

/// Python core metadata (`METADATA`, `PKG-INFO`): name, version, summary,
/// description (header or body), licence (expression, field or classifier),
/// authors and maintainers, URLs, `Requires-Dist`, `Requires-Python`.
pub(crate) fn python_metadata(t: &str, pkg: &mut Package) {
    let (f, body) = fields(t, "\n");
    pkg.name = field(&f, "Name").map(str::to_string);
    pkg.version = field(&f, "Version").map(str::to_string);
    pkg.summary = field(&f, "Summary").map(str::to_string);
    let body = body.trim();
    pkg.description =
        field(&f, "Description").map(str::to_string).or_else(|| (!body.is_empty()).then(|| body.to_string()));
    pkg.license = field(&f, "License-Expression")
        .or_else(|| field(&f, "License").filter(|l| !l.contains('\n') && l.len() < 100))
        .map(str::to_string)
        .or_else(|| {
            field_all(&f, "Classifier")
                .find_map(|c| c.strip_prefix("License :: OSI Approved :: ").or_else(|| c.strip_prefix("License :: ")))
                .map(str::to_string)
        });
    for key in ["Author", "Maintainer"] {
        pkg.authors.extend(field(&f, key).and_then(person));
    }
    for key in ["Author-email", "Maintainer-email"] {
        for a in field(&f, key).into_iter().flat_map(|v| v.split(',')) {
            if let Some(p) = person(a).filter(|p| !pkg.authors.contains(p)) {
                pkg.authors.push(p);
            }
        }
    }
    pkg.homepage = field(&f, "Home-page").map(str::to_string);
    for url in field_all(&f, "Project-URL") {
        let Some((label, u)) = url.split_once(',') else { continue };
        let label = label.trim().to_ascii_lowercase();
        if pkg.homepage.is_none() && label == "homepage" {
            pkg.homepage = Some(u.trim().to_string());
        } else if pkg.repository.is_none() && ["repository", "source", "source code"].contains(&label.as_str()) {
            pkg.repository = Some(u.trim().to_string());
        }
    }
    for req in field_all(&f, "Requires-Dist") {
        let (spec, marker) = req.split_once(';').unwrap_or((req, ""));
        let i = spec.find(['<', '>', '=', '!', '~', '(', ' ', '[']).unwrap_or(spec.len());
        let (name, rest) = spec.split_at(i);
        let mut c = rest.trim().trim_matches(['(', ')']).to_string();
        if !marker.trim().is_empty() {
            c = format!("{} ; {}", if c.is_empty() { "*" } else { &c }, marker.trim());
        }
        pkg.depend(name, &c);
    }
    for (key, out) in [("Metadata-Version", "metadata_version"), ("Requires-Python", "requires_python")] {
        if let Some(v) = field(&f, key) {
            pkg.set(out, v);
        }
    }
    let extras: Vec<&str> = field_all(&f, "Provides-Extra").collect();
    if !extras.is_empty() {
        pkg.set("extras", extras);
    }
    let classifiers = field_all(&f, "Classifier").count();
    if classifiers > 0 {
        pkg.set("classifiers", classifiers);
    }
}

/// The compression a package (or its payload) is wrapped in, by magic.
pub(crate) fn codec_of(head: &[u8]) -> Option<(Codec, &'static str)> {
    Some(if head.starts_with(b"\x1f\x8b") {
        (Codec::Gzip, "gzip")
    } else if head.starts_with(b"\x28\xb5\x2f\xfd") {
        (Codec::Zstd, "zstd")
    } else if head.starts_with(b"\xfd7zXZ\x00") {
        (Codec::Xz, "xz")
    } else if head.starts_with(b"BZh") {
        (Codec::Bzip2, "bzip2")
    } else if head.starts_with(b"\x04\x22\x4d\x18") {
        (Codec::Lz4, "lz4")
    } else if head.starts_with(b"\x5d\x00\x00") {
        (Codec::LzmaAlone, "lzma")
    } else {
        return None;
    })
}

/// `data` decompressed (when a known codec's magic starts it) within the
/// parse limit; the flag says the result is only a prefix.
pub(crate) fn unwrap(
    cx: &mut Context<'_>,
    data: Vec<u8>,
) -> Result<(Vec<u8>, Option<&'static str>, bool), ExtractError> {
    let Some((codec, name)) = codec_of(&data) else { return Ok((data, None, false)) };
    let limit = cx.parse_limit();
    let d = cx.decompress(&data, codec, limit)?;
    match &d.end {
        End::Complete | End::Limit => {}
        End::Truncated => cx.warn(format!("the {name} stream ends early")),
        End::Error(e) => cx.warn(format!("{name}: {e}")),
    }
    let whole = d.complete();
    Ok((d.data, Some(name), !whole))
}

/// A tar archive (decompressed if need be) read for a package: the
/// inventory, the files asked for and the entries to hand on.
pub(crate) struct Tarball {
    pub inventory: Inventory,
    /// `(path, data)` of the files `want` picked, in archive order.
    pub files: Vec<(String, Vec<u8>)>,
    data: crate::plugin::BytesSource,
    pending: Vec<archive::Stored>,
}

impl Tarball {
    /// Read the tar archive in `data`, keeping the files whose path
    /// `want` accepts (up to [`MAX_META`] bytes each).
    pub fn read(
        cx: &mut Context<'_>,
        name: &str,
        data: Vec<u8>,
        mut want: impl FnMut(&str) -> bool,
    ) -> Result<Self, ExtractError> {
        let mut src = cx.memory_source(name, data);
        let mut wanted: Vec<(String, u64, u64)> = Vec::new();
        let mut pending: Vec<archive::Stored> = Vec::new();
        let listing = archive::tar::list(&mut src, cx, |e, at, size, sparse, cx| {
            if e.kind == archive::Kind::File && !sparse {
                if want(&e.path) && wanted.len() < 64 {
                    wanted.push((e.path.clone(), at, size));
                }
                if archive::wanted(e) && pending.len() < cx.child_room() {
                    pending.push((e.path.clone(), at, size));
                }
            }
        })?;
        let mut files = Vec::new();
        let s: &mut dyn Source = &mut src;
        for (path, at, size) in wanted {
            let n = usize::try_from(size.min(MAX_META as u64).min(s.len().saturating_sub(at))).unwrap_or(0);
            files.push((path, s.read_vec(at, n)?));
        }
        Ok(Self { inventory: listing.inventory, files, data: src, pending })
    }

    /// The first kept file whose path `pick` accepts.
    pub fn file(&self, mut pick: impl FnMut(&str) -> bool) -> Option<&[u8]> {
        self.files.iter().find(|(p, _)| pick(p)).map(|(_, d)| d.as_slice())
    }

    /// Report the inventory and hand the entries on.
    pub fn finish(mut self, cx: &mut Context<'_>, package_bytes: u64) -> Result<(), ExtractError> {
        self.inventory.report(cx, package_bytes);
        archive::stored_children(&mut self.data, cx, self.pending)
    }
}

/// A file's path without a leading `./` or `/`.
pub(crate) fn bare(path: &str) -> &str {
    path.trim_start_matches("./").trim_start_matches('/')
}

/// Report the entries of a ZIP-based package as an archive inventory and
/// hand them on.
pub(crate) fn zip_payload(src: &mut dyn Source, cx: &mut Context<'_>, zip: &Zip) -> Result<(), ExtractError> {
    let mut inv = Inventory::new();
    inv.truncated = zip.truncated;
    for e in &zip.entries {
        inv.push(archive::zip::entry(e));
    }
    inv.report(cx, src.len());
    archive::zip::children(src, cx, zip)
}

/// Whether `name` has the extension `ext` (any case).
pub(crate) fn ext_is(name: &str, ext: &str) -> bool {
    std::path::Path::new(name).extension().is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

/// Every element of an XML manifest with its own text, in document order.
pub(crate) fn xml_elements(xml: &str, cx: &mut Context<'_>) -> Result<Vec<(Tag, String)>, ExtractError> {
    let mut out: Vec<(Tag, String)> = Vec::new();
    let mut open: Option<usize> = None;
    walk(xml, cx, |ev| {
        match ev {
            Ev::Open(t, empty) if out.len() < 20_000 => {
                out.push((t.clone(), String::new()));
                open = (!empty).then_some(out.len() - 1);
            }
            Ev::Open(..) => {}
            Ev::Text(s) => {
                if let Some(i) = open {
                    out[i].1.push_str(s);
                }
            }
            Ev::Close(_) => open = None,
        }
        Flow::Continue
    })?;
    Ok(out)
}

/// Text from a package file, lossily decoded and without a BOM.
pub(crate) fn text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).trim_start_matches('\u{feff}').to_string()
}

/// Names of the tar entries whose headers lie in `head` (a sniffer's
/// window, or the start of a decompressed stream), in order.
pub(crate) fn tar_names(head: &[u8]) -> Vec<String> {
    archive::tar::head_names(head, 512)
}

/// The first `max` bytes a gzip stream at the start of `head` expands to
/// (for sniffers: bounded, no budget needed).
pub(crate) fn gunzip_head(head: &[u8], max: usize) -> Option<Vec<u8>> {
    let start = crate::plugin::codec::gzip_header_len(head)?;
    let mut d = miniz_oxide::inflate::core::DecompressorOxide::new();
    let mut out = vec![0u8; max];
    let flags = miniz_oxide::inflate::core::inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    let (_, _, n) = miniz_oxide::inflate::core::decompress(&mut d, &head[start..], &mut out, 0, flags);
    out.truncate(n);
    (n > 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc822_fields() {
        let (f, body) = fields("Package: tides\nDescription: Tide tables\n more text\n .\n last\n\nBody here\n", "\n");
        assert_eq!(field(&f, "package"), Some("tides"));
        assert_eq!(field(&f, "Description"), Some("Tide tables\nmore text\n\nlast"));
        assert_eq!(body, "Body here\n");
        let (m, _) = fields("Implementation-Title: Saltmere Ti\n des\r\n", "");
        assert_eq!(field(&m, "Implementation-Title"), Some("Saltmere Tides"));
    }

    #[test]
    fn people() {
        assert_eq!(person("Ana Lighthouse <ana@example.org>").as_deref(), Some("Ana Lighthouse"));
        assert_eq!(person("<ana@example.org>").as_deref(), Some("ana@example.org"));
        assert_eq!(person("  "), None);
    }

    #[test]
    fn codecs() {
        assert_eq!(codec_of(b"\x1f\x8b\x08").map(|c| c.1), Some("gzip"));
        assert_eq!(codec_of(b"ustar").map(|c| c.1), None);
    }
}
