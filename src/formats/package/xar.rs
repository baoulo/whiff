//! XAR archives and the macOS installer packages built on them (`.pkg`,
//! `.mpkg`). The zlib-compressed XML table of contents lists every member
//! (path, type, mode, owner, times, archived and extracted sizes,
//! encoding) and the archive's signatures (RSA with X.509 certificates,
//! CMS). For an installer, the product `Distribution` gives the title,
//! product id and version, the component packages, host architectures,
//! minimum OS and the installer JavaScript it runs; each component's
//! `PackageInfo` gives its identifier, version, install location,
//! whether it installs as root, its payload size and its install scripts.
//! The first component's payload (gzip or `pbzx` cpio) is listed and its
//! files handed on.
//!
//! Specifications: the xar file format (mackyle/xar wiki); Apple's
//! "Distribution XML Reference" and `pkgbuild(1)` (`PackageInfo`).

use std::collections::BTreeMap;

use super::archive::{Entry, Inventory, Kind, cpio, stored_children};
use super::xml::{Ev, Flow, walk};
use super::{Package, ext_is, unwrap, xml_elements};
use crate::plugin::{
    ByteReader, Codec, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe,
    Sniff, Source,
};

/// Extractor for XAR archives and installer packages.
pub struct Xar;

static META: ExtractorMeta = ExtractorMeta {
    id: "package.xar",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "pkg",
            name: "macOS installer package",
            family: "package",
            mimes: &["application/vnd.apple.installer+xml"],
            extensions: &["pkg", "mpkg"],
            magic: &[Magic::prefix(b"xar!")],
            parent: None,
        },
        FormatSpec {
            id: "xar",
            name: "XAR archive",
            family: "archive",
            mimes: &["application/x-xar"],
            extensions: &["xar", "xip"],
            magic: &[Magic::prefix(b"xar!")],
            parent: None,
        },
    ],
};

/// Largest table of contents (expanded) and metadata member read.
const MAX_TOC: usize = 32 << 20;
const MAX_META: usize = 8 << 20;
/// Members kept from the table of contents.
const MAX_FILES: usize = 1 << 16;

/// One member from the table of contents.
#[derive(Debug, Default, Clone)]
struct Member {
    path: String,
    kind: String,
    mode: Option<u32>,
    mtime: Option<String>,
    /// Archived (heap) offset and size.
    offset: Option<u64>,
    size: Option<u64>,
    /// Extracted size.
    length: Option<u64>,
    encoding: String,
    link: Option<String>,
    /// Position in the table of contents (members are listed in it).
    order: usize,
}

/// The parsed table of contents.
#[derive(Debug, Default)]
struct Toc {
    files: Vec<Member>,
    created: Option<String>,
    signatures: Vec<String>,
    checksum: Option<String>,
}

fn parse_toc(xml: &str, cx: &mut Context<'_>) -> Result<Toc, ExtractError> {
    let mut toc = Toc::default();
    let mut stack: Vec<Member> = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut order = 0usize;
    walk(xml, cx, |ev| {
        match ev {
            Ev::Open(t, empty) => {
                match t.name.as_str() {
                    "file" if !empty => {
                        order += 1;
                        stack.push(Member { order, ..Member::default() });
                    }
                    "signature" | "x-signature" => toc.signatures.extend(t.attr("style").map(str::to_string)),
                    "checksum" if stack.is_empty() && path.last().is_some_and(|p| p == "toc") => {
                        toc.checksum = t.attr("style").map(str::to_string);
                    }
                    "encoding" => {
                        if let Some(m) = stack.last_mut() {
                            m.encoding = t.attr("style").unwrap_or("").to_string();
                        }
                    }
                    _ => {}
                }
                if !empty {
                    path.push(t.name.clone());
                }
                text.clear();
            }
            Ev::Text(s) => text.push_str(s),
            Ev::Close(name) => {
                let parent = path.len().checked_sub(2).and_then(|i| path.get(i)).map(String::as_str);
                let value = text.trim().to_string();
                match (name, parent) {
                    ("file", _) => {
                        if let Some(mut m) = stack.pop() {
                            // Nested `<file>` elements are a folder's members.
                            let mut full: Vec<&str> = stack.iter().map(|p| p.path.as_str()).collect();
                            full.push(&m.path);
                            m.path = full.join("/");
                            if toc.files.len() < MAX_FILES {
                                toc.files.push(m);
                            }
                        }
                    }
                    ("name", Some("file")) => {
                        if let Some(m) = stack.last_mut() {
                            m.path = value;
                        }
                    }
                    ("type", Some("file")) => {
                        if let Some(m) = stack.last_mut() {
                            m.kind = value;
                        }
                    }
                    ("mode", Some("file")) => {
                        if let Some(m) = stack.last_mut() {
                            m.mode = u32::from_str_radix(&value, 8).ok();
                        }
                    }
                    ("mtime", Some("file")) => {
                        if let Some(m) = stack.last_mut() {
                            m.mtime = Some(value);
                        }
                    }
                    ("link", Some("file")) => {
                        if let Some(m) = stack.last_mut() {
                            m.link = Some(value);
                        }
                    }
                    ("offset", Some("data")) => {
                        if let Some(m) = stack.last_mut() {
                            m.offset = value.parse().ok();
                        }
                    }
                    // `length` is the archived size, `size` the extracted one.
                    ("length", Some("data")) => {
                        if let Some(m) = stack.last_mut() {
                            m.size = value.parse().ok();
                        }
                    }
                    ("size", Some("data")) => {
                        if let Some(m) = stack.last_mut() {
                            m.length = value.parse().ok();
                        }
                    }
                    ("creation-time", Some("toc")) => toc.created = Some(value),
                    _ => {}
                }
                path.pop();
                text.clear();
            }
        }
        Flow::Continue
    })?;
    // Members close after their folder's own fields: list them as opened.
    toc.files.sort_by_key(|m| m.order);
    Ok(toc)
}

/// A member's data, decoded (zlib, bzip2, xz) and capped.
fn member_data(
    src: &mut dyn Source,
    cx: &mut Context<'_>,
    heap: u64,
    m: &Member,
    max: usize,
) -> Result<Vec<u8>, ExtractError> {
    let (Some(off), Some(size)) = (m.offset, m.size) else { return Ok(Vec::new()) };
    let raw = src.read_vec(heap.saturating_add(off), usize::try_from(size.min(max as u64)).unwrap_or(0))?;
    let codec = match m.encoding.as_str() {
        // xar's "gzip" encoding is a zlib stream.
        "application/x-gzip" => Some(Codec::Zlib),
        "application/x-bzip2" => Some(Codec::Bzip2),
        "application/x-xz" => Some(Codec::Xz),
        "application/x-lzma" => Some(Codec::LzmaAlone),
        _ => None,
    };
    match codec {
        Some(c) => Ok(cx.decompress(&raw, c, max)?.data),
        None => Ok(raw),
    }
}

/// Apple's `pbzx` stream: chunks of xz (or raw) data.
fn pbzx(cx: &mut Context<'_>, data: &[u8], max: usize) -> Result<Vec<u8>, ExtractError> {
    let mut out = Vec::new();
    let mut r = ByteReader::new(data.get(12..).unwrap_or(&[]));
    while out.len() < max && r.remaining() >= 16 {
        let _flags = r.be_u64()?;
        let size = usize::try_from(r.be_u64()?).unwrap_or(usize::MAX);
        let Ok(chunk) = r.bytes(size) else { break };
        if chunk.starts_with(b"\xfd7zXZ\x00") {
            out.extend(cx.decompress(chunk, Codec::Xz, max - out.len())?.data);
        } else {
            out.extend_from_slice(chunk);
        }
    }
    Ok(out)
}

impl Extractor for Xar {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if !probe.head.starts_with(b"xar!") {
            return None;
        }
        let format = if matches!(probe.extension, Some("pkg" | "mpkg")) { "pkg" } else { "xar" };
        Some(Sniff { format, confidence: 0.9 })
    }

    #[allow(clippy::too_many_lines)] // header, TOC, distribution, components, payload
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let fixed = src.read_vec(0, 28)?;
        let mut r = ByteReader::new(&fixed);
        r.advance(4)?;
        let header = u64::from(r.be_u16()?);
        let version = r.be_u16()?;
        let toc_len = r.be_u64()?;
        let toc_raw = r.be_u64()?;
        let toc_data = src.read_vec(header, usize::try_from(toc_len.min(MAX_TOC as u64)).unwrap_or(0))?;
        let toc_xml =
            cx.decompress(&toc_data, Codec::Zlib, MAX_TOC.min(usize::try_from(toc_raw).unwrap_or(MAX_TOC)))?;
        let toc = parse_toc(&String::from_utf8_lossy(&toc_xml.data), cx)?;
        let heap = header + toc_len;
        let installer = toc
            .files
            .iter()
            .any(|f| f.path == "Distribution" || f.path == "PackageInfo" || f.path.ends_with("/PackageInfo"));
        if cx.format_id() == "xar" && installer {
            cx.redirect("pkg");
            return Ok(());
        }
        let mut pkg = Package::new("macos_installer");
        pkg.set("xar_version", version);
        if let Some(c) = &toc.checksum {
            pkg.set("toc_checksum", c.clone());
        }
        if let Some(t) = &toc.created {
            pkg.set("created", t.clone());
            cx.temporal().content_date(DateField::Created, t.clone(), t.ends_with('Z'));
        }
        pkg.signed = Some(!toc.signatures.is_empty());
        pkg.signatures.clone_from(&toc.signatures);
        if cx.format_id() == "xar" {
            pkg.ecosystem = "xar";
            pkg.write(cx);
            let mut inv = Inventory::new();
            for m in &toc.files {
                inv.push(entry(m));
            }
            inv.report(cx, src.len());
            return Ok(());
        }
        let find = |p: &str| toc.files.iter().find(|f| f.path == p).cloned();
        // The product's Distribution.
        if let Some(d) = find("Distribution") {
            let xml = String::from_utf8_lossy(&member_data(src, cx, heap, &d, MAX_META)?).into_owned();
            let els = xml_elements(&xml, cx)?;
            let mut components = Vec::new();
            for (t, body) in &els {
                match t.name.as_str() {
                    "title" if !body.trim().is_empty() => pkg.summary = Some(body.trim().to_string()),
                    "product" => {
                        pkg.name = t.attr("id").map(str::to_string);
                        pkg.version = t.attr("version").map(str::to_string);
                    }
                    "pkg-ref" if t.attr("version").is_some() => {
                        components.push(
                            format!("{} {}", t.attr("id").unwrap_or("?"), t.attr("version").unwrap_or(""))
                                .trim()
                                .to_string(),
                        );
                    }
                    "options" => {
                        if let Some(a) = t.attr("hostArchitectures") {
                            pkg.architecture = Some(a.to_string());
                        }
                    }
                    "os-version" => {
                        if let Some(m) = t.attr("min") {
                            pkg.set("minimum_os", m);
                        }
                    }
                    "script" if !body.trim().is_empty() => {
                        if !pkg.scripts.iter().any(|s| s == "Distribution JavaScript") {
                            pkg.scripts.push("Distribution JavaScript".into());
                        }
                    }
                    "installation-check" | "volume-check" if t.attr("script").is_some() => {
                        pkg.set(&t.name.replace('-', "_"), t.attr("script").unwrap_or(""));
                    }
                    "license" => pkg.set("license_file", t.attr("file").unwrap_or("")),
                    _ => {}
                }
            }
            if !components.is_empty() {
                pkg.set("components", components);
            }
        }
        // Components: `PackageInfo` at the root (a component package) or in
        // each `<name>.pkg` folder (a product).
        let infos: Vec<Member> = toc
            .files
            .iter()
            .filter(|f| {
                f.path == "PackageInfo" || f.path.strip_suffix("/PackageInfo").is_some_and(|d| ext_is(d, "pkg"))
            })
            .cloned()
            .collect();
        let mut first_payload: Option<String> = None;
        let mut installed_kib = 0u64;
        for info in infos.iter().take(64) {
            let dir = info.path.strip_suffix("PackageInfo").unwrap_or("");
            let xml = String::from_utf8_lossy(&member_data(src, cx, heap, info, MAX_META)?).into_owned();
            for (t, _) in xml_elements(&xml, cx)? {
                match t.name.as_str() {
                    "pkg-info" => {
                        if pkg.name.is_none() {
                            pkg.name = t.attr("identifier").map(str::to_string);
                            pkg.version = t.attr("version").map(str::to_string);
                        }
                        if let Some(l) = t.attr("install-location") {
                            pkg.set("install_location", l);
                        }
                        if t.attr("auth").is_some_and(|a| a.eq_ignore_ascii_case("root")) {
                            pkg.set("installs_as_root", true);
                        }
                    }
                    "payload" => {
                        installed_kib += t.attr("installKBytes").and_then(|k| k.parse::<u64>().ok()).unwrap_or(0);
                        if let Some(n) = t.attr("numberOfFiles") {
                            pkg.set(
                                "payload_files",
                                n.parse::<u64>().map_or(serde_json::Value::from(n), serde_json::Value::from),
                            );
                        }
                    }
                    "preinstall" | "postinstall" | "preupgrade" | "postupgrade" => {
                        let s = format!("{}{}", dir, t.name);
                        if !pkg.scripts.contains(&s) {
                            pkg.scripts.push(s);
                        }
                    }
                    _ => {}
                }
            }
            if first_payload.is_none() {
                first_payload = Some(format!("{dir}Payload"));
            }
        }
        if installed_kib > 0 {
            pkg.set("installed_size_bytes", installed_kib * 1024);
        }
        let encodings: BTreeMap<&str, u64> =
            toc.files.iter().filter(|f| !f.encoding.is_empty()).fold(BTreeMap::new(), |mut m, f| {
                *m.entry(f.encoding.trim_start_matches("application/")).or_default() += 1;
                m
            });
        if !encodings.is_empty() {
            pkg.set("encodings", serde_json::to_value(&encodings).unwrap_or_default());
        }
        pkg.write(cx);
        // The first component's payload: a gzip or pbzx cpio archive.
        let payload = first_payload.and_then(|p| find(&p));
        let Some(p) = payload.filter(|_| cx.child_room() > 0) else {
            let mut inv = Inventory::new();
            for m in &toc.files {
                inv.push(entry(m));
            }
            inv.report(cx, src.len());
            return Ok(());
        };
        let limit = cx.parse_limit();
        let data = member_data(src, cx, heap, &p, limit)?;
        let cpio_data = if data.starts_with(b"pbzx") { pbzx(cx, &data, limit)? } else { unwrap(cx, data)?.0 };
        let mut payload = cx.memory_source("Payload", cpio_data);
        match cpio::list(&mut payload, cx) {
            Ok((inv, pending)) => {
                inv.report(cx, src.len());
                stored_children(&mut payload, cx, pending)
            }
            Err(_) => Ok(()),
        }
    }
}

crate::register_extractor!(Xar);

fn entry(m: &Member) -> Entry {
    let kind = match m.kind.as_str() {
        "directory" => Kind::Dir,
        "symlink" => Kind::Symlink,
        "hardlink" => Kind::Hardlink,
        "file" | "" => Kind::File,
        _ => Kind::Special,
    };
    Entry {
        path: m.path.clone(),
        kind,
        size: m.length.or(m.size).or(Some(0)),
        compressed: m.size.or(Some(0)),
        modified: m.mtime.clone(),
        mode: m.mode.map(|x| x & 0o7777),
        link: m.link.clone(),
        encrypted: false,
        method: Some(m.encoding.trim_start_matches("application/").to_string()).filter(|e| !e.is_empty()),
    }
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("pkg", "xar");
}
