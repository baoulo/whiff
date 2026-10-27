//! Linux application bundles: Snap packages (a squashfs image with
//! `meta/snap.yaml`: name, version, summary, description, licence, base,
//! grade, confinement, architectures, apps with their commands and
//! interfaces, plugs and slots), AppImages (an ELF runtime with a squashfs
//! image appended: the desktop entry's name, version, comment and
//! categories, the AppStream metadata's licence and homepage, the update
//! information and embedded signature) and Flatpak reference files
//! (`.flatpakref`, `.flatpakrepo`: application, branch, title, repository,
//! runtime repository, whether a GPG key is included). The squashfs
//! payload is listed with the archive inventory and its files handed on.
//!
//! Specifications: snapcraft "The snap format" (`snap.yaml`); AppImage
//! specification (type 2) and the freedesktop Desktop Entry
//! Specification; `flatpak-flatpakref(5)` and `flatpak-flatpakrepo(5)`.

use serde_json::{Value, json};

use super::archive::squashfs::Image;
use super::yaml::first_document;
use super::{Package, person};
use crate::plugin::volume::num::{le16, le32, le64};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source};

/// Extractor for Linux application bundles.
pub struct LinuxBundle;

static META: ExtractorMeta = ExtractorMeta {
    id: "package.linux",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "snap",
            name: "Snap package",
            family: "package",
            mimes: &["application/vnd.snap"],
            extensions: &["snap"],
            magic: &[],
            parent: Some("squashfs"),
        },
        FormatSpec {
            id: "appimage",
            name: "AppImage",
            family: "package",
            mimes: &["application/vnd.appimage"],
            extensions: &["appimage"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "flatpakref",
            name: "Flatpak reference",
            family: "package",
            mimes: &["application/vnd.flatpak.ref", "application/vnd.flatpak.repo"],
            extensions: &["flatpakref", "flatpakrepo"],
            magic: &[],
            parent: None,
        },
    ],
};

/// Metadata files read at most.
const MAX_META: u64 = 1 << 20;

impl Extractor for LinuxBundle {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.starts_with(b"\x7fELF") && h.get(8..11).is_some_and(|m| m == b"AI\x02" || m == b"AI\x01") {
            return Some(Sniff { format: "appimage", confidence: 0.97 });
        }
        if h.starts_with(b"[Flatpak Ref]") || h.starts_with(b"[Flatpak Repo]") {
            return Some(Sniff { format: "flatpakref", confidence: 0.97 });
        }
        (h.starts_with(b"hsqs") && probe.extension == Some("snap")).then_some(Sniff { format: "snap", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "snap" => snap(src, cx),
            "appimage" => appimage(src, cx),
            _ => flatpakref(src, cx),
        }
    }
}

crate::register_extractor!(LinuxBundle);

/// A YAML scalar as text.
fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Interface names of a `plugs` / `slots` value (a list or a map).
fn interfaces(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(scalar).collect(),
        Some(Value::Object(m)) => m.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

fn snap(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut fs = Image::open(src, 0)?;
    let listed = fs.list(src, cx)?;
    let mut pkg = Package::new("snap");
    if let Some((_, f)) = listed.files.iter().find(|(p, _)| p == "meta/snap.yaml") {
        let data = fs.read(src, cx, f, MAX_META)?;
        if let Some(Value::Object(y)) = first_document(&String::from_utf8_lossy(&data)) {
            let s = |k: &str| y.get(k).and_then(scalar);
            pkg.name = s("name");
            pkg.version = s("version");
            pkg.summary = s("summary");
            pkg.description = s("description");
            pkg.license = s("license");
            pkg.homepage = s("website");
            if let Some(c) = s("contact") {
                pkg.authors.extend(person(&c));
            }
            for k in ["title", "base", "grade", "confinement", "type", "assumes"] {
                if let Some(v) = s(k) {
                    pkg.set(k, v);
                }
            }
            if let Some(Value::Array(a)) = y.get("architectures") {
                pkg.set("architectures", a.iter().filter_map(scalar).collect::<Vec<_>>());
            }
            let mut plugs = interfaces(y.get("plugs"));
            if let Some(Value::Object(apps)) = y.get("apps") {
                let mut list = Vec::new();
                for (name, app) in apps.iter().take(64) {
                    let mut m = serde_json::Map::new();
                    m.insert("name".into(), json!(name));
                    if let Some(c) = app.get("command").and_then(scalar) {
                        m.insert("command".into(), json!(c));
                    }
                    if let Some(d) = app.get("daemon").and_then(scalar) {
                        m.insert("daemon".into(), json!(d));
                    }
                    let p = interfaces(app.get("plugs"));
                    plugs.extend(p.iter().cloned());
                    if !p.is_empty() {
                        m.insert("plugs".into(), json!(p));
                    }
                    list.push(Value::Object(m));
                }
                pkg.set("apps", list);
            }
            plugs.sort();
            plugs.dedup();
            if !plugs.is_empty() {
                pkg.set("plugs", plugs);
            }
            let slots = interfaces(y.get("slots"));
            if !slots.is_empty() {
                pkg.set("slots", slots);
            }
            if s("confinement").as_deref() == Some("classic") {
                pkg.set("unconfined", true);
            }
        }
    } else {
        cx.warn("no meta/snap.yaml");
    }
    let hooks: Vec<String> = listed
        .files
        .iter()
        .filter_map(|(p, _)| p.strip_prefix("meta/hooks/").or_else(|| p.strip_prefix("snap/hooks/")))
        .map(str::to_string)
        .collect();
    if !hooks.is_empty() {
        pkg.scripts = hooks;
    }
    pkg.set("squashfs", Value::Object(fs.facts()));
    pkg.write(cx);
    listed.inventory.report(cx, src.len());
    fs.hand_on(src, cx, listed.files)
}

/// Desktop-entry fields of the `[Desktop Entry]` group.
fn desktop_entry(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_entry = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if in_entry && let Some((k, v)) = line.split_once('=') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

/// Where the ELF runtime ends (its section header table is last).
fn elf_end(h: &[u8]) -> Option<u64> {
    if h.get(4) != Some(&2) || h.get(5) != Some(&1) {
        return None;
    }
    let shoff = le64(h, 0x28)?;
    let (shentsize, shnum) = (u64::from(le16(h, 0x3A)?), u64::from(le16(h, 0x3C)?));
    Some(shoff + shentsize * shnum)
}

/// AppImage ELF sections `(name, offset, size)`.
fn elf_sections(src: &mut dyn Source, h: &[u8]) -> Vec<(String, u64, u64)> {
    let (Some(shoff), Some(shentsize), Some(shnum), Some(shstrndx)) =
        (le64(h, 0x28), le16(h, 0x3A), le16(h, 0x3C), le16(h, 0x3E))
    else {
        return Vec::new();
    };
    let Ok(table) = src.read_vec(shoff, usize::from(shentsize) * usize::from(shnum.min(256))) else {
        return Vec::new();
    };
    let entry = |i: usize| table.get(i * usize::from(shentsize)..(i + 1) * usize::from(shentsize));
    let Some(strtab) = entry(usize::from(shstrndx)) else { return Vec::new() };
    let (Some(str_at), Some(str_len)) = (le64(strtab, 0x18), le64(strtab, 0x20)) else { return Vec::new() };
    let Ok(names) = src.read_vec(str_at, usize::try_from(str_len.min(1 << 16)).unwrap_or(0)) else { return Vec::new() };
    (0..usize::from(shnum.min(256)))
        .filter_map(|i| {
            let e = entry(i)?;
            let n = le32(e, 0)? as usize;
            let end = names.get(n..)?.iter().position(|&c| c == 0)? + n;
            Some((String::from_utf8_lossy(&names[n..end]).into_owned(), le64(e, 0x18)?, le64(e, 0x20)?))
        })
        .collect()
}

fn appimage(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.head().to_vec();
    let mut pkg = Package::new("appimage");
    pkg.set("appimage_type", if h.get(10) == Some(&2) { 2 } else { 1 });
    let arch = match le16(&h, 0x12) {
        Some(0x3E) => "x86_64",
        Some(0xB7) => "aarch64",
        Some(0x03) => "i386",
        Some(0x28) => "armhf",
        _ => "other",
    };
    pkg.architecture = Some(arch.into());
    for (name, at, size) in elf_sections(src, &h) {
        let Ok(data) = src.read_vec(at, usize::try_from(size.min(MAX_META)).unwrap_or(0)) else { continue };
        let used = data.iter().any(|&b| b != 0);
        match name.as_str() {
            ".upd_info" if used => {
                if let Some(u) = crate::plugin::volume::text_field(&data) {
                    pkg.set("update_information", u);
                }
            }
            ".sha256_sig" if used => {
                pkg.signed = Some(true);
                pkg.signatures.push("gpg".into());
            }
            ".sha256_sig" => pkg.signed = Some(false),
            _ => {}
        }
    }
    let Some(offset) = elf_end(&h).filter(|&o| o < src.len()) else {
        return Err(ExtractError::malformed("no squashfs image after the runtime"));
    };
    pkg.set("payload_offset", offset);
    let mut fs = Image::open(src, offset)?;
    let listed = fs.list(src, cx)?;
    let desktop = listed.files.iter().find(|(p, _)| !p.contains('/') && p.ends_with(".desktop")).cloned();
    if let Some((_, f)) = desktop {
        let text = String::from_utf8_lossy(&fs.read(src, cx, &f, MAX_META)?).into_owned();
        let entry = desktop_entry(&text);
        let get = |k: &str| entry.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone()).filter(|v| !v.is_empty());
        pkg.name = get("Name");
        pkg.version = get("X-AppImage-Version");
        pkg.summary = get("Comment");
        if let Some(c) = get("Categories") {
            pkg.set("categories", c.split(';').filter(|c| !c.is_empty()).collect::<Vec<_>>());
        }
        if let Some(e) = get("Exec") {
            pkg.set("exec", e);
        }
    }
    let appdata =
        listed.files.iter().find(|(p, _)| p.starts_with("usr/share/metainfo/") && super::ext_is(p, "xml")).cloned();
    if let Some((_, f)) = appdata {
        let text = String::from_utf8_lossy(&fs.read(src, cx, &f, MAX_META)?).into_owned();
        for (tag, value) in super::xml_elements(&text, cx)? {
            match tag.name.as_str() {
                "project_license" if pkg.license.is_none() => pkg.license = Some(value),
                "url" if tag.attr("type") == Some("homepage") && pkg.homepage.is_none() => pkg.homepage = Some(value),
                "developer_name" if pkg.authors.is_empty() => pkg.authors.push(value),
                "summary" if pkg.summary.is_none() => pkg.summary = Some(value),
                _ => {}
            }
        }
    }
    pkg.set("squashfs", Value::Object(fs.facts()));
    pkg.write(cx);
    listed.inventory.report(cx, src.len());
    fs.hand_on(src, cx, listed.files)
}

fn flatpakref(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let text = cx.read_text(src)?.text;
    let repo = text.trim_start().starts_with("[Flatpak Repo]");
    let mut pkg = Package::new("flatpak");
    pkg.set("kind", if repo { "repository" } else { "application" });
    for line in text.lines().map(str::trim) {
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim().to_string());
        if v.is_empty() {
            continue;
        }
        match k {
            "Name" => pkg.name = Some(v),
            "Title" => pkg.summary = Some(v),
            "Comment" if pkg.summary.is_none() => pkg.summary = Some(v),
            "Description" => pkg.description = Some(v),
            "Homepage" => pkg.homepage = Some(v),
            "Branch" => pkg.version = Some(v),
            "Url" => pkg.set("repository_url", v),
            "RuntimeRepo" => pkg.set("runtime_repository", v),
            "SuggestRemoteName" => pkg.set("remote_name", v),
            "IsRuntime" => pkg.set("is_runtime", v == "true"),
            "GPGKey" => {
                pkg.signed = Some(true);
                pkg.signatures.push("gpg".into());
            }
            _ => {}
        }
    }
    if pkg.signed.is_none() {
        pkg.signed = Some(false);
    }
    pkg.write(cx);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_entries() {
        let e =
            desktop_entry("[Desktop Entry]\nName=Tides\nX-AppImage-Version=1.2.0\n[Desktop Action New]\nName=Other\n");
        assert_eq!(e, [("Name".to_string(), "Tides".to_string()), ("X-AppImage-Version".into(), "1.2.0".into())]);
    }

    crate::fixture_tests!("snap", "appimage", "flatpakref");
}
