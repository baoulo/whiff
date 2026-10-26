//! ZIP-based packages with a manifest inside: Python wheels and eggs (core
//! metadata, `WHEEL` tags, entry points, `.pth` start-up hooks), NuGet
//! packages (`.nuspec`: id, version, authors, licence, dependencies per
//! target framework; PowerShell install scripts; the package signature),
//! MSIX / APPX packages and bundles (`AppxManifest.xml`: identity,
//! publisher, target device families, capabilities, applications; the
//! bundle's packages; `AppxSignature.p7x`), Visual Studio and VS Code
//! extensions (`.vsix`: `extension.vsixmanifest`, `package.json`
//! activation events) and browser extensions — Firefox `.xpi` and Chrome
//! `.crx` (the CRX2 / CRX3 header, its signatures and extension id), with
//! the WebExtension manifest's permissions. Entries are listed and handed
//! on.
//!
//! Specifications: PyPA binary distribution format and core metadata 2.4;
//! NuGet `.nuspec` reference; MSIX `AppxManifest` and bundle manifest
//! schemas; VSIX 2.0 schema; VS Code extension manifest; CRX3
//! `crx3.proto`; WebExtensions `manifest.json`.

use serde_json::Value;

use super::known::extension_permissions;
use super::{Package, ext_is, field, fields, python_metadata, text, xml_elements, zip_payload};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, Zip, zip_names,
};

/// Extractor for ZIP-based packages.
pub struct Zipped;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, [$($ext:literal),*]) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: "package",
            mimes: &[$mime],
            extensions: &[$($ext),*],
            magic: &[],
            parent: Some("zip"),
        }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "package.zipped",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("wheel", "Python wheel", "application/zip", ["whl"]),
        spec!("egg", "Python egg", "application/zip", ["egg"]),
        spec!("nupkg", "NuGet package", "application/zip", ["nupkg", "snupkg"]),
        spec!("msix", "MSIX / APPX package", "application/msix", ["msix", "appx"]),
        spec!("msix_bundle", "MSIX / APPX bundle", "application/msixbundle", ["msixbundle", "appxbundle"]),
        spec!("vsix", "Visual Studio / VS Code extension", "application/vsix", ["vsix"]),
        spec!("xpi", "Firefox extension", "application/x-xpinstall", ["xpi"]),
        FormatSpec {
            id: "crx",
            name: "Chrome extension",
            family: "package",
            mimes: &["application/x-chrome-extension"],
            extensions: &["crx"],
            magic: &[Magic::prefix(b"Cr24")],
            parent: None,
        },
    ],
};

const MAX_ENTRIES: usize = 1 << 16;
/// Largest manifest read.
const MAX_MANIFEST: usize = 8 << 20;
/// MSIX capabilities that need Microsoft's approval in the Store.
const RESTRICTED: [&str; 6] = [
    "runFullTrust",
    "allowElevation",
    "broadFileSystemAccess",
    "packageManagement",
    "unvirtualizedResources",
    "localSystemServices",
];

/// Which package the entry names (and extension) say this is.
fn kind(names: &[String], ext: Option<&str>) -> Option<(&'static str, f64)> {
    let has = |n: &str| names.iter().any(|x| x == n);
    let any = |f: &dyn Fn(&str) -> bool| names.iter().any(|x| f(x));
    Some(if any(&|n| n.split_once('/').is_some_and(|(d, f)| ext_is(d, "dist-info") && f == "WHEEL")) {
        ("wheel", 0.96)
    } else if has("EGG-INFO/PKG-INFO") {
        ("egg", 0.95)
    } else if any(&|n| !n.contains('/') && ext_is(n, "nuspec")) {
        ("nupkg", 0.96)
    } else if has("AppxManifest.xml") {
        ("msix", 0.96)
    } else if has("AppxMetadata/AppxBundleManifest.xml") {
        ("msix_bundle", 0.96)
    } else if has("extension.vsixmanifest") {
        ("vsix", 0.96)
    } else if has("manifest.json") && (ext == Some("xpi") || has("META-INF/mozilla.rsa") || has("META-INF/cose.sig")) {
        ("xpi", 0.95)
    } else {
        return None;
    })
}

impl Extractor for Zipped {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if probe.head.starts_with(b"Cr24") {
            return Some(Sniff { format: "crx", confidence: 0.97 });
        }
        if !probe.head.starts_with(b"PK\x03\x04") {
            return None;
        }
        let names = zip_names(probe, 4000);
        kind(&names, probe.extension).map(|(format, confidence)| Sniff { format, confidence })
    }

    #[allow(clippy::too_many_lines)] // one arm per package kind
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let format = cx.format_id().to_string();
        let mut pkg = Package::new(match format.as_str() {
            "wheel" | "egg" => "pypi",
            "nupkg" => "nuget",
            "msix" | "msix_bundle" => "msix",
            "vsix" => "vsix",
            _ => "webextension",
        });
        if format == "crx" {
            crx_header(src, &mut pkg)?;
        }
        let zip = Zip::open(src, MAX_ENTRIES)?;
        let read = |zip: &Zip, src: &mut dyn Source, cx: &mut Context<'_>, name: &str| -> Option<String> {
            match zip.read_text(src, name, cx, MAX_MANIFEST) {
                Some(Ok(t)) => Some(t),
                _ => None,
            }
        };
        match format.as_str() {
            "wheel" => {
                let info = zip
                    .entries
                    .iter()
                    .find_map(|e| e.name.strip_suffix("/WHEEL").filter(|d| ext_is(d, "dist-info")).map(str::to_string));
                if let Some(dir) = info {
                    if let Some(t) = read(&zip, src, cx, &format!("{dir}/METADATA")) {
                        python_metadata(&t, &mut pkg);
                    }
                    if let Some(t) = read(&zip, src, cx, &format!("{dir}/WHEEL")) {
                        let (f, _) = fields(&t, "\n");
                        let tags: Vec<&str> = super::field_all(&f, "Tag").collect();
                        if !tags.is_empty() {
                            pkg.architecture = Some(tags.join(", "));
                            pkg.set("tags", tags);
                        }
                        for (key, out) in [("Wheel-Version", "wheel_version"), ("Generator", "generator")] {
                            if let Some(v) = field(&f, key) {
                                pkg.set(out, v);
                            }
                        }
                        if let Some(p) = field(&f, "Root-Is-Purelib") {
                            pkg.set("pure_python", p == "true");
                        }
                    }
                    if let Some(t) = read(&zip, src, cx, &format!("{dir}/entry_points.txt")) {
                        entry_points(&t, &mut pkg);
                    }
                    let signed = [".jws", ".p7s"].iter().any(|x| zip.find(&format!("{dir}/RECORD{x}")).is_some());
                    pkg.signed = Some(signed);
                }
                pth_hooks(&zip, src, cx, &mut pkg)?;
            }
            "egg" => {
                if let Some(t) = read(&zip, src, cx, "EGG-INFO/PKG-INFO") {
                    python_metadata(&t, &mut pkg);
                }
                if let Some(t) = read(&zip, src, cx, "EGG-INFO/entry_points.txt") {
                    entry_points(&t, &mut pkg);
                }
                pth_hooks(&zip, src, cx, &mut pkg)?;
            }
            "nupkg" => {
                let spec = zip
                    .entries
                    .iter()
                    .find(|e| !e.name.contains('/') && ext_is(&e.name, "nuspec"))
                    .map(|e| e.name.clone());
                if let Some(t) = spec.and_then(|n| read(&zip, src, cx, &n)) {
                    nuspec(&t, cx, &mut pkg)?;
                }
                for e in &zip.entries {
                    let lower = e.name.to_ascii_lowercase();
                    if lower.starts_with("tools/") && ext_is(&lower, "ps1") {
                        pkg.scripts.push(e.name.clone());
                    }
                }
                if zip.find(".signature.p7s").is_some() {
                    pkg.signed = Some(true);
                    pkg.signatures.push("pkcs7".into());
                } else {
                    pkg.signed = Some(false);
                }
            }
            "msix" => {
                if let Some(t) = read(&zip, src, cx, "AppxManifest.xml") {
                    appx(&t, cx, &mut pkg)?;
                }
                pkg.signed = Some(zip.find("AppxSignature.p7x").is_some());
            }
            "msix_bundle" => {
                if let Some(t) = read(&zip, src, cx, "AppxMetadata/AppxBundleManifest.xml") {
                    appx(&t, cx, &mut pkg)?;
                }
                pkg.signed = Some(zip.find("AppxSignature.p7x").is_some());
            }
            "vsix" => {
                if let Some(t) = read(&zip, src, cx, "extension.vsixmanifest") {
                    vsix(&t, cx, &mut pkg)?;
                }
                if let Some(v) =
                    read(&zip, src, cx, "extension/package.json").and_then(|t| serde_json::from_str(&t).ok())
                {
                    vscode(&v, &mut pkg);
                }
                pkg.signed = Some(zip.find(".signature.p7s").is_some());
            }
            _ => {
                if let Some(v) =
                    read(&zip, src, cx, "manifest.json").and_then(|t| serde_json::from_str::<Value>(&t).ok())
                {
                    webextension(&v, cx, &mut pkg);
                }
                if format == "xpi" {
                    let sigs: Vec<String> = ["META-INF/mozilla.rsa", "META-INF/cose.sig"]
                        .into_iter()
                        .filter(|n| zip.find(n).is_some())
                        .map(|n| n.rsplit('/').next().unwrap_or(n).to_string())
                        .collect();
                    pkg.signed = Some(!sigs.is_empty());
                    pkg.signatures = sigs;
                }
            }
        }
        pkg.write(cx);
        zip_payload(src, cx, &zip)
    }
}

crate::register_extractor!(Zipped);

/// `console_scripts` and `gui_scripts` from `entry_points.txt`.
fn entry_points(t: &str, pkg: &mut Package) {
    let mut section = "";
    let mut scripts = Vec::new();
    for line in t.lines().map(str::trim) {
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = s;
        } else if matches!(section, "console_scripts" | "gui_scripts")
            && let Some((name, _)) = line.split_once('=')
        {
            scripts.push(name.trim().to_string());
        }
    }
    if !scripts.is_empty() {
        pkg.set("commands", scripts);
    }
}

/// `.pth` files at the top of a wheel run their `import` lines whenever
/// Python starts.
fn pth_hooks(zip: &Zip, src: &mut dyn Source, cx: &mut Context<'_>, pkg: &mut Package) -> Result<(), ExtractError> {
    let pth: Vec<_> = zip.entries.iter().filter(|e| !e.name.contains('/') && ext_is(&e.name, "pth")).cloned().collect();
    for e in pth.iter().take(16) {
        let body = text(&zip.read(src, e, cx, 1 << 20)?);
        if body.lines().any(|l| l.trim_start().starts_with("import ") || l.trim_start().starts_with("import\t")) {
            pkg.scripts.push(e.name.clone());
        }
    }
    Ok(())
}

fn nuspec(xml: &str, cx: &mut Context<'_>, pkg: &mut Package) -> Result<(), ExtractError> {
    let els = xml_elements(xml, cx)?;
    let text_of = |name: &str| {
        els.iter().find(|(t, _)| t.name == name).map(|(_, s)| s.trim().to_string()).filter(|s| !s.is_empty())
    };
    pkg.name = text_of("id");
    pkg.version = text_of("version");
    pkg.summary = text_of("title").or_else(|| text_of("summary"));
    pkg.description = text_of("description");
    pkg.authors = text_of("authors").map(|a| a.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default();
    pkg.homepage = text_of("projectUrl");
    pkg.license = text_of("license").or_else(|| text_of("licenseUrl"));
    pkg.repository =
        els.iter().find(|(t, _)| t.name == "repository").and_then(|(t, _)| t.attr("url")).map(str::to_string);
    let mut frameworks: Vec<String> = Vec::new();
    for (t, _) in &els {
        match t.name.as_str() {
            "group" => frameworks.extend(t.attr("targetFramework").map(str::to_string)),
            "dependency" => pkg.depend(t.attr("id").unwrap_or(""), t.attr("version").unwrap_or("")),
            _ => {}
        }
    }
    frameworks.dedup();
    if !frameworks.is_empty() {
        pkg.set("target_frameworks", frameworks);
    }
    if let Some(tags) = text_of("tags") {
        pkg.set("tags", tags.split_whitespace().collect::<Vec<_>>());
    }
    if let Some(o) = text_of("owners") {
        pkg.set("owners", o);
    }
    Ok(())
}

fn appx(xml: &str, cx: &mut Context<'_>, pkg: &mut Package) -> Result<(), ExtractError> {
    let els = xml_elements(xml, cx)?;
    let text_of = |name: &str| {
        els.iter().find(|(t, _)| t.name == name).map(|(_, s)| s.trim().to_string()).filter(|s| !s.is_empty())
    };
    if let Some((id, _)) = els.iter().find(|(t, _)| t.name == "Identity") {
        pkg.name = id.attr("Name").map(str::to_string);
        pkg.version = id.attr("Version").map(str::to_string);
        pkg.architecture = id.attr("ProcessorArchitecture").map(str::to_string);
        if let Some(p) = id.attr("Publisher") {
            pkg.set("publisher", p);
        }
    }
    pkg.summary = text_of("DisplayName").filter(|n| !n.starts_with("ms-resource:"));
    pkg.description = text_of("Description").filter(|n| !n.starts_with("ms-resource:"));
    pkg.authors.extend(text_of("PublisherDisplayName").filter(|n| !n.starts_with("ms-resource:")));
    let mut families = Vec::new();
    let mut capabilities: Vec<String> = Vec::new();
    let mut apps = Vec::new();
    let mut packages = Vec::new();
    for (t, _) in &els {
        match t.name.as_str() {
            "TargetDeviceFamily" => {
                if let Some(n) = t.attr("Name") {
                    families.push(format!("{n} {}", t.attr("MinVersion").unwrap_or("")).trim().to_string());
                }
            }
            "PackageDependency" => pkg.depend(t.attr("Name").unwrap_or(""), t.attr("MinVersion").unwrap_or("")),
            "Capability" | "DeviceCapability" | "CustomCapability" => {
                capabilities.extend(t.attr("Name").map(str::to_string));
            }
            "Application" => apps.extend(t.attr("Executable").or(t.attr("Id")).map(str::to_string)),
            "Package" => packages.extend(t.attr("FileName").map(str::to_string)),
            _ => {}
        }
    }
    if !families.is_empty() {
        pkg.set("target_device_families", families);
    }
    let restricted: Vec<&String> = capabilities.iter().filter(|c| RESTRICTED.contains(&c.as_str())).collect();
    if !restricted.is_empty() {
        pkg.set("restricted_capabilities", restricted.iter().map(|c| c.as_str()).collect::<Vec<_>>());
    }
    if !capabilities.is_empty() {
        pkg.set("capabilities", capabilities);
    }
    if !apps.is_empty() {
        pkg.set("applications", apps);
    }
    if !packages.is_empty() {
        pkg.set("packages", packages);
    }
    Ok(())
}

fn vsix(xml: &str, cx: &mut Context<'_>, pkg: &mut Package) -> Result<(), ExtractError> {
    let els = xml_elements(xml, cx)?;
    let text_of = |name: &str| {
        els.iter().find(|(t, _)| t.name == name).map(|(_, s)| s.trim().to_string()).filter(|s| !s.is_empty())
    };
    if let Some((id, _)) = els.iter().find(|(t, _)| t.name == "Identity") {
        pkg.name = id.attr("Id").map(str::to_string);
        pkg.version = id.attr("Version").map(str::to_string);
        pkg.authors.extend(id.attr("Publisher").map(str::to_string));
    }
    pkg.summary = text_of("DisplayName");
    pkg.description = text_of("Description");
    if let Some(tags) = text_of("Tags") {
        pkg.set("tags", tags.split(',').map(str::trim).collect::<Vec<_>>());
    }
    let targets: Vec<String> = els
        .iter()
        .filter(|(t, _)| t.name == "InstallationTarget")
        .filter_map(|(t, _)| {
            t.attr("Id").map(|i| format!("{i} {}", t.attr("Version").unwrap_or("")).trim().to_string())
        })
        .collect();
    if !targets.is_empty() {
        pkg.set("installation_targets", targets);
    }
    Ok(())
}

/// A VS Code extension's `package.json`.
fn vscode(v: &Value, pkg: &mut Package) {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    pkg.license = s("license");
    pkg.repository =
        v.get("repository").and_then(|r| r.as_str().or_else(|| r.get("url")?.as_str())).map(str::to_string);
    if let Some(e) = v.pointer("/engines/vscode").and_then(Value::as_str) {
        pkg.set("vscode_engine", e);
    }
    if let Some(events) = v.get("activationEvents").and_then(Value::as_array) {
        pkg.set("activation_events", Value::Array(events.clone()));
    }
    if let Some(m) = s("main").or_else(|| s("browser")) {
        pkg.set("main", m);
    }
    if let Some(Value::Object(deps)) = v.get("dependencies") {
        for (n, c) in deps {
            pkg.depend(n, c.as_str().unwrap_or(""));
        }
    }
    if let Some(Value::Object(c)) = v.get("contributes") {
        pkg.set("contributes", c.keys().cloned().collect::<Vec<_>>());
    }
}

/// A WebExtension `manifest.json` (Firefox or Chrome).
fn webextension(v: &Value, cx: &mut Context<'_>, pkg: &mut Package) {
    let s = |k: &str| v.get(k).and_then(Value::as_str).filter(|n| !n.starts_with("__MSG_")).map(str::to_string);
    pkg.name = s("name");
    pkg.version = s("version");
    pkg.description = s("description");
    pkg.homepage = s("homepage_url");
    pkg.authors
        .extend(v.get("author").and_then(|a| a.as_str().or_else(|| a.get("email")?.as_str())).map(str::to_string));
    if let Some(id) = v.pointer("/browser_specific_settings/gecko/id").or_else(|| v.pointer("/applications/gecko/id")) {
        pkg.set("gecko_id", id.clone());
    }
    if let Some(mv) = v.get("manifest_version") {
        pkg.set("manifest_version", mv.clone());
    }
    // Permissions and the broad-permission risk, as for a bare manifest.
    let perms = extension_permissions(v, cx);
    if !perms.is_empty() {
        pkg.set("permissions", perms);
    }
    if let Some(n) = v.get("content_scripts").and_then(Value::as_array).map(Vec::len) {
        pkg.set("content_scripts", n);
    }
    if v.get("background").is_some() {
        pkg.set("background", true);
    }
}

/// The CRX header before the ZIP: version, signatures, extension id.
fn crx_header(src: &mut dyn Source, pkg: &mut Package) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 16)?;
    let le = |at: usize| h.get(at..at + 4).map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let version = le(4);
    pkg.set("crx_version", version);
    if version == 2 {
        pkg.signed = Some(le(12) > 0);
        pkg.signatures = vec!["rsa".into()];
        return Ok(());
    }
    let size = le(8) as usize;
    let header = src.read_vec(12, size.min(1 << 20))?;
    let mut sigs = Vec::new();
    let mut id = None;
    for (f, data) in proto(&header) {
        match f {
            2 => sigs.push("sha256_with_rsa"),
            3 => sigs.push("sha256_with_ecdsa"),
            10000 => {
                // SignedData { crx_id: bytes = 1 }: 16 bytes, written as a–p.
                if let Some((1, raw)) = proto(data).into_iter().next()
                    && raw.len() == 16
                {
                    id = Some(
                        raw.iter().flat_map(|b| [b >> 4, b & 15]).map(|n| char::from(b'a' + n)).collect::<String>(),
                    );
                }
            }
            _ => {}
        }
    }
    pkg.signed = Some(!sigs.is_empty());
    sigs.dedup();
    pkg.signatures = sigs.into_iter().map(str::to_string).collect();
    if let Some(id) = id {
        pkg.set("extension_id", id);
    }
    Ok(())
}

/// Length-delimited fields of a protocol-buffer message.
fn proto(mut b: &[u8]) -> Vec<(u64, &[u8])> {
    fn varint(b: &mut &[u8]) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = b.split_first()?;
            *b = rest;
            v |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
    let mut out = Vec::new();
    while !b.is_empty() && out.len() < 1024 {
        let Some(key) = varint(&mut b) else { break };
        match key & 7 {
            0 => {
                if varint(&mut b).is_none() {
                    break;
                }
            }
            2 => {
                let Some(n) = varint(&mut b).and_then(|n| usize::try_from(n).ok()) else { break };
                let Some((v, rest)) = b.split_at_checked(n) else { break };
                out.push((key >> 3, v));
                b = rest;
            }
            _ => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn kinds() {
        assert_eq!(kind(&names(&["t/__init__.py", "t-1.dist-info/WHEEL"]), None).map(|k| k.0), Some("wheel"));
        assert_eq!(kind(&names(&["Tides.nuspec", "lib/x.dll"]), None).map(|k| k.0), Some("nupkg"));
        assert_eq!(kind(&names(&["AppxManifest.xml"]), None).map(|k| k.0), Some("msix"));
        assert_eq!(kind(&names(&["manifest.json"]), Some("zip")), None);
        assert_eq!(kind(&names(&["manifest.json"]), Some("xpi")).map(|k| k.0), Some("xpi"));
    }

    #[test]
    fn entry_point_names() {
        let mut p = Package::new("pypi");
        entry_points("[console_scripts]\ntides = t:main\n[other]\nx = y\n", &mut p);
        assert_eq!(p.extra.get("commands"), Some(&serde_json::json!(["tides"])));
    }

    crate::fixture_tests!("wheel", "egg", "nupkg", "msix", "msix_bundle", "vsix", "xpi", "crx");
}
