//! Electron application archives (`.asar`): a JSON header (Chromium
//! pickle framing) lists every file with its size, offset, executable bit,
//! integrity hashes and whether it is kept outside the archive
//! (`unpacked`); symbolic links have a target. The app's `package.json`
//! gives name, version, description, licence, author and entry point.
//! Files stored in the archive are handed on.
//!
//! Specification: electron/asar `README` ("Format") and its `pickle.js`.

use serde_json::Value;

use super::archive::{Entry, Inventory, Kind, Stored, stored_children, wanted};
use super::{Package, person};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source};

/// Extractor for Electron archives.
pub struct Asar;

static META: ExtractorMeta = ExtractorMeta {
    id: "package.asar",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "asar",
        name: "Electron archive",
        family: "package",
        mimes: &["application/x-asar"],
        extensions: &["asar"],
        magic: &[],
        parent: None,
    }],
};

/// Largest header read.
const MAX_HEADER: u32 = 64 << 20;
/// Folder depth followed.
const MAX_DEPTH: usize = 64;

/// `(header JSON offset, length, data start)` from the pickle framing.
fn framing(head: &[u8]) -> Option<(usize, usize, u64)> {
    let le = |at: usize| head.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    if le(0)? != 4 {
        return None;
    }
    let header = le(4)?;
    let json = le(12)?;
    (header <= MAX_HEADER && json < header).then_some((16, json as usize, 8 + u64::from(header)))
}

/// Walk the `files` tree, depth first.
fn walk(node: &Value, prefix: &str, depth: usize, out: &mut Vec<(String, Value)>) {
    let Some(files) = node.get("files").and_then(Value::as_object) else { return };
    for (name, v) in files {
        if out.len() >= 1 << 18 {
            return;
        }
        let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
        let is_dir = v.get("files").is_some();
        out.push((if is_dir { format!("{path}/") } else { path.clone() }, v.clone()));
        if is_dir && depth < MAX_DEPTH {
            walk(v, &path, depth + 1, out);
        }
    }
}

impl Extractor for Asar {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let (at, _, _) = framing(probe.head)?;
        probe.head.get(at..)?.starts_with(b"{\"files\":").then_some(Sniff { format: "asar", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (at, len, data_start) = framing(src.head()).ok_or_else(|| ExtractError::malformed("no asar header"))?;
        let json = src.read_vec(at as u64, len)?;
        let header: Value = serde_json::from_slice(&json).map_err(|e| ExtractError::malformed(e.to_string()))?;
        let mut files = Vec::new();
        walk(&header, "", 0, &mut files);
        let mut pkg = Package::new("electron");
        let mut inv = Inventory::new();
        let mut pending: Vec<Stored> = Vec::new();
        let (mut unpacked, mut executable, mut integrity) = (0u64, 0u64, 0u64);
        let mut manifest: Option<(u64, u64)> = None;
        for (path, v) in &files {
            let kind = if path.ends_with('/') {
                Kind::Dir
            } else if v.get("link").is_some() {
                Kind::Symlink
            } else {
                Kind::File
            };
            let size = v.get("size").and_then(Value::as_u64);
            let offset = v.get("offset").and_then(|o| o.as_str().and_then(|s| s.parse().ok()).or_else(|| o.as_u64()));
            let outside = v.get("unpacked").and_then(Value::as_bool) == Some(true);
            unpacked += u64::from(outside);
            executable += u64::from(v.get("executable").and_then(Value::as_bool) == Some(true));
            integrity += u64::from(v.get("integrity").is_some());
            let e = Entry {
                path: path.clone(),
                kind,
                size: if kind == Kind::File { size } else { Some(0) },
                compressed: if kind == Kind::File && !outside { size } else { Some(0) },
                link: v.get("link").and_then(Value::as_str).map(str::to_string),
                ..Entry::default()
            };
            if let (Some(o), Some(n)) = (offset, size)
                && !outside
            {
                if path == "package.json" {
                    manifest = Some((data_start + o, n));
                }
                if wanted(&e) && pending.len() < cx.child_room() {
                    pending.push((path.clone(), data_start + o, n));
                }
            }
            inv.push(e);
        }
        if let Some((o, n)) = manifest
            && let Ok(Value::Object(m)) =
                serde_json::from_slice::<Value>(&src.read_vec(o, usize::try_from(n.min(4 << 20)).unwrap_or(0))?)
        {
            let s = |k: &str| m.get(k).and_then(Value::as_str).map(str::to_string);
            pkg.name = s("productName").or_else(|| s("name"));
            pkg.version = s("version");
            pkg.description = s("description");
            pkg.license = s("license");
            pkg.homepage = s("homepage");
            pkg.authors
                .extend(m.get("author").and_then(|a| a.as_str().or_else(|| a.get("name")?.as_str())).and_then(person));
            if let Some(main) = s("main") {
                pkg.set("main", main);
            }
            if let Some(Value::Object(deps)) = m.get("dependencies") {
                for (n, c) in deps {
                    pkg.depend(n, c.as_str().unwrap_or(""));
                }
            }
        }
        if unpacked > 0 {
            pkg.set("unpacked_files", unpacked);
        }
        if executable > 0 {
            pkg.set("executable_files", executable);
        }
        if integrity > 0 {
            pkg.set("integrity_hashes", integrity);
        }
        pkg.write(cx);
        inv.report(cx, src.len());
        stored_children(src, cx, pending)
    }
}

crate::register_extractor!(Asar);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::cast_possible_truncation)] // a short test header
    fn pickle_framing() {
        let json = br#"{"files":{}}"#;
        let mut h = Vec::new();
        h.extend_from_slice(&4u32.to_le_bytes());
        h.extend_from_slice(&(8 + json.len() as u32 + 4).to_le_bytes());
        h.extend_from_slice(&(4 + json.len() as u32).to_le_bytes());
        h.extend_from_slice(&(json.len() as u32).to_le_bytes());
        h.extend_from_slice(json);
        assert_eq!(framing(&h), Some((16, json.len(), 8 + 8 + json.len() as u64 + 4)));
        assert_eq!(framing(b"\x05\0\0\0"), None);
    }

    crate::fixture_tests!("asar");
}
