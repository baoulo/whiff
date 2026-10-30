//! Android compiled resources outside an APK:
//! * binary XML (`AndroidManifest.xml`, `res/**/*.xml` as `aapt2` writes
//!   them): root element, element count and histogram, attributes, and for
//!   a manifest the package, version, SDK levels and permissions;
//! * resource tables (`resources.arsc`): packages (ID, name, resource
//!   types, key count), the global string pool size, configurations and
//!   the locales translated.
//!
//! Specification: AOSP `libandroidfw/include/androidfw/ResourceTypes.h`
//! (`ResChunk_header`, `ResXMLTree`, `ResTable_package`, `ResTable_type`,
//! `ResTable_config`).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use super::{Element, binary_xml, string_pool};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, truncate_chars};

/// Extractor for Android binary XML and resource tables.
pub struct AndroidResources;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.android",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "android_binary_xml",
            name: "Android binary XML",
            family: "data.binser",
            mimes: &[],
            extensions: &[],
            magic: &[Magic::at(0, b"\x03\x00\x08\x00")],
            parent: None,
        },
        FormatSpec {
            id: "arsc",
            name: "Java .properties-like binary: Android resources.arsc",
            family: "data.binser",
            mimes: &[],
            extensions: &["arsc"],
            magic: &[Magic::at(0, b"\x02\x00\x0c\x00")],
            parent: None,
        },
    ],
};

fn le16(b: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?)))
}

fn le32(b: &[u8], at: usize) -> Option<usize> {
    usize::try_from(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?)).ok()
}

/// The chunks inside `b[start..]`: `(type, header size, bytes)`.
fn chunks(b: &[u8], start: usize) -> Vec<(usize, usize, &[u8])> {
    let mut out = Vec::new();
    let mut at = start;
    while let (Some(ty), Some(h), Some(size)) = (le16(b, at), le16(b, at + 2), le32(b, at + 4)) {
        if size < 8 || at + size > b.len() || out.len() > 100_000 {
            break;
        }
        out.push((ty, h, &b[at..at + size]));
        at += size;
    }
    out
}

impl Extractor for AndroidResources {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, _) = cx.read_bytes(src)?;
        if cx.format_id() == "arsc" {
            table(&data, cx)
        } else {
            let els = binary_xml(&data)?;
            xml(&els, cx);
            Ok(())
        }
    }
}

crate::register_extractor!(AndroidResources);

fn xml(els: &[Element], cx: &mut Context<'_>) {
    let Some(root) = els.first() else { return };
    cx.format_set("root", truncate_chars(&root.name, 100));
    cx.format_set("elements", els.len());
    cx.format_set("attributes", els.iter().map(|e| e.attrs.len()).sum::<usize>());
    cx.format_set("max_depth", els.iter().map(|e| e.depth).max().unwrap_or(0));
    let mut hist: BTreeMap<&str, u64> = BTreeMap::new();
    for e in els {
        *hist.entry(&e.name).or_default() += 1;
    }
    let mut v: Vec<(&str, u64)> = hist.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let m: Map<String, Value> = v.into_iter().take(30).map(|(k, n)| (truncate_chars(k, 100), n.into())).collect();
    cx.format_set("element_types", Value::Object(m));
    if root.name == "manifest" {
        for (attr, key) in [("package", "package"), ("versionName", "version_name"), ("versionCode", "version_code")] {
            if let Some(v) = root.str(attr) {
                cx.format_set(key, truncate_chars(&v, 200));
            }
        }
        if let Some(sdk) = els.iter().find(|e| e.name == "uses-sdk") {
            for (attr, key) in [("minSdkVersion", "min_sdk"), ("targetSdkVersion", "target_sdk")] {
                if let Some(v) = sdk.str(attr) {
                    cx.format_set(key, v);
                }
            }
        }
        let perms: Vec<String> = els
            .iter()
            .filter(|e| e.name == "uses-permission" || e.name == "uses-permission-sdk-23")
            .filter_map(|e| e.str("name"))
            .take(200)
            .collect();
        if !perms.is_empty() {
            cx.format_set("permissions", perms);
        }
    }
}

fn table(b: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let header = le16(b, 2).filter(|&h| h >= 12).ok_or_else(|| ExtractError::malformed("table header"))?;
    cx.format_set("declared_packages", le32(b, 8).unwrap_or(0));
    let mut packages = Vec::new();
    let mut locales: BTreeSet<String> = BTreeSet::new();
    let (mut configs, mut entries) = (0u64, 0u64);
    for (ty, _, chunk) in chunks(b, header) {
        match ty {
            0x0001 => cx.format_set("strings", le32(chunk, 8).unwrap_or(0)),
            0x0200 => {
                let id = le32(chunk, 8).unwrap_or(0);
                let units: Vec<u16> = chunk
                    .get(12..268)
                    .unwrap_or_default()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .take_while(|&u| u != 0)
                    .collect();
                let name = String::from_utf16_lossy(&units);
                let (type_at, key_at) = (le32(chunk, 268).unwrap_or(0), le32(chunk, 276).unwrap_or(0));
                let pool = |at: usize| chunk.get(at..).map(string_pool).unwrap_or_default();
                let types = if type_at > 0 { pool(type_at) } else { Vec::new() };
                let keys = if key_at > 0 { pool(key_at).len() } else { 0 };
                let hsize = le16(chunk, 2).unwrap_or(288);
                for (cty, _, c) in chunks(chunk, hsize) {
                    if cty == 0x0201 {
                        configs += 1;
                        entries += le32(c, 12).unwrap_or(0) as u64;
                        // ResTable_config at 20: language at +8, country at +10.
                        let lang = c.get(28..30).unwrap_or_default();
                        let country = c.get(30..32).unwrap_or_default();
                        if lang.iter().all(u8::is_ascii_lowercase) && lang.len() == 2 {
                            let mut l = String::from_utf8_lossy(lang).into_owned();
                            if country.iter().all(u8::is_ascii_uppercase) && country.len() == 2 {
                                l = format!("{l}-{}", String::from_utf8_lossy(country));
                            }
                            locales.insert(l);
                        }
                    }
                }
                packages.push(json!({
                    "id": format!("0x{id:02x}"),
                    "name": truncate_chars(&name, 200),
                    "types": types.iter().take(100).map(|t| truncate_chars(t, 60)).collect::<Vec<_>>(),
                    "keys": keys,
                }));
            }
            _ => {}
        }
    }
    if packages.is_empty() {
        return Err(ExtractError::malformed("no package in the resource table"));
    }
    cx.format_set("packages", Value::Array(packages));
    cx.format_set("configurations", configs);
    cx.format_set("entries", entries);
    if !locales.is_empty() {
        cx.format_set("locales", locales.into_iter().collect::<Vec<_>>());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_walk() {
        let mut b = vec![0u8; 4];
        b.extend([1, 0, 8, 0, 8, 0, 0, 0]);
        b.extend([2, 0, 8, 0, 9, 0, 0, 0, 0]);
        let c = chunks(&b, 4);
        assert_eq!(c.iter().map(|(t, _, x)| (*t, x.len())).collect::<Vec<_>>(), [(1, 8), (2, 9)]);
    }

    crate::fixture_tests!("android_binary_xml", "arsc");
}
