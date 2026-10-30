//! Android DEX files: the DEX version and the Android release it needs,
//! the header checksum (verified) and SHA-1 signature, the counts of
//! strings, types, prototypes, fields, methods and classes; the classes
//! defined (with their packages and source files), the packages they
//! reference, the compiler marker D8 / R8 leave (tool, version, mode,
//! minimum API level) and the source language when Kotlin metadata is
//! present.
//!
//! Specification: Android Open Source Project, "Dalvik Executable format".

use serde_json::{Map, Value};

use super::{hex, java_name, mutf8, names, package_of};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for DEX files.
pub struct Dex;

static META: ExtractorMeta = ExtractorMeta {
    id: "bytecode.dex",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "dex",
        name: "Android DEX",
        family: "bytecode",
        mimes: &["application/vnd.android.dex"],
        extensions: &["dex"],
        magic: &[Magic::prefix(b"dex\n0")],
        parent: None,
    }],
};

const HEADER: usize = 0x70;
const NO_INDEX: u32 = u32::MAX;
/// Class definitions walked for names, packages and source files.
const MAX_CLASSES: u32 = 200_000;

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

fn uleb(b: &[u8], at: &mut usize) -> Option<u32> {
    let mut v = 0u32;
    for i in 0..5 {
        let x = *b.get(*at)?;
        *at += 1;
        v |= u32::from(x & 0x7f) << (7 * i);
        if x & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// Adler-32, the header checksum.
fn adler32(b: &[u8]) -> u32 {
    let (mut a, mut s) = (1u32, 0u32);
    for chunk in b.chunks(5552) {
        for &x in chunk {
            a += u32::from(x);
            s += a;
        }
        a %= 65521;
        s %= 65521;
    }
    (s << 16) | a
}

/// The Android release that introduced a DEX version.
fn api_level(version: &str) -> Option<u32> {
    match version {
        "037" => Some(24),
        "038" => Some(26),
        "039" => Some(28),
        _ => None,
    }
}

struct Dexfile<'a> {
    b: &'a [u8],
    strings: (u32, usize),
    types: (u32, usize),
}

impl Dexfile<'_> {
    fn string(&self, i: u32) -> Option<String> {
        if i >= self.strings.0 {
            return None;
        }
        let off = u32_at(self.b, self.strings.1 + i as usize * 4)? as usize;
        let mut at = off;
        uleb(self.b, &mut at)?;
        let rest = self.b.get(at..)?;
        let end = rest.iter().position(|&c| c == 0)?;
        Some(mutf8(&rest[..end]))
    }

    fn type_name(&self, i: u32) -> Option<String> {
        if i >= self.types.0 {
            return None;
        }
        self.string(u32_at(self.b, self.types.1 + i as usize * 4)?)
    }
}

impl Extractor for Dex {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // header, classes, types, marker
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len().min(cx.parse_limit() as u64);
        let b = src.read_vec(0, usize::try_from(len).unwrap_or(0))?;
        if b.len() < HEADER || !b.starts_with(b"dex\n") {
            return Err(ExtractError::malformed("DEX header"));
        }
        let version = String::from_utf8_lossy(&b[4..7]).into_owned();
        cx.format_set("version", version.clone());
        if let Some(api) = api_level(&version) {
            cx.format_set("min_api_level", api);
        }
        let field = |at: usize| u32_at(&b, at).unwrap_or(0);
        if field(40) != 0x1234_5678 {
            cx.format_set("byte_order", "big_endian");
            return Ok(());
        }
        let file_size = field(32);
        let checksum = field(8);
        if (file_size as usize) <= b.len() && file_size as usize >= 12 {
            cx.format_set("checksum_valid", adler32(&b[12..file_size as usize]) == checksum);
        }
        if u64::from(file_size) != src.len() {
            cx.warn(format!("header gives {file_size} bytes, the file has {}", src.len()));
        }
        cx.format_set("sha1", hex(&b[12..32]));
        let mut counts = Map::new();
        for (key, at) in
            [("strings", 56), ("types", 64), ("prototypes", 72), ("fields", 80), ("methods", 88), ("classes", 96)]
        {
            counts.insert(key.into(), field(at).into());
        }
        cx.format_set("counts", Value::Object(counts));
        let d = Dexfile { b: &b, strings: (field(56), field(60) as usize), types: (field(64), field(68) as usize) };

        // Classes defined here.
        let (n, off) = (field(96).min(MAX_CLASSES), field(100) as usize);
        let mut classes = Vec::new();
        let mut packages: Vec<(String, u32)> = Vec::new();
        let mut sources = Vec::new();
        let (mut methods, mut fields) = (0u64, 0u64);
        for i in 0..n as usize {
            let at = off + i * 32;
            let Some(class_idx) = u32_at(&b, at) else { break };
            let name = d.type_name(class_idx).map(|t| java_name(&t)).unwrap_or_default();
            let pkg = package_of(&name).unwrap_or("").to_string();
            match packages.iter_mut().find(|(p, _)| *p == pkg) {
                Some((_, c)) => *c += 1,
                None => packages.push((pkg, 1)),
            }
            classes.push(name);
            let source = u32_at(&b, at + 16).unwrap_or(NO_INDEX);
            if source != NO_INDEX
                && let Some(s) = d.string(source)
                && !sources.contains(&s)
            {
                sources.push(s);
            }
            let data = u32_at(&b, at + 24).unwrap_or(0) as usize;
            if data != 0 {
                let mut p = data;
                let sizes: Vec<u32> = (0..4).map_while(|_| uleb(&b, &mut p)).collect();
                if let [sf, inf, dm, vm] = sizes[..] {
                    fields += u64::from(sf) + u64::from(inf);
                    methods += u64::from(dm) + u64::from(vm);
                }
            }
            if i % 4096 == 4095 {
                cx.checkpoint()?;
            }
        }
        if !classes.is_empty() {
            cx.format_set("defined_methods", methods);
            cx.format_set("defined_fields", fields);
            cx.format_set("class_names", names(&classes));
            packages.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let list: Vec<String> = packages
                .iter()
                .map(|(p, c)| format!("{} ({c})", if p.is_empty() { "(default package)" } else { p }))
                .collect();
            cx.format_set("packages", names(&list));
        }
        if !sources.is_empty() {
            cx.format_set("source_files", names(&sources));
        }

        // Types referenced but not defined here.
        let mut referenced: Vec<String> = Vec::new();
        let mut kotlin = false;
        for i in 0..d.types.0.min(1 << 20) {
            let Some(t) = d.type_name(i) else { break };
            if !t.starts_with('L') {
                continue;
            }
            kotlin |= t == "Lkotlin/Metadata;";
            let name = java_name(&t);
            if let Some(pkg) = package_of(&name)
                && !packages.iter().any(|(p, _)| p == pkg)
                && !referenced.iter().any(|r| r == pkg)
            {
                referenced.push(pkg.to_string());
            }
        }
        if !referenced.is_empty() {
            referenced.sort();
            cx.format_set("referenced_packages", names(&referenced));
        }
        if kotlin {
            cx.format_set("language", "kotlin");
        }

        // D8 / R8 / L8 sort their marker (`~~D8{json}`) last among the strings.
        for i in (0..d.strings.0).rev().take(8) {
            let Some(s) = d.string(i) else { break };
            let Some((tool, json)) = ["D8", "R8", "L8"]
                .iter()
                .find_map(|t| s.strip_prefix("~~").and_then(|r| r.strip_prefix(t)).map(|j| (*t, j)))
            else {
                continue;
            };
            let mut m = Map::new();
            m.insert("tool".into(), tool.into());
            if let Ok(Value::Object(o)) = serde_json::from_str::<Value>(json) {
                for (k, key) in [("version", "version"), ("compilation-mode", "mode"), ("min-api", "min_api")] {
                    if let Some(v) = o.get(k) {
                        m.insert(key.into(), v.clone());
                    }
                }
                if let Some(api) = o.get("min-api").and_then(Value::as_u64) {
                    cx.format_set("min_api_level", api);
                }
            }
            cx.format_set("compiler", Value::Object(m));
            break;
        }
        Ok(())
    }
}

crate::register_extractor!(Dex);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_matches_the_reference() {
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
        assert_eq!(adler32(&[]), 1);
    }

    #[test]
    fn dex_versions_map_to_api_levels() {
        assert_eq!(api_level("038"), Some(26));
        assert_eq!(api_level("041"), None);
    }

    crate::fixture_tests!("dex");
}
