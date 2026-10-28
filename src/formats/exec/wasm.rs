//! WebAssembly binary modules (and the component-model layer): the
//! section inventory (types, functions, tables, memories, globals, data
//! and element segments), imports by module (WASI is named) and exports,
//! memory limits (shared, 64-bit), the start function, custom sections:
//! the module name, `producers` (languages, tools, SDKs), target features,
//! DWARF and source maps, and whether it is a relocatable object or a
//! dynamic library (`linking`, `dylink.0`).
//!
//! Specifications: WebAssembly Core Specification 2.0 (binary format), the
//! tool conventions for `producers`, `target_features`, linking and dynamic
//! linking, and the component model's binary layer.

use serde_json::{Map, Value, json};

use super::{names, uleb};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for WebAssembly modules.
pub struct Wasm;

static META: ExtractorMeta = ExtractorMeta {
    id: "exec.wasm",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "wasm",
        name: "WebAssembly module",
        family: "exec",
        mimes: &["application/wasm"],
        extensions: &["wasm"],
        magic: &[Magic::prefix(b"\0asm")],
        parent: None,
    }],
};

const MAX_SECTIONS: usize = 4096;
const MAX_ENTRIES: u64 = 1 << 20;

/// A cursor over a section's bytes.
struct Cur<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cur<'a> {
    fn uleb(&mut self) -> Option<u64> {
        let (v, n) = uleb(self.b.get(self.at..)?)?;
        self.at += n;
        Some(v)
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.b.get(self.at)?;
        self.at += 1;
        Some(b)
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }

    fn name(&mut self) -> Option<String> {
        let n = usize::try_from(self.uleb()?).ok()?;
        Some(String::from_utf8_lossy(self.bytes(n)?).into_owned())
    }

    /// Limits: flags, minimum, optional maximum.
    fn limits(&mut self) -> Option<(u8, u64, Option<u64>)> {
        let flags = self.byte()?;
        let min = self.uleb()?;
        let max = if flags & 1 != 0 { Some(self.uleb()?) } else { None };
        Some((flags, min, max))
    }
}

impl Extractor for Wasm {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // one section kind after another
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len().min(cx.parse_limit() as u64);
        let data = src.read_vec(0, usize::try_from(len).unwrap_or(0))?;
        if data.len() < 8 {
            return Err(ExtractError::malformed("WebAssembly header"));
        }
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version != 1 {
            // Component model: version 0x0d, layer 1.
            if data[4..8] == [0x0d, 0, 1, 0] {
                cx.format_set("kind", "component");
                cx.format_set("version", 13);
                return Ok(());
            }
            cx.format_set("version", version);
            return Err(ExtractError::malformed("unknown WebAssembly version"));
        }
        cx.format_set("version", 1);
        let mut kind = "module";
        let mut counts = Map::new();
        let mut custom = Vec::new();
        let mut imports = Vec::new();
        let mut by_module: Map<String, Value> = Map::new();
        let mut exports = Vec::new();
        let mut at = 8usize;
        let mut sections = 0;
        while at < data.len() && sections < MAX_SECTIONS {
            sections += 1;
            let id = data[at];
            let Some((size, n)) = uleb(&data[at + 1..]) else { break };
            let start = at + 1 + n;
            let Some(end) = usize::try_from(size).ok().and_then(|s| start.checked_add(s)) else { break };
            if end > data.len() {
                if (data.len() as u64) < src.len() {
                    cx.warn("module larger than the parse limit; later sections not read");
                } else {
                    cx.warn("section runs past the end of the file");
                }
                break;
            }
            let mut c = Cur { b: &data[start..end], at: 0 };
            let count_key = match id {
                1 => Some("types"),
                3 => Some("functions"),
                4 => Some("tables"),
                6 => Some("globals"),
                9 => Some("element_segments"),
                10 => Some("function_bodies"),
                11 => Some("data_segments"),
                13 => Some("tags"),
                _ => None,
            };
            match id {
                0 => {
                    let Some(name) = c.name() else { break };
                    match name.as_str() {
                        "name" => module_name(&mut c, cx),
                        "producers" => producers(&mut c, cx),
                        "target_features" => {
                            let n = c.uleb().unwrap_or(0).min(256);
                            let mut f = Vec::new();
                            for _ in 0..n {
                                let (Some(prefix), Some(name)) = (c.byte(), c.name()) else { break };
                                if prefix != b'-' {
                                    f.push(name);
                                }
                            }
                            cx.format_set("target_features", names(&f));
                        }
                        "sourceMappingURL" => {
                            if let Some(u) = c.name() {
                                cx.format_set("source_map", u);
                            }
                        }
                        "linking" => kind = "object",
                        "dylink" | "dylink.0" => kind = "shared_library",
                        n if n.starts_with(".debug_") => {
                            cx.format_set("debug", json!({"dwarf": true}));
                        }
                        _ => {}
                    }
                    if custom.len() < 64 {
                        custom.push(name);
                    }
                }
                2 => {
                    let n = c.uleb().unwrap_or(0).min(MAX_ENTRIES);
                    counts.insert("imports".into(), n.into());
                    for _ in 0..n {
                        let (Some(module), Some(field), Some(k)) = (c.name(), c.name(), c.byte()) else { break };
                        let ok = match k {
                            0 => c.uleb().is_some(),
                            1 => c.byte().is_some() && c.limits().is_some(),
                            2 => c.limits().is_some_and(|l| {
                                memory(cx, l, true);
                                true
                            }),
                            3 => c.bytes(2).is_some(),
                            4 => c.byte().is_some() && c.uleb().is_some(),
                            _ => false,
                        };
                        if !ok {
                            break;
                        }
                        let e = by_module.entry(module.clone()).or_insert(Value::from(0));
                        *e = Value::from(e.as_u64().unwrap_or(0) + 1);
                        imports.push(format!("{module}.{field}"));
                    }
                }
                5 => {
                    let n = c.uleb().unwrap_or(0);
                    counts.insert("memories".into(), n.into());
                    if let Some(l) = c.limits() {
                        memory(cx, l, false);
                    }
                }
                7 => {
                    let n = c.uleb().unwrap_or(0).min(MAX_ENTRIES);
                    counts.insert("exports".into(), n.into());
                    for _ in 0..n {
                        let (Some(name), Some(_), Some(_)) = (c.name(), c.byte(), c.uleb()) else { break };
                        exports.push(name);
                    }
                }
                8 => {
                    if let Some(f) = c.uleb() {
                        cx.format_set("start_function", f);
                    }
                }
                _ => {
                    if let Some(key) = count_key
                        && let Some(n) = c.uleb()
                    {
                        counts.insert(key.into(), n.into());
                    }
                }
            }
            at = end;
        }
        cx.format_set("kind", kind);
        if !counts.is_empty() {
            cx.format_set("counts", Value::Object(counts));
        }
        if !by_module.is_empty() {
            if by_module.keys().any(|m| m.starts_with("wasi")) {
                cx.format_set("wasi", true);
            }
            cx.format_set("import_modules", Value::Object(by_module));
        }
        if !imports.is_empty() {
            cx.format_set("imports", names(&imports));
        }
        if !exports.is_empty() {
            cx.format_set("exports", names(&exports));
        }
        if !custom.is_empty() {
            cx.format_set("custom_sections", names(&custom));
        }
        Ok(())
    }
}

crate::register_extractor!(Wasm);

fn memory(cx: &mut Context<'_>, (flags, min, max): (u8, u64, Option<u64>), imported: bool) {
    let mut m = Map::new();
    m.insert("min_pages".into(), min.into());
    if let Some(max) = max {
        m.insert("max_pages".into(), max.into());
    }
    if flags & 2 != 0 {
        m.insert("shared".into(), true.into());
    }
    if flags & 4 != 0 {
        m.insert("memory64".into(), true.into());
    }
    if imported {
        m.insert("imported".into(), true.into());
    }
    cx.format_set("memory", Value::Object(m));
}

/// The `name` section's module name (subsection 0).
fn module_name(c: &mut Cur<'_>, cx: &mut Context<'_>) {
    while let (Some(id), Some(size)) = (c.byte(), c.uleb()) {
        let Ok(size) = usize::try_from(size) else { return };
        if id == 0 {
            if let Some(n) = c.name() {
                cx.format_set("module_name", n);
            }
            return;
        }
        if c.bytes(size).is_none() {
            return;
        }
    }
}

/// `producers`: fields (language, processed-by, sdk) of `(name, version)` pairs.
fn producers(c: &mut Cur<'_>, cx: &mut Context<'_>) {
    let mut out = Map::new();
    let n = c.uleb().unwrap_or(0).min(16);
    for _ in 0..n {
        let Some(field) = c.name() else { break };
        let m = c.uleb().unwrap_or(0).min(64);
        let mut values = Vec::new();
        for _ in 0..m {
            let (Some(name), Some(version)) = (c.name(), c.name()) else { break };
            values.push(if version.is_empty() { name } else { format!("{name} {version}") });
        }
        out.insert(field, names(&values));
    }
    if !out.is_empty() {
        cx.format_set("producers", Value::Object(out));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_reads_names_and_limits() {
        let b = [5, b's', b'a', b'l', b't', b'y', 0x03, 1, 0x81, 0x01];
        let mut c = Cur { b: &b, at: 0 };
        assert_eq!(c.name().as_deref(), Some("salty"));
        assert_eq!(c.limits(), Some((3, 1, Some(129))));
        assert_eq!(c.byte(), None);
    }

    crate::fixture_tests!("wasm");
}
