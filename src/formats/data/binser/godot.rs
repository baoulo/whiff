//! Godot resources and scenes:
//! * text (`.tres`, `.tscn`): kind (resource or scene), resource type,
//!   format version, UID, external resources (count, types, scripts),
//!   sub-resources by type, nodes (count, root, types), signal
//!   connections;
//! * binary (`.res`, `.scn`, `RSRC` / compressed `RSCC`): byte order,
//!   engine version, format version, resource type.
//!
//! Specification: Godot docs "TSCN file format"; `core/io/resource_format_binary.cpp`.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, TextRole,
    truncate_chars,
};

/// Extractor for Godot resources.
pub struct Godot;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.godot",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "godot_resource",
            name: "Godot resource",
            family: "data.binser",
            mimes: &[],
            extensions: &["tres", "tscn"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "godot_binary_resource",
            name: "Godot binary resource",
            family: "data.binser",
            mimes: &[],
            extensions: &["res", "scn"],
            magic: &[Magic::at(0, b"RSRC"), Magic::at(0, b"RSCC")],
            parent: None,
        },
    ],
};

/// The value of `key="…"` or `key=…` in a section header.
fn attr<'a>(header: &'a str, key: &str) -> Option<&'a str> {
    let i = header.find(&format!("{key}="))? + key.len() + 1;
    let rest = &header[i..];
    if let Some(r) = rest.strip_prefix('"') { r.split('"').next() } else { rest.split([' ', ']']).next() }
}

fn histogram(m: BTreeMap<String, u64>) -> Value {
    let mut v: Vec<(String, u64)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Value::Object(v.into_iter().take(40).map(|(k, n)| (k, n.into())).collect::<Map<_, _>>())
}

impl Extractor for Godot {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head.strip_prefix(b"\xef\xbb\xbf").unwrap_or(probe.head);
        (h.starts_with(b"[gd_resource") || h.starts_with(b"[gd_scene"))
            .then_some(Sniff { format: "godot_resource", confidence: 0.97 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "godot_binary_resource" {
            let (b, _) = cx.read_bytes(src)?;
            return binary(&b, cx);
        }
        let text = cx.read_text(src)?.text;
        cx.emit_text(TextRole::Data, &text);
        let mut ext_types: BTreeMap<String, u64> = BTreeMap::new();
        let mut sub_types: BTreeMap<String, u64> = BTreeMap::new();
        let mut node_types: BTreeMap<String, u64> = BTreeMap::new();
        let mut scripts = Vec::new();
        let (mut ext, mut sub, mut nodes, mut connections) = (0u64, 0u64, 0u64, 0u64);
        let mut first = true;
        for line in text.lines().filter(|l| l.starts_with('[')) {
            let section = line.trim_start_matches('[').split([' ', ']']).next().unwrap_or("");
            if first {
                first = false;
                let kind = match section {
                    "gd_scene" => "scene",
                    "gd_resource" => "resource",
                    _ => return Err(ExtractError::malformed("no gd_scene / gd_resource header")),
                };
                cx.format_set("kind", kind);
                if let Some(t) = attr(line, "type") {
                    cx.format_set("resource_type", truncate_chars(t, 100));
                }
                if let Some(f) = attr(line, "format") {
                    cx.format_set("format_version", truncate_chars(f, 10));
                }
                if let Some(u) = attr(line, "uid") {
                    cx.format_set("uid", truncate_chars(u, 100));
                }
                if let Some(s) = attr(line, "script_class") {
                    cx.format_set("script_class", truncate_chars(s, 100));
                }
                continue;
            }
            match section {
                "ext_resource" => {
                    ext += 1;
                    let t = attr(line, "type").unwrap_or("?");
                    *ext_types.entry(truncate_chars(t, 60)).or_default() += 1;
                    if t == "Script"
                        && let Some(p) = attr(line, "path")
                        && scripts.len() < 50
                    {
                        scripts.push(truncate_chars(p, 300));
                    }
                }
                "sub_resource" => {
                    sub += 1;
                    *sub_types.entry(truncate_chars(attr(line, "type").unwrap_or("?"), 60)).or_default() += 1;
                }
                "node" => {
                    nodes += 1;
                    if nodes == 1
                        && let Some(n) = attr(line, "name")
                    {
                        cx.format_set("root_node", truncate_chars(n, 100));
                    }
                    if let Some(t) = attr(line, "type") {
                        *node_types.entry(truncate_chars(t, 60)).or_default() += 1;
                    } else if attr(line, "instance").is_some() {
                        *node_types.entry("(instance)".into()).or_default() += 1;
                    }
                }
                "connection" => connections += 1,
                _ => {}
            }
        }
        if first {
            return Err(ExtractError::malformed("no section"));
        }
        cx.format_set("external_resources", ext);
        if !ext_types.is_empty() {
            cx.format_set("external_types", histogram(ext_types));
        }
        if !scripts.is_empty() {
            cx.format_set("scripts", scripts);
        }
        cx.format_set("sub_resources", sub);
        if !sub_types.is_empty() {
            cx.format_set("sub_resource_types", histogram(sub_types));
        }
        if nodes > 0 {
            cx.format_set("nodes", nodes);
            cx.format_set("node_types", histogram(node_types));
        }
        if connections > 0 {
            cx.format_set("connections", connections);
        }
        Ok(())
    }
}

crate::register_extractor!(Godot);

fn binary(b: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    if b.starts_with(b"RSCC") {
        // Compressed: a FileAccessCompressed stream around the resource.
        cx.format_set("compressed", true);
        return Ok(());
    }
    let big = b.get(4..8).ok_or_else(|| ExtractError::malformed("RSRC header"))? != [0, 0, 0, 0];
    let u = |at: usize| -> Option<u32> {
        let raw: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
        Some(if big { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) })
    };
    cx.format_set("byte_order", if big { "big_endian" } else { "little_endian" });
    if u(8).is_some_and(|r| r != 0) {
        cx.format_set("real_64", true);
    }
    let (major, minor, fmt) = (u(12), u(16), u(20));
    if let (Some(a), Some(b)) = (major, minor) {
        cx.format_set("engine_version", format!("{a}.{b}"));
    }
    if let Some(f) = fmt {
        cx.format_set("format_version", f);
    }
    let len = u(24).and_then(|n| usize::try_from(n).ok()).ok_or_else(|| ExtractError::malformed("type length"))?;
    let raw = b.get(28..28 + len.min(512)).ok_or_else(|| ExtractError::malformed("type name"))?;
    let t = String::from_utf8_lossy(raw.split(|&c| c == 0).next().unwrap_or(raw)).into_owned();
    cx.format_set("resource_type", truncate_chars(&t, 100));
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::plugin::testing::report_for;

    #[test]
    fn scene_sections() {
        let t = "[gd_scene load_steps=3 format=3 uid=\"uid://b1\"]\n\n\
            [ext_resource type=\"Script\" path=\"res://tide.gd\" id=\"1\"]\n\
            [sub_resource type=\"CircleShape2D\" id=\"2\"]\n\
            [node name=\"Harbour\" type=\"Node2D\"]\nscript = ExtResource(\"1\")\n\
            [node name=\"Buoy\" type=\"Area2D\" parent=\".\"]\n\
            [connection signal=\"body_entered\" from=\"Buoy\" to=\".\" method=\"_on\"]\n";
        let r = report_for("harbour.tscn", t.as_bytes());
        let f = &r.format["godot_resource"];
        assert_eq!((f["kind"].as_str(), f["nodes"].as_u64()), (Some("scene"), Some(2)));
        assert_eq!(f["root_node"], "Harbour");
        assert_eq!(f["scripts"][0], "res://tide.gd");
    }

    crate::fixture_tests!("godot_resource", "godot_binary_resource");
}
