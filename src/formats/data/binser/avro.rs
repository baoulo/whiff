//! Apache Avro object container files and schemas:
//! * container files (`Obj\x01`): the writer schema (name, namespace,
//!   type, fields with their types, doc), the codec, other metadata keys,
//!   blocks and the record count from the block headers (the records are
//!   not decoded);
//! * schema files (`.avsc`): the same schema summary.
//!
//! Specification: Apache Avro 1.12 specification ("Object Container
//! Files", "Schema Declaration").

use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for Avro containers and schemas.
pub struct Avro;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.avro",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "avro",
            name: "Apache Avro container",
            family: "data.binser",
            mimes: &["application/avro"],
            extensions: &["avro"],
            magic: &[Magic::at(0, b"Obj\x01")],
            parent: None,
        },
        FormatSpec {
            id: "avro_schema",
            name: "Avro schema",
            family: "data.binser",
            mimes: &[],
            extensions: &["avsc"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

/// Fields listed per record.
const MAX_FIELDS: usize = 200;
/// Blocks walked.
const MAX_BLOCKS: u64 = 10_000_000;

/// A zig-zag varint (Avro `long`).
fn long(b: &[u8], at: &mut usize) -> Option<i64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let x = *b.get(*at)?;
        *at += 1;
        v |= u64::from(x & 0x7f) << shift;
        if x & 0x80 == 0 {
            return Some((v >> 1).cast_signed() ^ -((v & 1).cast_signed()));
        }
    }
    None
}

fn bytes<'a>(b: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let n = usize::try_from(long(b, at)?).ok()?;
    let s = b.get(*at..at.checked_add(n)?)?;
    *at += n;
    Some(s)
}

/// A short type description: `"string"`, `"record Tide"`, `"array<long>"`,
/// `"union<null,string>"` …
fn type_name(t: &Value, depth: usize) -> String {
    if depth > 8 {
        return "…".into();
    }
    match t {
        Value::String(s) => s.clone(),
        Value::Array(u) => {
            format!("union<{}>", u.iter().map(|x| type_name(x, depth + 1)).collect::<Vec<_>>().join(","))
        }
        Value::Object(o) => {
            let kind = o.get("type").map_or_else(String::new, |k| type_name(k, depth + 1));
            let logical = o.get("logicalType").and_then(Value::as_str);
            match (kind.as_str(), logical) {
                (_, Some(l)) => format!("{kind}:{l}"),
                ("array", _) => {
                    format!("array<{}>", o.get("items").map_or_else(String::new, |i| type_name(i, depth + 1)))
                }
                ("map", _) => format!("map<{}>", o.get("values").map_or_else(String::new, |i| type_name(i, depth + 1))),
                ("record" | "enum" | "fixed" | "error", _) => {
                    format!("{kind} {}", o.get("name").and_then(Value::as_str).unwrap_or(""))
                }
                _ => kind,
            }
        }
        _ => "?".into(),
    }
}

/// The schema summary: name, namespace, type, doc, fields.
fn schema(cx: &mut Context<'_>, s: &Value) {
    cx.format_set("schema_type", truncate_chars(&type_name(s, 0), 200));
    if let Some(o) = s.as_object() {
        for (k, out) in [("name", "schema_name"), ("namespace", "namespace"), ("doc", "doc")] {
            if let Some(v) = o.get(k).and_then(Value::as_str) {
                cx.format_set(out, truncate_chars(v, 500));
            }
        }
        if let Some(fields) = o.get("fields").and_then(Value::as_array) {
            let m: Map<String, Value> = fields
                .iter()
                .take(MAX_FIELDS)
                .filter_map(|f| {
                    let name = f.get("name")?.as_str()?;
                    Some((name.to_string(), Value::String(truncate_chars(&type_name(f.get("type")?, 0), 200))))
                })
                .collect();
            cx.format_set("field_count", fields.len());
            cx.format_set("fields", Value::Object(m));
        }
        if let Some(symbols) = o.get("symbols").and_then(Value::as_array) {
            cx.format_set("symbols", symbols.len());
        }
    }
}

impl Extractor for Avro {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let schema = probe.extension == Some("avsc") && probe.head.windows(6).any(|w| w == b"\"type\"");
        schema.then_some(Sniff { format: "avro_schema", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "avro_schema" {
            let text = cx.read_text(src)?.text;
            let v: Value = serde_json::from_str(&text).map_err(|_| ExtractError::malformed("schema JSON"))?;
            schema(cx, &v);
            return Ok(());
        }
        let (b, cut) = cx.read_bytes(src)?;
        let mut at = 4;
        let mut meta = Map::new();
        // The metadata map: blocks of (key, value) pairs; a negative count
        // is followed by the block's byte size.
        loop {
            let n = long(&b, &mut at).ok_or_else(|| ExtractError::malformed("metadata"))?;
            if n == 0 {
                break;
            }
            if n < 0 {
                long(&b, &mut at);
            }
            for _ in 0..n.unsigned_abs().min(10_000) {
                let k = bytes(&b, &mut at).ok_or_else(|| ExtractError::malformed("metadata key"))?;
                let v = bytes(&b, &mut at).ok_or_else(|| ExtractError::malformed("metadata value"))?;
                meta.insert(
                    String::from_utf8_lossy(k).into_owned(),
                    Value::String(String::from_utf8_lossy(v).into_owned()),
                );
            }
        }
        let sync = b.get(at..at + 16).ok_or_else(|| ExtractError::malformed("sync marker"))?.to_vec();
        at += 16;
        let codec = meta.get("avro.codec").and_then(Value::as_str).unwrap_or("null").to_string();
        cx.format_set("codec", codec);
        if let Some(s) = meta.get("avro.schema").and_then(Value::as_str) {
            match serde_json::from_str::<Value>(s) {
                Ok(v) => schema(cx, &v),
                Err(_) => cx.format_set("schema_error", "writer schema is not JSON"),
            }
        }
        let others: Vec<&String> =
            meta.keys().filter(|k| !matches!(k.as_str(), "avro.schema" | "avro.codec")).collect();
        if !others.is_empty() {
            cx.format_set("metadata_keys", others.iter().take(50).map(|k| truncate_chars(k, 100)).collect::<Vec<_>>());
        }
        let (mut blocks, mut records) = (0u64, 0u64);
        while at < b.len() && blocks < MAX_BLOCKS {
            let (Some(n), Some(size)) = (long(&b, &mut at), long(&b, &mut at)) else { break };
            let Some(end) = usize::try_from(size).ok().and_then(|s| at.checked_add(s)) else { break };
            if n < 0 || b.get(end..end + 16) != Some(&sync[..]) {
                if !cut {
                    cx.format_set("decode_error", "block does not end with the sync marker");
                }
                break;
            }
            blocks += 1;
            records += n.unsigned_abs();
            at = end + 16;
        }
        cx.format_set("blocks", blocks);
        cx.format_set("records", records);
        if cut {
            cx.format_set("truncated", true);
        }
        Ok(())
    }
}

crate::register_extractor!(Avro);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn varints_and_types() {
        let mut at = 0;
        assert_eq!(long(&[0x03], &mut at), Some(-2));
        at = 0;
        assert_eq!(long(&[0x80, 0x01], &mut at), Some(64));
        let t = json!({ "type": "array", "items": ["null", { "type": "long", "logicalType": "timestamp-millis" }] });
        assert_eq!(type_name(&t, 0), "array<union<null,long:timestamp-millis>>");
    }

    crate::fixture_tests!("avro", "avro_schema");
}
