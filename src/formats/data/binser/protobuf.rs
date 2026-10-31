//! Protocol Buffers binary messages without their schema: a wire-format
//! walk that gives every field number with its wire type (varint, 64-bit,
//! 32-bit, string, bytes or nested message, guessed by whether the bytes
//! parse as a message), how often it occurs, and the nesting below it.
//! A file that is not one message but a stream of length-delimited ones
//! (`writeDelimitedTo`) is read as such. String values go to the secret
//! scan.
//!
//! Specification: protobuf.dev "Encoding" (wire types, varints, tags).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::Walk;
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole,
};

/// Extractor for binary protobuf messages.
pub struct Protobuf;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.protobuf",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "protobuf_binary",
        name: "Protocol Buffers binary",
        family: "data.binser",
        mimes: &["application/x-protobuf", "application/protobuf"],
        extensions: &["pb", "binpb", "protobuf"],
        magic: &[],
        parent: None,
    }],
};

/// Nesting followed when guessing sub-messages.
const MAX_DEPTH: usize = 12;
/// Field numbers kept per message.
const MAX_FIELDS: usize = 200;
/// Messages of a delimited stream walked.
const MAX_MESSAGES: u64 = 1_000_000;

fn varint(b: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let x = *b.get(*at)?;
        *at += 1;
        v |= u64::from(x & 0x7f) << shift;
        if x & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// What one field number holds across its occurrences.
#[derive(Default)]
struct Field {
    kinds: BTreeMap<&'static str, u64>,
    nested: Option<Shape>,
}

type Shape = BTreeMap<u64, Field>;

/// Parse `b` as one whole message; `None` when it is not one.
fn message(b: &[u8], depth: usize, w: &mut Walk, keep_text: bool) -> Option<Shape> {
    if depth > MAX_DEPTH {
        return None;
    }
    let mut shape = Shape::new();
    let mut at = 0;
    while at < b.len() {
        let tag = varint(b, &mut at)?;
        let (num, wire) = (tag >> 3, tag & 7);
        if num == 0 || num > (1 << 29) - 1 {
            return None;
        }
        w.value().ok()?;
        let kind = match wire {
            0 => {
                varint(b, &mut at)?;
                "varint"
            }
            1 => {
                at = at.checked_add(8).filter(|&e| e <= b.len())?;
                "fixed64"
            }
            5 => {
                at = at.checked_add(4).filter(|&e| e <= b.len())?;
                "fixed32"
            }
            2 => {
                let n = usize::try_from(varint(b, &mut at)?).ok()?;
                let body = b.get(at..at.checked_add(n)?)?;
                at += n;
                let mut sub = Walk::default();
                if let Some(inner) = (!body.is_empty()).then(|| message(body, depth + 1, &mut sub, keep_text)).flatten()
                {
                    w.values += sub.values;
                    if !sub.text.is_empty() {
                        w.string(sub.text.trim_end());
                    }
                    w.max_depth = w.max_depth.max(depth + 1 + sub.max_depth);
                    let f = shape.entry(num).or_default();
                    let nested = f.nested.get_or_insert_with(Shape::new);
                    merge(nested, inner);
                    "message"
                } else {
                    match std::str::from_utf8(body) {
                        Ok(s) if !s.chars().any(|c| c.is_control() && !c.is_whitespace()) => {
                            if keep_text {
                                w.string(s);
                            }
                            "string"
                        }
                        _ => "bytes",
                    }
                }
            }
            _ => return None,
        };
        let f = shape.entry(num).or_default();
        *f.kinds.entry(kind).or_default() += 1;
        if shape.len() > MAX_FIELDS * 4 {
            return None;
        }
    }
    Some(shape)
}

fn merge(into: &mut Shape, from: Shape) {
    for (num, f) in from {
        let e = into.entry(num).or_default();
        for (k, n) in f.kinds {
            *e.kinds.entry(k).or_default() += n;
        }
        if let Some(n) = f.nested {
            merge(e.nested.get_or_insert_with(Shape::new), n);
        }
    }
}

fn to_json(s: &Shape) -> Value {
    let m: Map<String, Value> = s
        .iter()
        .take(MAX_FIELDS)
        .map(|(num, f)| {
            let mut o = Map::new();
            let kinds: Vec<&str> = f.kinds.keys().copied().collect();
            o.insert("type".into(), Value::String(kinds.join("|")));
            o.insert("count".into(), f.kinds.values().sum::<u64>().into());
            if let Some(n) = &f.nested {
                o.insert("fields".into(), to_json(n));
            }
            (num.to_string(), Value::Object(o))
        })
        .collect();
    Value::Object(m)
}

/// A stream of varint-length-prefixed messages covering all of `b`.
fn delimited(b: &[u8], w: &mut Walk) -> Option<(Shape, u64)> {
    let mut shape = Shape::new();
    let (mut at, mut n) = (0usize, 0u64);
    while at < b.len() && n < MAX_MESSAGES {
        let len = usize::try_from(varint(b, &mut at)?).ok()?;
        let body = b.get(at..at.checked_add(len)?)?;
        at += len;
        merge(&mut shape, message(body, 0, w, true)?);
        n += 1;
    }
    (n > 1).then_some((shape, n))
}

impl Extractor for Protobuf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let named = probe.extension.is_some_and(|e| ["pb", "binpb", "protobuf"].contains(&e));
        let whole = probe.len == probe.head.len() as u64;
        let mut w = Walk::default();
        let ok = named
            && (!whole || message(probe.head, 0, &mut w, false).is_some() || delimited(probe.head, &mut w).is_some());
        ok.then_some(Sniff { format: "protobuf", confidence: 0.8 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, cut) = cx.read_bytes(src)?;
        let mut w = Walk::default();
        if let Some(shape) = message(&data, 0, &mut w, true) {
            cx.format_set("encoding", "message");
            cx.format_set("fields", to_json(&shape));
        } else {
            w = Walk::default();
            let (shape, n) =
                delimited(&data, &mut w).ok_or_else(|| ExtractError::malformed("not a protobuf message"))?;
            cx.format_set("encoding", "delimited");
            cx.format_set("messages", n);
            cx.format_set("fields", to_json(&shape));
        }
        cx.format_set("values", w.values);
        cx.format_set("max_depth", w.max_depth);
        if cut {
            cx.format_set("truncated", true);
        }
        if !w.text.is_empty() {
            cx.emit_text(TextRole::Data, &w.text);
        }
        Ok(())
    }
}

crate::register_extractor!(Protobuf);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_and_strings() {
        // 1: 150 (varint), 2: "tide", 3: { 1: 1 }
        let b = b"\x08\x96\x01\x12\x04tide\x1a\x02\x08\x01";
        let s = message(b, 0, &mut Walk::default(), true).unwrap();
        let j = to_json(&s);
        assert_eq!(j["1"]["type"], "varint");
        assert_eq!(j["2"]["type"], "string");
        assert_eq!(j["3"]["fields"]["1"]["type"], "varint");
        assert!(message(b"\x08", 0, &mut Walk::default(), true).is_none());
        let mut two = vec![u8::try_from(b.len()).unwrap()];
        two.extend(b);
        two.push(u8::try_from(b.len()).unwrap());
        two.extend(b);
        assert_eq!(delimited(&two, &mut Walk::default()).map(|(_, n)| n), Some(2));
    }

    crate::fixture_tests!("protobuf_binary");
}
