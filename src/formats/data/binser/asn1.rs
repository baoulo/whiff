//! ASN.1 BER / DER blobs that are not certificates, keys or CMS objects
//! (which `crypto.pki` reads): the element tree summarised as element
//! count, depth, a histogram of universal and context tags, the object
//! identifiers used (named where known), times, and string values for
//! the secret scan.
//!
//! Specification: ITU-T X.690 (BER / DER encoding).

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::Walk;
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, der,
    truncate_chars,
};

/// Extractor for generic BER / DER data.
pub struct Asn1;

static META: ExtractorMeta = ExtractorMeta {
    id: "data.asn1",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "asn1",
        name: "ASN.1 BER/DER blob",
        family: "data.binser",
        mimes: &[],
        extensions: &["der", "ber", "asn1"],
        magic: &[],
        parent: None,
    }],
};

/// Elements walked.
const MAX_ELEMENTS: u64 = 1_000_000;
/// Nesting followed.
const MAX_DEPTH: usize = 64;
/// Distinct object identifiers listed.
const MAX_OIDS: usize = 100;

fn tag_name(tag: u8) -> String {
    let class = tag >> 6;
    let n = tag & 0x1f;
    if class == 2 {
        return format!("[{n}]");
    }
    if class != 0 {
        return format!("{}_{n}", if class == 1 { "application" } else { "private" });
    }
    match n {
        1 => "boolean",
        2 => "integer",
        3 => "bit_string",
        4 => "octet_string",
        5 => "null",
        6 => "oid",
        10 => "enumerated",
        12 => "utf8_string",
        16 => "sequence",
        17 => "set",
        19 => "printable_string",
        20 => "t61_string",
        22 => "ia5_string",
        23 => "utc_time",
        24 => "generalized_time",
        30 => "bmp_string",
        _ => return format!("universal_{n}"),
    }
    .to_string()
}

impl Extractor for Asn1 {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let named = probe.extension.is_some_and(|e| ["der", "ber", "asn1"].contains(&e));
        let whole = probe.len == probe.head.len() as u64;
        let ok = named
            && matches!(probe.head.first(), Some(0x30 | 0x31 | 0x60..=0x7f | 0xa0..=0xbf))
            && (!whole || der::read(probe.head).is_some_and(|(_, rest)| rest.is_empty()));
        // Below crypto.pki, which claims what it understands.
        ok.then_some(Sniff { format: "asn1", confidence: 0.5 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, cut) = cx.read_bytes(src)?;
        let mut w = Walk::default();
        let mut tags: BTreeMap<String, u64> = BTreeMap::new();
        let mut oids: Vec<String> = Vec::new();
        let (mut elements, mut top, mut times) = (0u64, 0u64, Vec::new());
        let mut stack: Vec<(&[u8], usize)> = vec![(&data, 0)];
        let mut rest_top = 0usize;
        while let Some((mut buf, depth)) = stack.pop() {
            while !buf.is_empty() {
                let Some((t, rest)) = der::read(buf) else {
                    if depth == 0 {
                        rest_top = buf.len();
                    }
                    break;
                };
                buf = rest;
                elements += 1;
                if depth == 0 {
                    top += 1;
                }
                w.max_depth = w.max_depth.max(depth);
                *tags.entry(tag_name(t.tag)).or_default() += 1;
                match t.tag {
                    0x06 if oids.len() < MAX_OIDS => {
                        let o = der::named(t.body);
                        if !oids.contains(&o) {
                            oids.push(o);
                        }
                    }
                    0x0c | 0x13 | 0x14 | 0x16 | 0x1e => w.string(&der::string(t)),
                    0x17 | 0x18 if times.len() < 20 => times.extend(der::time(t)),
                    _ => {}
                }
                if t.tag & 0x20 != 0 && depth < MAX_DEPTH {
                    stack.push((t.body, depth + 1));
                }
                if elements >= MAX_ELEMENTS {
                    stack.clear();
                    break;
                }
            }
        }
        if elements == 0 {
            return Err(ExtractError::malformed("no BER element"));
        }
        cx.format_set("elements", elements);
        if top != 1 {
            cx.format_set("top_level_elements", top);
        }
        cx.format_set("max_depth", w.max_depth);
        if rest_top > 0 && !cut {
            cx.format_set("trailing_bytes", rest_top);
        }
        let m: Map<String, Value> = tags.into_iter().map(|(k, n)| (k, n.into())).collect();
        cx.format_set("tags", Value::Object(m));
        if !oids.is_empty() {
            cx.format_set("oids", oids.iter().map(|o| truncate_chars(o, 100)).collect::<Vec<_>>());
        }
        if !times.is_empty() {
            times.sort();
            times.dedup();
            cx.format_set("times", times);
        }
        if !w.text.is_empty() {
            cx.emit_text(TextRole::Data, &w.text);
        }
        Ok(())
    }
}

crate::register_extractor!(Asn1);

#[cfg(test)]
mod tests {
    use crate::plugin::testing::report_for;

    #[test]
    fn element_tree() {
        // SEQUENCE { OID 2.5.4.3, UTF8String "tide", [0] { INTEGER 5 } }
        let b = b"\x30\x10\x06\x03\x55\x04\x03\x0c\x04tide\xa0\x03\x02\x01\x05";
        let r = report_for("x.ber", b);
        let f = &r.format["asn1"];
        assert_eq!(f["elements"], 5);
        assert_eq!(f["max_depth"], 2);
        assert_eq!(f["tags"]["[0]"], 1);
        assert_eq!(f["oids"][0], "CN");
    }

    crate::fixture_tests!("asn1");
}
