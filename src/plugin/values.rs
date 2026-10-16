//! Helpers for extractors that parse structured text with serde.

use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use serde_json::{Map, Number, Value};

/// Nesting deeper than this is refused before parsing: recursive parsers
/// would otherwise exhaust the stack, which `catch_unwind` cannot contain.
pub const MAX_NESTING: usize = 128;

/// Any self-describing serde input (YAML, TOML, JSON5, …) as a JSON value.
///
/// Map keys that are not strings (YAML allows `1: x` or `[a, b]: x`) become
/// their JSON text; bytes become `{"binary_bytes": N}`; tagged values
/// (`!Ref x`) become `{"!Ref": x}`.
///
/// Call [`nesting_depth`] first for parsers without their own depth limit.
#[derive(Debug, Clone, PartialEq)]
pub struct AnyValue(pub Value);

impl<'de> Deserialize<'de> for AnyValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(AnyVisitor).map(AnyValue)
    }
}

struct AnyVisitor;

impl<'de> Visitor<'de> for AnyVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }
    fn visit_i128<E>(self, v: i128) -> Result<Value, E> {
        Ok(i64::try_from(v).map_or_else(|_| Value::String(v.to_string()), Value::from))
    }
    fn visit_u128<E>(self, v: u128) -> Result<Value, E> {
        Ok(u64::try_from(v).map_or_else(|_| Value::String(v.to_string()), Value::from))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Number::from_f64(v).map_or_else(|| Value::String(v.to_string()), Value::Number))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_bytes<E>(self, v: &[u8]) -> Result<Value, E> {
        Ok(serde_json::json!({ "binary_bytes": v.len() }))
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(AnyValue(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some((AnyValue(k), AnyValue(v))) = map.next_entry()? {
            let key = match k {
                Value::String(s) => s,
                other => other.to_string(),
            };
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<Value, A::Error> {
        let (AnyValue(tag), variant) = data.variant::<AnyValue>()?;
        let tag = match tag {
            Value::String(s) => s,
            other => other.to_string(),
        };
        let AnyValue(inner) = variant.newtype_variant::<AnyValue>().map_err(de::Error::custom)?;
        let mut m = Map::new();
        m.insert(tag, inner);
        Ok(Value::Object(m))
    }
}

/// Maximum nesting of `[`/`{` brackets outside quoted strings. Cheap; run
/// it before a recursive parser. For TOML also check [`dotted_key_depth`].
pub fn nesting_depth(text: &str) -> usize {
    let (mut depth, mut max) = (0usize, 0usize);
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q || c == '\n' {
                // An unterminated quote does not swallow the rest of the file.
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '[' | '{' => {
                depth += 1;
                max = max.max(depth);
            }
            ']' | '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

/// The most dots in a TOML key (`a.b.c = 1` or `[a.b.c]`): each one is a
/// level of nested tables.
pub fn dotted_key_depth(text: &str) -> usize {
    text.lines()
        .map(|l| {
            let l = l.trim_start();
            let key =
                if l.starts_with('[') { l.split(']').next().unwrap_or(l) } else { l.split('=').next().unwrap_or("") };
            if key.contains(['"', '\'']) { 0 } else { key.matches('.').count() }
        })
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_value_from_json_text() {
        let v: AnyValue = serde_json::from_str(r#"{"a": [1, 2.5, "x", null, true]}"#).unwrap();
        assert_eq!(v.0, serde_json::json!({ "a": [1, 2.5, "x", null, true] }));
    }

    #[test]
    fn nesting() {
        assert_eq!(nesting_depth("{\"a\": [1, {\"b\": 2}]}"), 3);
        assert_eq!(nesting_depth("x = \"[[[[\""), 0);
        assert_eq!(nesting_depth("[1.5, 2.5, 3.5]"), 1);
        assert_eq!(dotted_key_depth("a.b.c = 1\n[x.y]\nv = 1.5"), 2);
        assert_eq!(nesting_depth(&"[".repeat(10_000)), 10_000);
    }
}
