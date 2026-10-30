//! Self-describing binary serialisations, decoded to a bounded tree for
//! the shared report (top-level type and keys, documents in a stream,
//! inferred schema, value count, depth, tags / extension types):
//! * MessagePack (timestamps decoded, extension types counted);
//! * CBOR (RFC 8949: indefinite lengths, tags counted, epoch and string
//!   dates, the self-describe tag);
//! * BSON documents and `mongodump` streams (ObjectId time range);
//! * UBJSON (Draft 12, optimised containers) and Smile (shared names and
//!   values);
//! * Amazon Ion binary 1.0 (local symbol tables, annotations);
//! * bencode, with torrent facts (name, files, size, piece length,
//!   trackers, creator, date, private flag, info hash);
//! * PHP `serialize()` output (class names; known gadget-chain classes
//!   flagged);
//! * Minecraft NBT (Java big-endian and Bedrock little-endian).
//!
//! Specifications: msgpack spec 2.0; RFC 8949; bsonspec.org 1.1; UBJSON
//! Draft 12; Jackson "Smile format specification" 1.0; Amazon Ion 1.0
//! binary encoding; BEP 3 (bencode, metainfo); PHP `var_unserializer.re`;
//! minecraft.wiki "NBT format".

use serde_json::{Map, Value, json};

use super::{Decoded, Fail, KEEP, Walk, bytes, hex, key_of, report, stream, text_or_bytes, unix_time};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, der, truncate_chars,
};

/// Extractor for self-describing binary serialisations.
pub struct SelfDescribing;

const fn spec(
    id: &'static str,
    name: &'static str,
    mimes: &'static [&'static str],
    extensions: &'static [&'static str],
    magic: &'static [Magic],
) -> FormatSpec {
    FormatSpec { id, name, family: "data.binser", mimes, extensions, magic, parent: None }
}

static META: ExtractorMeta = ExtractorMeta {
    id: "data.binser",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec("msgpack", "MessagePack", &["application/vnd.msgpack"], &["msgpack", "mpk"], &[]),
        spec("cbor", "CBOR", &["application/cbor"], &["cbor"], &[]),
        spec("bson", "BSON", &["application/bson"], &["bson"], &[]),
        spec("ubjson", "Smile / UBJSON", &["application/ubjson"], &["ubj", "ubjson"], &[]),
        spec("smile", "Smile", &["application/x-jackson-smile"], &["sml", "smile"], &[Magic::at(0, b":)\n")]),
        spec("ion", "Ion (Amazon)", &["application/ion"], &["ion", "10n"], &[Magic::at(0, b"\xe0\x01\x00\xea")]),
        spec("bencode", "Bencode", &["application/x-bittorrent"], &["bencode", "torrent"], &[]),
        spec("php_serialized", "PHP serialized", &[], &["phpser"], &[]),
        spec("nbt", "NBT (Minecraft)", &["application/x-minecraft-nbt"], &["nbt", "schematic", "litematic"], &[]),
    ],
};

/// Classes of known PHP unserialize gadget chains (phpggc).
const PHP_GADGETS: [&str; 12] = [
    "Monolog\\Handler\\SyslogUdpHandler",
    "Monolog\\Handler\\BufferHandler",
    "GuzzleHttp\\Cookie\\FileCookieJar",
    "GuzzleHttp\\Psr7\\FnStream",
    "Illuminate\\Broadcasting\\PendingBroadcast",
    "Illuminate\\Foundation\\Testing\\PendingCommand",
    "Symfony\\Component\\Process\\Pipes\\WindowsPipes",
    "Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter",
    "Swift_KeyCache_DiskKeyCache",
    "Laminas\\Log\\Logger",
    "Zend\\Log\\Logger",
    "Doctrine\\Common\\Cache\\Psr6\\CacheAdapter",
];

impl Extractor for SelfDescribing {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ext = probe.extension.unwrap_or("");
        let whole = probe.len == h.len() as u64;
        // A head decode that runs out of input is still a match.
        let fits = |r: Result<(Value, usize), Fail>| match r {
            Ok((_, n)) => n > 0,
            Err(e) => e == "truncated" && !whole,
        };
        let mut w = Walk::default();
        // The self-describe tag (optional) marks CBOR whatever the name.
        if h.starts_with(b"\xd9\xd9\xf7") && fits(cbor(h, &mut w)) {
            return Some(Sniff { format: "cbor", confidence: 0.9 });
        }
        let format = match ext {
            "msgpack" | "mpk" if fits(msgpack(h, &mut w)) => "msgpack",
            "cbor" if fits(cbor(h, &mut w)) => "cbor",
            "ubj" | "ubjson" if matches!(h.first(), Some(b'{' | b'[')) && fits(ubjson(h, &mut w)) => "ubjson",
            "ion" | "10n" if !h.starts_with(b"\xe0\x01") => return None, // Ion text: textdata
            _ if is_bson(h, probe.len) => "bson",
            "bson" if fits(bson(h, &mut w)) => "bson",
            _ if h.first() == Some(&b'd') && h.get(1).is_some_and(u8::is_ascii_digit) && fits(bencode(h, &mut w)) => {
                "bencode"
            }
            _ if php_start(h) && fits(php(h, &mut w)) => "php_serialized",
            _ if nbt_start(h) && fits(nbt(h, &mut w, false)) => "nbt",
            _ => return None,
        };
        let confidence =
            if matches!(format, "bson" | "bencode" | "nbt" | "php_serialized") && ext.is_empty() { 0.7 } else { 0.85 };
        Some(Sniff { format, confidence })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, cut) = cx.read_bytes(src)?;
        if cut {
            cx.format_set("truncated", true);
        }
        let mut w = Walk::default();
        let d = match cx.format_id() {
            "msgpack" => stream(&data, &mut w, msgpack),
            "cbor" => stream(&data, &mut w, cbor),
            "bson" => {
                let d = stream(&data, &mut w, bson);
                object_id_times(&d, cx);
                d
            }
            "ubjson" => stream(&data, &mut w, ubjson),
            "smile" => smile(&data, &mut w, cx),
            "ion" => ion(&data, &mut w),
            "bencode" => {
                let d = stream(&data, &mut w, bencode);
                torrent(&data, &d, cx);
                d
            }
            "php_serialized" => {
                let d = stream(&data, &mut w, php);
                let gadgets: Vec<&str> = PHP_GADGETS.into_iter().filter(|g| w.tags.contains_key(*g)).collect();
                if !gadgets.is_empty() {
                    cx.security().risk("unsafe_deserialization", Some(gadgets.join(", ")));
                }
                d
            }
            _ => {
                let mut d = stream(&data, &mut w, |b, w| nbt(b, w, false));
                if d.documents == 0 && data.len() > 8 {
                    // Bedrock: little-endian, after an 8-byte header in level.dat.
                    w = Walk::default();
                    let skip = if data.get(8) == Some(&10) { 8 } else { 0 };
                    d = stream(&data[skip..], &mut w, |b, w| nbt(b, w, true));
                    cx.format_set("byte_order", "little_endian");
                }
                d
            }
        };
        if d.documents == 0 {
            return Err(ExtractError::malformed(d.error.unwrap_or("no value")));
        }
        cx.checkpoint()?;
        report(cx, &d, &w);
        Ok(())
    }
}

crate::register_extractor!(SelfDescribing);

/// A bounded byte cursor.
struct Cur<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }

    fn u8(&mut self) -> Result<u8, Fail> {
        let v = *self.b.get(self.at).ok_or("truncated")?;
        self.at += 1;
        Ok(v)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Fail> {
        let end = self.at.checked_add(n).ok_or("truncated")?;
        let s = self.b.get(self.at..end).ok_or("truncated")?;
        self.at = end;
        Ok(s)
    }

    fn be(&mut self, n: usize) -> Result<u64, Fail> {
        Ok(self.take(n)?.iter().fold(0u64, |a, &x| a << 8 | u64::from(x)))
    }

    fn le(&mut self, n: usize) -> Result<u64, Fail> {
        Ok(self.take(n)?.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x)))
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.at).copied()
    }

    /// A length that the remaining input can hold (one byte per item at least).
    fn len(&self, n: u64) -> Result<usize, Fail> {
        let n = usize::try_from(n).map_err(|_| "length too large")?;
        if n > self.b.len() - self.at { Err("truncated") } else { Ok(n) }
    }
}

fn float(v: f64) -> Value {
    serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number)
}

/// Push into a kept list while under the keep limit.
fn keep(items: &mut Vec<Value>, v: Value) {
    if items.len() < KEEP {
        items.push(v);
    }
}

fn keep_field(m: &mut Map<String, Value>, k: String, v: Value) {
    if m.len() < KEEP {
        m.insert(k, v);
    }
}

// MessagePack ---------------------------------------------------------------

fn msgpack(b: &[u8], w: &mut Walk) -> Result<(Value, usize), Fail> {
    let mut c = Cur::new(b);
    let v = mp_value(&mut c, w)?;
    Ok((v, c.at))
}

fn mp_value(c: &mut Cur<'_>, w: &mut Walk) -> Result<Value, Fail> {
    w.value()?;
    let t = c.u8()?;
    Ok(match t {
        0x00..=0x7f => json!(t),
        0xe0..=0xff => json!(i64::from(t.cast_signed())),
        0x80..=0x8f => return mp_map(c, w, u64::from(t & 0x0f)),
        0x90..=0x9f => return mp_array(c, w, u64::from(t & 0x0f)),
        0xa0..=0xbf => mp_str(c, w, u64::from(t & 0x1f))?,
        0xc0 => Value::Null,
        0xc2 => json!(false),
        0xc3 => json!(true),
        0xc4..=0xc6 => {
            let n = c.be(1 << (t - 0xc4))?;
            let n = c.len(n)?;
            c.take(n)?;
            bytes(n)
        }
        0xc7..=0xc9 => {
            let n = c.be(1 << (t - 0xc7))?;
            let n = c.len(n)?;
            mp_ext(c, w, n)?
        }
        0xca => float(f64::from(f32::from_bits(u32::try_from(c.be(4)?).unwrap_or(0)))),
        0xcb => float(f64::from_bits(c.be(8)?)),
        0xcc..=0xcf => json!(c.be(1 << (t - 0xcc))?),
        0xd0..=0xd3 => {
            let n = 1 << (t - 0xd0);
            let raw = c.be(n)?;
            let shift = 64 - 8 * n;
            json!((raw << shift).cast_signed() >> shift)
        }
        0xd4..=0xd8 => mp_ext(c, w, 1 << (t - 0xd4))?,
        0xd9..=0xdb => {
            let n = c.be(1 << (t - 0xd9))?;
            mp_str(c, w, n)?
        }
        0xdc | 0xdd => {
            let n = c.be(if t == 0xdc { 2 } else { 4 })?;
            return mp_array(c, w, n);
        }
        0xde | 0xdf => {
            let n = c.be(if t == 0xde { 2 } else { 4 })?;
            return mp_map(c, w, n);
        }
        _ => return Err("reserved type 0xc1"),
    })
}

fn mp_str(c: &mut Cur<'_>, w: &mut Walk, n: u64) -> Result<Value, Fail> {
    let n = c.len(n)?;
    let s = String::from_utf8_lossy(c.take(n)?).into_owned();
    w.string(&s);
    Ok(Value::String(truncate_chars(&s, 2000)))
}

fn mp_ext(c: &mut Cur<'_>, w: &mut Walk, n: usize) -> Result<Value, Fail> {
    let ty = c.u8()?.cast_signed();
    let body = c.take(n)?;
    if ty == -1 {
        // Timestamp: seconds (and nanoseconds) since 1970.
        let secs = match n {
            4 => Some(i64::from(u32::from_be_bytes(body.try_into().unwrap_or_default()))),
            8 => i64::try_from(u64::from_be_bytes(body.try_into().unwrap_or_default()) & 0x3_ffff_ffff).ok(),
            12 => Some(i64::from_be_bytes(body[4..].try_into().unwrap_or_default())),
            _ => None,
        };
        w.tag("timestamp");
        return Ok(secs.and_then(unix_time).map_or_else(|| bytes(n), Value::String));
    }
    w.tag(format!("ext_{ty}"));
    Ok(bytes(n))
}

fn mp_array(c: &mut Cur<'_>, w: &mut Walk, n: u64) -> Result<Value, Fail> {
    let n = c.len(n)?;
    w.enter()?;
    let mut items = Vec::new();
    for _ in 0..n {
        keep(&mut items, mp_value(c, w)?);
    }
    w.leave();
    Ok(Value::Array(items))
}

fn mp_map(c: &mut Cur<'_>, w: &mut Walk, n: u64) -> Result<Value, Fail> {
    let n = c.len(n)?;
    w.enter()?;
    let mut m = Map::new();
    for _ in 0..n {
        let k = key_of(&mp_value(c, w)?);
        let v = mp_value(c, w)?;
        keep_field(&mut m, k, v);
    }
    w.leave();
    Ok(Value::Object(m))
}

// CBOR -----------------------------------------------------------------------

fn cbor(b: &[u8], w: &mut Walk) -> Result<(Value, usize), Fail> {
    let mut c = Cur::new(b);
    let v = cb_value(&mut c, w)?.ok_or("unexpected break")?;
    Ok((v, c.at))
}

/// The argument of an initial byte; `None` for indefinite length.
fn cb_arg(c: &mut Cur<'_>, info: u8) -> Result<Option<u64>, Fail> {
    Ok(Some(match info {
        0..=23 => u64::from(info),
        24 => c.be(1)?,
        25 => c.be(2)?,
        26 => c.be(4)?,
        27 => c.be(8)?,
        31 => return Ok(None),
        _ => return Err("reserved additional information"),
    }))
}

fn half(bits: u16) -> f64 {
    let exp = (bits >> 10) & 0x1f;
    let mant = f64::from(bits & 0x3ff);
    let v = match exp {
        0 => mant * 2f64.powi(-24),
        31 if mant == 0.0 => f64::INFINITY,
        31 => f64::NAN,
        e => (mant + 1024.0) * 2f64.powi(i32::from(e) - 25),
    };
    if bits & 0x8000 != 0 { -v } else { v }
}

/// A value, or `None` for the "break" stop code.
fn cb_value(c: &mut Cur<'_>, w: &mut Walk) -> Result<Option<Value>, Fail> {
    let ib = c.u8()?;
    let (major, info) = (ib >> 5, ib & 0x1f);
    if ib == 0xff {
        return Ok(None);
    }
    w.value()?;
    let arg = cb_arg(c, info)?;
    Ok(Some(match (major, arg) {
        (0, Some(n)) => json!(n),
        (1, Some(n)) => i64::try_from(n).map_or_else(|_| json!(-1.0 - n as f64), |n| json!(-1 - n)),
        (2 | 3, Some(n)) => {
            let n = c.len(n)?;
            let raw = c.take(n)?;
            if major == 2 { bytes(n) } else { text_or_bytes(raw, w) }
        }
        (2 | 3, None) => {
            // Chunks of the same major type until break.
            let mut all = Vec::new();
            loop {
                let ib = c.u8()?;
                if ib == 0xff {
                    break;
                }
                if ib >> 5 != major {
                    return Err("bad string chunk");
                }
                let n = cb_arg(c, ib & 0x1f)?.ok_or("nested indefinite string")?;
                let n = c.len(n)?;
                all.extend_from_slice(c.take(n)?);
            }
            if major == 2 { bytes(all.len()) } else { text_or_bytes(&all, w) }
        }
        (4, n) => {
            let n = n.map(|n| c.len(n)).transpose()?;
            w.enter()?;
            let mut items = Vec::new();
            let mut i = 0;
            while n.is_none_or(|n| i < n) {
                match cb_value(c, w)? {
                    Some(v) => keep(&mut items, v),
                    None if n.is_none() => break,
                    None => return Err("unexpected break"),
                }
                i += 1;
            }
            w.leave();
            Value::Array(items)
        }
        (5, n) => {
            let n = n.map(|n| c.len(n)).transpose()?;
            w.enter()?;
            let mut m = Map::new();
            let mut i = 0;
            while n.is_none_or(|n| i < n) {
                let Some(k) = cb_value(c, w)? else {
                    if n.is_none() {
                        break;
                    }
                    return Err("unexpected break");
                };
                let v = cb_value(c, w)?.ok_or("unexpected break")?;
                keep_field(&mut m, key_of(&k), v);
                i += 1;
            }
            w.leave();
            Value::Object(m)
        }
        (6, Some(tag)) => {
            let inner = cb_value(c, w)?.ok_or("unexpected break")?;
            match tag {
                55799 => return Ok(Some(inner)),
                0 => {
                    w.tag("date_string");
                    inner
                }
                1 => {
                    w.tag("epoch_date");
                    inner.as_i64().and_then(unix_time).map_or(inner, Value::String)
                }
                t => {
                    w.tag(format!("tag_{t}"));
                    inner
                }
            }
        }
        (7, arg) => match (info, arg) {
            (20, _) => json!(false),
            (21, _) => json!(true),
            (22 | 23, _) => Value::Null,
            (25, Some(b)) => float(half(u16::try_from(b).unwrap_or(0))),
            (26, Some(b)) => float(f64::from(f32::from_bits(u32::try_from(b).unwrap_or(0)))),
            (27, Some(b)) => float(f64::from_bits(b)),
            (_, Some(n)) => {
                w.tag(format!("simple_{n}"));
                Value::Null
            }
            _ => return Err("bad simple value"),
        },
        _ => return Err("indefinite length on a definite type"),
    }))
}

// BSON -----------------------------------------------------------------------

/// A whole BSON document (or a `mongodump` stream) by its length fields.
fn is_bson(h: &[u8], len: u64) -> bool {
    let Some(n) = h.get(..4).map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))) else {
        return false;
    };
    let first = h.get(4).copied().unwrap_or(0);
    let typed = matches!(first, 0x01..=0x13 | 0x7f | 0xff);
    let name_ok = h
        .get(5..)
        .and_then(|r| r.iter().position(|&c| c == 0))
        .is_some_and(|i| h[5..5 + i].iter().all(u8::is_ascii_graphic) && i > 0);
    let ends = usize::try_from(n).ok().and_then(|n| h.get(n.wrapping_sub(1))) == Some(&0) || n > h.len() as u64;
    n >= 5 && n <= len && typed && name_ok && ends && (n == len || len > n + 4)
}

fn bson(b: &[u8], w: &mut Walk) -> Result<(Value, usize), Fail> {
    let mut c = Cur::new(b);
    let v = bs_doc(&mut c, w, false)?;
    Ok((v, c.at))
}

fn cstring<'a>(c: &mut Cur<'a>) -> Result<&'a [u8], Fail> {
    let rest = &c.b[c.at..];
    let i = rest.iter().position(|&x| x == 0).ok_or("truncated")?;
    c.at += i + 1;
    Ok(&rest[..i])
}

fn bs_string(c: &mut Cur<'_>) -> Result<String, Fail> {
    let n = usize::try_from(c.le(4)?).map_err(|_| "bad length")?;
    let raw = c.take(n)?;
    let raw = raw.strip_suffix(b"\0").ok_or("string without NUL")?;
    Ok(String::from_utf8_lossy(raw).into_owned())
}

#[allow(clippy::too_many_lines)] // one arm per element type
fn bs_doc(c: &mut Cur<'_>, w: &mut Walk, array: bool) -> Result<Value, Fail> {
    w.value()?;
    let start = c.at;
    let len = usize::try_from(c.le(4)?).map_err(|_| "bad length")?;
    if len < 5 || c.b.len() < start + len {
        return Err("truncated");
    }
    w.enter()?;
    let mut m = Map::new();
    let mut items = Vec::new();
    loop {
        let ty = c.u8()?;
        if ty == 0 {
            break;
        }
        let name = String::from_utf8_lossy(cstring(c)?).into_owned();
        let v = match ty {
            0x01 => {
                w.value()?;
                float(f64::from_bits(c.le(8)?))
            }
            0x02 | 0x0d | 0x0e => {
                w.value()?;
                let s = bs_string(c)?;
                w.string(&s);
                if ty == 0x0d {
                    w.tag("javascript");
                }
                Value::String(truncate_chars(&s, 2000))
            }
            0x03 | 0x04 => bs_doc(c, w, ty == 0x04)?,
            0x05 => {
                w.value()?;
                let n = usize::try_from(c.le(4)?).map_err(|_| "bad length")?;
                let sub = c.u8()?;
                c.take(n)?;
                if sub == 4 && n == 16 {
                    w.tag("uuid");
                }
                bytes(n)
            }
            0x06 | 0x0a | 0x7f | 0xff => {
                w.value()?;
                Value::Null
            }
            0x07 => {
                w.value()?;
                let id = c.take(12)?;
                w.tag("object_id");
                Value::String(format!("ObjectId({})", hex(id)))
            }
            0x08 => {
                w.value()?;
                json!(c.u8()? != 0)
            }
            0x09 => {
                w.value()?;
                let ms = c.le(8)?.cast_signed();
                w.tag("datetime");
                unix_time(ms.div_euclid(1000)).map_or_else(|| json!(ms), Value::String)
            }
            0x0b => {
                w.value()?;
                let re = String::from_utf8_lossy(cstring(c)?).into_owned();
                cstring(c)?;
                Value::String(truncate_chars(&re, 200))
            }
            0x0c => {
                w.value()?;
                bs_string(c)?;
                c.take(12)?;
                Value::Null
            }
            0x0f => {
                w.value()?;
                c.le(4)?;
                let code = bs_string(c)?;
                w.tag("javascript");
                bs_doc(c, w, false)?;
                Value::String(truncate_chars(&code, 200))
            }
            0x10 => {
                w.value()?;
                json!(i64::from(u32::try_from(c.le(4)?).unwrap_or(0).cast_signed()))
            }
            0x11 => {
                w.value()?;
                json!(c.le(8)?)
            }
            0x12 => {
                w.value()?;
                json!(c.le(8)?.cast_signed())
            }
            0x13 => {
                w.value()?;
                c.take(16)?;
                w.tag("decimal128");
                Value::String("decimal128".into())
            }
            _ => return Err("unknown BSON element type"),
        };
        if array {
            keep(&mut items, v);
        } else {
            keep_field(&mut m, name, v);
        }
    }
    w.leave();
    if c.at != start + len {
        return Err("document length mismatch");
    }
    Ok(if array { Value::Array(items) } else { Value::Object(m) })
}

/// The range of ObjectId creation times (their first four bytes) at the
/// top level of the documents.
fn object_id_times(d: &Decoded, cx: &mut Context<'_>) {
    let (mut lo, mut hi) = (u32::MAX, 0u32);
    for doc in &d.docs {
        for v in doc.as_object().into_iter().flat_map(Map::values) {
            if let Some(hex) = v.as_str().and_then(|s| s.strip_prefix("ObjectId(")).and_then(|s| s.get(..8))
                && let Ok(t) = u32::from_str_radix(hex, 16)
            {
                lo = lo.min(t);
                hi = hi.max(t);
            }
        }
    }
    if let (Some(a), Some(b)) = (unix_time(i64::from(lo)), unix_time(i64::from(hi))) {
        cx.format_set("first_object_id_time", a);
        cx.format_set("last_object_id_time", b);
    }
}

// UBJSON ---------------------------------------------------------------------

fn ubjson(b: &[u8], w: &mut Walk) -> Result<(Value, usize), Fail> {
    let mut c = Cur::new(b);
    let m = c.u8()?;
    let v = ub_value(&mut c, w, m)?;
    Ok((v, c.at))
}

fn ub_int(c: &mut Cur<'_>, m: u8) -> Result<i64, Fail> {
    Ok(match m {
        b'i' => i64::from(c.u8()?.cast_signed()),
        b'U' => i64::from(c.u8()?),
        b'I' => i64::from(u16::try_from(c.be(2)?).unwrap_or(0).cast_signed()),
        b'l' => i64::from(u32::try_from(c.be(4)?).unwrap_or(0).cast_signed()),
        b'L' => c.be(8)?.cast_signed(),
        _ => return Err("expected an integer"),
    })
}

fn ub_len(c: &mut Cur<'_>) -> Result<usize, Fail> {
    let m = c.u8()?;
    let n = ub_int(c, m)?;
    c.len(u64::try_from(n).map_err(|_| "negative length")?)
}

fn ub_value(c: &mut Cur<'_>, w: &mut Walk, m: u8) -> Result<Value, Fail> {
    w.value()?;
    Ok(match m {
        b'Z' => Value::Null,
        b'T' => json!(true),
        b'F' => json!(false),
        b'i' | b'U' | b'I' | b'l' | b'L' => json!(ub_int(c, m)?),
        b'd' => float(f64::from(f32::from_bits(u32::try_from(c.be(4)?).unwrap_or(0)))),
        b'D' => float(f64::from_bits(c.be(8)?)),
        b'C' => Value::String(char::from(c.u8()?).to_string()),
        b'S' | b'H' => {
            let n = ub_len(c)?;
            let s = String::from_utf8_lossy(c.take(n)?).into_owned();
            w.string(&s);
            Value::String(truncate_chars(&s, 2000))
        }
        b'[' | b'{' => {
            let object = m == b'{';
            w.enter()?;
            // Optimised containers: `$type` then `#count`, or `#count` alone.
            let mut ty = None;
            let mut count = None;
            if c.peek() == Some(b'$') {
                c.u8()?;
                ty = Some(c.u8()?);
            }
            if c.peek() == Some(b'#') {
                c.u8()?;
                count = Some(ub_len(c)?);
            }
            let (mut items, mut map) = (Vec::new(), Map::new());
            let mut i = 0;
            loop {
                if count.is_some_and(|n| i >= n) {
                    break;
                }
                if count.is_none() {
                    while c.peek() == Some(b'N') {
                        c.u8()?;
                    }
                    if c.peek() == Some(if object { b'}' } else { b']' }) {
                        c.u8()?;
                        break;
                    }
                }
                let key = if object {
                    let n = ub_len(c)?;
                    Some(String::from_utf8_lossy(c.take(n)?).into_owned())
                } else {
                    None
                };
                let vm = match ty {
                    Some(t) => t,
                    None => c.u8()?,
                };
                let v = ub_value(c, w, vm)?;
                match key {
                    Some(k) => keep_field(&mut map, k, v),
                    None => keep(&mut items, v),
                }
                i += 1;
            }
            w.leave();
            if object { Value::Object(map) } else { Value::Array(items) }
        }
        b'N' => {
            let m = c.u8()?;
            return ub_value(c, w, m);
        }
        _ => return Err("unknown UBJSON marker"),
    })
}

// Smile ----------------------------------------------------------------------

/// Smile decoding state: shared name and value back-references.
struct Smile {
    names: Vec<String>,
    values: Vec<String>,
    share_names: bool,
    share_values: bool,
}

impl Smile {
    fn remember(list: &mut Vec<String>, on: bool, s: &str) {
        if on && s.len() <= 64 {
            if list.len() >= 1024 {
                list.clear();
            }
            list.push(s.to_string());
        }
    }
}

fn smile(data: &[u8], w: &mut Walk, cx: &mut Context<'_>) -> Decoded {
    let mut d = Decoded::default();
    let flags = data.get(3).copied().unwrap_or(0);
    cx.format_set("smile_version", flags >> 4);
    cx.format_set("shared_names", flags & 1 != 0);
    cx.format_set("shared_values", flags & 2 != 0);
    let mut s =
        Smile { names: Vec::new(), values: Vec::new(), share_names: flags & 1 != 0, share_values: flags & 2 != 0 };
    let mut c = Cur::new(data);
    c.at = 4;
    while c.at < data.len() {
        if c.peek() == Some(0xff) {
            c.at += 1;
            continue;
        }
        // Each document may restart with its own header.
        if data[c.at..].starts_with(b":)\n") {
            c.at += 4;
            s.names.clear();
            s.values.clear();
            continue;
        }
        match sm_value(&mut c, w, &mut s) {
            Ok(v) => {
                d.documents += 1;
                if d.docs.len() < super::SAMPLE_DOCS {
                    d.docs.push(v);
                }
            }
            Err(e) => {
                d.error = Some(e);
                d.trailing = data.len() - c.at;
                break;
            }
        }
    }
    d
}

fn zigzag(n: u64) -> i64 {
    (n >> 1).cast_signed() ^ -((n & 1).cast_signed())
}

fn sm_vint(c: &mut Cur<'_>) -> Result<u64, Fail> {
    let mut v = 0u64;
    for _ in 0..10 {
        let b = c.u8()?;
        if b & 0x80 != 0 {
            return Ok(v << 6 | u64::from(b & 0x3f));
        }
        v = v << 7 | u64::from(b);
    }
    Err("varint too long")
}

/// `n` bytes packed 7 bits per byte (floats and 7-bit binary).
fn sm_7bit(c: &mut Cur<'_>, bytes_in: usize) -> Result<u64, Fail> {
    let mut v = 0u64;
    for _ in 0..bytes_in {
        v = v << 7 | u64::from(c.u8()? & 0x7f);
    }
    Ok(v)
}

fn sm_until_end(c: &mut Cur<'_>) -> Result<String, Fail> {
    let rest = &c.b[c.at..];
    let i = rest.iter().position(|&x| x == 0xfc).ok_or("truncated")?;
    c.at += i + 1;
    Ok(String::from_utf8_lossy(&rest[..i]).into_owned())
}

fn sm_value(c: &mut Cur<'_>, w: &mut Walk, s: &mut Smile) -> Result<Value, Fail> {
    w.value()?;
    let t = c.u8()?;
    let text = |c: &mut Cur<'_>, n: usize, s: &mut Smile, w: &mut Walk| -> Result<Value, Fail> {
        let v = String::from_utf8_lossy(c.take(n)?).into_owned();
        Smile::remember(&mut s.values, s.share_values, &v);
        w.string(&v);
        Ok(Value::String(truncate_chars(&v, 2000)))
    };
    Ok(match t {
        0x01..=0x1f => Value::String(s.values.get(usize::from(t) - 1).cloned().ok_or("bad shared value")?),
        0x20 => Value::String(String::new()),
        0x21 => Value::Null,
        0x22 => json!(false),
        0x23 => json!(true),
        0x24 | 0x25 => json!(zigzag(sm_vint(c)?)),
        0x26 | 0x2a => {
            if t == 0x2a {
                sm_vint(c)?;
            }
            let n = usize::try_from(sm_vint(c)?).map_err(|_| "bad length")?;
            c.take(c.len((n * 8).div_ceil(7) as u64)?)?;
            Value::String("big number".into())
        }
        0x28 => float(f64::from(f32::from_bits(u32::try_from(sm_7bit(c, 5)?).unwrap_or(0)))),
        0x29 => float(f64::from_bits(sm_7bit(c, 10)?)),
        0x40..=0x5f => text(c, usize::from(t & 0x1f) + 1, s, w)?,
        0x60..=0x7f => text(c, usize::from(t & 0x1f) + 33, s, w)?,
        0x80..=0x9f => text(c, usize::from(t & 0x1f) + 2, s, w)?,
        0xa0..=0xbf => text(c, usize::from(t & 0x1f) + 34, s, w)?,
        0xc0..=0xdf => json!(zigzag(u64::from(t & 0x1f))),
        0xe0 | 0xe4 => {
            let v = sm_until_end(c)?;
            w.string(&v);
            Value::String(truncate_chars(&v, 2000))
        }
        0xe8 | 0xfd => {
            let n = usize::try_from(sm_vint(c)?).map_err(|_| "bad length")?;
            let stored = if t == 0xe8 { (n * 8).div_ceil(7) } else { n };
            c.take(c.len(stored as u64)?)?;
            bytes(n)
        }
        0xec..=0xef => {
            let i = usize::from(t & 3) << 8 | usize::from(c.u8()?);
            Value::String(s.values.get(i).cloned().ok_or("bad shared value")?)
        }
        0xf8 => {
            w.enter()?;
            let mut items = Vec::new();
            while c.peek() != Some(0xf9) {
                keep(&mut items, sm_value(c, w, s)?);
            }
            c.u8()?;
            w.leave();
            Value::Array(items)
        }
        0xfa => {
            w.enter()?;
            let mut m = Map::new();
            loop {
                let k = c.u8()?;
                let name = match k {
                    0xfb => break,
                    0x20 => String::new(),
                    0x30..=0x33 => {
                        let i = usize::from(k & 3) << 8 | usize::from(c.u8()?);
                        s.names.get(i).cloned().ok_or("bad shared name")?
                    }
                    0x34 => sm_until_end(c)?,
                    0x40..=0x7f => s.names.get(usize::from(k & 0x3f)).cloned().ok_or("bad shared name")?,
                    0x80..=0xf7 => {
                        let n = usize::from(k & 0x3f) + if k < 0xc0 { 1 } else { 2 };
                        let name = String::from_utf8_lossy(c.take(n)?).into_owned();
                        Smile::remember(&mut s.names, s.share_names, &name);
                        name
                    }
                    _ => return Err("bad Smile key"),
                };
                let v = sm_value(c, w, s)?;
                keep_field(&mut m, name, v);
            }
            w.leave();
            Value::Object(m)
        }
        _ => return Err("bad Smile token"),
    })
}

// Ion ------------------------------------------------------------------------

const ION_SYSTEM: [&str; 10] = [
    "$0",
    "$ion",
    "$ion_1_0",
    "$ion_symbol_table",
    "name",
    "version",
    "imports",
    "symbols",
    "max_id",
    "$ion_shared_symbol_table",
];

fn ion_varuint(c: &mut Cur<'_>) -> Result<u64, Fail> {
    let mut v = 0u64;
    for _ in 0..10 {
        let b = c.u8()?;
        v = v << 7 | u64::from(b & 0x7f);
        if b & 0x80 != 0 {
            return Ok(v);
        }
    }
    Err("varuint too long")
}

fn ion_varint(c: &mut Cur<'_>) -> Result<i64, Fail> {
    let first = c.u8()?;
    let neg = first & 0x40 != 0;
    let mut v = u64::from(first & 0x3f);
    let mut b = first;
    let mut n = 0;
    while b & 0x80 == 0 {
        b = c.u8()?;
        v = v << 7 | u64::from(b & 0x7f);
        n += 1;
        if n > 9 {
            return Err("varint too long");
        }
    }
    let v = v.cast_signed();
    Ok(if neg { -v } else { v })
}

fn ion(data: &[u8], w: &mut Walk) -> Decoded {
    let mut d = Decoded::default();
    let mut symbols: Vec<String> = ION_SYSTEM.iter().map(|s| (*s).to_string()).collect();
    let mut c = Cur::new(data);
    while c.at < data.len() {
        if data[c.at..].starts_with(b"\xe0\x01\x00\xea") {
            c.at += 4;
            symbols.truncate(ION_SYSTEM.len());
            continue;
        }
        match ion_value(&mut c, w, &symbols) {
            Ok(None) => {}
            Ok(Some((annotations, v))) => {
                if annotations.first().map(String::as_str) == Some("$ion_symbol_table") {
                    // A local symbol table: append (or replace) symbols.
                    let append = v.get("imports").and_then(Value::as_str) == Some("$ion_symbol_table");
                    if !append {
                        symbols.truncate(ION_SYSTEM.len());
                    }
                    let new = v.get("symbols").and_then(Value::as_array).into_iter().flatten();
                    symbols.extend(new.map(|s| s.as_str().unwrap_or("").to_string()).take(100_000));
                    w.tag("symbol_table");
                    continue;
                }
                for a in &annotations {
                    w.tag(format!("annotation:{}", truncate_chars(a, 60)));
                }
                d.documents += 1;
                if d.docs.len() < super::SAMPLE_DOCS {
                    d.docs.push(v);
                }
            }
            Err(e) => {
                d.error = Some(e);
                d.trailing = data.len() - c.at;
                break;
            }
        }
    }
    d
}

fn ion_symbol(symbols: &[String], sid: u64) -> String {
    usize::try_from(sid).ok().and_then(|i| symbols.get(i)).cloned().unwrap_or_else(|| format!("${sid}"))
}

/// A value with its annotations; `None` for padding.
fn ion_value(c: &mut Cur<'_>, w: &mut Walk, sy: &[String]) -> Result<Option<(Vec<String>, Value)>, Fail> {
    let td = c.u8()?;
    let (t, l) = (td >> 4, td & 0x0f);
    let len = match (t, l) {
        (_, 15) | (1, _) => 0,
        // Lengths above 13 (and sorted structs) follow as a VarUInt.
        (_, 14) | (13, 1) => {
            let n = ion_varuint(c)?;
            c.len(n)?
        }
        _ => usize::from(l),
    };
    if t == 0 && l != 15 {
        c.take(len)?;
        return Ok(None);
    }
    w.value()?;
    let body = c.take(len)?;
    let mut b = Cur::new(body);
    if l == 15 && t != 1 {
        return Ok(Some((Vec::new(), Value::Null)));
    }
    let v = match t {
        1 => json!(l == 1),
        2 | 3 => {
            let mag = body.iter().fold(0u128, |a, &x| a << 8 | u128::from(x));
            let mag = i128::try_from(mag).unwrap_or(i128::MAX);
            let n = if t == 3 { -mag } else { mag };
            i64::try_from(n).map_or_else(|_| json!(n.to_string()), |n| json!(n))
        }
        4 => match len {
            0 => json!(0.0),
            4 => float(f64::from(f32::from_bits(u32::try_from(b.be(4)?).unwrap_or(0)))),
            8 => float(f64::from_bits(b.be(8)?)),
            _ => return Err("bad Ion float"),
        },
        5 => {
            w.tag("decimal");
            Value::String("decimal".into())
        }
        6 => {
            w.tag("timestamp");
            ion_timestamp(&mut b).unwrap_or(Value::String("timestamp".into()))
        }
        7 => {
            let sid = body.iter().fold(0u64, |a, &x| a << 8 | u64::from(x));
            Value::String(ion_symbol(sy, sid))
        }
        8 => text_or_bytes(body, w),
        9 | 10 => bytes(len),
        11 | 12 => {
            w.enter()?;
            let mut items = Vec::new();
            while b.at < body.len() {
                if let Some((_, v)) = ion_value(&mut b, w, sy)? {
                    keep(&mut items, v);
                }
            }
            w.leave();
            Value::Array(items)
        }
        13 => {
            w.enter()?;
            let mut m = Map::new();
            while b.at < body.len() {
                let name = ion_symbol(sy, ion_varuint(&mut b)?);
                if let Some((_, v)) = ion_value(&mut b, w, sy)? {
                    keep_field(&mut m, name, v);
                }
            }
            w.leave();
            Value::Object(m)
        }
        14 => {
            let n = ion_varuint(&mut b)?;
            let end = b.at + b.len(n)?;
            let mut annotations = Vec::new();
            while b.at < end {
                annotations.push(ion_symbol(sy, ion_varuint(&mut b)?));
            }
            let inner = ion_value(&mut b, w, sy)?.map_or(Value::Null, |(_, v)| v);
            return Ok(Some((annotations, inner)));
        }
        _ => return Err("reserved Ion type"),
    };
    Ok(Some((Vec::new(), v)))
}

fn ion_timestamp(b: &mut Cur<'_>) -> Option<Value> {
    let _offset = ion_varint(b).ok()?;
    let year = ion_varuint(b).ok()?;
    let mut parts = vec![year];
    while parts.len() < 6 && b.at < b.b.len() {
        parts.push(ion_varuint(b).ok()?);
    }
    let p = |i: usize| parts.get(i).copied().unwrap_or(u64::from(i < 3));
    Some(Value::String(format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", p(0), p(1), p(2), p(3), p(4), p(5))))
}

// Bencode --------------------------------------------------------------------

fn bencode(b: &[u8], w: &mut Walk) -> Result<(Value, usize), Fail> {
    let mut c = Cur::new(b);
    let v = be_value(&mut c, w)?;
    Ok((v, c.at))
}

fn be_digits(c: &mut Cur<'_>, end: u8) -> Result<i64, Fail> {
    let rest = &c.b[c.at..];
    let i = rest.iter().take(21).position(|&x| x == end).ok_or("truncated")?;
    let s = std::str::from_utf8(&rest[..i]).map_err(|_| "bad number")?;
    c.at += i + 1;
    s.parse().map_err(|_| "bad number")
}

fn be_bytes<'a>(c: &mut Cur<'a>) -> Result<&'a [u8], Fail> {
    let n = be_digits(c, b':')?;
    let n = c.len(u64::try_from(n).map_err(|_| "negative length")?)?;
    c.take(n)
}

fn be_value(c: &mut Cur<'_>, w: &mut Walk) -> Result<Value, Fail> {
    w.value()?;
    Ok(match c.peek().ok_or("truncated")? {
        b'i' => {
            c.u8()?;
            json!(be_digits(c, b'e')?)
        }
        b'l' => {
            c.u8()?;
            w.enter()?;
            let mut items = Vec::new();
            while c.peek().ok_or("truncated")? != b'e' {
                keep(&mut items, be_value(c, w)?);
            }
            c.u8()?;
            w.leave();
            Value::Array(items)
        }
        b'd' => {
            c.u8()?;
            w.enter()?;
            let mut m = Map::new();
            while c.peek().ok_or("truncated")? != b'e' {
                let k = String::from_utf8_lossy(be_bytes(c)?).into_owned();
                let v = be_value(c, w)?;
                keep_field(&mut m, k, v);
            }
            c.u8()?;
            w.leave();
            Value::Object(m)
        }
        b'0'..=b'9' => {
            let raw = be_bytes(c)?;
            text_or_bytes(raw, w)
        }
        _ => return Err("bad bencode token"),
    })
}

/// The raw bytes of the value under `key` in the top-level dictionary.
fn be_raw<'a>(data: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut c = Cur::new(data);
    if c.u8().ok()? != b'd' {
        return None;
    }
    let mut w = Walk::default();
    while c.peek()? != b'e' {
        let k = be_bytes(&mut c).ok()?;
        let start = c.at;
        be_value(&mut c, &mut w).ok()?;
        if k == key {
            return data.get(start..c.at);
        }
    }
    None
}

/// Torrent metainfo facts.
fn torrent(data: &[u8], d: &Decoded, cx: &mut Context<'_>) {
    let Some(top) = d.docs.first().and_then(Value::as_object) else { return };
    let Some(info) = top.get("info").and_then(Value::as_object).filter(|i| i.contains_key("piece length")) else {
        return;
    };
    cx.format_set("kind", "torrent");
    let mut t = Map::new();
    if let Some(n) = info.get("name").and_then(Value::as_str) {
        t.insert("name".into(), truncate_chars(n, 300).into());
        cx.content().title(truncate_chars(n, 300));
    }
    let files = info.get("files").and_then(Value::as_array);
    let total: u64 = match files {
        Some(f) => f.iter().filter_map(|x| x.get("length").and_then(Value::as_u64)).sum(),
        None => info.get("length").and_then(Value::as_u64).unwrap_or(0),
    };
    t.insert("files".into(), files.map_or(1, Vec::len).into());
    t.insert("total_size".into(), total.into());
    if let Some(p) = info.get("piece length").and_then(Value::as_u64) {
        t.insert("piece_length".into(), p.into());
    }
    if info.get("private").and_then(Value::as_i64) == Some(1) {
        t.insert("private".into(), true.into());
    }
    let mut trackers: Vec<&str> = top.get("announce").and_then(Value::as_str).into_iter().collect();
    for tier in top.get("announce-list").and_then(Value::as_array).into_iter().flatten() {
        trackers.extend(tier.as_array().into_iter().flatten().filter_map(Value::as_str));
    }
    trackers.sort_unstable();
    trackers.dedup();
    t.insert("trackers".into(), trackers.len().into());
    if let Some(s) = top.get("created by").and_then(Value::as_str) {
        t.insert("created_by".into(), truncate_chars(s, 200).into());
    }
    if let Some(s) = top.get("creation date").and_then(Value::as_i64).and_then(unix_time) {
        t.insert("created".into(), s.into());
    }
    if let Some(raw) = be_raw(data, b"info") {
        t.insert("info_hash".into(), hex(&der::sha1(raw)).into());
    }
    cx.format_set("torrent", Value::Object(t));
}

// PHP serialize ----------------------------------------------------------------

fn php_start(h: &[u8]) -> bool {
    matches!(h.first(), Some(b'a' | b'O' | b'C')) && h.get(1) == Some(&b':') && h.get(2).is_some_and(u8::is_ascii_digit)
}

fn php(b: &[u8], w: &mut Walk) -> Result<(Value, usize), Fail> {
    let mut c = Cur::new(b);
    let v = php_value(&mut c, w)?;
    // Whitespace between values of a file.
    while c.peek().is_some_and(|x| x.is_ascii_whitespace()) {
        c.at += 1;
    }
    Ok((v, c.at))
}

fn php_until(c: &mut Cur<'_>, end: u8) -> Result<String, Fail> {
    let rest = &c.b[c.at..];
    let i = rest.iter().take(64).position(|&x| x == end).ok_or("truncated")?;
    c.at += i + 1;
    Ok(String::from_utf8_lossy(&rest[..i]).into_owned())
}

fn php_expect(c: &mut Cur<'_>, s: &[u8]) -> Result<(), Fail> {
    if c.take(s.len())? == s { Ok(()) } else { Err("bad PHP serialized syntax") }
}

/// `N:"…"` (a length then a quoted string).
fn php_quoted(c: &mut Cur<'_>) -> Result<String, Fail> {
    let n: usize = php_until(c, b':')?.parse().map_err(|_| "bad length")?;
    php_expect(c, b"\"")?;
    let s = String::from_utf8_lossy(c.take(c.len(n as u64)?)?).into_owned();
    php_expect(c, b"\"")?;
    Ok(s)
}

fn php_value(c: &mut Cur<'_>, w: &mut Walk) -> Result<Value, Fail> {
    w.value()?;
    let t = c.u8()?;
    if t == b'N' {
        php_expect(c, b";")?;
        return Ok(Value::Null);
    }
    php_expect(c, b":")?;
    Ok(match t {
        b'b' => json!(php_until(c, b';')? == "1"),
        b'i' => json!(php_until(c, b';')?.parse::<i64>().map_err(|_| "bad integer")?),
        b'd' => float(php_until(c, b';')?.parse::<f64>().map_err(|_| "bad float")?),
        b'r' | b'R' => {
            php_until(c, b';')?;
            w.tag("reference");
            Value::Null
        }
        b's' => {
            let s = php_quoted(c)?;
            php_expect(c, b";")?;
            w.string(&s);
            Value::String(truncate_chars(&s, 2000))
        }
        b'E' => {
            let s = php_quoted(c)?;
            php_expect(c, b";")?;
            w.tag("enum");
            Value::String(truncate_chars(&s, 200))
        }
        b'a' | b'O' => {
            let class = if t == b'O' {
                let class = php_quoted(c)?;
                php_expect(c, b":")?;
                w.tag(class.clone());
                Some(class)
            } else {
                None
            };
            let n: u64 = php_until(c, b':')?.parse().map_err(|_| "bad count")?;
            let n = c.len(n)?;
            php_expect(c, b"{")?;
            w.enter()?;
            let mut m = Map::new();
            if let Some(cl) = class {
                m.insert("__class".into(), Value::String(truncate_chars(&cl, 200)));
            }
            for _ in 0..n {
                let k = key_of(&php_value(c, w)?);
                // Private and protected property names carry NUL-delimited prefixes.
                let k = k.rsplit('\0').next().unwrap_or(&k).to_string();
                let v = php_value(c, w)?;
                keep_field(&mut m, k, v);
            }
            php_expect(c, b"}")?;
            w.leave();
            Value::Object(m)
        }
        b'C' => {
            let class = php_quoted(c)?;
            php_expect(c, b":")?;
            w.tag(class.clone());
            let n: u64 = php_until(c, b':')?.parse().map_err(|_| "bad length")?;
            php_expect(c, b"{")?;
            c.take(c.len(n)?)?;
            php_expect(c, b"}")?;
            json!({ "__class": truncate_chars(&class, 200) })
        }
        _ => return Err("unknown PHP serialized type"),
    })
}

// NBT ------------------------------------------------------------------------

fn nbt_start(h: &[u8]) -> bool {
    let Some(n) = h.get(1..3).map(|b| usize::from(u16::from_be_bytes([b[0], b[1]]))) else { return false };
    h.first() == Some(&10)
        && n <= 64
        && h.get(3..3 + n).is_some_and(|s| s.iter().all(|c| c.is_ascii_graphic() || *c == b' '))
        && h.get(3 + n).is_some_and(|&t| t <= 12)
}

fn nbt(b: &[u8], w: &mut Walk, little: bool) -> Result<(Value, usize), Fail> {
    let mut c = Cur::new(b);
    let t = c.u8()?;
    if t != 10 {
        return Err("NBT must start with a compound");
    }
    let n = usize::try_from(if little { c.le(2)? } else { c.be(2)? }).map_err(|_| "bad length")?;
    let root = String::from_utf8_lossy(c.take(n)?).into_owned();
    let v = nbt_payload(&mut c, w, 10, little)?;
    if !root.is_empty() {
        w.tag(format!("root:{}", truncate_chars(&root, 60)));
    }
    Ok((v, c.at))
}

fn nbt_payload(c: &mut Cur<'_>, w: &mut Walk, t: u8, little: bool) -> Result<Value, Fail> {
    w.value()?;
    let num = |c: &mut Cur<'_>, n: usize| if little { c.le(n) } else { c.be(n) };
    let signed = |raw: u64, n: usize| (raw << (64 - 8 * n)).cast_signed() >> (64 - 8 * n);
    Ok(match t {
        1 => json!(signed(num(c, 1)?, 1)),
        2 => json!(signed(num(c, 2)?, 2)),
        3 => json!(signed(num(c, 4)?, 4)),
        4 => json!(signed(num(c, 8)?, 8)),
        5 => float(f64::from(f32::from_bits(u32::try_from(num(c, 4)?).unwrap_or(0)))),
        6 => float(f64::from_bits(num(c, 8)?)),
        7 | 11 | 12 => {
            let n = signed(num(c, 4)?, 4);
            let size = [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 8][usize::from(t)];
            let n = usize::try_from(n).map_err(|_| "negative length")?;
            let total = n.checked_mul(size).ok_or("length too large")?;
            c.take(c.len(total as u64)?)?;
            Value::String(format!(
                "<{n} {}>",
                ["", "", "", "", "", "", "", "bytes", "", "", "", "ints", "longs"][usize::from(t)]
            ))
        }
        8 => {
            let n = usize::try_from(num(c, 2)?).map_err(|_| "bad length")?;
            let s = String::from_utf8_lossy(c.take(n)?).into_owned();
            w.string(&s);
            Value::String(truncate_chars(&s, 2000))
        }
        9 => {
            let et = c.u8()?;
            let n = usize::try_from(signed(num(c, 4)?, 4).max(0)).map_err(|_| "bad length")?;
            if et > 12 || (et == 0 && n > 0) {
                return Err("bad NBT list type");
            }
            let n = c.len(n as u64)?;
            w.enter()?;
            let mut items = Vec::new();
            for _ in 0..n {
                keep(&mut items, nbt_payload(c, w, et, little)?);
            }
            w.leave();
            Value::Array(items)
        }
        10 => {
            w.enter()?;
            let mut m = Map::new();
            loop {
                let ct = c.u8()?;
                if ct == 0 {
                    break;
                }
                if ct > 12 {
                    return Err("bad NBT tag");
                }
                let n = usize::try_from(num(c, 2)?).map_err(|_| "bad length")?;
                let name = String::from_utf8_lossy(c.take(n)?).into_owned();
                let v = nbt_payload(c, w, ct, little)?;
                keep_field(&mut m, name, v);
            }
            w.leave();
            Value::Object(m)
        }
        _ => return Err("bad NBT tag"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::testing::report_for;

    type Decoder = fn(&[u8], &mut Walk) -> Result<(Value, usize), Fail>;

    fn one(f: Decoder, b: &[u8]) -> Value {
        f(b, &mut Walk::default()).unwrap().0
    }

    #[test]
    fn msgpack_values() {
        // {"a": [1, -1, "x"], "t": timestamp 0x5f5e1000}
        let b = b"\x82\xa1a\x93\x01\xff\xa1x\xa1t\xd6\xff\x5f\x5e\x10\x00";
        assert_eq!(one(msgpack, b), json!({ "a": [1, -1, "x"], "t": "2020-09-13T12:26:40Z" }));
        assert!(msgpack(b"\x92\x01", &mut Walk::default()).is_err());
    }

    #[test]
    fn cbor_values() {
        // {"a": [1, -2, h'00'], "b": 1.5 (half)}, indefinite array
        let b = b"\xa2\x61a\x83\x01\x21\x41\x00\x61b\xf9\x3e\x00";
        assert_eq!(one(cbor, b), json!({ "a": [1, -2, "<1 bytes>"], "b": 1.5 }));
        assert_eq!(one(cbor, b"\x9f\x01\x02\xff"), json!([1, 2]));
        assert!(cbor(b"\x9f\x01", &mut Walk::default()).is_err());
    }

    #[test]
    fn bson_document() {
        let mut doc = Vec::new();
        let body: &[u8] = b"\x02name\0\x05\0\0\0tide\0\x10n\0\x07\0\0\0\x04a\0\x0c\0\0\0\x100\0\x01\0\0\0\0";
        doc.extend(u32::try_from(body.len() + 5).unwrap().to_le_bytes());
        doc.extend(body);
        doc.push(0);
        assert_eq!(one(bson, &doc), json!({ "name": "tide", "n": 7, "a": [1] }));
        assert!(is_bson(&doc, doc.len() as u64));
    }

    #[test]
    fn ubjson_values() {
        assert_eq!(one(ubjson, b"{i\x01aSi\x02hi}"), json!({ "a": "hi" }));
        assert_eq!(one(ubjson, b"[$i#i\x03\x01\x02\x03"), json!([1, 2, 3]));
    }

    #[test]
    fn bencode_and_php() {
        assert_eq!(one(bencode, b"d1:ai1e1:bl2:xyee"), json!({ "a": 1, "b": ["xy"] }));
        assert_eq!(
            one(php, b"a:2:{s:1:\"a\";i:1;i:0;O:8:\"stdClass\":1:{s:1:\"x\";b:1;}}"),
            json!({ "a": 1, "0": { "__class": "stdClass", "x": true } })
        );
    }

    #[test]
    fn php_gadget_classes_are_flagged() {
        let s = b"O:32:\"Monolog\\Handler\\SyslogUdpHandler\":0:{}";
        let r = report_for("x.phpser", s);
        assert!(r.security.risks.iter().any(|r| r.kind == "unsafe_deserialization"));
    }

    #[test]
    fn nbt_compound() {
        let b = b"\x0a\x00\x04root\x08\x00\x04name\x00\x04tide\x03\x00\x01n\x00\x00\x00\x07\x00";
        let (v, n) = nbt(b, &mut Walk::default(), false).unwrap();
        assert_eq!((v, n), (json!({ "name": "tide", "n": 7 }), b.len()));
    }

    #[test]
    fn ion_symbols() {
        // BVM, local symbol table {symbols: ["tide"]}, then struct {tide: 1}.
        let mut b = b"\xe0\x01\x00\xea".to_vec();
        b.extend(b"\xea\x81\x83\xd7\x87\xb5\x84tide");
        b.extend(b"\xd3\x8a\x21\x01");
        let d = ion(&b, &mut Walk::default());
        assert_eq!(d.docs, vec![json!({ "tide": 1 })]);
    }

    #[test]
    fn deep_nesting_is_refused() {
        let b = vec![0x91u8; 1000];
        assert_eq!(msgpack(&b, &mut Walk::default()).unwrap_err(), "nested too deeply");
    }

    crate::fixture_tests!("msgpack", "cbor", "bson", "ubjson", "smile", "ion", "bencode", "php_serialized", "nbt");
}
