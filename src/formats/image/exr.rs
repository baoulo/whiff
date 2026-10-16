//! OpenEXR: version flags (tiled, multi-part, deep), and the header
//! attributes: data and display windows, channels, compression, line order,
//! owner, comments, capture date, location, frame rate, software and more.
//!
//! Specification: OpenEXR file layout (openexr.com).

use serde_json::{Map, Value, json};

use crate::plugin::{
    ByteReader, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, TextRole,
};

/// Extractor for OpenEXR.
pub struct Exr;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.exr",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "exr",
        name: "OpenEXR image",
        family: "image.texture",
        mimes: &["image/x-exr"],
        extensions: &["exr", "sxr", "mxr"],
        magic: &[Magic::prefix(b"\x76\x2f\x31\x01")],
        parent: None,
    }],
};

const MAX_ATTRS: usize = 512;

impl Extractor for Exr {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head().to_vec();
        let mut r = ByteReader::new(&head).skip(4)?;
        let flags = r.le_u32()?;
        let (tiled, long_names, deep, multipart) =
            (flags & 0x200 != 0, flags & 0x400 != 0, flags & 0x800 != 0, flags & 0x1000 != 0);
        cx.format_set("version", flags & 0xff);
        cx.format_set("tiled", tiled);
        cx.format_set("deep", deep);
        cx.format_set("multipart", multipart);
        let max_name = if long_names { 255 } else { 31 };
        let mut attrs = Map::new();
        let mut parts = 1u32;
        for _ in 0..MAX_ATTRS {
            let name = cstr(&mut r, max_name)?;
            if name.is_empty() {
                if multipart && r.peek(1).is_some_and(|b| b[0] != 0) {
                    parts += 1;
                    continue;
                }
                break;
            }
            let ty = cstr(&mut r, max_name)?;
            let size = r.le_u32()? as usize;
            let v = r.bytes(size)?;
            if attrs.contains_key(&name) {
                continue;
            }
            attrs.insert(name, value(&ty, v));
        }
        if let Some(Value::Array(dw)) = attrs.get("dataWindow")
            && let [x0, y0, x1, y1] = dw.as_slice()
            && let (Some(x0), Some(y0), Some(x1), Some(y1)) = (x0.as_i64(), y0.as_i64(), x1.as_i64(), y1.as_i64())
        {
            let channels = attrs.get("channels").and_then(Value::as_array).map_or(0, Vec::len);
            let w = u32::try_from(x1 - x0 + 1).unwrap_or(0);
            let h = u32::try_from(y1 - y0 + 1).unwrap_or(0);
            let mut img = cx.physical().image(w, h);
            img.channels(u8::try_from(channels).unwrap_or(u8::MAX)).color_space("linear");
            let half =
                attrs.get("channels").and_then(Value::as_array).is_some_and(|c| c.iter().all(|c| c["type"] == "half"));
            img.bit_depth(if half { 16 } else { 32 });
        }
        if let Some(o) = attrs.get("owner").and_then(Value::as_str) {
            cx.rights().source("exr.owner").creator(o).copyright(o);
        }
        if let Some(c) = attrs.get("comments").and_then(Value::as_str) {
            cx.content().source("exr.comments").description(c);
            cx.emit_text(TextRole::Caption, c);
        }
        if let Some(d) = attrs.get("capDate").and_then(Value::as_str) {
            // `YYYY:MM:DD hh:mm:ss`, local time; `utcOffset` is seconds UTC - local.
            let civil = d.replacen(':', "-", 2).replacen(' ', "T", 1);
            let offset = attrs.get("utcOffset").and_then(Value::as_f64).filter(|s| s.abs() < 86_400.0).map(|s| {
                let secs = i64::from(super::px(s.abs()));
                if s > 0.0 { -secs } else { secs }
            });
            let value = match offset {
                Some(o) => format!(
                    "{civil}{}{:02}:{:02}",
                    if o < 0 { '-' } else { '+' },
                    o.abs() / 3600,
                    (o.abs() % 3600) / 60
                ),
                None => civil,
            };
            if let Some((v, tz)) = crate::plugin::parse_date(&value) {
                cx.temporal().source("exr.capDate").content_date(DateField::Captured, v, tz);
            }
        }
        if let (Some(lat), Some(lon)) =
            (attrs.get("latitude").and_then(Value::as_f64), attrs.get("longitude").and_then(Value::as_f64))
        {
            cx.content().source("exr.latitude").location(lat, lon, attrs.get("altitude").and_then(Value::as_f64));
        }
        if multipart {
            cx.format_set("parts", parts);
        }
        cx.format_set("attributes", Value::Object(attrs));
        Ok(())
    }
}

crate::register_extractor!(Exr);

fn cstr(r: &mut ByteReader<'_>, max: usize) -> Result<String, ExtractError> {
    let mut out = Vec::new();
    loop {
        let b = r.u8()?;
        if b == 0 {
            return Ok(String::from_utf8_lossy(&out).into_owned());
        }
        if out.len() >= max {
            return Err(ExtractError::malformed("attribute name too long"));
        }
        out.push(b);
    }
}

fn value(ty: &str, v: &[u8]) -> Value {
    let mut r = ByteReader::new(v);
    let f32s = |r: &mut ByteReader<'_>, n: usize| -> Option<Vec<f64>> {
        (0..n).map(|_| r.le_u32().ok().map(|b| (f64::from(f32::from_bits(b)) * 1e4).round() / 1e4)).collect()
    };
    match ty {
        "box2i" => (0..4)
            .map(|_| r.le_u32().map(u32::cast_signed))
            .collect::<Result<Vec<_>, _>>()
            .map_or(Value::Null, |v| json!(v)),
        "box2f" => f32s(&mut r, 4).map_or(Value::Null, |v| json!(v)),
        "int" => r.le_u32().map_or(Value::Null, |x| json!(x.cast_signed())),
        "float" => f32s(&mut r, 1).map_or(Value::Null, |v| json!(v[0])),
        "double" => r.le_u64().map_or(Value::Null, |b| json!((f64::from_bits(b) * 1e6).round() / 1e6)),
        "v2i" => (0..2)
            .map(|_| r.le_u32().map(u32::cast_signed))
            .collect::<Result<Vec<_>, _>>()
            .map_or(Value::Null, |v| json!(v)),
        "v2f" => f32s(&mut r, 2).map_or(Value::Null, |v| json!(v)),
        "v3f" => f32s(&mut r, 3).map_or(Value::Null, |v| json!(v)),
        "chromaticities" => f32s(&mut r, 8).map_or(Value::Null, |v| json!(v)),
        "rational" => match (r.le_u32(), r.le_u32()) {
            (Ok(n), Ok(d)) if d != 0 => json!((f64::from(n.cast_signed()) / f64::from(d) * 1e4).round() / 1e4),
            _ => Value::Null,
        },
        "string" => json!(crate::plugin::truncate_chars(&String::from_utf8_lossy(v), 2000)),
        "compression" => json!(match v.first() {
            Some(0) => "none",
            Some(1) => "RLE",
            Some(2) => "ZIPS",
            Some(3) => "ZIP",
            Some(4) => "PIZ",
            Some(5) => "PXR24",
            Some(6) => "B44",
            Some(7) => "B44A",
            Some(8) => "DWAA",
            Some(9) => "DWAB",
            Some(10) => "HTJ2K",
            _ => "unknown",
        }),
        "lineOrder" => json!(match v.first() {
            Some(0) => "increasing Y",
            Some(1) => "decreasing Y",
            _ => "random Y",
        }),
        "chlist" => {
            let mut out = Vec::new();
            while let Ok(name) = cstr(&mut r, 255) {
                if name.is_empty() || out.len() > 64 {
                    break;
                }
                let Ok(t) = r.le_u32() else { break };
                if r.advance(12).is_err() {
                    break;
                }
                let t = match t {
                    0 => "uint",
                    1 => "half",
                    2 => "float",
                    _ => "unknown",
                };
                out.push(json!({ "name": name, "type": t }));
            }
            Value::Array(out)
        }
        _ => json!({ "type": ty, "binary_bytes": v.len() }),
    }
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("exr");
}
