//! EXIF (TIFF-structured) blocks: IFD0, the Exif, GPS and Interoperability
//! IFDs, and the thumbnail IFD, decoded with `kamadak-exif` into
//! `metadata.exif` under the standard tag names.
//!
//! Numbers stay numbers (rationals become decimals; `ExposureTime` keeps its
//! `1/120` form), enumerations become their names, text is decoded (including
//! `UserComment` and the Windows `XP*` tags), and maker notes are reported by
//! size only. Normalised fields are left to the MWG analyzer.
//!
//! Specification: CIPA DC-008 (Exif 3.0), TIFF 6.0.

use exif::{Context as ExifContext, Field, In, Tag, Value as ExifValue};
use serde_json::{Map, Value, json};

use super::{MAX_ARRAY, binary, text_value};
use crate::plugin::{BlockDecoder, BlockKind, Context, ExtractError, TextRole};

/// Decoder for EXIF blocks.
pub struct Exif;

/// Larger blocks are not EXIF in practice; refuse them.
const MAX_BLOCK: usize = 64 * 1024 * 1024;

impl BlockDecoder for Exif {
    fn kind(&self) -> BlockKind {
        BlockKind::EXIF
    }

    fn id(&self) -> &'static str {
        "meta.exif"
    }

    fn decode(&self, data: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let tiff = strip_header(data);
        if tiff.len() < 8 || tiff.len() > MAX_BLOCK {
            return Err(ExtractError::malformed(format!("EXIF block of {} bytes", tiff.len())));
        }
        let mut reader = exif::Reader::new();
        reader.continue_on_error(true);
        let (parsed, errors) = match reader.read_raw(tiff.to_vec()) {
            Ok(e) => (e, Vec::new()),
            Err(exif::Error::PartialResult(p)) => p.into_inner(),
            Err(e) => return Err(ExtractError::malformed(e.to_string())),
        };
        if !errors.is_empty() {
            cx.warn(format!("EXIF: {} damaged entr{}", errors.len(), if errors.len() == 1 { "y" } else { "ies" }));
        }
        let (map, texts) = to_json(&parsed);
        for t in texts {
            cx.emit_text(TextRole::Metadata, &t);
        }
        // A file can carry several EXIF blocks (JPEG + MPF, TIFF + preview);
        // the first value of each tag wins.
        let target = cx.metadata("exif");
        for (k, v) in map {
            target.entry(k).or_insert(v);
        }
        Ok(())
    }
}

crate::register_block_decoder!(Exif);

/// The TIFF structure inside an APP1 / `eXIf` / `Exif` box payload.
pub fn strip_header(data: &[u8]) -> &[u8] {
    let d = data.strip_prefix(b"Exif\0\0").or_else(|| data.strip_prefix(b"Exif\0\xff")).unwrap_or(data);
    // Some writers put a few bytes before the byte-order mark.
    match d.windows(4).take(16).position(|w| w == b"II*\0" || w == b"MM\0*") {
        Some(i) => &d[i..],
        None => d,
    }
}

/// Tags whose numbers mean something: shown by name.
/// (`Orientation` stays a number: it is used as one, 1–8.)
const ENUMERATED: &[Tag] = &[
    Tag::ResolutionUnit,
    Tag::YCbCrPositioning,
    Tag::Compression,
    Tag::PhotometricInterpretation,
    Tag::ExposureProgram,
    Tag::MeteringMode,
    Tag::LightSource,
    Tag::Flash,
    Tag::ColorSpace,
    Tag::SensingMethod,
    Tag::CustomRendered,
    Tag::ExposureMode,
    Tag::WhiteBalance,
    Tag::SceneCaptureType,
    Tag::GainControl,
    Tag::Contrast,
    Tag::Saturation,
    Tag::Sharpness,
    Tag::SubjectDistanceRange,
    Tag::FocalPlaneResolutionUnit,
    Tag::SensitivityType,
    Tag::ComponentsConfiguration,
    Tag::SceneType,
    Tag::FileSource,
    Tag::CompositeImage,
];

/// Windows Explorer tags in IFD0 (UTF-16LE in BYTE arrays).
const XP_TAGS: &[(u16, &str)] =
    &[(0x9c9b, "XPTitle"), (0x9c9c, "XPComment"), (0x9c9d, "XPAuthor"), (0x9c9e, "XPKeywords"), (0x9c9f, "XPSubject")];

/// `metadata.exif`, plus texts worth handing to the analyzers.
fn to_json(e: &exif::Exif) -> (Map<String, Value>, Vec<String>) {
    let mut map = Map::new();
    let mut texts = Vec::new();
    let mut thumbnail = Map::new();
    let mut unknown = 0u64;
    // Primary image first, so its values win over the thumbnail's.
    let mut fields: Vec<&Field> = e.fields().collect();
    fields.sort_by_key(|f| f.ifd_num != In::PRIMARY);
    for f in fields {
        if f.ifd_num != In::PRIMARY {
            match f.tag {
                Tag::JPEGInterchangeFormatLength => {
                    thumbnail.insert("bytes".into(), number(&f.value));
                }
                Tag::ImageWidth | Tag::ImageLength | Tag::Compression => {
                    thumbnail.insert(f.tag.to_string(), value(f));
                }
                _ => {}
            }
            continue;
        }
        if let Some((_, name)) =
            XP_TAGS.iter().find(|(n, _)| f.tag.context() == ExifContext::Tiff && f.tag.number() == *n)
        {
            if let Some(s) = utf16_bytes(&f.value) {
                texts.push(s.clone());
                map.insert((*name).to_string(), text_value(&s));
            }
            continue;
        }
        if f.tag.description().is_none() {
            unknown += 1;
            continue;
        }
        let v = value(f);
        if matches!(f.tag, Tag::ImageDescription | Tag::UserComment)
            && let Some(s) = v.as_str()
        {
            texts.push(s.to_string());
        }
        map.insert(f.tag.to_string(), v);
    }
    if !thumbnail.is_empty() {
        map.insert("thumbnail".into(), Value::Object(thumbnail));
    }
    if unknown > 0 {
        map.insert("unknown_tags".into(), json!(unknown));
    }
    (map, texts)
}

fn value(f: &Field) -> Value {
    if ENUMERATED.contains(&f.tag) {
        return json!(f.display_value().to_string());
    }
    match (&f.value, f.tag) {
        (ExifValue::Undefined(b, _), Tag::MakerNote) => binary(b.len()),
        (ExifValue::Undefined(b, _), Tag::UserComment) => {
            user_comment(b).map_or_else(|| binary(b.len()), |s| text_value(&s))
        }
        (ExifValue::Undefined(b, _), Tag::ExifVersion | Tag::FlashpixVersion | Tag::InteroperabilityVersion) => {
            json!(String::from_utf8_lossy(b).trim_matches('\0'))
        }
        (ExifValue::Rational(r), Tag::ExposureTime) if r.len() == 1 => {
            let r = r[0];
            if r.num == 1 && r.denom > 1 { json!(format!("1/{}", r.denom)) } else { number(&f.value) }
        }
        (ExifValue::Byte(b), Tag::GPSVersionID) => {
            json!(b.iter().map(u8::to_string).collect::<Vec<_>>().join("."))
        }
        (ExifValue::Ascii(parts), _) => {
            let strings: Vec<String> = parts
                .iter()
                .map(|p| super::latin1_or_utf8(p).trim_matches(|c: char| c == '\0' || c == ' ').to_string())
                .filter(|s| !s.is_empty())
                .collect();
            match strings.as_slice() {
                [] => json!(""),
                [one] => text_value(one),
                many => json!(many),
            }
        }
        (ExifValue::Undefined(b, _) | ExifValue::Byte(b), _) => {
            if b.len() <= 8 {
                json!(b)
            } else {
                binary(b.len())
            }
        }
        _ => number(&f.value),
    }
}

/// Numbers, or arrays of numbers (long arrays summarised).
fn number(v: &ExifValue) -> Value {
    let round = |x: f64| if x.is_finite() { json!((x * 1e6).round() / 1e6) } else { Value::Null };
    let list: Vec<Value> = match v {
        ExifValue::Short(a) => a.iter().map(|x| json!(x)).collect(),
        ExifValue::Long(a) => a.iter().map(|x| json!(x)).collect(),
        ExifValue::SShort(a) => a.iter().map(|x| json!(x)).collect(),
        ExifValue::SLong(a) => a.iter().map(|x| json!(x)).collect(),
        ExifValue::SByte(a) => a.iter().map(|x| json!(x)).collect(),
        ExifValue::Rational(a) => {
            a.iter().map(|r| if r.denom == 0 { Value::Null } else { round(r.to_f64()) }).collect()
        }
        ExifValue::SRational(a) => {
            a.iter().map(|r| if r.denom == 0 { Value::Null } else { round(r.to_f64()) }).collect()
        }
        ExifValue::Float(a) => a.iter().map(|x| round(f64::from(*x))).collect(),
        ExifValue::Double(a) => a.iter().map(|x| round(*x)).collect(),
        ExifValue::Byte(a) | ExifValue::Undefined(a, _) => a.iter().map(|x| json!(x)).collect(),
        ExifValue::Ascii(_) | ExifValue::Unknown(..) => return Value::Null,
    };
    match list.len() {
        1 => list.into_iter().next().unwrap_or(Value::Null),
        n if n > MAX_ARRAY => json!({ "count": n }),
        _ => Value::Array(list),
    }
}

/// `UserComment`: an 8-byte character-code prefix, then the text.
fn user_comment(b: &[u8]) -> Option<String> {
    if b.len() < 8 {
        return None;
    }
    let (code, body) = b.split_at(8);
    let s = match code {
        b"UNICODE\0" => {
            let units: Vec<u16> = if body.starts_with(&[0xFE, 0xFF]) || (body.len() > 1 && body[0] == 0) {
                body.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect()
            } else {
                body.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect()
            };
            String::from_utf16_lossy(&units)
        }
        b"JIS\0\0\0\0\0" => encoding_rs::SHIFT_JIS.decode_without_bom_handling(body).0.into_owned(),
        _ => super::latin1_or_utf8(body),
    };
    let s = s.trim_matches(|c: char| c == '\0' || c.is_whitespace()).to_string();
    (!s.is_empty()).then_some(s)
}

fn utf16_bytes(v: &ExifValue) -> Option<String> {
    let (ExifValue::Byte(b) | ExifValue::Undefined(b, _)) = v else { return None };
    let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    let s = String::from_utf16_lossy(&units).trim_matches('\0').trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// GPS position from `metadata.exif` (decimal degrees, metres).
pub fn gps(m: &Map<String, Value>) -> Option<(f64, f64, Option<f64>)> {
    let coord = |v: &str, r: &str| -> Option<f64> {
        let parts: Vec<f64> = match m.get(v)? {
            Value::Array(a) => a.iter().filter_map(Value::as_f64).collect(),
            Value::Number(n) => vec![n.as_f64()?],
            _ => return None,
        };
        let deg = parts.first()? + parts.get(1).unwrap_or(&0.0) / 60.0 + parts.get(2).unwrap_or(&0.0) / 3600.0;
        let negative = m.get(r).and_then(Value::as_str).is_some_and(|s| s.starts_with('S') || s.starts_with('W'));
        Some(if negative { -deg } else { deg })
    };
    let lat = coord("GPSLatitude", "GPSLatitudeRef")?;
    let lon = coord("GPSLongitude", "GPSLongitudeRef")?;
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) || (lat == 0.0 && lon == 0.0) {
        return None;
    }
    let alt = m.get("GPSAltitude").and_then(Value::as_f64).map(|a| {
        let below = m.get("GPSAltitudeRef").and_then(Value::as_u64) == Some(1);
        if below { -a } else { a }
    });
    Some((round6(lat), round6(lon), alt))
}

fn round6(x: f64) -> f64 {
    (x * 1e6).round() / 1e6
}

/// `2026:09:14 17:03:22` (+ `OffsetTime*` `+02:00`) → RFC 3339 / civil date-time.
pub fn date(m: &Map<String, Value>, tag: &str, offset_tag: &str) -> Option<(String, bool)> {
    let raw = m.get(tag)?.as_str()?.trim();
    let b = raw.as_bytes();
    // Digits and separators only, so the byte slices below are on char boundaries.
    if b.len() < 19 || !b[..19].is_ascii() || b[4] != b':' || b[7] != b':' || raw.starts_with("0000") {
        return None;
    }
    let civil = format!("{}-{}-{}T{}", &raw[..4], &raw[5..7], &raw[8..10], &raw[11..19]);
    match m.get(offset_tag).and_then(Value::as_str).map(str::trim) {
        Some(off) if off.len() == 6 && (off.starts_with('+') || off.starts_with('-')) => {
            crate::text::parse_date(&format!("{civil}{off}"))
        }
        _ => crate::text::parse_date(&civil),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_and_helpers() {
        assert_eq!(strip_header(b"Exif\0\0II*\0rest"), b"II*\0rest");
        assert_eq!(strip_header(b"\0\0\0\x06Exif\0\0MM\0*x").len(), 5);
        assert_eq!(user_comment(b"ASCII\0\0\0Harbour at dusk\0").as_deref(), Some("Harbour at dusk"));
        let mut m = Map::new();
        m.insert("GPSLatitude".into(), json!([43.0, 17.0, 47.4]));
        m.insert("GPSLatitudeRef".into(), json!("N"));
        m.insert("GPSLongitude".into(), json!([5.0, 22.0, 11.28]));
        m.insert("GPSLongitudeRef".into(), json!("E"));
        m.insert("DateTimeOriginal".into(), json!("2026:09:14 17:03:22"));
        m.insert("OffsetTimeOriginal".into(), json!("+02:00"));
        let (lat, lon, _) = gps(&m).unwrap();
        assert!((lat - 43.2965).abs() < 1e-4 && (lon - 5.3698).abs() < 1e-4);
        assert_eq!(
            date(&m, "DateTimeOriginal", "OffsetTimeOriginal"),
            Some(("2026-09-14T17:03:22+02:00".into(), true))
        );
        assert_eq!(date(&m, "DateTimeOriginal", "None"), Some(("2026-09-14T17:03:22".into(), false)));
    }
}
