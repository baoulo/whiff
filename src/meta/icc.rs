//! ICC colour profiles: header (class, colour space, PCS, version, CMM,
//! creation date, rendering intent, device manufacturer and model) and the
//! description, copyright and white-point tags, into `metadata.icc`.
//!
//! Specification: ICC.1:2022 (v4.4), ICC.1:2001-04 (v2).

use serde_json::{Map, Value, json};

use super::text_value;
use crate::plugin::{BlockDecoder, BlockKind, ByteReader, Context, ExtractError};

/// Decoder for ICC profiles.
pub struct Icc;

const MAX_TAGS: u32 = 256;

impl BlockDecoder for Icc {
    fn kind(&self) -> BlockKind {
        BlockKind::ICC
    }

    fn id(&self) -> &'static str {
        "meta.icc"
    }

    fn decode(&self, data: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let m = parse(data)?;
        let target = cx.metadata("icc");
        if target.is_empty() {
            *target = m;
        }
        Ok(())
    }
}

crate::register_block_decoder!(Icc);

fn four_cc(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim_matches(|c: char| c == '\0' || c == ' ').to_string()
}

/// The profile as `metadata.icc`.
pub fn parse(data: &[u8]) -> Result<Map<String, Value>, ExtractError> {
    if data.len() < 132 || &data[36..40] != b"acsp" {
        return Err(ExtractError::malformed("not an ICC profile (no acsp signature)"));
    }
    let mut r = ByteReader::new(data);
    let declared = r.be_u32()?;
    let cmm = four_cc(r.bytes(4)?);
    let version = r.bytes(4)?;
    let class = four_cc(r.bytes(4)?);
    let space = four_cc(r.bytes(4)?);
    let pcs = four_cc(r.bytes(4)?);
    let mut created = [0u16; 6];
    for d in &mut created {
        *d = r.be_u16()?;
    }
    r.advance(4)?; // acsp
    let platform = four_cc(r.bytes(4)?);
    r.advance(4)?; // flags
    let manufacturer = four_cc(r.bytes(4)?);
    let model = four_cc(r.bytes(4)?);
    r.advance(8)?; // attributes
    let intent = r.be_u32()?;

    let mut m = Map::new();
    m.insert("version".into(), json!(format!("{}.{}.{}", version[0], version[1] >> 4, version[1] & 0x0f)));
    m.insert(
        "class".into(),
        json!(match class.as_str() {
            "scnr" => "input",
            "mntr" => "display",
            "prtr" => "output",
            "link" => "device link",
            "spac" => "colour space",
            "abst" => "abstract",
            "nmcl" => "named colour",
            other => other,
        }),
    );
    m.insert("color_space".into(), json!(space));
    m.insert("pcs".into(), json!(pcs));
    for (k, v) in [("cmm", &cmm), ("platform", &platform), ("manufacturer", &manufacturer), ("model", &model)] {
        if !v.is_empty() {
            m.insert(k.into(), json!(v));
        }
    }
    if created[0] > 1900 {
        m.insert(
            "created".into(),
            json!(format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
                created[0], created[1], created[2], created[3], created[4], created[5]
            )),
        );
    }
    m.insert(
        "rendering_intent".into(),
        json!(match intent {
            0 => "perceptual",
            1 => "relative colorimetric",
            2 => "saturation",
            3 => "absolute colorimetric",
            _ => "unknown",
        }),
    );
    m.insert("size_bytes".into(), json!(declared));

    let mut t = ByteReader::new(data).skip(128)?;
    let count = t.be_u32()?.min(MAX_TAGS);
    for _ in 0..count {
        let sig = four_cc(t.bytes(4)?);
        let offset = t.be_u32()? as usize;
        let size = t.be_u32()? as usize;
        let Some(body) = offset.checked_add(size).and_then(|end| data.get(offset..end)) else { continue };
        let key = match sig.as_str() {
            "desc" => "description",
            "cprt" => "copyright",
            "dmnd" => "device_manufacturer",
            "dmdd" => "device_model",
            "wtpt" => "white_point",
            "lumi" => "luminance",
            _ => continue,
        };
        let value = match key {
            "white_point" | "luminance" => xyz(body),
            _ => text_tag(body).map(|s| text_value(&s)),
        };
        if let Some(v) = value {
            m.insert(key.into(), v);
        }
    }
    Ok(m)
}

/// `desc` (v2 textDescription), `text`, or `mluc` (v4, first record).
fn text_tag(b: &[u8]) -> Option<String> {
    let kind = b.get(..4)?;
    let s = match kind {
        b"desc" => {
            let n = u32::from_be_bytes(b.get(8..12)?.try_into().ok()?) as usize;
            String::from_utf8_lossy(b.get(12..12 + n.min(b.len().saturating_sub(12)))?).into_owned()
        }
        b"text" => String::from_utf8_lossy(b.get(8..)?).into_owned(),
        b"mluc" => {
            let records = u32::from_be_bytes(b.get(8..12)?.try_into().ok()?);
            if records == 0 {
                return None;
            }
            let len = u32::from_be_bytes(b.get(20..24)?.try_into().ok()?) as usize;
            let off = u32::from_be_bytes(b.get(24..28)?.try_into().ok()?) as usize;
            let units: Vec<u16> =
                b.get(off..off.checked_add(len)?)?.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
            String::from_utf16_lossy(&units)
        }
        _ => return None,
    };
    let s = s.trim_matches(|c: char| c == '\0' || c.is_whitespace()).to_string();
    (!s.is_empty()).then_some(s)
}

/// `XYZ ` type: the first triplet, as decimals.
fn xyz(b: &[u8]) -> Option<Value> {
    if b.get(..4)? != b"XYZ " {
        return None;
    }
    let f = |i: usize| -> Option<f64> {
        let v = i32::from_be_bytes(b.get(8 + 4 * i..12 + 4 * i)?.try_into().ok()?);
        Some((f64::from(v) / 65536.0 * 1e4).round() / 1e4)
    };
    Some(json!([f(0)?, f(1)?, f(2)?]))
}

/// A minimal valid v2 display profile (header + desc + cprt + wtpt), for tests and fixtures.
#[cfg(test)]
pub(crate) fn sample_profile(description: &str) -> Vec<u8> {
    let mut desc = b"desc\0\0\0\0".to_vec();
    desc.extend_from_slice(&u32::try_from(description.len() + 1).unwrap().to_be_bytes());
    desc.extend_from_slice(description.as_bytes());
    desc.push(0);
    desc.extend_from_slice(&[0; 79]);
    let cprt = b"text\0\0\0\0No copyright, use freely\0".to_vec();
    let mut wtpt = b"XYZ \0\0\0\0".to_vec();
    for v in [63190i32, 65536, 54061] {
        wtpt.extend_from_slice(&v.to_be_bytes());
    }
    let tags: [(&[u8; 4], &Vec<u8>); 3] = [(b"desc", &desc), (b"cprt", &cprt), (b"wtpt", &wtpt)];
    let mut body = Vec::new();
    let mut table = Vec::new();
    let mut offset = 128 + 4 + 12 * tags.len();
    for (sig, data) in tags {
        table.extend_from_slice(sig);
        table.extend_from_slice(&u32::try_from(offset).unwrap().to_be_bytes());
        table.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
        body.extend_from_slice(data);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        offset = 128 + 4 + 12 * tags.len() + body.len();
    }
    let total = 128 + 4 + table.len() + body.len();
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&u32::try_from(total).unwrap().to_be_bytes());
    p.extend_from_slice(b"none");
    p.extend_from_slice(&[2, 0x10, 0, 0]);
    p.extend_from_slice(b"mntrRGB XYZ ");
    for v in [2026u16, 10, 16, 12, 0, 0] {
        p.extend_from_slice(&v.to_be_bytes());
    }
    p.extend_from_slice(b"acsp");
    p.resize(128, 0);
    p.extend_from_slice(&u32::try_from(tags.len()).unwrap().to_be_bytes());
    p.extend_from_slice(&table);
    p.extend_from_slice(&body);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header_and_tags() {
        let m = parse(&sample_profile("Harbour RGB")).unwrap();
        assert_eq!(m["description"], json!("Harbour RGB"));
        assert_eq!(m["class"], json!("display"));
        assert_eq!(m["color_space"], json!("RGB"));
        assert_eq!(m["version"], json!("2.1.0"));
        assert_eq!(m["created"], json!("2026-10-16T12:00:00"));
        assert_eq!(m["white_point"], json!([0.9642, 1.0, 0.8249]));
        assert!(parse(b"short").is_err());
    }
}
