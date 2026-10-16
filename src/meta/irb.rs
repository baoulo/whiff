//! Photoshop image resource blocks (`8BIM` records in JPEG APP13, TIFF tag
//! 34377 and PSD files). The IPTC, ICC, EXIF and XMP they carry are passed
//! on to their decoders; resolution, thumbnail, version, copyright flag, URL
//! and the IPTC digest go to `metadata.photoshop`. The digest says whether
//! the IPTC block still matches the XMP (MWG reconciliation uses it).
//!
//! Specification: Adobe Photoshop File Formats Specification, "Image Resource Blocks".

use md5::{Digest, Md5};
use serde_json::{Map, Value, json};

use super::text_value;
use crate::plugin::{BlockDecoder, BlockKind, ByteReader, Context, ExtractError};

/// Decoder for Photoshop image resource blocks.
pub struct Irb;

const MAX_RESOURCES: usize = 4096;

/// Names of the resources listed in `metadata.photoshop.resources`.
const NAMES: &[(u16, &str)] = &[
    (0x03e8, "channels_rows_columns"),
    (0x03ed, "resolution_info"),
    (0x03ee, "alpha_channel_names"),
    (0x03f3, "print_flags"),
    (0x0404, "iptc_naa"),
    (0x0406, "jpeg_quality"),
    (0x0408, "grid_and_guides"),
    (0x0409, "thumbnail_ps4"),
    (0x040a, "copyright_flag"),
    (0x040b, "url"),
    (0x040c, "thumbnail"),
    (0x040f, "icc_profile"),
    (0x0414, "document_id_seed"),
    (0x0419, "global_altitude"),
    (0x041a, "slices"),
    (0x0421, "version_info"),
    (0x0422, "exif_data_1"),
    (0x0423, "exif_data_3"),
    (0x0424, "xmp"),
    (0x0425, "iptc_digest"),
    (0x0426, "print_scale"),
    (0x0428, "pixel_aspect_ratio"),
    (0x042d, "layer_selection_ids"),
    (0x0435, "layer_comps"),
    (0x043a, "print_information"),
    (0x0bb7, "clipping_path_name"),
    (0x2710, "print_flags_info"),
];

impl BlockDecoder for Irb {
    fn kind(&self) -> BlockKind {
        BlockKind::PHOTOSHOP_IRB
    }

    fn id(&self) -> &'static str {
        "meta.photoshop"
    }

    fn decode(&self, data: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let resources = resources(data)?;
        let mut m = Map::new();
        let mut listed = Vec::new();
        let mut iptc_md5 = None;
        let mut digest = None;
        for (id, body) in &resources {
            if listed.len() < 128 {
                let name = NAMES
                    .iter()
                    .find(|(i, _)| i == id)
                    .map_or_else(|| format!("0x{id:04x}"), |(_, n)| (*n).to_string());
                listed.push(json!(name));
            }
            match id {
                0x0404 => {
                    iptc_md5 = Some(hex(&Md5::digest(body)));
                    cx.emit_block(BlockKind::IPTC_IIM, body.clone());
                }
                0x040f => cx.emit_block(BlockKind::ICC, body.clone()),
                0x0422 | 0x0423 => cx.emit_block(BlockKind::EXIF, body.clone()),
                0x0424 => cx.emit_block(BlockKind::XMP, body.clone()),
                0x0425 if body.len() == 16 => digest = Some(hex(body)),
                0x03ed if body.len() >= 16 => {
                    let fixed = |o: usize| {
                        f64::from(u32::from_be_bytes([body[o], body[o + 1], body[o + 2], body[o + 3]])) / 65536.0
                    };
                    let (h, v) = (fixed(0), fixed(8));
                    let per_cm = u16::from_be_bytes([body[4], body[5]]) == 2;
                    let to_dpi =
                        |x: f64| if per_cm { (x * 2.54 * 100.0).round() / 100.0 } else { (x * 100.0).round() / 100.0 };
                    m.insert("resolution_dpi".into(), json!([to_dpi(h), to_dpi(v)]));
                }
                0x040a if !body.is_empty() => {
                    m.insert("copyright_flag".into(), json!(body[0] != 0));
                }
                0x040b => {
                    m.insert("url".into(), text_value(&super::latin1_or_utf8(body)));
                }
                0x0409 | 0x040c if body.len() >= 28 => {
                    let u = |o: usize| u32::from_be_bytes([body[o], body[o + 1], body[o + 2], body[o + 3]]);
                    m.insert("thumbnail".into(), json!({ "width": u(4), "height": u(8), "bytes": u(20) }));
                }
                0x0421 => {
                    if let Some((writer, reader)) = version_info(body) {
                        m.insert("writer".into(), text_value(&writer));
                        m.insert("reader".into(), text_value(&reader));
                    }
                }
                _ => {}
            }
        }
        if let Some(d) = &digest {
            m.insert("iptc_digest".into(), json!(d));
            if let Some(actual) = &iptc_md5 {
                m.insert("iptc_digest_matches".into(), json!(actual == d));
            }
        }
        m.insert("resources".into(), Value::Array(listed));
        let target = cx.metadata("photoshop");
        for (k, v) in m {
            target.entry(k).or_insert(v);
        }
        Ok(())
    }
}

crate::register_block_decoder!(Irb);

/// `(resource id, data)` for each block. An optional `Photoshop 3.0\0` prefix is skipped.
pub fn resources(data: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, ExtractError> {
    let data = data.strip_prefix(b"Photoshop 3.0\0").unwrap_or(data);
    let mut r = ByteReader::new(data);
    let mut out = Vec::new();
    while r.remaining() >= 12 && out.len() < MAX_RESOURCES {
        let sig = r.array::<4>()?;
        if !matches!(&sig, b"8BIM" | b"MeSa" | b"PHUT" | b"AgHg" | b"DCSR") {
            break;
        }
        let id = r.be_u16()?;
        // Pascal name padded to an even length (length byte included).
        let name_len = usize::from(r.u8()?);
        r.advance(name_len + usize::from(name_len % 2 == 0))?;
        let size = r.be_u32()? as usize;
        let Ok(body) = r.bytes(size) else { break };
        out.push((id, body.to_vec()));
        if size % 2 == 1 && !r.is_empty() {
            r.advance(1)?;
        }
    }
    if out.is_empty() {
        return Err(ExtractError::malformed("no 8BIM resources"));
    }
    Ok(out)
}

/// Resource 0x0421: version, has-real-merged-data, writer and reader names (UTF-16 strings).
fn version_info(b: &[u8]) -> Option<(String, String)> {
    let mut r = ByteReader::new(b).skip(5).ok()?;
    let mut string = || -> Option<String> {
        let n = r.be_u32().ok()? as usize;
        let raw = r.bytes(n.checked_mul(2)?).ok()?;
        let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
        Some(String::from_utf16_lossy(&units).trim_matches('\0').to_string())
    };
    Some((string()?, string()?))
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::with_capacity(b.len() * 2), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resources() {
        let mut data = b"Photoshop 3.0\0".to_vec();
        let mut push = |id: u16, body: &[u8]| {
            data.extend_from_slice(b"8BIM");
            data.extend_from_slice(&id.to_be_bytes());
            data.extend_from_slice(&[0, 0]);
            data.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
            data.extend_from_slice(body);
            if body.len() % 2 == 1 {
                data.push(0);
            }
        };
        push(0x040a, &[1]);
        push(0x0404, b"\x1c\x02\x05\x00\x03abc");
        let r = resources(&data).unwrap();
        assert_eq!(r.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [0x040a, 0x0404]);
        assert!(resources(b"nothing").is_err());
    }
}
