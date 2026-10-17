//! Khronos textures: KTX 2 (Vulkan format, levels, layers, faces,
//! supercompression, key/value data such as the writer) and KTX 1.
//!
//! Specification: KTX File Format Specification 2.0 and 1.1 (Khronos).

use serde_json::{Map, Value, json};

use crate::plugin::{ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for KTX textures.
pub struct Ktx;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.ktx",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "ktx2",
            name: "KTX 2 texture",
            family: "image.texture",
            mimes: &["image/ktx2"],
            extensions: &["ktx2"],
            magic: &[Magic::prefix(b"\xabKTX 20\xbb\r\n\x1a\n")],
            parent: None,
        },
        FormatSpec {
            id: "ktx",
            name: "KTX texture",
            family: "image.texture",
            mimes: &["image/ktx"],
            extensions: &["ktx"],
            magic: &[Magic::prefix(b"\xabKTX 11\xbb\r\n\x1a\n")],
            parent: None,
        },
    ],
};

impl Extractor for Ktx {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head().to_vec();
        if cx.format_id() == "ktx" {
            return ktx1(&head, cx);
        }
        let mut r = ByteReader::new(&head).skip(12)?;
        let vk_format = r.le_u32()?;
        let _type_size = r.le_u32()?;
        let (w, h, depth) = (r.le_u32()?, r.le_u32()?, r.le_u32()?);
        let (layers, faces, levels) = (r.le_u32()?, r.le_u32()?, r.le_u32()?);
        let scheme = r.le_u32()?;
        r.advance(8)?; // DFD offset and length
        let (kvd_off, kvd_len) = (r.le_u32()?, r.le_u32()?);
        cx.physical().image(w, h.max(1));
        cx.format_set("vk_format", vk_format);
        cx.format_set("basis_universal", vk_format == 0 && scheme == 1);
        if depth > 0 {
            cx.format_set("depth", depth);
        }
        cx.format_set("layers", layers);
        cx.format_set("faces", faces);
        cx.format_set("levels", levels);
        cx.format_set(
            "supercompression",
            match scheme {
                0 => "none",
                1 => "BasisLZ",
                2 => "Zstandard",
                3 => "ZLIB",
                _ => "other",
            },
        );
        if kvd_len > 0 && kvd_len < 1 << 20 {
            let kvd = src.read_vec(u64::from(kvd_off), kvd_len as usize)?;
            let kv = key_values(&kvd);
            if let Some(Value::String(w)) = kv.get("KTXwriter") {
                cx.format_set("software", w.clone());
            }
            cx.format_set("key_values", Value::Object(kv));
        }
        Ok(())
    }
}

crate::register_extractor!(Ktx);

fn key_values(b: &[u8]) -> Map<String, Value> {
    let mut r = ByteReader::new(b);
    let mut m = Map::new();
    while let Ok(len) = r.le_u32() {
        let Ok(kv) = r.bytes(len as usize) else { break };
        let mut parts = kv.splitn(2, |&c| c == 0);
        let key = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
        let val = parts.next().unwrap_or_default();
        let printable = val.iter().all(|&c| c == 0 || (0x20..0x7f).contains(&c));
        let v = if printable {
            json!(String::from_utf8_lossy(val).trim_end_matches('\0'))
        } else {
            json!({ "binary_bytes": val.len() })
        };
        if m.len() < 64 {
            m.insert(key, v);
        }
        let pad = (4 - len as usize % 4) % 4;
        if r.advance(pad).is_err() {
            break;
        }
    }
    m
}

fn ktx1(head: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let le = head.get(12..16) == Some(&[1, 2, 3, 4]);
    let mut r = ByteReader::new(head).skip(16)?;
    let mut u = || -> Result<u32, ExtractError> { if le { r.le_u32() } else { r.be_u32() } };
    let (gl_type, _type_size, gl_format, internal, _base) = (u()?, u()?, u()?, u()?, u()?);
    let (w, h, depth, elements, faces, mips) = (u()?, u()?, u()?, u()?, u()?, u()?);
    cx.physical().image(w, h.max(1));
    cx.format_set("gl_type", gl_type);
    cx.format_set("gl_format", gl_format);
    cx.format_set("gl_internal_format", internal);
    cx.format_set("compressed", gl_type == 0);
    if depth > 0 {
        cx.format_set("depth", depth);
    }
    cx.format_set("array_elements", elements);
    cx.format_set("faces", faces);
    cx.format_set("levels", mips.max(1));
    Ok(())
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("ktx2", "ktx");
}
