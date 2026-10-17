//! GIMP XCF: version, size, base type and precision, compression,
//! resolution, the image parasites (comment, ICC profile, EXIF, XMP) and
//! the layer names.
//!
//! Specification: GIMP `devel-docs/xcf.txt`.

use serde_json::json;

use crate::plugin::{
    BlockKind, ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, TextRole,
};

/// Extractor for XCF.
pub struct Xcf;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.xcf",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "xcf",
        name: "GIMP image",
        family: "image.layered",
        mimes: &["image/x-xcf"],
        extensions: &["xcf"],
        magic: &[Magic::prefix(b"gimp xcf ")],
        parent: None,
    }],
};

/// Bytes of image properties read.
const MAX_PROPS: usize = 32 << 20;
const MAX_LAYERS: usize = 10_000;

impl Extractor for Xcf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, _) = src.read_prefix(MAX_PROPS)?;
        let mut r = ByteReader::new(&data).skip(9)?;
        let tag = r.bytes(4)?;
        let version: u32 = match tag {
            b"file" => 0,
            [b'v', rest @ ..] => std::str::from_utf8(rest).ok().and_then(|s| s.parse().ok()).unwrap_or(0),
            _ => return Err(ExtractError::malformed("version tag")),
        };
        r.tag(b"\0")?;
        let (w, h) = (r.be_u32()?, r.be_u32()?);
        let base = r.be_u32()?;
        let precision = if version >= 4 { Some(r.be_u32()?) } else { None };
        let (space, channels) = match base {
            0 => ("RGB", 3),
            1 => ("Gray", 1),
            2 => ("indexed", 3),
            _ => ("unknown", 0),
        };
        let mut img = cx.physical().image(w, h);
        img.color_space(space).channels(channels);
        let (bits, linear) = match precision {
            None => (8, false),
            Some(p) if version < 7 => ([8, 16, 32, 16, 32].get(p as usize).copied().unwrap_or(8), false),
            // 100s: 8-bit, 200s: 16, 300s: 32 (integer); 500s half, 600s float, 700s double.
            Some(p) => (
                match p / 100 {
                    2 | 5 => 16,
                    3 | 6 => 32,
                    7 => 64,
                    _ => 8,
                },
                p % 100 == 0,
            ),
        };
        img.bit_depth(u8::try_from(bits).unwrap_or(8));
        cx.format_set("version", version);
        cx.format_set("base_type", space);
        if precision.is_some() {
            cx.format_set("precision", json!({ "bits": bits, "linear": linear }));
        }

        // Image properties.
        let mut comment = None;
        for _ in 0..10_000 {
            let (Ok(kind), Ok(len)) = (r.be_u32(), r.be_u32()) else { break };
            if kind == 0 {
                break;
            }
            let Ok(p) = r.bytes(len as usize) else { break };
            match kind {
                17 => cx.format_set(
                    "compression",
                    match p.first() {
                        Some(0) => "none",
                        Some(1) => "RLE",
                        Some(2) => "zlib",
                        Some(3) => "fractal",
                        _ => "unknown",
                    },
                ),
                19 if p.len() == 8 => {
                    let x = f64::from(f32::from_be_bytes([p[0], p[1], p[2], p[3]]));
                    let y = f64::from(f32::from_be_bytes([p[4], p[5], p[6], p[7]]));
                    if let Some(mut img) = cx.physical().existing_image() {
                        img.dpi((x * 100.0).round() / 100.0, (y * 100.0).round() / 100.0);
                    }
                }
                21 => comment = parasites(p, cx).or(comment),
                _ => {}
            }
        }
        // Layer pointers (64-bit from version 11).
        let mut layers = Vec::new();
        let mut names = Vec::new();
        while layers.len() < MAX_LAYERS {
            let ptr = if version >= 11 { r.be_u64() } else { r.be_u32().map(u64::from) };
            match ptr {
                Ok(0) | Err(_) => break,
                Ok(p) => layers.push(p),
            }
        }
        for &p in layers.iter().take(256) {
            let Ok(at) = usize::try_from(p) else { continue };
            let mut l = ByteReader::new(&data);
            if l.seek(at).is_err() || l.advance(12).is_err() {
                continue;
            }
            if let Ok(len) = l.be_u32()
                && let Ok(n) = l.bytes(len as usize)
            {
                names.push(String::from_utf8_lossy(n).trim_end_matches('\0').to_string());
            }
        }
        cx.format_set("layers", layers.len());
        if !names.is_empty() {
            cx.format_set("layer_names", json!(names));
        }
        if let Some(c) = comment {
            cx.content().source("xcf.gimp-comment").description(c.clone());
            cx.emit_text(TextRole::Comment, &c);
        }
        Ok(())
    }
}

crate::register_extractor!(Xcf);

/// Image parasites; returns the comment, if any.
fn parasites(p: &[u8], cx: &mut Context<'_>) -> Option<String> {
    let mut r = ByteReader::new(p);
    let mut comment = None;
    let mut list = Vec::new();
    while r.remaining() > 8 {
        let Ok(len) = r.be_u32() else { break };
        let Ok(name) = r.bytes(len as usize) else { break };
        let name = String::from_utf8_lossy(name).trim_end_matches('\0').to_string();
        let (Ok(_flags), Ok(size)) = (r.be_u32(), r.be_u32()) else { break };
        let Ok(d) = r.bytes(size as usize) else { break };
        match name.as_str() {
            "gimp-comment" => comment = Some(String::from_utf8_lossy(d).trim_end_matches('\0').to_string()),
            "icc-profile" => cx.emit_block(BlockKind::ICC, d.to_vec()),
            "exif-data" => cx.emit_block(BlockKind::EXIF, d.strip_prefix(b"Exif\0\0").unwrap_or(d).to_vec()),
            "gimp-metadata" if d.windows(7).any(|w| w == b"rdf:RDF") => cx.emit_block(BlockKind::XMP, d.to_vec()),
            _ => {}
        }
        if list.len() < 64 {
            list.push(name);
        }
    }
    cx.format_set("parasites", json!(list));
    comment
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("xcf");
}
