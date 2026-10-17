//! WebP: lossy (`VP8 `), lossless (`VP8L`) and extended (`VP8X`) files,
//! canvas size, alpha, animation (frames, duration, loops), and the
//! embedded EXIF, XMP and ICC chunks.
//!
//! Specification: RFC 9649 (WebP Image Format).

use serde_json::json;

use crate::plugin::{BlockKind, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for WebP.
pub struct WebP;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.webp",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "webp",
        name: "WebP image",
        family: "image.raster",
        mimes: &["image/webp"],
        extensions: &["webp"],
        magic: &[Magic::masked(0, b"RIFF\0\0\0\0WEBP", b"\xff\xff\xff\xff\0\0\0\0\xff\xff\xff\xff")],
        parent: None,
    }],
};

const MAX_CHUNKS: usize = 100_000;
/// Metadata chunks larger than this are not read.
const MAX_META: u32 = 16 << 20;

impl Extractor for WebP {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let mut pos = 12u64;
        let (mut kind, mut canvas, mut alpha) = (None, None, false);
        let (mut frames, mut duration_ms, mut loops) = (0u32, 0u64, None);
        let mut chunks = Vec::new();
        for n in 0..MAX_CHUNKS {
            if n % 256 == 0 {
                cx.checkpoint()?;
            }
            let Ok(h) = src.read_vec(pos, 8) else { break };
            let id = [h[0], h[1], h[2], h[3]];
            let size = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
            let body_at = pos + 8;
            if body_at + u64::from(size) > len {
                cx.warn(format!("chunk {} runs past the end", String::from_utf8_lossy(&id)));
                break;
            }
            if chunks.len() < 32 {
                chunks.push(String::from_utf8_lossy(&id).trim_end().to_string());
            }
            match &id {
                b"VP8 " => {
                    kind.get_or_insert("lossy");
                    let d = src.read_vec(body_at, (size as usize).min(10))?;
                    if canvas.is_none() && d.len() == 10 && d[3..6] == [0x9d, 0x01, 0x2a] {
                        canvas = Some((
                            u32::from(u16::from_le_bytes([d[6], d[7]]) & 0x3fff),
                            u32::from(u16::from_le_bytes([d[8], d[9]]) & 0x3fff),
                        ));
                    }
                }
                b"VP8L" => {
                    kind.get_or_insert("lossless");
                    let d = src.read_vec(body_at, (size as usize).min(5))?;
                    if canvas.is_none() && d.len() == 5 && d[0] == 0x2f {
                        let bits = u32::from_le_bytes([d[1], d[2], d[3], d[4]]);
                        canvas = Some(((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1));
                        alpha |= (bits >> 28) & 1 == 1;
                    }
                }
                b"VP8X" => {
                    let d = src.read_vec(body_at, (size as usize).min(10))?;
                    if d.len() == 10 {
                        alpha |= d[0] & 0x10 != 0;
                        let w = u32::from_le_bytes([d[4], d[5], d[6], 0]) + 1;
                        let h = u32::from_le_bytes([d[7], d[8], d[9], 0]) + 1;
                        canvas = Some((w, h));
                    }
                }
                b"ALPH" => alpha = true,
                b"ANIM" => {
                    let d = src.read_vec(body_at, (size as usize).min(6))?;
                    if d.len() == 6 {
                        loops = Some(u16::from_le_bytes([d[4], d[5]]));
                    }
                }
                b"ANMF" => {
                    frames += 1;
                    let d = src.read_vec(body_at, (size as usize).min(16))?;
                    if d.len() >= 15 {
                        duration_ms += u64::from(u32::from_le_bytes([d[12], d[13], d[14], 0]));
                    }
                }
                b"EXIF" | b"XMP " | b"ICCP" if size <= MAX_META => {
                    let d = src.read_vec(body_at, size as usize)?;
                    let kind = match &id {
                        b"EXIF" => BlockKind::EXIF,
                        b"XMP " => BlockKind::XMP,
                        _ => BlockKind::ICC,
                    };
                    cx.emit_block(kind, d);
                }
                _ => {}
            }
            pos = body_at + u64::from(size) + u64::from(size % 2);
            if pos >= len {
                break;
            }
        }
        if let Some((w, h)) = canvas {
            let mut img = cx.physical().image(w, h);
            img.bit_depth(8).channels(if alpha { 4 } else { 3 });
            if frames > 1 {
                img.frames(frames);
            }
        }
        if frames > 0 {
            cx.physical().duration_s(duration_ms as f64 / 1000.0);
            cx.format_set("animation", json!({ "frames": frames, "duration_ms": duration_ms, "loop_count": loops }));
        }
        cx.format_set("compression", kind.unwrap_or(if frames > 0 { "animated" } else { "unknown" }));
        cx.format_set("alpha", alpha);
        cx.format_set("chunks", json!(chunks));
        Ok(())
    }
}

crate::register_extractor!(WebP);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("webp");
}
