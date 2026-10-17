//! GIF 87a / 89a: screen size, palette, frames, total duration, loop count,
//! comments and the XMP application extension. Image data is skipped
//! block by block, never decompressed.
//!
//! Specification: GIF89a (CompuServe, 1990).

use serde_json::json;

use crate::plugin::{
    BlockKind, ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, TextRole,
    truncate_chars,
};

/// Extractor for GIF.
pub struct Gif;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.gif",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "gif",
        name: "GIF image",
        family: "image.raster",
        mimes: &["image/gif"],
        extensions: &["gif"],
        magic: &[Magic::prefix(b"GIF87a"), Magic::prefix(b"GIF89a")],
        parent: None,
    }],
};

const MAX_FRAMES: u32 = 100_000;

impl Extractor for Gif {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, _) = cx.read_bytes(src)?;
        let mut r = ByteReader::new(&data);
        let version = String::from_utf8_lossy(r.bytes(6)?).into_owned();
        let w = r.le_u16()?;
        let h = r.le_u16()?;
        let packed = r.u8()?;
        let _background = r.u8()?;
        let _aspect = r.u8()?;
        let global = packed & 0x80 != 0;
        let palette = 1usize << ((packed & 7) + 1);
        if global {
            r.advance(3 * palette)?;
        }
        cx.physical()
            .image(u32::from(w), u32::from(h))
            .bit_depth(((packed >> 4) & 7) + 1)
            .channels(3)
            .color_space("palette");

        let mut a = Blocks::default();
        let mut complete = false;
        while let Ok(b) = r.u8() {
            if a.frames % 512 == 0 {
                cx.checkpoint()?;
            }
            match b {
                0x2C => {
                    a.frames += 1;
                    if a.frames > MAX_FRAMES {
                        break;
                    }
                    r.advance(8)?;
                    let p = r.u8()?;
                    if p & 0x80 != 0 {
                        r.advance(3 * (1usize << ((p & 7) + 1)))?;
                    }
                    r.advance(1)?; // LZW minimum code size
                    skip_sub_blocks(&mut r)?;
                }
                0x21 => a.extension(&mut r, &data, cx)?,
                0x3B => {
                    complete = true;
                    break;
                }
                _ => {
                    cx.warn(format!("unexpected block 0x{b:02X} at offset {}", r.position() - 1));
                    break;
                }
            }
        }
        for c in &a.comments {
            cx.emit_text(TextRole::Comment, c);
        }
        if let Some(mut img) = cx.physical().existing_image() {
            img.frames(a.frames);
        }
        if a.frames > 1 {
            cx.physical().duration_s(a.delay_cs as f64 / 100.0);
        }
        cx.format_set("version", version);
        cx.format_set("global_palette", if global { json!(palette) } else { json!(null) });
        cx.format_set("frames", a.frames);
        cx.format_set("animated", a.frames > 1);
        if let Some(l) = a.loops {
            cx.format_set("loop_count", if l == 0 { json!("infinite") } else { json!(l) });
        }
        cx.format_set("transparency", a.transparency);
        if !a.comments.is_empty() {
            cx.format_set("comments", json!(a.comments));
        }
        if !complete {
            cx.format_set("complete", false);
        }
        Ok(())
    }
}

crate::register_extractor!(Gif);

/// What the frames and extension blocks add up to.
#[derive(Default)]
struct Blocks {
    frames: u32,
    delay_cs: u64,
    loops: Option<u16>,
    transparency: bool,
    comments: Vec<String>,
}

impl Blocks {
    /// An extension block (after its `0x21` introducer).
    fn extension(&mut self, r: &mut ByteReader<'_>, data: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match r.u8()? {
            0xF9 => {
                let body = sub_blocks(r, 16)?;
                if body.len() >= 4 {
                    self.transparency |= body[0] & 1 != 0;
                    self.delay_cs += u64::from(u16::from_le_bytes([body[1], body[2]]));
                }
            }
            0xFE => {
                let c = sub_blocks(r, 64 * 1024)?;
                // Encoders often repeat one comment on every frame.
                let c = truncate_chars(&crate::plugin::latin1_or_utf8(&c), 1000);
                if self.comments.len() < 16 && !self.comments.contains(&c) {
                    self.comments.push(c);
                }
            }
            0xFF => {
                let size = usize::from(r.u8()?);
                let id = r.bytes(size)?;
                if id.starts_with(b"NETSCAPE2.0") || id.starts_with(b"ANIMEXTS1.0") {
                    let body = sub_blocks(r, 16)?;
                    if body.len() >= 3 && body[0] == 1 {
                        self.loops = Some(u16::from_le_bytes([body[1], body[2]]));
                    }
                } else {
                    if id.starts_with(b"XMP DataXMP") {
                        // The packet is stored raw, followed by a 258-byte "magic
                        // trailer" (01 FF FE … 01 00 00) that makes it parse as sub-blocks.
                        let rest = &data[r.position()..];
                        if let Some(end) = rest.windows(4).position(|w| w == [0x01, 0xff, 0xfe, 0xfd]) {
                            cx.emit_block(BlockKind::XMP, rest[..end].to_vec());
                        }
                    }
                    skip_sub_blocks(r)?;
                }
            }
            _ => skip_sub_blocks(r)?,
        }
        Ok(())
    }
}

fn skip_sub_blocks(r: &mut ByteReader<'_>) -> Result<(), ExtractError> {
    loop {
        let n = r.u8()?;
        if n == 0 {
            return Ok(());
        }
        r.advance(usize::from(n))?;
    }
}

/// Concatenated sub-block data, up to `max` bytes (the rest is skipped).
fn sub_blocks(r: &mut ByteReader<'_>, max: usize) -> Result<Vec<u8>, ExtractError> {
    let mut out = Vec::new();
    loop {
        let n = r.u8()?;
        if n == 0 {
            return Ok(out);
        }
        let b = r.bytes(usize::from(n))?;
        if out.len() < max {
            out.extend_from_slice(b);
        }
    }
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("gif");
}
