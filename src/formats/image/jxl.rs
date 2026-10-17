//! JPEG XL: bare codestream or ISO BMFF container; image size from the
//! codestream `SizeHeader`; container boxes (EXIF, XMP, JUMBF / C2PA,
//! JPEG-reconstruction data, Brotli-compressed metadata).
//!
//! Specification: ISO/IEC 18181-1 (codestream), 18181-2 (file format).

use serde_json::json;

use super::{fourcc, read_box, top_boxes};
use crate::plugin::{BlockKind, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for JPEG XL.
pub struct Jxl;

const CONTAINER: &[u8] = b"\0\0\0\x0cJXL \r\n\x87\n";

static META: ExtractorMeta = ExtractorMeta {
    id: "image.jxl",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "jxl",
        name: "JPEG XL image",
        family: "image.raster",
        mimes: &["image/jxl"],
        extensions: &["jxl"],
        magic: &[Magic::prefix(b"\xff\x0a"), Magic::prefix(CONTAINER)],
        parent: None,
    }],
};

/// Metadata boxes larger than this are not read.
const MAX_BOX: u64 = 16 << 20;

impl Extractor for Jxl {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head().to_vec();
        let codestream: Vec<u8> = if head.starts_with(b"\xff\x0a") {
            cx.format_set("container", false);
            head
        } else {
            cx.format_set("container", true);
            let mut list = Vec::new();
            let mut stream = Vec::new();
            for b in top_boxes(src, 4096)? {
                list.push(fourcc(&b.kind));
                // The codestream only needs its first bytes (the size header).
                let body = match &b.kind {
                    b"jxlc" | b"jxlp" => src.read_vec(b.at, usize::try_from(b.len.min(256)).unwrap_or(0))?,
                    _ => match read_box(src, &b, MAX_BOX) {
                        Some(body) => body,
                        None => continue,
                    },
                };
                let body = body.as_slice();
                match &b.kind {
                    b"jxlc" if stream.is_empty() => stream.extend_from_slice(body),
                    b"jxlp" if stream.is_empty() => stream.extend_from_slice(body.get(4..).unwrap_or_default()),
                    b"Exif" if body.len() > 4 => {
                        let skip = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
                        if let Some(t) = body.get(4 + skip..) {
                            cx.emit_block(BlockKind::EXIF, t.to_vec());
                        }
                    }
                    b"xml " => cx.emit_block(BlockKind::XMP, body.to_vec()),
                    b"jumb" if body.windows(4).any(|w| w == b"c2pa") => {
                        cx.format_set("c2pa", true);
                        cx.security().signed(true);
                    }
                    b"jbrd" => cx.format_set("jpeg_reconstruction", true),
                    b"brob" => cx.format_set("brotli_compressed_metadata", true),
                    b"jxll" if !body.is_empty() => cx.format_set("level", body[0]),
                    _ => {}
                }
            }
            cx.format_set("boxes", json!(list));
            stream
        };
        match size_header(&codestream) {
            Some((w, h)) => {
                cx.physical().image(w, h);
            }
            None => cx.warn("no codestream size header"),
        }
        Ok(())
    }
}

crate::register_extractor!(Jxl);

/// LSB-first bit reader over the codestream.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn read(&mut self, n: usize) -> Option<u32> {
        let mut v = 0u32;
        for i in 0..n {
            let byte = *self.data.get((self.pos + i) / 8)?;
            v |= u32::from((byte >> ((self.pos + i) % 8)) & 1) << i;
        }
        self.pos += n;
        Some(v)
    }

    /// `U32(1 + u(9), 1 + u(13), 1 + u(18), 1 + u(30))`.
    fn size(&mut self) -> Option<u32> {
        let bits = [9, 13, 18, 30][self.read(2)? as usize];
        Some(self.read(bits)? + 1)
    }
}

/// Width and height from the `SizeHeader` after the `FF 0A` signature.
fn size_header(cs: &[u8]) -> Option<(u32, u32)> {
    if !cs.starts_with(b"\xff\x0a") {
        return None;
    }
    let mut b = Bits { data: &cs[2..], pos: 0 };
    let small = b.read(1)? == 1;
    let height = if small { (b.read(5)? + 1) * 8 } else { b.size()? };
    let ratio = b.read(3)?;
    let width = match ratio {
        0 if small => (b.read(5)? + 1) * 8,
        0 => b.size()?,
        1 => height,
        2 => height * 12 / 10,
        3 => height * 4 / 3,
        4 => height * 3 / 2,
        5 => height * 16 / 9,
        6 => height * 5 / 4,
        _ => height * 2,
    };
    Some((width, height))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_size_header() {
        // div8 = 1, height = (7 + 1) * 8 = 64, ratio = 1 (square).
        let bits: u32 = 1 | (7 << 1) | (1 << 6);
        let b = bits.to_le_bytes();
        let cs = [0xff, 0x0a, b[0], b[1]];
        assert_eq!(size_header(&cs), Some((64, 64)));
    }

    crate::fixture_tests!("jxl");
}
