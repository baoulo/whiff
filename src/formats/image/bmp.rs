//! Windows bitmap (BMP / DIB): every header version (OS/2 core, `INFO`,
//! v2–v5), size, bit depth, compression, resolution, palette, colour space
//! and the ICC profile embedded in v5 headers.
//!
//! Specification: Microsoft BITMAPINFOHEADER / BITMAPV5HEADER.

use crate::plugin::{
    BlockKind, ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source,
};

/// Extractor for BMP.
pub struct Bmp;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.bmp",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "bmp",
        name: "BMP image",
        family: "image.raster",
        mimes: &["image/bmp"],
        extensions: &["bmp", "dib"],
        // `BM`, then the file size, then two reserved words that are zero.
        magic: &[Magic::masked(0, b"BM\0\0\0\0\0\0\0\0", b"\xff\xff\0\0\0\0\xff\xff\xff\xff")],
        parent: None,
    }],
};

impl Extractor for Bmp {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head().to_vec();
        let mut r = ByteReader::new(&head).skip(2)?;
        let file_size = r.le_u32()?;
        r.advance(4)?;
        let data_offset = r.le_u32()?;
        let header_size = r.le_u32()?;
        let (w, h, planes, bpp) = if header_size == 12 {
            (i64::from(r.le_u16()?), i64::from(r.le_u16()?), r.le_u16()?, r.le_u16()?)
        } else if header_size >= 40 {
            (i64::from(r.le_u32()?.cast_signed()), i64::from(r.le_u32()?.cast_signed()), r.le_u16()?, r.le_u16()?)
        } else {
            return Err(ExtractError::malformed(format!("DIB header of {header_size} bytes")));
        };
        let header = match header_size {
            12 => "BITMAPCOREHEADER",
            40 => "BITMAPINFOHEADER",
            52 => "BITMAPV2INFOHEADER",
            56 => "BITMAPV3INFOHEADER",
            64 => "OS22XBITMAPHEADER",
            108 => "BITMAPV4HEADER",
            124 => "BITMAPV5HEADER",
            _ => "unknown",
        };
        let (width, height) =
            (u32::try_from(w.unsigned_abs()).unwrap_or(0), u32::try_from(h.unsigned_abs()).unwrap_or(0));
        let mut img = cx.physical().image(width, height);
        img.bit_depth(u8::try_from(bpp).unwrap_or(0));
        if bpp <= 8 {
            img.channels(3).color_space("palette");
        }
        cx.format_set("header", header);
        cx.format_set("top_down", h < 0);
        cx.format_set("planes", planes);
        cx.format_set("bits_per_pixel", bpp);
        cx.format_set("declared_size", file_size);
        cx.format_set("pixel_data_offset", data_offset);
        if header_size >= 40 {
            let compression = r.le_u32()?;
            let _image_size = r.le_u32()?;
            let (xppm, yppm) = (r.le_u32()?, r.le_u32()?);
            let colors = r.le_u32()?;
            cx.format_set(
                "compression",
                match compression {
                    0 => "none",
                    1 => "RLE8",
                    2 => "RLE4",
                    3 => "bitfields",
                    4 => "JPEG",
                    5 => "PNG",
                    6 => "alpha bitfields",
                    11..=13 => "CMYK",
                    _ => "other",
                },
            );
            if colors > 0 {
                cx.format_set("palette_colors", colors);
            }
            if xppm > 0
                && yppm > 0
                && let Some(mut img) = cx.physical().existing_image()
            {
                img.dpi(
                    (f64::from(xppm) * 0.0254 * 100.0).round() / 100.0,
                    (f64::from(yppm) * 0.0254 * 100.0).round() / 100.0,
                );
            }
        }
        if header_size >= 108 {
            let mut v = ByteReader::new(&head).skip(14 + 56)?;
            let space = v.bytes(4)?;
            let name = match space {
                b"BGRs" => "sRGB",
                b" niW" => "Windows default",
                b"KNIL" => "linked profile",
                b"DEBM" => "embedded profile",
                [0, 0, 0, 0] => "calibrated RGB",
                _ => "unknown",
            };
            cx.format_set("color_space", name);
            if name == "sRGB"
                && let Some(mut img) = cx.physical().existing_image()
            {
                img.color_space("sRGB");
            }
            if header_size >= 124 && space == b"DEBM" {
                let mut p = ByteReader::new(&head).skip(14 + 112)?;
                let (offset, size) = (p.le_u32()?, p.le_u32()?);
                if size > 0 && size < 16 << 20 {
                    let at = 14 + u64::from(offset);
                    match src.read_vec(at, size as usize) {
                        Ok(icc) => cx.emit_block(BlockKind::ICC, icc),
                        Err(e) => cx.warn(format!("embedded ICC profile: {e}")),
                    }
                }
            }
        }
        Ok(())
    }
}

crate::register_extractor!(Bmp);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("bmp");
}
