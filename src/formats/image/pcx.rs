//! ZSoft PCX: version, size, bit depth, planes and resolution.
//!
//! Specification: ZSoft PCX Technical Reference Manual.

use crate::plugin::{ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for PCX.
pub struct Pcx;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.pcx",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "pcx",
        name: "PCX image",
        family: "image.raster",
        mimes: &["image/vnd.zbrush.pcx"],
        extensions: &["pcx"],
        // Manufacturer 10, version 0–5, RLE encoding 1.
        magic: &[Magic::masked(0, b"\x0a\x00\x01", b"\xff\xf8\xff")],
        parent: None,
    }],
};

impl Extractor for Pcx {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head().to_vec();
        let mut r = ByteReader::new(&head).skip(1)?;
        let version = r.u8()?;
        r.advance(1)?;
        let bits = r.u8()?;
        let (x0, y0, x1, y1) = (r.le_u16()?, r.le_u16()?, r.le_u16()?, r.le_u16()?);
        let (hdpi, vdpi) = (r.le_u16()?, r.le_u16()?);
        r.advance(48 + 1)?;
        let planes = r.u8()?;
        if x1 < x0 || y1 < y0 {
            return Err(ExtractError::malformed("window"));
        }
        let mut img = cx.physical().image(u32::from(x1 - x0) + 1, u32::from(y1 - y0) + 1);
        img.bit_depth(bits).channels(planes);
        if hdpi > 0 && vdpi > 0 {
            img.dpi(f64::from(hdpi), f64::from(vdpi));
        }
        cx.format_set(
            "version",
            match version {
                0 => "2.5",
                2 => "2.8 with palette",
                3 => "2.8 without palette",
                4 => "PC Paintbrush for Windows",
                5 => "3.0",
                _ => "unknown",
            },
        );
        cx.format_set("planes", planes);
        Ok(())
    }
}

crate::register_extractor!(Pcx);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("pcx");
}
