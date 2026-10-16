//! QOI (Quite OK Image): size, channels and colour space.
//!
//! Specification: qoiformat.org/qoi-specification.pdf.

use crate::plugin::{ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for QOI.
pub struct Qoi;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.qoi",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "qoi",
        name: "QOI image",
        family: "image.raster",
        mimes: &["image/qoi"],
        extensions: &["qoi"],
        magic: &[Magic::prefix(b"qoif")],
        parent: None,
    }],
};

impl Extractor for Qoi {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut r = ByteReader::new(src.head()).skip(4)?;
        let (w, h) = (r.be_u32()?, r.be_u32()?);
        let channels = r.u8()?;
        let space = r.u8()?;
        if !matches!(channels, 3 | 4) || space > 1 {
            return Err(ExtractError::malformed(format!("channels {channels}, colour space {space}")));
        }
        cx.physical().image(w, h).channels(channels).bit_depth(8).color_space(if space == 0 {
            "sRGB"
        } else {
            "linear"
        });
        Ok(())
    }
}

crate::register_extractor!(Qoi);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("qoi");
}
