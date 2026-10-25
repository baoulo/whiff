//! bzip2 (block size from the header; the stream is decompressed and
//! analysed as the inner file).
//!
//! Specification: the bzip2 1.0.8 sources.

use super::{Stated, unpack};
use crate::plugin::{Codec, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for bzip2 files.
pub struct Bzip2;

static META: ExtractorMeta = ExtractorMeta {
    id: "compress.bzip2",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "bzip2",
        name: "bzip2",
        family: "compress",
        mimes: &["application/x-bzip2"],
        extensions: &["bz2", "bzip2", "tbz", "tbz2", "tb2"],
        // "BZh", the block size digit, then a block or the end-of-stream magic.
        magic: &[
            Magic::masked(0, b"BZh01AY&SY", b"\xff\xff\xff\xf0\xff\xff\xff\xff\xff\xff"),
            Magic::masked(0, b"BZh0\x17\x72\x45\x38\x50\x90", b"\xff\xff\xff\xf0\xff\xff\xff\xff\xff\xff"),
        ],
        parent: None,
    }],
};

impl Extractor for Bzip2 {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let level = src
            .head()
            .get(3)
            .copied()
            .filter(u8::is_ascii_digit)
            .ok_or_else(|| ExtractError::Unsupported("bzip2".into()))?;
        cx.format_set("block_size_bytes", u64::from(level - b'0') * 100_000);
        unpack(src, cx, Codec::Bzip2, &Stated::default())
    }
}

crate::register_extractor!(Bzip2);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("bzip2");
}
