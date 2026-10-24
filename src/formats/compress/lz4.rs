//! LZ4 (the first frame's descriptor: block size, independence, content
//! size, checksums, dictionary id; the legacy format named). The stream is
//! decompressed and analysed as the inner file.
//!
//! Specification: LZ4 Frame Format Description 1.6.4.

use super::{Stated, unpack};
use crate::plugin::{
    ByteReader, Codec, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source,
};

/// Extractor for LZ4 files.
pub struct Lz4;

static META: ExtractorMeta = ExtractorMeta {
    id: "compress.lz4",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "lz4",
        name: "LZ4",
        family: "compress",
        mimes: &["application/x-lz4"],
        extensions: &["lz4"],
        magic: &[Magic::prefix(b"\x04\x22\x4d\x18"), Magic::prefix(b"\x02\x21\x4c\x18")],
        parent: None,
    }],
};

impl Extractor for Lz4 {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head();
        let mut stated = Stated::default();
        if head.starts_with(b"\x02\x21\x4c\x18") {
            cx.format_set("variant", "legacy");
        } else {
            let mut r = ByteReader::new(head).skip(4)?;
            let flg = r.u8()?;
            let bd = r.u8()?;
            if flg >> 6 != 1 {
                return Err(ExtractError::malformed("LZ4 frame version"));
            }
            let block = match (bd >> 4) & 7 {
                4 => 64u64 << 10,
                5 => 256 << 10,
                6 => 1 << 20,
                7 => 4 << 20,
                _ => return Err(ExtractError::malformed("LZ4 block size")),
            };
            cx.format_set("block_size_bytes", block);
            cx.format_set("independent_blocks", flg & 0x20 != 0);
            cx.format_set("block_checksums", flg & 0x10 != 0);
            cx.format_set("content_checksum", flg & 0x04 != 0);
            if flg & 0x08 != 0 {
                stated.size = Some(r.le_u64()?);
            }
            if flg & 0x01 != 0 {
                cx.format_set("dictionary_id", r.le_u32()?);
                cx.warn("the frame needs a dictionary that is not in the file");
                return Ok(());
            }
        }
        unpack(src, cx, Codec::Lz4, &stated)
    }
}

crate::register_extractor!(Lz4);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("lz4");
}
