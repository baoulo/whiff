//! The other single-stream formats. Decompressed and analysed as the inner
//! file: Brotli (no header; found by extension), Unix `compress` (`.Z`:
//! code width, block mode) and the Snappy framing format. Headers only:
//! lzop (version, method, level, original name and time, mode), LZFSE
//! (block kinds and sizes) and the old `pack` / `compact` / `freeze`
//! formats.
//!
//! Specifications: RFC 7932 (Brotli); the `ncompress` sources; Snappy
//! `framing_format.txt`; the lzop 1.04 sources (`lzop.c`, header layout);
//! Apple's `lzfse_internal.h` (block magics).

use super::{Stated, unix_time, unpack};
use crate::plugin::{
    ByteReader, Codec, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source,
    latin1_or_utf8,
};

/// Extractor for Brotli, `.Z`, Snappy, lzop and LZFSE files.
pub struct Other;

static META: ExtractorMeta = ExtractorMeta {
    id: "compress.other",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "brotli",
            name: "Brotli",
            family: "compress",
            mimes: &["application/x-brotli"],
            extensions: &["br"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "z",
            name: "Unix compress",
            family: "compress",
            mimes: &["application/x-compress"],
            extensions: &["z", "taz", "tz"],
            magic: &[Magic::prefix(b"\x1f\x9d")],
            parent: None,
        },
        FormatSpec {
            id: "snappy",
            name: "Snappy (framed)",
            family: "compress",
            mimes: &["application/x-snappy-framed"],
            extensions: &["sz", "snappy"],
            magic: &[Magic::prefix(b"\xff\x06\x00\x00sNaPpY")],
            parent: None,
        },
        FormatSpec {
            id: "lzop",
            name: "lzop",
            family: "compress",
            mimes: &["application/x-lzop"],
            extensions: &["lzo", "tzo"],
            magic: &[Magic::prefix(b"\x89LZO\x00\r\n\x1a\n")],
            parent: None,
        },
        FormatSpec {
            id: "lzfse",
            name: "LZFSE",
            family: "compress",
            mimes: &["application/x-lzfse"],
            extensions: &["lzfse"],
            magic: &[Magic::prefix(b"bvx2"), Magic::prefix(b"bvx1"), Magic::prefix(b"bvxn"), Magic::prefix(b"bvx-")],
            parent: None,
        },
    ],
};

impl Extractor for Other {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "brotli" => unpack(src, cx, Codec::Brotli, &Stated::default()),
            "z" => {
                let flags = *src.head().get(2).ok_or_else(|| ExtractError::Unsupported("compress".into()))?;
                cx.format_set("max_code_bits", flags & 0x1f);
                cx.format_set("block_mode", flags & 0x80 != 0);
                unpack(src, cx, Codec::Lzw, &Stated::default())
            }
            "snappy" => unpack(src, cx, Codec::Snappy, &Stated::default()),
            "lzop" => lzop(src.head(), cx),
            _ => lzfse(src.head(), cx),
        }
    }
}

crate::register_extractor!(Other);

fn lzop(head: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(head).skip(9)?;
    let version = r.be_u16()?;
    cx.format_set("version", format!("{}.{:03x}", version >> 12, version & 0xfff));
    r.be_u16()?; // library version
    if version >= 0x0940 {
        r.be_u16()?; // version needed to extract
    }
    let method = r.u8()?;
    cx.format_set(
        "method",
        match method {
            1 => "LZO1X-1",
            2 => "LZO1X-1(15)",
            3 => "LZO1X-999",
            _ => "unknown",
        },
    );
    if version >= 0x0940 {
        cx.format_set("level", r.u8()?);
    }
    let flags = r.be_u32()?;
    if flags & 0x800 != 0 {
        r.be_u32()?; // filter
    }
    let mode = r.be_u32()?;
    if mode != 0 {
        cx.format_set("mode", format!("{:o}", mode & 0o7777));
    }
    let mut mtime = i64::from(r.be_u32()?);
    if version >= 0x0940 {
        mtime |= i64::from(r.be_u32()?) << 32;
    }
    if let Some(t) = unix_time(mtime) {
        cx.format_set("modified", t.clone());
        cx.temporal().content_date(DateField::Modified, t, true);
    }
    let n = usize::from(r.u8()?);
    let name = latin1_or_utf8(r.bytes(n)?);
    if !name.is_empty() {
        cx.format_set("original_name", name);
    }
    cx.warn("LZO data is not decompressed");
    Ok(())
}

fn lzfse(head: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(head);
    let kind = r.bytes(4)?;
    cx.format_set(
        "first_block",
        match kind {
            b"bvx2" => "LZFSE (compressed tables)",
            b"bvx1" => "LZFSE",
            b"bvxn" => "LZVN",
            _ => "uncompressed",
        },
    );
    cx.format_set("first_block_size_bytes", r.le_u32()?);
    cx.warn("LZFSE data is not decompressed");
    Ok(())
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("brotli", "z", "snappy", "lzop", "lzfse");
}
