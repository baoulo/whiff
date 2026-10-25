//! The LZMA family: xz (check type, streams, blocks and the uncompressed
//! size from the index, the first block's filter chain and dictionary),
//! `.lzma` (properties, dictionary, declared size) and lzip (version,
//! dictionary, sizes from the member trailer). Each stream is decompressed
//! and analysed as the inner file.
//!
//! Specifications: The .xz File Format 1.2.1; the LZMA SDK's `lzma.txt`
//! (`.lzma` header); the lzip manual §10 (file format).

use super::{Stated, unpack};
use crate::plugin::{
    ByteReader, Codec, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    codec,
};

/// Extractor for xz, `.lzma` and lzip files.
pub struct Lzma;

static META: ExtractorMeta = ExtractorMeta {
    id: "compress.lzma",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "xz",
            name: "xz",
            family: "compress",
            mimes: &["application/x-xz"],
            extensions: &["xz", "txz"],
            magic: &[Magic::prefix(b"\xfd7zXZ\x00")],
            parent: None,
        },
        FormatSpec {
            id: "lzma",
            name: "LZMA (alone)",
            family: "compress",
            mimes: &["application/x-lzma"],
            extensions: &["lzma", "tlz"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "lzip",
            name: "lzip",
            family: "compress",
            mimes: &["application/x-lzip"],
            extensions: &["lz", "tlz"],
            magic: &[Magic::prefix(b"LZIP\x01")],
            parent: None,
        },
    ],
};

/// The `.lzma` header fields, when they are plausible: properties byte,
/// dictionary size, declared size (`None`: unknown, end marker).
fn lzma_header(head: &[u8]) -> Option<(u8, u32, Option<u64>)> {
    let mut r = ByteReader::new(head);
    let props = r.u8().ok()?;
    let dict = r.le_u32().ok()?;
    let size = r.le_u64().ok()?;
    // lc + lp ≤ 4 as xz writes them, a power-of-two-ish dictionary, and a
    // size that is unknown or below 256 TiB.
    let (lc, lp) = (props % 9, (props / 9) % 5);
    let dict_ok = dict >= 4096 && (dict.is_power_of_two() || (dict >> dict.trailing_zeros()) == 3);
    (props < 225 && lc + lp <= 4 && dict_ok && (size == u64::MAX || size < 1 << 48))
        .then(|| (props, dict, (size != u64::MAX).then_some(size)))
}

impl Extractor for Lzma {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let (props, _, size) = lzma_header(probe.head)?;
        // `lzma` and `xz --format=lzma` always write properties 0x5d; any
        // valid header counts with the extension.
        let confidence = match probe.extension {
            Some("lzma" | "tlz") => 0.85,
            _ if props == 0x5d && size.is_none() => 0.55,
            _ => return None,
        };
        Some(Sniff { format: "lzma", confidence })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "xz" => {
                let stated = xz(src.head(), src.tail(), src.len(), cx);
                unpack(src, cx, Codec::Xz, &stated)
            }
            "lzip" => {
                let stated = lzip(src.head(), src.tail(), src.len(), cx)?;
                unpack(src, cx, Codec::Lzip, &stated)
            }
            _ => {
                let (props, dict, size) =
                    lzma_header(src.head()).ok_or_else(|| ExtractError::Unsupported("lzma".into()))?;
                cx.format_set("lc", props % 9);
                cx.format_set("lp", (props / 9) % 5);
                cx.format_set("pb", props / 45);
                cx.format_set("dictionary_bytes", dict);
                unpack(src, cx, Codec::LzmaAlone, &Stated { size, name: None })
            }
        }
    }
}

crate::register_extractor!(Lzma);

fn check_name(check: u8) -> String {
    match check {
        0 => "none".into(),
        1 => "CRC32".into(),
        4 => "CRC64".into(),
        10 => "SHA-256".into(),
        n => format!("reserved ({n})"),
    }
}

fn xz(head: &[u8], tail: &[u8], len: u64, cx: &mut Context<'_>) -> Stated {
    if let Some(&check) = head.get(7) {
        cx.format_set("check", check_name(check & 15));
    }
    if let Some((filters, dict)) = codec::xz_first_filters(head) {
        cx.format_set("filters", filters);
        if let Some(d) = dict {
            cx.format_set("dictionary_bytes", d);
        }
    }
    let mut stated = Stated::default();
    // The index at the end lists every block; the tail window holds it
    // unless the file has very many blocks.
    if let Some(idx) = codec::xz_index(tail, len - tail.len() as u64)
        && idx.whole_file
    {
        cx.format_set("streams", idx.streams);
        cx.format_set("blocks", idx.blocks);
        stated.size = Some(idx.uncompressed);
    }
    stated
}

fn lzip(head: &[u8], tail: &[u8], len: u64, cx: &mut Context<'_>) -> Result<Stated, ExtractError> {
    let mut r = ByteReader::new(head).skip(4)?;
    cx.format_set("version", r.u8()?);
    cx.format_set("dictionary_bytes", codec::lzip_dict_size(r.u8()?));
    // The last member's trailer: CRC32, data size, member size.
    let mut stated = Stated::default();
    if tail.len() >= 20 {
        let mut t = ByteReader::new(&tail[tail.len() - 20..]).skip(4)?;
        let data = t.le_u64()?;
        let member = t.le_u64()?;
        // A single-member file: the member is the whole file.
        if member == len {
            stated.size = Some(data);
        }
    }
    Ok(stated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lzma_headers() {
        assert_eq!(lzma_header(b"\x5d\x00\x00\x80\x00\xff\xff\xff\xff\xff\xff\xff\xff"), Some((0x5d, 1 << 23, None)));
        assert_eq!(
            lzma_header(b"\x5d\x00\x00\x30\x00\x10\x00\x00\x00\x00\x00\x00\x00"),
            Some((0x5d, 3 << 20, Some(16)))
        );
        assert_eq!(lzma_header(b"\xe1\x00\x00\x80\x00\xff\xff\xff\xff\xff\xff\xff\xff"), None);
        assert_eq!(lzma_header(b"\x5d\x01\x02\x03\x04\xff\xff\xff\xff\xff\xff\xff\xff"), None);
        assert_eq!(lzma_header(b"\x5d"), None);
    }

    crate::fixture_tests!("xz", "lzma", "lzip");
}
