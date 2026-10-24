//! Zstandard (the first frame's descriptor: window size, content size,
//! dictionary id, checksum; frames and skippable frames counted, with the
//! seekable-format footer named). The stream is decompressed and analysed
//! as the inner file.
//!
//! Specification: RFC 8878; the zstd seekable format (`contrib/seekable_format`).

use super::{Stated, unpack};
use crate::plugin::{
    ByteReader, Codec, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source,
};

/// Extractor for Zstandard files.
pub struct Zstd;

static META: ExtractorMeta = ExtractorMeta {
    id: "compress.zstd",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "zstd",
        name: "Zstandard",
        family: "compress",
        mimes: &["application/zstd"],
        extensions: &["zst", "zstd", "tzst"],
        magic: &[Magic::prefix(b"\x28\xb5\x2f\xfd"), Magic::masked(0, b"\x50\x2a\x4d\x18", b"\xf0\xff\xff\xff")],
        parent: None,
    }],
};

/// Seekable-format footer magic (the last four bytes of the file).
const SEEKABLE_MAGIC: u32 = 0x8F92_EAB1;

/// What a frame header states.
#[derive(Debug, PartialEq, Eq)]
struct Frame {
    window: Option<u64>,
    size: Option<u64>,
    dictionary: Option<u32>,
    checksum: bool,
}

fn frame_header(data: &[u8]) -> Result<Frame, ExtractError> {
    let mut r = ByteReader::new(data).skip(4)?;
    let fhd = r.u8()?;
    let fcs_flag = fhd >> 6;
    let single = fhd & 0x20 != 0;
    let checksum = fhd & 0x04 != 0;
    let dict_bytes = [0, 1, 2, 4][usize::from(fhd & 3)];
    let window = if single {
        None
    } else {
        let wd = r.u8()?;
        let exp = u32::from(wd >> 3) + 10;
        let base = 1u64 << exp;
        Some(base + (base / 8) * u64::from(wd & 7))
    };
    let dict = match dict_bytes {
        0 => None,
        n => Some(r.bytes(n)?.iter().rev().fold(0u32, |a, &b| (a << 8) | u32::from(b))).filter(|&d| d != 0),
    };
    let fcs_bytes = match (fcs_flag, single) {
        (0, true) => 1,
        (0, false) => 0,
        (1, _) => 2,
        (2, _) => 4,
        _ => 8,
    };
    let size = match fcs_bytes {
        0 => None,
        n => {
            let v = r.bytes(n)?.iter().rev().fold(0u64, |a, &b| (a << 8) | u64::from(b));
            Some(if n == 2 { v + 256 } else { v })
        }
    };
    // In a single-segment frame the window is the content.
    Ok(Frame { window: window.or(size), size, dictionary: dict, checksum })
}

impl Extractor for Zstd {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head();
        // Skip leading skippable frames (pzstd writes one before each frame).
        let mut at = 0usize;
        let mut skippable = 0u64;
        while let Some(m) = head.get(at..at + 8) {
            if u32::from_le_bytes([m[0], m[1], m[2], m[3]]) & 0xFFFF_FFF0 != 0x184D_2A50 {
                break;
            }
            skippable += 1;
            at += 8 + u32::from_le_bytes([m[4], m[5], m[6], m[7]]) as usize;
        }
        if skippable > 0 {
            cx.format_set("leading_skippable_frames", skippable);
        }
        let mut stated = Stated::default();
        let mut dictionary = false;
        if let Some(frame) = head.get(at..).filter(|f| f.starts_with(b"\x28\xb5\x2f\xfd")) {
            let Frame { window, size, dictionary: dict, checksum } = frame_header(frame)?;
            if let Some(w) = window {
                cx.format_set("window_bytes", w);
            }
            if let Some(d) = dict {
                cx.format_set("dictionary_id", d);
                dictionary = true;
            }
            cx.format_set("checksum", checksum);
            // The first frame's size is the whole content when the file is
            // that one frame (the zstd tool's output). pzstd puts a
            // skippable frame before each of several; the decoded size is
            // used whenever the whole stream decodes.
            if skippable == 0 {
                stated.size = size;
            }
        }
        if src.tail().last_chunk::<4>().is_some_and(|m| u32::from_le_bytes(*m) == SEEKABLE_MAGIC) {
            cx.format_set("variant", "seekable");
        }
        if dictionary {
            // Only the writer has the dictionary.
            cx.warn("the frames need a dictionary that is not in the file");
            return Ok(());
        }
        unpack(src, cx, Codec::Zstd, &stated)
    }
}

crate::register_extractor!(Zstd);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_headers() {
        // Single segment, 1-byte content size 5, checksum.
        let frame = |window, size, dictionary, checksum| Frame { window, size, dictionary, checksum };
        assert_eq!(frame_header(b"\x28\xb5\x2f\xfd\x24\x05").unwrap(), frame(Some(5), Some(5), None, true));
        // Window descriptor 0x58 (2^21), 4-byte content size, 1-byte dictionary id.
        assert_eq!(
            frame_header(b"\x28\xb5\x2f\xfd\x81\x58\x07\x00\x00\x10\x00").unwrap(),
            frame(Some(1 << 21), Some(1 << 20), Some(7), false)
        );
        assert!(frame_header(b"\x28\xb5\x2f\xfd").is_err());
    }

    crate::fixture_tests!("zstd");
}
