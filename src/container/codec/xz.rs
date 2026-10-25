//! The xz container: streams, blocks (LZMA2 with optional delta / BCJ
//! filters, decoded by `lzma-rust2`), the index and stream padding. Header
//! CRCs are checked; the check fields after each block are skipped.
//!
//! Specification: The .xz File Format 1.2.1.

use lzma_rust2::filter::{FilterConfig, FilterType, StreamFilter};

use super::{Sink, Step, Stop, bad, crc32};

/// Stream header magic.
pub const MAGIC: &[u8; 6] = b"\xfd7zXZ\0";

/// Size of the check field for each check id.
fn check_size(check: u8) -> usize {
    [0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64][usize::from(check & 15)]
}

fn varint(data: &[u8], at: &mut usize) -> Step<u64> {
    let mut v = 0u64;
    for i in 0..9 {
        let &b = data.get(*at).ok_or(Stop::Truncated)?;
        *at += 1;
        v |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    bad("xz integer")
}

/// LZMA2 dictionary size from its property byte.
pub fn lzma2_dict_size(b: u8) -> Option<u32> {
    match b {
        0..=39 => Some((2 | u32::from(b & 1)) << (b / 2 + 11)),
        40 => Some(u32::MAX),
        _ => None,
    }
}

/// A block's filter chain: `(id, properties)`, in encoding order.
fn filters(header: &[u8]) -> Step<Vec<(u64, Vec<u8>)>> {
    let flags = header[1];
    let mut at = 2;
    if flags & 0x40 != 0 {
        varint(header, &mut at)?;
    }
    if flags & 0x80 != 0 {
        varint(header, &mut at)?;
    }
    let mut chain = Vec::new();
    for _ in 0..=(flags & 3) {
        let id = varint(header, &mut at)?;
        let n = usize::try_from(varint(header, &mut at)?).map_err(|_| Stop::Bad("xz filter".into()))?;
        let props = header.get(at..at + n).ok_or(Stop::Truncated)?.to_vec();
        at += n;
        chain.push((id, props));
    }
    Ok(chain)
}

/// The name of an xz filter id.
pub fn filter_name(id: u64) -> &'static str {
    match id {
        0x03 => "delta",
        0x04 => "x86",
        0x05 => "powerpc",
        0x06 => "ia64",
        0x07 => "arm",
        0x08 => "armthumb",
        0x09 => "sparc",
        0x0a => "arm64",
        0x0b => "riscv",
        0x21 => "lzma2",
        _ => "unknown",
    }
}

fn stream_filter(id: u64, props: &[u8]) -> Step<StreamFilter> {
    let filter_type = match id {
        0x03 => FilterType::Delta,
        0x04 => FilterType::BcjX86,
        0x05 => FilterType::BcjPpc,
        0x06 => FilterType::BcjIa64,
        0x07 => FilterType::BcjArm,
        0x08 => FilterType::BcjArmThumb,
        0x09 => FilterType::BcjSparc,
        0x0a => FilterType::BcjArm64,
        0x0b => FilterType::BcjRiscv,
        _ => return bad(format!("xz filter {id:#x}")),
    };
    let property = match (id, props) {
        (0x03, [d]) => u32::from(*d) + 1,
        (0x03, _) => return bad("xz delta properties"),
        (_, [a, b, c, d]) => u32::from_le_bytes([*a, *b, *c, *d]),
        _ => 0,
    };
    StreamFilter::new(&FilterConfig { filter_type, property }).map_err(|e| Stop::Bad(e.to_string()))
}

/// Decode every xz stream at the start of `input`; returns the bytes used.
pub(super) fn decode(input: &[u8], sink: &mut Sink<'_>) -> Step<usize> {
    let mut at = 0;
    let mut streams = 0;
    loop {
        if !input[at..].starts_with(MAGIC) {
            if streams == 0 {
                return if input.len() < 12 { Err(Stop::Truncated) } else { bad("xz magic") };
            }
            return Ok(at);
        }
        let header = input.get(at..at + 12).ok_or(Stop::Truncated)?;
        if crc32(&header[6..8]).to_le_bytes() != header[8..12] || header[6] != 0 || header[7] > 15 {
            return bad("xz stream header");
        }
        let check = check_size(header[7]);
        let stream_start = at;
        at += 12;
        loop {
            let &size = input.get(at).ok_or(Stop::Truncated)?;
            if size == 0 {
                at = skip_index(input, at)?;
                break;
            }
            let header_len = (usize::from(size) + 1) * 4;
            let header = input.get(at..at + header_len).ok_or(Stop::Truncated)?;
            if crc32(&header[..header_len - 4]).to_le_bytes() != header[header_len - 4..] {
                return bad("xz block header");
            }
            let chain = filters(header)?;
            let Some(((0x21, lzma), rest)) = chain.split_last().map(|(l, r)| (l.clone(), r)) else {
                return bad("xz filter chain (LZMA2 last)");
            };
            let dict = lzma.first().and_then(|&b| lzma2_dict_size(b)).ok_or_else(|| Stop::Bad("xz LZMA2".into()))?;
            let out_start = sink.out.len();
            let data = at + header_len;
            let used = super::lzma2(&input[data..], dict, sink);
            // Undo the other filters, last applied first, even on a prefix.
            for (id, props) in rest.iter().rev() {
                let mut f = stream_filter(*id, props)?;
                f.decode(&mut sink.out[out_start..]);
                f.finish();
            }
            at = data + used?;
            at = stream_start + (at - stream_start).div_ceil(4) * 4 + check;
        }
        // Stream padding: zeros, a multiple of four.
        while input.get(at..at + 4) == Some(&[0, 0, 0, 0]) {
            at += 4;
        }
        streams += 1;
        if at >= input.len() {
            return Ok(at.min(input.len()));
        }
    }
}

/// Skip the index at `at` and the stream footer after it.
fn skip_index(input: &[u8], start: usize) -> Step<usize> {
    let mut at = start + 1;
    let records = varint(input, &mut at)?;
    for _ in 0..records {
        varint(input, &mut at)?;
        varint(input, &mut at)?;
    }
    at = start + (at - start).div_ceil(4) * 4 + 4;
    let footer = input.get(at..at + 12).ok_or(Stop::Truncated)?;
    if &footer[10..12] != b"YZ" {
        return bad("xz stream footer");
    }
    Ok(at + 12)
}

/// What the index of an xz stream says, read from the end of the file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XzIndex {
    /// Streams found (walking back from the end of the data given).
    pub streams: u32,
    /// Blocks in those streams.
    pub blocks: u64,
    /// Total uncompressed size of those streams.
    pub uncompressed: u64,
    /// Check type of the last stream (0 none, 1 CRC32, 4 CRC64, 10 SHA-256).
    pub check: u8,
    /// Whether every stream of the file was reached (the first one starts
    /// at the start of `data`).
    pub whole_file: bool,
}

/// Read the xz indexes at the end of `data`, the last bytes of a file that
/// starts `offset` bytes before them (0 when `data` is the whole file).
/// `None` when the end is not an xz stream footer.
pub fn xz_index(data: &[u8], offset: u64) -> Option<XzIndex> {
    let mut idx = XzIndex::default();
    let mut end = data.len();
    loop {
        while end >= 4 && data[end - 4..end] == [0, 0, 0, 0] {
            end -= 4;
        }
        let Some(footer) = end.checked_sub(12).map(|s| &data[s..end]) else {
            return (idx.streams > 0).then_some(idx);
        };
        if &footer[10..12] != b"YZ" || crc32(&footer[4..10]).to_le_bytes() != footer[..4] {
            return (idx.streams > 0).then_some(idx);
        }
        let index_size = (u32::from_le_bytes([footer[4], footer[5], footer[6], footer[7]]) as usize + 1) * 4;
        let index_start = (end - 12).checked_sub(index_size)?;
        let index = &data[index_start..end - 12];
        if index.first() != Some(&0) {
            return None;
        }
        let mut at = 1;
        let records = varint(index, &mut at).ok()?;
        let mut blocks_size = 0u64;
        for _ in 0..records {
            let unpadded = varint(index, &mut at).ok()?;
            idx.uncompressed = idx.uncompressed.saturating_add(varint(index, &mut at).ok()?);
            blocks_size = blocks_size.saturating_add(unpadded.div_ceil(4) * 4);
        }
        if idx.streams == 0 {
            idx.check = footer[9] & 15;
        }
        idx.streams += 1;
        idx.blocks += records;
        // Where the stream starts, in the file.
        let start = (offset + index_start as u64).checked_sub(blocks_size + 12)?;
        if start == 0 {
            idx.whole_file = true;
            return Some(idx);
        }
        // An earlier stream ends before this one: read on if it is in `data`.
        let Some(local) = start.checked_sub(offset).and_then(|s| usize::try_from(s).ok()) else { return Some(idx) };
        if !data[local..].starts_with(MAGIC) {
            return None;
        }
        end = local;
    }
}

/// The filter chain of the first block of the xz stream at the start of
/// `head`, by name, and the LZMA2 dictionary size.
pub fn xz_first_filters(head: &[u8]) -> Option<(Vec<&'static str>, Option<u32>)> {
    let &size = head.get(12)?;
    if !head.starts_with(MAGIC) || size == 0 {
        return None;
    }
    let header = head.get(12..12 + (usize::from(size) + 1) * 4)?;
    let chain = filters(header).ok()?;
    let dict =
        chain.last().filter(|(id, _)| *id == 0x21).and_then(|(_, p)| p.first().and_then(|&b| lzma2_dict_size(b)));
    Some((chain.iter().map(|(id, _)| filter_name(*id)).collect(), dict))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::codec::{Codec, End, decode as run};
    use crate::io::Budget;

    /// `printf 'Harbour wall at dawn, harbour wall at dawn.' | xz -6`
    const SAMPLE: &[u8] = include_bytes!("../../../tests/fixtures/xz/harbour-wall-xz.txt.xz");

    #[test]
    fn decodes_and_reads_the_index() {
        let budget = Budget::unlimited();
        let d = run(SAMPLE, Codec::Xz, usize::MAX, &budget).unwrap();
        assert_eq!(
            (d.data.as_slice(), d.end, d.consumed),
            (&b"Harbour wall at dawn, harbour wall at dawn."[..], End::Complete, SAMPLE.len())
        );
        let idx = xz_index(SAMPLE, 0).unwrap();
        assert_eq!(idx, XzIndex { streams: 1, blocks: 1, uncompressed: 43, check: 4, whole_file: true });
        let two = [SAMPLE, &[0; 8], SAMPLE].concat();
        assert_eq!(xz_index(&two, 0).unwrap().streams, 2);
        // Only the end of the file: the last stream, not known to be all.
        let tail = &two[two.len() - SAMPLE.len()..];
        let idx = xz_index(tail, (two.len() - SAMPLE.len()) as u64).unwrap();
        assert_eq!((idx.streams, idx.whole_file), (1, false));
        let idx = xz_index(&two[20..], 20).unwrap();
        assert_eq!((idx.streams, idx.whole_file), (2, true));
        assert_eq!(run(&two, Codec::Xz, usize::MAX, &budget).unwrap().data.len(), 86);
        assert_eq!(xz_first_filters(SAMPLE), Some((vec!["lzma2"], Some(8 << 20))));
        assert_eq!(run(&SAMPLE[..40], Codec::Xz, usize::MAX, &budget).unwrap().end, End::Truncated);
        assert_eq!(lzma2_dict_size(0), Some(4096));
        assert_eq!(lzma2_dict_size(41), None);
    }
}
