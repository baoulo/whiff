//! bzip2 decoding: Huffman-coded MTF / RLE2 symbols, the inverse
//! Burrows–Wheeler transform and the final run-length step, block by block,
//! for every stream of a file (`pbzip2` writes several). Block and stream
//! CRCs are checked.
//!
//! Specification: the bzip2 1.0.8 sources (`decompress.c`), as described in
//! Joe Tsai's "bzip2 format specification".

use super::{Sink, Step, Stop, bad};

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const END_MAGIC: u64 = 0x1772_4538_5090;
const MAX_GROUPS: usize = 6;
const MAX_ALPHA: usize = 258;
const MAX_CODE_LEN: u32 = 20;
const GROUP_SIZE: usize = 50;
const MAX_SELECTORS: usize = 18_002;

/// MSB-first bit reader.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u64,
    n: u32,
}

impl Bits<'_> {
    #[allow(clippy::cast_possible_truncation)] // at most 24 bits
    fn bits(&mut self, count: u32) -> Step<u32> {
        while self.n < count {
            let Some(&b) = self.data.get(self.pos) else { return Err(Stop::Truncated) };
            self.pos += 1;
            self.acc = (self.acc << 8) | u64::from(b);
            self.n += 8;
        }
        self.n -= count;
        Ok(((self.acc >> self.n) & ((1u64 << count) - 1)) as u32)
    }

    fn bit(&mut self) -> Step<bool> {
        Ok(self.bits(1)? == 1)
    }

    fn u48(&mut self) -> Step<u64> {
        Ok((u64::from(self.bits(24)?) << 24) | u64::from(self.bits(24)?))
    }

    /// Drop the bits left in the current byte.
    fn align(&mut self) {
        self.n -= self.n % 8;
    }

    /// Bytes consumed, counting a partly read byte.
    fn consumed(&self) -> usize {
        self.pos - (self.n / 8) as usize
    }
}

/// Canonical Huffman decoding table (bzip2's limit / base / perm).
struct Table {
    min_len: u32,
    limit: [i32; MAX_CODE_LEN as usize + 2],
    base: [i32; MAX_CODE_LEN as usize + 2],
    perm: [u16; MAX_ALPHA],
}

impl Table {
    #[allow(clippy::cast_possible_truncation)] // fewer than 258 symbols
    fn new(lengths: &[u8]) -> Self {
        let min_len = u32::from(*lengths.iter().min().unwrap_or(&1));
        let max_len = u32::from(*lengths.iter().max().unwrap_or(&1));
        let mut t = Table { min_len, limit: [0; 22], base: [0; 22], perm: [0; MAX_ALPHA] };
        let mut pp = 0;
        for len in min_len..=max_len {
            for (sym, &l) in lengths.iter().enumerate() {
                if u32::from(l) == len {
                    t.perm[pp] = sym as u16;
                    pp += 1;
                }
            }
        }
        let mut count = [0i32; 22];
        for &l in lengths {
            count[usize::from(l)] += 1;
        }
        let (mut code, mut index) = (0i32, 0i32);
        for len in min_len..=max_len {
            let len = len as usize;
            // Codes of this length are `code .. code + count`; their symbols
            // start at `index` in `perm`.
            t.base[len] = index - code;
            code += count[len];
            index += count[len];
            t.limit[len] = code - 1;
            code <<= 1;
        }
        for len in (max_len as usize + 1)..t.limit.len() {
            t.limit[len] = i32::MAX;
        }
        t
    }

    #[allow(clippy::cast_possible_wrap)] // codes of at most 20 bits
    fn decode(&self, bits: &mut Bits<'_>) -> Step<u16> {
        let mut len = self.min_len;
        let mut code = bits.bits(len)? as i32;
        loop {
            if len > MAX_CODE_LEN {
                return bad("bzip2 Huffman code");
            }
            if code <= self.limit[len as usize] {
                let i = code + self.base[len as usize];
                return usize::try_from(i)
                    .ok()
                    .and_then(|i| self.perm.get(i).copied())
                    .ok_or_else(|| Stop::Bad("bzip2 Huffman code".into()));
            }
            code = (code << 1) | bits.bits(1)? as i32;
            len += 1;
        }
    }
}

/// bzip2's CRC-32 (MSB first, polynomial 0x04C11DB7).
fn crc_table() -> &'static [u32; 256] {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in (0u32..).zip(t.iter_mut()) {
            let mut c = i << 24;
            for _ in 0..8 {
                c = if c & 0x8000_0000 != 0 { (c << 1) ^ 0x04C1_1DB7 } else { c << 1 };
            }
            *slot = c;
        }
        t
    })
}

/// Decode every bzip2 stream at the start of `input`; returns the bytes used.
pub(super) fn decode(input: &[u8], sink: &mut Sink<'_>) -> Step<usize> {
    let mut bits = Bits { data: input, pos: 0, acc: 0, n: 0 };
    let mut streams = 0;
    loop {
        let start = bits.consumed();
        if input.len() < start + 4 || &input[start..start + 3] != b"BZh" {
            if streams == 0 {
                return if input.len() < 4 { Err(Stop::Truncated) } else { bad("bzip2 header") };
            }
            return Ok(start);
        }
        let level = input[start + 3];
        if !(b'1'..=b'9').contains(&level) {
            return if streams == 0 { bad("bzip2 block size") } else { Ok(start) };
        }
        bits.pos = start + 4;
        bits.n = 0;
        let max_block = usize::from(level - b'0') * 100_000;
        let mut combined = 0u32;
        loop {
            match bits.u48()? {
                BLOCK_MAGIC => {
                    let crc = bits.bits(32)?;
                    let got = block(&mut bits, max_block, sink)?;
                    if got != crc {
                        return bad("bzip2 block CRC");
                    }
                    combined = combined.rotate_left(1) ^ crc;
                }
                END_MAGIC => {
                    if bits.bits(32)? != combined {
                        return bad("bzip2 stream CRC");
                    }
                    bits.align();
                    break;
                }
                _ => return bad("bzip2 block magic"),
            }
        }
        streams += 1;
    }
}

/// One block: decoded into the sink; returns its CRC.
#[allow(clippy::too_many_lines)] // one pass over the block layout
#[allow(clippy::cast_possible_truncation)] // symbols < 258, lengths ≤ 20, blocks ≤ 900 000 bytes
fn block(bits: &mut Bits<'_>, max_block: usize, sink: &mut Sink<'_>) -> Step<u32> {
    if bits.bit()? {
        return bad("bzip2 randomised block (bzip2 0.9.0)");
    }
    let orig_ptr = bits.bits(24)? as usize;

    // Symbols in use.
    let used_groups = bits.bits(16)?;
    let mut seq_to_unseq = Vec::with_capacity(256);
    for i in 0..16u8 {
        if used_groups & (0x8000 >> i) != 0 {
            let used = bits.bits(16)?;
            for j in 0..16u8 {
                if used & (0x8000 >> j) != 0 {
                    seq_to_unseq.push(i * 16 + j);
                }
            }
        }
    }
    if seq_to_unseq.is_empty() {
        return bad("bzip2 symbol map");
    }
    let alpha = seq_to_unseq.len() + 2;

    let groups = bits.bits(3)? as usize;
    if !(2..=MAX_GROUPS).contains(&groups) {
        return bad("bzip2 Huffman groups");
    }
    let selectors = bits.bits(15)? as usize;
    if selectors == 0 {
        return bad("bzip2 selectors");
    }
    let mut mtf_groups: Vec<u8> = (0..groups as u8).collect();
    let mut selector = Vec::with_capacity(selectors.min(MAX_SELECTORS));
    for _ in 0..selectors {
        let mut j = 0;
        while bits.bit()? {
            j += 1;
            if j >= groups {
                return bad("bzip2 selector");
            }
        }
        // bzip2 1.0.8 reads but ignores selectors past the maximum.
        if selector.len() < MAX_SELECTORS {
            let g = mtf_groups.remove(j);
            mtf_groups.insert(0, g);
            selector.push(g);
        }
    }

    let mut tables = Vec::with_capacity(groups);
    for _ in 0..groups {
        let mut len = bits.bits(5)?;
        let mut lengths = vec![0u8; alpha];
        for l in &mut lengths {
            loop {
                if !(1..=MAX_CODE_LEN).contains(&len) {
                    return bad("bzip2 code length");
                }
                if !bits.bit()? {
                    break;
                }
                if bits.bit()? {
                    len -= 1;
                } else {
                    len += 1;
                }
            }
            *l = len as u8;
        }
        tables.push(Table::new(&lengths));
    }

    // MTF / RLE2 symbols into `tt` (low byte), with byte counts.
    let eob = (alpha - 1) as u16;
    let mut mtf: Vec<u8> = (0..=255u8).collect();
    let mut tt: Vec<u32> = Vec::with_capacity(max_block.min(1 << 20));
    let mut counts = [0usize; 256];
    let (mut group_left, mut group_index) = (0usize, 0usize);
    let mut table = &tables[0];
    let mut next = |bits: &mut Bits<'_>| -> Step<u16> {
        if group_left == 0 {
            let Some(&g) = selector.get(group_index) else { return bad("bzip2 selector overrun") };
            table = &tables[usize::from(g)];
            group_index += 1;
            group_left = GROUP_SIZE;
        }
        group_left -= 1;
        table.decode(bits)
    };
    let mut sym = next(bits)?;
    loop {
        if sym == eob {
            break;
        }
        if sym <= 1 {
            // RUNA / RUNB: a run of the front symbol, length in bijective base 2.
            let (mut run, mut weight) = (0usize, 1usize);
            while sym <= 1 {
                run += weight << sym;
                weight <<= 1;
                if weight > max_block * 2 {
                    return bad("bzip2 run length");
                }
                sym = next(bits)?;
            }
            let b = seq_to_unseq[usize::from(mtf[0])];
            if tt.len() + run > max_block {
                return bad("bzip2 block overflow");
            }
            counts[usize::from(b)] += run;
            tt.extend(std::iter::repeat_n(u32::from(b), run));
            continue;
        }
        let index = usize::from(sym - 1);
        let Some(&m) = mtf.get(index) else { return bad("bzip2 MTF index") };
        mtf.copy_within(0..index, 1);
        mtf[0] = m;
        let Some(&b) = seq_to_unseq.get(usize::from(m)) else { return bad("bzip2 symbol") };
        if tt.len() >= max_block {
            return bad("bzip2 block overflow");
        }
        counts[usize::from(b)] += 1;
        tt.push(u32::from(b));
        sym = next(bits)?;
    }
    if orig_ptr >= tt.len() {
        return if tt.is_empty() { Ok(0) } else { bad("bzip2 origin pointer") };
    }

    // Inverse BWT: link each position to the next in the original order.
    let mut start = [0usize; 256];
    let mut sum = 0;
    for (s, c) in start.iter_mut().zip(counts) {
        *s = sum;
        sum += c;
    }
    for i in 0..tt.len() {
        let b = (tt[i] & 0xff) as usize;
        tt[start[b]] |= (i as u32) << 8;
        start[b] += 1;
    }

    // Undo the initial run-length step (4 equal bytes, then a count) while
    // writing, and compute the block CRC over the output.
    let table = crc_table();
    let mut crc = 0xFFFF_FFFFu32;
    let emit = |b: u8, sink: &mut Sink<'_>, crc: &mut u32| -> Step<()> {
        *crc = (*crc << 8) ^ table[((*crc >> 24) as u8 ^ b) as usize];
        sink.push(b)
    };
    let mut pos = tt[orig_ptr] >> 8;
    let (mut last, mut run) = (None::<u8>, 0u8);
    for _ in 0..tt.len() {
        let entry = tt[pos as usize];
        let b = (entry & 0xff) as u8;
        pos = entry >> 8;
        if run == 4 {
            for _ in 0..b {
                emit(last.unwrap_or(0), sink, &mut crc)?;
            }
            run = 0;
            last = None;
            continue;
        }
        if Some(b) == last {
            run += 1;
        } else {
            last = Some(b);
            run = 1;
        }
        emit(b, sink, &mut crc)?;
    }
    Ok(!crc)
}

#[cfg(test)]
mod tests {
    use super::super::{Codec, End, decode as run};
    use crate::io::Budget;

    /// `printf 'Harbour bells, harbour bells, aaaaaaaaaaaaaaaa!' | bzip2 -9`
    const SAMPLE: &[u8] = &[
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x46, 0x6a, 0x89, 0xe4, 0x00, 0x00, 0x04, 0x55,
        0x80, 0x00, 0x04, 0x60, 0x04, 0x00, 0x40, 0x32, 0x44, 0x9a, 0x00, 0x20, 0x00, 0x31, 0x00, 0x00, 0x04, 0xa8,
        0xc9, 0x93, 0x4c, 0x23, 0x72, 0x8d, 0xad, 0x8e, 0xda, 0x79, 0x84, 0x20, 0xf0, 0x92, 0x50, 0xa6, 0x10, 0x29,
        0x87, 0xc5, 0xdc, 0x91, 0x4e, 0x14, 0x24, 0x11, 0x9a, 0xa2, 0x79, 0x00,
    ];

    #[test]
    fn decodes_a_stream_and_rejects_damage() {
        let budget = Budget::unlimited();
        let d = run(SAMPLE, Codec::Bzip2, usize::MAX, &budget).unwrap();
        assert_eq!(d.end, End::Complete, "{d:?}");
        assert_eq!(d.data, b"Harbour bells, harbour bells, aaaaaaaaaaaaaaaa!");
        assert_eq!(d.consumed, SAMPLE.len());
        // Two streams back to back.
        let two = [SAMPLE, SAMPLE].concat();
        assert_eq!(run(&two, Codec::Bzip2, usize::MAX, &budget).unwrap().data.len(), 94);
        // A flipped bit fails a CRC (or the structure); a cut is truncation.
        let mut bad = SAMPLE.to_vec();
        bad[30] ^= 0x10;
        assert!(matches!(run(&bad, Codec::Bzip2, usize::MAX, &budget).unwrap().end, End::Error(_)));
        assert_eq!(run(&SAMPLE[..30], Codec::Bzip2, usize::MAX, &budget).unwrap().end, End::Truncated);
        let d = run(SAMPLE, Codec::Bzip2, 10, &budget).unwrap();
        assert_eq!((d.data.as_slice(), d.end), (&b"Harbour be"[..], End::Limit));
    }
}
