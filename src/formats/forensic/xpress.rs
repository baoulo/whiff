//! LZXPRESS Huffman decompression (Windows 8+ Prefetch files, `MAM\x04`).
//!
//! Specification: Microsoft "MS-XCA" 2.2.4, "LZ77+Huffman Decompression".

/// Output produced per Huffman table.
const BLOCK: usize = 65536;
/// Longest code.
const MAX_BITS: u32 = 15;

/// Decode `input` into at most `size` bytes. `None` when the stream is
/// invalid; a stream that ends early gives what was decoded.
pub(crate) fn decompress(input: &[u8], size: usize) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(size);
    let mut pos = 0usize;
    let word = |p: usize| -> u32 { input.get(p..p + 2).map_or(0, |w| u32::from(u16::from_le_bytes([w[0], w[1]]))) };
    while out.len() < size && pos + 256 <= input.len() {
        let table = decoding_table(&input[pos..pos + 256])?;
        pos += 256;
        let mut bits: u32 = (word(pos) << 16) | word(pos + 2);
        pos += 4;
        let mut extra: i32 = 16;
        let end = (out.len() + BLOCK).min(size);
        let refill = |bits: &mut u32, extra: &mut i32, pos: &mut usize| {
            if *extra < 0 {
                *bits |= word(*pos) << (-*extra);
                *extra += 16;
                *pos += 2;
            }
        };
        while out.len() < end {
            let (sym, len) = table[(bits >> (32 - MAX_BITS)) as usize];
            if len == 0 {
                return None;
            }
            bits <<= len;
            extra -= i32::from(len);
            refill(&mut bits, &mut extra, &mut pos);
            if sym < 256 {
                out.push(u8::try_from(sym).unwrap_or(0));
                continue;
            }
            if sym == 256 && pos >= input.len() {
                return Some(out);
            }
            let s = sym - 256;
            let mut length = usize::from(s & 15);
            let offset_bits = u32::from(s >> 4);
            if length == 15 {
                length = usize::from(*input.get(pos)?);
                pos += 1;
                if length == 255 {
                    length = usize::from(u16::from_le_bytes(input.get(pos..pos + 2)?.try_into().ok()?));
                    pos += 2;
                    length = length.checked_sub(15)?;
                }
                length += 15;
            }
            length += 3;
            let offset =
                if offset_bits == 0 { 0 } else { (bits >> (32 - offset_bits)) as usize } + (1usize << offset_bits);
            if offset_bits > 0 {
                bits <<= offset_bits;
            }
            extra -= offset_bits.cast_signed();
            refill(&mut bits, &mut extra, &mut pos);
            let start = out.len().checked_sub(offset)?;
            for i in 0..length.min(size - out.len()) {
                let b = out[start + i];
                out.push(b);
            }
        }
    }
    Some(out)
}

/// The 2^15-entry table: symbol and code length for every 15-bit prefix.
fn decoding_table(lengths: &[u8]) -> Option<Vec<(u16, u8)>> {
    let len = |i: usize| (lengths[i / 2] >> (4 * (i % 2))) & 0x0f;
    let mut table = vec![(0u16, 0u8); 1 << MAX_BITS];
    let mut code = 0usize;
    for bit_len in 1..=15u8 {
        for sym in 0..512usize {
            if len(sym) == bit_len {
                let span = 1usize << (MAX_BITS - u32::from(bit_len));
                let at = code.checked_mul(span)?;
                table.get_mut(at..at + span)?.fill((u16::try_from(sym).ok()?, bit_len));
                code += 1;
            }
        }
        code <<= 1;
    }
    Some(table)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bits written as the format reads them: 16-bit little-endian words,
    /// most significant bit first.
    struct Bits {
        words: Vec<u16>,
        cur: u32,
        n: u32,
    }

    impl Bits {
        fn put(&mut self, v: u32, len: u32) {
            for i in (0..len).rev() {
                self.cur = (self.cur << 1) | ((v >> i) & 1);
                self.n += 1;
                if self.n == 16 {
                    self.words.push(u16::try_from(self.cur).unwrap());
                    self.cur = 0;
                    self.n = 0;
                }
            }
        }
    }

    #[test]
    fn literals_and_a_match() {
        // Every symbol 9 bits long: the canonical code of a symbol is its value.
        let mut out = vec![0x99u8; 256];
        let mut b = Bits { words: Vec::new(), cur: 0, n: 0 };
        for &c in b"tide " {
            b.put(u32::from(c), 9);
        }
        // Match: length 7 (nibble 4 + 3), offset 5 (2 offset bits: 1 + 0b01).
        b.put(256 + (2 << 4) + 4, 9);
        b.put(0b01, 2);
        b.put(256, 9);
        b.put(0, 16);
        b.put(0, 16);
        if b.n > 0 {
            let pad = 16 - b.n;
            b.put(0, pad);
        }
        for w in &b.words {
            out.extend(w.to_le_bytes());
        }
        assert_eq!(decompress(&out, 12).unwrap(), b"tide tide ti");
    }
}
