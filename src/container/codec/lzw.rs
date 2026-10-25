//! Unix `compress` (`.Z`) decoding: LZW with 9- to 16-bit codes, block
//! mode (code 256 clears the table), and `compress`'s habit of padding the
//! input to a whole group of eight codes whenever the code width changes.
//!
//! Specification: the `ncompress` 4.2 sources, as gzip's `unlzw.c` reads them.

use super::{Sink, Step, Stop, bad};

const CLEAR: usize = 256;
const INIT_BITS: u32 = 9;

/// Decode a `.Z` stream; returns the bytes used (all of them).
#[allow(clippy::cast_possible_truncation)] // codes are below 2^16
pub(super) fn decode(input: &[u8], sink: &mut Sink<'_>) -> Step<usize> {
    if input.len() < 3 {
        return Err(Stop::Truncated);
    }
    if input[0] != 0x1f || input[1] != 0x9d {
        return bad("compress magic");
    }
    let max_bits = u32::from(input[2] & 0x1f);
    let block_mode = input[2] & 0x80 != 0;
    if !(INIT_BITS..=16).contains(&max_bits) {
        return bad("compress code width");
    }
    let max_max_code = 1usize << max_bits;
    let total_bits = input.len() * 8;
    let mut prefix = vec![0u16; max_max_code];
    let mut suffix: Vec<u8> = (0..max_max_code).map(|i| i as u8).collect();
    let mut stack: Vec<u8> = Vec::with_capacity(1 << 16);
    let mut n_bits = INIT_BITS;
    let mut max_code = (1usize << n_bits) - 1;
    let mut free = if block_mode { CLEAR + 1 } else { CLEAR };
    // Bit position in the file. `compress` writes codes in groups of eight
    // and pads the group out when the width changes or the table is
    // cleared; groups count from the last such point (`base`).
    let mut pos = 24usize;
    let mut base = pos;
    let mut old: Option<usize> = None;
    let mut fin = 0u8;
    // Skip to the end of the current group of eight `n_bits` codes.
    let regroup = |pos: usize, base: usize, n_bits: u32| {
        let group = (n_bits as usize) << 3;
        base + (pos - base).div_ceil(group) * group
    };
    loop {
        if free > max_code && n_bits < max_bits {
            pos = regroup(pos, base, n_bits);
            base = pos;
            n_bits += 1;
            max_code = if n_bits == max_bits { max_max_code } else { (1usize << n_bits) - 1 };
        }
        if pos + n_bits as usize > total_bits {
            return Ok(input.len());
        }
        let byte = pos >> 3;
        let mut word = 0u32;
        for (k, b) in input[byte..input.len().min(byte + 3)].iter().enumerate() {
            word |= u32::from(*b) << (8 * k);
        }
        let code = ((word >> (pos & 7)) & ((1u32 << n_bits) - 1)) as usize;
        pos += n_bits as usize;
        let Some(prev) = old else {
            if code > 255 {
                return bad("compress first code");
            }
            fin = code as u8;
            old = Some(code);
            sink.push(fin)?;
            continue;
        };
        if code == CLEAR && block_mode {
            prefix.fill(0);
            free = CLEAR;
            pos = regroup(pos, base, n_bits);
            base = pos;
            n_bits = INIT_BITS;
            max_code = (1usize << n_bits) - 1;
            continue;
        }
        let mut c = code;
        stack.clear();
        if c >= free {
            if c > free {
                return bad("compress code");
            }
            stack.push(fin);
            c = prev;
        }
        while c > 255 {
            stack.push(suffix[c]);
            c = usize::from(prefix[c]);
            if stack.len() > max_max_code {
                return bad("compress code chain");
            }
        }
        fin = suffix[c];
        stack.push(fin);
        for &b in stack.iter().rev() {
            sink.push(b)?;
        }
        if free < max_max_code {
            prefix[free] = prev as u16;
            suffix[free] = fin;
            free += 1;
        }
        old = Some(code);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Codec, End, decode as run};
    use crate::io::Budget;

    /// `compress -c -f` of `TOBEORNOTTOBEORTOBEORNOT` (macOS `compress`).
    const SAMPLE: &[u8] = &[
        0x1f, 0x9d, 0x90, 0x54, 0x9e, 0x08, 0x29, 0xf2, 0x44, 0x8a, 0x93, 0x27, 0x54, 0x02, 0x0e, 0x2c, 0xa8, 0x90,
        0xa0, 0x41, 0x84,
    ];

    #[test]
    fn decodes_compress_output() {
        let budget = Budget::unlimited();
        let d = run(SAMPLE, Codec::Lzw, usize::MAX, &budget).unwrap();
        assert_eq!((d.data.as_slice(), d.end), (&b"TOBEORNOTTOBEORTOBEORNOT"[..], End::Complete));
        assert!(matches!(run(b"\x1f\x9d\x08abc", Codec::Lzw, 99, &budget).unwrap().end, End::Error(_)));
    }
}
