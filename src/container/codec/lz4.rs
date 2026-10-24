//! LZ4 decoding: the frame format (every frame; skippable frames skipped)
//! and the legacy format `lz4 -l` writes. Checksums are not verified.
//!
//! Specification: LZ4 Frame Format Description 1.6.4 and LZ4 Block Format
//! Description 1.6.4.

use super::{Sink, Step, Stop, bad};

/// Frame magic.
pub const FRAME_MAGIC: u32 = 0x184D_2204;
/// Legacy-format magic.
pub const LEGACY_MAGIC: u32 = 0x184C_2102;
const LEGACY_BLOCK: usize = 8 << 20;

fn u32_at(data: &[u8], at: usize) -> Step<u32> {
    let b = data.get(at..at + 4).ok_or(Stop::Truncated)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Decode one LZ4 block into the sink. `floor` is where references may
/// reach back to (the frame start for linked blocks, the block start for
/// independent ones); `max_out` is the block's largest output.
pub(crate) fn block(data: &[u8], floor: usize, max_out: usize, sink: &mut Sink<'_>) -> Step<()> {
    let start = sink.out.len();
    let mut i = 0;
    let length = |i: &mut usize, mut n: usize| -> Step<usize> {
        if n == 15 {
            loop {
                let &b = data.get(*i).ok_or_else(|| Stop::Bad("lz4 length".into()))?;
                *i += 1;
                n += usize::from(b);
                if b != 255 {
                    break;
                }
            }
        }
        Ok(n)
    };
    loop {
        let &token = data.get(i).ok_or_else(|| Stop::Bad("lz4 token".into()))?;
        i += 1;
        let lit = length(&mut i, usize::from(token >> 4))?;
        let literals = data.get(i..i + lit).ok_or_else(|| Stop::Bad("lz4 literals".into()))?;
        sink.extend(literals)?;
        i += lit;
        if i == data.len() {
            return Ok(());
        }
        let off = data.get(i..i + 2).ok_or_else(|| Stop::Bad("lz4 offset".into()))?;
        let dist = usize::from(u16::from_le_bytes([off[0], off[1]]));
        i += 2;
        let len = length(&mut i, usize::from(token & 15))? + 4;
        if sink.out.len() - start + len > max_out {
            return bad("lz4 block too large");
        }
        sink.copy_back(floor, dist, len)?;
    }
}

/// Decode every LZ4 frame at the start of `input`; returns the bytes used.
pub(super) fn decode(input: &[u8], sink: &mut Sink<'_>) -> Step<usize> {
    let mut at = 0;
    let mut frames = 0;
    loop {
        let Ok(magic) = u32_at(input, at) else {
            return if frames == 0 { Err(Stop::Truncated) } else { Ok(at) };
        };
        if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
            at += 8 + u32_at(input, at + 4)? as usize;
            if at > input.len() {
                return Err(Stop::Truncated);
            }
        } else if magic == FRAME_MAGIC {
            at = frame(input, at + 4, sink)?;
        } else if magic == LEGACY_MAGIC {
            at += 4;
            // Blocks until the end of the input or the next magic.
            while let Ok(size) = u32_at(input, at) {
                if size == FRAME_MAGIC || size == LEGACY_MAGIC || size & 0xFFFF_FFF0 == 0x184D_2A50 {
                    break;
                }
                let data = input.get(at + 4..at + 4 + size as usize).ok_or(Stop::Truncated)?;
                let floor = sink.out.len();
                block(data, floor, LEGACY_BLOCK, sink)?;
                at += 4 + size as usize;
            }
        } else {
            return if frames == 0 { bad("lz4 magic") } else { Ok(at) };
        }
        frames += 1;
    }
}

/// One frame after its magic; returns the offset after it.
fn frame(input: &[u8], mut at: usize, sink: &mut Sink<'_>) -> Step<usize> {
    let (&flg, &bd) = (input.get(at).ok_or(Stop::Truncated)?, input.get(at + 1).ok_or(Stop::Truncated)?);
    if flg >> 6 != 1 {
        return bad("lz4 frame version");
    }
    let independent = flg & 0x20 != 0;
    let block_checksum = flg & 0x10 != 0;
    let content_size = flg & 0x08 != 0;
    let content_checksum = flg & 0x04 != 0;
    let dict_id = flg & 0x01 != 0;
    let max_block = match (bd >> 4) & 7 {
        4 => 64 << 10,
        5 => 256 << 10,
        6 => 1 << 20,
        7 => 4 << 20,
        _ => return bad("lz4 block size"),
    };
    at += 2 + if content_size { 8 } else { 0 } + if dict_id { 4 } else { 0 } + 1;
    let frame_start = sink.out.len();
    loop {
        let size = u32_at(input, at)?;
        at += 4;
        if size == 0 {
            break;
        }
        let stored = size & 0x8000_0000 != 0;
        let len = (size & 0x7FFF_FFFF) as usize;
        if len > max_block {
            return bad("lz4 block size");
        }
        let data = input.get(at..at + len).ok_or(Stop::Truncated)?;
        if stored {
            sink.extend(data)?;
        } else {
            let floor = if independent { sink.out.len() } else { frame_start };
            block(data, floor, max_block, sink)?;
        }
        at += len + if block_checksum { 4 } else { 0 };
    }
    at += if content_checksum { 4 } else { 0 };
    if at > input.len() {
        return Err(Stop::Truncated);
    }
    Ok(at)
}

#[cfg(test)]
mod tests {
    use super::super::{Codec, End, decode as run};
    use crate::io::Budget;

    #[test]
    fn frames_blocks_and_matches() {
        // One frame: a block with literals "abc", a match of 9 at distance 3,
        // then the final literals "!" (blocks end with literals).
        let block = [0x35, b'a', b'b', b'c', 3, 0, 0x10, b'!'];
        let mut frame = vec![0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x82];
        frame.extend_from_slice(&u32::try_from(block.len()).unwrap().to_le_bytes());
        frame.extend_from_slice(&block);
        frame.extend_from_slice(&0u32.to_le_bytes());
        // A skippable frame, then a stored block.
        let mut input = frame.clone();
        input.extend_from_slice(&[0x50, 0x2a, 0x4d, 0x18, 2, 0, 0, 0, 9, 9]);
        input.extend_from_slice(&[0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x82]);
        input.extend_from_slice(&(0x8000_0002u32).to_le_bytes());
        input.extend_from_slice(b"ok");
        input.extend_from_slice(&0u32.to_le_bytes());
        let budget = Budget::unlimited();
        let d = run(&input, Codec::Lz4, usize::MAX, &budget).unwrap();
        assert_eq!((d.data.as_slice(), d.end, d.consumed), (&b"abcabcabcabc!ok"[..], End::Complete, input.len()));
        assert_eq!(run(&frame[..12], Codec::Lz4, usize::MAX, &budget).unwrap().end, End::Truncated);
        let mut far = frame.clone();
        far[15] = 9; // distance 9, before the start of the output
        assert!(matches!(run(&far, Codec::Lz4, usize::MAX, &budget).unwrap().end, End::Error(_)));
    }
}
