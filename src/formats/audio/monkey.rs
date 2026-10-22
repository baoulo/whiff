//! Monkey's Audio (APE): the descriptor and header of version 3.98 and
//! later, and the older single header (compression level, channels, sample
//! rate, bit depth, frames, total blocks), plus APEv2 / ID3v1 tags.
//!
//! Specification: the Monkey's Audio SDK (`APEHeader.h`, `APEInfo.cpp`).

use super::{Stream, Tags, apetag, id3};
use crate::plugin::{ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for Monkey's Audio.
pub struct Monkey;

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.monkey",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "ape",
        name: "Monkey's Audio",
        family: "audio",
        mimes: &["audio/ape", "audio/x-ape"],
        extensions: &["ape"],
        magic: &[Magic::prefix(b"MAC ")],
        parent: None,
    }],
};

struct Header {
    version: u16,
    compression: u16,
    channels: u16,
    rate: u32,
    bits: u16,
    frames: u32,
    final_blocks: u32,
    blocks_per_frame: u32,
}

impl Extractor for Monkey {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut tags = Tags::default();
        let start = match id3::read_v2(src, 0, cx, &mut tags)? {
            Some(i) => i.len,
            None => 0,
        };
        let d = src.read_vec(start, 76.min(usize::try_from(src.len() - start.min(src.len())).unwrap_or(0)))?;
        let h = header(&d).ok_or_else(|| ExtractError::malformed("APE header"))?;
        let mut s = Stream::new("ape");
        s.sample_rate_hz = Some(h.rate);
        s.channels = Some(h.channels);
        s.bits_per_sample = Some(h.bits);
        if h.frames > 0 {
            s.samples = Some(u64::from(h.frames - 1) * u64::from(h.blocks_per_frame) + u64::from(h.final_blocks));
        }
        cx.format_set("version", format!("{}.{:02}", h.version / 1000, (h.version % 1000) / 10));
        cx.format_set(
            "compression",
            match h.compression {
                1000 => "fast",
                2000 => "normal",
                3000 => "high",
                4000 => "extra_high",
                5000 => "insane",
                _ => "unknown",
            },
        );
        cx.format_set("frames", h.frames);
        cx.format_set("blocks_per_frame", h.blocks_per_frame);
        let tail = src.tail().to_vec();
        let v1 = id3::read_v1(&tail, cx, &mut tags);
        let ape = apetag::read(src, v1, cx, &mut tags)?;
        if let Some(dur) = s.duration_s().filter(|d| *d > 0.0) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
            let br = ((src.len() - v1 - ape - start) as f64 * 8.0 / dur).round() as u64;
            s.bitrate_bps = Some(br);
        }
        s.report(cx, None, src.len());
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Monkey);

fn header(d: &[u8]) -> Option<Header> {
    let mut r = ByteReader::new(d);
    r.tag(b"MAC ").ok()?;
    let version = r.le_u16().ok()?;
    if version >= 3980 {
        // Descriptor: padding, its own size, header size…, then the header.
        let _pad = r.le_u16().ok()?;
        let descriptor = r.le_u32().ok()?;
        r.seek(usize::try_from(descriptor).ok()?).ok()?;
        let compression = r.le_u16().ok()?;
        let _flags = r.le_u16().ok()?;
        let blocks_per_frame = r.le_u32().ok()?;
        let final_blocks = r.le_u32().ok()?;
        let frames = r.le_u32().ok()?;
        let bits = r.le_u16().ok()?;
        let channels = r.le_u16().ok()?;
        let rate = r.le_u32().ok()?;
        return Some(Header { version, compression, channels, rate, bits, frames, final_blocks, blocks_per_frame });
    }
    let compression = r.le_u16().ok()?;
    let flags = r.le_u16().ok()?;
    let channels = r.le_u16().ok()?;
    let rate = r.le_u32().ok()?;
    let (_header_bytes, _terminating) = (r.le_u32().ok()?, r.le_u32().ok()?);
    let frames = r.le_u32().ok()?;
    let final_blocks = r.le_u32().ok()?;
    let blocks_per_frame = if version >= 3950 {
        73728 * 4
    } else if version >= 3900 || (version >= 3800 && compression == 4000) {
        73728
    } else {
        9216
    };
    let bits = if flags & 1 != 0 {
        8
    } else if flags & 8 != 0 {
        24
    } else {
        16
    };
    Some(Header { version, compression, channels, rate, bits, frames, final_blocks, blocks_per_frame })
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("ape");

    #[test]
    fn old_header() {
        let mut d = b"MAC ".to_vec();
        for v in [3970u16, 3000, 0, 2] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        for v in [44100u32, 44, 0, 3, 1000] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        let h = header(&d).unwrap();
        assert_eq!((h.blocks_per_frame, h.bits, h.frames, h.rate), (294_912, 16, 3, 44100));
    }
}
