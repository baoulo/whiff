//! WavPack: the first block header (version, sample rate, bit depth,
//! channels, total samples, lossless / hybrid / float / DSD), the channel
//! layout and MD5 sub-blocks, and APEv2 / ID3v1 tags at the end.
//!
//! Specification: WavPack 5 file format (wavpack.com/WavPack5FileFormat.pdf).

use super::{Stream, Tags, apetag, id3, mask_layout};
use crate::plugin::{ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for WavPack.
pub struct WavPack;

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.wavpack",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "wv",
        name: "WavPack audio",
        family: "audio",
        mimes: &["audio/wavpack", "audio/x-wavpack"],
        extensions: &["wv", "wvc"],
        magic: &[Magic::prefix(b"wvpk")],
        parent: None,
    }],
};

const RATES: [u32; 15] =
    [6000, 8000, 9600, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000, 64000, 88200, 96000, 192_000];

impl Extractor for WavPack {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let h = src.read_vec(0, 32)?;
        let mut r = ByteReader::new(&h[4..]);
        let size = r.le_u32()?;
        let version = r.le_u16()?;
        let (_index_hi, total_hi) = (r.u8()?, r.u8()?);
        let (total_lo, _index_lo, _block_samples, flags, _crc) =
            (r.le_u32()?, r.le_u32()?, r.le_u32()?, r.le_u32()?, r.le_u32()?);
        let mut s = Stream::new(if flags & 0x8000_0000 != 0 { "wavpack_dsd" } else { "wavpack" });
        let rate_index = ((flags >> 23) & 0xf) as usize;
        s.sample_rate_hz = RATES.get(rate_index).copied();
        let float = flags & 0x80 != 0;
        s.bits_per_sample = Some(if float { 32 } else { u16::try_from((flags & 3) + 1).unwrap_or(2) * 8 });
        s.channels = Some(if flags & 4 != 0 { 1 } else { 2 });
        if total_lo != u32::MAX {
            s.samples = Some((u64::from(total_hi) << 32) | u64::from(total_lo));
        }
        let hybrid = flags & 8 != 0;
        // Metadata sub-blocks of the first block: channel info, sample rate, MD5.
        let body_len = (size as usize).saturating_sub(24).min(1 << 20);
        let body = src.read_vec(32, body_len.min(usize::try_from(src.len().saturating_sub(32)).unwrap_or(0)))?;
        let mut md5 = None;
        let mut r = ByteReader::new(&body);
        for _ in 0..256 {
            let Ok(id) = r.u8() else { break };
            let Ok(n) = (if id & 0x80 != 0 {
                r.bytes(3).map(|b| u32::from_le_bytes([b[0], b[1], b[2], 0]) as usize * 2)
            } else {
                r.u8().map(|b| usize::from(b) * 2)
            }) else {
                break;
            };
            let Ok(data) = r.bytes(n) else { break };
            let data = if id & 0x40 != 0 { &data[..n.saturating_sub(1)] } else { data };
            match id & 0x3f {
                0x0d if !data.is_empty() => {
                    // Channel count, then the speaker mask (1–4 bytes).
                    s.channels = Some(u16::from(data[0]));
                    let mut mask = 0u32;
                    for (i, &b) in data[1..].iter().take(4).enumerate() {
                        mask |= u32::from(b) << (8 * i);
                    }
                    if mask != 0 {
                        s.channel_layout = mask_layout(mask);
                    }
                }
                0x27 if data.len() >= 3 => {
                    s.sample_rate_hz = Some(u32::from_le_bytes([data[0], data[1], data[2], 0]));
                }
                0x26 if data.len() == 16 => md5 = Some(super::hex(data)),
                _ => {}
            }
        }
        cx.format_set("version", format!("0x{version:03x}"));
        cx.format_set("mode", if hybrid { "hybrid" } else { "lossless" });
        cx.format_set("float", float);
        cx.format_set("joint_stereo", flags & 0x10 != 0);
        if let Some(m) = md5 {
            cx.format_set("audio_md5", m);
        }
        let mut tags = Tags::default();
        let tail = src.tail().to_vec();
        let v1 = id3::read_v1(&tail, cx, &mut tags);
        let ape = apetag::read(src, v1, cx, &mut tags)?;
        if let Some(d) = s.duration_s().filter(|d| *d > 0.0) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
            let br = ((src.len() - v1 - ape) as f64 * 8.0 / d).round() as u64;
            s.bitrate_bps = Some(br);
        }
        s.vbr = Some(true);
        s.report(cx, None, src.len());
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(WavPack);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("wv");
}
