//! Musepack: SV8 (`MPCK` packets: stream header, ReplayGain, encoder info)
//! and SV7 (`MP+` header: frames, sample rate, profile, gains, gapless
//! length, encoder), plus APEv2 / ID3v1 tags.
//!
//! Specifications: the Musepack SV8 specification and the SV7 stream
//! header (musepack.net).

use serde_json::json;

use super::{Stream, Tags, apetag, id3};
use crate::plugin::{ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for Musepack.
pub struct Musepack;

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.musepack",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "mpc",
        name: "Musepack audio",
        family: "audio",
        mimes: &["audio/musepack", "audio/x-musepack"],
        extensions: &["mpc", "mp+", "mpp"],
        magic: &[Magic::prefix(b"MPCK"), Magic::masked(0, b"MP+\x07", b"\xff\xff\xff\x0f")],
        parent: None,
    }],
};

const RATES: [u32; 4] = [44100, 48000, 37800, 32000];
/// SV8 packets read before the audio.
const MAX_PACKETS: usize = 64;

impl Extractor for Musepack {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut tags = Tags::default();
        let start = match id3::read_v2(src, 0, cx, &mut tags)? {
            Some(i) => i.len,
            None => 0,
        };
        let n = usize::try_from(src.len().saturating_sub(start).min(64 << 10)).unwrap_or(0);
        let head = src.read_vec(start, n)?;
        let mut s = if head.starts_with(b"MPCK") {
            sv8(&head[4..], cx)
        } else if head.starts_with(b"MP+") {
            sv7(&head, cx)
        } else {
            None
        }
        .ok_or_else(|| ExtractError::malformed("Musepack header"))?;
        let tail = src.tail().to_vec();
        let v1 = id3::read_v1(&tail, cx, &mut tags);
        let ape = apetag::read(src, v1, cx, &mut tags)?;
        if let Some(d) = s.duration_s().filter(|d| *d > 0.0) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
            let br = ((src.len() - v1 - ape - start) as f64 * 8.0 / d).round() as u64;
            s.bitrate_bps = Some(br);
        }
        s.vbr = Some(true);
        s.report(cx, None, src.len());
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Musepack);

/// A variable-length SV8 number (7 bits per byte, high bit = more).
fn varint(r: &mut ByteReader<'_>) -> Option<u64> {
    let mut n = 0u64;
    for _ in 0..9 {
        let b = r.u8().ok()?;
        n = (n << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some(n);
        }
    }
    None
}

fn sv8(d: &[u8], cx: &mut Context<'_>) -> Option<Stream> {
    let mut r = ByteReader::new(d);
    let mut stream = None;
    for _ in 0..MAX_PACKETS {
        let key = r.array::<2>().ok()?;
        let start = r.position();
        let size = usize::try_from(varint(&mut r)?).ok()?;
        let header = r.position() - start + 2;
        let body = r.bytes(size.checked_sub(header)?).ok()?;
        let mut b = ByteReader::new(body);
        match &key {
            b"SH" => {
                let _crc = b.be_u32().ok()?;
                let version = b.u8().ok()?;
                let samples = varint(&mut b)?;
                let silence = varint(&mut b)?;
                let x = b.u8().ok()?;
                let y = b.u8().ok()?;
                let mut s = Stream::new("musepack");
                s.profile = Some(format!("SV{version}"));
                s.sample_rate_hz = Some(RATES[usize::from(x >> 5)]);
                s.channels = Some(u16::from(y >> 4) + 1);
                s.samples = Some(samples.saturating_sub(silence));
                cx.format_set("stream_version", version);
                cx.format_set("mid_side_stereo", y & 8 != 0);
                if silence > 0 {
                    cx.format_set("leading_silence_samples", silence);
                }
                stream = Some(s);
            }
            b"RG" => {
                let _v = b.u8().ok()?;
                let gain = |v: i16| f64::from(v) / 256.0;
                // All zero: not measured.
                if let (Ok(tg), Ok(tp), Ok(ag), Ok(ap)) = (b.be_i16(), b.be_u16(), b.be_i16(), b.be_u16())
                    && (tg, tp, ag, ap) != (0, 0, 0, 0)
                {
                    cx.format_set(
                        "replaygain",
                        json!({ "track_gain": gain(tg), "track_peak": tp, "album_gain": gain(ag), "album_peak": ap }),
                    );
                }
            }
            b"EI" => {
                if let (Ok(p), Ok(major), Ok(minor), Ok(build)) = (b.u8(), b.u8(), b.u8(), b.u8()) {
                    cx.format_set("encoder_profile", f64::from(p >> 1) / 8.0);
                    cx.format_set("encoder", format!("{major}.{minor}.{build}"));
                }
            }
            b"AP" | b"SE" => break, // audio packets begin
            _ => {}
        }
    }
    stream
}

fn sv7(d: &[u8], cx: &mut Context<'_>) -> Option<Stream> {
    let mut r = ByteReader::new(d.get(4..)?);
    let frames = r.le_u32().ok()?;
    let a = r.le_u32().ok()?;
    let (_title_gain, _album_gain) = (r.le_u32().ok()?, r.le_u32().ok()?);
    let g = r.le_u32().ok()?;
    let encoder = *d.get(27)?;
    let rate = RATES[((a >> 16) & 3) as usize];
    let profile = (a >> 20) & 0xf;
    let gapless = g >> 31 == 1;
    let last = (g >> 20) & 0x7ff;
    let mut s = Stream::new("musepack");
    s.profile = Some("SV7".into());
    s.sample_rate_hz = Some(rate);
    s.channels = Some(2);
    let samples = u64::from(frames) * 1152;
    s.samples = Some(if gapless && frames > 0 { samples - 1152 + u64::from(last) } else { samples });
    cx.format_set("stream_version", 7);
    cx.format_set("frames", frames);
    cx.format_set("encoder_profile", profile);
    if encoder > 0 {
        cx.format_set("encoder", format!("{}.{:02}", encoder / 100, encoder % 100));
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("mpc");

    #[test]
    fn sv7_header() {
        // 10 frames, 44.1 kHz, profile 10, gapless with a 576-sample last frame, encoder 1.15.
        let mut d = b"MP+\x07".to_vec();
        d.extend_from_slice(&10u32.to_le_bytes());
        d.extend_from_slice(&(10u32 << 20).to_le_bytes());
        d.extend_from_slice(&[0; 8]);
        d.extend_from_slice(&((1u32 << 31) | (576 << 20)).to_le_bytes());
        d.extend_from_slice(&[0, 0, 0, 115]);
        d.resize(64, 0);
        let r = crate::plugin::testing::report_for("tide.mpc", &d);
        let f = &r.format["mpc"];
        assert_eq!((&f["stream_version"], &f["encoder"]), (&serde_json::json!(7), &serde_json::json!("1.15")));
        let m = r.physical.media.as_ref().unwrap();
        assert_eq!(m.streams[0]["samples"], 9 * 1152 + 576);
    }

    #[test]
    fn varints() {
        let mut r = ByteReader::new(&[0x81, 0x00, 0x05]);
        assert_eq!(varint(&mut r), Some(128));
        assert_eq!(varint(&mut r), Some(5));
    }
}
