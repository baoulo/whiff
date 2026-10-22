//! MPEG packetised elementary streams, shared by the transport and program
//! stream extractors: the PES header (MPEG-1 and MPEG-2 forms, PTS / DTS),
//! presentation-time spans, and the codec of an elementary stream from its
//! first bytes (H.264 / HEVC parameter sets, MPEG video sequence headers,
//! ADTS, MPEG audio, AC-3 / E-AC-3, DTS and LPCM headers).
//!
//! Specifications: ISO/IEC 13818-1 §2.4.3.6 (PES), ISO/IEC 13818-7 §6.2
//! (ADTS), ATSC A/52 §5.4 (AC-3 / E-AC-3 sync frames), ETSI TS 102 114 §5.3
//! (DTS core frame header), DVD-Video and Blu-ray LPCM headers.

use super::super::audio::{Stream, mpeg};
use super::{Video, codec};

/// PTS / DTS clock rate.
pub(crate) const CLOCK: f64 = 90_000.0;
/// PTS values wrap at 2^33.
const WRAP: u64 = 1 << 33;

/// A PES packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub stream_id: u8,
    pub pts: Option<u64>,
    /// Offset of the payload from the start code.
    pub payload: usize,
    /// `PES_packet_length` (0 = unbounded, video in a transport stream).
    pub length: usize,
}

fn timestamp(b: &[u8]) -> Option<u64> {
    let b = b.get(..5)?;
    // Marker bits must be set.
    if b[0] & 1 != 1 || b[2] & 1 != 1 || b[4] & 1 != 1 {
        return None;
    }
    Some(
        (u64::from((b[0] >> 1) & 7) << 30)
            | (u64::from(b[1]) << 22)
            | (u64::from(b[2] >> 1) << 15)
            | (u64::from(b[3]) << 7)
            | u64::from(b[4] >> 1),
    )
}

/// Parse a PES header at `d` (which starts with `00 00 01 stream_id`).
pub(crate) fn header(d: &[u8]) -> Option<Header> {
    if d.get(..3)? != [0, 0, 1] {
        return None;
    }
    let stream_id = *d.get(3)?;
    if stream_id < 0xbc {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([*d.get(4)?, *d.get(5)?]));
    // Program stream map, padding, private stream 2, ECM / EMM, directory: no header extension.
    if matches!(stream_id, 0xbc | 0xbe | 0xbf | 0xf0 | 0xf1 | 0xf2 | 0xf8 | 0xff) {
        return Some(Header { stream_id, pts: None, payload: 6, length });
    }
    let flags = *d.get(6)?;
    if flags & 0xc0 == 0x80 {
        let (pts_flags, header_len) = (*d.get(7)? >> 6, usize::from(*d.get(8)?));
        let pts = if pts_flags >= 2 { timestamp(d.get(9..)?) } else { None };
        return Some(Header { stream_id, pts, payload: 9 + header_len, length });
    }
    // MPEG-1: stuffing, an optional STD buffer field, then the time stamps.
    let mut i = 6;
    while d.get(i) == Some(&0xff) && i < 6 + 16 {
        i += 1;
    }
    if d.get(i)? & 0xc0 == 0x40 {
        i += 2;
    }
    let b = *d.get(i)?;
    let (pts, skip) = match b >> 4 {
        2 => (timestamp(d.get(i..)?), 5),
        3 => (timestamp(d.get(i..)?), 10),
        _ if b == 0x0f => (None, 1),
        _ => return None,
    };
    Some(Header { stream_id, pts, payload: i + skip, length })
}

/// First and last presentation time of a stream (90 kHz units).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Span {
    pub first: Option<u64>,
    pub last: Option<u64>,
}

impl Span {
    pub(crate) fn first(&mut self, pts: u64) {
        self.first.get_or_insert(pts);
    }

    /// The latest time seen near the end; B-frames reorder presentation
    /// times, so the largest one counts (allowing for one wrap).
    pub(crate) fn last(&mut self, pts: u64) {
        self.last = Some(match self.last {
            Some(l) if pts < l && l - pts < WRAP / 2 => l,
            Some(l) if pts > l && pts - l > WRAP / 2 => l,
            _ => pts,
        });
    }
}

/// The duration covered by the spans: the latest end (its last frame's
/// duration added) minus the earliest start.
pub(crate) fn duration(spans: &[(Span, f64)]) -> Option<f64> {
    let start = spans.iter().filter_map(|(s, _)| s.first).min()?;
    let end = spans
        .iter()
        .filter_map(|(s, frame)| {
            let last = s.last?;
            let last = if last < start { last + WRAP } else { last };
            Some((last - start) as f64 / CLOCK + frame)
        })
        .reduce(f64::max)?;
    (end > 0.0).then_some(end)
}

/// What an elementary stream is, from the transport / program stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    H264,
    Hevc,
    Vvc,
    MpegVideo,
    Mpeg4Video,
    Vc1,
    Cavs,
    Adts,
    Latm,
    MpegAudio,
    Ac3,
    Eac3,
    Dts,
    TrueHd,
    DvdLpcm,
    BdLpcm,
    Opus,
}

impl Kind {
    /// ffprobe's codec name before probing.
    pub(crate) fn codec(self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::Hevc => "hevc",
            Self::Vvc => "vvc",
            Self::MpegVideo => "mpeg2video",
            Self::Mpeg4Video => "mpeg4",
            Self::Vc1 => "vc1",
            Self::Cavs => "cavs",
            Self::Adts | Self::Latm => "aac",
            Self::MpegAudio => "mp2",
            Self::Ac3 => "ac3",
            Self::Eac3 => "eac3",
            Self::Dts => "dts",
            Self::TrueHd => "truehd",
            Self::DvdLpcm | Self::BdLpcm => "pcm",
            Self::Opus => "opus",
        }
    }

    pub(crate) fn is_video(self) -> bool {
        matches!(
            self,
            Self::H264 | Self::Hevc | Self::Vvc | Self::MpegVideo | Self::Mpeg4Video | Self::Vc1 | Self::Cavs
        )
    }
}

/// A probed stream.
pub(crate) enum Probed {
    Video(Box<Video>),
    /// The stream and the duration of one frame in seconds.
    Audio(Stream, f64),
}

const AAC_RATES: [u32; 13] = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350];
const AC3_RATES: [u32; 3] = [48000, 44100, 32000];
const AC3_KBPS: [u32; 19] = [32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640];
const AC3_CHANNELS: [u16; 8] = [2, 1, 2, 3, 3, 4, 4, 5];

/// The codec details from the first bytes of a stream, once enough is seen.
pub(crate) fn probe(kind: Kind, d: &[u8]) -> Option<Probed> {
    match kind {
        Kind::H264 => codec::annexb_nals(d, 64).into_iter().find_map(codec::h264_sps).map(video),
        Kind::Hevc => codec::annexb_nals(d, 64).into_iter().find_map(codec::hevc_sps).map(video),
        Kind::MpegVideo => codec::mpeg_sequence(d).map(video),
        Kind::Mpeg4Video => codec::mpeg4_visual(d).map(video),
        Kind::Adts => adts(d),
        Kind::MpegAudio => {
            let (_, f) = mpeg::first_frame(d)?;
            let mut s = Stream::new(match f.layer {
                3 => "mp3",
                2 => "mp2",
                _ => "mp1",
            });
            s.sample_rate_hz = Some(f.sample_rate);
            s.channels = Some(f.channels());
            s.bitrate_bps = Some(u64::from(f.bitrate_kbps) * 1000);
            Some(Probed::Audio(s, f64::from(f.samples()) / f64::from(f.sample_rate)))
        }
        Kind::Ac3 | Kind::Eac3 => ac3(d),
        Kind::Dts => dts(d),
        Kind::DvdLpcm => {
            // Private stream 1 LPCM: the sub-stream id, frame count, first access, then the format byte.
            let b = *d.get(5)?;
            let mut s = Stream::new("pcm");
            s.bits_per_sample = [16, 20, 24].get(usize::from(b >> 6)).copied();
            s.sample_rate_hz = Some(if (b >> 4) & 3 == 1 { 96000 } else { 48000 });
            s.channels = Some(u16::from(b & 7) + 1);
            Some(Probed::Audio(s, 1.0 / 600.0))
        }
        Kind::BdLpcm => {
            let (a, b) = (*d.get(2)?, *d.get(3)?);
            let mut s = Stream::new("pcm");
            s.channels = match a >> 4 {
                1 => Some(1),
                3 => Some(2),
                4 | 5 => Some(3),
                6 | 7 => Some(4),
                8 => Some(5),
                9 => Some(6),
                10 => Some(7),
                11 => Some(8),
                _ => None,
            };
            s.sample_rate_hz = match a & 0xf {
                1 => Some(48000),
                4 => Some(96000),
                5 => Some(192_000),
                _ => None,
            };
            s.bits_per_sample = [0, 16, 20, 24].get(usize::from(b >> 6)).copied().filter(|b| *b > 0);
            Some(Probed::Audio(s, 1.0 / 200.0))
        }
        _ => None,
    }
}

fn video(v: Video) -> Probed {
    Probed::Video(Box::new(v))
}

fn adts(d: &[u8]) -> Option<Probed> {
    let at = d.windows(2).position(|w| w[0] == 0xff && w[1] & 0xf6 == 0xf0)?;
    let h = d.get(at..at + 7)?;
    let object = (h[2] >> 6) + 1;
    let rate = *AAC_RATES.get(usize::from((h[2] >> 2) & 0xf))?;
    let mut s = Stream::new("aac");
    s.profile = Some(crate::plugin::mp4::aac_profile(object).to_string());
    s.sample_rate_hz = Some(rate);
    s.channels = Some(u16::from(((h[2] & 1) << 2) | (h[3] >> 6))).filter(|c| *c > 0);
    Some(Probed::Audio(s, 1024.0 / f64::from(rate)))
}

fn ac3(d: &[u8]) -> Option<Probed> {
    let at = d.windows(2).position(|w| w == [0x0b, 0x77])?;
    let h = d.get(at..at + 8)?;
    let bsid = h[5] >> 3;
    let mut b = codec::Bits::new(&h[2..]);
    if bsid > 10 {
        // E-AC-3: strmtyp, substreamid, frmsiz, fscod, numblkscod / fscod2, acmod, lfeon.
        b.skip(2 + 3)?;
        let frame_words = b.take(11)? + 1;
        let fscod = b.take(2)?;
        let blocks_code = b.take(2)?;
        let rate = if fscod == 3 {
            [24000, 22050, 16000].get(blocks_code as usize).copied()?
        } else {
            *AC3_RATES.get(fscod as usize)?
        };
        let blocks: u32 = if fscod == 3 { 6 } else { [1, 2, 3, 6][blocks_code as usize] };
        let acmod = b.take(3)? as usize;
        let lfe = b.take(1)?;
        let mut s = Stream::new("eac3");
        s.sample_rate_hz = Some(rate);
        s.channels = Some(AC3_CHANNELS[acmod] + u16::try_from(lfe).ok()?);
        let samples = 256.0 * f64::from(blocks);
        // Frame bits × frames per second (256 samples per block).
        s.bitrate_bps = Some(u64::from(frame_words) * 16 * u64::from(rate) / (256 * u64::from(blocks)));
        return Some(Probed::Audio(s, samples / f64::from(rate)));
    }
    let fscod = usize::from(h[4] >> 6);
    let rate = *AC3_RATES.get(fscod)?;
    let kbps = *AC3_KBPS.get(usize::from((h[4] & 0x3f) >> 1))?;
    b.skip(16 + 8 + 8)?; // crc1, fscod / frmsizecod, bsid / bsmod
    let acmod = b.take(3)?;
    if acmod & 1 != 0 && acmod != 1 {
        b.skip(2)?;
    }
    if acmod & 4 != 0 {
        b.skip(2)?;
    }
    if acmod == 2 {
        b.skip(2)?;
    }
    let lfe = b.take(1)?;
    let mut s = Stream::new("ac3");
    s.sample_rate_hz = Some(rate);
    s.channels = Some(AC3_CHANNELS[acmod as usize] + u16::try_from(lfe).ok()?);
    s.bitrate_bps = Some(u64::from(kbps) * 1000);
    Some(Probed::Audio(s, 1536.0 / f64::from(rate)))
}

fn dts(d: &[u8]) -> Option<Probed> {
    const RATES: [u32; 16] = [0, 8000, 16000, 32000, 0, 0, 11025, 22050, 44100, 0, 0, 12000, 24000, 48000, 0, 0];
    const CHANNELS: [u16; 16] = [1, 2, 2, 2, 2, 3, 3, 4, 4, 5, 6, 6, 6, 7, 8, 8];
    let at = d.windows(4).position(|w| w == [0x7f, 0xfe, 0x80, 0x01])?;
    let mut b = codec::Bits::new(d.get(at + 4..at + 16)?);
    b.skip(1 + 5 + 1)?;
    let blocks = b.take(7)? + 1;
    b.skip(14)?;
    let amode = b.take(6)? as usize;
    let rate = *RATES.get(b.take(4)? as usize)?;
    if rate == 0 {
        return None;
    }
    b.skip(5 + 1 + 1 + 1 + 1 + 1 + 3 + 1 + 1)?;
    let lff = b.take(2)?;
    let mut s = Stream::new("dts");
    s.sample_rate_hz = Some(rate);
    s.channels = CHANNELS.get(amode).map(|c| c + u16::from(matches!(lff, 1 | 2)));
    let samples = f64::from(blocks) * 32.0;
    Some(Probed::Audio(s, samples / f64::from(rate)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pes_headers_and_spans() {
        // MPEG-2 PES, PTS 90000 (one second).
        let d = [0, 0, 1, 0xe0, 0, 0, 0x80, 0x80, 5, 0x21, 0x00, 0x05, 0xbf, 0x21, 0xaa];
        let h = header(&d).unwrap();
        assert_eq!((h.stream_id, h.pts, h.payload), (0xe0, Some(90_000), 14));
        // MPEG-1 PES with stuffing and a PTS.
        let d = [0, 0, 1, 0xc0, 0, 0, 0xff, 0x21, 0x00, 0x05, 0xbf, 0x21];
        assert_eq!(header(&d).unwrap().pts, Some(90_000));
        let mut s = Span::default();
        s.first(90_000);
        s.last(270_000);
        s.last(260_000);
        assert!((duration(&[(s, 0.04)]).unwrap() - 2.04).abs() < 1e-9);
        // A stream that wrapped past 2^33.
        let mut w = Span::default();
        w.first(WRAP - 90_000);
        w.last(90_000);
        assert!((duration(&[(w, 0.0)]).unwrap() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn audio_headers() {
        // ADTS AAC-LC, 48 kHz, stereo.
        let Some(Probed::Audio(s, _)) = probe(Kind::Adts, &[0xff, 0xf1, 0x4c, 0x80, 0x01, 0x7f, 0xfc]) else {
            panic!("adts");
        };
        assert_eq!((s.sample_rate_hz, s.channels), (Some(48000), Some(2)));
        // AC-3, 48 kHz, 192 kbit/s, 3/2 with LFE (acmod 7, lfeon).
        let Some(Probed::Audio(s, _)) = probe(Kind::Ac3, &[0x0b, 0x77, 0, 0, 0x14, 0x40, 0xe1, 0x00]) else {
            panic!("ac3");
        };
        assert_eq!((s.sample_rate_hz, s.channels, s.bitrate_bps), (Some(48000), Some(6), Some(192_000)));
    }
}
