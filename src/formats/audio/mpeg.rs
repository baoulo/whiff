//! MPEG-1 / 2 / 2.5 audio, Layers I–III (MP3, MP2, MP1): frame header
//! (version, layer, sample rate, channel mode, bitrate, flags), the Xing /
//! Info and VBRI headers (frame and byte counts, VBR), the LAME tag
//! (encoder, VBR method, lowpass, delay and padding, ReplayGain), duration
//! (from the VBR header, the CBR size, or by walking the frames), and the
//! ID3v2, APE and ID3v1 tags.
//!
//! Specifications: ISO/IEC 11172-3 and 13818-3 (frame header); the Xing,
//! VBRI and LAME tag descriptions (gabriel.mp3-tech.org).

use serde_json::{Map, Value, json};

use super::{Stream, Tags, apetag, id3};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for MPEG audio.
pub struct Mpeg;

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.mpeg",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "mp3",
            name: "MP3 audio",
            family: "audio",
            mimes: &["audio/mpeg", "audio/mp3"],
            extensions: &["mp3", "mpga"],
            magic: &[Magic::prefix(b"ID3"), Magic::masked(0, b"\xff\xe2", b"\xff\xe6")],
            parent: None,
        },
        FormatSpec {
            id: "mp2",
            name: "MPEG audio Layer I / II",
            family: "audio",
            mimes: &["audio/mpeg"],
            extensions: &["mp2", "mp1", "mpa", "m2a", "m1a"],
            magic: &[Magic::masked(0, b"\xff\xe4", b"\xff\xe6"), Magic::masked(0, b"\xff\xe6", b"\xff\xe6")],
            parent: None,
        },
    ],
};

/// Bytes searched for the first frame after the tags.
const SYNC_WINDOW: usize = 128 << 10;
/// Audio bytes walked frame by frame when there is no VBR header.
const MAX_SCAN: u64 = 64 << 20;
/// Bytes read per step of the walk.
const CHUNK: usize = 1 << 20;

/// A parsed frame header (its flags are the header's bits).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Frame {
    /// 1 = MPEG-1, 2 = MPEG-2, 25 = MPEG-2.5.
    pub version: u8,
    pub layer: u8,
    pub crc: bool,
    pub bitrate_kbps: u32,
    pub sample_rate: u32,
    pub padding: bool,
    /// 0 stereo, 1 joint stereo, 2 dual channel, 3 mono.
    pub mode: u8,
    pub copyright: bool,
    pub original: bool,
    pub emphasis: u8,
}

const BITRATES: [[u32; 15]; 5] = [
    [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448], // V1 L1
    [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],    // V1 L2
    [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],     // V1 L3
    [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256],    // V2 L1
    [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],         // V2 L2 / L3
];

impl Frame {
    /// Parse a 4-byte header; free-format and reserved values are rejected.
    pub(crate) fn parse(h: &[u8]) -> Option<Self> {
        let h = h.get(..4)?;
        if h[0] != 0xff || h[1] & 0xe0 != 0xe0 {
            return None;
        }
        let version = match (h[1] >> 3) & 3 {
            0 => 25,
            2 => 2,
            3 => 1,
            _ => return None,
        };
        let layer = match (h[1] >> 1) & 3 {
            1 => 3,
            2 => 2,
            3 => 1,
            _ => return None,
        };
        let bi = usize::from(h[2] >> 4);
        let si = usize::from((h[2] >> 2) & 3);
        if bi == 0 || bi == 15 || si == 3 {
            return None;
        }
        let table = match (version, layer) {
            (1, l) => usize::from(l - 1),
            (_, 1) => 3,
            _ => 4,
        };
        let base = [44100, 48000, 32000][si];
        let sample_rate = match version {
            1 => base,
            2 => base / 2,
            _ => base / 4,
        };
        Some(Self {
            version,
            layer,
            crc: h[1] & 1 == 0,
            bitrate_kbps: BITRATES[table][bi],
            sample_rate,
            padding: h[2] & 2 != 0,
            mode: h[3] >> 6,
            copyright: h[3] & 8 != 0,
            original: h[3] & 4 != 0,
            emphasis: h[3] & 3,
        })
    }

    /// Samples per frame.
    pub(crate) fn samples(&self) -> u32 {
        match (self.layer, self.version) {
            (1, _) => 384,
            (3, 2 | 25) => 576,
            _ => 1152,
        }
    }

    /// Frame length in bytes, header included.
    pub(crate) fn len(&self) -> usize {
        let br = self.bitrate_kbps * 1000;
        let pad = u32::from(self.padding);
        (if self.layer == 1 {
            (12 * br / self.sample_rate + pad) * 4
        } else {
            self.samples() / 8 * br / self.sample_rate + pad
        }) as usize
    }

    fn channels(&self) -> u16 {
        if self.mode == 3 { 1 } else { 2 }
    }

    /// Bytes from the frame start to a Xing / Info header.
    fn xing_offset(&self) -> usize {
        4 + match (self.version, self.mode) {
            (1, 3) => 17,
            (1, _) => 32,
            (_, 3) => 9,
            _ => 17,
        }
    }

    fn same_stream(&self, other: &Self) -> bool {
        self.version == other.version && self.layer == other.layer && self.sample_rate == other.sample_rate
    }
}

impl Extractor for Mpeg {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // After an ID3v2 tag: the layer of the first frame decides.
        let len = usize::try_from(id3::v2_len(probe.head)?).ok()?;
        let (_, f) = first_frame(probe.head.get(len..)?)?;
        Some(Sniff { format: if f.layer == 3 { "mp3" } else { "mp2" }, confidence: 0.95 })
    }

    #[allow(clippy::too_many_lines)] // tags, frame header, VBR header and duration in turn
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let mut tags = Tags::default();
        // ID3v2 tags (some files carry several), then the first frame.
        let mut start = 0u64;
        let mut id3_versions = Vec::new();
        while let Some(info) = id3::read_v2(src, start, cx, &mut tags)? {
            id3_versions.push(info.version);
            start += info.len;
            if id3_versions.len() >= 4 {
                break;
            }
        }
        let window =
            src.read_vec(start, usize::try_from((len - start.min(len)).min(SYNC_WINDOW as u64)).unwrap_or(0))?;
        let Some((skip, first)) = first_frame(&window) else {
            return Err(ExtractError::malformed("no MPEG audio frame found"));
        };
        let audio_start = start + skip as u64;
        if skip > 0 {
            cx.format_set("junk_before_audio_bytes", skip);
        }

        // Tags at the end: ID3v1, then an APE tag before it.
        let tail = src.tail().to_vec();
        let v1 = id3::read_v1(&tail, cx, &mut tags);
        let ape = apetag::read(src, v1, cx, &mut tags)?;
        let audio_end = len - v1 - ape;
        let audio_bytes = audio_end.saturating_sub(audio_start);

        let head = &window[skip..];
        let vbr_header = xing(head, &first).or_else(|| vbri(head));
        let mut frames = vbr_header.as_ref().and_then(|v| v.frames);
        let mut bytes = vbr_header.as_ref().and_then(|v| v.bytes).map(u64::from);
        let mut vbr = vbr_header.as_ref().map(|v| v.vbr);
        if vbr_header.is_none() {
            // No header: CBR if the first frames agree, else walk them all.
            if bitrates_vary(head) {
                let (n, b) = walk(src, audio_start, audio_end, &first, cx)?;
                frames = Some(n);
                bytes = Some(b);
                vbr = Some(true);
            } else {
                vbr = Some(false);
            }
        }
        let spf = f64::from(first.samples());
        let sr = f64::from(first.sample_rate);
        let duration = match frames {
            // The VBR header's own frame (an empty frame) is not audio.
            Some(n) if n > 0 => f64::from(n) * spf / sr,
            _ => audio_bytes as f64 * 8.0 / f64::from(first.bitrate_kbps * 1000),
        };
        let mut stream = Stream::new(match first.layer {
            3 => "mp3",
            2 => "mp2",
            _ => "mp1",
        });
        stream.profile = Some(format!(
            "MPEG-{} Layer {}",
            if first.version == 25 { "2.5".into() } else { first.version.to_string() },
            ["", "I", "II", "III"][usize::from(first.layer)]
        ));
        stream.sample_rate_hz = Some(first.sample_rate);
        stream.channels = Some(first.channels());
        stream.vbr = vbr;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
        let avg = match (vbr, bytes) {
            (Some(true), Some(b)) if duration > 0.0 => (b as f64 * 8.0 / duration).round() as u64,
            (Some(true), None) if duration > 0.0 => (audio_bytes as f64 * 8.0 / duration).round() as u64,
            _ => u64::from(first.bitrate_kbps) * 1000,
        };
        stream.bitrate_bps = Some(avg);
        if let Some(n) = frames {
            stream.samples = Some(u64::from(n) * u64::from(first.samples()));
        }
        stream.report(cx, Some(duration), len);

        cx.format_set("mpeg_version", if first.version == 25 { "2.5".to_string() } else { first.version.to_string() });
        cx.format_set("layer", first.layer);
        cx.format_set("channel_mode", ["stereo", "joint_stereo", "dual_channel", "mono"][usize::from(first.mode)]);
        cx.format_set("crc_protected", first.crc);
        cx.format_set("original", first.original);
        cx.format_set("copyright_bit", first.copyright);
        if first.emphasis != 0 {
            cx.format_set("emphasis", ["none", "50/15 us", "reserved", "CCITT J.17"][usize::from(first.emphasis)]);
        }
        if first.copyright {
            cx.rights().source("mpeg.copyright_bit").marked(true);
        }
        if let Some(n) = frames {
            cx.format_set("frames", n);
        }
        cx.format_set("audio_bytes", audio_bytes);
        if let Some(v) = vbr_header {
            cx.format_set("vbr_header", v.json);
            if let Some(l) = v.lame {
                if let Some(e) = l.get("encoder").and_then(Value::as_str) {
                    tags.set("encoder", e, "lame");
                }
                if let Some(g) = l.get("replaygain_track_gain_db").and_then(Value::as_f64) {
                    tags.set("replaygain_track_gain_db", &g.to_string(), "lame");
                }
                cx.format_set("lame", Value::Object(l));
            }
        }
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Mpeg);

/// The first frame in `data` that is followed by a matching frame (or ends
/// the data): its offset and header.
pub(crate) fn first_frame(data: &[u8]) -> Option<(usize, Frame)> {
    let mut i = 0;
    while i + 4 <= data.len() {
        if data[i] == 0xff
            && let Some(f) = Frame::parse(&data[i..])
        {
            let next = i + f.len();
            match data.get(next..next + 4) {
                Some(h) if Frame::parse(h).is_some_and(|g| f.same_stream(&g)) => return Some((i, f)),
                None if next <= data.len() + 4 && i == 0 => return Some((i, f)),
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Whether the first frames (up to 16) have different bitrates.
fn bitrates_vary(data: &[u8]) -> bool {
    let mut pos = 0;
    let mut first = None;
    for _ in 0..16 {
        let Some(f) = data.get(pos..).and_then(Frame::parse) else { break };
        match first {
            None => first = Some(f.bitrate_kbps),
            Some(b) if b != f.bitrate_kbps => return true,
            _ => {}
        }
        pos += f.len().max(1);
    }
    false
}

/// Count frames and bytes from `start` to `end` (at most [`MAX_SCAN`]
/// bytes; the rest is estimated from the average frame size).
fn walk(
    src: &mut dyn Source,
    start: u64,
    end: u64,
    first: &Frame,
    cx: &mut Context<'_>,
) -> Result<(u32, u64), ExtractError> {
    let (mut frames, mut bytes) = (0u64, 0u64);
    let mut pos = start;
    let limit = end.min(start.saturating_add(MAX_SCAN));
    let mut buf = Vec::new();
    let mut buf_at = start;
    while pos + 4 <= limit {
        if pos + 4 > buf_at + buf.len() as u64 {
            cx.checkpoint()?;
            buf_at = pos;
            let n = usize::try_from((end - pos).min(CHUNK as u64)).unwrap_or(0);
            buf = src.read_vec(pos, n)?;
            if buf.len() < 4 {
                break;
            }
        }
        let off = usize::try_from(pos - buf_at).unwrap_or(0);
        match Frame::parse(&buf[off..]) {
            Some(f) if f.same_stream(first) => {
                frames += 1;
                bytes += f.len() as u64;
                pos += f.len() as u64;
            }
            // Lost sync: look for the next frame byte by byte.
            _ => pos += 1,
        }
    }
    if limit < end && bytes > 0 {
        let estimate = (end - start) as f64 / (bytes as f64 / frames as f64);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let est = estimate.round() as u64;
        cx.warn("frame count estimated beyond the scanned part");
        return Ok((u32::try_from(est).unwrap_or(u32::MAX), end - start));
    }
    Ok((u32::try_from(frames).unwrap_or(u32::MAX), bytes))
}

struct VbrHeader {
    frames: Option<u32>,
    bytes: Option<u32>,
    vbr: bool,
    json: Value,
    lame: Option<Map<String, Value>>,
}

/// A Xing (VBR) or Info (CBR) header in the first frame, with the LAME tag.
fn xing(frame: &[u8], f: &Frame) -> Option<VbrHeader> {
    let at = f.xing_offset();
    let id = frame.get(at..at + 4)?;
    if id != b"Xing" && id != b"Info" {
        return None;
    }
    let flags = u32::from_be_bytes(frame.get(at + 4..at + 8)?.try_into().ok()?);
    let mut p = at + 8;
    let mut take = |present: bool, n: usize| -> Option<&[u8]> {
        if !present {
            return None;
        }
        let v = frame.get(p..p + n);
        p += n;
        v
    };
    let be = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let frames = take(flags & 1 != 0, 4).map(be);
    let bytes = take(flags & 2 != 0, 4).map(be);
    let toc = take(flags & 4 != 0, 100).is_some();
    let quality = take(flags & 8 != 0, 4).map(be);
    let vbr = id == b"Xing";
    let mut j = Map::new();
    j.insert("kind".into(), json!(if vbr { "xing" } else { "info" }));
    if let Some(n) = frames {
        j.insert("frames".into(), json!(n));
    }
    if let Some(n) = bytes {
        j.insert("bytes".into(), json!(n));
    }
    j.insert("toc".into(), json!(toc));
    if let Some(q) = quality {
        j.insert("quality".into(), json!(q));
    }
    Some(VbrHeader { frames, bytes, vbr, json: Value::Object(j), lame: frame.get(p..).and_then(lame) })
}

/// The LAME / LAVC tag after a Xing header.
fn lame(d: &[u8]) -> Option<Map<String, Value>> {
    let enc = d.get(..9)?;
    if !(enc.starts_with(b"LAME") || enc.starts_with(b"Lavc") || enc.starts_with(b"Lavf") || enc.starts_with(b"GOGO")) {
        return None;
    }
    let mut m = Map::new();
    let name = String::from_utf8_lossy(enc).trim_end_matches(['\0', ' ']).to_string();
    m.insert("encoder".into(), json!(name));
    let t = d.get(9..36)?;
    let method = match t[0] & 0x0f {
        1 => "cbr",
        2 => "abr",
        3..=6 => "vbr",
        8 => "cbr_2pass",
        9 => "abr_2pass",
        _ => "unknown",
    };
    m.insert("vbr_method".into(), json!(method));
    if t[1] != 0 {
        m.insert("lowpass_hz".into(), json!(u32::from(t[1]) * 100));
    }
    // ReplayGain: radio (track) gain in tenths of a dB, sign in bit 9.
    let rg = u16::from_be_bytes([t[6], t[7]]);
    if rg >> 13 == 1 && rg & 0x1ff != 0 {
        let v = f64::from(rg & 0x1ff) / 10.0;
        m.insert("replaygain_track_gain_db".into(), json!(if rg & 0x200 != 0 { -v } else { v }));
    }
    let delay = (u32::from(t[12]) << 4) | (u32::from(t[13]) >> 4);
    let padding = ((u32::from(t[13]) & 0x0f) << 8) | u32::from(t[14]);
    m.insert("encoder_delay_samples".into(), json!(delay));
    m.insert("encoder_padding_samples".into(), json!(padding));
    if method == "abr" || method == "cbr" {
        m.insert("bitrate_kbps".into(), json!(t[11]));
    }
    m.insert("music_length_bytes".into(), json!(u32::from_be_bytes([t[19], t[20], t[21], t[22]])));
    Some(m)
}

/// A Fraunhofer VBRI header (32 bytes after the frame header).
fn vbri(frame: &[u8]) -> Option<VbrHeader> {
    let d = frame.get(36..36 + 18)?;
    if &d[..4] != b"VBRI" {
        return None;
    }
    let bytes = u32::from_be_bytes([d[10], d[11], d[12], d[13]]);
    let frames = u32::from_be_bytes([d[14], d[15], d[16], d[17]]);
    let delay = u16::from_be_bytes([d[6], d[7]]);
    Some(VbrHeader {
        frames: Some(frames),
        bytes: Some(bytes),
        vbr: true,
        json: json!({ "kind": "vbri", "frames": frames, "bytes": bytes, "delay": delay }),
        lame: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("mp3", "mp2");

    #[test]
    fn frame_headers() {
        let f = Frame::parse(&[0xff, 0xfb, 0x90, 0x00]).unwrap();
        assert_eq!((f.version, f.layer, f.bitrate_kbps, f.sample_rate, f.len()), (1, 3, 128, 44100, 417));
        let f = Frame::parse(&[0xff, 0xf3, 0x40, 0xc4]).unwrap();
        assert_eq!((f.version, f.samples(), f.sample_rate, f.mode), (2, 576, 22050, 3));
        assert!(Frame::parse(&[0xff, 0xfb, 0xf0, 0]).is_none()); // bad bitrate
        assert!(Frame::parse(&[0xff, 0xfb, 0x0c, 0]).is_none()); // reserved rate
    }

    #[test]
    fn vbr_without_header_is_walked() {
        // 128 kbit/s and 64 kbit/s frames alternating, no Xing header.
        let mut file = Vec::new();
        for i in 0..20 {
            let (b2, n) = if i % 2 == 0 { (0x90, 417) } else { (0x50, 208) };
            let mut fr = vec![0xff, 0xfb, b2, 0xc0];
            fr.resize(n, 0x55);
            file.extend(fr);
        }
        let r = crate::plugin::testing::report_for("walk.mp3", &file);
        assert_eq!(r.format["mp3"]["frames"], 20);
        assert_eq!(r.physical.media.as_ref().unwrap().streams[0]["bitrate_mode"], "vbr");
        let d = r.physical.media.as_ref().unwrap().duration_s.unwrap();
        assert!((d - 20.0 * 1152.0 / 44100.0).abs() < 1e-6);
    }
}
