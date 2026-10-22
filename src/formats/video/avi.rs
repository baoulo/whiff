//! AVI (RIFF `AVI `, including OpenDML / AVI 2.0 files over 1 GiB): the
//! main header (frame time, frame count, size), every stream header and
//! format (`BITMAPINFOHEADER` video with its FourCC, `WAVEFORMATEX` audio,
//! text), stream names, OpenDML total frames, video properties (frame aspect
//! ratio, interlacing), `INFO` tags, the `IDIT` date, the codec details of
//! the first video frame (H.264 / MPEG-4 Part 2 headers), and the index.
//!
//! Specifications: Microsoft AVI RIFF file reference, OpenDML AVI File
//! Format Extensions 1.02, `BITMAPINFOHEADER` / `WAVEFORMATEX`.

use serde_json::json;

use super::super::audio::{Stream, Tags, riff};
use super::codec;
use super::{Video, audio_map, finish, labels, other_map};
use crate::plugin::{
    ByteReader, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source,
};

/// Extractor for AVI.
pub struct Avi;

static META: ExtractorMeta = ExtractorMeta {
    id: "video.avi",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "avi",
        name: "AVI video",
        family: "video",
        mimes: &["video/x-msvideo", "video/avi", "video/vnd.avi"],
        extensions: &["avi", "divx", "xvid"],
        magic: &[Magic::masked(0, b"RIFF\0\0\0\0AVI ", b"\xff\xff\xff\xff\0\0\0\0\xff\xff\xff\xff")],
        parent: None,
    }],
};

/// Largest `hdrl` list read.
const MAX_HEADER: u32 = 4 << 20;
/// Bytes of `movi` searched for the first video chunk.
const FIRST_FRAME: usize = 512 << 10;
const MAX_STREAMS: usize = 64;

#[derive(Default)]
struct StreamHeader {
    kind: [u8; 4],
    handler: [u8; 4],
    language: u16,
    scale: u32,
    rate: u32,
    length: u32,
    sample_size: u32,
    format: Vec<u8>,
    name: Option<String>,
}

impl StreamHeader {
    fn seconds(&self) -> Option<f64> {
        (self.rate > 0 && self.scale > 0 && self.length > 0)
            .then(|| f64::from(self.length) * f64::from(self.scale) / f64::from(self.rate))
    }
}

impl Extractor for Avi {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // chunk walk, then one stream map per type
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let mut tags = Tags::default();
        let mut streams: Vec<StreamHeader> = Vec::new();
        let mut main: Option<(u32, u32, u32, u32, u32)> = None;
        let (mut odml_frames, mut aspect, mut interlaced) = (None, None, None);
        let (mut index, mut riffs, mut movi) = (false, 0u32, None);
        let mut pos = 0u64;
        // RIFF AVI , then RIFF AVIX continuations (OpenDML).
        while pos + 12 <= len && riffs < 1024 {
            let h = src.read_vec(pos, 12)?;
            if &h[..4] != b"RIFF" {
                break;
            }
            let size = u64::from(u32::from_le_bytes([h[4], h[5], h[6], h[7]]));
            riffs += 1;
            let end = (pos + 8 + size).min(len);
            if &h[8..12] == b"AVI " {
                let mut at = pos + 12;
                while at + 8 <= end {
                    let c = src.read_vec(at, 12.min(usize::try_from(end - at).unwrap_or(0)))?;
                    let n = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
                    let body = at + 8;
                    match (&c[..4], c.get(8..12)) {
                        (b"LIST", Some(b"hdrl")) if n <= MAX_HEADER => {
                            let d = src.read_vec(body + 4, (n as usize).saturating_sub(4))?;
                            header_list(&d, &mut main, &mut streams, &mut odml_frames, &mut aspect, &mut interlaced);
                        }
                        (b"LIST", Some(b"INFO")) if n <= MAX_HEADER => {
                            let d = src.read_vec(body, n as usize)?;
                            riff::list(&d, cx, &mut tags);
                        }
                        (b"LIST", Some(b"movi")) => movi = Some((body + 4, u64::from(n).saturating_sub(4))),
                        (b"idx1", _) => index = true,
                        (b"IDIT", _) if n <= 256 => {
                            let d = src.read_vec(body, n as usize)?;
                            let t = audio_text(&d);
                            if !t.is_empty() {
                                cx.format_set("digitization_date", t.as_str());
                                if let Some((v, tz)) = crate::plugin::parse_date(&t) {
                                    cx.temporal().source("avi.IDIT").content_date(DateField::Digitized, v, tz);
                                }
                            }
                        }
                        _ => {}
                    }
                    at = body + u64::from(n) + u64::from(n % 2);
                }
            }
            pos = end + (size % 2);
        }
        let Some((usec, total, _flags, width, height)) = main else {
            return Err(ExtractError::malformed("no AVI main header"));
        };
        cx.format_set("riff_chunks", riffs);
        cx.format_set("opendml", riffs > 1 || odml_frames.is_some());
        cx.format_set("indexed", index);
        // The first video chunk, for the codec's own headers.
        let mut first_frame = Vec::new();
        if let Some((at, n)) = movi {
            let d = src.read_vec(at, usize::try_from(n).unwrap_or(0).min(FIRST_FRAME))?;
            first_frame = first_video_chunk(&d);
        }
        let mut maps = Vec::new();
        let mut longest: Option<f64> = None;
        let frames = odml_frames.unwrap_or(total);
        for (i, s) in streams.iter().enumerate() {
            let seconds = s.seconds();
            // A compressed audio stream counted in bytes (sample size set) has
            // an unreliable length; like ffprobe, leave it out of the duration.
            let pcm = s.format.len() >= 2 && matches!(u16::from_le_bytes([s.format[0], s.format[1]]), 1 | 3 | 0xfffe);
            let counted = if &s.kind == b"auds" && s.sample_size > 0 && !pcm { None } else { seconds };
            longest = match (longest, counted) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
            let mut m = match &s.kind {
                b"vids" => {
                    let fourcc =
                        if s.format.len() >= 20 { fourcc_text(&s.format[16..20]) } else { fourcc_text(&s.handler) };
                    let mut v = Video::new(vfw_codec(&fourcc));
                    v.codec_tag = Some(fourcc);
                    if s.format.len() >= 16 {
                        let w = i32::from_le_bytes([s.format[4], s.format[5], s.format[6], s.format[7]]);
                        let h = i32::from_le_bytes([s.format[8], s.format[9], s.format[10], s.format[11]]);
                        v.width = Some(w.unsigned_abs()).filter(|w| *w > 0);
                        v.height = Some(h.unsigned_abs()).filter(|h| *h > 0);
                    }
                    if v.width.is_none() && width > 0 {
                        (v.width, v.height) = (Some(width), Some(height));
                    }
                    if s.rate > 0 && s.scale > 0 {
                        v.fps = Some(f64::from(s.rate) / f64::from(s.scale));
                    } else if usec > 0 {
                        v.fps = Some(1e6 / f64::from(usec));
                    }
                    v.frames = Some(u64::from(if i == 0 { frames.max(s.length) } else { s.length }));
                    v.dar = aspect;
                    v.interlaced = interlaced;
                    v.duration_s = seconds;
                    // Codec headers from the extra data of the format, else the first frame.
                    let extra = s.format.get(40..).unwrap_or_default();
                    for d in [extra, first_frame.as_slice()] {
                        let parsed = match v.codec.as_str() {
                            "h264" => codec::annexb_nals(d, 32).into_iter().find_map(codec::h264_sps),
                            "hevc" => codec::annexb_nals(d, 32).into_iter().find_map(codec::hevc_sps),
                            "mpeg4" => codec::mpeg4_visual(d),
                            "mpeg1video" | "mpeg2video" => codec::mpeg_sequence(d),
                            _ => None,
                        };
                        if let Some(c) = parsed {
                            v.absorb(c);
                            break;
                        }
                    }
                    v.title.clone_from(&s.name);
                    v.to_map()
                }
                b"auds" => {
                    let mut st = audio_format(&s.format);
                    if let (Some(d), Some(st_rate)) = (seconds, st.sample_rate_hz)
                        && st.codec == "pcm"
                    {
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
                        let n = (d * f64::from(st_rate)).round() as u64;
                        st.samples = Some(n);
                    }
                    let mut m = audio_map(&st);
                    labels(&mut m, None, s.name.as_deref(), None, None);
                    m
                }
                b"txts" => {
                    let mut m = other_map("subtitle", "text");
                    labels(&mut m, None, s.name.as_deref(), None, None);
                    m
                }
                other => other_map("data", &fourcc_text(other)),
            };
            if s.language != 0 {
                m.insert("language_id".into(), json!(s.language));
            }
            maps.push(m);
        }
        let main_s = (usec > 0 && frames > 0).then(|| f64::from(frames) * f64::from(usec) / 1e6);
        let duration = longest.or(main_s);
        cx.format_set(
            "main_header",
            json!({ "microseconds_per_frame": usec, "total_frames": total, "width": width, "height": height }),
        );
        if let Some(f) = odml_frames {
            cx.format_set("opendml_total_frames", f);
        }
        finish(cx, maps, duration, len);
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Avi);

fn audio_text(d: &[u8]) -> String {
    String::from_utf8_lossy(d).trim_matches(|c: char| c == '\0' || c.is_whitespace()).to_string()
}

fn fourcc_text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim_end_matches(['\0', ' ']).to_string()
}

fn header_list(
    d: &[u8],
    main: &mut Option<(u32, u32, u32, u32, u32)>,
    streams: &mut Vec<StreamHeader>,
    odml: &mut Option<u32>,
    aspect: &mut Option<(u32, u32)>,
    interlaced: &mut Option<bool>,
) {
    for (id, body) in chunks(d) {
        match (&id, body.get(..4)) {
            (b"avih", _) => {
                let mut r = ByteReader::new(body);
                if let (Ok(usec), Ok(_max), Ok(_pad), Ok(flags), Ok(total), Ok(_init), Ok(_n), Ok(_buf), Ok(w), Ok(h)) = (
                    r.le_u32(),
                    r.le_u32(),
                    r.le_u32(),
                    r.le_u32(),
                    r.le_u32(),
                    r.le_u32(),
                    r.le_u32(),
                    r.le_u32(),
                    r.le_u32(),
                    r.le_u32(),
                ) {
                    *main = Some((usec, total, flags, w, h));
                }
            }
            (b"LIST", Some(b"strl")) if streams.len() < MAX_STREAMS => {
                let mut s = StreamHeader::default();
                for (k, b) in chunks(&body[4..]) {
                    match &k {
                        b"strh" if b.len() >= 48 => {
                            let u = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
                            s.kind.copy_from_slice(&b[..4]);
                            s.handler.copy_from_slice(&b[4..8]);
                            s.language = u16::from_le_bytes([b[14], b[15]]);
                            (s.scale, s.rate, s.length, s.sample_size) = (u(20), u(24), u(32), u(44));
                        }
                        b"strf" => s.format = b.to_vec(),
                        b"strn" => s.name = Some(audio_text(b)).filter(|n| !n.is_empty()),
                        b"vprp" if b.len() >= 36 => {
                            let ratio = u32::from_le_bytes([b[20], b[21], b[22], b[23]]);
                            let (x, y) = (ratio >> 16, ratio & 0xffff);
                            *aspect = Some((x, y)).filter(|a| a.0 > 0 && a.1 > 0);
                            let fields = u32::from_le_bytes([b[32], b[33], b[34], b[35]]);
                            *interlaced = Some(fields == 2);
                        }
                        _ => {}
                    }
                }
                streams.push(s);
            }
            (b"LIST", Some(b"odml")) => {
                for (k, b) in chunks(&body[4..]) {
                    if &k == b"dmlh" && b.len() >= 4 {
                        *odml = Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]])).filter(|f| *f > 0);
                    }
                }
            }
            _ => {}
        }
    }
}

/// RIFF chunks in `d`: id and body (word-aligned).
fn chunks(d: &[u8]) -> impl Iterator<Item = ([u8; 4], &[u8])> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let h = d.get(at..at + 8)?;
        let id = [h[0], h[1], h[2], h[3]];
        let n = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
        let body = d.get(at + 8..(at + 8).checked_add(n)?.min(d.len()))?;
        at = at + 8 + n + n % 2;
        Some((id, body))
    })
}

/// The first `##dc` / `##db` chunk of the `movi` list.
fn first_video_chunk(d: &[u8]) -> Vec<u8> {
    let mut at = 0usize;
    while let Some(h) = d.get(at..at + 8) {
        let n = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
        if &h[..4] == b"LIST" {
            at += 12; // a `rec ` list: walk into it
            continue;
        }
        if (&h[2..4] == b"dc" || &h[2..4] == b"db") && n > 0 {
            return d.get(at + 8..(at + 8 + n).min(d.len())).unwrap_or_default().to_vec();
        }
        at += 8 + n + n % 2;
    }
    Vec::new()
}

fn audio_format(f: &[u8]) -> Stream {
    if f.len() < 14 {
        return Stream::new("unknown");
    }
    let tag = u16::from_le_bytes([f[0], f[1]]);
    let mut s = Stream::new(riff::codec(tag));
    s.channels = Some(u16::from_le_bytes([f[2], f[3]]));
    s.sample_rate_hz = Some(u32::from_le_bytes([f[4], f[5], f[6], f[7]]));
    s.bitrate_bps = Some(u64::from(u32::from_le_bytes([f[8], f[9], f[10], f[11]])) * 8).filter(|b| *b > 0);
    if f.len() >= 16 && matches!(tag, 1 | 3 | 0xfffe) {
        s.bits_per_sample = Some(u16::from_le_bytes([f[14], f[15]])).filter(|b| *b > 0);
    }
    if tag == 0xff
        && let Some(asc) = f.get(18..)
        && let Some(c) = crate::plugin::mp4::AudioConfig::parse(asc)
    {
        s.profile = Some(crate::plugin::mp4::aac_profile(c.object).into());
    }
    s
}

/// ffprobe's codec name for a Video for Windows FourCC.
pub(crate) fn vfw_codec(fourcc: &str) -> String {
    let upper = fourcc.to_ascii_uppercase();
    match upper.as_str() {
        "H264" | "X264" | "AVC1" | "DAVC" | "VSSH" | "AVCX" => "h264",
        "HEVC" | "H265" | "HVC1" | "X265" => "hevc",
        "XVID" | "DIVX" | "DX50" | "FMP4" | "MP4V" | "MP4S" | "M4S2" | "3IV2" | "RMP4" | "SEDG" | "BLZ0" => "mpeg4",
        "DIV3" | "MP43" | "DIV4" | "AP41" | "COL1" => "msmpeg4v3",
        "MP42" | "DIV2" => "msmpeg4v2",
        "MPG4" | "DIV1" => "msmpeg4v1",
        "MJPG" | "AVRN" | "LJPG" | "JPGL" | "MJLS" | "DMB1" => "mjpeg",
        "MPG1" | "PIM1" => "mpeg1video",
        "MPG2" | "MPEG" | "MMES" | "HDV2" => "mpeg2video",
        "WMV1" => "wmv1",
        "WMV2" => "wmv2",
        "WMV3" => "wmv3",
        "WVC1" | "WMVA" => "vc1",
        "VP80" => "vp8",
        "VP90" => "vp9",
        "AV01" => "av1",
        "FFV1" => "ffv1",
        "HFYU" => "huffyuv",
        "FFVH" => "ffvhuff",
        "DVSD" | "DV25" | "DV50" | "DVHD" | "CDVC" | "CDVH" => "dvvideo",
        "CVID" => "cinepak",
        "IV31" | "IV32" => "indeo3",
        "IV41" => "indeo4",
        "IV50" => "indeo5",
        "TSCC" => "tscc",
        "MSVC" | "CRAM" | "WHAM" => "msvideo1",
        "MRLE" => "msrle",
        "H263" | "U263" | "S263" => "h263",
        "FLV1" => "flv1",
        "MAGY" => "magicyuv",
        "ULRG" | "ULY0" | "ULY2" | "ULH0" | "ULH2" | "UQY2" => "utvideo",
        "CFHD" => "cfhd",
        "APCH" | "APCN" | "APCS" | "APCO" | "AP4H" => "prores",
        "" | "DIB " | "RGB " | "RAW " | "I420" | "YV12" | "YUY2" | "UYVY" | "Y800" | "NV12" => "rawvideo",
        _ if fourcc.bytes().all(|b| b == 0) => "rawvideo",
        _ => return fourcc.trim().to_ascii_lowercase(),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("avi");

    #[test]
    fn fourccs_and_chunks() {
        assert_eq!(vfw_codec("XVID"), "mpeg4");
        assert_eq!(vfw_codec("h264"), "h264");
        assert_eq!(vfw_codec("\0\0\0\0"), "rawvideo");
        assert_eq!(vfw_codec("ABCD"), "abcd");
        let d = [b"strn".as_slice(), &[3, 0, 0, 0], b"abc\0"].concat();
        let list: Vec<_> = chunks(&d).collect();
        assert_eq!(list, [(*b"strn", &b"abc"[..])]);
        let s = StreamHeader { kind: *b"vids", scale: 1, rate: 25, length: 50, ..StreamHeader::default() };
        assert_eq!(s.seconds(), Some(2.0));
    }
}
