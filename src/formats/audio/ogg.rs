//! Ogg: Vorbis, Opus, Speex and FLAC streams (identification and comment
//! headers, reassembled across pages), Theora video (Ogg video, `.ogv`),
//! the logical streams of a multiplexed file, and the duration from the
//! last page's granule position.
//!
//! Specifications: RFC 3533 (Ogg), Vorbis I §4.2, RFC 7845 (Ogg Opus),
//! the Speex manual (Ogg mapping), the FLAC-in-Ogg mapping (RFC 9639 §10.1).

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::super::video::{self, codec as video_codec};
use super::{Stream, Tags, flac, vorbis};
use crate::plugin::{ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for Ogg audio.
pub struct Ogg;

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.ogg",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "ogg",
            name: "Ogg audio",
            family: "audio",
            mimes: &["audio/ogg", "application/ogg"],
            extensions: &["ogg", "oga", "ogx"],
            magic: &[Magic::prefix(b"OggS")],
            parent: None,
        },
        FormatSpec {
            id: "opus",
            name: "Opus audio",
            family: "audio",
            mimes: &["audio/opus", "audio/ogg"],
            extensions: &["opus"],
            magic: &[Magic::at(28, b"OpusHead")],
            parent: Some("ogg"),
        },
        FormatSpec {
            id: "ogv",
            name: "Ogg video",
            family: "video",
            mimes: &["video/ogg"],
            extensions: &["ogv", "ogm"],
            magic: &[Magic::at(28, b"\x80theora")],
            parent: Some("ogg"),
        },
        FormatSpec {
            id: "spx",
            name: "Speex audio",
            family: "audio",
            mimes: &["audio/speex", "audio/ogg"],
            extensions: &["spx"],
            magic: &[Magic::at(28, b"Speex   ")],
            parent: Some("ogg"),
        },
    ],
};

/// Pages read for the headers.
const MAX_HEADER_PAGES: usize = 512;
/// Largest header packet kept (comments with cover art).
const MAX_PACKET: usize = 16 << 20;
/// Logical streams tracked.
const MAX_STREAMS: usize = 32;
/// Bytes searched backwards for the last page.
const TAIL_SEARCH: u64 = 256 << 10;

#[derive(Default)]
struct Logical {
    /// Completed packets (the first three are the headers).
    packets: Vec<Vec<u8>>,
    partial: Vec<u8>,
    overflow: bool,
    codec: &'static str,
}

impl Extractor for Ogg {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut streams: BTreeMap<u32, Logical> = BTreeMap::new();
        let mut order = Vec::new();
        let mut pos = 0u64;
        for _ in 0..MAX_HEADER_PAGES {
            let Some(page) = page_at(src, pos) else { break };
            pos = page.end;
            let first_page = page.flags & 2 != 0;
            if first_page && streams.len() < MAX_STREAMS && !streams.contains_key(&page.serial) {
                order.push(page.serial);
                streams.insert(page.serial, Logical::default());
            }
            let Some(s) = streams.get_mut(&page.serial) else { continue };
            if s.packets.len() >= 3 {
                if streams.values().all(|s| s.packets.len() >= 3) {
                    break;
                }
                continue;
            }
            let body = src.read_vec(page.body, page.body_len)?;
            let mut at = 0usize;
            for &lace in &page.lacing {
                let n = usize::from(lace);
                let seg = body.get(at..at + n).unwrap_or_default();
                at += n;
                if s.partial.len() + seg.len() <= MAX_PACKET {
                    s.partial.extend_from_slice(seg);
                } else {
                    s.overflow = true;
                }
                if lace < 255 {
                    s.packets.push(std::mem::take(&mut s.partial));
                    if s.packets.len() >= 3 {
                        break;
                    }
                }
            }
            if streams.values().all(|s| s.packets.len() >= 3) {
                break;
            }
        }
        if order.is_empty() {
            return Err(ExtractError::malformed("no Ogg page"));
        }
        let last = last_granules(src, cx)?;
        let mut tags = Tags::default();
        let mut list = Vec::new();
        for s in streams.values_mut() {
            s.codec = codec(s.packets.first().map_or(&[][..], Vec::as_slice));
        }
        if cx.format_id() != "ogv" && streams.values().any(|s| s.codec == "theora") {
            cx.redirect("ogv");
            return Ok(());
        }
        // Theora first: its length counts towards the file's duration.
        let mut video_s = None;
        for serial in &order {
            let s = &streams[serial];
            if s.codec == "theora"
                && video_s.is_none()
                && let Some(d) = theora(s, last.get(serial).copied(), cx, &mut tags)
            {
                video_s = Some(d);
            }
        }
        let mut main_done = false;
        for serial in &order {
            let s = streams.get_mut(serial).expect("tracked");
            list.push(json!({ "serial": serial, "codec": s.codec }));
            if main_done || !matches!(s.codec, "vorbis" | "opus" | "speex" | "flac") {
                continue;
            }
            main_done = true;
            if s.overflow {
                cx.warn("header packet larger than 16 MiB not read");
            }
            audio_stream(s, last.get(serial).copied(), video_s, src.len(), cx, &mut tags);
        }
        cx.format_set("logical_streams", Value::Array(list));
        if !main_done && video_s.is_none() {
            cx.warn("no audio stream recognised");
        } else if !main_done && let Some(d) = video_s {
            video::finish(cx, Vec::new(), Some(d), src.len());
        }
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Ogg);

struct Page {
    flags: u8,
    serial: u32,
    lacing: Vec<u8>,
    body: u64,
    body_len: usize,
    end: u64,
}

fn page_at(src: &mut dyn Source, pos: u64) -> Option<Page> {
    let Ok(h) = src.read_vec(pos, 27) else { return None };
    if &h[..4] != b"OggS" || h[4] != 0 {
        return None;
    }
    let serial = u32::from_le_bytes([h[14], h[15], h[16], h[17]]);
    let n = usize::from(h[26]);
    let Ok(lacing) = src.read_vec(pos + 27, n) else { return None };
    let body_len: usize = lacing.iter().map(|&l| usize::from(l)).sum();
    let body = pos + 27 + n as u64;
    if body + body_len as u64 > src.len() {
        return None;
    }
    Some(Page { flags: h[5], serial, lacing, body, body_len, end: body + body_len as u64 })
}

/// The last granule position of each logical stream, from the pages near
/// the end of the file.
fn last_granules(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<BTreeMap<u32, i64>, ExtractError> {
    let len = src.len();
    let start = len.saturating_sub(TAIL_SEARCH);
    let tail = src.read_vec(start, usize::try_from(len - start).unwrap_or(0))?;
    cx.checkpoint()?;
    let mut out = BTreeMap::new();
    let mut i = 0;
    while let Some(p) = tail.get(i..).and_then(|t| t.windows(4).position(|w| w == b"OggS")) {
        let at = i + p;
        if let Some(h) = tail.get(at..at + 27)
            && h[4] == 0
        {
            let granule = i64::from_le_bytes(h[6..14].try_into().unwrap_or_default());
            let serial = u32::from_le_bytes([h[14], h[15], h[16], h[17]]);
            if granule >= 0 {
                out.insert(serial, granule);
            }
        }
        i = at + 4;
    }
    Ok(out)
}

fn codec(first: &[u8]) -> &'static str {
    if first.starts_with(b"\x01vorbis") {
        "vorbis"
    } else if first.starts_with(b"OpusHead") {
        "opus"
    } else if first.starts_with(b"Speex   ") {
        "speex"
    } else if first.starts_with(b"\x7fFLAC") {
        "flac"
    } else if first.starts_with(b"\x80theora") {
        "theora"
    } else if first.starts_with(b"\x80daala") {
        "daala"
    } else if first.starts_with(b"fishead") {
        "skeleton"
    } else if first.starts_with(b"\x01video") {
        "ogm_video"
    } else if first.starts_with(b"\x01audio") {
        "ogm_audio"
    } else if first.starts_with(b"\x01text") {
        "ogm_text"
    } else if first.starts_with(b"CELT    ") {
        "celt"
    } else if first.starts_with(b"\x80kate") {
        "kate"
    } else if first.starts_with(b"BBCD") {
        "dirac"
    } else {
        "unknown"
    }
}

/// A Theora stream: its map (written now) and its duration.
fn theora(s: &Logical, last: Option<i64>, cx: &mut Context<'_>, tags: &mut Tags) -> Option<f64> {
    let (mut v, shift, one_based) = video_codec::theora(s.packets.first()?)?;
    let mut duration = None;
    if let (Some(g), Some(fps)) = (last.and_then(|g| u64::try_from(g).ok()), v.fps)
        && shift < 32
    {
        let frames = (g >> shift) + (g & ((1 << shift) - 1)) + u64::from(!one_based);
        v.frames = Some(frames);
        duration = Some(frames as f64 / fps).filter(|d| *d > 0.0);
    }
    if let Some(c) = s.packets.get(1).and_then(|c| c.strip_prefix(b"\x81theora")) {
        vorbis::comments(c, cx, tags);
    }
    video::finish(cx, vec![v.to_map()], None, 0);
    duration
}

#[allow(clippy::too_many_lines)] // one arm per codec
fn audio_stream(
    s: &Logical,
    last: Option<i64>,
    video_s: Option<f64>,
    file_len: u64,
    cx: &mut Context<'_>,
    tags: &mut Tags,
) {
    let id = s.packets.first().map_or(&[][..], Vec::as_slice);
    let comments = s.packets.get(1).map_or(&[][..], Vec::as_slice);
    let mut stream = Stream::new(s.codec);
    let mut r = ByteReader::new(id);
    let mut granule_rate = None;
    let mut pre_skip = 0u64;
    match s.codec {
        "vorbis" => {
            if r.advance(7).is_ok()
                && let (Ok(version), Ok(ch), Ok(rate), Ok(max), Ok(nominal), Ok(min)) =
                    (r.le_u32(), r.u8(), r.le_u32(), r.le_i32(), r.le_i32(), r.le_i32())
            {
                stream.channels = Some(u16::from(ch));
                stream.sample_rate_hz = Some(rate);
                granule_rate = Some(rate);
                if nominal > 0 {
                    stream.bitrate_bps = u64::try_from(nominal).ok();
                }
                stream.vbr = Some(!(max == nominal && min == nominal && nominal > 0));
                cx.format_set("vorbis_version", version);
            }
            if let Some(c) = comments.strip_prefix(b"\x03vorbis") {
                vorbis::comments(c, cx, tags);
            }
        }
        "opus" => {
            if r.advance(8).is_ok()
                && let (Ok(version), Ok(ch), Ok(skip), Ok(rate), Ok(gain), Ok(family)) =
                    (r.u8(), r.u8(), r.le_u16(), r.le_u32(), r.le_i16(), r.u8())
            {
                stream.channels = Some(u16::from(ch));
                // Opus always decodes at 48 kHz; the input rate is informational.
                stream.sample_rate_hz = Some(48_000);
                granule_rate = Some(48_000);
                pre_skip = u64::from(skip);
                cx.format_set(
                    "opus",
                    json!({
                        "version": version,
                        "input_sample_rate_hz": rate,
                        "pre_skip_samples": skip,
                        "output_gain_db": f64::from(gain) / 256.0,
                        "channel_mapping_family": family,
                    }),
                );
            }
            if let Some(c) = comments.strip_prefix(b"OpusTags") {
                vorbis::comments(c, cx, tags);
            }
        }
        "speex" => {
            if r.advance(8).is_ok()
                && let Ok(version) = r.bytes(20)
                && let (Ok(_vid), Ok(_hsize), Ok(rate), Ok(mode), Ok(_mbv), Ok(ch), Ok(bitrate), Ok(frame), Ok(vbr)) = (
                    r.le_i32(),
                    r.le_i32(),
                    r.le_u32(),
                    r.le_i32(),
                    r.le_i32(),
                    r.le_i32(),
                    r.le_i32(),
                    r.le_i32(),
                    r.le_i32(),
                )
            {
                stream.channels = u16::try_from(ch).ok();
                stream.sample_rate_hz = Some(rate);
                granule_rate = Some(rate);
                stream.bitrate_bps = u64::try_from(bitrate).ok().filter(|b| *b > 0);
                stream.vbr = Some(vbr != 0);
                stream.profile = Some(
                    match mode {
                        0 => "narrowband",
                        1 => "wideband",
                        2 => "ultra-wideband",
                        _ => "unknown",
                    }
                    .into(),
                );
                cx.format_set(
                    "speex",
                    json!({
                        "version": String::from_utf8_lossy(version).trim_end_matches('\0'),
                        "frame_samples": frame,
                    }),
                );
            }
            vorbis::comments(comments, cx, tags);
        }
        "flac" => {
            // 0x7F "FLAC" major minor headers(2) "fLaC" STREAMINFO block.
            if let Some(info) = id.get(13 + 4..)
                && let Some((st, extra)) = flac::streaminfo(info)
            {
                granule_rate = st.sample_rate_hz;
                stream = st;
                cx.format_set("streaminfo", extra);
            }
            if comments.first().map(|b| b & 0x7f) == Some(4) {
                vorbis::comments(comments.get(4..).unwrap_or_default(), cx, tags);
            }
        }
        _ => {}
    }
    let duration = match (last, granule_rate) {
        (Some(g), Some(rate)) if rate > 0 && g > 0 => {
            let samples = u64::try_from(g).unwrap_or(0).saturating_sub(pre_skip);
            stream.samples = Some(samples);
            Some(samples as f64 / f64::from(rate))
        }
        _ => None,
    };
    let duration = match (duration, video_s) {
        (Some(a), Some(v)) => Some(a.max(v)),
        (a, v) => a.or(v),
    };
    stream.report(cx, duration, file_len);
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("ogg", "opus", "spx", "ogv");
}
