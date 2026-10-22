//! Flash Video (FLV): the header flags, the `onMetaData` script object
//! (AMF0: duration, size, frame rate, data rates, codec ids, encoder,
//! creation date, keyframe index), the first audio and video tags (codec,
//! rate, channels; AVC / HEVC decoder configuration and AAC
//! AudioSpecificConfig from their sequence headers, enhanced-RTMP FourCCs),
//! and the duration (metadata, else the last tag's time stamp).
//!
//! Specifications: Adobe Flash Video File Format Specification 10.1
//! (FLV, AMF0 data), Enhanced RTMP (v1) for HEVC / AV1 / VP9 in FLV.

use serde_json::{Map, Value, json};

use super::super::audio::{Stream, Tags, add_raw};
use super::codec;
use super::{Video, audio_map, finish, other_map};
use crate::plugin::mp4::{AudioConfig, aac_profile};
use crate::plugin::{Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for Flash Video.
pub struct Flv;

static META: ExtractorMeta = ExtractorMeta {
    id: "video.flv",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "flv",
        name: "Flash Video",
        family: "video",
        mimes: &["video/x-flv", "video/flv"],
        extensions: &["flv"],
        magic: &[Magic::prefix(b"FLV\x01")],
        parent: None,
    }],
};

/// Bytes walked from the start for the metadata and sequence headers.
const HEAD_SCAN: u64 = 4 << 20;
/// Largest script tag read.
const MAX_SCRIPT: u32 = 1 << 20;
/// Tag bytes read for codec headers.
const MAX_TAG_PREFIX: usize = 64 << 10;
const MAX_TAGS: usize = 2000;
/// AMF nesting and list limits.
const MAX_DEPTH: usize = 8;
const MAX_LIST: usize = 64;

impl Extractor for Flv {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // the tag walk, then the stream maps
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let h = src.read_vec(0, 9)?;
        let flags = h[4];
        let header = u64::from(u32::from_be_bytes([h[5], h[6], h[7], h[8]]));
        cx.format_set("version", h[3]);
        cx.format_set("has_audio", flags & 4 != 0);
        cx.format_set("has_video", flags & 1 != 0);
        let mut meta: Option<Map<String, Value>> = None;
        let (mut video, mut audio): (Option<Video>, Option<Stream>) = (None, None);
        let (mut video_cfg, mut audio_cfg) = (false, false);
        let (mut first_ts, mut tags_seen, mut encrypted) = (None, 0usize, false);
        let mut pos = header + 4;
        let end = len.min(HEAD_SCAN);
        while pos + 11 <= end && tags_seen < MAX_TAGS {
            let t = src.read_vec(pos, 11)?;
            let kind = t[0] & 0x1f;
            encrypted |= t[0] & 0x20 != 0;
            let size = (u32::from(t[1]) << 16) | (u32::from(t[2]) << 8) | u32::from(t[3]);
            let ts = (u32::from(t[7]) << 24) | (u32::from(t[4]) << 16) | (u32::from(t[5]) << 8) | u32::from(t[6]);
            let data_at = pos + 11;
            if data_at + u64::from(size) > len {
                break;
            }
            tags_seen += 1;
            match kind {
                18 if meta.is_none() && size <= MAX_SCRIPT => {
                    let d = src.read_vec(data_at, size as usize)?;
                    let mut at = 0;
                    if let Some(Value::String(name)) = amf(&d, &mut at, 0)
                        && name == "onMetaData"
                        && let Some(Value::Object(m)) = amf(&d, &mut at, 0)
                    {
                        meta = Some(m);
                    }
                }
                9 if size > 0 => {
                    first_ts.get_or_insert(ts);
                    if !video_cfg {
                        let d = src.read_vec(data_at, (size as usize).min(MAX_TAG_PREFIX))?;
                        let (v, cfg) = video_tag(&d);
                        if video.is_none() || cfg {
                            video = v.or(video);
                        }
                        video_cfg = cfg;
                    }
                }
                8 if size > 0 => {
                    first_ts.get_or_insert(ts);
                    if !audio_cfg {
                        let d = src.read_vec(data_at, (size as usize).min(MAX_TAG_PREFIX))?;
                        let (a, cfg) = audio_tag(&d);
                        if audio.is_none() || cfg {
                            audio = a.or(audio);
                        }
                        audio_cfg = cfg;
                    }
                }
                _ => {}
            }
            pos = data_at + u64::from(size) + 4;
            let wants_video = flags & 1 != 0 && !video_cfg;
            let wants_audio = flags & 4 != 0 && !audio_cfg;
            if meta.is_some() && !wants_video && !wants_audio {
                break;
            }
        }
        let num = |k: &str| meta.as_ref().and_then(|m| m.get(k)).and_then(Value::as_f64).filter(|v| v.is_finite());
        let mut tags = Tags::default();
        let mut maps = Vec::new();
        if video.is_some() || flags & 1 != 0 || num("videocodecid").is_some() {
            #[allow(clippy::cast_possible_truncation)] // a small codec id
            let id = num("videocodecid").map_or(-1, |c| c.round() as i64);
            let mut v = video.unwrap_or_else(|| Video::new(video_codec(id)));
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive sizes and rates
            {
                v.width = v.width.or(num("width").filter(|w| *w > 0.0).map(|w| w.round() as u32));
                v.height = v.height.or(num("height").filter(|h| *h > 0.0).map(|h| h.round() as u32));
                v.bitrate_bps = num("videodatarate").filter(|r| *r > 0.0).map(|r| (r * 1000.0).round() as u64);
            }
            v.fps = num("framerate").filter(|f| *f > 0.0).or(v.fps);
            v.encrypted = encrypted;
            maps.push(v.to_map());
        }
        if audio.is_some() || flags & 4 != 0 {
            let mut s = audio.unwrap_or_else(|| Stream::new("unknown"));
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive rates
            {
                s.bitrate_bps = num("audiodatarate").filter(|r| *r > 0.0).map(|r| (r * 1000.0).round() as u64);
                if let Some(r) = num("audiosamplerate").filter(|r| *r > 0.0) {
                    s.sample_rate_hz = s.sample_rate_hz.or(Some(r.round() as u32));
                }
            }
            maps.push(audio_map(&s));
        }
        if maps.is_empty() {
            maps.push(other_map("data", "script"));
        }
        // Duration: the metadata, else the time stamps of the first and last tags.
        let mut duration = num("duration").filter(|d| *d > 0.0);
        if duration.is_none()
            && let Some(first) = first_ts
            && let Some(last) = last_timestamp(src)?
        {
            duration = Some(f64::from(last.saturating_sub(first)) / 1000.0).filter(|d| *d > 0.0);
        }
        if let Some(m) = &meta {
            for (k, v) in m {
                let v = match (k.as_str(), v) {
                    ("keyframes", Value::Object(o)) => {
                        let n = o.get("times").and_then(Value::as_array).map_or(0, Vec::len);
                        json!({ "indexed": n })
                    }
                    _ => v.clone(),
                };
                add_raw(cx, "flv", k, v.clone());
                let text = v.as_str().unwrap_or_default();
                match k.as_str() {
                    "encoder" | "metadatacreator" => tags.set("encoder", text, "flv"),
                    "title" => tags.set("title", text, "flv"),
                    "artist" | "author" => tags.set("artist", text, "flv"),
                    "comment" | "description" => tags.set("comment", text, "flv"),
                    "copyright" => tags.set("copyright", text, "flv"),
                    "creationdate" | "creation_date" => {
                        if let Some((d, tz)) = crate::plugin::parse_date(text.trim()) {
                            cx.temporal().source("flv.onMetaData.creationdate").content_date(DateField::Created, d, tz);
                        }
                    }
                    _ => {}
                }
            }
            cx.format_set("metadata_keys", m.len());
        }
        if encrypted {
            cx.security().encrypted(true);
        }
        finish(cx, maps, duration, len);
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Flv);

/// The time stamp of the last tag, through the trailing previous-tag size.
fn last_timestamp(src: &mut dyn Source) -> Result<Option<u32>, ExtractError> {
    let len = src.len();
    if len < 15 {
        return Ok(None);
    }
    let p = src.read_vec(len - 4, 4)?;
    let prev = u64::from(u32::from_be_bytes([p[0], p[1], p[2], p[3]]));
    if prev < 11 || prev + 4 > len {
        return Ok(None);
    }
    let t = src.read_vec(len - 4 - prev, 11)?;
    if !matches!(t[0] & 0x1f, 8 | 9 | 18) {
        return Ok(None);
    }
    Ok(Some((u32::from(t[7]) << 24) | (u32::from(t[4]) << 16) | (u32::from(t[5]) << 8) | u32::from(t[6])))
}

fn video_codec(id: i64) -> &'static str {
    match id {
        2 => "flv1",
        3 => "flashsv",
        4 => "vp6f",
        5 => "vp6a",
        6 => "flashsv2",
        7 => "h264",
        12 => "hevc",
        13 => "av1",
        _ => "unknown",
    }
}

/// A video tag: the codec, and its configuration when this is a sequence
/// header (`true` once the configuration is known).
fn video_tag(d: &[u8]) -> (Option<Video>, bool) {
    let Some(&b) = d.first() else { return (None, false) };
    if b & 0x80 != 0 {
        // Enhanced RTMP: packet type, then a FourCC.
        let Some(fourcc) = d.get(1..5) else { return (None, false) };
        let codec = match fourcc {
            b"hvc1" => "hevc",
            b"av01" => "av1",
            b"vp09" => "vp9",
            b"avc1" => "h264",
            _ => "unknown",
        };
        let mut v = Video::new(codec);
        v.codec_tag = Some(String::from_utf8_lossy(fourcc).into_owned());
        // Packet type 0: the sequence start (decoder configuration).
        if b.trailing_zeros() >= 4 {
            let cfg = d.get(5..).unwrap_or_default();
            let parsed = match codec {
                "hevc" => codec::hvcc(cfg),
                "av1" => codec::av1c(cfg),
                "vp9" => codec::vpcc("vp9", cfg),
                "h264" => codec::avcc(cfg),
                _ => None,
            };
            if let Some(c) = parsed {
                v.absorb(c);
                return (Some(v), true);
            }
        }
        return (Some(v), false);
    }
    let id = i64::from(b & 0x0f);
    let mut v = Video::new(video_codec(id));
    if matches!(id, 7 | 12) && d.get(1) == Some(&0) {
        let cfg = d.get(5..).unwrap_or_default();
        let parsed = if id == 7 { codec::avcc(cfg) } else { codec::hvcc(cfg) };
        if let Some(c) = parsed {
            v.absorb(c);
            return (Some(v), true);
        }
    }
    // Sorenson H.263 and VP6 have no separate configuration.
    (Some(v), !matches!(id, 7 | 12))
}

/// An audio tag: the codec, rate and channels (from the AAC configuration
/// when this is its sequence header).
fn audio_tag(d: &[u8]) -> (Option<Stream>, bool) {
    let Some(&b) = d.first() else { return (None, false) };
    let format = b >> 4;
    let codec = match format {
        0 | 3 => "pcm",
        1 => "adpcm_swf",
        2 | 14 => "mp3",
        4..=6 => "nellymoser",
        7 => "pcm_alaw",
        8 => "pcm_mulaw",
        10 => "aac",
        11 => "speex",
        _ => "unknown",
    };
    let mut s = Stream::new(codec);
    s.sample_rate_hz = Some(match (format, (b >> 2) & 3) {
        (5 | 14, _) => 8000,
        (4 | 11, _) => 16000,
        (_, 0) => 5512,
        (_, 1) => 11025,
        (_, 2) => 22050,
        _ => 44100,
    });
    s.channels = Some(if b & 1 == 1 { 2 } else { 1 });
    if matches!(format, 0 | 3) {
        s.bits_per_sample = Some(if b & 2 != 0 { 16 } else { 8 });
    }
    if format == 10 {
        if d.get(1) == Some(&0)
            && let Some(c) = d.get(2..).and_then(AudioConfig::parse)
        {
            s.profile = Some(aac_profile(c.object).into());
            s.sample_rate_hz = c.rate.or(s.sample_rate_hz);
            s.channels = c.channels.or(s.channels);
            return (Some(s), true);
        }
        return (Some(s), false);
    }
    (Some(s), true)
}

/// An AMF0 value.
fn amf(d: &[u8], at: &mut usize, depth: usize) -> Option<Value> {
    let kind = *d.get(*at)?;
    *at += 1;
    let mut take = |n: usize| -> Option<&[u8]> {
        let s = d.get(*at..at.checked_add(n)?)?;
        *at += n;
        Some(s)
    };
    match kind {
        0 => {
            let f = f64::from_be_bytes(take(8)?.try_into().ok()?);
            Some(if f.is_finite() { json!(f) } else { Value::Null })
        }
        1 => Some(json!(take(1)?[0] != 0)),
        2 => {
            let n = take(2)?;
            let n = usize::from(u16::from_be_bytes([n[0], n[1]]));
            Some(json!(String::from_utf8_lossy(take(n)?)))
        }
        12 => {
            let n = take(4)?;
            let n = u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as usize;
            Some(json!(crate::plugin::truncate_chars(&String::from_utf8_lossy(take(n)?), 2000)))
        }
        3 | 8 => {
            if kind == 8 {
                take(4)?; // approximate count
            }
            if depth >= MAX_DEPTH {
                return None;
            }
            let mut m = Map::new();
            loop {
                let n = d.get(*at..*at + 2)?;
                let n = usize::from(u16::from_be_bytes([n[0], n[1]]));
                *at += 2;
                if n == 0 && d.get(*at) == Some(&9) {
                    *at += 1;
                    break;
                }
                let key = String::from_utf8_lossy(d.get(*at..*at + n)?).into_owned();
                *at += n;
                let v = amf(d, at, depth + 1)?;
                if m.len() < 256 {
                    m.insert(key, v);
                }
            }
            Some(Value::Object(m))
        }
        10 => {
            let n = take(4)?;
            let n = u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as usize;
            if depth >= MAX_DEPTH {
                return None;
            }
            let mut list = Vec::new();
            for _ in 0..n {
                let v = amf(d, at, depth + 1)?;
                if list.len() < MAX_LIST {
                    list.push(v);
                }
            }
            Some(Value::Array(list))
        }
        11 => {
            let ms = f64::from_be_bytes(take(8)?.try_into().ok()?);
            take(2)?;
            #[allow(clippy::cast_possible_truncation)] // milliseconds since 1970
            let t = jiff::Timestamp::from_millisecond(ms as i64).ok()?;
            Some(json!(t.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()))
        }
        5 | 6 => Some(Value::Null),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("flv");

    #[test]
    fn amf_values_and_tags() {
        let mut d = vec![2, 0, 10];
        d.extend_from_slice(b"onMetaData");
        d.extend_from_slice(&[8, 0, 0, 0, 2, 0, 8]);
        d.extend_from_slice(b"duration");
        d.push(0);
        d.extend_from_slice(&2.5f64.to_be_bytes());
        d.extend_from_slice(&[0, 6]);
        d.extend_from_slice(b"stereo");
        d.extend_from_slice(&[1, 1, 0, 0, 9]);
        let mut at = 0;
        assert_eq!(amf(&d, &mut at, 0), Some(json!("onMetaData")));
        assert_eq!(amf(&d, &mut at, 0), Some(json!({ "duration": 2.5, "stereo": true })));
        let (a, done) = audio_tag(&[0xaf, 0x00, 0x12, 0x10]);
        let a = a.unwrap();
        assert!(done);
        assert_eq!((a.codec.as_str(), a.sample_rate_hz, a.channels), ("aac", Some(44100), Some(2)));
        let (v, done) = video_tag(&[0x22]);
        assert_eq!((v.unwrap().codec.as_str(), done), ("flv1", true));
    }
}
