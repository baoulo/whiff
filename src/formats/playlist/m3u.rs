//! M3U playlists (plain and extended, with IPTV attributes) and HTTP Live
//! Streaming playlists. HLS master playlists: variants (bandwidth,
//! resolution, codecs, frame rate, video range), renditions (type,
//! language, name), I-frame variants, session data and keys. HLS media
//! playlists: segments, target duration, sequence, type, end of list,
//! discontinuities, byte ranges, fMP4 init sections, encryption, program
//! date-times, ad markers, low-latency parts.
//!
//! Specifications: RFC 8216 and draft-pantos-hls-rfc8216bis; the extended
//! M3U directives as Winamp and IPTV players write them.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use super::{Entry, Playlist, artist_title, drm_system, round};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, parse_date, truncate_chars,
};

/// Extractor for M3U and HLS playlists.
pub struct M3u;

static META: ExtractorMeta = ExtractorMeta {
    id: "playlist.m3u",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "m3u",
            name: "M3U playlist",
            family: "audio.playlist",
            mimes: &["audio/x-mpegurl"],
            extensions: &["m3u", "m3u8"],
            // Not `#EXTM3U` magic: a plain M3U is a list of paths.
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "hls",
            name: "HLS playlist",
            family: "audio.playlist",
            mimes: &["application/vnd.apple.mpegurl"],
            extensions: &["m3u8"],
            magic: &[],
            parent: Some("m3u"),
        },
    ],
};

/// Variants and renditions listed.
const MAX_LISTED: usize = 32;

impl Extractor for M3u {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let text = super::super::subtitle::head_text(probe.head);
        let t = text.trim_start();
        if !t.starts_with("#EXTM3U") {
            // A plain list of paths or URLs, named as a playlist.
            let named =
                probe.extension.is_some_and(|e| e.eq_ignore_ascii_case("m3u") || e.eq_ignore_ascii_case("m3u8"));
            let lines = t.lines().filter(|l| !l.trim().is_empty()).take(16);
            let plain = lines.clone().count() > 0 && lines.into_iter().all(|l| !l.contains('\0') && l.len() < 4096);
            return (named && plain).then_some(Sniff { format: "m3u", confidence: 0.5 });
        }
        let hls = t.lines().take(64).any(|l| l.trim_start().starts_with("#EXT-X-"));
        Some(Sniff { format: if hls { "hls" } else { "m3u" }, confidence: if hls { 0.95 } else { 0.9 } })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.checkpoint()?;
        let p = if cx.format_id() == "hls" { hls(&text) } else { m3u(&text) };
        p.report(cx);
        Ok(())
    }
}

crate::register_extractor!(M3u);

/// An HLS attribute list: `KEY=value,KEY="quoted, value"`.
pub(crate) fn attributes(s: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut rest = s.trim();
    while !rest.is_empty() && out.len() < 64 {
        let Some((key, tail)) = rest.split_once('=') else { break };
        let (value, tail) = if let Some(q) = tail.strip_prefix('"') {
            let end = q.find('"').unwrap_or(q.len());
            (&q[..end], q.get(end + 1..).unwrap_or(""))
        } else {
            let end = tail.find(',').unwrap_or(tail.len());
            (&tail[..end], &tail[end..])
        };
        out.insert(key.trim().to_ascii_uppercase(), value.to_string());
        rest = tail.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
    }
    out
}

/// `#EXTINF:123.4 tvg-id="x" group-title="News",Artist - Title`: the
/// duration, the attributes and the title.
fn extinf(v: &str) -> (Option<f64>, BTreeMap<String, String>, String) {
    // The title follows the first comma outside quotes.
    let mut quoted = false;
    let mut split = v.len();
    for (i, c) in v.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                split = i;
                break;
            }
            _ => {}
        }
    }
    let (head, title) = (&v[..split], v.get(split + 1..).unwrap_or(""));
    let (dur, attrs) = head.split_once(char::is_whitespace).unwrap_or((head, ""));
    let duration = dur.trim().parse::<f64>().ok().filter(|d| *d >= 0.0);
    let mut a = BTreeMap::new();
    let mut rest = attrs.trim();
    while let Some((k, tail)) = rest.split_once("=\"") {
        let Some(end) = tail.find('"') else { break };
        a.insert(k.trim().to_ascii_lowercase(), tail[..end].to_string());
        rest = tail[end + 1..].trim_start();
    }
    (duration, a, title.trim().to_string())
}

fn m3u(text: &str) -> Playlist {
    let mut p = Playlist::default();
    let mut pending = Entry::default();
    let (mut extended, mut iptv, mut logos) = (false, false, 0u64);
    let mut genres = BTreeSet::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Some(d) = line.strip_prefix('#') {
            // `#EXTM3U url-tvg="…"`: the header takes attributes, not a value.
            let (tag, v) = match d.get(..6) {
                Some(h) if h.eq_ignore_ascii_case("EXTM3U") => (h, &d[6..]),
                _ => d.split_once(':').unwrap_or((d, "")),
            };
            match tag.to_ascii_uppercase().as_str() {
                "EXTM3U" => {
                    extended = true;
                    let a = extinf(&format!("-1 {v}")).1;
                    if let Some(epg) = a.get("url-tvg").or_else(|| a.get("x-tvg-url")) {
                        p.set("epg_url_host", super::Location::of(epg).host);
                    }
                }
                "EXTINF" => {
                    let (duration, a, title) = extinf(v);
                    let (artist, title) = artist_title(&title);
                    pending.duration = duration;
                    pending.artist = artist;
                    pending.title = a.get("tvg-name").cloned().filter(|_| title.is_none()).or(title);
                    pending.group = a.get("group-title").cloned();
                    if a.keys().any(|k| k.starts_with("tvg-")) {
                        iptv = true;
                    }
                    if a.contains_key("tvg-logo") {
                        logos += 1;
                    }
                }
                "EXTGRP" => pending.group = Some(v.trim().to_string()),
                "EXTALB" => pending.album = Some(v.trim().to_string()),
                "EXTART" => pending.artist = Some(v.trim().to_string()),
                "EXTGENRE" => {
                    genres.insert(truncate_chars(v.trim(), 60));
                }
                "PLAYLIST" => p.title = Some(v.trim().to_string()),
                _ => {}
            }
            continue;
        }
        let mut e = std::mem::take(&mut pending);
        e.location = Some(line.to_string());
        p.push(e);
    }
    p.set("extended", extended);
    if iptv {
        p.set("iptv", true);
        if logos > 0 {
            p.set("channel_logos", logos);
        }
    }
    p.genres = genres.into_iter().filter(|g| !g.is_empty()).take(10).collect();
    p
}

#[allow(clippy::too_many_lines)] // one pass over the tags
fn hls(text: &str) -> Playlist {
    let mut p = Playlist { unlisted: true, ..Playlist::default() };
    let mut fields: Map<String, Value> = Map::new();
    let (mut variants, mut iframes, mut renditions) = (Vec::new(), 0u64, Vec::new());
    let mut pending_variant: Option<Map<String, Value>> = None;
    let mut pending = Entry::default();
    let (mut endlist, mut discontinuities, mut byteranges, mut gaps, mut parts, mut ads, mut dateranges) =
        (false, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut maps = 0u64;
    let mut methods: BTreeSet<String> = BTreeSet::new();
    let mut drm: BTreeSet<&'static str> = BTreeSet::new();
    let mut session_data: Vec<String> = Vec::new();
    let (mut first_pdt, mut last_pdt) = (None::<String>, None::<String>);
    let mut codecs: BTreeSet<String> = BTreeSet::new();
    let mut encrypted = false;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some(directive) = line.strip_prefix('#') else {
            if let Some(variant) = pending_variant.take() {
                variants.push(Value::Object(variant));
                p.push(Entry { location: Some(line.to_string()), ..Entry::default() });
            } else {
                let mut entry = std::mem::take(&mut pending);
                entry.location = Some(line.to_string());
                p.push(entry);
            }
            continue;
        };
        let (tag, v) = directive.split_once(':').unwrap_or((directive, ""));
        match tag {
            "EXT-X-VERSION" => {
                fields.insert("version".into(), json!(v.trim().parse::<u32>().ok()));
            }
            "EXT-X-TARGETDURATION" => {
                fields.insert("target_duration_s".into(), json!(v.trim().parse::<f64>().ok()));
            }
            "EXT-X-MEDIA-SEQUENCE" => {
                fields.insert("media_sequence".into(), json!(v.trim().parse::<u64>().ok()));
            }
            "EXT-X-PLAYLIST-TYPE" => {
                fields.insert("playlist_type".into(), json!(v.trim().to_ascii_lowercase()));
            }
            "EXT-X-ENDLIST" => endlist = true,
            "EXT-X-I-FRAMES-ONLY" => {
                fields.insert("i_frames_only".into(), json!(true));
            }
            "EXT-X-INDEPENDENT-SEGMENTS" => {
                fields.insert("independent_segments".into(), json!(true));
            }
            "EXTINF" => {
                let (duration, _, title) = extinf(v);
                pending.duration = duration;
                pending.title = (!title.is_empty()).then_some(title);
            }
            "EXT-X-BYTERANGE" => byteranges += 1,
            "EXT-X-DISCONTINUITY" => discontinuities += 1,
            "EXT-X-GAP" => gaps += 1,
            "EXT-X-PART" => parts += 1,
            "EXT-X-MAP" => maps += 1,
            "EXT-X-KEY" | "EXT-X-SESSION-KEY" => {
                encrypted |= key(&attributes(v), &mut methods, &mut drm);
            }
            "EXT-X-PROGRAM-DATE-TIME" => {
                if let Some((d, _)) = parse_date(v) {
                    first_pdt.get_or_insert_with(|| d.clone());
                    last_pdt = Some(d);
                }
            }
            "EXT-X-DATERANGE" => {
                dateranges += 1;
                if v.contains("SCTE35") {
                    ads += 1;
                }
            }
            "EXT-X-CUE-OUT" | "EXT-OATCLS-SCTE35" | "EXT-X-SCTE35" => ads += 1,
            "EXT-X-SERVER-CONTROL" => {
                fields.insert("low_latency".into(), json!(true));
            }
            "EXT-X-STREAM-INF" => {
                let attrs = attributes(v);
                pending_variant = Some(variant(&attrs, &mut codecs));
            }
            "EXT-X-I-FRAME-STREAM-INF" => iframes += 1,
            "EXT-X-MEDIA" => {
                let attrs = attributes(v);
                if renditions.len() < MAX_LISTED {
                    let mut rendition = Map::new();
                    for (k, out) in [
                        ("TYPE", "type"),
                        ("GROUP-ID", "group"),
                        ("LANGUAGE", "language"),
                        ("NAME", "name"),
                        ("CHANNELS", "channels"),
                        ("INSTREAM-ID", "instream_id"),
                    ] {
                        if let Some(x) = attrs.get(k) {
                            let x = if k == "TYPE" { x.to_ascii_lowercase() } else { truncate_chars(x, 100) };
                            rendition.insert(out.into(), json!(x));
                        }
                    }
                    for (k, out) in [("DEFAULT", "default"), ("FORCED", "forced")] {
                        if attrs.get(k).is_some_and(|x| x.eq_ignore_ascii_case("YES")) {
                            rendition.insert(out.into(), json!(true));
                        }
                    }
                    renditions.push(Value::Object(rendition));
                }
            }
            "EXT-X-SESSION-DATA" => {
                if let Some(id) = attributes(v).get("DATA-ID")
                    && session_data.len() < MAX_LISTED
                {
                    session_data.push(truncate_chars(id, 100));
                }
            }
            "EXT-X-CONTENT-STEERING" => {
                fields.insert("content_steering".into(), json!(true));
            }
            _ => {}
        }
    }
    let master = !variants.is_empty() || iframes > 0 || !renditions.is_empty();
    p.set("kind", if master { "master" } else { "media" });
    for (k, v) in fields {
        p.set(&k, v);
    }
    if master {
        p.set("variants", variants.len());
        p.set("variant_list", Value::Array(variants.into_iter().take(MAX_LISTED).collect()));
        if iframes > 0 {
            p.set("i_frame_variants", iframes);
        }
        p.set("renditions", Value::Array(renditions));
        p.set("codecs", codecs.into_iter().collect::<Vec<_>>());
        p.set("session_data", session_data);
    } else {
        p.set("segments", p.entries.len());
        p.set("live", !endlist && p.format.get("playlist_type").is_none_or(|t| t != "vod"));
        let ext: BTreeSet<String> = p
            .entries
            .iter()
            .filter_map(|e| e.location.as_deref())
            .filter_map(|l| super::Location::of(l).extension)
            .collect();
        let kind = if maps > 0 || ext.contains("m4s") || ext.contains("mp4") {
            "fmp4"
        } else if ext.contains("ts") {
            "mpeg_ts"
        } else if ext.contains("vtt") || ext.contains("webvtt") {
            "webvtt"
        } else if ext.iter().any(|e| matches!(e.as_str(), "aac" | "ac3" | "ec3" | "mp3")) {
            "packed_audio"
        } else {
            "unknown"
        };
        p.set("segment_format", kind);
        p.sum_is_length = true;
        // Segment titles are rarely set; they are not track titles.
        if let Some(max) = p.entries.iter().filter_map(|e| e.duration).reduce(f64::max) {
            p.set("longest_segment_s", round(max));
        }
    }
    for (k, v) in [
        ("discontinuities", discontinuities),
        ("byte_ranges", byteranges),
        ("gaps", gaps),
        ("parts", parts),
        ("init_sections", maps),
        ("ad_markers", ads),
        ("date_ranges", dateranges),
    ] {
        if v > 0 {
            p.set(k, v);
        }
    }
    if encrypted {
        p.encrypted = true;
        p.set("encryption", methods.into_iter().map(|m| m.to_ascii_lowercase()).collect::<Vec<_>>());
        p.set("drm", drm.into_iter().collect::<Vec<_>>());
    }
    if let (Some(a), Some(b)) = (first_pdt, last_pdt) {
        p.set("program_date_time_range", json!([a, b]));
    }
    p
}

/// Note an `EXT-X-KEY`: whether it encrypts (a method other than `NONE`).
fn key(a: &BTreeMap<String, String>, methods: &mut BTreeSet<String>, drm: &mut BTreeSet<&'static str>) -> bool {
    let m = a.get("METHOD").map(|m| m.to_ascii_uppercase()).unwrap_or_default();
    if m.is_empty() || m == "NONE" {
        return false;
    }
    methods.insert(m);
    if let Some(d) = a.get("KEYFORMAT").and_then(|k| drm_system(k)) {
        drm.insert(d);
    }
    true
}

/// One `EXT-X-STREAM-INF` variant.
fn variant(a: &BTreeMap<String, String>, codecs: &mut BTreeSet<String>) -> Map<String, Value> {
    let mut m = Map::new();
    for (k, out) in [("BANDWIDTH", "bandwidth_bps"), ("AVERAGE-BANDWIDTH", "average_bandwidth_bps")] {
        if let Some(v) = a.get(k).and_then(|v| v.trim().parse::<u64>().ok()) {
            m.insert(out.into(), json!(v));
        }
    }
    if let Some(r) = a.get("RESOLUTION") {
        m.insert("resolution".into(), json!(r.to_ascii_lowercase()));
    }
    if let Some(c) = a.get("CODECS") {
        m.insert("codecs".into(), json!(c));
        for c in c.split(',') {
            let c = c.trim();
            if !c.is_empty() && codecs.len() < MAX_LISTED {
                codecs.insert(c.to_string());
            }
        }
    }
    if let Some(r) = a.get("FRAME-RATE").and_then(|v| v.parse::<f64>().ok()) {
        m.insert("frame_rate".into(), json!(r));
    }
    for (k, out) in [
        ("VIDEO-RANGE", "video_range"),
        ("HDCP-LEVEL", "hdcp_level"),
        ("AUDIO", "audio_group"),
        ("SUBTITLES", "subtitles_group"),
    ] {
        if let Some(v) = a.get(k) {
            m.insert(out.into(), json!(truncate_chars(v, 60)));
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("m3u", "hls");

    #[test]
    fn attribute_lists() {
        let a = attributes("BANDWIDTH=1280000,CODECS=\"avc1.4d401f,mp4a.40.2\",RESOLUTION=640x360");
        assert_eq!(a["CODECS"], "avc1.4d401f,mp4a.40.2");
        assert_eq!(a["RESOLUTION"], "640x360");
        let (d, a, t) = extinf("-1 tvg-id=\"n1\" group-title=\"News, Local\",Harbour TV");
        assert_eq!((d, a["group-title"].as_str(), t.as_str()), (None, "News, Local", "Harbour TV"));
        assert_eq!(extinf("12.5,Band - Song").0, Some(12.5));
    }

    #[test]
    fn playlists() {
        let p = m3u(
            "#EXTM3U\n#PLAYLIST:Mix\n#EXTINF:200,Band - Song\nmusic/01.mp3\n#EXTINF:-1,Radio\nhttp://radio.example/stream\n",
        );
        assert_eq!(p.title.as_deref(), Some("Mix"));
        assert_eq!(p.entries.len(), 2);
        assert_eq!((p.entries[0].artist.as_deref(), p.entries[0].duration), (Some("Band"), Some(200.0)));
        assert_eq!(p.entries[1].duration, None);
        let h = hls(
            "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:6\n#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"skd://k\",KEYFORMAT=\"com.apple.streamingkeydelivery\"\n#EXT-X-MAP:URI=\"init.mp4\"\n#EXTINF:6.0,\na.m4s\n#EXTINF:4.5,\nb.m4s\n#EXT-X-ENDLIST\n",
        );
        assert_eq!(h.format["kind"], "media");
        assert_eq!(h.format["segment_format"], "fmp4");
        assert_eq!(h.format["live"], false);
        assert_eq!(h.format["drm"], json!(["fairplay"]));
        assert!(h.encrypted && h.sum_is_length);
        let m = hls(
            "#EXTM3U\n#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"a\",LANGUAGE=\"en\",NAME=\"English\",DEFAULT=YES\n#EXT-X-STREAM-INF:BANDWIDTH=800000,RESOLUTION=640x360,CODECS=\"avc1.4d401e,mp4a.40.2\",AUDIO=\"a\"\nlow/index.m3u8\n",
        );
        assert_eq!(m.format["kind"], "master");
        assert_eq!(m.format["variant_list"][0]["resolution"], "640x360");
        assert_eq!(m.format["renditions"][0]["default"], true);
        assert_eq!(m.format["codecs"], json!(["avc1.4d401e", "mp4a.40.2"]));
    }
}
