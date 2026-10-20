//! Matroska and WebM (MKV, MKA, MKS, MK3D, WebM): the EBML header, segment
//! information (title, duration, dates, muxing and writing applications),
//! every track (codec and its private data: `avcC`, `hvcC`, `av1C`,
//! AudioSpecificConfig, `WAVEFORMATEX`, `BITMAPINFOHEADER`; size, crop,
//! display size, frame rate, colour, HDR mastering and light level, Dolby
//! Vision, stereo mode, language, name, default / forced flags, encryption),
//! chapters, tags (global ones normalised, per-track statistics), and
//! attachments (fonts, cover art).
//!
//! Elements before the first cluster and those its seek head points to are
//! read; clusters are skipped, except the first (for the key frames of
//! VP8 / VP9 / AV1 streams without codec private data) and the last (for the
//! duration of a file whose header has none).
//!
//! Specifications: RFC 8794 (EBML), RFC 9559 (Matroska), the WebM container
//! guidelines, the Matroska codec mappings and tagging guidelines.

use serde_json::{Map, Value, json};

use super::super::audio::{self, Chapter, Picture, Stream, Tags, add_raw, comment_key};
use super::codec::{self, Colour};
use super::{Video, audio_map, avi, finish, labels, other_map};
use crate::plugin::mp4::AudioConfig;
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
};

/// Extractor for Matroska and WebM.
pub struct Matroska;

static META: ExtractorMeta = ExtractorMeta {
    id: "video.matroska",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "mkv",
            name: "Matroska video",
            family: "video",
            mimes: &["video/x-matroska", "video/matroska"],
            extensions: &["mkv", "mk3d"],
            magic: &[Magic::prefix(&[0x1a, 0x45, 0xdf, 0xa3])],
            parent: None,
        },
        FormatSpec {
            id: "webm",
            name: "WebM video",
            family: "video",
            mimes: &["video/webm", "audio/webm"],
            extensions: &["webm", "weba"],
            magic: &[],
            parent: Some("mkv"),
        },
        FormatSpec {
            id: "mka",
            name: "Matroska audio",
            family: "audio",
            mimes: &["audio/x-matroska", "audio/matroska"],
            extensions: &["mka"],
            magic: &[],
            parent: Some("mkv"),
        },
        FormatSpec {
            id: "mks",
            name: "Matroska subtitles",
            family: "video",
            mimes: &["application/x-matroska"],
            extensions: &["mks"],
            magic: &[],
            parent: Some("mkv"),
        },
    ],
};

const EBML: u32 = 0x1a45_dfa3;
const DOC_TYPE: u32 = 0x4282;
const DOC_TYPE_VERSION: u32 = 0x4287;
const SEGMENT: u32 = 0x1853_8067;
const SEEK_HEAD: u32 = 0x114d_9b74;
const INFO: u32 = 0x1549_a966;
const TRACKS: u32 = 0x1654_ae6b;
const CHAPTERS: u32 = 0x1043_a770;
const TAGS: u32 = 0x1254_c367;
const ATTACHMENTS: u32 = 0x1941_a469;
const CLUSTER: u32 = 0x1f43_b675;

/// Largest metadata element read whole.
const MAX_ELEMENT: u64 = 16 << 20;
/// Largest codec private data kept.
const MAX_PRIVATE: usize = 1 << 20;
/// Top-level elements walked.
const MAX_TOP: usize = 1 << 16;
/// Bytes of the first clusters read for key frames and block times.
const FIRST_CLUSTER: u64 = 2 << 20;
/// Bytes searched at the end for the last cluster.
const TAIL: u64 = 4 << 20;
/// Largest attached picture handed on as cover art.
const MAX_COVER: u64 = 8 << 20;
const MAX_ATTACHMENTS: usize = 256;
const MAX_TAGS: usize = 4096;
const MAX_DEPTH: usize = 8;

/// A variable-length integer: value and length. `marker` keeps the length
/// marker bit (element ids).
fn vint(d: &[u8], marker: bool) -> Option<(u64, usize)> {
    let first = *d.first()?;
    let len = first.leading_zeros() as usize + 1;
    if len > 8 {
        return None;
    }
    let mut v = if marker { u64::from(first) } else { u64::from(first) & (0xff >> len) };
    for &b in d.get(1..len)? {
        v = (v << 8) | u64::from(b);
    }
    Some((v, len))
}

/// An element header in `d`: id, header length, and size (`None` = unknown).
fn header(d: &[u8]) -> Option<(u32, usize, Option<u64>)> {
    let (id, il) = vint(d, true)?;
    if il > 4 {
        return None;
    }
    let (size, sl) = vint(d.get(il..)?, false)?;
    let unknown = size == (1u64 << (7 * sl)) - 1;
    Some((u32::try_from(id).ok()?, il + sl, (!unknown).then_some(size)))
}

/// The child elements of a body: id and data.
fn children(d: &[u8]) -> impl Iterator<Item = (u32, &[u8])> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let (id, hl, size) = header(d.get(at..)?)?;
        let start = at + hl;
        let end = match size {
            Some(s) => start.checked_add(usize::try_from(s).ok()?)?,
            None => d.len(),
        };
        let body = d.get(start..end.min(d.len()))?;
        at = end;
        Some((id, body))
    })
}

fn uint(d: &[u8]) -> u64 {
    d.iter().take(8).fold(0, |v, &b| (v << 8) | u64::from(b))
}

fn int(d: &[u8]) -> i64 {
    if d.is_empty() || d.len() > 8 {
        return 0;
    }
    let neg = d[0] & 0x80 != 0;
    let mut b = if neg { [0xff; 8] } else { [0; 8] };
    b[8 - d.len()..].copy_from_slice(d);
    i64::from_be_bytes(b)
}

fn float(d: &[u8]) -> Option<f64> {
    match d.len() {
        4 => Some(f64::from(f32::from_be_bytes(d.try_into().ok()?))),
        8 => Some(f64::from_be_bytes(d.try_into().ok()?)),
        _ => None,
    }
    .filter(|f| f.is_finite())
}

fn text(d: &[u8]) -> String {
    String::from_utf8_lossy(d).trim_end_matches('\0').trim().to_string()
}

/// Read an element header from the source.
fn read_header(src: &mut dyn Source, pos: u64, end: u64) -> Option<(u32, u64, Option<u64>)> {
    let n = usize::try_from(end.min(src.len()).checked_sub(pos)?.min(12)).ok()?;
    let d = src.read_vec(pos, n).ok()?;
    let (id, hl, size) = header(&d)?;
    Some((id, pos + hl as u64, size))
}

impl Extractor for Matroska {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let (id, hl, size) = header(probe.head)?;
        if id != EBML {
            return None;
        }
        let body = probe.head.get(hl..hl + usize::try_from(size?).ok()?)?;
        let doc = children(body).find(|(id, _)| *id == DOC_TYPE).map(|(_, d)| text(d))?;
        let format = match (doc.as_str(), probe.extension) {
            ("webm", _) => "webm",
            ("matroska", Some("mka")) => "mka",
            ("matroska", Some("mks")) => "mks",
            ("matroska", _) => "mkv",
            _ => return None,
        };
        Some(Sniff { format, confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let (id, at, size) = read_header(src, 0, len).ok_or_else(|| ExtractError::malformed("no EBML header"))?;
        let size = size.filter(|s| *s <= 4096 && id == EBML).ok_or_else(|| ExtractError::malformed("EBML header"))?;
        let head = src.read_vec(at, usize::try_from(size).unwrap_or(0))?;
        for (id, d) in children(&head) {
            match id {
                DOC_TYPE => cx.format_set("doc_type", text(d)),
                DOC_TYPE_VERSION => cx.format_set("doc_type_version", uint(d)),
                _ => {}
            }
        }
        // The segment.
        let mut pos = at + size;
        let mut segment = None;
        while let Some((id, data, size)) = read_header(src, pos, len) {
            if id == SEGMENT {
                segment = Some((data, size.map_or(len, |s| data.saturating_add(s).min(len))));
                break;
            }
            match size {
                Some(s) => pos = data.saturating_add(s),
                None => break,
            }
        }
        let (seg, seg_end) = segment.ok_or_else(|| ExtractError::malformed("no segment"))?;
        let mut m = Mkv::default();
        let mut seeks: Vec<(u32, u64)> = Vec::new();
        let mut pos = seg;
        let mut first_cluster = None;
        let mut last_cluster = None;
        for _ in 0..MAX_TOP {
            let Some((id, data, size)) = read_header(src, pos, seg_end) else { break };
            match id {
                SEEK_HEAD | INFO | TRACKS | CHAPTERS | TAGS if size.is_some_and(|s| s <= MAX_ELEMENT) => {
                    // A truncated element is read as far as it goes.
                    let n = size.unwrap_or(0).min(seg_end.saturating_sub(data));
                    let body = src.read_vec(data, usize::try_from(n).unwrap_or(0))?;
                    if id == SEEK_HEAD {
                        seeks.extend(seek_entries(&body));
                    } else {
                        m.element(id, &body);
                    }
                }
                ATTACHMENTS if size.is_some() => {
                    m.attachments(src, data, data.saturating_add(size.unwrap_or(0)), cx)?;
                }
                CLUSTER => {
                    first_cluster.get_or_insert((data, size));
                    last_cluster = Some(data);
                    if !seeks.is_empty() || size.is_none() {
                        break;
                    }
                    cx.checkpoint()?;
                }
                _ => {}
            }
            match size {
                Some(s) => pos = data.saturating_add(s),
                None => break,
            }
            if pos >= seg_end {
                break;
            }
        }
        for (id, at) in seeks {
            if m.seen.contains(&id) || !matches!(id, INFO | TRACKS | CHAPTERS | TAGS | ATTACHMENTS) {
                continue;
            }
            let Some((found, data, Some(size))) = read_header(src, seg.saturating_add(at), seg_end) else { continue };
            if found != id {
                continue;
            }
            if id == ATTACHMENTS {
                m.attachments(src, data, data.saturating_add(size), cx)?;
            } else if size <= MAX_ELEMENT
                && let Ok(body) = src.read_vec(data, usize::try_from(size).unwrap_or(0))
            {
                m.element(id, &body);
            }
        }
        if let Some((at, size)) = first_cluster {
            // The first clusters (2 MiB at most): key frames and block times.
            let n = FIRST_CLUSTER.min(seg_end.saturating_sub(at));
            let body = src.read_vec(at, usize::try_from(n).unwrap_or(0))?;
            let first = usize::try_from(size.unwrap_or(n).min(n)).unwrap_or(0);
            m.key_frames(&body[..first]);
            if let Some(next) = body.get(first..) {
                for (id, cluster) in children(next).take(64) {
                    if id == CLUSTER {
                        m.key_frames(cluster);
                    }
                }
            }
        }
        if m.duration_ns.is_none() {
            m.duration_ns = last_block_time(src, seg_end, last_cluster, &m)?;
        }
        m.report(cx, len);
        Ok(())
    }
}

crate::register_extractor!(Matroska);

fn seek_entries(body: &[u8]) -> Vec<(u32, u64)> {
    let mut out = Vec::new();
    for (id, seek) in children(body) {
        if id != 0x4dbb {
            continue;
        }
        let (mut sid, mut spos) = (None, None);
        for (k, d) in children(seek) {
            match k {
                0x53ab => sid = u32::try_from(uint(d)).ok(),
                0x53ac => spos = Some(uint(d)),
                _ => {}
            }
        }
        if let (Some(i), Some(p)) = (sid, spos) {
            out.push((i, p));
        }
    }
    out
}

#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // the Matroska track flags
struct Track {
    number: u64,
    uid: u64,
    kind: u64,
    codec_id: String,
    private: Vec<u8>,
    name: Option<String>,
    language: Option<String>,
    default: bool,
    forced: bool,
    hearing_impaired: bool,
    commentary: bool,
    default_duration: Option<u64>,
    encrypted: bool,
    video: Video,
    pixel: Option<(u32, u32)>,
    crop: (u32, u32, u32, u32),
    display: Option<(u32, u32)>,
    display_unit: u64,
    chroma_sub: Option<(u64, u64)>,
    bits: Option<u8>,
    rate: Option<f64>,
    output_rate: Option<f64>,
    channels: Option<u16>,
    audio_bits: Option<u16>,
    statistics: Map<String, Value>,
    probed: bool,
    /// Block time stamps seen in the first cluster (for the frame rate when
    /// there is no default duration).
    times: Vec<i64>,
}

struct SimpleTag {
    name: String,
    value: String,
    language: Option<String>,
}

#[derive(Default)]
struct Mkv {
    seen: Vec<u32>,
    timestamp_scale: Option<u64>,
    duration_ns: Option<f64>,
    title: Option<String>,
    muxing_app: Option<String>,
    writing_app: Option<String>,
    date_utc: Option<i64>,
    segment_uid: Option<String>,
    tracks: Vec<Track>,
    chapters: Vec<Chapter>,
    editions: u64,
    /// (target type value, track uid, tag)
    tags: Vec<(u64, Option<u64>, SimpleTag)>,
    attachments: Vec<Value>,
    fonts: u64,
    pictures: Vec<Picture>,
}

impl Mkv {
    fn element(&mut self, id: u32, body: &[u8]) {
        if self.seen.contains(&id) {
            return;
        }
        self.seen.push(id);
        match id {
            INFO => self.info(body),
            TRACKS => {
                for (k, entry) in children(body) {
                    if k == 0xae && self.tracks.len() < 256 {
                        self.tracks.push(track(entry));
                    }
                }
            }
            CHAPTERS => self.chapters(body),
            TAGS => self.tags(body),
            _ => {}
        }
    }

    fn info(&mut self, body: &[u8]) {
        let mut duration = None;
        for (id, d) in children(body) {
            match id {
                0x002a_d7b1 => self.timestamp_scale = Some(uint(d)).filter(|s| *s > 0),
                0x4489 => duration = float(d),
                0x7ba9 => self.title = Some(text(d)).filter(|t| !t.is_empty()),
                0x4d80 => self.muxing_app = Some(text(d)),
                0x5741 => self.writing_app = Some(text(d)),
                0x4461 => self.date_utc = Some(int(d)),
                0x73a4 => self.segment_uid = Some(audio::hex(d)),
                _ => {}
            }
        }
        let scale = self.timestamp_scale.unwrap_or(1_000_000) as f64;
        self.duration_ns = duration.map(|d| d * scale).filter(|d| *d > 0.0);
    }

    fn chapters(&mut self, body: &[u8]) {
        // The default edition, else the first.
        let editions: Vec<&[u8]> = children(body).filter(|(id, _)| *id == 0x45b9).map(|(_, d)| d).collect();
        self.editions = editions.len() as u64;
        let pick = editions
            .iter()
            .find(|e| children(e).any(|(id, d)| id == 0x45db && uint(d) == 1))
            .or_else(|| editions.first());
        let Some(edition) = pick else { return };
        for (id, atom) in children(edition) {
            if id != 0xb6 || self.chapters.len() >= 1000 {
                continue;
            }
            let (mut start, mut end, mut title, mut hidden, mut enabled) = (0u64, None, String::new(), false, true);
            for (k, d) in children(atom) {
                match k {
                    0x91 => start = uint(d),
                    0x92 => end = Some(uint(d)),
                    0x98 => hidden = uint(d) == 1,
                    0x4598 => enabled = uint(d) != 0,
                    0x80 if title.is_empty() => {
                        title = children(d).find(|(k, _)| *k == 0x85).map(|(_, s)| text(s)).unwrap_or_default();
                    }
                    _ => {}
                }
            }
            if !hidden && enabled {
                self.chapters.push(Chapter { start_s: start as f64 / 1e9, end_s: end.map(|e| e as f64 / 1e9), title });
            }
        }
    }

    fn tags(&mut self, body: &[u8]) {
        for (id, tag) in children(body) {
            if id != 0x7373 {
                continue;
            }
            let (mut target, mut track_uid) = (50u64, None);
            if let Some((_, t)) = children(tag).find(|(k, _)| *k == 0x63c0) {
                for (k, d) in children(t) {
                    match k {
                        0x68ca => target = uint(d),
                        0x63c5 => track_uid = Some(uint(d)).filter(|u| *u != 0),
                        _ => {}
                    }
                }
            }
            for (k, st) in children(tag) {
                if k == 0x67c8 {
                    simple_tags(st, "", target, track_uid, &mut self.tags, 0);
                }
            }
        }
    }

    /// List the attached files; keep the cover art.
    fn attachments(
        &mut self,
        src: &mut dyn Source,
        at: u64,
        end: u64,
        cx: &mut Context<'_>,
    ) -> Result<(), ExtractError> {
        if self.seen.contains(&ATTACHMENTS) {
            return Ok(());
        }
        self.seen.push(ATTACHMENTS);
        let end = end.min(src.len());
        let mut pos = at;
        while self.attachments.len() < MAX_ATTACHMENTS {
            let Some((id, data, Some(size))) = read_header(src, pos, end) else { break };
            pos = data.saturating_add(size);
            if id != 0x61a7 {
                continue;
            }
            cx.checkpoint()?;
            let (mut name, mut mime, mut description, mut file) = (String::new(), String::new(), None, None);
            let mut p = data;
            let file_end = data.saturating_add(size);
            while p < file_end {
                let Some((k, d, Some(s))) = read_header(src, p, file_end) else { break };
                p = d.saturating_add(s);
                let small = || usize::try_from(s.min(4096)).unwrap_or(0);
                let mut read = || src.read_vec(d, small()).map(|b| text(&b)).unwrap_or_default();
                match k {
                    0x466e => name = read(),
                    0x4660 => mime = read().to_ascii_lowercase(),
                    0x467e => description = Some(read()),
                    0x465c => file = Some((d, s)),
                    _ => {}
                }
            }
            let size_bytes = file.map_or(0, |f| f.1);
            let mut entry =
                json!({ "name": crate::plugin::truncate_chars(&name, 200), "mime": mime, "size_bytes": size_bytes });
            if let Some(d) = description.filter(|d| !d.is_empty()) {
                entry["description"] = json!(crate::plugin::truncate_chars(&d, 200));
            }
            self.attachments.push(entry);
            let lower = name.to_ascii_lowercase();
            if mime.contains("font") || [".ttf", ".otf", ".ttc", ".woff", ".woff2"].iter().any(|e| lower.ends_with(e)) {
                self.fonts += 1;
            }
            if mime.starts_with("image/")
                && (lower.starts_with("cover") || self.pictures.is_empty())
                && self.pictures.len() < 4
                && let Some((d, s)) = file.filter(|f| f.1 <= MAX_COVER)
                && let Ok(data) = src.read_vec(d, usize::try_from(s).unwrap_or(0))
            {
                self.pictures.push(Picture {
                    mime: mime.clone(),
                    kind: Some(if lower.starts_with("cover") { 3 } else { 0 }),
                    description: name.clone(),
                    width: None,
                    height: None,
                    data,
                });
            }
        }
        Ok(())
    }

    /// Codec details from the first key frame of each VP8 / VP9 / AV1 track
    /// that has no codec private data, and the block time stamps.
    fn key_frames(&mut self, cluster: &[u8]) {
        let mut base = 0i64;
        for (id, d) in children(cluster) {
            if id == 0xe7 {
                base = i64::try_from(uint(d)).unwrap_or(0);
                continue;
            }
            let block = match id {
                0xa3 => d,
                0xa0 => match children(d).find(|(k, _)| *k == 0xa1) {
                    Some((_, b)) => b,
                    None => continue,
                },
                _ => continue,
            };
            let Some((number, n)) = vint(block, false) else { continue };
            let Some(t) = self.tracks.iter_mut().find(|t| t.number == number) else { continue };
            if let Some(rel) = block.get(n..n + 2)
                && t.times.len() < 4096
            {
                t.times.push(base + i64::from(i16::from_be_bytes([rel[0], rel[1]])));
            }
            if t.probed {
                continue;
            }
            let Some(&flags) = block.get(n + 2) else { continue };
            if flags & 0x06 != 0 {
                continue; // laced
            }
            let frame = block.get(n + 3..).unwrap_or_default();
            let probed = match t.codec_id.as_str() {
                "V_VP9" => codec::vp9_frame(frame),
                "V_VP8" => codec::vp8_frame(frame),
                "V_AV1" if t.private.is_empty() => codec::av1_obus(frame),
                _ => None,
            };
            if let Some(v) = probed {
                t.video.absorb(v);
                t.probed = true;
            }
        }
    }

    #[allow(clippy::too_many_lines)] // one section of the report after another
    fn report(mut self, cx: &mut Context<'_>, len: u64) {
        let scale = self.timestamp_scale.unwrap_or(1_000_000);
        cx.format_set("timestamp_scale_ns", scale);
        if let Some(a) = &self.muxing_app {
            cx.format_set("muxing_app", a.as_str());
        }
        if let Some(u) = &self.segment_uid {
            cx.format_set("segment_uid", u.as_str());
        }
        if let Some(t) = self.date_utc.and_then(date_2001) {
            cx.temporal().source("matroska.Info.DateUTC").content_date(DateField::Created, t, true);
        }
        let duration = self.duration_ns.map(|d| d / 1e9);
        // Per-track statistics tags (mkvmerge's BPS, NUMBER_OF_FRAMES, DURATION).
        for (_, uid, t) in &self.tags {
            if let Some(track) = uid.and_then(|u| self.tracks.iter_mut().find(|k| k.uid == u)) {
                track.statistics.insert(t.name.clone(), json!(t.value));
            }
        }
        let mut list = Vec::new();
        let mut streams = Vec::new();
        let mut encrypted = false;
        for t in &mut self.tracks {
            encrypted |= t.encrypted;
            let mut entry = json!({ "number": t.number, "type": track_type(t.kind), "codec_id": t.codec_id });
            if !t.statistics.is_empty() {
                entry["statistics"] = Value::Object(t.statistics.clone());
            }
            list.push(entry);
            let stat = |k: &str| t.statistics.get(k).and_then(Value::as_str).and_then(|v| v.trim().parse::<u64>().ok());
            let (bps, frames) = (stat("BPS"), stat("NUMBER_OF_FRAMES"));
            let lang = t.language.as_deref();
            let mut m = match t.kind {
                1 => {
                    let mut v = std::mem::take(&mut t.video);
                    video_details(t, &mut v);
                    if v.fps.is_none() {
                        v.fps = block_rate(&t.times, scale);
                    }
                    v.bitrate_bps = v.bitrate_bps.or(bps);
                    v.frames = frames;
                    v.language.clone_from(&t.language);
                    v.title.clone_from(&t.name);
                    (v.default, v.forced) = (Some(t.default), Some(t.forced));
                    v.encrypted = t.encrypted;
                    v.to_map()
                }
                2 => {
                    let mut s = audio_stream(t);
                    s.bitrate_bps = s.bitrate_bps.or(bps);
                    let mut m = audio_map(&s);
                    labels(&mut m, lang, t.name.as_deref(), Some(t.default), Some(t.forced));
                    m
                }
                0x11 => {
                    let mut m = other_map("subtitle", subtitle_codec(&t.codec_id));
                    labels(&mut m, lang, t.name.as_deref(), Some(t.default), Some(t.forced));
                    m
                }
                _ => {
                    let mut m = other_map("data", track_type(t.kind));
                    labels(&mut m, lang, t.name.as_deref(), None, None);
                    m
                }
            };
            if t.hearing_impaired {
                m.insert("hearing_impaired".into(), json!(true));
            }
            if t.commentary {
                m.insert("commentary".into(), json!(true));
            }
            m.insert("track".into(), json!(t.number));
            streams.push(m);
        }
        cx.format_set("tracks", Value::Array(list));
        if encrypted {
            cx.format_set("encrypted", true);
            cx.security().encrypted(true);
        }
        if !self.attachments.is_empty() {
            cx.format_set("attachments", Value::Array(std::mem::take(&mut self.attachments)));
            if self.fonts > 0 {
                cx.format_set("font_attachments", self.fonts);
            }
        }
        if self.editions > 1 {
            cx.format_set("chapter_editions", self.editions);
        }
        finish(cx, streams, duration, len);
        let mut tags = Tags::default();
        tags.system("matroska");
        if let Some(t) = &self.title {
            tags.set("title", t, "matroska");
        }
        if let Some(w) = &self.writing_app {
            tags.set("encoder", w, "matroska");
        }
        let audio_only = cx.format_id() == "mka";
        for (target, uid, t) in &self.tags {
            if uid.is_some() {
                continue;
            }
            let upper = t.name.to_ascii_uppercase();
            let key = match (upper.as_str(), audio_only && *target >= 50) {
                ("TITLE", true) => Some("album"),
                ("ARTIST", true) => Some("album_artist"),
                (n, _) => tag_key(n),
            };
            if let Some(k) = key {
                tags.set(k, &t.value, "matroska");
            }
            let raw = match &t.language {
                Some(l) if l != "und" && l != "eng" => format!("{}@{l}", t.name),
                _ => t.name.clone(),
            };
            add_raw(cx, "matroska", &raw, json!(crate::plugin::truncate_chars(&t.value, 2000)));
        }
        tags.chapters = std::mem::take(&mut self.chapters);
        audio::mp4::close_chapters(&mut tags.chapters, duration);
        tags.pictures = std::mem::take(&mut self.pictures);
        tags.report(cx);
    }
}

fn simple_tags(
    d: &[u8],
    prefix: &str,
    target: u64,
    track: Option<u64>,
    out: &mut Vec<(u64, Option<u64>, SimpleTag)>,
    depth: usize,
) {
    let (mut name, mut value, mut language) = (String::new(), None, None);
    let mut nested = Vec::new();
    for (k, v) in children(d) {
        match k {
            0x45a3 => name = text(v),
            0x4487 => value = Some(text(v)),
            0x447a | 0x447b => language = Some(text(v)),
            0x67c8 => nested.push(v),
            _ => {}
        }
    }
    let full = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
    if let Some(value) = value.filter(|v| !v.is_empty())
        && out.len() < MAX_TAGS
    {
        out.push((target, track, SimpleTag { name: full.clone(), value, language }));
    }
    if depth < MAX_DEPTH {
        for n in nested {
            simple_tags(n, &full, target, track, out, depth + 1);
        }
    }
}

fn track(entry: &[u8]) -> Track {
    let mut t = Track { default: true, kind: 0, ..Track::default() };
    let mut language = None;
    let mut bcp47 = None;
    for (id, d) in children(entry) {
        match id {
            0xd7 => t.number = uint(d),
            0x73c5 => t.uid = uint(d),
            0x83 => t.kind = uint(d),
            0x86 => t.codec_id = text(d),
            0x63a2 if d.len() <= MAX_PRIVATE => t.private = d.to_vec(),
            0x536e => t.name = Some(text(d)).filter(|n| !n.is_empty()),
            0x0022_b59c => language = Some(text(d)),
            0x0022_b59d => bcp47 = Some(text(d)),
            0x88 => t.default = uint(d) != 0,
            0x55aa => t.forced = uint(d) != 0,
            0x55ab => t.hearing_impaired = uint(d) != 0,
            0x55af => t.commentary = uint(d) != 0,
            0x0023_e383 => t.default_duration = Some(uint(d)).filter(|d| *d > 0),
            0xe0 => video_element(d, &mut t),
            0xe1 => {
                for (k, v) in children(d) {
                    match k {
                        0xb5 => t.rate = float(v),
                        0x78b5 => t.output_rate = float(v),
                        0x9f => t.channels = u16::try_from(uint(v)).ok(),
                        0x6264 => t.audio_bits = u16::try_from(uint(v)).ok(),
                        _ => {}
                    }
                }
            }
            0x6d80 => {
                // ContentEncodings > ContentEncoding > ContentEncodingType (1 = encryption).
                t.encrypted = children(d)
                    .filter(|(k, _)| *k == 0x6240)
                    .any(|(_, e)| children(e).any(|(k, v)| (k == 0x5033 && uint(v) == 1) || k == 0x5035));
            }
            0x41e4 => {
                let (mut kind, mut extra) = (0u64, None);
                for (k, v) in children(d) {
                    match k {
                        0x41e7 => kind = uint(v),
                        0x41ed => extra = Some(v),
                        _ => {}
                    }
                }
                // BlockAddIDType `dvcC` / `dvvC`: a Dolby Vision configuration.
                if matches!(kind, 0x6476_6343 | 0x6476_7643)
                    && let Some(e) = extra
                {
                    t.video.dolby_vision = codec::dolby_vision(e);
                }
            }
            _ => {}
        }
    }
    // Language defaults to English when absent (RFC 9559 §5.1.4.1.19).
    t.language = bcp47.or(language).or_else(|| Some("eng".into())).filter(|l| !l.is_empty());
    t
}

fn video_element(d: &[u8], t: &mut Track) {
    let (mut w, mut h) = (None, None);
    let (mut dw, mut dh) = (None, None);
    for (k, v) in children(d) {
        let n = || u32::try_from(uint(v)).ok();
        match k {
            0xb0 => w = n(),
            0xba => h = n(),
            0x54b0 => dw = n(),
            0x54ba => dh = n(),
            0x54b2 => t.display_unit = uint(v),
            0x54aa => t.crop.3 = n().unwrap_or(0),
            0x54bb => t.crop.2 = n().unwrap_or(0),
            0x54cc => t.crop.0 = n().unwrap_or(0),
            0x54dd => t.crop.1 = n().unwrap_or(0),
            0x9a => {
                t.video.interlaced = match uint(v) {
                    1 => Some(true),
                    2 => Some(false),
                    _ => None,
                };
            }
            0x9d => {
                t.video.field_order = match uint(v) {
                    1 | 14 => Some("top_first"),
                    6 | 9 => Some("bottom_first"),
                    _ => None,
                };
            }
            0x53b8 => t.video.stereo_mode = stereo_mode(uint(v)).map(Into::into),
            0x53c0 => t.video.alpha = Some(uint(v) == 1),
            0x55b0 => colour_element(v, t),
            _ => {}
        }
    }
    t.pixel = w.zip(h);
    t.display = dw.zip(dh).filter(|d| d.0 > 0 && d.1 > 0);
}

fn colour_element(d: &[u8], t: &mut Track) {
    let (mut prim, mut trc, mut mat, mut range) = (2u32, 2u32, 2u32, None);
    let (mut sh, mut sv) = (None, None);
    for (k, v) in children(d) {
        let n = || u32::try_from(uint(v)).unwrap_or(2);
        match k {
            0x55b1 => mat = n(),
            0x55b2 => t.bits = u8::try_from(uint(v)).ok().filter(|b| *b > 0),
            0x55b3 => sh = Some(uint(v)),
            0x55b4 => sv = Some(uint(v)),
            0x55b9 => {
                range = match uint(v) {
                    1 => Some(false),
                    2 => Some(true),
                    _ => None,
                };
            }
            0x55ba => trc = n(),
            0x55bb => prim = n(),
            0x55bc => {
                let cll = u32::try_from(uint(v)).unwrap_or(0);
                t.video.light_level = Some((cll, t.video.light_level.map_or(0, |l| l.1)));
            }
            0x55bd => {
                let fall = u32::try_from(uint(v)).unwrap_or(0);
                t.video.light_level = Some((t.video.light_level.map_or(0, |l| l.0), fall));
            }
            0x55d0 => {
                let (mut max, mut min) = (None, None);
                for (m, x) in children(v) {
                    match m {
                        0x55d9 => max = float(x),
                        0x55da => min = float(x),
                        _ => {}
                    }
                }
                if let Some(max) = max {
                    t.video.mastering = Some((max, min.unwrap_or(0.0)));
                }
            }
            _ => {}
        }
    }
    // Matrix 2 / primaries 2 / transfer 2 mean "unspecified".
    t.video.colour = Colour::new(prim, trc, mat, range);
    t.chroma_sub = sh.zip(sv);
}

fn stereo_mode(v: u64) -> Option<&'static str> {
    Some(match v {
        1 => "side_by_side_left_first",
        2 => "top_bottom_right_first",
        3 => "top_bottom_left_first",
        4 => "checkerboard_right_first",
        5 => "checkerboard_left_first",
        6 => "row_interleaved_right_first",
        7 => "row_interleaved_left_first",
        8 => "column_interleaved_right_first",
        9 => "column_interleaved_left_first",
        10 => "anaglyph_cyan_red",
        11 => "side_by_side_right_first",
        12 => "anaglyph_green_magenta",
        13 => "block_left_first",
        14 => "block_right_first",
        _ => return None,
    })
}

fn track_type(kind: u64) -> &'static str {
    match kind {
        1 => "video",
        2 => "audio",
        3 => "complex",
        0x10 => "logo",
        0x11 => "subtitle",
        0x12 => "buttons",
        0x20 => "control",
        0x21 => "metadata",
        _ => "unknown",
    }
}

/// The video codec, private data, size, display size and frame rate.
fn video_details(t: &Track, v: &mut Video) {
    let id = t.codec_id.as_str();
    v.codec_tag = Some(t.codec_id.clone());
    v.codec = match id {
        "V_MPEG4/ISO/AVC" => "h264",
        "V_MPEGH/ISO/HEVC" => "hevc",
        "V_MPEGI/ISO/VVC" => "vvc",
        "V_AV1" => "av1",
        "V_VP8" => "vp8",
        "V_VP9" => "vp9",
        "V_MPEG4/ISO/SP" | "V_MPEG4/ISO/ASP" | "V_MPEG4/ISO/AP" | "V_MPEG4/MS/V3" => "mpeg4",
        "V_MPEG1" => "mpeg1video",
        "V_MPEG2" => "mpeg2video",
        "V_THEORA" => "theora",
        "V_PRORES" => "prores",
        "V_MJPEG" => "mjpeg",
        "V_FFV1" => "ffv1",
        "V_UNCOMPRESSED" => "rawvideo",
        "V_DIRAC" => "dirac",
        "V_REAL/RV10" => "rv10",
        "V_REAL/RV20" => "rv20",
        "V_REAL/RV30" => "rv30",
        "V_REAL/RV40" => "rv40",
        _ => "",
    }
    .to_string();
    if id == "V_MPEG4/MS/V3" {
        v.codec = "msmpeg4v3".into();
    }
    let p = &t.private;
    let parsed = match id {
        "V_MPEG4/ISO/AVC" => codec::avcc(p),
        "V_MPEGH/ISO/HEVC" => codec::hvcc(p),
        "V_AV1" if !p.is_empty() => codec::av1c(p),
        "V_MPEG1" | "V_MPEG2" => codec::mpeg_sequence(p),
        "V_MPEG4/ISO/SP" | "V_MPEG4/ISO/ASP" | "V_MPEG4/ISO/AP" => codec::mpeg4_visual(p),
        "V_MS/VFW/FOURCC" if p.len() >= 20 => {
            let fourcc = String::from_utf8_lossy(&p[16..20]).into_owned();
            v.codec = avi::vfw_codec(&fourcc);
            v.codec_tag = Some(fourcc);
            None
        }
        _ => None,
    };
    if v.codec.is_empty() {
        v.codec = id.trim_start_matches("V_").to_ascii_lowercase();
    }
    if let Some(c) = parsed {
        v.absorb(c);
    }
    if let Some((w, h)) = t.pixel {
        let (l, r, tp, b) = t.crop;
        v.width = v.width.or(Some(w.saturating_sub(l + r)));
        v.height = v.height.or(Some(h.saturating_sub(tp + b)));
    }
    match (t.display_unit, t.display) {
        (0, Some(d)) if Some(d) != v.width.zip(v.height) => v.display = Some(d),
        (3, Some(d)) => v.dar = Some(d),
        _ => {}
    }
    if v.bit_depth.is_none() {
        v.bit_depth = t.bits;
    }
    if v.chroma.is_none() {
        v.chroma = match t.chroma_sub {
            Some((1, 1)) => Some("4:2:0"),
            Some((1, 0)) => Some("4:2:2"),
            Some((0, 0)) => Some("4:4:4"),
            _ => None,
        };
    }
    if let Some(dd) = t.default_duration {
        v.fps = Some(1e9 / dd as f64);
    }
}

/// The mean frame interval of a track's first-cluster blocks, as a rate.
fn block_rate(times: &[i64], scale: u64) -> Option<f64> {
    let (min, max) = (times.iter().min()?, times.iter().max()?);
    let span = (max - min) as f64 * scale as f64 / 1e9;
    (times.len() >= 8 && span > 0.0).then(|| (times.len() - 1) as f64 / span)
}

fn audio_stream(t: &Track) -> Stream {
    let id = t.codec_id.as_str();
    let codec = match id {
        _ if id.starts_with("A_AAC") => "aac",
        "A_MPEG/L3" => "mp3",
        "A_MPEG/L2" => "mp2",
        "A_MPEG/L1" => "mp1",
        "A_AC3" | "A_AC3/BSID9" | "A_AC3/BSID10" => "ac3",
        "A_EAC3" => "eac3",
        "A_DTS" | "A_DTS/EXPRESS" | "A_DTS/LOSSLESS" => "dts",
        "A_TRUEHD" | "A_MLP" => "truehd",
        "A_OPUS" => "opus",
        "A_VORBIS" => "vorbis",
        "A_FLAC" => "flac",
        "A_ALAC" => "alac",
        "A_WAVPACK4" => "wavpack",
        "A_TTA1" => "tta",
        _ if id.starts_with("A_PCM") => "pcm",
        _ if id.starts_with("A_REAL/") => "real",
        _ => "",
    };
    let mut s =
        Stream::new(if codec.is_empty() { id.trim_start_matches("A_").to_ascii_lowercase() } else { codec.into() });
    let rate = t.output_rate.or(t.rate).filter(|r| *r > 0.0);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // a positive sample rate
    {
        s.sample_rate_hz = rate.map(|r| r.round() as u32);
    }
    s.channels = t.channels.or(Some(1));
    if matches!(codec, "pcm" | "flac" | "alac" | "wavpack" | "tta") {
        s.bits_per_sample = t.audio_bits;
    }
    match id {
        _ if codec == "aac" => {
            if let Some(c) = AudioConfig::parse(&t.private) {
                s.profile = Some(crate::plugin::mp4::aac_profile(c.object).into());
                s.sample_rate_hz = c.rate.or(s.sample_rate_hz);
                s.channels = c.channels.or(s.channels);
            } else if id.contains("SBR") {
                s.profile = Some("he_aac".into());
            } else if id.ends_with("/LC") {
                s.profile = Some("aac_lc".into());
            }
        }
        "A_MS/ACM" if t.private.len() >= 16 => {
            let p = &t.private;
            s.codec = audio::riff::codec(u16::from_le_bytes([p[0], p[1]]));
            s.bits_per_sample = Some(u16::from_le_bytes([p[14], p[15]])).filter(|b| *b > 0);
            let br = u32::from_le_bytes([p[8], p[9], p[10], p[11]]);
            s.bitrate_bps = Some(u64::from(br) * 8).filter(|b| *b > 0);
        }
        _ => {}
    }
    s
}

fn subtitle_codec(id: &str) -> &str {
    match id {
        "S_TEXT/UTF8" | "S_TEXT/ASCII" => "subrip",
        "S_TEXT/ASS" | "S_ASS" => "ass",
        "S_TEXT/SSA" | "S_SSA" => "ssa",
        "S_TEXT/WEBVTT" | "D_WEBVTT/SUBTITLES" | "D_WEBVTT/CAPTIONS" | "D_WEBVTT/DESCRIPTIONS" => "webvtt",
        "S_TEXT/USF" => "usf",
        "S_VOBSUB" => "dvd_subtitle",
        "S_HDMV/PGS" => "hdmv_pgs_subtitle",
        "S_HDMV/TEXTST" => "hdmv_text_subtitle",
        "S_DVBSUB" => "dvb_subtitle",
        "S_KATE" => "kate",
        "S_ARIBSUB" => "arib_caption",
        other => other,
    }
}

/// The normalised tag of a Matroska tag name.
fn tag_key(name: &str) -> Option<&'static str> {
    Some(match name {
        "TITLE" => "title",
        "SUBTITLE" => "subtitle",
        "ARTIST" | "LEAD_PERFORMER" | "DIRECTOR" => "artist",
        "DATE_RELEASED" | "DATE_RECORDED" | "DATE" => "date",
        "SYNOPSIS" | "SUMMARY" | "DESCRIPTION" => "description",
        "COMMENT" => "comment",
        "ENCODER" => "encoder",
        "PART_NUMBER" => "track",
        "TOTAL_PARTS" => "track_total",
        "PUBLISHER" | "LABEL" => "label",
        _ => return comment_key(name),
    })
}

/// Nanoseconds since 2001-01-01 as an RFC 3339 UTC timestamp.
fn date_2001(ns: i64) -> Option<String> {
    const EPOCH_2001: i64 = 978_307_200;
    let unix = EPOCH_2001.checked_add(ns.div_euclid(1_000_000_000))?;
    let ts = jiff::Timestamp::from_second(unix).ok()?;
    Some(ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// The end of the last block (cluster timestamp + block offset + one frame),
/// in nanoseconds, from the last cluster found near the end of the segment.
fn last_block_time(
    src: &mut dyn Source,
    seg_end: u64,
    last_cluster: Option<u64>,
    m: &Mkv,
) -> Result<Option<f64>, ExtractError> {
    let seg_end = seg_end.min(src.len());
    let from = seg_end.saturating_sub(TAIL).max(last_cluster.map_or(0, |c| c.saturating_sub(12))).min(seg_end);
    let tail = src.read_vec(from, usize::try_from(seg_end - from).unwrap_or(0))?;
    let id = CLUSTER.to_be_bytes();
    let mut best: Option<f64> = None;
    let scale = m.timestamp_scale.unwrap_or(1_000_000) as f64;
    let mut search = tail.len();
    // The last cluster whose timestamp parses; earlier ones only if it has no blocks.
    for _ in 0..8 {
        let Some(at) = tail[..search].windows(4).rposition(|w| w == id) else { break };
        search = at;
        let Some((_, hl, size)) = header(&tail[at..]) else { continue };
        let end = size.and_then(|s| usize::try_from(s).ok()).map_or(tail.len(), |s| (at + hl).saturating_add(s));
        let body = &tail[at + hl..end.min(tail.len())];
        let mut base = None;
        for (k, d) in children(body) {
            match k {
                0xe7 => base = Some(uint(d)),
                0xa3 | 0xa0 => {
                    let block = if k == 0xa3 { Some(d) } else { children(d).find(|(x, _)| *x == 0xa1).map(|(_, b)| b) };
                    let Some(block) = block else { continue };
                    let Some((number, n)) = vint(block, false) else { continue };
                    let Some(rel) = block.get(n..n + 2).map(|b| i16::from_be_bytes([b[0], b[1]])) else { continue };
                    let Some(base) = base else { continue };
                    let frame = m.tracks.iter().find(|t| t.number == number).and_then(|t| t.default_duration);
                    let end = (base as f64 + f64::from(rel)) * scale + frame.map_or(0.0, |f| f as f64);
                    best = Some(best.map_or(end, |b| b.max(end)));
                }
                _ => {}
            }
        }
        if best.is_some() {
            break;
        }
    }
    Ok(best.filter(|b| *b > 0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("mkv", "webm", "mka", "mks");

    #[test]
    fn ebml_primitives() {
        assert_eq!(vint(&[0x81], false), Some((1, 1)));
        assert_eq!(vint(&[0x40, 0x02], false), Some((2, 2)));
        assert_eq!(vint(&[0x1a, 0x45, 0xdf, 0xa3], true), Some((0x1a45_dfa3, 4)));
        assert_eq!(header(&[0xa3, 0xff]), Some((0xa3, 2, None)));
        assert_eq!(int(&[0xff, 0xfe]), -2);
        assert_eq!(float(&[0x40, 0x49, 0x0f, 0xdb]).map(|f| (f * 100.0).round()), Some(314.0));
        let body = [0x86, 0x82, b'V', b'_', 0xd7, 0x81, 0x01];
        let list: Vec<(u32, &[u8])> = children(&body).collect();
        assert_eq!(list, [(0x86, &b"V_"[..]), (0xd7, &[1][..])]);
        assert_eq!(date_2001(0).as_deref(), Some("2001-01-01T00:00:00Z"));
        assert_eq!(tag_key("DATE_RELEASED"), Some("date"));
        assert_eq!(subtitle_codec("S_TEXT/UTF8"), "subrip");
    }
}
