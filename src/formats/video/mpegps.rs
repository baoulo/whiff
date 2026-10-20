//! MPEG program streams (MPEG-1 system streams, MPEG-2 `.mpg`, DVD `.vob`):
//! the system version, mux rate, each elementary stream (MPEG video and
//! audio, and DVD private streams: AC-3, DTS, LPCM, subpictures) with its
//! codec details from the first payloads, DVD navigation packs, and the
//! duration from the first and last presentation time stamps.
//!
//! The first 4 MiB and the last 2 MiB are read.
//!
//! Specifications: ISO/IEC 11172-1 §2.4.3 and 13818-1 §2.5 (pack, system
//! header, PES), the DVD-Video private stream 1 sub-stream numbering.

use std::collections::BTreeMap;

use serde_json::json;

use super::pes::{self, Kind, Probed, Span};
use super::{Video, audio_map, finish, other_map};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for MPEG program streams.
pub struct MpegPs;

static META: ExtractorMeta = ExtractorMeta {
    id: "video.mpegps",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "mpg",
        name: "MPEG program stream",
        family: "video",
        mimes: &["video/mpeg", "video/mp2p"],
        extensions: &["mpg", "mpeg", "mpe", "m2p", "vob", "vro", "mod", "tod", "evo", "dat"],
        magic: &[Magic::prefix(&[0, 0, 1, 0xba])],
        parent: None,
    }],
};

const HEAD_SCAN: u64 = 4 << 20;
const TAIL_SCAN: u64 = 2 << 20;
const MAX_PROBE: usize = 256 << 10;
const MAX_STREAMS: usize = 64;

#[derive(Default)]
struct Es {
    kind: Option<Kind>,
    class: &'static str,
    codec: &'static str,
    buf: Vec<u8>,
    probed: Option<Probed>,
    span: Span,
    packets: u64,
}

/// The stream key: the stream id, and the sub-stream id of private stream 1.
fn key(d: &[u8], h: &pes::Header) -> u16 {
    let sub = if h.stream_id == 0xbd { d.get(h.payload).copied().unwrap_or(0) } else { 0 };
    (u16::from(h.stream_id) << 8) | u16::from(sub)
}

fn classify(key: u16) -> (Option<Kind>, &'static str, &'static str) {
    let (id, sub) = ((key >> 8) as u8, (key & 0xff) as u8);
    match (id, sub) {
        (0xe0..=0xef, _) => (Some(Kind::MpegVideo), "video", "mpeg2video"),
        (0xc0..=0xdf, _) => (Some(Kind::MpegAudio), "audio", "mp2"),
        (0xbd, 0x80..=0x87) => (Some(Kind::Ac3), "audio", "ac3"),
        (0xbd, 0x88..=0x8f) => (Some(Kind::Dts), "audio", "dts"),
        (0xbd, 0xa0..=0xa7) => (Some(Kind::DvdLpcm), "audio", "pcm"),
        (0xbd, 0xc0..=0xcf) => (Some(Kind::Eac3), "audio", "eac3"),
        (0xbd, 0x20..=0x3f) => (None, "subtitle", "dvd_subtitle"),
        (0xfd, _) => (None, "video", "vc1"),
        _ => (None, "data", "private"),
    }
}

impl Extractor for MpegPs {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // the pack / PES walk, the tail scan, then the stream maps
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let head = src.read_vec(0, usize::try_from(len.min(HEAD_SCAN)).unwrap_or(0))?;
        cx.checkpoint()?;
        let mut streams: BTreeMap<u16, Es> = BTreeMap::new();
        let mut order = Vec::new();
        let (mut mpeg2, mut mux_rate, mut packs, mut nav) = (None, None, 0u64, false);
        let mut i = 0;
        while i + 6 <= head.len() {
            if head[i..i + 3] != [0, 0, 1] {
                i += 1;
                continue;
            }
            let d = &head[i..];
            match d[3] {
                0xba => {
                    packs += 1;
                    if d.get(4).is_some_and(|b| b & 0xc0 == 0x40) && d.len() >= 14 {
                        mpeg2 = Some(true);
                        let rate = (u32::from(d[10]) << 14) | (u32::from(d[11]) << 6) | (u32::from(d[12]) >> 2);
                        mux_rate.get_or_insert(u64::from(rate) * 400);
                        i += 14 + usize::from(d[13] & 7);
                    } else if d.get(4).is_some_and(|b| b & 0xf0 == 0x20) && d.len() >= 12 {
                        mpeg2.get_or_insert(false);
                        let rate = (u32::from(d[9] & 0x7f) << 15) | (u32::from(d[10]) << 7) | (u32::from(d[11]) >> 1);
                        mux_rate.get_or_insert(u64::from(rate) * 400);
                        i += 12;
                    } else {
                        i += 4;
                    }
                }
                0xbb..=0xff => {
                    let Some(h) = pes::header(d) else {
                        i += 4;
                        continue;
                    };
                    if h.stream_id == 0xbf {
                        nav = true;
                    }
                    if !matches!(h.stream_id, 0xbb | 0xbc | 0xbe | 0xbf) {
                        let k = key(d, &h);
                        if streams.len() < MAX_STREAMS || streams.contains_key(&k) {
                            if !streams.contains_key(&k) {
                                order.push(k);
                            }
                            let e = streams.entry(k).or_insert_with(|| {
                                let (kind, class, codec) = classify(k);
                                Es { kind, class, codec, ..Es::default() }
                            });
                            e.packets += 1;
                            if let Some(pts) = h.pts {
                                e.span.first(pts);
                                e.span.last(pts);
                            }
                            let end = if h.length > 0 { (6 + h.length).min(d.len()) } else { d.len().min(6 + 65536) };
                            if let (Some(kind), None) = (e.kind, &e.probed)
                                && e.buf.len() < MAX_PROBE
                            {
                                e.buf.extend_from_slice(d.get(h.payload..end).unwrap_or_default());
                                e.probed = pes::probe(kind, &e.buf).or_else(|| {
                                    // H.264 in a program stream uses the video stream ids too.
                                    (kind == Kind::MpegVideo).then(|| pes::probe(Kind::H264, &e.buf)).flatten()
                                });
                            }
                        }
                    }
                    i += if h.length > 0 { 6 + h.length } else { 4 };
                }
                _ => i += 4,
            }
            if i >= head.len().min(1 << 20)
                && !streams.is_empty()
                && streams.values().all(|e| e.kind.is_none() || e.probed.is_some())
            {
                break;
            }
        }
        if packs == 0 && streams.is_empty() {
            return Err(ExtractError::malformed("no pack or PES header"));
        }
        // The last time stamps, from PES headers near the end.
        let tail_at = len.saturating_sub(TAIL_SCAN);
        let tail = src.read_vec(tail_at, usize::try_from(len - tail_at).unwrap_or(0))?;
        let mut j = 0;
        while let Some(p) = tail.get(j..).and_then(|t| t.windows(3).position(|w| w == [0, 0, 1])) {
            let at = j + p;
            if let Some(h) = pes::header(&tail[at..])
                && let Some(pts) = h.pts
                && let Some(e) = streams.get_mut(&key(&tail[at..], &h))
            {
                e.span.last(pts);
            }
            j = at + 3;
        }
        cx.format_set("system", if mpeg2 == Some(true) { "mpeg2_ps" } else { "mpeg1_system" });
        if let Some(r) = mux_rate {
            cx.format_set("mux_rate_bps", r);
        }
        cx.format_set("packs_scanned", packs);
        if nav {
            cx.format_set("dvd_navigation", true);
        }
        let mut spans = Vec::new();
        let mut maps = Vec::new();
        for k in &order {
            let e = &streams[k];
            let mut frame = 0.0;
            let mut m = match &e.probed {
                Some(Probed::Video(v)) => {
                    frame = v.fps.filter(|f| *f > 0.0).map_or(0.0, |f| 1.0 / f);
                    v.to_map()
                }
                Some(Probed::Audio(s, d)) => {
                    frame = *d;
                    audio_map(s)
                }
                None if e.class == "video" => Video::new(e.codec).to_map(),
                None => other_map(e.class, e.codec),
            };
            m.insert("stream_id".into(), json!(format!("0x{:02x}", k >> 8)));
            if k & 0xff != 0 {
                m.insert("substream_id".into(), json!(format!("0x{:02x}", k & 0xff)));
            }
            if matches!(e.class, "video" | "audio") {
                spans.push((e.span, frame));
            }
            maps.push(m);
        }
        finish(cx, maps, pes::duration(&spans), len);
        Ok(())
    }
}

crate::register_extractor!(MpegPs);

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("mpg");

    #[test]
    fn stream_keys() {
        assert_eq!(classify(0xe000).2, "mpeg2video");
        assert_eq!(classify(0xbd80).2, "ac3");
        assert_eq!(classify(0xbd21).1, "subtitle");
        assert_eq!(classify(0xbda0).2, "pcm");
    }
}
