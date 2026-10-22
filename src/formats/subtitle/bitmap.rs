//! Bitmap subtitles: Blu-ray PGS (`.sup`: display sets, the video size and
//! frame rate, forced and cropped objects, cue times) and the VobSub index
//! (`.idx`: picture size, palette, tracks with their languages, cue start
//! times). The pictures themselves carry the text, so there is no
//! transcript.
//!
//! Specifications: the HDMV presentation graphics stream (Blu-ray Disc
//! Read-Only Format part 3, as ffmpeg's `pgssubdec` reads it); the VobSub
//! index as VSFilter writes it.

use serde_json::{Map, Value, json};

use super::{Cue, Subtitles, clock, head_text, language_code, ms};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for PGS and VobSub subtitles.
pub struct Bitmap;

static META: ExtractorMeta = ExtractorMeta {
    id: "subtitle.bitmap",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "pgs",
            name: "Blu-ray PGS subtitles",
            family: "text.subtitle",
            mimes: &["application/x-pgs"],
            extensions: &["sup"],
            magic: &[Magic::prefix(b"PG")],
            parent: None,
        },
        FormatSpec {
            id: "vobsub",
            name: "VobSub index",
            family: "text.subtitle",
            mimes: &["text/x-vobsub-index"],
            extensions: &["idx"],
            magic: &[Magic::prefix(b"# VobSub index file")],
            parent: None,
        },
    ],
};

/// PGS segments walked.
const MAX_SEGMENTS: u64 = 1 << 22;

impl Extractor for Bitmap {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        // A presentation composition segment (0x16) or palette (0x14) first.
        if h.len() >= 13 && &h[..2] == b"PG" && matches!(h[10], 0x14..=0x17 | 0x80) {
            return Some(Sniff { format: "pgs", confidence: 0.9 });
        }
        head_text(&h[..h.len().min(256)])
            .starts_with("# VobSub index file")
            .then_some(Sniff { format: "vobsub", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let subs = if cx.format_id() == "vobsub" {
            let text = cx.read_text(src)?.text;
            vobsub(&text)
        } else {
            pgs(src, cx)?
        };
        if subs.cues.is_empty() {
            cx.warn("no cues found");
        }
        subs.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Bitmap);

/// PGS frame-rate codes.
fn pgs_rate(code: u8) -> Option<f64> {
    Some(match code {
        0x10 => 24_000.0 / 1001.0,
        0x20 => 24.0,
        0x30 => 25.0,
        0x40 => 30_000.0 / 1001.0,
        0x60 => 50.0,
        0x70 => 60_000.0 / 1001.0,
        _ => return None,
    })
}

fn pgs(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<Subtitles, ExtractError> {
    let mut s = Subtitles { bitmap: true, ..Subtitles::new("hdmv_pgs_subtitle") };
    let len = src.len();
    let (mut pos, mut segments) = (0u64, 0u64);
    let (mut sets, mut epochs, mut forced, mut cropped, mut objects, mut palettes) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut size: Option<(u16, u16)> = None;
    let mut rate = None;
    let mut open: Option<f64> = None;
    let mut bad = false;
    while pos + 13 <= len && segments < MAX_SEGMENTS {
        if segments.is_multiple_of(4096) {
            cx.checkpoint()?;
        }
        let head = src.read_vec(pos, 13)?;
        if &head[..2] != b"PG" {
            bad = true;
            break;
        }
        let pts = f64::from(u32::from_be_bytes([head[2], head[3], head[4], head[5]])) / 90_000.0;
        let kind = head[10];
        let length = u64::from(u16::from_be_bytes([head[11], head[12]]));
        segments += 1;
        match kind {
            0x16 => {
                let pcs = src.read_vec(pos + 13, usize::try_from(length.min(512)).unwrap_or(0))?;
                if pcs.len() >= 11 {
                    sets += 1;
                    size.get_or_insert((u16::from_be_bytes([pcs[0], pcs[1]]), u16::from_be_bytes([pcs[2], pcs[3]])));
                    if rate.is_none() {
                        rate = pgs_rate(pcs[4]);
                    }
                    if pcs[7] & 0x80 != 0 {
                        epochs += 1;
                    }
                    let count = usize::from(pcs[10]);
                    let mut at = 11;
                    let mut any_forced = false;
                    for _ in 0..count {
                        let Some(o) = pcs.get(at..at + 8) else { break };
                        if o[3] & 0x40 != 0 {
                            any_forced = true;
                        }
                        at += 8;
                        if o[3] & 0x80 != 0 {
                            cropped += 1;
                            at += 8;
                        }
                    }
                    if any_forced {
                        forced += 1;
                    }
                    // Each composition replaces what was shown.
                    if let Some(start) = open.take() {
                        s.push(Cue { start, end: Some(pts.max(start)), ..Cue::default() });
                    }
                    if count > 0 {
                        open = Some(pts);
                    }
                }
            }
            0x15 => objects += 1,
            0x14 => palettes += 1,
            _ => {}
        }
        pos += 13 + length;
    }
    if let Some(start) = open {
        s.push(Cue { start, end: None, ..Cue::default() });
    }
    if bad && segments == 0 {
        return Err(ExtractError::malformed("not a PGS stream"));
    }
    if bad {
        cx.warn(format!("segment header lost at byte {pos}"));
    }
    s.frame_rate = rate;
    if let Some((w, h)) = size {
        s.set("video_size", format!("{w}x{h}"));
    }
    s.set("segments", segments);
    s.set("display_sets", sets);
    for (k, v) in [
        ("epochs", epochs),
        ("forced_cues", forced),
        ("cropped_objects", cropped),
        ("object_segments", objects),
        ("palette_segments", palettes),
    ] {
        if v > 0 {
            s.set(k, v);
        }
    }
    Ok(s)
}

/// One VobSub track.
#[derive(Default)]
struct Track {
    language: Option<String>,
    index: Option<u32>,
    starts: Vec<f64>,
}

fn vobsub(text: &str) -> Subtitles {
    let mut s = Subtitles { bitmap: true, ..Subtitles::new("dvd_subtitle") };
    let mut tracks: Vec<Track> = Vec::new();
    let mut default_index = None;
    let mut forced = false;
    let mut delay = 0.0;
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') {
            if let Some(v) = line.strip_prefix("# VobSub index file, ") {
                s.set("version", v.split_whitespace().next().unwrap_or(""));
            }
            continue;
        }
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim();
        match k.trim() {
            "size" => s.set("video_size", v),
            "langidx" => default_index = v.parse::<u32>().ok(),
            "forced subs" => forced = v.eq_ignore_ascii_case("on"),
            "palette" => s.set("palette_colours", v.split(',').filter(|c| !c.trim().is_empty()).count()),
            "id" => {
                let (lang, index) = v.split_once(',').map_or((v, None), |(l, r)| {
                    (l.trim(), r.split_once(':').and_then(|(_, n)| n.trim().parse::<u32>().ok()))
                });
                tracks.push(Track { language: language_code(lang), index, starts: Vec::new() });
                delay = 0.0;
            }
            "delay" => delay = signed_clock(v).unwrap_or(0.0),
            "timestamp" => {
                let ts = v.split(',').next().unwrap_or("");
                if let (Some(t), Some(track)) = (vobsub_time(ts), tracks.last_mut()) {
                    track.starts.push((t + delay).max(0.0));
                }
            }
            _ => {}
        }
    }
    if forced {
        s.set("forced_only", true);
    }
    let main = default_index
        .and_then(|i| tracks.iter().position(|t| t.index == Some(i)))
        .or_else(|| tracks.iter().position(|t| !t.starts.is_empty()))
        .unwrap_or(0);
    for (i, t) in tracks.iter().enumerate() {
        let mut m: Map<String, Value> = Map::new();
        m.insert("type".into(), json!("subtitle"));
        m.insert("codec".into(), json!("dvd_subtitle"));
        if let Some(l) = &t.language {
            m.insert("language".into(), json!(l));
        }
        m.insert("cues".into(), json!(t.starts.len()));
        if let Some(last) = t.starts.last() {
            m.insert("last_cue_s".into(), json!(ms(*last)));
        }
        if i == main {
            m.insert("default".into(), json!(true));
        }
        s.tracks.push(m);
    }
    if let Some(t) = tracks.get(main) {
        if let Some(l) = &t.language {
            s.declare_language(l, "vobsub.id");
        }
        for &start in &t.starts {
            s.push(Cue { start, ..Cue::default() });
        }
    }
    s.close_open_cues();
    s
}

/// `00:00:01:500` (milliseconds after the last colon).
fn vobsub_time(t: &str) -> Option<f64> {
    let (hms, millis) = t.trim().rsplit_once(':')?;
    clock(&format!("{hms}.{millis}"))
}

/// A delay: `-00:00:01:000` or `00:00:01:000`.
fn signed_clock(v: &str) -> Option<f64> {
    match v.strip_prefix('-') {
        Some(r) => vobsub_time(r).map(|t| -t),
        None => vobsub_time(v.trim_start_matches('+')),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::testing::report_for;

    crate::fixture_tests!("pgs", "vobsub");

    #[test]
    fn idx_tracks() {
        let s = vobsub(
            "# VobSub index file, v7 (do not modify this line!)\nsize: 720x576\npalette: 000000, ffffff\nlangidx: 1\n\
             id: en, index: 0\ntimestamp: 00:00:01:000, filepos: 000000000\n\
             id: fr, index: 1\ndelay: 00:00:00:500\ntimestamp: 00:00:02:000, filepos: 000000800\ntimestamp: 00:00:04:250, filepos: 000001000\n",
        );
        assert_eq!(s.tracks.len(), 2);
        assert_eq!(s.language, Some(("fr".into(), "vobsub.id")));
        assert_eq!(s.cues.iter().map(|c| c.start).collect::<Vec<_>>(), [2.5, 4.75]);
        assert_eq!(s.format["video_size"], "720x576");
        assert_eq!(s.format["palette_colours"], 2);
        assert_eq!(signed_clock("-00:00:01:000"), Some(-1.0));
    }

    #[test]
    fn pgs_display_sets() {
        // Two display sets: one object shown at 1 s, cleared at 3 s.
        let seg = |pts: u32, kind: u8, data: &[u8]| {
            let mut v = b"PG".to_vec();
            v.extend_from_slice(&(pts * 90_000).to_be_bytes());
            v.extend_from_slice(&[0; 4]);
            v.push(kind);
            v.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            v.extend_from_slice(data);
            v
        };
        let show = [7, 0x80, 4, 0x38, 0x10, 0, 1, 0x80, 0, 0, 1, 0, 0, 0, 0x40, 0, 10, 0, 20];
        let clear = [7, 0x80, 4, 0x38, 0x10, 0, 2, 0, 0, 0, 0];
        let mut f = seg(1, 0x16, &show);
        f.extend(seg(1, 0x80, &[]));
        f.extend(seg(3, 0x16, &clear));
        f.extend(seg(3, 0x80, &[]));
        let r = report_for("x.sup", &f);
        let fmt = &r.format["pgs"];
        assert_eq!(fmt["cues"], 1);
        assert_eq!(fmt["video_size"], "1920x1080");
        assert_eq!(fmt["forced_cues"], 1);
        assert_eq!(fmt["last_cue_end_s"], 3.0);
    }
}
