//! Line-based subtitles: SubRip (SRT), WebVTT, YouTube SBV, SubViewer 1
//! and 2, Spruce STL, MicroDVD, MPL2 and LRC lyrics. Cues, times, text and
//! voices; WebVTT header fields (`Kind`, `Language`), notes, style and
//! region blocks; LRC ID tags (title, artist, album, author, length,
//! offset); the MicroDVD frame rate; SubViewer header fields; Spruce STL
//! settings.
//!
//! Specifications: <https://www.w3.org/TR/webvtt1/>; SubRip, SBV, SubViewer, Spruce STL,
//! MicroDVD, MPL2 and LRC as their writers and ffmpeg's readers use them.

use super::{Cue, Subtitles, clock, head_text, plain_text};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for line-based subtitles.
pub struct Timed;

static META: ExtractorMeta = ExtractorMeta {
    id: "subtitle.timed",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "srt",
            name: "SubRip subtitles",
            family: "text.subtitle",
            mimes: &["application/x-subrip"],
            extensions: &["srt"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "vtt",
            name: "WebVTT",
            family: "text.subtitle",
            mimes: &["text/vtt"],
            extensions: &["vtt", "webvtt"],
            magic: &[Magic::prefix(b"WEBVTT"), Magic::prefix(b"\xEF\xBB\xBFWEBVTT")],
            parent: None,
        },
        FormatSpec {
            id: "sbv",
            name: "YouTube SBV subtitles",
            family: "text.subtitle",
            mimes: &["text/x-sbv"],
            extensions: &["sbv"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "subviewer",
            name: "SubViewer subtitles",
            family: "text.subtitle",
            mimes: &["text/x-subviewer"],
            extensions: &["sub"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "spruce_stl",
            name: "Spruce STL subtitles",
            family: "text.subtitle",
            mimes: &["text/x-spruce-stl"],
            // Not `stl`: an extension-only match would claim 3D models.
            extensions: &[],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "microdvd",
            name: "MicroDVD subtitles",
            family: "text.subtitle",
            mimes: &["text/x-microdvd"],
            extensions: &["sub"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "mpl2",
            name: "MPL2 subtitles",
            family: "text.subtitle",
            mimes: &["text/x-mpl2"],
            extensions: &["mpl"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "lrc",
            name: "LRC lyrics",
            family: "text.subtitle",
            mimes: &["application/x-lrc"],
            extensions: &["lrc"],
            magic: &[],
            parent: None,
        },
    ],
};

/// MicroDVD frame rate when the file does not declare one (as ffmpeg).
const MICRODVD_DEFAULT_FPS: f64 = 23.976;
/// Spruce STL frame rate (the file does not say; DVD Studio Pro's PAL default).
const SPRUCE_FPS: f64 = 25.0;

impl Extractor for Timed {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let text = head_text(probe.head);
        let format = sniff_text(&text)?;
        Some(Sniff { format, confidence: if format == "mpl2" || format == "lrc" { 0.85 } else { 0.9 } })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.checkpoint()?;
        let subs = match cx.format_id() {
            "vtt" => vtt(&text),
            "subviewer" if subviewer1(&text) => subviewer_v1(&text),
            "sbv" | "subviewer" => comma_timed(&text, cx.format_id() == "subviewer"),
            "spruce_stl" => spruce(&text),
            "microdvd" => microdvd(&text),
            "mpl2" => mpl2(&text),
            "lrc" => lrc(&text),
            _ => srt(&text),
        };
        if subs.cues.is_empty() {
            cx.warn("no cues found");
        }
        subs.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Timed);

/// Which line-based format `text` starts like.
fn sniff_text(text: &str) -> Option<&'static str> {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).take(12).collect();
    let first = lines.first()?.trim_start_matches('\u{feff}');
    if first.starts_with("WEBVTT") {
        return Some("vtt");
    }
    let timing = |l: &str| arrow(l).is_some_and(|(a, _, _)| a.contains(':'));
    if timing(first) || (first.bytes().all(|b| b.is_ascii_digit()) && lines.get(1).is_some_and(|l| timing(l))) {
        return Some("srt");
    }
    if first.eq_ignore_ascii_case("[INFORMATION]") || first.eq_ignore_ascii_case("[SUBTITLE]") || subviewer1(text) {
        return Some("subviewer");
    }
    if spruce_file(text) {
        return Some("spruce_stl");
    }
    if let Some((a, _)) = comma_times(first) {
        // SBV writes milliseconds, SubViewer hundredths.
        let frac = a.rsplit('.').next().unwrap_or("");
        return Some(if frac.len() == 3 { "sbv" } else { "subviewer" });
    }
    if frames(first, '{', '}').is_some() {
        return Some("microdvd");
    }
    if lines.len() >= 3 && lines.iter().take(3).all(|l| frames(l, '[', ']').is_some()) {
        return Some("mpl2");
    }
    let lrc_lines = lines.iter().filter(|l| lrc_line(l)).count();
    (lrc_lines >= 2 && lrc_lines * 4 >= lines.len() * 3).then_some("lrc")
}

/// `start --> end [settings]`: the two times and the rest of the line.
fn arrow(line: &str) -> Option<(&str, &str, &str)> {
    let (a, rest) = line.split_once("-->")?;
    let rest = rest.trim_start();
    let end_len = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let (b, settings) = rest.split_at(end_len);
    let a = a.trim();
    (clock(a).is_some() && clock(b).is_some()).then_some((a, b, settings.trim()))
}

/// `0:00:01.000,0:00:03.000` (SBV, SubViewer 2).
fn comma_times(line: &str) -> Option<(&str, &str)> {
    let (a, b) = line.split_once(',')?;
    let ok = |s: &str| s.contains(':') && s.contains('.') && clock(s).is_some();
    (ok(a) && ok(b.trim())).then_some((a, b.trim()))
}

/// `{start}{end}text` (MicroDVD) or `[start][end]text` (MPL2): the two
/// numbers (the end may be empty) and the text.
fn frames(line: &str, open: char, close: char) -> Option<(u64, Option<u64>, &str)> {
    let num = |s: &str| -> Option<Option<u64>> {
        if s.is_empty() {
            return Some(None);
        }
        (s.len() <= 12 && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok())
    };
    let rest = line.strip_prefix(open)?;
    let (a, rest) = rest.split_once(close)?;
    let rest = rest.strip_prefix(open)?;
    let (b, text) = rest.split_once(close)?;
    Some((num(a)??, num(b)?, text))
}

/// SRT: optional counter line, timing line, text lines up to a blank line.
fn srt(text: &str) -> Subtitles {
    let mut s = Subtitles::new("subrip");
    let lines: Vec<&str> = text.lines().collect();
    let timings: Vec<usize> = (0..lines.len()).filter(|&i| arrow(lines[i].trim()).is_some()).collect();
    // A cue's text runs to the next timing line, blank lines included (as
    // ffmpeg reads it); the counter line before that timing line is not text.
    let counter = |l: &str| {
        let l = l.trim();
        !l.is_empty() && l.trim_start_matches('-').bytes().all(|b| b.is_ascii_digit())
    };
    for (k, &at) in timings.iter().enumerate() {
        let Some((a, b, settings)) = arrow(lines[at].trim()) else { continue };
        if !settings.is_empty() {
            s.markup.insert("position");
        }
        let mut end = timings.get(k + 1).copied().unwrap_or(lines.len());
        while end > at + 1 && lines[end - 1].trim().is_empty() {
            end -= 1;
        }
        if k + 1 < timings.len() && end > at + 1 && counter(lines[end - 1]) {
            end -= 1;
        }
        let raw = lines[at + 1..end.max(at + 1)].join("\n");
        let text = plain_text(&raw, &mut s.markup);
        s.push(Cue { start: clock(a).unwrap_or(0.0), end: clock(b), text, speaker: None });
    }
    s
}

fn vtt(text: &str) -> Subtitles {
    let mut s = Subtitles::new("webvtt");
    let blocks = blocks(text);
    let (mut notes, mut styles, mut regions, mut ids) = (0u64, 0u64, 0u64, 0u64);
    for (n, block) in blocks.iter().enumerate() {
        let first = block[0].trim();
        if n == 0 && first.starts_with("WEBVTT") {
            // Header lines: `Kind: captions`, `Language: en`, HLS time map.
            for l in &block[1..] {
                if let Some((k, v)) = l.split_once(':') {
                    match k.trim().to_ascii_lowercase().as_str() {
                        "kind" => s.set("kind", v.trim().to_ascii_lowercase()),
                        "language" => s.declare_language(v, "vtt.Language"),
                        _ => {}
                    }
                }
                if l.starts_with("X-TIMESTAMP-MAP") {
                    s.set("hls_timestamp_map", true);
                }
            }
            continue;
        }
        if first.starts_with("NOTE") {
            notes += 1;
            continue;
        }
        if first == "STYLE" {
            styles += 1;
            continue;
        }
        if first == "REGION" {
            regions += 1;
            continue;
        }
        let (timing, body) = match arrow(first) {
            Some(t) => (t, &block[1..]),
            None => match block.get(1).and_then(|l| arrow(l.trim())) {
                Some(t) => {
                    ids += 1;
                    (t, &block[2..])
                }
                None => continue,
            },
        };
        let (a, b, settings) = timing;
        if !settings.is_empty() {
            s.markup.insert("position");
        }
        let raw = body.join("\n");
        let speaker = voice(&raw);
        let text = plain_text(&raw, &mut s.markup);
        s.push(Cue { start: clock(a).unwrap_or(0.0), end: clock(b), text, speaker });
    }
    for (k, v) in [("notes", notes), ("style_blocks", styles), ("regions", regions), ("cue_identifiers", ids)] {
        if v > 0 {
            s.set(k, v);
        }
    }
    s
}

/// Groups of non-blank lines.
fn blocks(text: &str) -> Vec<Vec<&str>> {
    let mut out: Vec<Vec<&str>> = Vec::new();
    let mut cur: Vec<&str> = Vec::new();
    for l in text.lines() {
        if l.trim().is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(l);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The first `<v Name>` voice of a WebVTT cue.
fn voice(raw: &str) -> Option<String> {
    let at = raw.find("<v")?;
    let rest = &raw[at + 2..];
    let rest = match rest.as_bytes().first()? {
        b' ' | b'\t' => &rest[1..],
        // `<v.loud Bob>`: skip the classes.
        b'.' => rest.split_once([' ', '\t'])?.1,
        _ => return None,
    };
    let name = rest.split('>').next()?.trim();
    (!name.is_empty() && name.len() <= 120).then(|| name.to_string())
}

/// SBV and SubViewer 2: a `start,end` line, then text lines (SubViewer
/// breaks lines with `[br]`) up to a blank line.
fn comma_timed(text: &str, subviewer: bool) -> Subtitles {
    // ffmpeg reads both with its SubViewer demuxer.
    let mut s = Subtitles::new("subviewer");
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    let mut info = true;
    while i < lines.len() {
        let line = lines[i].trim();
        i += 1;
        if subviewer && info {
            if line.eq_ignore_ascii_case("[END INFORMATION]") {
                info = false;
            } else if let Some(rest) = line.strip_prefix('[')
                && let Some((tag, value)) = rest.split_once(']')
            {
                let value = value.trim();
                match tag.to_ascii_uppercase().as_str() {
                    "TITLE" => s.title = Some(value.to_string()),
                    "AUTHOR" => s.author = Some(value.to_string()),
                    "SOURCE" => s.set("source", value),
                    "PRG" => s.set("program", value),
                    "DELAY" => s.set("delay", value),
                    "COMMENT" => s.set("comment", value),
                    _ => {}
                }
            }
        }
        let Some((a, b)) = comma_times(line) else { continue };
        info = false;
        let mut raw = String::new();
        while i < lines.len() && !lines[i].trim().is_empty() && comma_times(lines[i].trim()).is_none() {
            if !raw.is_empty() {
                raw.push('\n');
            }
            raw.push_str(lines[i]);
            i += 1;
        }
        let raw = if subviewer { raw.replace("[br]", "\n").replace("[BR]", "\n") } else { raw };
        let text = plain_text(&raw, &mut s.markup);
        s.push(Cue { start: clock(a).unwrap_or(0.0), end: clock(b), text, speaker: None });
    }
    s
}

/// SubViewer 1: a `[hh:mm:ss]` line starts each cue; its header holds
/// `[TAG]` lines with the value on the next line.
fn subviewer1(text: &str) -> bool {
    let head = super::prefix(text, 4096);
    head.contains("START SCRIPT") || head.lines().filter(|l| bracket_time(l.trim()).is_some()).count() >= 3
}

/// `[00:03:41]` as seconds.
fn bracket_time(line: &str) -> Option<f64> {
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    (inner.len() == 8 && inner.matches(':').count() == 2).then(|| clock(inner)).flatten()
}

fn subviewer_v1(text: &str) -> Subtitles {
    let mut s = Subtitles::new("subviewer1");
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let mut delay = 0.0;
    let mut starts: Vec<(f64, String)> = Vec::new();
    let mut script = false;
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        i += 1;
        if let Some(t) = bracket_time(line) {
            script = true;
            let mut raw = String::new();
            while i < lines.len() && bracket_time(lines[i]).is_none() {
                if !lines[i].is_empty() {
                    raw.push_str(&lines[i].replace('|', "\n"));
                    raw.push('\n');
                }
                i += 1;
            }
            starts.push((t + delay, raw));
            continue;
        }
        if script || line.contains("START SCRIPT") {
            script |= line.contains("START SCRIPT");
            continue;
        }
        let Some(tag) = line.strip_prefix('[').and_then(|r| r.strip_suffix(']')) else { continue };
        let value = lines.get(i).copied().filter(|v| !v.starts_with('['));
        let Some(value) = value.filter(|v| !v.is_empty()) else { continue };
        match tag.to_ascii_uppercase().as_str() {
            "TITLE" => s.title = Some(value.to_string()),
            "AUTHOR" => s.author = Some(value.to_string()),
            "SOURCE" => s.set("source", value),
            "DELAY" => {
                delay = value.parse::<f64>().unwrap_or(0.0);
                s.set("delay", value);
            }
            _ => {}
        }
    }
    // A cue lasts until the next time stamp; an empty one only clears.
    for (k, (start, raw)) in starts.iter().enumerate() {
        let text = plain_text(raw, &mut s.markup);
        if text.is_empty() {
            continue;
        }
        let end = starts.get(k + 1).map(|n| n.0).filter(|e| *e >= *start);
        s.push(Cue { start: *start, end, text, speaker: None });
    }
    s.set("version", 1);
    s
}

/// `00:00:31:02 , 00:00:33:00 , text` (Spruce STL): the two timecodes (in
/// frames) and the text.
fn spruce_line(line: &str) -> Option<(f64, f64, &str)> {
    let mut parts = line.splitn(3, ',');
    let tc = |p: &str| -> Option<f64> {
        let n: Vec<u32> = p.trim().split(':').map(|x| x.parse().ok()).collect::<Option<_>>()?;
        let [h, m, sec, f] = n[..] else { return None };
        (m < 60 && sec < 60).then(|| f64::from(h * 3600 + m * 60 + sec) + f64::from(f) / SPRUCE_FPS)
    };
    let a = tc(parts.next()?)?;
    let b = tc(parts.next()?)?;
    Some((a, b, parts.next().unwrap_or("")))
}

/// A Spruce STL file: `//` comments, `$Name = value` settings and cue lines.
fn spruce_file(text: &str) -> bool {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).take(64).collect();
    let cues = lines.iter().filter(|l| spruce_line(l).is_some()).count();
    cues > 0 && lines.iter().all(|l| l.starts_with("//") || l.starts_with('$') || spruce_line(l).is_some())
}

/// Spruce STL: settings (`$FontName`, `$Italic`…), cues with `|` line
/// breaks and `^I` / `^B` / `^U` style toggles.
fn spruce(text: &str) -> Subtitles {
    let mut s = Subtitles::new("stl");
    let mut settings = 0u64;
    let mut fonts = std::collections::BTreeSet::new();
    for line in text.lines().map(|l| l.trim().trim_start_matches('\u{feff}')) {
        if let Some(set) = line.strip_prefix('$') {
            settings += 1;
            if let Some((k, v)) = set.split_once('=')
                && k.trim().eq_ignore_ascii_case("FontName")
            {
                fonts.insert(v.trim().to_string());
            }
            continue;
        }
        let Some((a, b, raw)) = spruce_line(line) else { continue };
        for (code, kind) in [("^I", "italic"), ("^B", "bold"), ("^U", "underline")] {
            if raw.contains(code) {
                s.markup.insert(kind);
            }
        }
        let raw = raw.replace("^I", "").replace("^B", "").replace("^U", "").replace('|', "\n");
        let text = plain_text(&raw, &mut s.markup);
        s.push(Cue { start: a, end: Some(b), text, speaker: None });
    }
    s.frame_rate = Some(SPRUCE_FPS);
    s.set("frame_rate_assumed", true);
    s.set("settings", settings);
    s.set("fonts", fonts.into_iter().collect::<Vec<_>>());
    s
}

/// MicroDVD: frame numbers, `|` line breaks, `{y:i}`-style control codes.
/// A first cue `{1}{1}23.976` declares the frame rate.
fn microdvd(text: &str) -> Subtitles {
    let mut s = Subtitles::new("microdvd");
    let mut fps = None;
    let mut parsed: Vec<(u64, Option<u64>, String)> = Vec::new();
    for (n, line) in text.lines().map(str::trim).filter(|l| !l.is_empty()).enumerate() {
        let Some((a, b, body)) = frames(line, '{', '}') else { continue };
        // `{1}{1}23.976` or `{0}{}25.000 FPS`.
        let number: String = body.trim().chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        if n == 0
            && let Ok(rate) = number.parse::<f64>()
            && rate > 0.0
            && rate < 1000.0
        {
            fps = Some(rate);
            continue;
        }
        let mut raw = String::new();
        for part in body.split('|') {
            let mut part = part;
            // Control codes: `{y:i}`, `{c:$0000ff}`, `{P:1}`.
            while let Some(rest) = part.strip_prefix('{')
                && let Some((code, tail)) = rest.split_once('}')
                && code.len() >= 2
                && code.as_bytes()[1] == b':'
            {
                note_microdvd(code, &mut s);
                part = tail;
            }
            if !raw.is_empty() {
                raw.push('\n');
            }
            raw.push_str(part);
        }
        parsed.push((a, b, raw));
    }
    let rate = fps.unwrap_or(MICRODVD_DEFAULT_FPS);
    if fps.is_none() {
        s.set("frame_rate_assumed", true);
    }
    s.frame_rate = Some(rate);
    for (a, b, raw) in parsed {
        let text = plain_text(&raw, &mut s.markup);
        s.push(Cue { start: a as f64 / rate, end: b.map(|b| b as f64 / rate), text, speaker: None });
    }
    // `{start}{}`: shown until the next cue.
    s.cues.sort_by(|a, b| a.start.total_cmp(&b.start));
    s.close_open_cues();
    s
}

fn note_microdvd(code: &str, s: &mut Subtitles) {
    let kind = match code.as_bytes()[0].to_ascii_lowercase() {
        b'y' => match code[2..].to_ascii_lowercase().as_str() {
            "i" => "italic",
            "b" => "bold",
            "u" => "underline",
            "s" => "strikethrough",
            _ => return,
        },
        b'c' => "colour",
        b'f' | b's' => "font",
        b'p' => "position",
        _ => return,
    };
    s.markup.insert(kind);
}

/// MPL2: times in tenths of a second, `|` line breaks, `/` for italics.
fn mpl2(text: &str) -> Subtitles {
    let mut s = Subtitles::new("mpl2");
    for line in text.lines().map(str::trim) {
        let Some((a, b, body)) = frames(line, '[', ']') else { continue };
        let mut lines = Vec::new();
        for part in body.split('|') {
            if let Some(p) = part.strip_prefix('/') {
                s.markup.insert("italic");
                lines.push(p);
            } else {
                lines.push(part);
            }
        }
        let text = plain_text(&lines.join("\n"), &mut s.markup);
        s.push(Cue { start: a as f64 / 10.0, end: b.map(|b| b as f64 / 10.0), text, speaker: None });
    }
    s
}

/// An LRC line: a time stamp or an ID tag.
fn lrc_line(l: &str) -> bool {
    let Some(rest) = l.strip_prefix('[') else { return false };
    let Some((tag, _)) = rest.split_once(']') else { return false };
    lrc_time(tag).is_some()
        || tag.split_once(':').is_some_and(|(k, _)| {
            matches!(
                k.to_ascii_lowercase().as_str(),
                "ti" | "ar" | "al" | "au" | "by" | "length" | "offset" | "re" | "ve" | "id" | "#" | "lang" | "tool"
            )
        })
}

/// `mm:ss.xx` (or `mm:ss:xx`, `mm:ss`) as seconds.
fn lrc_time(tag: &str) -> Option<f64> {
    let (m, rest) = tag.split_once(':')?;
    if m.is_empty() || !m.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let rest = match rest.split_once(':') {
        Some((s, f)) => format!("{s}.{f}"),
        None => rest.to_string(),
    };
    clock(&format!("{m}:{rest}"))
}

/// LRC lyrics: ID tags, then lines with one or more time stamps (enhanced
/// LRC adds `<mm:ss.xx>` word times inside the line).
fn lrc(text: &str) -> Subtitles {
    let mut s = Subtitles::new("text");
    let mut offset = 0.0;
    let mut cues: Vec<(f64, String)> = Vec::new();
    for line in text.lines().map(str::trim) {
        let mut rest = line;
        let mut times = Vec::new();
        while let Some(r) = rest.strip_prefix('[')
            && let Some((tag, tail)) = r.split_once(']')
        {
            if let Some(t) = lrc_time(tag) {
                times.push(t);
            } else if let Some((k, v)) = tag.split_once(':') {
                let v = v.trim();
                match k.trim().to_ascii_lowercase().as_str() {
                    "ti" => s.title = Some(v.to_string()),
                    "ar" => s.set("artist", v),
                    "al" => s.set("album", v),
                    "au" => s.author = Some(v.to_string()),
                    "by" => s.set("lyrics_by", v),
                    "length" => {
                        if let Some(l) = clock(v) {
                            s.set("length_s", super::ms(l));
                        }
                    }
                    "offset" => {
                        if let Ok(o) = v.trim_start_matches('+').parse::<f64>() {
                            offset = o / 1000.0;
                            s.set("offset_ms", o);
                        }
                    }
                    "re" | "tool" => s.set("generator", v),
                    "ve" => s.set("generator_version", v),
                    "lang" => s.declare_language(v, "lrc.lang"),
                    _ => {}
                }
            } else {
                break;
            }
            rest = tail;
        }
        for t in times {
            cues.push((t, rest.to_string()));
        }
    }
    cues.sort_by(|a, b| a.0.total_cmp(&b.0));
    for (t, raw) in cues {
        let text = plain_text(&raw, &mut s.markup);
        s.push(Cue { start: (t - offset).max(0.0), end: None, text, speaker: None });
    }
    s.close_open_cues();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("srt", "vtt", "sbv", "subviewer", "spruce_stl", "microdvd", "mpl2", "lrc");

    #[test]
    fn sniffs() {
        assert_eq!(sniff_text("1\n00:00:01,000 --> 00:00:02,000\nHi\n"), Some("srt"));
        assert_eq!(sniff_text("\u{feff}WEBVTT\n\n00:01.000 --> 00:02.000\nHi"), Some("vtt"));
        assert_eq!(sniff_text("0:00:01.000,0:00:02.000\nHi\n"), Some("sbv"));
        assert_eq!(sniff_text("[INFORMATION]\n[TITLE]x\n"), Some("subviewer"));
        assert_eq!(sniff_text("00:00:01.00,00:00:02.00\nHi\n"), Some("subviewer"));
        assert_eq!(sniff_text("{1}{1}25\n{25}{50}Hi\n"), Some("microdvd"));
        assert_eq!(sniff_text("[10][20]a\n[30][40]b\n[50][60]c\n"), Some("mpl2"));
        assert_eq!(sniff_text("[ti:Song]\n[ar:Band]\n[00:01.00]La\n"), Some("lrc"));
        assert_eq!(sniff_text("[TITLE]\nFilm\n**** START SCRIPT ****\n[00:00:01]\nHi\n"), Some("subviewer"));
        assert_eq!(sniff_text("// c\n$FontName = Arial\n00:00:01:00 , 00:00:02:00 , Hi\n"), Some("spruce_stl"));
        assert_eq!(sniff_text("[section]\nkey=value\n"), None);
        assert_eq!(sniff_text(""), None);
    }

    #[test]
    fn parses_each_dialect() {
        let sub = srt("1\n00:00:01,000 --> 00:00:02,500 X1:10\n<i>Hi</i>\n2\n00:00:03,000 --> 00:00:04,000\nBye\n");
        assert_eq!(sub.cues.len(), 2);
        assert_eq!((sub.cues[0].text.as_str(), sub.cues[0].end), ("Hi", Some(2.5)));
        assert!(sub.markup.contains("position") && sub.markup.contains("italic"));

        let web = vtt(
            "WEBVTT\nKind: captions\nLanguage: fr-CA\n\nNOTE x\n\nSTYLE\n::cue {}\n\nid1\n00:01.000 --> 00:02.000 align:start\n<v.loud Ana>Bonjour\n",
        );
        assert_eq!(web.cues[0].speaker.as_deref(), Some("Ana"));
        assert_eq!(web.language, Some(("fr".into(), "vtt.Language")));
        assert_eq!(web.format["notes"], 1);
        assert_eq!(web.format["cue_identifiers"], 1);

        let dvd = microdvd("{1}{1}25\n{25}{50}{y:i}One|two\n{75}{}Three\n");
        assert_eq!(dvd.frame_rate, Some(25.0));
        assert_eq!((dvd.cues[0].start, dvd.cues[0].end, dvd.cues[0].text.as_str()), (1.0, Some(2.0), "One\ntwo"));
        assert_eq!(dvd.cues[1].end, None);
        assert_eq!(microdvd("{0}{}25.000 FPS\n{25}{}a\n{50}{75}b\n").cues[0].end, Some(2.0));
        assert!(microdvd("{0}{25}x\n").format.contains_key("frame_rate_assumed"));

        let mpl = mpl2("[10][25]/Ital|plain\n");
        assert_eq!((mpl.cues[0].start, mpl.cues[0].end, mpl.cues[0].text.as_str()), (1.0, Some(2.5), "Ital\nplain"));

        let lyrics = lrc("[ti:T]\n[offset:+500]\n[00:02.00][00:10.50]Chorus\n[00:05.00]Verse <00:05.50>word\n");
        assert_eq!(lyrics.cues.iter().map(|c| c.start).collect::<Vec<_>>(), [1.5, 4.5, 10.0]);
        assert_eq!(lyrics.cues[0].end, Some(4.5));
        assert_eq!(lyrics.cues[1].text, "Verse word");
        assert!(lyrics.markup.contains("karaoke_timing"));

        let v1 = subviewer_v1(
            "[TITLE]\nFilm\n[DELAY]\n2\n**** START SCRIPT ****\n[00:00:01]\nOne|two\n[00:00:03]\n\n[00:00:04]\nThree\n",
        );
        assert_eq!(v1.cues.iter().map(|c| (c.start, c.end)).collect::<Vec<_>>(), [(3.0, Some(5.0)), (6.0, None)]);
        assert_eq!((v1.title.as_deref(), v1.cues[0].text.as_str()), (Some("Film"), "One\ntwo"));
        let st = spruce("$FontName = Arial\n$Italic = TRUE\n00:00:01:00 , 00:00:02:12 , ^IHi^I|there\n");
        assert_eq!((st.cues[0].start, st.cues[0].end, st.cues[0].text.as_str()), (1.0, Some(2.48), "Hi\nthere"));
        assert_eq!(st.format["fonts"], serde_json::json!(["Arial"]));
        let sv = comma_timed("[INFORMATION]\n[TITLE]Film\n[END INFORMATION]\n00:00:01.00,00:00:02.00\nA[br]B\n", true);
        assert_eq!((sv.title.as_deref(), sv.cues[0].text.as_str()), (Some("Film"), "A\nB"));
    }
}
