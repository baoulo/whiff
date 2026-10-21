//! Dev-time oracles: compare whiff with a reference tool, field by field.
//!
//! * `whiff-dev oracle images`: normalised image metadata against exiftool's
//!   MWG composite tags (`exiftool -use MWG`);
//! * `whiff-dev oracle media`: audio and video duration, sample rate and
//!   channels against `ffprobe`.
//! * `subtitles`: subtitle codecs, cue counts and the end of the last cue
//!   against `ffprobe`'s packets.
//!
//! The reference tools are never shipped. A field counts when the tool
//! reports it; whiff agreeing scores, whiff missing or differing does not.
//! Fields whiff finds that the tool does not report are not scored.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use whiff::Engine;

/// The fields of the Stage 2 exit criterion; the others are reported but not gated.
const GATED: &[&str] = &["title", "copyright", "captured", "location"];

pub fn images(paths: &[PathBuf], min: f64, verbose: bool) -> Result<(), String> {
    let files = collect(paths)?;
    if files.is_empty() {
        return Err("no files to compare".into());
    }
    let oracle = exiftool(&files);
    if oracle.is_empty() {
        return Err("exiftool read none of the files (is it installed? set WHIFF_EXIFTOOL)".into());
    }
    let engine = Engine::new();
    let mut tally: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    let mut misses = Vec::new();
    let mut compared = 0;
    for file in &files {
        let Some(expected) = oracle.get(file) else { continue };
        let report = engine.extract_path(file).map_err(|e| format!("{}: {e}", file.display()))?;
        if !report.identification.family.as_deref().is_some_and(|f| f.starts_with("image.")) {
            continue;
        }
        let got = serde_json::to_value(&report).map_err(|e| e.to_string())?;
        compared += 1;
        for check in compare(expected, &got) {
            let t = tally.entry(check.field).or_default();
            t.0 += 1;
            if check.ok {
                t.1 += 1;
            } else {
                misses.push((file.clone(), check));
            }
        }
    }

    println!("{:<12} {:>7} {:>7} {:>8}", "field", "checked", "agree", "rate");
    let (mut gated_n, mut gated_ok) = (0, 0);
    for (field, (n, ok)) in &tally {
        let gate = if GATED.contains(field) {
            gated_n += n;
            gated_ok += ok;
            "*"
        } else {
            ""
        };
        println!("{:<12} {n:>7} {ok:>7} {:>7.1}% {gate}", field, rate(*ok, *n));
    }
    let overall = rate(gated_ok, gated_n);
    println!("\n{compared} images; gated fields (*) agree on {overall:.1}% ({gated_ok}/{gated_n}), minimum {min}%");
    let shown = if verbose { misses.len() } else { misses.len().min(25) };
    if shown > 0 {
        println!(
            "\ndisagreements{}:",
            if shown < misses.len() { format!(" (first {shown} of {})", misses.len()) } else { String::new() }
        );
        for (file, c) in misses.iter().take(shown) {
            println!("  {} {}: exiftool {:?}, whiff {:?}", file.display(), c.field, c.expected, c.got);
        }
    }
    if gated_n > 0 && overall < min { Err(format!("agreement {overall:.1}% is below {min}%")) } else { Ok(()) }
}

fn rate(ok: u64, n: u64) -> f64 {
    if n == 0 { 100.0 } else { ok as f64 * 100.0 / n as f64 }
}

/// Files under `paths` (recursively), skipping `SOURCE.md` and hidden files.
fn collect(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = paths.to_vec();
    while let Some(p) = stack.pop() {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') || name == "SOURCE.md" {
            continue;
        }
        if p.is_dir() {
            let entries = std::fs::read_dir(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            stack.extend(entries.filter_map(|e| e.ok().map(|e| e.path())));
        } else if p.is_file() {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

/// exiftool's view of every file, keyed by path. `WHIFF_EXIFTOOL` overrides
/// the binary. If the batch run fails (exiftool can die on one file), each
/// file is read on its own and the ones that fail are skipped.
fn exiftool(files: &[PathBuf]) -> BTreeMap<PathBuf, Value> {
    if let Ok(all) = exiftool_batch(files) {
        return all;
    }
    let mut out = BTreeMap::new();
    for f in files {
        match exiftool_batch(std::slice::from_ref(f)) {
            Ok(one) => out.extend(one),
            Err(e) => eprintln!("oracle: skipping {}: {e}", f.display()),
        }
    }
    out
}

fn exiftool_batch(files: &[PathBuf]) -> Result<BTreeMap<PathBuf, Value>, String> {
    let bin = std::env::var("WHIFF_EXIFTOOL").unwrap_or_else(|_| "exiftool".into());
    let args = std::env::temp_dir().join(format!("whiff-oracle-{}.args", std::process::id()));
    let list = files.iter().map(|f| f.display().to_string()).collect::<Vec<_>>().join("\n");
    std::fs::write(&args, list).map_err(|e| e.to_string())?;
    let mut cmd = Command::new(&bin);
    cmd.args(["-j", "-n", "-q", "-q", "-G1", "-use", "MWG", "-api", "LargeFileSupport=1"]);
    cmd.args(["-MWG:all", "-XMP-dc:Title", "-IPTC:ObjectName", "-Composite:GPSLatitude", "-Composite:GPSLongitude"]);
    cmd.args(["-Composite:ImageSize", "-RawImageFullSize", "-@"]).arg(&args);
    let output = cmd.output().map_err(|e| format!("cannot run `{bin}` ({e}); install exiftool or set WHIFF_EXIFTOOL"));
    let _ = std::fs::remove_file(&args);
    let output = output?;
    let rows: Vec<Value> = serde_json::from_slice(&output.stdout).map_err(|e| format!("exiftool output: {e}"))?;
    Ok(rows.into_iter().filter_map(|r| Some((PathBuf::from(r.get("SourceFile")?.as_str()?), r))).collect())
}

#[derive(Debug)]
struct Check {
    field: &'static str,
    ok: bool,
    expected: String,
    got: String,
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::Array(a) => a.first().and_then(text),
        _ => None,
    }
    .filter(|s| !s.is_empty())
}

fn list(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().filter_map(text).collect(),
        other => text(other).into_iter().collect(),
    }
}

/// `2024:05:01 19:42:10+02:00` → (`2024-05-01T19:42:10`, `Some("+02:00")`).
fn exif_date(s: &str) -> Option<(String, Option<String>)> {
    let b = s.as_bytes();
    if b.len() < 19 || !s.is_char_boundary(19) {
        return None;
    }
    let civil = format!("{}-{}-{}T{}", s.get(..4)?, s.get(5..7)?, s.get(8..10)?, s.get(11..19)?);
    let rest = s[19..].trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    let zone = match rest {
        "Z" | "+00:00" => Some("+00:00".to_string()),
        z if z.len() == 6 && (z.starts_with('+') || z.starts_with('-')) => Some(z.to_string()),
        _ => None,
    };
    Some((civil, zone))
}

/// whiff's RFC 3339 / civil value in the same form.
fn whiff_date(s: &str) -> Option<(String, Option<String>)> {
    let civil = s.get(..19)?.to_string();
    let rest = s[19..].trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    let zone = match rest {
        "Z" => Some("+00:00".to_string()),
        z if z.len() == 6 => Some(z.to_string()),
        _ => None,
    };
    Some((civil, zone))
}

fn compare(exp: &Value, got: &Value) -> Vec<Check> {
    let mut out = Vec::new();
    let mut push = |field, expected: String, got: Option<String>, ok: bool| {
        out.push(Check { field, ok, expected, got: got.unwrap_or_default() });
    };
    let g = |path: &str| got.pointer(path).and_then(text);

    let title = exp.get("XMP-dc:Title").or_else(|| exp.get("IPTC:ObjectName")).and_then(text);
    if let Some(t) = title {
        let w = g("/content/title");
        push("title", t.clone(), w.clone(), w.as_deref() == Some(t.as_str()));
    }
    if let Some(d) = exp.get("MWG:Description").and_then(text) {
        let w = g("/content/description");
        push("description", d.clone(), w.clone(), w.as_deref() == Some(d.as_str()));
    }
    if let Some(c) = exp.get("MWG:Copyright").and_then(text) {
        let w = g("/rights/copyright");
        push("copyright", c.clone(), w.clone(), w.as_deref() == Some(c.as_str()));
    }
    let creators = exp.get("MWG:Creator").map(list).unwrap_or_default();
    if !creators.is_empty() {
        let w = got.pointer("/rights/creators").map(list).unwrap_or_default();
        push("creator", creators.join("; "), Some(w.join("; ")), w == creators);
    }
    let keywords = exp.get("MWG:Keywords").map(list).unwrap_or_default();
    if !keywords.is_empty() {
        let w: Vec<String> = got.pointer("/content/keywords").map(list).unwrap_or_default();
        let lower: Vec<String> = w.iter().map(|k| k.to_lowercase()).collect();
        let ok = keywords.iter().all(|k| lower.contains(&k.to_lowercase()));
        push("keywords", keywords.join(", "), Some(w.join(", ")), ok);
    }
    if let Some((civil, zone)) = exp.get("MWG:DateTimeOriginal").and_then(text).as_deref().and_then(exif_date) {
        let captured = got
            .pointer("/temporal/content")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().find(|d| d["field"] == "captured"))
            .and_then(|d| d["value"].as_str())
            .map(str::to_string);
        let w = captured.as_deref().and_then(whiff_date);
        // A zone exiftool knows must match; one only whiff knows is extra information.
        let ok = w.as_ref().is_some_and(|(c, z)| *c == civil && (zone.is_none() || *z == zone));
        push("captured", format!("{civil}{}", zone.unwrap_or_default()), captured, ok);
    }
    if let (Some(lat), Some(lon)) = (
        exp.get("Composite:GPSLatitude").and_then(Value::as_f64),
        exp.get("Composite:GPSLongitude").and_then(Value::as_f64),
    ) {
        let w = (
            got.pointer("/content/location/lat").and_then(Value::as_f64),
            got.pointer("/content/location/lon").and_then(Value::as_f64),
        );
        let ok = matches!(w, (Some(a), Some(b)) if (a - lat).abs() < 1e-4 && (b - lon).abs() < 1e-4);
        push("location", format!("{lat:.5},{lon:.5}"), w.0.zip(w.1).map(|(a, b)| format!("{a:.5},{b:.5}")), ok);
    }
    // whiff reports a raw file's sensor size; exiftool's ImageSize may be a preview's.
    let raw_size =
        exp.as_object().and_then(|m| m.iter().find(|(k, _)| k.ends_with(":RawImageFullSize")).map(|(_, v)| v));
    if let Some(size) = raw_size.or_else(|| exp.get("Composite:ImageSize")).and_then(Value::as_str) {
        let expected = size.replace(' ', "x");
        let w = got
            .pointer("/physical/image")
            .and_then(|i| Some(format!("{}x{}", i.get("width")?.as_u64()?, i.get("height")?.as_u64()?)));
        let ok = w.as_deref() == Some(expected.as_str());
        push("size", expected, w, ok);
    }
    out
}

/// Compare durations (within `tolerance` seconds), the first audio stream's
/// sample rate and channel count, and the first video stream's codec, size
/// and frame rate (within 1 %) of every audio / video file under `paths`
/// with `ffprobe`.
/// `WHIFF_FFPROBE` overrides the binary. Fails if durations agree on less
/// than `min` percent of the files ffprobe gives one for.
#[allow(clippy::too_many_lines)] // one check per field, then the summary
pub fn media(paths: &[PathBuf], tolerance: f64, min: f64, verbose: bool) -> Result<(), String> {
    let files = collect(paths)?;
    let engine = Engine::new();
    let bin = std::env::var("WHIFF_FFPROBE").unwrap_or_else(|_| "ffprobe".into());
    let mut tally: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    let mut misses = Vec::new();
    let mut compared = 0;
    let mut untrimmed_only = 0u64;
    let mut upmixed = 0u64;
    for file in &files {
        let report = engine.extract_path(file).map_err(|e| format!("{}: {e}", file.display()))?;
        let family = report.identification.family.as_deref().unwrap_or("");
        if family != "audio" && family != "video" {
            continue;
        }
        let Some(expected) = ffprobe(&bin, file)? else { continue };
        compared += 1;
        let media = report.physical.media.as_ref();
        let first = |kind: &str| {
            media.and_then(|m| m.streams.iter().find(|s| s.get("type").and_then(Value::as_str) == Some(kind)))
        };
        let (stream, video) = (first("audio"), first("video"));
        let mut check = |field: &'static str, want: String, got: Option<String>, ok: bool| {
            let t = tally.entry(field).or_default();
            t.0 += 1;
            if ok {
                t.1 += 1;
            } else {
                misses.push((file.clone(), Check { field, ok, expected: want, got: got.unwrap_or_default() }));
            }
        };
        if let Some(d) = expected.duration {
            let got = media.and_then(|m| m.duration_s);
            // ffprobe keeps the encoder priming and padding that a CAF packet
            // table or an MP4 edit list tells whiff to trim; either length agrees.
            let exact = got.is_some_and(|g| (g - d).abs() <= tolerance);
            let untrimmed = !exact && untrimmed(&report).is_some_and(|u| (u - d).abs() <= tolerance);
            if untrimmed {
                untrimmed_only += 1;
            }
            check("duration", format!("{d:.3}"), got.map(|g| format!("{g:.3}")), exact || untrimmed);
        }
        let field = |k: &str| stream.and_then(|s| s.get(k)).and_then(Value::as_u64);
        if let Some(r) = expected.sample_rate {
            let got = field("sample_rate_hz");
            // ffprobe gives DSD's byte rate (one byte holds eight 1-bit samples).
            let dsd = stream
                .and_then(|s| s.get("codec"))
                .and_then(Value::as_str)
                .is_some_and(|c| c.starts_with("dsd") || c == "dst");
            let want = if dsd { r * 8 } else { r };
            check("sample_rate", want.to_string(), got.map(|g| g.to_string()), got == Some(want));
        }
        if let Some(c) = expected.channels {
            let got = field("channels");
            // ffmpeg decodes mono HE-AAC to stereo (parametric stereo may be
            // signalled implicitly); whiff reports the configuration's count.
            let he_mono = got == Some(1)
                && c == 2
                && stream.and_then(|s| s.get("profile")).and_then(Value::as_str) == Some("he_aac");
            if he_mono {
                upmixed += 1;
            }
            check("channels", c.to_string(), got.map(|g| g.to_string()), got == Some(c) || he_mono);
        }
        let vfield = |k: &str| video.and_then(|s| s.get(k));
        if let Some(codec) = &expected.video_codec {
            let got = vfield("codec").and_then(Value::as_str).map(str::to_string);
            check("video_codec", codec.clone(), got.clone(), got.as_deref() == Some(codec.as_str()));
        }
        if let Some((w, h)) = expected.size {
            let got = vfield("width").and_then(Value::as_u64).zip(vfield("height").and_then(Value::as_u64));
            check("video_size", format!("{w}x{h}"), got.map(|(a, b)| format!("{a}x{b}")), got == Some((w, h)));
        }
        if let Some(f) = expected.frame_rate {
            let got = vfield("frame_rate").and_then(Value::as_f64);
            let ok = got.is_some_and(|g| (g - f).abs() <= f * 0.01 + 0.001);
            check("frame_rate", format!("{f:.3}"), got.map(|g| format!("{g:.3}")), ok);
        }
    }
    if compared == 0 {
        return Err(format!("ffprobe gave nothing to compare (is `{bin}` installed? set WHIFF_FFPROBE)"));
    }
    println!("{:<12} {:>7} {:>7} {:>8}", "field", "checked", "agree", "rate");
    for (field, (n, ok)) in &tally {
        println!(
            "{:<12} {n:>7} {ok:>7} {:>7.1}%{}",
            field,
            rate(*ok, *n),
            if *field == "duration" { " *" } else { "" }
        );
    }
    let (n, ok) = tally.get("duration").copied().unwrap_or_default();
    let overall = rate(ok, n);
    println!(
        "\n{compared} files; durations (*) agree within {tolerance} s on {overall:.1}% ({ok}/{n}), minimum {min}%"
    );
    if untrimmed_only > 0 {
        println!("{untrimmed_only} of them agree only with priming and padding left in (ffprobe's media length)");
    }
    if upmixed > 0 {
        println!("{upmixed} mono HE-AAC streams counted as agreeing with ffprobe's stereo output");
    }
    let shown = if verbose { misses.len() } else { misses.len().min(25) };
    if shown > 0 {
        println!(
            "\ndisagreements{}:",
            if shown < misses.len() { format!(" (first {shown} of {})", misses.len()) } else { String::new() }
        );
        for (file, c) in misses.iter().take(shown) {
            println!("  {} {}: ffprobe {:?}, whiff {:?}", file.display(), c.field, c.expected, c.got);
        }
    }
    if n > 0 && overall < min { Err(format!("duration agreement {overall:.1}% is below {min}%")) } else { Ok(()) }
}

/// The length with encoder priming and padding left in: a CAF's packet
/// table totals, or the longest MP4 track's media duration.
fn untrimmed(report: &whiff::Report) -> Option<f64> {
    if let Some(t) = report.format.get("caf").and_then(|c| c.get("packet_table")) {
        let frames = t["valid_frames"].as_u64()? + t["priming_frames"].as_u64()? + t["remainder_frames"].as_u64()?;
        let rate = report.physical.media.as_ref()?.streams.first()?.get("sample_rate_hz")?.as_u64()?;
        return (rate > 0).then(|| frames as f64 / rate as f64);
    }
    let tracks = report.format.get(&report.identification.format)?.get("tracks")?.as_array()?;
    tracks.iter().filter_map(|t| t["duration_s"].as_f64()).reduce(f64::max)
}

/// What ffprobe reports for a file.
struct Probe {
    duration: Option<f64>,
    sample_rate: Option<u64>,
    channels: Option<u64>,
    video_codec: Option<String>,
    size: Option<(u64, u64)>,
    frame_rate: Option<f64>,
}

/// ffprobe's format duration and first audio and video streams, or `None`
/// if it cannot read the file. Attached pictures (cover art) are not video.
fn ffprobe(bin: &str, file: &Path) -> Result<Option<Probe>, String> {
    let entries = "format=duration:stream=codec_type,codec_name,sample_rate,channels,width,height,avg_frame_rate,\
                   r_frame_rate:stream_disposition=attached_pic";
    let output = Command::new(bin)
        .args(["-v", "error", "-of", "json", "-show_entries", entries])
        .arg(file)
        .output()
        .map_err(|e| format!("cannot run `{bin}` ({e}); install ffmpeg or set WHIFF_FFPROBE"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let v: Value = serde_json::from_slice(&output.stdout).map_err(|e| format!("ffprobe output: {e}"))?;
    let num = |v: Option<&Value>| v.and_then(|x| x.as_str().and_then(|s| s.parse::<f64>().ok()).or_else(|| x.as_f64()));
    let audio = v["streams"].as_array().and_then(|s| s.iter().find(|s| s["codec_type"] == "audio"));
    let video = v["streams"].as_array().and_then(|s| {
        s.iter().find(|s| s["codec_type"] == "video" && s.pointer("/disposition/attached_pic") != Some(&1.into()))
    });
    let rate = |key: &str| {
        let (n, d) = video?.get(key)?.as_str()?.split_once('/')?;
        let (n, d) = (n.parse::<f64>().ok()?, d.parse::<f64>().ok()?);
        (n > 0.0 && d > 0.0).then(|| n / d)
    };
    Ok(Some(Probe {
        video_codec: video.and_then(|s| s["codec_name"].as_str()).map(str::to_string),
        size: video.and_then(|s| s["width"].as_u64().zip(s["height"].as_u64())),
        // A frame rate only when the stream says it is constant (both agree).
        frame_rate: rate("avg_frame_rate").filter(|a| rate("r_frame_rate").is_some_and(|r| (r - a).abs() < 1e-6)),
        duration: num(v.pointer("/format/duration")).filter(|d| *d > 0.0),
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // sample rates are small integers
        sample_rate: num(audio.and_then(|a| a.get("sample_rate"))).map(|r| r as u64),
        channels: audio.and_then(|a| a["channels"].as_u64()),
    }))
}

/// Compare subtitle files with `ffprobe`'s packets: the codec, the cue
/// count and the end of the last cue (within `tolerance` seconds). ffmpeg
/// counts differently for some formats, so the whiff field compared is the
/// one that counts the same thing: PGS segments, SCC caption lines, the
/// default VobSub track. Fails if cue counts agree on less than `min`
/// percent of the files ffprobe reads.
pub fn subtitles(paths: &[PathBuf], tolerance: f64, min: f64, verbose: bool) -> Result<(), String> {
    let files = collect(paths)?;
    let engine = Engine::new();
    let bin = std::env::var("WHIFF_FFPROBE").unwrap_or_else(|_| "ffprobe".into());
    let mut tally: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    let mut misses = Vec::new();
    let mut compared = 0;
    let mut bracketed = 0u64;
    let mut unscored = 0u64;
    for file in &files {
        let report = engine.extract_path(file).map_err(|e| format!("{}: {e}", file.display()))?;
        if report.identification.family.as_deref() != Some("text.subtitle") {
            continue;
        }
        let id = report.identification.format.clone();
        // ffmpeg has no EBU STL reader (it tries Spruce STL text).
        if id == "ebu_stl" {
            continue;
        }
        let Some(p) = packets(&bin, file)? else { continue };
        compared += 1;
        let f = report.format.get(&id).cloned().unwrap_or_default();
        let stream = report.physical.media.as_ref().and_then(|m| m.streams.first());
        let mut check = |field: &'static str, want: String, got: String, ok: bool| {
            let t = tally.entry(field).or_default();
            t.0 += 1;
            if ok {
                t.1 += 1;
            } else {
                misses.push((file.clone(), Check { field, ok, expected: want, got }));
            }
        };
        let codec = stream.and_then(|s| s.get("codec")).and_then(Value::as_str).unwrap_or("");
        check("codec", p.codec.clone(), codec.to_string(), codec == p.codec);
        let count_field = match id.as_str() {
            "pgs" => "segments",
            "scc" => "timecode_lines",
            "sami" => "syncs",
            _ => "cues",
        };
        let mut got = f.get(count_field).and_then(Value::as_u64);
        // ffmpeg keeps LRC's blank lines (they clear the lyric) as packets.
        if id == "lrc" {
            got = got.map(|g| g + f.get("empty_cues").and_then(Value::as_u64).unwrap_or(0));
        }
        // ffmpeg keeps cues with negative times; whiff drops them.
        let p = Packets { count: p.count - p.negative, ..p };
        // ffmpeg's SubViewer reader takes a cue text starting with `[` for
        // a header tag and drops the cue.
        let dropped = if matches!(id.as_str(), "sbv" | "subviewer") { bracket_cues(file) } else { 0 };
        if dropped > 0 && got == Some(p.count + dropped) {
            bracketed += 1;
        }
        let ok = got == Some(p.count) || got == Some(p.count + dropped);
        check("cues", p.count.to_string(), got.map(|g| g.to_string()).unwrap_or_default(), ok);
        // ffmpeg reads Spruce STL's last timecode field as hundredths (it
        // counts frames), and LRC millisecond fractions as hundredths.
        let misread = id == "spruce_stl" || (id == "lrc" && millisecond_lrc(file));
        if misread {
            unscored += 1;
        }
        if let Some(end) = p.end.filter(|_| !misread) {
            let got = f.get("last_cue_end_s").and_then(Value::as_f64);
            let ok = got.is_some_and(|g| (g - end).abs() <= tolerance);
            check("last_cue_end", format!("{end:.3}"), got.map(|g| format!("{g:.3}")).unwrap_or_default(), ok);
        }
    }
    if compared == 0 {
        return Err(format!("ffprobe read no subtitle file (is `{bin}` installed? set WHIFF_FFPROBE)"));
    }
    println!("{:<12} {:>7} {:>7} {:>8}", "field", "checked", "agree", "rate");
    for (field, (n, ok)) in &tally {
        println!("{field:<12} {n:>7} {ok:>7} {:>7.1}%{}", rate(*ok, *n), if *field == "cues" { " *" } else { "" });
    }
    let (n, ok) = tally.get("cues").copied().unwrap_or_default();
    let overall = rate(ok, n);
    println!("\n{compared} files; cue counts (*) agree on {overall:.1}% ({ok}/{n}), minimum {min}%");
    if bracketed > 0 {
        println!(
            "{bracketed} SubViewer / SBV files agree once the cues ffmpeg drops (text starting with `[`) are counted"
        );
    }
    if unscored > 0 {
        println!(
            "{unscored} files' end times not scored: ffmpeg misreads their times (Spruce STL frames, LRC milliseconds)"
        );
    }
    let shown = if verbose { misses.len() } else { misses.len().min(25) };
    if shown > 0 {
        println!("\ndisagreements:");
        for (file, c) in misses.iter().take(shown) {
            println!("  {} {}: ffprobe {:?}, whiff {:?}", file.display(), c.field, c.expected, c.got);
        }
    }
    if overall < min { Err(format!("cue count agreement {overall:.1}% is below {min}%")) } else { Ok(()) }
}

/// SubViewer / SBV cues whose first text line starts with `[`.
fn bracket_cues(file: &Path) -> u64 {
    let text = std::fs::read(file).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let timing =
        |l: &str| l.split_once(',').is_some_and(|(a, b)| a.contains(':') && b.contains(':') && !a.contains(' '));
    lines.windows(2).filter(|w| timing(w[0]) && w[1].starts_with('[')).count() as u64
}

/// ffprobe's first subtitle stream: codec, packet count, and the latest
/// packet end (`None` unless every packet has a duration).
struct Packets {
    codec: String,
    count: u64,
    /// Packets with a negative time.
    negative: u64,
    end: Option<f64>,
}

/// An LRC file with millisecond time stamps (`[01:02.345]`).
fn millisecond_lrc(file: &Path) -> bool {
    let text = std::fs::read(file).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    text.lines().any(|l| fraction_digits(l) == Some(3))
}

/// Digits after the point of a line's leading LRC time stamp.
fn fraction_digits(line: &str) -> Option<usize> {
    let t = line.split(']').next()?.strip_prefix('[')?;
    if !t.starts_with(|c: char| c.is_ascii_digit() || c == '-') {
        return None;
    }
    t.rsplit_once('.').map(|(_, f)| f.len())
}

fn packets(bin: &str, file: &Path) -> Result<Option<Packets>, String> {
    let output = Command::new(bin)
        .args(["-v", "error", "-of", "json", "-select_streams", "s:0", "-show_packets"])
        .args(["-show_entries", "packet=pts_time,duration_time:stream=codec_name"])
        .arg(file)
        .output()
        .map_err(|e| format!("cannot run `{bin}` ({e}); install ffmpeg or set WHIFF_FFPROBE"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let v: Value = serde_json::from_slice(&output.stdout).map_err(|e| format!("ffprobe output: {e}"))?;
    let Some(codec) = v.pointer("/streams/0/codec_name").and_then(Value::as_str) else { return Ok(None) };
    let num = |x: &Value| x.as_str().and_then(|s| s.parse::<f64>().ok());
    let list = v["packets"].as_array().cloned().unwrap_or_default();
    let mut end = Some(0.0f64);
    let mut negative = 0;
    for pk in &list {
        let t = num(&pk["pts_time"]);
        if t.is_some_and(|t| t < 0.0) {
            negative += 1;
            continue;
        }
        // ffmpeg writes -1 (a tick) for a duration it does not know.
        end = match (end, t, num(&pk["duration_time"])) {
            (Some(e), Some(t), Some(d)) => Some(e.max(t + d.max(0.0))),
            _ => None,
        };
    }
    Ok(Some(Packets { codec: codec.to_string(), count: list.len() as u64, negative, end: end.filter(|e| *e > 0.0) }))
}

/// What `oracle images` compares when given no paths.
pub fn default_paths(root: &Path) -> Vec<PathBuf> {
    vec![root.join("tests/fixtures")]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_normalise() {
        assert_eq!(exif_date("2024:05:01 19:42:10+02:00"), Some(("2024-05-01T19:42:10".into(), Some("+02:00".into()))));
        assert_eq!(exif_date("2024:05:01 19:42:10.25"), Some(("2024-05-01T19:42:10".into(), None)));
        assert_eq!(whiff_date("2024-05-01T17:42:10Z"), Some(("2024-05-01T17:42:10".into(), Some("+00:00".into()))));
    }
}
