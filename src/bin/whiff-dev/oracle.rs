//! `whiff-dev oracle images`: compare whiff's normalised image metadata with
//! exiftool's MWG composite tags (`exiftool -use MWG`), field by field.
//!
//! exiftool is a dev-time oracle only. A field counts when exiftool reports
//! it; whiff agreeing scores, whiff missing or differing does not. Fields
//! whiff finds that exiftool does not report are not scored.

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
