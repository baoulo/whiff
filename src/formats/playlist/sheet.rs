//! PLS playlists (`[playlist]`: files, titles, lengths) and CUE sheets
//! (disc catalogue number, CD-TEXT title and performer, REM genre / date /
//! disc id / comment / ReplayGain, files with their types, tracks with
//! title, performer, songwriter, ISRC, flags, pre-gaps and index times; the
//! track lengths that follow from the index times).
//!
//! Specifications: the PLS format as Winamp and SHOUTcast write it; the CUE
//! sheet syntax of CDRWIN, as EAC, foobar2000 and `metaflac` write it.

use std::collections::{BTreeMap, BTreeSet};

use super::{Entry, Playlist, artist_title, round};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, parse_date, truncate_chars,
};

/// Extractor for PLS playlists and CUE sheets.
pub struct Sheet;

static META: ExtractorMeta = ExtractorMeta {
    id: "playlist.sheet",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "pls",
            name: "PLS playlist",
            family: "audio.playlist",
            mimes: &["audio/x-scpls"],
            extensions: &["pls"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "cue",
            name: "CUE sheet",
            family: "audio.playlist",
            mimes: &["application/x-cue"],
            extensions: &["cue"],
            magic: &[],
            parent: None,
        },
    ],
};

/// CD frames per second.
const FRAMES: f64 = 75.0;

impl Extractor for Sheet {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let text = super::super::subtitle::head_text(probe.head);
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
        let first = lines.next()?;
        if first.eq_ignore_ascii_case("[playlist]") {
            return Some(Sniff { format: "pls", confidence: 0.95 });
        }
        // A CUE sheet has a FILE and a TRACK command near the top.
        let head: Vec<&str> = std::iter::once(first).chain(lines).take(40).collect();
        let command = |l: &&str, c: &str| l.get(..c.len()).is_some_and(|p| p.eq_ignore_ascii_case(c));
        let cue = head.iter().any(|l| command(l, "FILE "))
            && head.iter().any(|l| command(l, "TRACK "))
            && head.iter().all(|l| {
                [
                    "REM",
                    "FILE",
                    "TRACK",
                    "INDEX",
                    "TITLE",
                    "PERFORMER",
                    "SONGWRITER",
                    "CATALOG",
                    "CDTEXTFILE",
                    "ISRC",
                    "FLAGS",
                    "PREGAP",
                    "POSTGAP",
                ]
                .iter()
                .any(|c| command(l, c))
            });
        cue.then_some(Sniff { format: "cue", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.checkpoint()?;
        let p = if cx.format_id() == "cue" { cue(&text) } else { pls(&text) };
        p.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Sheet);

fn pls(text: &str) -> Playlist {
    let mut p = Playlist::default();
    let mut entries: BTreeMap<u32, Entry> = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        let Some((name, v)) = line.split_once('=') else { continue };
        let (name, v) = (name.trim().to_ascii_lowercase(), v.trim());
        let split = name.find(|c: char| c.is_ascii_digit()).unwrap_or(name.len());
        let (key, number) = name.split_at(split);
        let Ok(number) = number.parse::<u32>() else {
            match key {
                "numberofentries" => p.set("declared_entries", v.parse::<u64>().ok()),
                "version" => p.set("version", v.parse::<u32>().ok()),
                "x-gnome-title" | "title" => p.title = Some(v.to_string()),
                _ => {}
            }
            continue;
        };
        if entries.len() >= super::MAX_ENTRIES && !entries.contains_key(&number) {
            continue;
        }
        let entry = entries.entry(number).or_default();
        match key {
            "file" => entry.location = Some(v.to_string()),
            "title" => (entry.artist, entry.title) = artist_title(v),
            "length" => entry.duration = v.parse::<f64>().ok().filter(|d| *d >= 0.0),
            _ => {}
        }
    }
    for (_, entry) in entries {
        p.push(entry);
    }
    p
}

/// A quoted or bare CUE argument and the rest of the line.
fn argument(s: &str) -> (String, &str) {
    let s = s.trim_start();
    if let Some(q) = s.strip_prefix('"') {
        let end = q.find('"').unwrap_or(q.len());
        return (q[..end].to_string(), q.get(end + 1..).unwrap_or("").trim_start());
    }
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    (s[..end].to_string(), s[end..].trim_start())
}

/// `mm:ss:ff` (75 frames a second) as seconds.
fn msf(s: &str) -> Option<f64> {
    let p: Vec<u32> = s.trim().split(':').map(|x| x.parse().ok()).collect::<Option<_>>()?;
    let [m, sec, f] = p[..] else { return None };
    (sec < 60 && f < 75).then(|| f64::from(m) * 60.0 + f64::from(sec) + f64::from(f) / FRAMES)
}

/// One CUE track.
#[derive(Default)]
struct Track {
    number: u32,
    kind: String,
    file: Option<String>,
    title: Option<String>,
    performer: Option<String>,
    start: Option<f64>,
}

#[allow(clippy::too_many_lines)] // one pass over the commands
fn cue(text: &str) -> Playlist {
    let mut p = Playlist::default();
    let mut tracks: Vec<Track> = Vec::new();
    let mut files: Vec<(String, String)> = Vec::new();
    let mut flags: BTreeSet<String> = BTreeSet::new();
    let (mut isrcs, mut pregaps, mut songwriters) = (0u64, 0u64, BTreeSet::new());
    let mut rem: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        let (cmd, rest) = argument(line);
        let cmd = cmd.to_ascii_uppercase();
        let in_track = !tracks.is_empty();
        match cmd.as_str() {
            "REM" => {
                let (k, v) = argument(rest);
                let v = v.trim().trim_matches('"');
                if !v.is_empty() && rem.len() < 32 {
                    rem.entry(k.to_ascii_lowercase()).or_insert_with(|| truncate_chars(v, 200));
                }
            }
            "CATALOG" => p.set("catalog", argument(rest).0),
            "CDTEXTFILE" => p.set("cdtext_file", super::Location::of(&argument(rest).0).name),
            "FILE" => {
                let (name, kind) = argument(rest);
                files.push((name, kind.trim().to_ascii_lowercase()));
            }
            "TRACK" => {
                let (n, kind) = argument(rest);
                tracks.push(Track {
                    number: n.parse().unwrap_or(0),
                    kind: kind.trim().to_ascii_lowercase(),
                    file: files.last().map(|f| f.0.clone()),
                    ..Track::default()
                });
            }
            "TITLE" | "PERFORMER" | "SONGWRITER" => {
                let v = argument(rest).0;
                match (cmd.as_str(), tracks.last_mut()) {
                    ("TITLE", Some(t)) => t.title = Some(v),
                    ("PERFORMER", Some(t)) => t.performer = Some(v),
                    ("TITLE", None) => p.title = Some(v),
                    ("PERFORMER", None) => p.author = Some(v),
                    ("SONGWRITER", _) if songwriters.len() < 20 => {
                        songwriters.insert(v);
                    }
                    _ => {}
                }
            }
            "ISRC" if in_track => isrcs += 1,
            "FLAGS" => {
                for fl in rest.split_whitespace() {
                    flags.insert(fl.to_ascii_lowercase());
                }
            }
            "PREGAP" => pregaps += 1,
            "INDEX" => {
                let (n, t) = argument(rest);
                if n.parse::<u32>().ok() == Some(1)
                    && let Some(track) = tracks.last_mut()
                {
                    track.start = msf(t);
                }
            }
            _ => {}
        }
    }
    let data = tracks.iter().filter(|t| t.kind != "audio").count();
    // A track lasts until the next track of the same file starts.
    for i in 0..tracks.len() {
        let next = tracks.get(i + 1).filter(|n| n.file == tracks[i].file).and_then(|n| n.start);
        let t = &tracks[i];
        let duration = match (t.start, next) {
            (Some(a), Some(b)) if b >= a => Some(b - a),
            _ => None,
        };
        let performer = t.performer.clone().or_else(|| p.author.clone());
        p.push(Entry {
            location: t.file.clone(),
            title: t.title.clone(),
            artist: performer,
            album: p.title.clone(),
            duration,
            group: None,
        });
    }
    if let Some(d) = rem.get("date").and_then(|d| parse_date(d).or_else(|| year(d))) {
        p.date = Some(d);
    }
    if let Some(g) = rem.get("genre") {
        p.genres.push(g.clone());
    }
    p.set("tracks", tracks.len());
    let starts: Vec<serde_json::Value> = tracks
        .iter()
        .take(99)
        .map(|t| serde_json::json!({ "track": t.number, "start_s": t.start.map(round) }))
        .collect();
    p.set("track_starts", starts);
    p.set(
        "files",
        files
            .iter()
            .take(50)
            .map(|(n, k)| serde_json::json!({ "file": super::Location::of(n).name, "type": k }))
            .collect::<Vec<_>>(),
    );
    if data > 0 {
        p.set("data_tracks", data);
        p.set("disc_image", true);
    }
    if isrcs > 0 {
        p.set("isrc_codes", isrcs);
    }
    if pregaps > 0 {
        p.set("pregaps", pregaps);
    }
    p.set("flags", flags.into_iter().collect::<Vec<_>>());
    p.set("songwriters", songwriters.into_iter().collect::<Vec<_>>());
    p.set("rem", serde_json::Value::Object(rem.into_iter().map(|(k, v)| (k, v.into())).collect()));
    p
}

/// A bare year (`REM DATE 1987`).
fn year(s: &str) -> Option<(String, bool)> {
    let s = s.trim();
    (s.len() == 4 && s.bytes().all(|b| b.is_ascii_digit())).then(|| (s.to_string(), false))
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("pls", "cue");

    #[test]
    fn sheets() {
        let p = pls(
            "[playlist]\nFile1=http://radio.example/live\nTitle1=Harbour FM\nLength1=-1\nFile2=b.mp3\nTitle2=Band - Song\nLength2=180\nNumberOfEntries=2\nVersion=2\n",
        );
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.entries[0].duration, None);
        assert_eq!((p.entries[1].artist.as_deref(), p.entries[1].duration), (Some("Band"), Some(180.0)));
        assert_eq!(p.format["declared_entries"], 2);

        let c = cue(
            "REM GENRE Folk\nREM DATE 1999\nPERFORMER \"Band\"\nTITLE \"Album\"\nFILE \"disc.flac\" WAVE\n  TRACK 01 AUDIO\n    TITLE \"One\"\n    INDEX 01 00:00:00\n  TRACK 02 AUDIO\n    TITLE \"Two\"\n    PERFORMER \"Guest\"\n    INDEX 00 03:00:00\n    INDEX 01 03:02:37\n",
        );
        assert_eq!(c.entries.len(), 2);
        assert_eq!(c.entries[0].duration, Some(182.0 + 37.0 / 75.0));
        assert_eq!(c.entries[1].artist.as_deref(), Some("Guest"));
        assert_eq!((c.title.as_deref(), c.author.as_deref()), (Some("Album"), Some("Band")));
        assert_eq!(c.date, Some(("1999".into(), false)));
        assert_eq!(c.genres, ["Folk"]);
        assert_eq!(msf("01:02:74"), Some(62.0 + 74.0 / 75.0));
        assert_eq!(msf("01:02:75"), None);
    }
}
