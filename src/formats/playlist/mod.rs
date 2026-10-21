//! `audio.playlist` extractors (feature `common`): playlists, cue sheets and
//! streaming manifests. Every format is read into [`Playlist`] (entries
//! with locations, titles, artists and durations, plus format facts) and
//! reported the same way: entry count, declared duration, where entries
//! point (local files or hosts), file types, and the titles as text.
//!
//! Locations are reported by file name (and host for URLs) only: paths
//! name folders and users, and query strings can carry access tokens.

pub(crate) mod m3u;
pub(crate) mod manifest;
pub(crate) mod sheet;
pub(crate) mod xml;

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::text::url_host;
use crate::plugin::{Context, DateField, TextRole, truncate_chars};

/// Entries kept per playlist.
pub(crate) const MAX_ENTRIES: usize = 1 << 20;
/// Entries listed in the report.
const MAX_LISTED: usize = 50;
/// Hosts, groups and file types listed.
const MAX_KEYS: usize = 20;

/// One playlist entry.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Entry {
    /// File path or URL as written.
    pub location: Option<String>,
    pub title: Option<String>,
    pub artist: Option<String>,
    pub album: Option<String>,
    /// Seconds; `None` when unknown (or -1 in the file).
    pub duration: Option<f64>,
    /// IPTV `group-title`, CUE file, …
    pub group: Option<String>,
}

/// A playlist, as every format reads it.
#[derive(Debug, Default)]
pub(crate) struct Playlist {
    pub entries: Vec<Entry>,
    pub title: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub copyright: Option<String>,
    /// Licence URL (XSPF).
    pub license: Option<String>,
    pub genres: Vec<String>,
    pub date: Option<(String, bool)>,
    /// Total duration stated by the file (DASH, Smooth Streaming, WPL),
    /// preferred over the sum of the entries.
    pub duration: Option<f64>,
    /// Encrypted media (HLS keys, DRM systems).
    pub encrypted: bool,
    /// The sum of the entry durations is the presentation length (an HLS
    /// media playlist, a CUE sheet does not have one).
    pub sum_is_length: bool,
    /// Entries dropped because the file has more than [`MAX_ENTRIES`].
    pub dropped: u64,
    /// Entries are segments or renditions (streaming manifests): counted,
    /// not listed.
    pub unlisted: bool,
    /// Format-specific fields.
    pub format: Map<String, Value>,
}

impl Playlist {
    pub(crate) fn push(&mut self, mut e: Entry) {
        if self.entries.len() >= MAX_ENTRIES {
            self.dropped += 1;
            return;
        }
        e.duration = e.duration.filter(|d| d.is_finite() && *d >= 0.0);
        for f in [&mut e.title, &mut e.artist, &mut e.album, &mut e.location, &mut e.group] {
            if f.as_deref().is_some_and(|v| v.trim().is_empty()) {
                *f = None;
            }
        }
        self.entries.push(e);
    }

    /// Set a format field unless it is null or empty.
    pub(crate) fn set(&mut self, key: &str, v: impl Into<Value>) {
        let v = v.into();
        let empty = match &v {
            Value::Null => true,
            Value::String(s) => s.trim().is_empty(),
            Value::Array(a) => a.is_empty(),
            Value::Object(o) => o.is_empty(),
            _ => false,
        };
        if !empty {
            self.format.insert(key.into(), v);
        }
    }

    /// Write the report.
    #[allow(clippy::too_many_lines)] // one pass over the entries, then the fields
    pub(crate) fn report(mut self, cx: &mut Context<'_>) {
        let n = self.entries.len();
        let (mut remote, mut local, mut timed) = (0u64, 0u64, 0u64);
        let mut sum = 0.0;
        let mut hosts: BTreeMap<String, u64> = BTreeMap::new();
        let mut types: BTreeMap<String, u64> = BTreeMap::new();
        let mut groups: BTreeMap<String, u64> = BTreeMap::new();
        let mut text = String::new();
        let mut listed = Vec::new();
        for e in &self.entries {
            if let Some(d) = e.duration {
                timed += 1;
                sum += d;
            }
            let loc = e.location.as_deref().map(Location::of);
            match &loc {
                Some(Location { host: Some(h), .. }) => {
                    remote += 1;
                    *hosts.entry(h.clone()).or_default() += 1;
                }
                Some(_) => local += 1,
                None => {}
            }
            if let Some(ext) = loc.as_ref().and_then(|l| l.extension.clone()) {
                *types.entry(ext).or_default() += 1;
            }
            if let Some(g) = &e.group {
                *groups.entry(truncate_chars(g.trim(), 80)).or_default() += 1;
            }
            let line = match (&e.artist, &e.title) {
                (Some(a), Some(t)) => format!("{a} - {t}"),
                (None, Some(t)) => t.clone(),
                (Some(a), None) => a.clone(),
                (None, None) => String::new(),
            };
            if !line.is_empty() && text.len() < 1 << 20 {
                text.push_str(&line);
                text.push('\n');
            }
            if !self.unlisted && listed.len() < MAX_LISTED {
                let mut m = Map::new();
                for (k, v) in [("title", &e.title), ("artist", &e.artist), ("album", &e.album)] {
                    if let Some(v) = v {
                        m.insert(k.into(), json!(truncate_chars(v.trim(), 200)));
                    }
                }
                if let Some(d) = e.duration {
                    m.insert("duration_s".into(), json!(round(d)));
                }
                if let Some(l) = &loc {
                    if let Some(h) = &l.host {
                        m.insert("host".into(), json!(h));
                    }
                    if let Some(f) = &l.name {
                        m.insert("file".into(), json!(truncate_chars(f, 200)));
                    }
                }
                if !m.is_empty() {
                    listed.push(Value::Object(m));
                }
            }
        }

        if let Some(t) = self.title.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            cx.content().source("playlist.title").title(truncate_chars(t, 300));
            cx.emit_text(TextRole::Title, t);
        }
        if let Some(a) = self.author.as_deref().map(str::trim).filter(|a| !a.is_empty()) {
            cx.content().source("playlist.author").author(truncate_chars(a, 200));
        }
        if let Some(d) = self.description.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
            cx.content().source("playlist.description").description(truncate_chars(d, 2000));
            cx.emit_text(TextRole::Body, d);
        }
        if let Some(c) = self.copyright.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
            cx.rights().source("playlist.copyright").copyright(truncate_chars(c, 300));
        }
        if let Some(l) = self.license.as_deref().map(str::trim).filter(|l| !l.is_empty()) {
            let url = l.starts_with("http").then_some(l);
            cx.rights().source("playlist.license").license(url.is_none().then_some(l), url);
        }
        for g in &self.genres {
            cx.content().source("playlist.genre").tag(g.clone());
        }
        if let Some((d, tz)) = self.date.clone() {
            cx.temporal().source("playlist.date").content_date(DateField::Created, d, tz);
        }
        if !text.is_empty() {
            cx.emit_text(TextRole::Body, &text);
        }
        if remote > 0 {
            cx.security().external_references(remote);
        }
        if self.encrypted {
            cx.security().encrypted(true);
        }
        let all_timed = n > 0 && timed == n as u64;
        let length = self.duration.or((all_timed && self.sum_is_length).then_some(sum)).filter(|d| *d > 0.0);
        {
            let mut p = cx.physical();
            p.entries(n as u64);
            if let Some(d) = length {
                p.duration_s(round(d));
            }
        }

        let mut f = Map::new();
        f.insert("entries".into(), json!(n));
        if timed > 0 {
            f.insert("declared_duration_s".into(), json!(round(sum)));
            if !all_timed {
                f.insert("entries_with_duration".into(), json!(timed));
            }
        }
        if local > 0 {
            f.insert("local_entries".into(), json!(local));
        }
        if remote > 0 {
            f.insert("remote_entries".into(), json!(remote));
            f.insert("hosts".into(), top(hosts));
        }
        if !types.is_empty() {
            f.insert("file_types".into(), top(types));
        }
        if !groups.is_empty() {
            f.insert("groups".into(), json!(groups.len()));
            f.insert("top_groups".into(), top(groups));
        }
        if self.dropped > 0 {
            f.insert("entries_not_read".into(), json!(self.dropped));
        }
        f.append(&mut self.format);
        if !listed.is_empty() {
            f.insert("listed".into(), Value::Array(listed));
        }
        cx.format().append(&mut f);
    }
}

/// The most frequent keys, at most [`MAX_KEYS`].
fn top(counts: BTreeMap<String, u64>) -> Value {
    let mut v: Vec<(String, u64)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Value::Object(v.into_iter().take(MAX_KEYS).map(|(k, n)| (k, json!(n))).collect())
}

/// Seconds rounded to the millisecond.
pub(crate) fn round(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// What the report keeps of a location: the host of a URL, the file name
/// and its extension.
#[derive(Debug, PartialEq)]
pub(crate) struct Location {
    pub host: Option<String>,
    pub name: Option<String>,
    pub extension: Option<String>,
}

impl Location {
    pub(crate) fn of(loc: &str) -> Self {
        let loc = loc.trim();
        let host = url_host(loc).filter(|_| !loc.to_ascii_lowercase().starts_with("file:"));
        let path = loc.split(['?', '#']).next().unwrap_or(loc);
        let path =
            if let Some((_, rest)) = path.split_once("://") { rest.split_once('/').map_or("", |x| x.1) } else { path };
        let name = path.rsplit(['/', '\\']).next().map(percent_decode).filter(|n| !n.is_empty());
        let extension = name.as_deref().and_then(|n| {
            let (stem, ext) = n.rsplit_once('.')?;
            (!stem.is_empty() && (1..=5).contains(&ext.len()) && ext.chars().all(|c| c.is_ascii_alphanumeric()))
                .then(|| ext.to_ascii_lowercase())
        });
        Self { host, name, extension }
    }
}

/// `%20` → space; invalid escapes stay as written.
fn percent_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(h) = s.get(i + 1..i + 3)
            && let Ok(v) = u8::from_str_radix(h, 16)
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// DRM system names for the ids DASH, Smooth Streaming and HLS key formats
/// use (PSSH system ids).
pub(crate) fn drm_system(id: &str) -> Option<&'static str> {
    let id = id.trim().trim_start_matches("urn:uuid:").trim_matches(['{', '}']).to_ascii_lowercase();
    Some(match id.as_str() {
        "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed" => "widevine",
        "9a04f079-9840-4286-ab92-e65be0885f95" | "com.microsoft.playready" => "playready",
        "94ce86fb-07ff-4f43-adb8-93d2fa968ca2" | "com.apple.streamingkeydelivery" => "fairplay",
        "e2719d58-a985-b3c9-781a-b030af78d30e" | "1077efec-c0b2-4d02-ace3-3c1e52e2fb4b" | "org.w3.clearkey" => {
            "clearkey"
        }
        "5e629af5-38da-4063-8977-97ffbd9902d4" => "marlin",
        "f239e769-efa3-4850-9c16-a903c6932efb" => "primetime",
        "80a6be7e-1448-4c37-9e70-d5aebe04c8d2" => "irdeto",
        "3d5e6d35-9b9a-41e8-b843-dd3c6e72c42c" => "chinadrm",
        _ => return None,
    })
}

/// An ISO 8601 duration (`PT1H2M3.5S`, `P1DT2H`) in seconds.
pub(crate) fn iso_duration(s: &str) -> Option<f64> {
    let s = s.trim().strip_prefix('P')?;
    let (date, time) = s.split_once('T').unwrap_or((s, ""));
    let mut total = 0.0;
    let mut add = |part: &str, units: &[(char, f64)]| -> Option<()> {
        let mut num = String::new();
        for c in part.chars() {
            if c.is_ascii_digit() || c == '.' {
                num.push(c);
            } else {
                let &(_, scale) = units.iter().find(|(u, _)| *u == c)?;
                total += num.parse::<f64>().ok()? * scale;
                num.clear();
            }
        }
        num.is_empty().then_some(())
    };
    add(date, &[('Y', 365.0 * 86_400.0), ('M', 30.0 * 86_400.0), ('W', 7.0 * 86_400.0), ('D', 86_400.0)])?;
    add(time, &[('H', 3600.0), ('M', 60.0), ('S', 1.0)])?;
    total.is_finite().then_some(total)
}

/// `Artist - Title` split on the first ` - `.
pub(crate) fn artist_title(s: &str) -> (Option<String>, Option<String>) {
    let s = s.trim();
    match s.split_once(" - ") {
        Some((a, t)) if !a.trim().is_empty() && !t.trim().is_empty() => {
            (Some(a.trim().to_string()), Some(t.trim().to_string()))
        }
        _ => (None, (!s.is_empty()).then(|| s.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        let l = Location::of("https://cdn.example.org/a/b/seg%201.ts?token=secret");
        assert_eq!(
            l,
            Location {
                host: Some("cdn.example.org".into()),
                name: Some("seg 1.ts".into()),
                extension: Some("ts".into())
            }
        );
        let l = Location::of("C:\\Music\\Band\\01 Song.flac");
        assert_eq!((l.host, l.name.as_deref(), l.extension.as_deref()), (None, Some("01 Song.flac"), Some("flac")));
        assert_eq!(Location::of("file:///home/u/x.mp3").host, None);
        assert_eq!(Location::of("http://radio.example:8000/").name, None);
        assert_eq!(iso_duration("PT1H2M3.5S"), Some(3723.5));
        assert_eq!(iso_duration("P1DT1S"), Some(86_401.0));
        assert_eq!(iso_duration("PT"), Some(0.0));
        assert_eq!(iso_duration("1H"), None);
        assert_eq!(iso_duration("PT5X"), None);
        assert_eq!(drm_system("urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED"), Some("widevine"));
        assert_eq!(drm_system("nope"), None);
        assert_eq!(artist_title("Band - Song - Live"), (Some("Band".into()), Some("Song - Live".into())));
        assert_eq!(artist_title("Song"), (None, Some("Song".into())));
        assert_eq!(percent_decode("a%2Gb%41"), "a%2GbA");
    }
}
