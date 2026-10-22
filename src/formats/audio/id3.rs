//! ID3 tags: ID3v2.2, v2.3 and v2.4 (text, comment, lyrics, URL, user
//! text, unique file id, picture and chapter frames; unsynchronisation,
//! extended headers, compressed frames) and ID3v1 / v1.1. Shared by MP3,
//! ADTS AAC, WAV, AIFF and DSF.
//!
//! Specifications: id3.org ID3v2.2, ID3v2.3.0, ID3v2.4.0 (structure and
//! frames), ID3v2 Chapter Frame Addendum 1.0.

use serde_json::{Value, json};

use super::{Chapter, Picture, Tags, add_raw, freeform_key, sniff_image};
use crate::plugin::{Compression, Context, ExtractError, Source, latin1_or_utf8};

/// Largest tag read (pictures included).
const MAX_TAG: u64 = 16 << 20;
/// Largest decompressed frame.
const MAX_INFLATE: usize = 16 << 20;
/// Frames read from one tag.
const MAX_FRAMES: usize = 4096;
/// Chapters read (CHAP frames).
const MAX_CHAPTERS: usize = 500;

/// What was found in an ID3v2 tag.
pub(crate) struct Info {
    /// `2.3.0`, `2.4.0`…
    pub version: String,
    /// Bytes the tag takes, header and footer included.
    pub len: u64,
}

/// The length of an ID3v2 tag at the start of `head` (header, body and
/// footer), if there is one.
pub(crate) fn v2_len(head: &[u8]) -> Option<u64> {
    let h = head.get(..10)?;
    if &h[..3] != b"ID3" || h[3] == 0xff || h[4] == 0xff || h[6..10].iter().any(|b| b & 0x80 != 0) {
        return None;
    }
    let footer = if h[3] >= 4 && h[5] & 0x10 != 0 { 10 } else { 0 };
    Some(10 + u64::from(syncsafe(&h[6..10])) + footer)
}

/// Read the ID3v2 tag at `offset` into `tags` and `metadata.id3`.
pub(crate) fn read_v2(
    src: &mut dyn Source,
    offset: u64,
    cx: &mut Context<'_>,
    tags: &mut Tags,
) -> Result<Option<Info>, ExtractError> {
    let Ok(head) = src.read_vec(offset, 10) else { return Ok(None) };
    let Some(len) = v2_len(&head) else { return Ok(None) };
    let body_len = (len - 10).min(src.len().saturating_sub(offset + 10));
    if body_len > MAX_TAG {
        cx.warn(format!("ID3v2 tag of {body_len} bytes not read"));
        return Ok(Some(Info { version: version(&head), len }));
    }
    let body = src.read_vec(offset + 10, usize::try_from(body_len).unwrap_or(0))?;
    parse_v2(&head, &body, cx, tags);
    Ok(Some(Info { version: version(&head), len }))
}

/// Parse an ID3v2 tag held in memory (header included), e.g. a WAV `id3 `
/// chunk.
pub(crate) fn parse_bytes(data: &[u8], cx: &mut Context<'_>, tags: &mut Tags) -> Option<Info> {
    let len = v2_len(data)?;
    let end = usize::try_from(len).ok()?.min(data.len());
    parse_v2(&data[..10], data.get(10..end)?, cx, tags);
    Some(Info { version: version(data), len })
}

fn version(h: &[u8]) -> String {
    format!("2.{}.{}", h[3], h[4])
}

fn syncsafe(b: &[u8]) -> u32 {
    b.iter().fold(0u32, |n, &x| (n << 7) | u32::from(x & 0x7f))
}

/// Undo unsynchronisation (`FF 00` → `FF`).
fn resync(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut prev = 0u8;
    for &x in b {
        if !(prev == 0xff && x == 0) {
            out.push(x);
        }
        prev = x;
    }
    out
}

fn parse_v2(head: &[u8], body: &[u8], cx: &mut Context<'_>, tags: &mut Tags) {
    let (major, flags) = (head[3], head[5]);
    if !(2..=4).contains(&major) {
        cx.warn(format!("ID3v2.{major} is not supported"));
        return;
    }
    tags.system(format!("id3v2.{major}"));
    if major == 2 && flags & 0x40 != 0 {
        cx.warn("compressed ID3v2.2 tag not read");
        return;
    }
    let owned;
    let mut body = body;
    if flags & 0x80 != 0 && major < 4 {
        owned = resync(body);
        body = &owned;
    }
    let mut pos = 0usize;
    if flags & 0x40 != 0 && body.len() >= 4 {
        // Extended header: v2.3 size excludes its own 4 bytes, v2.4 includes them.
        pos = if major == 3 {
            4 + u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize
        } else {
            syncsafe(&body[..4]) as usize
        };
    }
    let mut seen = Vec::new();
    let mut frames = Frames { cx, tags, major, chapters: Vec::new(), toc_order: Vec::new() };
    let (id_len, header_len) = if major == 2 { (3, 6) } else { (4, 10) };
    for _ in 0..MAX_FRAMES {
        let Some(h) = body.get(pos..pos + header_len) else { break };
        if h[0] == 0 || !h[..id_len].iter().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) {
            break; // padding or garbage
        }
        let id = String::from_utf8_lossy(&h[..id_len]).into_owned();
        let size = match major {
            2 => u32::from_be_bytes([0, h[3], h[4], h[5]]) as usize,
            3 => u32::from_be_bytes([h[4], h[5], h[6], h[7]]) as usize,
            _ => frame_size_v24(body, pos),
        };
        let fflags = if major == 2 { 0 } else { u16::from_be_bytes([h[8], h[9]]) };
        let start = pos + header_len;
        let Some(data) = body.get(start..start.saturating_add(size)) else { break };
        pos = start + size;
        if !seen.contains(&id) && seen.len() < 256 {
            seen.push(id.clone());
        }
        let Some(data) = frames.unwrap_frame(data, fflags) else { continue };
        frames.frame(&id, &data);
    }
    let Frames { cx, tags, chapters, toc_order, .. } = frames;
    let mut chapters = chapters;
    if !toc_order.is_empty() {
        chapters.sort_by_key(|(id, _)| toc_order.iter().position(|t| t == id).unwrap_or(usize::MAX));
    }
    tags.chapters.extend(chapters.into_iter().map(|(_, c)| c));
    cx.format_set("id3v2", json!({ "version": version(head), "frames": seen }));
}

/// A v2.4 frame size: syncsafe as the standard says, unless that runs off
/// the tag or misses the next frame and the plain big-endian size does not
/// (iTunes wrote plain sizes in v2.4 tags).
fn frame_size_v24(body: &[u8], pos: usize) -> usize {
    let b = &body[pos + 4..pos + 8];
    let safe = syncsafe(b) as usize;
    let plain = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    if safe == plain {
        return safe;
    }
    let frame_starts = |at: usize| {
        body.get(at..at + 4).is_none_or(|n| n[0] == 0 || n.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()))
    };
    if !frame_starts(pos + 10 + safe) && frame_starts(pos + 10 + plain) && pos + 10 + plain <= body.len() {
        plain
    } else {
        safe
    }
}

struct Frames<'a, 'c> {
    cx: &'a mut Context<'c>,
    tags: &'a mut Tags,
    major: u8,
    chapters: Vec<(String, Chapter)>,
    toc_order: Vec<String>,
}

impl Frames<'_, '_> {
    /// Frame data with grouping, data-length, unsynchronisation and
    /// compression undone; `None` for encrypted frames.
    fn unwrap_frame(&mut self, data: &[u8], flags: u16) -> Option<Vec<u8>> {
        let (compressed, encrypted, grouped, unsync, length) = match self.major {
            3 => (flags & 0x0080 != 0, flags & 0x0040 != 0, flags & 0x0020 != 0, false, flags & 0x0080 != 0),
            4 => (
                flags & 0x0008 != 0,
                flags & 0x0004 != 0,
                flags & 0x0040 != 0,
                flags & 0x0002 != 0,
                flags & 0x0001 != 0,
            ),
            _ => (false, false, false, false, false),
        };
        if encrypted {
            return None;
        }
        let mut d = data;
        if grouped {
            d = d.get(1..)?;
        }
        if length {
            d = d.get(4..)?;
        }
        let d = if unsync { resync(d) } else { d.to_vec() };
        if compressed {
            return self.cx.inflate(&d, Compression::Zlib, MAX_INFLATE).ok();
        }
        Some(d)
    }

    fn meta(&mut self, key: &str, value: Value) {
        add_raw(self.cx, "id3", key, value);
    }

    fn frame(&mut self, id: &str, data: &[u8]) {
        let id = v22_id(id).unwrap_or(id);
        match id {
            "TXXX" => {
                let (desc, value) = described(data);
                // ffmpeg writes lyrics as TXXX:lyrics-<lang>.
                if desc.to_ascii_lowercase().starts_with("lyrics") {
                    self.tags.set("lyrics", &value, "id3");
                    self.meta(&format!("TXXX:{desc}"), json!(value.chars().count()));
                    return;
                }
                if let Some(key) = freeform_key(&desc) {
                    self.tags.set(key, &value, "id3");
                }
                self.meta(&format!("TXXX:{desc}"), json!(value));
            }
            _ if id.starts_with('T') => {
                let values = text_values(data);
                let joined = values.join("; ");
                if let Some(key) = text_key(id) {
                    for v in &values {
                        let v = if id == "TCON" { genre(v) } else { v.clone() };
                        self.tags.set(key, &v, "id3");
                    }
                }
                if id == "TYER" || id == "TDAT" {
                    // v2.3 splits the date; the year alone is a date too.
                    if id == "TYER" {
                        self.tags.set("date", &joined, "id3");
                    }
                }
                self.meta(id, if values.len() > 1 { json!(values) } else { json!(joined) });
            }
            "WXXX" => {
                let (desc, _) = described(data);
                let url = data.get(1..).map(|d| after_terminator(d, data[0])).unwrap_or_default();
                self.meta(&format!("WXXX:{desc}"), json!(latin1_or_utf8(url).trim_end_matches('\0')));
            }
            _ if id.starts_with('W') => {
                self.meta(id, json!(latin1_or_utf8(data).trim_end_matches('\0')));
            }
            "COMM" | "USLT" => {
                let Some((&enc, rest)) = data.split_first() else { return };
                let Some(rest) = rest.get(3..) else { return };
                let (desc, text) = split_terminated(rest, enc);
                let (desc, text) = (decode(desc, enc), decode(text, enc));
                if id == "USLT" {
                    self.tags.set("lyrics", &text, "id3");
                    self.meta("USLT", json!(text.chars().count()));
                    return;
                }
                // iTunes stores its normalisation and gapless data as comments.
                if !desc.starts_with("iTun") {
                    self.tags.set("comment", &text, "id3");
                }
                let key = if desc.is_empty() { "COMM".to_string() } else { format!("COMM:{desc}") };
                self.meta(&key, json!(text));
            }
            "UFID" => {
                let (owner, rest) = data.split_at(data.iter().position(|&b| b == 0).unwrap_or(data.len()));
                let owner = latin1_or_utf8(owner);
                let value = latin1_or_utf8(rest.get(1..).unwrap_or_default());
                if owner.contains("musicbrainz.org") {
                    self.tags.set("musicbrainz_recording_id", &value, "id3");
                }
                self.meta(&format!("UFID:{owner}"), json!(value));
            }
            "APIC" | "PIC" => self.picture(id, data),
            "CHAP" => self.chapter(data),
            "CTOC" => self.toc(data),
            _ => {}
        }
    }

    fn picture(&mut self, id: &str, data: &[u8]) {
        let Some((&enc, rest)) = data.split_first() else { return };
        let (mime, rest) = if id == "PIC" {
            let Some(fmt) = rest.get(..3) else { return };
            let mime = match &fmt.to_ascii_uppercase()[..] {
                b"JPG" => "image/jpeg",
                b"PNG" => "image/png",
                _ => "",
            };
            (mime.to_string(), &rest[3..])
        } else {
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            (latin1_or_utf8(&rest[..end]).to_ascii_lowercase(), rest.get(end + 1..).unwrap_or_default())
        };
        let Some((&kind, rest)) = rest.split_first() else { return };
        let (desc, image) = split_terminated(rest, enc);
        let sniffed = sniff_image(image);
        let mime =
            if mime.is_empty() || mime == "image/jpg" || !mime.contains('/') { sniffed.to_string() } else { mime };
        self.tags.pictures.push(Picture {
            mime,
            kind: Some(kind),
            description: decode(desc, enc),
            width: None,
            height: None,
            data: image.to_vec(),
        });
    }

    fn chapter(&mut self, data: &[u8]) {
        if self.chapters.len() >= MAX_CHAPTERS {
            return;
        }
        let Some(end) = data.iter().position(|&b| b == 0) else { return };
        let id = latin1_or_utf8(&data[..end]);
        let Some(t) = data.get(end + 1..end + 17) else { return };
        let start = u32::from_be_bytes([t[0], t[1], t[2], t[3]]);
        let stop = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        let title = sub_frames(&data[end + 17..], self.major)
            .find(|(fid, _)| fid == "TIT2")
            .map(|(_, d)| text_values(&d).join("; "));
        self.chapters.push((
            id,
            Chapter {
                start_s: f64::from(start) / 1000.0,
                end_s: (stop != u32::MAX && stop > start).then(|| f64::from(stop) / 1000.0),
                title: title.unwrap_or_default(),
            },
        ));
    }

    fn toc(&mut self, data: &[u8]) {
        let Some(end) = data.iter().position(|&b| b == 0) else { return };
        let Some(&flags) = data.get(end + 1) else { return };
        let Some(&count) = data.get(end + 2) else { return };
        // Only the top-level table of contents orders the chapters.
        if flags & 0x02 == 0 || !self.toc_order.is_empty() {
            return;
        }
        let mut rest = data.get(end + 3..).unwrap_or_default();
        for _ in 0..count {
            let Some(e) = rest.iter().position(|&b| b == 0) else { break };
            self.toc_order.push(latin1_or_utf8(&rest[..e]));
            rest = &rest[e + 1..];
        }
    }
}

/// Frames embedded in a CHAP / CTOC frame.
fn sub_frames(mut d: &[u8], major: u8) -> impl Iterator<Item = (String, Vec<u8>)> + '_ {
    std::iter::from_fn(move || {
        let h = d.get(..10)?;
        let id = std::str::from_utf8(&h[..4]).ok()?.to_string();
        let size = if major >= 4 { syncsafe(&h[4..8]) } else { u32::from_be_bytes([h[4], h[5], h[6], h[7]]) } as usize;
        let body = d.get(10..10 + size)?.to_vec();
        d = &d[10 + size..];
        Some((id, body))
    })
}

/// ID3v2.2 frame ids as their v2.3 equivalents.
fn v22_id(id: &str) -> Option<&'static str> {
    Some(match id {
        "TT1" => "TIT1",
        "TT2" => "TIT2",
        "TT3" => "TIT3",
        "TP1" => "TPE1",
        "TP2" => "TPE2",
        "TP3" => "TPE3",
        "TP4" => "TPE4",
        "TCM" => "TCOM",
        "TXT" => "TEXT",
        "TAL" => "TALB",
        "TRK" => "TRCK",
        "TPA" => "TPOS",
        "TYE" => "TYER",
        "TDA" => "TDAT",
        "TOR" => "TORY",
        "TCO" => "TCON",
        "TPB" => "TPUB",
        "TCR" => "TCOP",
        "TRC" => "TSRC",
        "TBP" => "TBPM",
        "TKE" => "TKEY",
        "TLA" => "TLAN",
        "TEN" => "TENC",
        "TSS" => "TSSE",
        "TCP" => "TCMP",
        "TXX" => "TXXX",
        "COM" => "COMM",
        "ULT" => "USLT",
        "UFI" => "UFID",
        "WXX" => "WXXX",
        _ => return None,
    })
}

/// The normalised tag for a text frame.
fn text_key(id: &str) -> Option<&'static str> {
    Some(match id {
        "TIT2" => "title",
        "TIT3" => "subtitle",
        "TPE1" => "artist",
        "TALB" => "album",
        "TPE2" => "album_artist",
        "TRCK" => "track",
        "TPOS" => "disc",
        "TDRC" | "TDRL" => "date",
        "TDOR" | "TORY" => "original_date",
        "TCON" => "genre",
        "TCOM" => "composer",
        "TEXT" => "lyricist",
        "TPE3" => "conductor",
        "TPE4" => "remixer",
        "TPUB" => "label",
        "TCOP" => "copyright",
        "TSRC" => "isrc",
        "TBPM" => "bpm",
        "TKEY" => "key",
        "TMOO" => "mood",
        "TIT1" | "GRP1" => "grouping",
        "TLAN" => "language",
        "TCMP" => "compilation",
        "TENC" => "encoded_by",
        "TSSE" => "encoder",
        _ => return None,
    })
}

/// The values of a text frame (v2.4 separates several with NULs).
fn text_values(data: &[u8]) -> Vec<String> {
    let Some((&enc, rest)) = data.split_first() else { return Vec::new() };
    let text = decode(rest, enc);
    text.split('\0').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).take(64).collect()
}

/// A description and value (TXXX).
fn described(data: &[u8]) -> (String, String) {
    let Some((&enc, rest)) = data.split_first() else { return (String::new(), String::new()) };
    let (d, v) = split_terminated(rest, enc);
    (decode(d, enc), decode(v, enc).trim_end_matches('\0').to_string())
}

/// Split at the first string terminator for the encoding (one NUL, or two
/// aligned NULs for UTF-16).
fn split_terminated(b: &[u8], enc: u8) -> (&[u8], &[u8]) {
    if enc == 1 || enc == 2 {
        let mut i = 0;
        while i + 1 < b.len() {
            if b[i] == 0 && b[i + 1] == 0 {
                return (&b[..i], &b[i + 2..]);
            }
            i += 2;
        }
        (b, &[])
    } else {
        match b.iter().position(|&x| x == 0) {
            Some(i) => (&b[..i], &b[i + 1..]),
            None => (b, &[]),
        }
    }
}

fn after_terminator(b: &[u8], enc: u8) -> &[u8] {
    split_terminated(b, enc).1
}

/// Decode ID3 text: 0 = Latin-1, 1 = UTF-16 with BOM, 2 = UTF-16BE,
/// 3 = UTF-8. A missing BOM is read as little-endian, the common case.
fn decode(b: &[u8], enc: u8) -> String {
    match enc {
        1 | 2 => {
            let (body, be) = match b {
                [0xfe, 0xff, rest @ ..] => (rest, true),
                [0xff, 0xfe, rest @ ..] => (rest, false),
                _ => (b, enc == 2),
            };
            let units: Vec<u16> = body
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| if be { u16::from_be_bytes(*c) } else { u16::from_le_bytes(*c) })
                .collect();
            // A list of UTF-16 values repeats the BOM after each separator.
            String::from_utf16_lossy(&units).replace('\u{feff}', "").trim_end_matches('\0').to_string()
        }
        3 => String::from_utf8_lossy(b).trim_end_matches('\0').to_string(),
        _ => b.iter().map(|&c| char::from(c)).collect::<String>().trim_end_matches('\0').to_string(),
    }
}

/// A `TCON` value with ID3v1 genre numbers resolved: `(13)`, `13`,
/// `(13)Pop`, `RX`, `CR`.
fn genre(v: &str) -> String {
    match v {
        "RX" | "(RX)" => return "Remix".into(),
        "CR" | "(CR)" => return "Cover".into(),
        _ => {}
    }
    if let Some(rest) = v.strip_prefix('(')
        && let Some((n, after)) = rest.split_once(')')
        && let Ok(n) = n.parse::<u8>()
    {
        return if after.is_empty() { genre_name(n).unwrap_or(v).to_string() } else { after.to_string() };
    }
    v.parse::<u8>().ok().and_then(genre_name).map_or_else(|| v.to_string(), str::to_string)
}

/// ID3v1 genres (0–79 from ID3v1, 80–191 the Winamp extensions).
const GENRES: &[&str] = &[
    "Blues",
    "Classic Rock",
    "Country",
    "Dance",
    "Disco",
    "Funk",
    "Grunge",
    "Hip-Hop",
    "Jazz",
    "Metal",
    "New Age",
    "Oldies",
    "Other",
    "Pop",
    "R&B",
    "Rap",
    "Reggae",
    "Rock",
    "Techno",
    "Industrial",
    "Alternative",
    "Ska",
    "Death Metal",
    "Pranks",
    "Soundtrack",
    "Euro-Techno",
    "Ambient",
    "Trip-Hop",
    "Vocal",
    "Jazz+Funk",
    "Fusion",
    "Trance",
    "Classical",
    "Instrumental",
    "Acid",
    "House",
    "Game",
    "Sound Clip",
    "Gospel",
    "Noise",
    "Alternative Rock",
    "Bass",
    "Soul",
    "Punk",
    "Space",
    "Meditative",
    "Instrumental Pop",
    "Instrumental Rock",
    "Ethnic",
    "Gothic",
    "Darkwave",
    "Techno-Industrial",
    "Electronic",
    "Pop-Folk",
    "Eurodance",
    "Dream",
    "Southern Rock",
    "Comedy",
    "Cult",
    "Gangsta",
    "Top 40",
    "Christian Rap",
    "Pop/Funk",
    "Jungle",
    "Native US",
    "Cabaret",
    "New Wave",
    "Psychedelic",
    "Rave",
    "Showtunes",
    "Trailer",
    "Lo-Fi",
    "Tribal",
    "Acid Punk",
    "Acid Jazz",
    "Polka",
    "Retro",
    "Musical",
    "Rock & Roll",
    "Hard Rock",
    "Folk",
    "Folk-Rock",
    "National Folk",
    "Swing",
    "Fast Fusion",
    "Bebop",
    "Latin",
    "Revival",
    "Celtic",
    "Bluegrass",
    "Avantgarde",
    "Gothic Rock",
    "Progressive Rock",
    "Psychedelic Rock",
    "Symphonic Rock",
    "Slow Rock",
    "Big Band",
    "Chorus",
    "Easy Listening",
    "Acoustic",
    "Humour",
    "Speech",
    "Chanson",
    "Opera",
    "Chamber Music",
    "Sonata",
    "Symphony",
    "Booty Bass",
    "Primus",
    "Porn Groove",
    "Satire",
    "Slow Jam",
    "Club",
    "Tango",
    "Samba",
    "Folklore",
    "Ballad",
    "Power Ballad",
    "Rhythmic Soul",
    "Freestyle",
    "Duet",
    "Punk Rock",
    "Drum Solo",
    "A Cappella",
    "Euro-House",
    "Dance Hall",
    "Goa",
    "Drum & Bass",
    "Club-House",
    "Hardcore Techno",
    "Terror",
    "Indie",
    "BritPop",
    "Negerpunk",
    "Polsk Punk",
    "Beat",
    "Christian Gangsta Rap",
    "Heavy Metal",
    "Black Metal",
    "Crossover",
    "Contemporary Christian",
    "Christian Rock",
    "Merengue",
    "Salsa",
    "Thrash Metal",
    "Anime",
    "Jpop",
    "Synthpop",
    "Abstract",
    "Art Rock",
    "Baroque",
    "Bhangra",
    "Big Beat",
    "Breakbeat",
    "Chillout",
    "Downtempo",
    "Dub",
    "EBM",
    "Eclectic",
    "Electro",
    "Electroclash",
    "Emo",
    "Experimental",
    "Garage",
    "Global",
    "IDM",
    "Illbient",
    "Industro-Goth",
    "Jam Band",
    "Krautrock",
    "Leftfield",
    "Lounge",
    "Math Rock",
    "New Romantic",
    "Nu-Breakz",
    "Post-Punk",
    "Post-Rock",
    "Psytrance",
    "Shoegaze",
    "Space Rock",
    "Trop Rock",
    "World Music",
    "Neoclassical",
    "Audiobook",
    "Audio Theatre",
    "Neue Deutsche Welle",
    "Podcast",
    "Indie Rock",
    "G-Funk",
    "Dubstep",
    "Garage Rock",
    "Psybient",
];

/// The name of an ID3v1 genre number.
pub(crate) fn genre_name(n: u8) -> Option<&'static str> {
    GENRES.get(usize::from(n)).copied()
}

/// Read an ID3v1 tag from the last 128 bytes of `tail` into `tags` and
/// `metadata.id3v1`. Returns the tag's length (0 if none).
pub(crate) fn read_v1(tail: &[u8], cx: &mut Context<'_>, tags: &mut Tags) -> u64 {
    let Some(t) = tail.len().checked_sub(128).map(|i| &tail[i..]) else { return 0 };
    if &t[..3] != b"TAG" {
        return 0;
    }
    let field = |b: &[u8]| {
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        latin1_or_utf8(&b[..end]).trim().to_string()
    };
    let (title, artist, album, year) = (field(&t[3..33]), field(&t[33..63]), field(&t[63..93]), field(&t[93..97]));
    // ID3v1.1: a zero byte before the last comment byte makes that byte the track.
    let (comment, track) =
        if t[125] == 0 && t[126] != 0 { (field(&t[97..125]), Some(t[126])) } else { (field(&t[97..127]), None) };
    let genre = genre_name(t[127]);
    tags.system(if track.is_some() { "id3v1.1" } else { "id3v1" });
    let mut m = serde_json::Map::new();
    for (k, v, key) in
        [("title", &title, "title"), ("artist", &artist, "artist"), ("album", &album, "album"), ("year", &year, "date")]
    {
        if !v.is_empty() {
            tags.fill(key, v, "id3v1");
            m.insert(k.into(), json!(v));
        }
    }
    if !comment.is_empty() {
        tags.fill("comment", &comment, "id3v1");
        m.insert("comment".into(), json!(comment));
    }
    if let Some(n) = track {
        tags.fill("track", &n.to_string(), "id3v1");
        m.insert("track".into(), json!(n));
    }
    if let Some(g) = genre {
        tags.fill("genre", g, "id3v1");
        m.insert("genre".into(), json!(g));
    }
    for (k, v) in m {
        cx.metadata_set("id3v1", &k, v);
    }
    128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_text() {
        assert_eq!(decode(b"\xff\xfeA\0B\0", 1), "AB");
        assert_eq!(decode(b"\xfe\xff\0A\0B", 1), "AB");
        assert_eq!(decode(b"A\0B\0", 1), "AB"); // no BOM
        assert_eq!(decode(b"caf\xe9", 0), "café");
        assert_eq!(split_terminated(b"ab\0cd", 0), (&b"ab"[..], &b"cd"[..]));
        assert_eq!(split_terminated(b"a\0\0\0b\0", 1), (&b"a\0"[..], &b"b\0"[..]));
        assert_eq!(resync(b"\xff\0\xe0\xff\0"), b"\xff\xe0\xff");
    }

    #[test]
    fn genres() {
        assert_eq!(genre("(13)"), "Pop");
        assert_eq!(genre("17"), "Rock");
        assert_eq!(genre("(13)Pop Rock"), "Pop Rock");
        assert_eq!(genre("Brass"), "Brass");
        assert_eq!(genre("RX"), "Remix");
        assert_eq!(GENRES.len(), 192);
    }

    #[test]
    fn tag_length() {
        assert_eq!(v2_len(b"ID3\x04\0\0\0\0\x01\x00"), Some(10 + 128));
        assert_eq!(v2_len(b"ID3\x04\0\x10\0\0\0\x0a"), Some(30));
        assert_eq!(v2_len(b"ID3\x04\0\0\0\0\x80\x00"), None);
        assert_eq!(v2_len(b"TAG"), None);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // test frames are small
    fn v23_unsynchronised_and_compressed_frames() {
        use crate::plugin::testing::report_for;
        let frame = |id: &[u8], flags: u16, body: &[u8]| {
            let mut f = id.to_vec();
            f.extend_from_slice(&(body.len() as u32).to_be_bytes());
            f.extend_from_slice(&flags.to_be_bytes());
            f.extend_from_slice(body);
            f
        };
        // TALB compressed: 4-byte decompressed size, then zlib data.
        let text = b"\x00Breakwater Sessions";
        let mut zipped = (text.len() as u32).to_be_bytes().to_vec();
        zipped.extend(miniz_oxide::deflate::compress_to_vec_zlib(text, 6));
        // TIT2 holds an 0xFF byte, so the unsynchronised tag stores FF 00.
        let mut body = frame(b"TIT2", 0, b"\x00Caf\xff");
        body.extend(frame(b"TALB", 0x0080, &zipped));
        body.extend(frame(b"TPE1", 0x0040, b"\x00secret")); // encrypted: skipped
        let mut synced = Vec::new();
        for &b in &body {
            synced.push(b);
            if b == 0xff {
                synced.push(0);
            }
        }
        let n = synced.len() as u32;
        let mut file = b"ID3\x03\x00\x80".to_vec();
        file.extend_from_slice(&[
            (n >> 21) as u8 & 0x7f,
            (n >> 14) as u8 & 0x7f,
            (n >> 7) as u8 & 0x7f,
            n as u8 & 0x7f,
        ]);
        file.extend(synced);
        for _ in 0..2 {
            let mut f = vec![0xff, 0xfb, 0x90, 0x00];
            f.resize(417, 0);
            file.extend(f);
        }
        let r = report_for("caf.mp3", &file);
        let tags = &r.format["mp3"]["tags"];
        assert_eq!(tags["title"], "Caf\u{ff}");
        assert_eq!(tags["album"], "Breakwater Sessions");
        assert!(tags.get("artist").is_none());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // test frames are small
    fn v24_frames_chapters_and_v1() {
        use crate::plugin::testing::report_for;
        // An MP3 with an ID3v2.4 tag holding a title, a TXXX, chapters and a
        // 2-frame MPEG stream, plus an ID3v1.1 tag.
        let frame = |id: &[u8], body: &[u8]| {
            let mut f = id.to_vec();
            let n = body.len() as u32;
            f.extend_from_slice(&[
                (n >> 21) as u8 & 0x7f,
                (n >> 14) as u8 & 0x7f,
                (n >> 7) as u8 & 0x7f,
                n as u8 & 0x7f,
            ]);
            f.extend_from_slice(&[0, 0]);
            f.extend_from_slice(body);
            f
        };
        let mut body = frame(b"TIT2", b"\x03Low Tide\0High Tide");
        body.extend(frame(b"TXXX", b"\x03MusicBrainz Album Id\0abc"));
        body.extend(frame(b"TCON", b"\x00(8)"));
        let mut chap = b"ch1\0".to_vec();
        chap.extend_from_slice(&[0, 0, 0, 0, 0, 0, 3, 232, 255, 255, 255, 255, 255, 255, 255, 255]);
        chap.extend(frame(b"TIT2", b"\x03Opening"));
        body.extend(frame(b"CHAP", &chap));
        body.extend(frame(b"CTOC", b"toc\0\x03\x01ch1\0"));
        let n = body.len() as u32;
        let mut file = b"ID3\x04\x00\x00".to_vec();
        file.extend_from_slice(&[
            (n >> 21) as u8 & 0x7f,
            (n >> 14) as u8 & 0x7f,
            (n >> 7) as u8 & 0x7f,
            n as u8 & 0x7f,
        ]);
        file.extend(body);
        // Two MPEG-1 Layer III frames, 128 kbit/s, 44.1 kHz (417 bytes each).
        for _ in 0..2 {
            let mut f = vec![0xff, 0xfb, 0x90, 0x00];
            f.resize(417, 0);
            file.extend(f);
        }
        let mut v1 = b"TAG".to_vec();
        v1.resize(128, 0);
        v1[3..9].copy_from_slice(b"Shoals");
        v1[126] = 7;
        v1[127] = 32; // Classical
        file.extend(v1);
        let r = report_for("tide.mp3", &file);
        let f = &r.format["mp3"];
        let tags = &f["tags"];
        assert_eq!(tags["title"], "Low Tide");
        assert_eq!(tags["musicbrainz_album_id"], "abc");
        assert_eq!(tags["genre"], "Jazz");
        assert_eq!(tags["track"], 7); // only ID3v1 has one
        assert_eq!(f["chapters"][0]["title"], "Opening");
        assert_eq!(f["chapters"][0]["end_s"], 1.0);
        assert_eq!(r.metadata["id3"]["TIT2"], json!(["Low Tide", "High Tide"]));
        assert_eq!(f["tag_formats"], json!(["id3v2.4", "id3v1.1"]));
    }
}
