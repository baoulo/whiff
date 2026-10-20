//! MPEG-4 audio (M4A, M4B audiobooks, M4P, M4R ringtones, 3GA): the audio
//! track (AAC profile, ALAC, Opus, FLAC, AC-3, AMR, MP3 in MP4), duration,
//! iTunes `ilst` and QuickTime metadata, cover art, chapters (Nero `chpl` or
//! a chapter track), DRM (FairPlay `drms`, CENC `enca`) and the layout.
//!
//! The file structure is read by `plugin::mp4`; see that module for the
//! specifications.

use serde_json::json;

use super::{Chapter, Picture, Stream, Tags, add_raw, comment_key, freeform_key, id3};
use crate::plugin::mp4::{self, Item, Value};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
};

/// Extractor for MPEG-4 audio.
pub struct Mp4Audio;

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.mp4",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "m4a",
        name: "MPEG-4 audio",
        family: "audio",
        mimes: &["audio/mp4", "audio/x-m4a", "audio/x-m4b"],
        extensions: &["m4a", "m4b", "m4p", "m4r", "3ga"],
        magic: &[
            Magic::at(4, b"ftypM4A "),
            Magic::at(4, b"ftypM4B "),
            Magic::at(4, b"ftypM4P "),
            Magic::at(4, b"ftypM4R "),
        ],
        parent: None,
    }],
};

impl Extractor for Mp4Audio {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // Generic brands (isom, mp42, 3gp…) with an audio file extension.
        let ext = probe.extension?;
        if !META.formats[0].extensions.contains(&ext) || probe.head.get(4..8)? != b"ftyp" {
            return None;
        }
        Some(Sniff { format: "m4a", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let movie = mp4::read(src)?;
        cx.format_set("major_brand", movie.major_brand.as_str());
        cx.format_set("compatible_brands", json!(movie.compatible_brands));
        cx.format_set("top_level_boxes", json!(movie.top));
        cx.format_set("fragmented", movie.fragmented);
        if let Some(f) = movie.faststart {
            cx.format_set("faststart", f);
        }
        for (when, field, key) in
            [(movie.created, DateField::Created, "created"), (movie.modified, DateField::Modified, "modified")]
        {
            if let Some(t) = mp4::mac_time(when) {
                cx.temporal().source(format!("mp4.mvhd.{key}")).content_date(field, t, true);
            }
        }
        let duration = movie.duration_s();
        let mut tracks = Vec::new();
        let mut reported = false;
        for t in &movie.tracks {
            let track_s = (t.timescale > 0).then(|| t.duration as f64 / f64::from(t.timescale));
            tracks.push(json!({
                "id": t.id,
                "handler": t.handler,
                "codec": t.codec,
                "language": t.language,
                "duration_s": track_s.map(super::round_s),
                "enabled": t.enabled,
            }));
            if t.handler != "soun" {
                continue;
            }
            if matches!(t.codec.as_str(), "drms" | "drmi") {
                cx.format_set("drm", "fairplay");
                cx.security().encrypted(true);
            } else if t.codec == "enca" {
                cx.format_set("drm", "cenc");
                cx.security().encrypted(true);
            }
            let mut s = Stream::new(codec(t));
            s.profile =
                t.profile.clone().filter(|p| p.starts_with("aac_") || p.starts_with("he_") || p.starts_with("xhe"));
            s.sample_rate_hz = t.sample_rate;
            s.channels = t.channels;
            s.bits_per_sample =
                t.bits.filter(|_| matches!(t.codec.as_str(), "alac" | "fLaC" | "lpcm" | "ipcm" | "sowt" | "twos"));
            s.bitrate_bps = t.avg_bitrate.map(u64::from).or_else(|| {
                let d = track_s.filter(|d| *d > 0.0)?;
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
                Some((t.sample_bytes as f64 * 8.0 / d).round() as u64)
            });
            s.language = t.language.clone().filter(|l| l != "und");
            if let (Some(rate), true) = (t.sample_rate, t.timescale > 0) {
                s.samples = Some(t.duration * u64::from(rate) / u64::from(t.timescale));
            }
            if reported {
                cx.physical().stream(stream_map(&s));
            } else {
                s.report(cx, duration.or(track_s), src.len());
                reported = true;
            }
        }
        cx.format_set("tracks", json!(tracks));
        cx.format_set("media_data_bytes", movie.mdat_bytes);
        if !reported {
            cx.warn("no audio track");
            if let Some(d) = duration {
                cx.physical().duration_s(super::round_s(d));
            }
        }
        let mut tags = Tags::default();
        for c in &movie.chapters {
            tags.chapters.push(Chapter { start_s: c.start_s, end_s: None, title: c.title.clone() });
        }
        close_chapters(&mut tags.chapters, duration);
        items(&movie.items, cx, &mut tags);
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Mp4Audio);

/// The stream map of a second audio track (only the first sets the duration).
fn stream_map(s: &Stream) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!("audio"));
    m.insert("codec".into(), json!(s.codec));
    if let Some(v) = s.sample_rate_hz {
        m.insert("sample_rate_hz".into(), json!(v));
    }
    if let Some(v) = s.channels {
        m.insert("channels".into(), json!(v));
    }
    if let Some(l) = &s.language {
        m.insert("language".into(), json!(l));
    }
    m
}

/// End each chapter where the next starts (the last at the end of the file).
pub(crate) fn close_chapters(chapters: &mut [Chapter], duration: Option<f64>) {
    let starts: Vec<f64> = chapters.iter().map(|c| c.start_s).skip(1).collect();
    for (i, c) in chapters.iter_mut().enumerate() {
        c.end_s = starts.get(i).copied().or(duration).filter(|e| *e > c.start_s);
    }
}

pub(crate) fn codec(t: &mp4::Track) -> String {
    match (t.codec.as_str(), t.profile.as_deref()) {
        ("mp4a", Some("mp3")) | (".mp3", _) => "mp3",
        ("mp4a", Some("ac3")) | ("ac-3", _) => "ac3",
        ("mp4a", Some("eac3")) | ("ec-3", _) => "eac3",
        ("mp4a", Some("opus")) | ("Opus", _) => "opus",
        ("mp4a" | "drms" | "enca", _) => "aac",
        ("alac", _) => "alac",
        ("fLaC", _) => "flac",
        ("samr", _) => "amr_nb",
        ("sawb", _) => "amr_wb",
        ("lpcm" | "ipcm" | "sowt" | "twos", _) => "pcm",
        ("ac-4", _) => "ac4",
        ("mha1" | "mhm1", _) => "mpeg_h",
        (other, _) => return other.to_string(),
    }
    .to_string()
}

/// The normalised tag of an `ilst` item type.
fn ilst_key(key: &str) -> Option<&'static str> {
    Some(match key {
        "©nam" => "title",
        "©ART" => "artist",
        "©alb" => "album",
        "aART" => "album_artist",
        "©day" => "date",
        "©gen" => "genre",
        "©wrt" => "composer",
        "©con" => "conductor",
        "©lyr" => "lyrics",
        "©cmt" => "comment",
        "desc" | "ldes" => "description",
        "cprt" | "©cpy" => "copyright",
        "©too" | "©swr" => "encoder",
        "©enc" => "encoded_by",
        "©grp" | "©mvn" => "grouping",
        "©st3" => "subtitle",
        "©pub" | "©lab" => "label",
        "tmpo" => "bpm",
        "cpil" => "compilation",
        _ => return None,
    })
}

/// The normalised tag of a QuickTime `keys` name.
fn quicktime_key(key: &str) -> Option<&'static str> {
    let k = key.strip_prefix("com.apple.quicktime.")?;
    Some(match k {
        "title" | "displayname" => "title",
        "artist" | "author" => "artist",
        "album" => "album",
        "comment" => "comment",
        "description" => "description",
        "copyright" => "copyright",
        "creationdate" => "date",
        "genre" => "genre",
        "software" => "encoder",
        _ => return None,
    })
}

pub(crate) fn items(list: &[Item], cx: &mut Context<'_>, tags: &mut Tags) {
    if list.iter().any(|i| !i.key.starts_with("udta:") && !i.key.starts_with("com.")) {
        tags.system("itunes");
    }
    if list.iter().any(|i| i.key.starts_with("udta:") || i.key.starts_with("com.")) {
        tags.system("quicktime");
    }
    for item in list {
        let (standard, key) = match item.key.strip_prefix("udta:") {
            Some(k) => ("quicktime", k),
            None if item.key.starts_with("com.") => ("quicktime", item.key.as_str()),
            None => ("itunes", item.key.as_str()),
        };
        let target = if let Some(name) = key.strip_prefix("----:") {
            name.rsplit(':').next().and_then(freeform_key)
        } else if standard == "quicktime" && key.starts_with("com.") {
            quicktime_key(key)
        } else {
            ilst_key(key)
        };
        let raw = match &item.value {
            Value::Text(t) => {
                if let Some(k) = target {
                    tags.set(k, t, standard);
                }
                if key == "apID" || key == "ownr" {
                    // The purchaser's Apple ID or name.
                    cx.mailbox(Some(t), None)
                } else if key == "©lyr" {
                    json!(t.chars().count())
                } else {
                    json!(crate::plugin::truncate_chars(t, 2000))
                }
            }
            Value::Int(n) => {
                match (key, target) {
                    ("gnre", _) => {
                        if let Some(g) = u8::try_from(n - 1).ok().and_then(id3::genre_name) {
                            tags.set("genre", g, standard);
                        }
                    }
                    ("cpil" | "pgap" | "pcst", _) => {
                        if key == "cpil" {
                            tags.set("compilation", if *n != 0 { "1" } else { "0" }, standard);
                        }
                    }
                    (_, Some(k)) => tags.set(k, &n.to_string(), standard),
                    _ => {}
                }
                if key == "stik" {
                    cx.format_set("media_kind", media_kind(*n));
                }
                json!(n)
            }
            Value::Pair(a, b) => {
                let k = if key == "disk" { "disc" } else { "track" };
                let v = if *b > 0 { format!("{a}/{b}") } else { a.to_string() };
                tags.set(k, &v, standard);
                json!([a, b])
            }
            Value::Image(mime, data) => {
                tags.pictures.push(Picture {
                    mime: (*mime).to_string(),
                    kind: Some(3),
                    description: String::new(),
                    width: None,
                    height: None,
                    data: data.clone(),
                });
                json!({ "image_bytes": data.len(), "mime": mime })
            }
            Value::Binary(kind, data) => {
                if key == "covr" {
                    let mime = super::sniff_image(data);
                    tags.pictures.push(Picture {
                        mime: mime.to_string(),
                        kind: Some(3),
                        description: String::new(),
                        width: None,
                        height: None,
                        data: data.clone(),
                    });
                }
                json!({ "type": kind, "binary_bytes": data.len() })
            }
        };
        add_raw(cx, standard, key, raw);
        // Keys shared with Vorbis spellings (free-form iTunes items often use them).
        if target.is_none()
            && let Some(name) = key.strip_prefix("----:").and_then(|n| n.rsplit(':').next())
            && let (Some(k), Value::Text(t)) = (comment_key(&name.to_ascii_uppercase()), &item.value)
        {
            tags.set(k, t, standard);
        }
    }
}

/// The iTunes media kind (`stik`).
pub(crate) fn media_kind(n: i64) -> &'static str {
    match n {
        0 | 1 => "music",
        2 => "audiobook",
        6 => "music_video",
        9 => "movie",
        10 => "tv_show",
        11 => "booklet",
        14 => "ringtone",
        21 => "podcast",
        23 => "itunes_u",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("m4a");

    fn bx(kind: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut b = u32::try_from(body.len() + 8).unwrap().to_be_bytes().to_vec();
        b.extend_from_slice(&kind);
        b.extend_from_slice(body);
        b
    }

    fn data(kind: u8, value: &[u8]) -> Vec<u8> {
        let mut d = vec![0, 0, 0, kind, 0, 0, 0, 0];
        d.extend_from_slice(value);
        bx(*b"data", &d)
    }

    /// A small M4A: one AAC-LC track, Nero chapters, QuickTime user data
    /// and `keys`, and iTunes items (track pair, tempo, free-form ISRC).
    fn synthetic() -> Vec<u8> {
        let mut mvhd = vec![0u8; 4];
        for v in [0u32, 0, 1000, 3000] {
            mvhd.extend_from_slice(&v.to_be_bytes());
        }
        mvhd.resize(100, 0);
        let mut tkhd = vec![0, 0, 0, 1];
        for v in [0u32, 0, 1, 0, 3000] {
            tkhd.extend_from_slice(&v.to_be_bytes());
        }
        tkhd.resize(84, 0);
        let mut mdhd = vec![0u8; 12];
        mdhd.extend_from_slice(&44100u32.to_be_bytes());
        mdhd.extend_from_slice(&132_300u32.to_be_bytes());
        mdhd.extend_from_slice(&[0x15, 0xc7, 0, 0]);
        let mut hdlr = vec![0u8; 8];
        hdlr.extend_from_slice(b"soun");
        hdlr.extend_from_slice(&[0; 12]);
        hdlr.extend_from_slice(b"Sound\0");
        // esds: ES descriptor > decoder config (AAC, 128 kbit/s) > AAC-LC, 44.1 kHz, stereo.
        let dc =
            [&[0x40u8, 0x15, 0, 0, 0][..], &128_000u32.to_be_bytes(), &128_000u32.to_be_bytes(), &[5, 2, 0x12, 0x10]]
                .concat();
        let es = [&[0u8, 1, 0][..], &[4, u8::try_from(dc.len()).unwrap()], &dc].concat();
        let esds = [&[0u8; 4][..], &[3, u8::try_from(es.len()).unwrap()], &es].concat();
        let mut mp4a = vec![0u8, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 16, 0, 0, 0, 0];
        mp4a.extend_from_slice(&(44100u32 << 16).to_be_bytes());
        mp4a.extend(bx(*b"esds", &esds));
        let stsd = [&[0u8; 4][..], &1u32.to_be_bytes(), &bx(*b"mp4a", &mp4a)].concat();
        let stsz =
            [&[0u8; 4][..], &0u32.to_be_bytes(), &2u32.to_be_bytes(), &100u32.to_be_bytes(), &120u32.to_be_bytes()]
                .concat();
        let stbl = bx(*b"stbl", &[bx(*b"stsd", &stsd), bx(*b"stsz", &stsz)].concat());
        let mdia = bx(*b"mdia", &[bx(*b"mdhd", &mdhd), bx(*b"hdlr", &hdlr), bx(*b"minf", &stbl)].concat());
        let trak = bx(*b"trak", &[bx(*b"tkhd", &tkhd), mdia].concat());
        let mut chpl = vec![1, 0, 0, 0, 0, 0, 0, 0, 2];
        for (t, name) in [(0u64, "Low Water"), (15_000_000, "High Water")] {
            chpl.extend_from_slice(&t.to_be_bytes());
            chpl.push(u8::try_from(name.len()).unwrap());
            chpl.extend_from_slice(name.as_bytes());
        }
        let mut nam = 10u16.to_be_bytes().to_vec();
        nam.extend_from_slice(&[0x55, 0xc4]);
        nam.extend_from_slice(b"Tide Table");
        let udta = bx(*b"udta", &[bx(*b"chpl", &chpl), bx(*b"\xa9nam", &nam)].concat());
        let key = b"com.apple.quicktime.author";
        let keys =
            [&[0u8; 4][..], &1u32.to_be_bytes(), &u32::try_from(key.len() + 8).unwrap().to_be_bytes(), b"mdta", key]
                .concat();
        let ilst = [
            bx([0, 0, 0, 1], &data(1, b"Mira Castell")),
            bx(*b"trkn", &data(0, &[0, 0, 0, 2, 0, 7, 0, 0])),
            bx(*b"tmpo", &data(21, &[0, 120])),
            bx(
                *b"----",
                &[bx(*b"mean", b"\0\0\0\0com.apple.iTunes"), bx(*b"name", b"\0\0\0\0ISRC"), data(1, b"ZZSLT2400001")]
                    .concat(),
            ),
        ]
        .concat();
        let mut qt_hdlr = vec![0u8; 8];
        qt_hdlr.extend_from_slice(b"mdta");
        qt_hdlr.extend_from_slice(&[0; 13]);
        let meta = bx(*b"meta", &[bx(*b"hdlr", &qt_hdlr), bx(*b"keys", &keys), bx(*b"ilst", &ilst)].concat());
        let moov = bx(*b"moov", &[bx(*b"mvhd", &mvhd), trak, udta, meta].concat());
        [bx(*b"ftyp", b"M4A \0\0\0\0M4A isom"), moov, bx(*b"mdat", &[0; 220])].concat()
    }

    #[test]
    fn tracks_chapters_and_quicktime_metadata() {
        let r = crate::plugin::testing::report_for("tide.m4a", &synthetic());
        let f = &r.format["m4a"];
        assert_eq!(f["faststart"], true);
        assert_eq!(f["chapters"][1]["title"], "High Water");
        assert_eq!(f["chapters"][1]["start_s"], 1.5);
        assert_eq!(f["chapters"][1]["end_s"], 3.0);
        let tags = &f["tags"];
        assert_eq!(
            (&tags["title"], &tags["artist"], &tags["track"], &tags["track_total"]),
            (&json!("Tide Table"), &json!("Mira Castell"), &json!(2), &json!(7))
        );
        assert_eq!((&tags["bpm"], &tags["isrc"]), (&json!(120), &json!("ZZSLT2400001")));
        let m = r.physical.media.as_ref().unwrap();
        assert_eq!(m.duration_s, Some(3.0));
        let s = &m.streams[0];
        assert_eq!(
            (&s["codec"], &s["profile"], &s["channels"], &s["language"]),
            (&json!("aac"), &json!("aac_lc"), &json!(2), &json!("eng"))
        );
        assert_eq!(r.metadata["quicktime"]["com.apple.quicktime.author"], "Mira Castell");
    }

    #[test]
    fn chapters_are_closed() {
        let mut c = vec![
            Chapter { start_s: 0.0, end_s: None, title: "a".into() },
            Chapter { start_s: 2.0, end_s: None, title: "b".into() },
        ];
        close_chapters(&mut c, Some(5.0));
        assert_eq!((c[0].end_s, c[1].end_s), (Some(2.0), Some(5.0)));
        assert_eq!(media_kind(2), "audiobook");
        assert_eq!(quicktime_key("com.apple.quicktime.author"), Some("artist"));
    }
}
