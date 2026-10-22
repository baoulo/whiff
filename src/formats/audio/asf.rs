//! Windows Media Audio (ASF): duration, the audio stream (WMA 1 / 2 / Pro /
//! Lossless / Voice, or another wave format), codec list, content
//! description and `WM/` attributes, pictures, and DRM (content
//! encryption).
//!
//! The header objects are read by `plugin::asf`.

use serde_json::json;

use super::{Picture, Stream, Tags, add_raw, freeform_key, riff};
use crate::plugin::asf::{self, Attr};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, filetime,
};

/// Extractor for WMA.
pub struct Wma;

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.asf",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "wma",
        name: "Windows Media Audio",
        family: "audio",
        mimes: &["audio/x-ms-wma"],
        extensions: &["wma"],
        magic: &[Magic::prefix(&asf::HEADER)],
        parent: None,
    }],
};

impl Extractor for Wma {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let a = asf::read(src)?;
        if a.streams.iter().any(|s| s.kind == "video") && cx.format_id() == "wma" {
            cx.redirect("wmv");
            return Ok(());
        }
        let duration = header(&a, cx);
        let mut first = true;
        for s in a.streams.iter().filter(|s| s.kind == "audio") {
            let Some(st) = stream(s) else { continue };
            if first {
                st.report(cx, duration, src.len());
                first = false;
            } else {
                cx.physical().stream(serde_json::Map::from_iter([
                    ("type".to_string(), json!("audio")),
                    ("codec".to_string(), json!(st.codec)),
                ]));
            }
        }
        if first && let Some(d) = duration {
            cx.physical().duration_s(super::round_s(d));
        }
        tags(&a, cx);
        Ok(())
    }
}

crate::register_extractor!(Wma);

/// An audio stream of an ASF file.
pub(crate) fn stream(s: &asf::Stream) -> Option<Stream> {
    let w = s.audio?;
    let mut st = Stream::new(riff::codec(w.tag));
    st.sample_rate_hz = Some(w.rate);
    st.channels = Some(w.channels);
    st.bits_per_sample = Some(w.bits).filter(|b| *b > 0 && matches!(w.tag, 1 | 3 | 0x163));
    st.bitrate_bps = Some(u64::from(w.byte_rate) * 8).filter(|b| *b > 0);
    st.language.clone_from(&s.language);
    Some(st)
}

/// The header objects, file properties, DRM and codec list; the duration.
pub(crate) fn header(a: &asf::Asf, cx: &mut Context<'_>) -> Option<f64> {
    cx.format_set("header_objects", json!(a.objects));
    let mut duration = None;
    if let Some(f) = a.file {
        duration = f.duration_s();
        cx.format_set("packets", f.packets);
        cx.format_set("preroll_ms", f.preroll_ms);
        cx.format_set("seekable", f.seekable);
        cx.format_set("broadcast", f.broadcast);
        if f.max_bitrate > 0 {
            cx.format_set("max_bitrate_bps", f.max_bitrate);
        }
        if let Some(t) = filetime(f.created) {
            cx.temporal().source("asf.file_properties.creation_date").content_date(DateField::Created, t, true);
        }
    }
    if a.encrypted || a.streams.iter().any(|s| s.encrypted) {
        cx.format_set("drm", true);
        cx.security().encrypted(true);
    }
    if !a.codecs.is_empty() {
        let list: Vec<_> = a
            .codecs
            .iter()
            .map(|(k, n, d)| {
                json!({ "type": match k { 1 => "video", 2 => "audio", _ => "unknown" }, "name": n, "description": d })
            })
            .collect();
        cx.format_set("codecs", json!(list));
    }
    duration
}

/// The content description and attributes, normalised.
pub(crate) fn tags(a: &asf::Asf, cx: &mut Context<'_>) {
    let mut tags = Tags::default();
    tags.system("asf");
    for (name, text) in &a.content {
        let key = match *name {
            "Title" => Some("title"),
            "Author" => Some("artist"),
            "Copyright" => Some("copyright"),
            "Description" => Some("comment"),
            _ => None,
        };
        if let Some(k) = key {
            tags.set(k, text, "asf");
        }
        add_raw(cx, "asf", name, json!(text));
    }
    for (name, v) in &a.attributes {
        attribute(name, v, cx, &mut tags);
    }
    tags.report(cx);
}

fn wm_key(name: &str) -> Option<&'static str> {
    Some(match name {
        "WM/AlbumTitle" => "album",
        "WM/AlbumArtist" => "album_artist",
        "WM/TrackNumber" => "track",
        "WM/PartOfSet" => "disc",
        "WM/Year" => "date",
        "WM/OriginalReleaseYear" | "WM/OriginalReleaseTime" => "original_date",
        "WM/Genre" => "genre",
        "WM/Composer" => "composer",
        "WM/Writer" => "lyricist",
        "WM/Conductor" => "conductor",
        "WM/ModifiedBy" => "remixer",
        "WM/Publisher" => "label",
        "WM/ISRC" => "isrc",
        "WM/Barcode" => "barcode",
        "WM/CatalogNo" => "catalog_number",
        "WM/BeatsPerMinute" => "bpm",
        "WM/InitialKey" => "key",
        "WM/Mood" => "mood",
        "WM/ContentGroupDescription" => "grouping",
        "WM/Language" => "language",
        "WM/IsCompilation" => "compilation",
        "WM/Lyrics" => "lyrics",
        "WM/EncodedBy" => "encoded_by",
        "WM/ToolName" | "WM/EncodingSettings" => "encoder",
        "WM/SubTitle" => "subtitle",
        "MusicBrainz/Track Id" => "musicbrainz_recording_id",
        "MusicBrainz/Release Track Id" => "musicbrainz_track_id",
        "MusicBrainz/Album Id" => "musicbrainz_album_id",
        "MusicBrainz/Artist Id" => "musicbrainz_artist_id",
        "MusicBrainz/Album Artist Id" => "musicbrainz_album_artist_id",
        "MusicBrainz/Release Group Id" => "musicbrainz_release_group_id",
        "Acoustid/Id" => "acoustid_id",
        _ => return freeform_key(name),
    })
}

fn attribute(name: &str, v: &Attr, cx: &mut Context<'_>, tags: &mut Tags) {
    let raw = match v {
        Attr::Text(t) => {
            if let Some(k) = wm_key(name) {
                tags.set(k, t, "asf");
            }
            if name == "WM/Lyrics" { json!(t.chars().count()) } else { json!(crate::plugin::truncate_chars(t, 2000)) }
        }
        Attr::Int(n) => {
            match name {
                // WM/Track is zero-based; WM/TrackNumber is not.
                "WM/Track" => tags.set("track", &(n + 1).to_string(), "asf"),
                "WM/IsCompilation" => tags.set("compilation", if *n != 0 { "1" } else { "0" }, "asf"),
                _ => {
                    if let Some(k) = wm_key(name) {
                        tags.set(k, &n.to_string(), "asf");
                    }
                }
            }
            json!(n)
        }
        Attr::Bool(b) => {
            if name == "WM/IsCompilation" {
                tags.set("compilation", if *b { "1" } else { "0" }, "asf");
            }
            json!(b)
        }
        Attr::Guid(g) => json!(g),
        Attr::Bytes(b) => {
            if name == "WM/Picture"
                && let Some((kind, mime, description, data)) = asf::picture(b)
            {
                let mime =
                    if mime.contains('/') { mime.to_ascii_lowercase() } else { super::sniff_image(data).to_string() };
                tags.pictures.push(Picture {
                    mime,
                    kind: Some(kind),
                    description,
                    width: None,
                    height: None,
                    data: data.to_vec(),
                });
            }
            json!({ "binary_bytes": b.len() })
        }
    };
    add_raw(cx, "asf", name, raw);
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("wma");
}
