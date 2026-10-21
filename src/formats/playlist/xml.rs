//! XML playlists: XSPF (title, creator, annotation, date, licence, tracks
//! with location, title, creator, album, duration), Windows Media ASX
//! (title, author, copyright, entries with references and durations,
//! entry references) and Windows Media / Zune playlists (WPL / ZPL: the
//! generator, declared item count and total duration, media items).
//!
//! Specifications: <https://xspf.org/spec>; the ASX and WPL element
//! references of the Windows Media Player SDK.

use super::super::text::{XmlNode, XmlTree, decode_xml, start_tag, xml_root};
use super::{Entry, Playlist, artist_title};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, parse_date,
};

/// Extractor for XML playlists.
pub struct Xml;

static META: ExtractorMeta = ExtractorMeta {
    id: "playlist.xml",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "xspf",
            name: "XSPF playlist",
            family: "audio.playlist",
            mimes: &["application/xspf+xml"],
            extensions: &["xspf"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "asx",
            name: "Windows Media ASX playlist",
            family: "audio.playlist",
            mimes: &["video/x-ms-asf-plugin", "audio/x-ms-wax", "video/x-ms-wvx"],
            extensions: &["asx", "wax", "wvx"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "wpl",
            name: "Windows Media playlist",
            family: "audio.playlist",
            mimes: &["application/vnd.ms-wpl"],
            extensions: &["wpl", "zpl"],
            magic: &[],
            parent: Some("xml"),
        },
    ],
};

impl Extractor for Xml {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let found = |format| Some(Sniff { format, confidence: 0.95 });
        let root = xml_root(probe.head)?;
        let head = String::from_utf8_lossy(&probe.head[..probe.head.len().min(1024)]).to_ascii_lowercase();
        match root.to_ascii_lowercase().as_str() {
            "playlist" if start_tag(probe.head, &root).is_some_and(|t| t.contains("xspf.org/ns/0")) => found("xspf"),
            "asx" => found("asx"),
            "smil" if head.contains("<?wpl") || head.contains("<?zpl") => found("wpl"),
            _ => None,
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, _) = cx.read_bytes(src)?;
        let text = decode_xml(&bytes);
        let tree = XmlTree::parse(&text).map_err(ExtractError::malformed)?;
        cx.checkpoint()?;
        let p = match cx.format_id() {
            "asx" => asx(&tree),
            "wpl" => wpl(&tree),
            _ => xspf(&tree),
        };
        p.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Xml);

/// Attribute by name, ignoring case (ASX writers use `HREF` and `href`).
fn attr<'a>(n: &'a XmlNode, name: &str) -> Option<&'a str> {
    n.attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()).filter(|v| !v.is_empty())
}

fn xspf(tree: &XmlTree) -> Playlist {
    let root = tree.root();
    let mut p = Playlist::default();
    let text = |n: &XmlNode, k: &str| tree.text(n, k).map(str::to_string);
    p.title = text(root, "title");
    p.author = text(root, "creator");
    p.description = text(root, "annotation");
    p.date = tree.text(root, "date").and_then(parse_date);
    p.set("version", attr(root, "version"));
    p.license = text(root, "license");
    p.set("info", text(root, "info"));
    let mut extensions = 0u64;
    for list in tree.children(root, "trackList") {
        for t in tree.children(list, "track") {
            extensions += tree.children(t, "extension").count() as u64;
            p.push(Entry {
                location: text(t, "location"),
                title: text(t, "title"),
                artist: text(t, "creator"),
                album: text(t, "album"),
                duration: tree.text(t, "duration").and_then(|d| d.parse::<f64>().ok()).map(|ms| ms / 1000.0),
                group: None,
            });
        }
    }
    if extensions > 0 {
        p.set("track_extensions", extensions);
    }
    p
}

/// An ASX duration: `00:03:20.5` or seconds.
fn asx_duration(v: &str) -> Option<f64> {
    super::super::subtitle::clock(v)
}

fn asx(tree: &XmlTree) -> Playlist {
    let root = tree.root();
    let mut p = Playlist::default();
    let text = |n: &XmlNode, k: &str| tree.text(n, k).map(str::to_string);
    p.title = text(root, "title");
    p.author = text(root, "author");
    p.description = text(root, "abstract");
    p.set("version", attr(root, "version"));
    p.copyright = text(root, "copyright");
    let (mut refs, mut entryrefs) = (0u64, 0u64);
    for c in tree.children(root, "*") {
        match c.name.to_ascii_lowercase().as_str() {
            "entry" => {
                let r: Vec<&XmlNode> = tree.children(c, "ref").collect();
                refs += r.len() as u64;
                let (artist, title) = match (text(c, "author"), text(c, "title")) {
                    (Some(a), t) => (Some(a), t),
                    (None, Some(t)) => artist_title(&t),
                    (None, None) => (None, None),
                };
                p.push(Entry {
                    location: r.first().and_then(|r| attr(r, "href")).map(str::to_string),
                    title,
                    artist,
                    album: None,
                    duration: tree.child(c, "duration").and_then(|d| attr(d, "value")).and_then(asx_duration),
                    group: None,
                });
            }
            "entryref" => {
                entryrefs += 1;
                p.push(Entry { location: attr(c, "href").map(str::to_string), ..Entry::default() });
            }
            _ => {}
        }
    }
    if refs > 0 {
        p.set("references", refs);
    }
    if entryrefs > 0 {
        p.set("entry_references", entryrefs);
    }
    p
}

fn wpl(tree: &XmlTree) -> Playlist {
    let root = tree.root();
    let mut p = Playlist::default();
    if let Some(head) = tree.child(root, "head") {
        p.title = tree.text(head, "title").map(str::to_string);
        p.author = tree.text(head, "author").map(str::to_string);
        for m in tree.children(head, "meta") {
            let (Some(name), Some(content)) = (attr(m, "name"), attr(m, "content")) else { continue };
            match name.to_ascii_lowercase().as_str() {
                "generator" => p.set("generator", content),
                "itemcount" => p.set("declared_entries", content.parse::<u64>().ok()),
                "totalduration" => p.duration = content.parse::<f64>().ok().map(|ms| ms / 1000.0),
                "contentpartnername" => p.set("content_partner", content),
                _ => {}
            }
        }
    }
    let Some(body) = tree.child(root, "body") else { return p };
    let mut smart = false;
    for seq in tree.children(body, "seq") {
        smart |= tree.child(seq, "smartPlaylist").is_some();
        for m in tree.children(seq, "media") {
            p.push(Entry {
                location: attr(m, "src").map(str::to_string),
                title: attr(m, "trackTitle").map(str::to_string),
                artist: attr(m, "trackArtist").map(str::to_string),
                album: attr(m, "albumTitle").map(str::to_string),
                duration: attr(m, "duration").and_then(|d| d.parse::<f64>().ok()).map(|ms| ms / 1000.0),
                group: None,
            });
        }
    }
    if smart {
        p.set("auto_playlist", true);
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("xspf", "asx", "wpl");

    #[test]
    fn xml_playlists() {
        let t = XmlTree::parse("<playlist version=\"1\" xmlns=\"http://xspf.org/ns/0/\"><title>Mix</title><trackList><track><location>file:///m/a.ogg</location><title>A</title><creator>Band</creator><duration>125000</duration></track></trackList></playlist>").unwrap();
        let p = xspf(&t);
        assert_eq!(
            p.entries[0],
            Entry {
                location: Some("file:///m/a.ogg".into()),
                title: Some("A".into()),
                artist: Some("Band".into()),
                album: None,
                duration: Some(125.0),
                group: None
            }
        );
        let t = XmlTree::parse("<ASX VERSION=\"3.0\"><TITLE>Radio</TITLE><ENTRY><TITLE>Band - Live</TITLE><REF HREF=\"mms://radio.example/live\"/><DURATION VALUE=\"00:01:00\"/></ENTRY><ENTRYREF HREF=\"http://radio.example/more.asx\"/></ASX>").unwrap();
        let p = asx(&t);
        assert_eq!(p.entries.len(), 2);
        assert_eq!((p.entries[0].artist.as_deref(), p.entries[0].duration), (Some("Band"), Some(60.0)));
        assert_eq!(p.format["entry_references"], 1);
        let t = XmlTree::parse("<smil><head><meta name=\"ItemCount\" content=\"1\"/><meta name=\"TotalDuration\" content=\"61000\"/><title>Evening</title></head><body><seq><media src=\"..\\Music\\a.wma\"/></seq></body></smil>").unwrap();
        let p = wpl(&t);
        assert_eq!((p.duration, p.entries.len(), p.title.as_deref()), (Some(61.0), 1, Some("Evening")));
    }
}
