//! macOS bookmark data and the alias files Finder writes with it: the
//! target's path, name, kind and creation date, the volume (name, mount
//! path, creation date, boot volume or not), whether the bookmark carries
//! a sandbox security scope. Path components under a user's home folder
//! and the user name stored in the bookmark are hidden when privacy is
//! strict.
//!
//! Specification: the `CFURL` bookmark layout as documented by the
//! `mac_alias` project and Patrick Wardle's / Howard Oakley's notes
//! (header, table of contents, typed items).

use serde_json::{Map, Value};

use super::{le_usize, unix_time};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
    truncate_chars, user_path,
};

/// Extractor for bookmarks and alias files.
pub struct Bookmark;

static META: ExtractorMeta = ExtractorMeta {
    id: "apple.bookmark",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "alias",
            name: "macOS alias / bookmark data",
            family: "apple",
            mimes: &[],
            extensions: &["alias"],
            magic: &[Magic::at(0, b"book\0\0\0\0mark")],
            parent: None,
        },
        FormatSpec {
            id: "bookmark_data",
            name: "macOS bookmark data",
            family: "apple",
            mimes: &[],
            extensions: &["bookmark"],
            magic: &[],
            parent: None,
        },
    ],
};

/// Seconds from 1970 to 2001-01-01, the `CFAbsoluteTime` epoch.
const CF_EPOCH: f64 = 978_307_200.0;
/// Items read from one array.
const MAX_ITEMS: usize = 256;

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn at(b: &[u8], off: usize) -> Option<usize> {
    Some(le_usize(b.get(off..off + 4)?))
}

/// A typed item at `off` of the bookmark data `d`.
#[derive(Debug, PartialEq)]
enum Item {
    Str(String),
    Data(Vec<u8>),
    Num(i64),
    Date(f64),
    Bool(bool),
    Array(Vec<usize>),
    Other,
}

fn item(d: &[u8], off: usize) -> Option<Item> {
    let len = at(d, off)?;
    let ty = le32(d, off + 4)?;
    let body = d.get(off + 8..off.checked_add(8)?.checked_add(len)?)?;
    Some(match ty {
        0x0101 => Item::Str(String::from_utf8_lossy(body).into_owned()),
        0x0201 => Item::Data(body.to_vec()),
        0x0303 => Item::Num(i64::from(i32::from_le_bytes(body.get(..4)?.try_into().ok()?))),
        0x0304 => Item::Num(i64::from_le_bytes(body.get(..8)?.try_into().ok()?)),
        0x0400 => Item::Date(f64::from_be_bytes(body.get(..8)?.try_into().ok()?)),
        0x0500 => Item::Bool(false),
        0x0501 => Item::Bool(true),
        0x0601 => Item::Array(body.as_chunks::<4>().0.iter().take(MAX_ITEMS).map(|c| le_usize(c)).collect()),
        _ => Item::Other,
    })
}

#[allow(clippy::cast_possible_truncation)] // range-checked whole seconds
fn date(secs: f64) -> Option<String> {
    let t = (secs + CF_EPOCH).floor();
    (0.0..1e11).contains(&t).then(|| unix_time(t as i64))?
}

/// The table of contents: key → item offset (first TOC only).
fn toc(d: &[u8]) -> Option<Vec<(u32, usize)>> {
    let first = at(d, 0)?;
    let count = at(d, first + 16)?;
    if le32(d, first + 4)? != 0xffff_fffe {
        return None;
    }
    Some(
        (0..count.min(1024))
            .map_while(|i| Some((le32(d, first + 20 + 12 * i)?, at(d, first + 24 + 12 * i)?)))
            .collect(),
    )
}

impl Extractor for Bookmark {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // In-memory bookmark data: `book`, size, version, header size.
        let h = probe.head;
        let ok = h.starts_with(b"book")
            && le32(h, 12).is_some_and(|n| (0x30..=0x100).contains(&n))
            && le32(h, 8).is_some_and(|v| v >> 16 == 0x1004 || v >> 16 == 0x1005);
        ok.then_some(Sniff { format: "bookmark_data", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, _) = cx.read_bytes(src)?;
        // Alias files put an 8-byte `mark` prefix before the header fields.
        let (file, hdr) =
            if data.starts_with(b"book\0\0\0\0mark") { (true, at(&data, 16)) } else { (false, at(&data, 12)) };
        let hdr =
            hdr.filter(|&h| h >= 16 && h < data.len()).ok_or_else(|| ExtractError::malformed("bookmark header"))?;
        let d = &data[hdr..];
        cx.format_set("kind", if file { "alias_file" } else { "bookmark" });
        let entries = toc(d).ok_or_else(|| ExtractError::malformed("bookmark table of contents"))?;
        let get = |key: u32| entries.iter().find(|(k, _)| *k == key).and_then(|&(_, off)| item(d, off));
        let strings = |key: u32| -> Vec<String> {
            match get(key) {
                Some(Item::Array(offs)) => offs
                    .iter()
                    .filter_map(|&o| match item(d, o) {
                        Some(Item::Str(s)) => Some(s),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            }
        };
        let path = strings(0x1004);
        if !path.is_empty() {
            let full = format!("/{}", path.join("/"));
            let shown = user_path(cx, &full);
            cx.format_set("target_path", shown);
        }
        if let Some(Item::Str(n)) = get(0xf017) {
            cx.format_set("target_name", truncate_chars(&n, 255));
        } else if let Some(n) = path.last() {
            cx.format_set("target_name", truncate_chars(n, 255));
        }
        if let Some(Item::Data(p)) = get(0x1010)
            && p.len() >= 16
        {
            let flags = u64::from_le_bytes(p[..8].try_into().unwrap_or_default());
            let kind = if flags & 2 != 0 {
                "directory"
            } else if flags & 4 != 0 {
                "symlink"
            } else if flags & 1 != 0 {
                "file"
            } else {
                "unknown"
            };
            cx.format_set("target_kind", kind);
            if flags & 0x2000 != 0 {
                cx.format_set("target_is_package", true);
            }
        }
        if let Some(Item::Date(t)) = get(0x1040)
            && let Some(t) = date(t)
        {
            cx.format_set("target_created", t.clone());
            cx.temporal().content_date(DateField::Other, t, true);
        }
        let mut vol = Map::new();
        if let Some(Item::Str(n)) = get(0x2010) {
            vol.insert("name".into(), truncate_chars(&n, 255).into());
        }
        if let Some(Item::Str(p)) = get(0x2002) {
            vol.insert("path".into(), truncate_chars(&p, 1000).into());
        }
        if let Some(Item::Date(t)) = get(0x2013)
            && let Some(t) = date(t)
        {
            vol.insert("created".into(), t.into());
        }
        if let Some(Item::Bool(b)) = get(0x2030) {
            vol.insert("boot".into(), b.into());
        }
        if let Some(Item::Num(n)) = get(0x2012) {
            vol.insert("size".into(), Value::from(n));
        }
        if !vol.is_empty() {
            cx.format_set("volume", Value::Object(vol));
        }
        if !cx.privacy_strict()
            && let Some(Item::Str(u)) = get(0xc011)
        {
            cx.format_set("user", u);
        }
        if entries.iter().any(|(k, _)| *k == 0xf080) {
            cx.format_set("security_scope", true);
        }
        Ok(())
    }
}

crate::register_extractor!(Bookmark);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_items() {
        let mut d = vec![0u8; 8];
        d.extend(5u32.to_le_bytes());
        d.extend(0x0101u32.to_le_bytes());
        d.extend(b"tides\0\0\0");
        assert_eq!(item(&d, 8), Some(Item::Str("tides".into())));
        assert_eq!(item(&d[..14], 8), None);
        assert_eq!(date(0.0).as_deref(), Some("2001-01-01T00:00:00Z"));
    }

    crate::fixture_tests!("alias", "bookmark_data");
}
