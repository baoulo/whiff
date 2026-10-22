//! Vorbis comments (FLAC, Ogg Vorbis, Opus, Speex, Ogg FLAC) and the FLAC
//! picture structure, also carried base64-encoded in a
//! `METADATA_BLOCK_PICTURE` comment.
//!
//! Specifications: Vorbis I §5 (comment header), RFC 9639 §8.8 (picture).

use serde_json::json;

use super::{Chapter, Picture, Tags, add_raw, comment_key};
use crate::plugin::{ByteReader, Context};

/// Comments read from one block.
const MAX_COMMENTS: usize = 10_000;

/// Parse a comment block (vendor string, count, `KEY=value` entries; no
/// framing bit) into `tags` and `metadata.<standard>`. `standard` is
/// `vorbis` for every container.
pub(crate) fn comments(data: &[u8], cx: &mut Context<'_>, tags: &mut Tags) {
    let mut r = ByteReader::new(data);
    let Ok(n) = r.le_u32() else { return };
    let Ok(vendor) = r.bytes(n as usize) else { return };
    let vendor = String::from_utf8_lossy(vendor).trim().to_string();
    tags.system("vorbis");
    if !vendor.is_empty() {
        cx.metadata_set("vorbis", "vendor", vendor.as_str());
        tags.set("encoder", &vendor, "vorbis");
    }
    let Ok(count) = r.le_u32() else { return };
    let mut chapters: Vec<(u32, Option<f64>, String)> = Vec::new();
    for _ in 0..(count as usize).min(MAX_COMMENTS) {
        let Ok(len) = r.le_u32() else { break };
        let Ok(entry) = r.bytes(len as usize) else { break };
        let entry = String::from_utf8_lossy(entry);
        let Some((key, value)) = entry.split_once('=') else { continue };
        let upper = key.trim().to_ascii_uppercase();
        if upper == "METADATA_BLOCK_PICTURE" {
            if let Some(p) = base64(value).and_then(|b| picture(&b)) {
                tags.pictures.push(p);
            }
            continue;
        }
        if upper == "COVERART" {
            // The pre-standard form: base64 image data alone.
            if let Some(b) = base64(value) {
                tags.pictures.push(Picture {
                    mime: super::sniff_image(&b).to_string(),
                    kind: None,
                    description: String::new(),
                    width: None,
                    height: None,
                    data: b,
                });
            }
            continue;
        }
        // Ogg chapters (CHAPTER001=00:00:00.000, CHAPTER001NAME=…).
        if let Some(rest) = upper.strip_prefix("CHAPTER") {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(n) = digits.parse::<u32>() {
                let i = chapters.iter().position(|c| c.0 == n).unwrap_or_else(|| {
                    chapters.push((n, None, String::new()));
                    chapters.len() - 1
                });
                if rest[digits.len()..].is_empty() {
                    chapters[i].1 = clock(value);
                } else if &rest[digits.len()..] == "NAME" {
                    chapters[i].2 = value.trim().to_string();
                }
                continue;
            }
        }
        if let Some(k) = comment_key(&upper) {
            tags.set(k, value, "vorbis");
        }
        let v = if upper == "LYRICS" || upper == "UNSYNCEDLYRICS" {
            json!(value.chars().count())
        } else {
            json!(crate::plugin::truncate_chars(value, 2000))
        };
        add_raw(cx, "vorbis", &upper, v);
    }
    chapters.sort_by_key(|c| c.0);
    for (_, start, title) in chapters {
        if let Some(start_s) = start {
            tags.chapters.push(Chapter { start_s, end_s: None, title });
        }
    }
}

/// `HH:MM:SS.sss` as seconds.
fn clock(v: &str) -> Option<f64> {
    let mut parts = v.trim().split(':').rev();
    let s: f64 = parts.next()?.parse().ok()?;
    let m: f64 = parts.next().map_or(Ok(0.0), str::parse).ok()?;
    let h: f64 = parts.next().map_or(Ok(0.0), str::parse).ok()?;
    Some(h * 3600.0 + m * 60.0 + s)
}

/// A FLAC picture block (big-endian lengths).
pub(crate) fn picture(data: &[u8]) -> Option<Picture> {
    let mut r = ByteReader::new(data);
    let kind = r.be_u32().ok()?;
    let n = r.be_u32().ok()? as usize;
    let mime = String::from_utf8_lossy(r.bytes(n).ok()?).to_ascii_lowercase();
    let n = r.be_u32().ok()? as usize;
    let description = String::from_utf8_lossy(r.bytes(n).ok()?).into_owned();
    let (width, height) = (r.be_u32().ok()?, r.be_u32().ok()?);
    let (_depth, _colours) = (r.be_u32().ok()?, r.be_u32().ok()?);
    let n = r.be_u32().ok()? as usize;
    let image = r.bytes(n).ok()?;
    let mime = if mime == "-->" {
        "text/uri-list".to_string() // a link to the picture, not the picture
    } else if mime.is_empty() || mime == "image/jpg" {
        super::sniff_image(image).to_string()
    } else {
        mime
    };
    Some(Picture {
        mime,
        kind: u8::try_from(kind).ok(),
        description,
        width: Some(width),
        height: Some(height),
        data: image.to_vec(),
    })
}

/// Decode standard base64 (padding optional, whitespace ignored).
pub(crate) fn base64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    #[allow(clippy::cast_possible_truncation)] // test comments are small
    fn chapters_and_pictures_in_comments() {
        // A FLAC file: STREAMINFO (44.1 kHz stereo, 1 s) and a comment block.
        let mut info = vec![0x10, 0, 0x10, 0, 0, 0, 0, 0, 0, 0];
        let x: u64 = (0xac44 << 44) | (1 << 41) | (15 << 36) | 0xac44; // 44.1 kHz, stereo, 16 bits, 44 100 samples
        info.extend_from_slice(&x.to_be_bytes());
        info.extend_from_slice(&[0; 16]);
        let mut comments = 4u32.to_le_bytes().to_vec();
        comments.extend_from_slice(b"test");
        let entries = [
            "CHAPTER001=00:00:00.000",
            "CHAPTER001NAME=Gulls",
            "CHAPTER002=00:00:00.500",
            "CHAPTER002NAME=Bells",
            "ARTIST=A",
            "ARTIST=B",
            "COVERART=iVBORw0KGgo=",
        ];
        comments.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for e in entries {
            comments.extend_from_slice(&(e.len() as u32).to_le_bytes());
            comments.extend_from_slice(e.as_bytes());
        }
        let mut file = b"fLaC\x00\x00\x00\x22".to_vec();
        file.extend(info);
        file.push(0x84);
        file.extend_from_slice(&(comments.len() as u32).to_be_bytes()[1..]);
        file.extend(comments);
        let r = crate::plugin::testing::report_for("gulls.flac", &file);
        let f = &r.format["flac"];
        assert_eq!(f["chapters"][1]["title"], "Bells");
        assert_eq!(f["chapters"][1]["start_s"], 0.5);
        assert_eq!(f["tags"]["artist"], json!(["A", "B"]));
        assert_eq!(f["cover_art"][0]["mime"], "image/png");
        assert_eq!(r.physical.media.as_ref().unwrap().duration_s, Some(1.0));
    }

    #[test]
    fn base64_and_clock() {
        assert_eq!(base64("aGVsbG8=").as_deref(), Some(&b"hello"[..]));
        assert_eq!(base64("aGVsbG8").as_deref(), Some(&b"hello"[..]));
        assert_eq!(base64("a?b"), None);
        assert_eq!(clock("00:01:30.500"), Some(90.5));
        assert_eq!(clock("x"), None);
    }
}
