//! APEv1 / APEv2 tags (Monkey's Audio, WavPack, Musepack, TTA, and MP3
//! files tagged by foobar2000 or mp3gain), found before an ID3v1 tag at the
//! end of the file.
//!
//! Specification: the APEv2 description on wiki.hydrogenaud.io.

use serde_json::json;

use super::{Picture, Tags, comment_key, sniff_image};
use crate::plugin::{ByteReader, Context, ExtractError, Source, latin1_or_utf8};

/// Largest tag read (cover art included).
const MAX_TAG: u64 = 16 << 20;
/// Items read.
const MAX_ITEMS: usize = 4096;

/// Read an APE tag whose footer ends `trailing` bytes before the end of the
/// file (the ID3v1 tag's length, or 0) into `tags` and `metadata.ape`.
/// Returns the bytes the tag takes (0 if there is none).
pub(crate) fn read(
    src: &mut dyn Source,
    trailing: u64,
    cx: &mut Context<'_>,
    tags: &mut Tags,
) -> Result<u64, ExtractError> {
    let end = src.len().saturating_sub(trailing);
    let Some(at) = end.checked_sub(32) else { return Ok(0) };
    let Ok(footer) = src.read_vec(at, 32) else { return Ok(0) };
    if &footer[..8] != b"APETAGEX" {
        return Ok(0);
    }
    let mut r = ByteReader::new(&footer[8..]);
    let (version, size, count, flags) = (r.le_u32()?, r.le_u32()?, r.le_u32()?, r.le_u32()?);
    let size = u64::from(size);
    if !(32..=MAX_TAG).contains(&size) || size > end {
        cx.warn("APE tag size out of range");
        return Ok(0);
    }
    let has_header = flags & 0x8000_0000 != 0;
    let items = src.read_vec(end - size, usize::try_from(size - 32).unwrap_or(0))?;
    tags.system(if version >= 2000 { "apev2" } else { "apev1" });
    parse_items(&items, count, cx, tags);
    Ok(size + if has_header { 32 } else { 0 })
}

fn parse_items(data: &[u8], count: u32, cx: &mut Context<'_>, tags: &mut Tags) {
    let mut r = ByteReader::new(data);
    for _ in 0..(count as usize).min(MAX_ITEMS) {
        let (Ok(len), Ok(flags)) = (r.le_u32(), r.le_u32()) else { break };
        let Ok(key) = r.cstr() else { break };
        let Ok(value) = r.bytes(len as usize) else { break };
        let key = latin1_or_utf8(key);
        let upper = key.to_ascii_uppercase();
        match (flags >> 1) & 3 {
            0 => {
                // Text; several values are separated by NULs.
                let text = String::from_utf8_lossy(value);
                let values: Vec<&str> = text.split('\0').filter(|v| !v.is_empty()).collect();
                if let Some(k) = comment_key(&upper) {
                    for v in &values {
                        tags.set(k, v, "ape");
                    }
                }
                let v = if upper == "LYRICS" {
                    json!(text.chars().count())
                } else if values.len() > 1 {
                    json!(values)
                } else {
                    json!(crate::plugin::truncate_chars(&text, 2000))
                };
                cx.metadata_set("ape", &key, v);
            }
            1 if upper.starts_with("COVER ART") => {
                // "file name\0image data"
                let at = value.iter().position(|&b| b == 0).map_or(0, |i| i + 1);
                let image = &value[at..];
                tags.pictures.push(Picture {
                    mime: sniff_image(image).to_string(),
                    kind: Some(if upper.contains("BACK") { 4 } else { 3 }),
                    description: latin1_or_utf8(&value[..at.saturating_sub(1)]),
                    width: None,
                    height: None,
                    data: image.to_vec(),
                });
                cx.metadata_set("ape", &key, json!({ "binary_bytes": value.len() }));
            }
            1 => cx.metadata_set("ape", &key, json!({ "binary_bytes": value.len() })),
            _ => cx.metadata_set("ape", &key, json!(String::from_utf8_lossy(value))),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::plugin::testing::report_for;

    #[test]
    #[allow(clippy::cast_possible_truncation)] // test items are small
    fn reads_items_before_id3v1() {
        // A Musepack SV7-looking stub followed by an APEv2 tag and ID3v1.
        let mut items = Vec::new();
        for (k, v) in [("Title", "Shoals"), ("Artist", "A\0B"), ("Track", "2/5")] {
            items.extend_from_slice(&(v.len() as u32).to_le_bytes());
            items.extend_from_slice(&0u32.to_le_bytes());
            items.extend_from_slice(k.as_bytes());
            items.push(0);
            items.extend_from_slice(v.as_bytes());
        }
        let size = items.len() as u32 + 32;
        let mut file = b"MP+\x17".to_vec();
        file.resize(64, 0);
        file.extend(items);
        file.extend_from_slice(b"APETAGEX");
        for v in [2000u32, size, 3, 0, 0, 0] {
            file.extend_from_slice(&v.to_le_bytes());
        }
        let r = report_for("shoals.mpc", &file);
        assert_eq!(r.format["mpc"]["tags"]["title"], "Shoals");
        assert_eq!(r.format["mpc"]["tags"]["artist"], serde_json::json!(["A", "B"]));
        assert_eq!(r.format["mpc"]["tags"]["track_total"], 5);
    }
}
