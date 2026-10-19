//! Mobipocket / Kindle (MOBI, AZW, AZW3 / KF8) and PalmDOC: the Palm
//! database header, the MOBI header, EXTH metadata records and the text
//! records (uncompressed or PalmDOC-compressed; HUFF/CDIC text is not read).
//!
//! References: the MobileRead wiki "MOBI" and "PDB" pages.

use serde_json::json;

use super::Book;
use crate::plugin::{Context, ExtractError, Source, truncate_chars};

const MAX_RECORDS: usize = 65_535;

/// Whether the head of a `BOOKMOBI` file is a KF8-only book (MOBI version 8).
pub(super) fn is_kf8(head: &[u8]) -> bool {
    let Some(first) = head.get(78..82) else { return false };
    let off = u32::from_be_bytes([first[0], first[1], first[2], first[3]]) as usize;
    head.get(off + 16..off + 20) == Some(b"MOBI")
        && head.get(off + 36..off + 40).is_some_and(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]) == 8)
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    b.get(i..i + 2).map(|x| u16::from_be_bytes([x[0], x[1]]))
}

fn be32(b: &[u8], i: usize) -> Option<u32> {
    b.get(i..i + 4).map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]))
}

/// A Palm date: seconds since 1904 (top bit set) or since 1970.
fn palm_date(v: u32) -> Option<String> {
    if v == 0 {
        return None;
    }
    let unix = if v & 0x8000_0000 != 0 { i64::from(v) - 2_082_844_800 } else { i64::from(v) };
    let (y, m, d) = civil(unix.div_euclid(86_400));
    let secs = unix.rem_euclid(86_400);
    Some(format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60))
}

/// Days since 1970-01-01 → (year, month, day) (H. Hinnant's algorithm).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[allow(clippy::too_many_lines)] // Palm, MOBI and EXTH headers in order
pub(super) fn extract(src: &mut dyn Source, cx: &mut Context<'_>, book: &mut Book) -> Result<(), ExtractError> {
    let len = src.len();
    let mut header = vec![0u8; 78usize.min(usize::try_from(len).unwrap_or(0))];
    src.read_exact_at(0, &mut header)?;
    if header.len() < 78 {
        return Err(ExtractError::malformed("short Palm database header"));
    }
    let name = String::from_utf8_lossy(header[..32].split(|&b| b == 0).next().unwrap_or_default()).into_owned();
    let kind = String::from_utf8_lossy(&header[60..68]).into_owned();
    book.format.insert("database_name".into(), json!(name));
    book.format.insert("type_creator".into(), json!(kind));
    if let Some(d) = be32(&header, 36).and_then(palm_date) {
        book.format.insert("database_created".into(), json!(d));
    }
    if let Some(d) = be32(&header, 40).and_then(palm_date) {
        book.format.insert("database_modified".into(), json!(d));
    }
    let n = usize::from(be16(&header, 76).unwrap_or(0)).min(MAX_RECORDS);
    let mut table = vec![0u8; n * 8];
    src.read_exact_at(78, &mut table)?;
    let mut offsets: Vec<u64> =
        table.as_chunks::<8>().0.iter().map(|e| u64::from(u32::from_be_bytes([e[0], e[1], e[2], e[3]]))).collect();
    offsets.push(len);
    book.format.insert("records".into(), json!(n));
    let record = |src: &mut dyn Source, i: usize, max: usize| -> Result<Vec<u8>, ExtractError> {
        let (Some(&a), Some(&b)) = (offsets.get(i), offsets.get(i + 1)) else {
            return Err(ExtractError::malformed("record index"));
        };
        if b < a || b > len {
            return Err(ExtractError::malformed("record offsets"));
        }
        let size = usize::try_from(b - a).unwrap_or(usize::MAX).min(max);
        let mut buf = vec![0u8; size];
        src.read_exact_at(a, &mut buf)?;
        Ok(buf)
    };
    let r0 = record(src, 0, 1 << 20)?;
    let compression = be16(&r0, 0).unwrap_or(1);
    let text_records = usize::from(be16(&r0, 8).unwrap_or(0));
    let encryption = be16(&r0, 12).unwrap_or(0);
    book.format.insert(
        "compression".into(),
        json!(match compression {
            1 => "none",
            2 => "palmdoc",
            17_480 => "huff_cdic",
            _ => "unknown",
        }),
    );
    if encryption != 0 {
        book.drm = Some(if encryption == 1 { "mobipocket_old".into() } else { "mobipocket".into() });
    }
    if cx.format_id() == "palmdoc" || r0.get(16..20) != Some(b"MOBI") {
        if book.title.is_none() && !name.is_empty() {
            book.title = Some(name.replace('_', " "));
        }
        return text(src, cx, book, &record, compression, text_records, 0, 1252);
    }
    let mobi_len = be32(&r0, 20).unwrap_or(0) as usize;
    let mobi_type = be32(&r0, 24).unwrap_or(0);
    let encoding = be32(&r0, 28).unwrap_or(1252);
    let version = be32(&r0, 36).unwrap_or(0);
    book.format.insert("mobi_version".into(), json!(version));
    book.format.insert(
        "mobi_type".into(),
        json!(match mobi_type {
            2 => "book",
            3 => "palmdoc",
            4 => "audio",
            232 => "mobipocket_generated",
            248 => "kf8",
            257 => "news",
            258 => "news_feed",
            259 => "news_magazine",
            513 => "pics",
            514 => "word",
            515 => "xls",
            516 => "ppt",
            517 => "text",
            518 => "html",
            _ => "other",
        }),
    );
    book.format.insert("text_encoding".into(), json!(if encoding == 65_001 { "utf-8" } else { "windows-1252" }));
    if let (Some(off), Some(n)) = (be32(&r0, 84), be32(&r0, 88))
        && let Some(raw) = r0.get(off as usize..(off + n) as usize)
    {
        let t = decode(raw, encoding);
        if !t.trim().is_empty() {
            book.title = Some(truncate_chars(t.trim(), 500));
        }
    }
    if let Some(l) = be32(&r0, 92).and_then(locale_language) {
        book.language = Some(l.into());
    }
    if be32(&r0, 128).is_some_and(|f| f & 0x40 != 0) {
        exth(&r0, 16 + mobi_len, encoding, book);
    }
    if be32(&r0, 168).is_some_and(|d| d != 0xFFFF_FFFF && d != 0) && book.drm.is_none() {
        book.drm = Some("mobipocket".into());
    }
    // Offsets in the MOBI header tables count from the start of record 0.
    let extra_flags = if mobi_len >= 0xE4 { be16(&r0, 0xF2).unwrap_or(0) } else { 0 };
    text(src, cx, book, &record, compression, text_records, extra_flags, encoding)
}

/// EXTH records (type, data) into the book.
fn exth(r0: &[u8], at: usize, encoding: u32, book: &mut Book) {
    if r0.get(at..at + 4) != Some(b"EXTH") {
        return;
    }
    let count = be32(r0, at + 8).unwrap_or(0).min(10_000);
    let mut i = at + 12;
    for _ in 0..count {
        let (Some(kind), Some(size)) = (be32(r0, i), be32(r0, i + 4)) else { break };
        let size = size as usize;
        let Some(data) = r0.get(i + 8..i + size.max(8)) else { break };
        i += size.max(8);
        let s = || truncate_chars(decode(data, encoding).trim(), 2000);
        match kind {
            100 => {
                for a in s().split(['&', ';']).map(str::trim).filter(|a| !a.is_empty()) {
                    book.creator(a, "aut");
                }
            }
            101 => book.publisher = Some(s()),
            103 => book.description = Some(s()),
            104 => book.identifier("isbn", &s()),
            105 => {
                if book.subjects.len() < 100 {
                    book.subjects.push(s());
                }
            }
            106 => book.published = Some(s()),
            108 => book.creator(&s(), "ctb"),
            109 => book.rights = Some(s()),
            112 => {
                let v = s();
                book.identifier(if v.to_ascii_lowercase().starts_with("calibre:") { "calibre" } else { "source" }, &v);
            }
            113 | 504 => book.identifier("asin", &s()),
            121 => {
                book.format.insert("kf8_boundary".into(), json!(be32(data, 0)));
            }
            201 => {
                book.cover = Some(json!({ "record_offset": be32(data, 0) }));
            }
            501 => {
                book.format.insert("cde_type".into(), json!(s()));
            }
            503 => book.title = Some(s()),
            524 => book.language = Some(s()),
            535 => {
                book.format.insert("creator_build".into(), json!(s()));
            }
            _ => {}
        }
    }
}

/// Reads record `i`, at most `max` bytes.
type ReadRecord<'a> = dyn Fn(&mut dyn Source, usize, usize) -> Result<Vec<u8>, ExtractError> + 'a;

#[allow(clippy::too_many_arguments)] // one call site per format variant
fn text(
    src: &mut dyn Source,
    cx: &mut Context<'_>,
    book: &mut Book,
    record: &ReadRecord<'_>,
    compression: u16,
    count: usize,
    extra_flags: u16,
    encoding: u32,
) -> Result<(), ExtractError> {
    if book.drm.is_some() || !matches!(compression, 1 | 2) {
        return Ok(());
    }
    let budget = cx.options().limits.max_text_bytes;
    let mut html = Vec::new();
    for i in 1..=count.min(MAX_RECORDS - 1) {
        cx.checkpoint()?;
        let Ok(raw) = record(src, i, 1 << 16) else { break };
        let raw = strip_trailing(&raw, extra_flags);
        let data = if compression == 2 { palmdoc_decompress(raw) } else { raw.to_vec() };
        html.extend_from_slice(&data);
        if html.len() > budget.saturating_mul(4) {
            break;
        }
    }
    let html = decode(&html, encoding);
    let (t, headings) = crate::plugin::html_text(&html, budget);
    if book.toc.is_empty() {
        book.toc = headings.into_iter().filter(|(l, _)| *l <= 3).take(crate::plugin::MAX_OUTLINE).collect();
    }
    book.add_text(&t, budget);
    Ok(())
}

/// Remove the trailing entries a text record carries (MOBI extra data flags).
fn strip_trailing(rec: &[u8], flags: u16) -> &[u8] {
    let mut end = rec.len();
    for bit in 1..16 {
        if flags & (1 << bit) == 0 {
            continue;
        }
        // Backward-encoded size: 7 bits per byte, high bit marks the start.
        let mut size = 0usize;
        let mut shift = 0;
        let mut i = end;
        while i > 0 && shift < 28 {
            i -= 1;
            let b = rec[i];
            size |= usize::from(b & 0x7F) << shift;
            shift += 7;
            if b & 0x80 != 0 {
                break;
            }
        }
        end = end.saturating_sub(size);
    }
    if flags & 1 != 0 && end > 0 {
        let n = usize::from(rec[end - 1] & 3) + 1;
        end = end.saturating_sub(n);
    }
    &rec[..end]
}

/// PalmDOC LZ77 decompression.
pub(super) fn palmdoc_decompress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 2);
    let mut i = 0;
    while i < data.len() {
        let c = data[i];
        i += 1;
        match c {
            0x01..=0x08 => {
                let n = usize::from(c);
                out.extend_from_slice(data.get(i..i + n).unwrap_or_default());
                i += n;
            }
            0x80..=0xBF => {
                let Some(&next) = data.get(i) else { break };
                i += 1;
                let pair = u16::from(c) << 8 | u16::from(next);
                let dist = usize::from((pair >> 3) & 0x07FF);
                let len = usize::from(pair & 7) + 3;
                if dist == 0 || dist > out.len() {
                    continue;
                }
                let start = out.len() - dist;
                for k in 0..len {
                    let b = out[start + k];
                    out.push(b);
                }
            }
            0xC0..=0xFF => {
                out.push(b' ');
                out.push(c ^ 0x80);
            }
            _ => out.push(c),
        }
        if out.len() > 1 << 20 {
            break;
        }
    }
    out
}

fn decode(raw: &[u8], encoding: u32) -> String {
    if encoding == 65_001 {
        String::from_utf8_lossy(raw).into_owned()
    } else {
        encoding_rs::WINDOWS_1252.decode_without_bom_handling(raw).0.into_owned()
    }
}

/// The language of a MOBI locale (low byte: Windows primary language id).
fn locale_language(locale: u32) -> Option<&'static str> {
    Some(match locale & 0xFF {
        0x01 => "ar",
        0x02 => "bg",
        0x03 => "ca",
        0x04 => "zh",
        0x05 => "cs",
        0x06 => "da",
        0x07 => "de",
        0x08 => "el",
        0x09 => "en",
        0x0A => "es",
        0x0B => "fi",
        0x0C => "fr",
        0x0D => "he",
        0x0E => "hu",
        0x0F => "is",
        0x10 => "it",
        0x11 => "ja",
        0x12 => "ko",
        0x13 => "nl",
        0x14 => "no",
        0x15 => "pl",
        0x16 => "pt",
        0x18 => "ro",
        0x19 => "ru",
        0x1A => "hr",
        0x1D => "sv",
        0x1F => "tr",
        0x22 => "uk",
        _ => return None,
    })
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // test books are small
mod tests {
    use super::*;

    #[test]
    fn palmdoc_lz77() {
        // "abcabc" as literals + a back-reference (distance 3, length 3), and a space+letter pair.
        let data = [b'a', b'b', b'c', 0x80, 0x18, 0xE8];
        assert_eq!(palmdoc_decompress(&data), b"abcabc h");
    }

    #[test]
    fn trailing_entries() {
        // One multibyte-overlap byte (flag bit 0): the last byte's low bits say 1 extra byte.
        assert_eq!(strip_trailing(b"text!\x01", 1), b"text");
        // A trailing entry of 3 bytes (flag bit 1), size encoded as 0x83.
        assert_eq!(strip_trailing(b"textxx\x83", 2), b"text");
    }

    #[test]
    fn palm_dates() {
        assert_eq!(palm_date(1_714_552_200).as_deref(), Some("2024-05-01T08:30:00Z"));
        assert_eq!(civil(0), (1970, 1, 1));
    }

    /// A one-record MOBI with EXTH author and ISBN, built in memory.
    #[test]
    fn reads_mobi_headers() {
        let text = b"<html><body><h1>Tides</h1><p>High water at noon.</p></body></html>";
        let title = b"Saltmere Tides";
        let mut exth = b"EXTH".to_vec();
        let recs: [(u32, &[u8]); 2] = [(100, b"Ana Lighthouse"), (104, b"9780306406157")];
        let body: Vec<u8> = recs
            .iter()
            .flat_map(|(t, d)| {
                let mut v = t.to_be_bytes().to_vec();
                v.extend_from_slice(&(d.len() as u32 + 8).to_be_bytes());
                v.extend_from_slice(d);
                v
            })
            .collect();
        exth.extend_from_slice(&(body.len() as u32 + 12).to_be_bytes());
        exth.extend_from_slice(&(recs.len() as u32).to_be_bytes());
        exth.extend_from_slice(&body);
        let mobi_len = 0xE8u32;
        let mut r0 = vec![0u8; 16 + mobi_len as usize];
        r0[0..2].copy_from_slice(&1u16.to_be_bytes()); // no compression
        r0[4..8].copy_from_slice(&(text.len() as u32).to_be_bytes());
        r0[8..10].copy_from_slice(&1u16.to_be_bytes()); // one text record
        r0[10..12].copy_from_slice(&4096u16.to_be_bytes());
        r0[16..20].copy_from_slice(b"MOBI");
        r0[20..24].copy_from_slice(&mobi_len.to_be_bytes());
        r0[24..28].copy_from_slice(&2u32.to_be_bytes());
        r0[28..32].copy_from_slice(&65_001u32.to_be_bytes());
        r0[36..40].copy_from_slice(&6u32.to_be_bytes());
        r0[92..96].copy_from_slice(&9u32.to_be_bytes());
        r0[128..132].copy_from_slice(&0x40u32.to_be_bytes());
        r0[168..172].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        r0.extend_from_slice(&exth);
        let title_off = r0.len() as u32;
        r0.extend_from_slice(title);
        r0[84..88].copy_from_slice(&title_off.to_be_bytes());
        r0[88..92].copy_from_slice(&(title.len() as u32).to_be_bytes());
        let mut pdb = vec![0u8; 78];
        pdb[..14].copy_from_slice(b"Saltmere_Tides");
        pdb[60..68].copy_from_slice(b"BOOKMOBI");
        pdb[76..78].copy_from_slice(&2u16.to_be_bytes());
        let start = 78 + 16;
        let r1 = start + r0.len();
        for off in [start, r1] {
            pdb.extend_from_slice(&(off as u32).to_be_bytes());
            pdb.extend_from_slice(&[0; 4]);
        }
        pdb.extend_from_slice(&r0);
        pdb.extend_from_slice(text);
        let r = crate::plugin::testing::report_for("tides.mobi", &pdb);
        assert_eq!(r.identification.format, "mobi");
        assert_eq!(r.content.title.as_deref(), Some("Saltmere Tides"));
        assert_eq!(r.content.authors, ["Ana Lighthouse"]);
        assert_eq!(r.format["mobi"]["identifiers"][0]["value"], "9780306406157");
        assert!(r.content.excerpt.as_deref().unwrap_or_default().contains("High water at noon."));
    }
}
