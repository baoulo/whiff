//! gzip (header: original name, modification time, comment, operating
//! system, compression level, extra subfields such as BGZF and dictzip;
//! the trailer's size) and raw zlib streams (window size, level, preset
//! dictionary). The stream is decompressed and analysed as the inner file.
//!
//! Specifications: RFC 1952 (gzip), RFC 1950 (zlib), SAMv1 §4.1 (BGZF).

use super::{Stated, unix_time, unpack};
use crate::plugin::{
    ByteReader, Codec, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe,
    Sniff, Source, latin1_or_utf8,
};

/// Extractor for gzip and zlib streams.
pub struct Gzip;

static META: ExtractorMeta = ExtractorMeta {
    id: "compress.gzip",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "gzip",
            name: "gzip",
            family: "compress",
            mimes: &["application/gzip", "application/x-gzip"],
            extensions: &["gz", "gzip", "tgz"],
            magic: &[Magic::prefix(b"\x1f\x8b\x08")],
            parent: None,
        },
        FormatSpec {
            id: "zlib",
            name: "zlib stream",
            family: "compress",
            mimes: &["application/zlib"],
            extensions: &["zz", "zlib"],
            magic: &[],
            parent: None,
        },
    ],
};

/// Whether `head` starts with a valid zlib header (deflate, window ≤ 32 KiB).
fn zlib_header(head: &[u8]) -> bool {
    matches!(head, [cmf, flg, ..] if cmf & 0x0f == 8 && cmf >> 4 <= 7 && (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0)
}

fn os_name(os: u8) -> Option<&'static str> {
    Some(match os {
        0 => "FAT",
        1 => "Amiga",
        2 => "VMS",
        3 => "Unix",
        4 => "VM/CMS",
        5 => "Atari TOS",
        6 => "HPFS",
        7 => "Macintosh",
        8 => "Z-System",
        9 => "CP/M",
        10 => "TOPS-20",
        11 => "NTFS",
        12 => "QDOS",
        13 => "Acorn RISCOS",
        _ => return None,
    })
}

impl Extractor for Gzip {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // zlib has no magic of its own: only with its extension.
        (matches!(probe.extension, Some("zz" | "zlib")) && zlib_header(probe.head))
            .then_some(Sniff { format: "zlib", confidence: 0.8 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "zlib" {
            let head = src.head();
            if !zlib_header(head) {
                return Err(ExtractError::Unsupported("zlib".into()));
            }
            cx.format_set("method", "deflate");
            cx.format_set("window_bytes", 1u64 << ((head[0] >> 4) + 8));
            cx.format_set("level", ["fastest", "fast", "default", "maximum"][usize::from(head[1] >> 6)]);
            if head[1] & 0x20 != 0 {
                // The preset dictionary is not in the file: nothing to decode.
                cx.format_set(
                    "preset_dictionary",
                    format!("{:08x}", u32::from_be_bytes(*head[2..].first_chunk().unwrap_or(&[0; 4]))),
                );
                return Ok(());
            }
            return unpack(src, cx, Codec::Zlib, &Stated::default());
        }
        let stated = header(src.head(), src.tail(), cx)?;
        unpack(src, cx, Codec::Gzip, &stated)
    }
}

crate::register_extractor!(Gzip);

/// Report the first member's header; return what it states.
fn header(head: &[u8], tail: &[u8], cx: &mut Context<'_>) -> Result<Stated, ExtractError> {
    let mut r = ByteReader::new(head).skip(3)?;
    let flags = r.u8()?;
    let mtime = r.le_u32()?;
    let xfl = r.u8()?;
    let os = r.u8()?;
    let mut stated = Stated::default();
    cx.format_set("method", "deflate");
    if flags & 1 != 0 {
        cx.format_set("text", true);
    }
    if let Some(t) = unix_time(i64::from(mtime)) {
        cx.format_set("modified", t.clone());
        cx.temporal().content_date(DateField::Modified, t, true);
    }
    match xfl {
        2 => cx.format_set("level", "maximum"),
        4 => cx.format_set("level", "fastest"),
        _ => {}
    }
    if let Some(name) = os_name(os) {
        cx.format_set("os", name);
    }
    let mut bgzf = false;
    if flags & 4 != 0 {
        let n = usize::from(r.le_u16()?);
        let mut extra = ByteReader::new(r.bytes(n)?);
        let mut ids = Vec::new();
        while extra.remaining() >= 4 {
            let id = extra.array::<2>()?;
            let len = usize::from(extra.le_u16()?);
            let Ok(data) = extra.bytes(len) else { break };
            let id = String::from_utf8_lossy(&id).into_owned();
            match id.as_str() {
                "BC" if len == 2 => {
                    bgzf = true;
                    cx.format_set("variant", "BGZF");
                    cx.format_set("block_size_bytes", u64::from(u16::from_le_bytes([data[0], data[1]])) + 1);
                }
                "RA" => cx.format_set("variant", "dictzip"),
                _ => {}
            }
            ids.push(id);
        }
        cx.format_set("extra_fields", ids);
    }
    if flags & 8 != 0 {
        let name = latin1_or_utf8(r.cstr()?);
        cx.format_set("original_name", name.clone());
        stated.name = Some(name);
    }
    if flags & 16 != 0 {
        let comment = latin1_or_utf8(r.cstr()?);
        cx.format_set("comment", comment.clone());
        cx.content().description(comment);
    }
    if flags & 2 != 0 {
        cx.format_set("header_crc", true);
    }
    // The last member's size (modulo 4 GiB). A BGZF file ends with an empty
    // block, so its trailer says nothing about the whole.
    if !bgzf && let Some(isize) = tail.last_chunk::<4>().map(|b| u32::from_le_bytes(*b)) {
        stated.size = Some(u64::from(isize)).filter(|&n| n > 0);
    }
    Ok(stated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zlib_headers() {
        assert!(zlib_header(&[0x78, 0x9c]));
        assert!(zlib_header(&[0x78, 0xda]));
        assert!(zlib_header(&[0x58, 0x85]));
        assert!(!zlib_header(&[0x78, 0x9d]));
        assert!(!zlib_header(&[0x79, 0x9c]));
        assert!(!zlib_header(b"x"));
    }

    crate::fixture_tests!("gzip", "zlib");
}
