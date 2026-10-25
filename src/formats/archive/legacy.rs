//! Older archivers, listed from their headers; entries stored without
//! compression are handed on (their compression is not decoded): LHA / LZH (header levels 0–2: names and folders, sizes,
//! methods, times, Unix modes, host system) and ARJ (main header with the
//! archive name, comment and times; file headers with sizes, methods,
//! host system and encryption).
//!
//! Specifications: the LHA header notes of Haruhiko Okumura and the
//! `lhasa` sources; Robert Jung's ARJ `TECHNOTE.TXT`.

use super::{Entry, Inventory, Kind, dos_stamp, stored_children, unix_time, wanted};
use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, latin1_or_utf8,
};

/// Extractor for LHA and ARJ archives.
pub struct Legacy;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.legacy",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "lha",
            name: "LHA / LZH archive",
            family: "archive",
            mimes: &["application/x-lzh-compressed"],
            extensions: &["lzh", "lha"],
            // "-lh5-" and the like at offset 2.
            magic: &[Magic::masked(2, b"-l\0\0-", b"\xff\xff\x00\x00\xff")],
            parent: None,
        },
        FormatSpec {
            id: "arj",
            name: "ARJ archive",
            family: "archive",
            mimes: &["application/x-arj"],
            extensions: &["arj"],
            magic: &[Magic::prefix(b"\x60\xea")],
            parent: None,
        },
    ],
};

const MAX_ENTRIES: u64 = 1 << 20;

impl Extractor for Legacy {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "lha" { lha(src, cx) } else { arj(src, cx) }
    }
}

crate::register_extractor!(Legacy);

fn lha_os(id: u8) -> &'static str {
    match id {
        b'M' => "MS-DOS",
        b'U' => "Unix",
        b'w' | b'W' => "Windows",
        b'm' => "Macintosh",
        b'2' => "OS/2",
        b'J' => "Java",
        b'K' => "OS-9",
        b'A' => "Amiga",
        b'H' => "Human68K",
        0 => "generic",
        _ => "other",
    }
}

/// LHA extension headers: (folder, name, mtime, mode).
fn lha_ext(data: &[u8], mut next: usize) -> (Option<String>, Option<String>, Option<i64>, Option<u32>, usize) {
    let (mut dir, mut name, mut mtime, mut mode) = (None, None, None, None);
    let mut at = 0;
    let mut total = 0;
    while next >= 3 && at + next <= data.len() {
        let h = &data[at..at + next];
        let body = &h[1..next - 2];
        match h[0] {
            0x01 => name = Some(latin1_or_utf8(body)),
            0x02 => {
                let d: Vec<u8> = body.iter().map(|&b| if b == 0xff { b'/' } else { b }).collect();
                dir = Some(latin1_or_utf8(&d));
            }
            0x50 if body.len() >= 2 => mode = Some(u32::from(u16::from_le_bytes([body[0], body[1]]))),
            0x54 if body.len() >= 4 => {
                mtime = Some(i64::from(u32::from_le_bytes([body[0], body[1], body[2], body[3]])));
            }
            _ => {}
        }
        total += next;
        let n = usize::from(u16::from_le_bytes([h[next - 2], h[next - 1]]));
        at += next;
        next = n;
    }
    (dir, name, mtime, mode, total)
}

#[allow(clippy::too_many_lines)] // three header levels in one walk
fn lha(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let mut inv = Inventory::new();
    let mut at = 0u64;
    let mut hosts: Vec<&str> = Vec::new();
    let mut levels: Vec<u8> = Vec::new();
    let mut stored = Vec::new();
    for i in 0..MAX_ENTRIES {
        if i % 1024 == 1023 {
            cx.checkpoint()?;
        }
        let Ok(h) = src.read_vec(at, usize::try_from(len.saturating_sub(at).min(4096)).unwrap_or(0)) else { break };
        if h.first().is_none_or(|&b| b == 0) || h.len() < 22 {
            break;
        }
        let level = h[20];
        if !levels.contains(&level) {
            levels.push(level);
        }
        let method = String::from_utf8_lossy(&h[2..7]).into_owned();
        if !method.starts_with('-') || !method.ends_with('-') {
            cx.warn(format!("bad header at offset {at}"));
            inv.truncated = true;
            break;
        }
        let mut r = ByteReader::new(&h).skip(7)?;
        let mut packed = u64::from(r.le_u32()?);
        let original = u64::from(r.le_u32()?);
        let stamp = r.le_u32()?;
        let (mut path, modified, mut mode, header_len, os) = match level {
            0 | 1 => {
                let size = usize::from(h[0]) + 2;
                let n = usize::from(h[21]);
                let name = latin1_or_utf8(h.get(22..22 + n).unwrap_or(&[]));
                let modified = dos_stamp(stamp);
                if level == 0 {
                    (
                        name,
                        modified,
                        None,
                        size as u64,
                        h.get(24 + n).copied().filter(|_| size > 24 + n).unwrap_or(b'M'),
                    )
                } else {
                    let os = h.get(24 + n).copied().unwrap_or(0);
                    let next = h.get(25 + n..27 + n).map_or(0, |b| usize::from(u16::from_le_bytes([b[0], b[1]])));
                    let (dir, long, mtime, mode, ext_len) = lha_ext(&h[size.min(h.len())..], next);
                    // Level 1: the packed size includes the extension headers.
                    packed = packed.saturating_sub(ext_len as u64);
                    let name = long.unwrap_or(name);
                    let path = dir.map_or(name.clone(), |d| format!("{}/{name}", d.trim_end_matches('/')));
                    let modified = mtime.and_then(unix_time).or(modified);
                    (path, modified, mode, (size + ext_len) as u64, os)
                }
            }
            2 => {
                let size = u64::from(u16::from_le_bytes([h[0], h[1]]));
                let os = h[23];
                let next = usize::from(u16::from_le_bytes([h[24], h[25]]));
                let (dir, name, _, mode, _) = lha_ext(&h[26..], next);
                let name = name.unwrap_or_default();
                let path = dir.map_or(name.clone(), |d| format!("{}/{name}", d.trim_end_matches('/')));
                (path, unix_time(i64::from(stamp)), mode, size, os)
            }
            _ => {
                cx.warn(format!("LHA header level {level} is not read"));
                inv.truncated = true;
                break;
            }
        };
        if path.is_empty() {
            path = "(unnamed)".into();
        }
        let host = lha_os(os);
        if !hosts.contains(&host) {
            hosts.push(host);
        }
        let dir = method == "-lhd-";
        let kind = if dir { Kind::Dir } else { mode.map_or(Kind::File, Kind::from_mode) };
        if kind == Kind::Symlink {
            mode = None;
        }
        // Unix symlinks keep their target after a `|` in the name.
        let (path, link) = match path.split_once('|') {
            Some((p, l)) => (p.to_string(), Some(l.to_string())),
            None => (path, None),
        };
        let e = Entry {
            path,
            kind: if link.is_some() { Kind::Symlink } else { kind },
            size: Some(if dir { 0 } else { original }),
            compressed: Some(if dir { 0 } else { packed }),
            modified,
            mode: mode.map(|m| m & 0o7777),
            link,
            encrypted: false,
            method: (!dir).then(|| method.trim_matches('-').to_string()),
        };
        if matches!(method.as_str(), "-lh0-" | "-lz4-" | "-pm0-") && packed == original && wanted(&e) {
            stored.push((e.path.clone(), at + header_len, packed));
        }
        inv.push(e);
        at = at.saturating_add(header_len).saturating_add(packed);
        if at >= len {
            break;
        }
    }
    cx.format_set("header_levels", levels);
    if let Some(h) = hosts.first() {
        cx.format_set("created_on", *h);
    }
    inv.report(cx, len);
    stored_children(src, cx, stored)
}

fn arj_os(os: u8) -> &'static str {
    match os {
        0 => "MS-DOS",
        1 => "PRIMOS",
        2 => "Unix",
        3 => "Amiga",
        4 => "Mac OS",
        5 => "OS/2",
        6 => "Apple GS",
        7 => "Atari ST",
        8 => "NeXT",
        9 => "VAX VMS",
        10 => "Windows 95",
        11 => "Windows NT",
        _ => "other",
    }
}

/// One ARJ header at `at`: the basic header and the offset after its
/// extended headers.
fn arj_header(src: &mut dyn Source, at: u64) -> Result<Option<(Vec<u8>, u64)>, ExtractError> {
    let h = src.read_vec(at, 4)?;
    if h[..2] != [0x60, 0xea] {
        return Err(ExtractError::malformed("ARJ header id"));
    }
    let size = u64::from(u16::from_le_bytes([h[2], h[3]]));
    if size == 0 {
        return Ok(None);
    }
    if size > 2600 {
        return Err(ExtractError::malformed("ARJ header size"));
    }
    let basic = src.read_vec(at + 4, usize::try_from(size).unwrap_or(0))?;
    let mut next = at + 4 + size + 4;
    // Extended headers: size, data, CRC, until a zero size.
    loop {
        let e = src.read_vec(next, 2)?;
        let n = u64::from(u16::from_le_bytes([e[0], e[1]]));
        next += 2;
        if n == 0 {
            break;
        }
        next += n + 4;
    }
    Ok(Some((basic, next)))
}

fn arj(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let Some((main, mut at)) = arj_header(src, 0)? else { return Err(ExtractError::Unsupported("arj".into())) };
    let mut r = ByteReader::new(&main);
    let first = usize::from(r.u8()?);
    cx.format_set("archiver_version", r.u8()?);
    r.u8()?;
    cx.format_set("created_on", arj_os(r.u8()?));
    let flags = r.u8()?;
    if flags & 0x04 != 0 {
        cx.format_set("volume", true);
    }
    if flags & 0x01 != 0 {
        cx.security().encrypted(true);
    }
    let mut d = ByteReader::new(&main).skip(8)?;
    if let Some(t) = dos_stamp(d.le_u32()?) {
        cx.format_set("created", t);
    }
    let mut names = ByteReader::new(main.get(first..).unwrap_or(&[]));
    let archive_name = latin1_or_utf8(names.cstr().unwrap_or(&[]));
    let comment = latin1_or_utf8(names.cstr().unwrap_or(&[]));
    if !archive_name.is_empty() {
        cx.format_set("archive_name", archive_name);
    }
    if !comment.trim().is_empty() {
        cx.format_set("comment", comment.trim());
        cx.content().description(comment.trim());
    }
    let mut inv = Inventory::new();
    let mut stored = Vec::new();
    for i in 0..MAX_ENTRIES {
        if i % 1024 == 1023 {
            cx.checkpoint()?;
        }
        if at + 4 > len {
            inv.truncated = true;
            break;
        }
        let Some((h, next)) = arj_header(src, at)? else { break };
        let mut r = ByteReader::new(&h);
        let first = usize::from(r.u8()?);
        r.advance(3)?;
        let flags = r.u8()?;
        let method = r.u8()?;
        let file_type = r.u8()?;
        r.u8()?;
        let stamp = r.le_u32()?;
        let packed = u64::from(r.le_u32()?);
        let original = u64::from(r.le_u32()?);
        r.le_u32()?;
        r.le_u16()?;
        let mode = r.le_u16()?;
        let mut names = ByteReader::new(h.get(first..).unwrap_or(&[]));
        let path = latin1_or_utf8(names.cstr().unwrap_or(&[]));
        let dir = file_type == 3;
        let e = Entry {
            path,
            kind: if dir { Kind::Dir } else { Kind::File },
            size: Some(if dir { 0 } else { original }),
            compressed: Some(if dir { 0 } else { packed }),
            modified: dos_stamp(stamp),
            mode: (h.get(3) == Some(&2)).then_some(u32::from(mode) & 0o7777),
            link: None,
            encrypted: flags & 0x01 != 0,
            method: (!dir).then(|| if method == 0 { "stored".to_string() } else { format!("method {method}") }),
        };
        // Stored, and not continued from or into another volume.
        if method == 0 && packed == original && flags & 0x04 == 0 && wanted(&e) {
            stored.push((e.path.clone(), next, packed));
        }
        inv.push(e);
        at = next + packed;
    }
    inv.report(cx, len);
    stored_children(src, cx, stored)
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("lha", "arj");
}
