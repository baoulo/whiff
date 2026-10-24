//! RAR archives, versions 1.5–4 and 5: the archive flags (volume, solid,
//! recovery record, locked, encrypted headers, comment) and the file list
//! (names, sizes, times, host system, method, attributes, encryption,
//! links in RAR 5). RAR's compression is not decoded: entries stored
//! without compression are handed on (within the limits), the others are
//! listed. Encrypted headers hide the names.
//!
//! Specifications: RARLAB "RAR 5.0 archive format"; the RAR 4 `technote.txt`
//! of RAR 3.x–4.x.

use super::{Entry, Inventory, Kind, Stored, dos_stamp, filetime, stored_children, unix_time, wanted};
use crate::plugin::{ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for RAR archives.
pub struct Rar;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.rar",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "rar",
        name: "RAR archive",
        family: "archive",
        mimes: &["application/vnd.rar", "application/x-rar-compressed"],
        extensions: &["rar"],
        magic: &[Magic::prefix(b"Rar!\x1a\x07\x00"), Magic::prefix(b"Rar!\x1a\x07\x01\x00")],
        parent: None,
    }],
};

const MAX_HEADERS: u64 = 1 << 20;

fn host_name(rar5: bool, os: u64) -> &'static str {
    match (rar5, os) {
        (true, 0) | (false, 2) => "Windows",
        (true, 1) | (false, 3) => "Unix",
        (false, 0) => "MS-DOS",
        (false, 1) => "OS/2",
        (false, 4) => "Mac OS",
        (false, 5) => "BeOS",
        _ => "other",
    }
}

fn method4(m: u8) -> &'static str {
    match m {
        0x30 => "store",
        0x31 => "fastest",
        0x32 => "fast",
        0x33 => "normal",
        0x34 => "good",
        0x35 => "best",
        _ => "unknown",
    }
}

/// Archive-wide flags, reported once.
#[derive(Default)]
#[allow(clippy::struct_excessive_bools)] // the flags as the format states them
struct Flags {
    volume: bool,
    solid: bool,
    recovery: bool,
    locked: bool,
    comment: bool,
    first_volume: Option<bool>,
    headers_encrypted: bool,
    hosts: Vec<&'static str>,
}

impl Extractor for Rar {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let rar5 = src.head().starts_with(b"Rar!\x1a\x07\x01\x00");
        cx.format_set("version", if rar5 { 5 } else { 4 });
        let mut flags = Flags::default();
        let mut inv = Inventory::new();
        let mut stored = Vec::new();
        let ended = if rar5 {
            rar5_blocks(src, cx, &mut flags, &mut inv, &mut stored)?
        } else {
            rar4_blocks(src, cx, &mut flags, &mut inv, &mut stored)?
        };
        for (key, on) in [
            ("volume", flags.volume),
            ("solid", flags.solid),
            ("recovery_record", flags.recovery),
            ("locked", flags.locked),
            ("has_comment", flags.comment),
        ] {
            if on {
                cx.format_set(key, true);
            }
        }
        if let Some(first) = flags.first_volume.filter(|_| flags.volume) {
            cx.format_set("first_volume", first);
        }
        if let Some(h) = flags.hosts.first() {
            cx.format_set("created_on", *h);
        }
        if flags.headers_encrypted {
            cx.format_set("headers_encrypted", true);
            cx.security().encrypted(true);
        }
        if !ended && !flags.headers_encrypted && !flags.volume {
            inv.truncated = true;
        }
        inv.report(cx, src.len());
        // A solid archive's entries depend on each other: none is stored alone.
        if !flags.solid {
            stored_children(src, cx, stored)?;
        }
        Ok(())
    }
}

crate::register_extractor!(Rar);

/// RAR 1.5–4 blocks; returns whether the end block was reached.
#[allow(clippy::too_many_lines)] // one pass over the block kinds
fn rar4_blocks(
    src: &mut dyn Source,
    cx: &mut Context<'_>,
    flags: &mut Flags,
    inv: &mut Inventory,
    stored: &mut Vec<Stored>,
) -> Result<bool, ExtractError> {
    let len = src.len();
    let mut at = 7u64;
    for i in 0..MAX_HEADERS {
        if i % 1024 == 1023 {
            cx.checkpoint()?;
        }
        if at + 7 > len {
            return Ok(false);
        }
        let h = src.read_vec(at, 7)?;
        let kind = h[2];
        let bflags = u16::from_le_bytes([h[3], h[4]]);
        let size = u64::from(u16::from_le_bytes([h[5], h[6]]));
        if size < 7 {
            return Err(ExtractError::malformed("RAR block size"));
        }
        let body = src.read_vec(at, usize::try_from(size.min(len - at)).unwrap_or(0))?;
        let mut add = 0u64;
        if bflags & 0x8000 != 0 && body.len() >= 11 {
            add = u64::from(u32::from_le_bytes([body[7], body[8], body[9], body[10]]));
        }
        match kind {
            0x73 => {
                flags.volume |= bflags & 0x01 != 0;
                flags.comment |= bflags & 0x02 != 0;
                flags.locked |= bflags & 0x04 != 0;
                flags.solid |= bflags & 0x08 != 0;
                flags.recovery |= bflags & 0x40 != 0;
                flags.first_volume = Some(bflags & 0x100 != 0);
                if bflags & 0x80 != 0 {
                    // Everything after the main header is encrypted.
                    flags.headers_encrypted = true;
                    return Ok(false);
                }
            }
            0x74 => {
                let mut r = ByteReader::new(&body).skip(7)?;
                let mut packed = u64::from(r.le_u32()?);
                let mut unpacked = u64::from(r.le_u32()?);
                let os = r.u8()?;
                r.le_u32()?; // CRC
                let ftime = r.le_u32()?;
                r.u8()?; // version needed
                let method = r.u8()?;
                let name_len = usize::from(r.le_u16()?);
                let attributes = r.le_u32()?;
                if bflags & 0x100 != 0 {
                    packed |= u64::from(r.le_u32()?) << 32;
                    unpacked |= u64::from(r.le_u32()?) << 32;
                }
                let raw = r.bytes(name_len)?;
                let name =
                    if bflags & 0x200 != 0 { rar4_unicode_name(raw) } else { crate::plugin::latin1_or_utf8(raw) };
                let host = host_name(false, u64::from(os));
                if !flags.hosts.contains(&host) {
                    flags.hosts.push(host);
                }
                let dir = bflags & 0xe0 == 0xe0;
                let unix = (os == 3).then_some(attributes);
                let kind = if dir { Kind::Dir } else { unix.map_or(Kind::File, Kind::from_mode) };
                // A file split across volumes continues here: count it once.
                if bflags & 0x01 == 0 {
                    let e = Entry {
                        path: name,
                        kind,
                        size: Some(if dir { 0 } else { unpacked }),
                        compressed: Some(if dir { 0 } else { packed }),
                        modified: dos_stamp(ftime),
                        mode: unix.map(|m| m & 0o7777),
                        link: None,
                        encrypted: bflags & 0x04 != 0,
                        method: (!dir).then(|| method4(method).to_string()),
                    };
                    if method == 0x30 && bflags & 0x02 == 0 && wanted(&e) && packed == unpacked {
                        stored.push((e.path.clone(), at + size, packed));
                    }
                    inv.push(e);
                }
                add = packed;
            }
            0x7b => return Ok(true),
            _ => {}
        }
        at = at.saturating_add(size).saturating_add(add);
    }
    Ok(false)
}

/// A RAR 4 Unicode name: the ASCII name, a NUL, then the Unicode name
/// encoded against it.
fn rar4_unicode_name(raw: &[u8]) -> String {
    let Some(zero) = raw.iter().position(|&b| b == 0) else { return String::from_utf8_lossy(raw).into_owned() };
    let (ascii, enc) = (&raw[..zero], &raw[zero + 1..]);
    let Some((&high, mut enc)) = enc.split_first() else { return crate::plugin::latin1_or_utf8(ascii) };
    let mut out: Vec<u16> = Vec::new();
    let (mut flags, mut flag_bits) = (0u8, 0);
    let next = |enc: &mut &[u8]| -> Option<u8> {
        let (&b, rest) = enc.split_first()?;
        *enc = rest;
        Some(b)
    };
    while !enc.is_empty() {
        if flag_bits == 0 {
            let Some(f) = next(&mut enc) else { break };
            flags = f;
            flag_bits = 8;
        }
        flag_bits -= 2;
        match (flags >> flag_bits) & 3 {
            0 => {
                let Some(b) = next(&mut enc) else { break };
                out.push(u16::from(b));
            }
            1 => {
                let Some(b) = next(&mut enc) else { break };
                out.push(u16::from(b) | u16::from(high) << 8);
            }
            2 => {
                let (Some(lo), Some(hi)) = (next(&mut enc), next(&mut enc)) else { break };
                out.push(u16::from_le_bytes([lo, hi]));
            }
            _ => {
                let Some(l) = next(&mut enc) else { break };
                if l & 0x80 != 0 {
                    let Some(correction) = next(&mut enc) else { break };
                    for _ in 0..(l & 0x7f) + 2 {
                        let b = ascii.get(out.len()).copied().unwrap_or(0);
                        out.push(u16::from(b.wrapping_add(correction)) | u16::from(high) << 8);
                    }
                } else {
                    for _ in 0..l + 2 {
                        out.push(u16::from(ascii.get(out.len()).copied().unwrap_or(0)));
                    }
                }
            }
        }
    }
    String::from_utf16_lossy(&out)
}

/// A RAR 5 variable-length integer.
fn vint(r: &mut ByteReader<'_>) -> Result<u64, ExtractError> {
    let mut v = 0u64;
    for i in 0..10 {
        let b = r.u8()?;
        v |= u64::from(b & 0x7f).checked_shl(7 * i).unwrap_or(0);
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(ExtractError::malformed("RAR 5 integer"))
}

/// RAR 5 headers; returns whether the end header was reached.
#[allow(clippy::too_many_lines)] // one pass over the header kinds
fn rar5_blocks(
    src: &mut dyn Source,
    cx: &mut Context<'_>,
    flags: &mut Flags,
    inv: &mut Inventory,
    stored: &mut Vec<Stored>,
) -> Result<bool, ExtractError> {
    let len = src.len();
    let mut at = 8u64;
    for i in 0..MAX_HEADERS {
        if i % 1024 == 1023 {
            cx.checkpoint()?;
        }
        if at + 7 > len {
            return Ok(false);
        }
        // CRC32, then the header size as a vint (at most 3 bytes).
        let pre = src.read_vec(at, usize::try_from(7.min(len - at)).unwrap_or(0))?;
        let mut p = ByteReader::new(&pre).skip(4)?;
        let size = vint(&mut p)?;
        let start = at + 4 + p.position() as u64 - 4;
        if size > 2 << 20 || start + size > len {
            return Err(ExtractError::malformed("RAR 5 header size"));
        }
        let body = src.read_vec(start, usize::try_from(size).unwrap_or(0))?;
        let mut r = ByteReader::new(&body);
        let kind = vint(&mut r)?;
        let hflags = vint(&mut r)?;
        let extra_size = if hflags & 1 != 0 { vint(&mut r)? } else { 0 };
        let data_size = if hflags & 2 != 0 { vint(&mut r)? } else { 0 };
        let extra_at = body.len().saturating_sub(usize::try_from(extra_size).unwrap_or(0));
        let extra = &body[extra_at..];
        match kind {
            1 => {
                let aflags = vint(&mut r)?;
                flags.volume |= aflags & 1 != 0;
                flags.solid |= aflags & 4 != 0;
                flags.recovery |= aflags & 8 != 0;
                flags.locked |= aflags & 16 != 0;
                if aflags & 2 != 0 {
                    flags.first_volume = Some(vint(&mut r)? == 0);
                } else if flags.volume {
                    flags.first_volume = Some(true);
                }
            }
            2 | 3 => {
                let file_flags = vint(&mut r)?;
                let unpacked = vint(&mut r)?;
                let attributes = vint(&mut r)?;
                let mtime = if file_flags & 2 != 0 { Some(r.le_u32()?) } else { None };
                if file_flags & 4 != 0 {
                    r.le_u32()?;
                }
                let comp = vint(&mut r)?;
                let os = vint(&mut r)?;
                let name_len = usize::try_from(vint(&mut r)?).unwrap_or(usize::MAX);
                let name = String::from_utf8_lossy(r.bytes(name_len)?).into_owned();
                if kind == 3 {
                    // Service headers: CMT is the archive comment.
                    if name == "CMT" {
                        flags.comment = true;
                    }
                } else {
                    let host = host_name(true, os);
                    if !flags.hosts.contains(&host) {
                        flags.hosts.push(host);
                    }
                    let (encrypted, link, modified) = rar5_extra(extra);
                    let dir = file_flags & 1 != 0;
                    let unix = if os == 1 { u32::try_from(attributes).ok() } else { None };
                    let mut kind = if dir { Kind::Dir } else { unix.map_or(Kind::File, Kind::from_mode) };
                    if let Some((link_kind, _)) = &link {
                        kind = *link_kind;
                    }
                    let method = (comp >> 7) & 7;
                    // A file continued from the previous volume is counted there.
                    if hflags & 8 == 0 {
                        let split = hflags & 0x10 != 0;
                        if method == 0
                            && !encrypted
                            && !split
                            && kind == Kind::File
                            && unpacked == data_size
                            && unpacked > 0
                        {
                            stored.push((name.clone(), start + size, data_size));
                        }
                        inv.push(Entry {
                            path: name,
                            kind,
                            size: Some(if kind == Kind::File && file_flags & 8 == 0 { unpacked } else { 0 }),
                            compressed: Some(if kind == Kind::File { data_size } else { 0 }),
                            modified: modified.or_else(|| mtime.and_then(|t| unix_time(i64::from(t)))),
                            mode: unix.map(|m| m & 0o7777),
                            link: link.map(|(_, target)| target),
                            encrypted,
                            method: (kind == Kind::File)
                                .then(|| if method == 0 { "store".to_string() } else { format!("level {method}") }),
                        });
                    }
                }
            }
            4 => {
                flags.headers_encrypted = true;
                return Ok(false);
            }
            5 => return Ok(true),
            _ => {}
        }
        at = start.saturating_add(size).saturating_add(data_size);
    }
    Ok(false)
}

/// RAR 5 file extra records: (encrypted, link, high-precision mtime).
fn rar5_extra(extra: &[u8]) -> (bool, Option<(Kind, String)>, Option<String>) {
    let mut r = ByteReader::new(extra);
    let (mut encrypted, mut link, mut mtime) = (false, None, None);
    while let Ok(size) = vint(&mut r) {
        let Ok(record) = r.bytes(usize::try_from(size).unwrap_or(usize::MAX)) else { break };
        let mut x = ByteReader::new(record);
        match vint(&mut x) {
            Ok(1) => encrypted = true,
            Ok(3) => {
                // Time record: flags (1 Unix time, 2 mtime, …).
                if let Ok(tflags) = vint(&mut x)
                    && tflags & 2 != 0
                {
                    mtime = if tflags & 1 != 0 {
                        x.le_u32().ok().and_then(|t| unix_time(i64::from(t)))
                    } else {
                        x.le_u64().ok().and_then(filetime)
                    };
                }
            }
            Ok(5) => {
                if let (Ok(kind), Ok(_), Ok(n)) = (vint(&mut x), vint(&mut x), vint(&mut x))
                    && let Ok(target) = x.bytes(usize::try_from(n).unwrap_or(usize::MAX))
                {
                    let kind = if kind == 4 { Kind::Hardlink } else { Kind::Symlink };
                    link = Some((kind, String::from_utf8_lossy(target).into_owned()));
                }
            }
            _ => {}
        }
    }
    (encrypted, link, mtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vints_and_names() {
        let mut r = ByteReader::new(&[0x05, 0x81, 0x01, 0xff, 0x7f]);
        assert_eq!(vint(&mut r).unwrap(), 5);
        assert_eq!(vint(&mut r).unwrap(), 129);
        assert_eq!(vint(&mut r).unwrap(), 0x3fff);
        assert_eq!(rar4_unicode_name(b"plain"), "plain");
        // ASCII "ab", then: high byte 0x04, flags 0b01_00_0000 → one char
        // with the high byte (0x0430 'а'), one plain byte 'b'.
        assert_eq!(rar4_unicode_name(b"ab\0\x04\x40\x30b"), "аb");
    }

    crate::fixture_tests!("rar");
}
