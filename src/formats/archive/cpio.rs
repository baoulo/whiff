//! cpio archives in the new ASCII (`newc`, and `crc` with checksums),
//! old portable ASCII (`odc`) and old binary formats (either byte order).
//! Entries are stored as they are, so every file is handed on (within the
//! limits).
//!
//! Specification: the `cpio(5)` manual page of libarchive (formats as
//! GNU cpio and bsdcpio write them).

use super::{Entry, Inventory, Kind, Stored, stored_children, unix_time, wanted};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, latin1_or_utf8};

/// Extractor for cpio archives.
pub struct Cpio;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.cpio",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "cpio",
        name: "cpio archive",
        family: "archive",
        mimes: &["application/x-cpio"],
        extensions: &["cpio"],
        magic: &[
            Magic::prefix(b"070701"),
            Magic::prefix(b"070702"),
            Magic::prefix(b"070707"),
            Magic::prefix(b"\xc7\x71"),
            Magic::prefix(b"\x71\xc7"),
        ],
        parent: None,
    }],
};

const MAX_HEADERS: u64 = 1 << 20;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    Newc,
    Crc,
    Odc,
    BinLe,
    BinBe,
}

impl Variant {
    fn of(head: &[u8]) -> Option<Self> {
        Some(match head.get(..6)? {
            b"070701" => Self::Newc,
            b"070702" => Self::Crc,
            b"070707" => Self::Odc,
            [0xc7, 0x71, ..] => Self::BinLe,
            [0x71, 0xc7, ..] => Self::BinBe,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Newc => "newc",
            Self::Crc => "crc",
            Self::Odc => "odc",
            Self::BinLe | Self::BinBe => "binary",
        }
    }
}

/// One header: (mode, mtime, name size, file size, header length, links).
#[allow(clippy::cast_possible_truncation)] // modes are 16 or 32 bits
fn header(v: Variant, h: &[u8]) -> Option<(u32, u64, u64, u64, u64, u64)> {
    let ascii = |s: &[u8], radix| std::str::from_utf8(s).ok().and_then(|s| u64::from_str_radix(s, radix).ok());
    match v {
        Variant::Newc | Variant::Crc => {
            let f = |i: usize| ascii(h.get(6 + i * 8..14 + i * 8)?, 16);
            Some((f(1)? as u32, f(5)?, f(11)?, f(6)?, 110, f(4)?))
        }
        Variant::Odc => {
            let f = |at: usize, n: usize| ascii(h.get(at..at + n)?, 8);
            Some((f(18, 6)? as u32, f(48, 11)?, f(59, 6)?, f(65, 11)?, 76, f(36, 6)?))
        }
        Variant::BinLe | Variant::BinBe => {
            let w = |i: usize| {
                let b = [*h.get(i * 2)?, *h.get(i * 2 + 1)?];
                Some(u64::from(if v == Variant::BinLe { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) }))
            };
            // Times and sizes are two 16-bit words, most significant first.
            Some((w(3)? as u32, w(8)? << 16 | w(9)?, w(10)?, w(11)? << 16 | w(12)?, 26, w(6)?))
        }
    }
}

impl Extractor for Cpio {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let v = Variant::of(src.head()).ok_or_else(|| ExtractError::Unsupported("cpio".into()))?;
        cx.format_set("variant", v.name());
        let (inv, pending) = list(src, cx)?;
        inv.report(cx, src.len());
        stored_children(src, cx, pending)
    }
}

/// Read every header of the cpio archive in `src` into an inventory; also
/// returns the entries to hand on (within the child limit).
pub(crate) fn list(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(Inventory, Vec<Stored>), ExtractError> {
    let v = Variant::of(src.head()).ok_or_else(|| ExtractError::Unsupported("cpio".into()))?;
    let len = src.len();
    let align = |n: u64| match v {
        Variant::Newc | Variant::Crc => n.div_ceil(4) * 4,
        Variant::BinLe | Variant::BinBe => n.div_ceil(2) * 2,
        Variant::Odc => n,
    };
    let mut inv = Inventory::new();
    let mut pending = Vec::new();
    let mut at = 0u64;
    let mut ended = false;
    for i in 0..MAX_HEADERS {
        if i % 1024 == 1023 {
            cx.checkpoint()?;
        }
        let h = src.read_vec(at, usize::try_from(110.min(len.saturating_sub(at))).unwrap_or(0))?;
        if Variant::of(&h) != Some(v) {
            break;
        }
        let Some((mode, mtime, name_len, size, hlen, links)) = header(v, &h) else { break };
        let name_at = at + hlen;
        let name = src.read_vec(name_at, usize::try_from(name_len.min(4096)).unwrap_or(0))?;
        let name = latin1_or_utf8(name.split(|&b| b == 0).next().unwrap_or(&[]));
        let data_at = align(name_at + name_len);
        if name == "TRAILER!!!" {
            ended = true;
            break;
        }
        // newc keeps a hard-linked file's data with its last link only.
        let mut kind = Kind::from_mode(mode);
        if kind == Kind::File && links > 1 && size == 0 && matches!(v, Variant::Newc | Variant::Crc) {
            kind = Kind::Hardlink;
        }
        let link = if kind == Kind::Symlink && size <= 4096 {
            Some(latin1_or_utf8(&src.read_vec(data_at, usize::try_from(size).unwrap_or(0))?))
        } else {
            None
        };
        let e = Entry {
            path: name.clone(),
            kind,
            size: Some(if kind == Kind::File { size } else { 0 }),
            compressed: Some(if kind == Kind::File { size } else { 0 }),
            modified: i64::try_from(mtime).ok().and_then(unix_time),
            mode: Some(mode & 0o7777),
            link,
            ..Entry::default()
        };
        if wanted(&e) && pending.len() < cx.child_room() {
            pending.push((name, data_at, size));
        }
        inv.push(e);
        at = align(data_at.saturating_add(size));
        if at >= len {
            break;
        }
    }
    if !ended {
        inv.truncated = true;
        cx.warn("no TRAILER!!! entry (the archive may be cut short)");
    }
    Ok((inv, pending))
}

crate::register_extractor!(Cpio);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("cpio");
}
