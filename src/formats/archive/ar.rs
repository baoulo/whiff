//! Unix `ar` archives (static libraries and the like): GNU / System V long
//! names (`//` table) and BSD long names (`#1/<len>`), the symbol table,
//! member times, owners' ids and modes. Members are stored as they are, so
//! every one is handed on (within the limits).
//!
//! Specification: the `ar(5)` manual pages of FreeBSD and GNU binutils.

use super::{Entry, Inventory, Kind, child, unix_time, wanted};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, latin1_or_utf8};

/// Extractor for `ar` archives.
pub struct Ar;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.ar",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "ar",
        name: "Unix ar archive",
        family: "archive",
        mimes: &["application/x-archive"],
        extensions: &["a", "ar", "lib"],
        magic: &[Magic::prefix(b"!<arch>\n")],
        parent: None,
    }],
};

const MAX_MEMBERS: u64 = 1 << 20;

fn field(h: &[u8], at: usize, n: usize) -> &str {
    std::str::from_utf8(&h[at..at + n]).unwrap_or("").trim_end()
}

impl Extractor for Ar {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let mut inv = Inventory::new();
        let mut pending = Vec::new();
        let mut long_names: Vec<u8> = Vec::new();
        let (mut gnu, mut bsd, mut symbols) = (false, false, false);
        let mut at = 8u64;
        for i in 0..MAX_MEMBERS {
            if i % 1024 == 1023 {
                cx.checkpoint()?;
            }
            if at + 60 > len {
                break;
            }
            let h = src.read_vec(at, 60)?;
            if &h[58..60] != b"`\n" {
                cx.warn(format!("bad member header at offset {at}"));
                inv.truncated = true;
                break;
            }
            let raw = field(&h, 0, 16).to_string();
            let size: u64 = field(&h, 48, 10).parse().map_err(|_| ExtractError::malformed("ar member size"))?;
            let mut data_at = at + 60;
            let mut data_size = size;
            let next = (at + 60).saturating_add(size).saturating_add(size % 2);
            let name = if raw == "/" || raw == "/SYM64/" || raw == "__.SYMDEF" || raw == "__.SYMDEF SORTED" {
                symbols = true;
                at = next;
                continue;
            } else if raw == "//" {
                gnu = true;
                long_names = src.read_vec(data_at, usize::try_from(size.min(1 << 20)).unwrap_or(0))?;
                at = next;
                continue;
            } else if let Some(n) = raw.strip_prefix("#1/").and_then(|n| n.parse::<u64>().ok()) {
                // BSD: the name is the first `n` bytes of the data.
                bsd = true;
                let name = src.read_vec(data_at, usize::try_from(n.min(4096).min(size)).unwrap_or(0))?;
                data_at += n;
                data_size = size.saturating_sub(n);
                let name = latin1_or_utf8(name.split(|&b| b == 0).next().unwrap_or(&[]));
                if name.starts_with("__.SYMDEF") {
                    symbols = true;
                    at = next;
                    continue;
                }
                name
            } else if let Some(off) = raw.strip_prefix('/').and_then(|n| n.parse::<usize>().ok()) {
                gnu = true;
                let rest = long_names.get(off..).unwrap_or(&[]);
                let end = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
                latin1_or_utf8(&rest[..end]).trim_end_matches('/').to_string()
            } else {
                raw.trim_end_matches('/').to_string()
            };
            let mode = u32::from_str_radix(field(&h, 40, 8), 8).ok();
            let e = Entry {
                path: name.clone(),
                kind: mode.map_or(Kind::File, Kind::from_mode),
                size: Some(data_size),
                compressed: Some(data_size),
                modified: field(&h, 16, 12).parse::<i64>().ok().and_then(unix_time),
                mode: mode.map(|m| m & 0o7777),
                ..Entry::default()
            };
            if wanted(&e) && pending.len() < cx.child_room() {
                pending.push((name, data_at, data_size));
            }
            inv.push(e);
            at = next;
        }
        cx.format_set(
            "variant",
            if gnu {
                "gnu"
            } else if bsd {
                "bsd"
            } else {
                "common"
            },
        );
        if symbols {
            cx.format_set("symbol_table", true);
        }
        inv.report(cx, len);
        let limit = cx.parse_limit() as u64;
        for (name, offset, size) in pending {
            let n = size.min(limit).min(len.saturating_sub(offset));
            let data = src.read_vec(offset, usize::try_from(n).unwrap_or(0))?;
            if !child(cx, &name, data, n == size)? {
                break;
            }
        }
        Ok(())
    }
}

crate::register_extractor!(Ar);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("ar");
}
