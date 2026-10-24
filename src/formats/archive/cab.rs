//! Microsoft Cabinet files: the header (version, set id and position in a
//! multi-cabinet set with the neighbouring cabinets' names, reserved
//! areas), folders with their compression (none, MSZIP, Quantum, LZX and
//! its window), and the file list (names, sizes, times, attributes).
//! Files in uncompressed and MSZIP folders are handed on (within the
//! limits); Quantum and LZX are listed only.
//!
//! Specification: [MS-CAB] Cabinet File Format, revision 7.0.

use super::{Entry, Inventory, Kind, child, dos_time, wanted};
use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, latin1_or_utf8,
};

/// Extractor for cabinet files.
pub struct Cab;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.cab",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "cab",
        name: "Microsoft Cabinet",
        family: "archive",
        mimes: &["application/vnd.ms-cab-compressed"],
        extensions: &["cab"],
        magic: &[Magic::prefix(b"MSCF\0\0\0\0")],
        parent: None,
    }],
};

const MAX_FILES: usize = 1 << 16;

struct Folder {
    offset: u64,
    blocks: u16,
    compression: u16,
}

fn compression_name(t: u16) -> String {
    match t & 0x0f {
        0 => "none".into(),
        1 => "MSZIP".into(),
        2 => format!("Quantum (level {})", (t >> 4) & 0xf),
        3 => format!("LZX (window 2^{})", (t >> 8) & 0x1f),
        _ => "unknown".into(),
    }
}

fn cstr(r: &mut ByteReader<'_>, utf8: bool) -> Result<String, ExtractError> {
    let raw = r.cstr()?;
    Ok(if utf8 { String::from_utf8_lossy(raw).into_owned() } else { latin1_or_utf8(raw) })
}

impl Extractor for Cab {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // header, folders, files, children
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let head = src.read_vec(0, usize::try_from(len.min(1 << 16)).unwrap_or(0))?;
        let mut r = ByteReader::new(&head).skip(8)?;
        let declared = r.le_u32()?;
        r.le_u32()?;
        let files_at = u64::from(r.le_u32()?);
        r.le_u32()?;
        let (minor, major) = (r.u8()?, r.u8()?);
        let n_folders = r.le_u16()?;
        let n_files = r.le_u16()?;
        let flags = r.le_u16()?;
        let set_id = r.le_u16()?;
        let index = r.le_u16()?;
        cx.format_set("version", format!("{major}.{minor}"));
        if u64::from(declared) != len {
            cx.format_set("declared_size_bytes", declared);
        }
        let (mut folder_reserve, mut data_reserve) = (0usize, 0usize);
        if flags & 4 != 0 {
            let header_reserve = usize::from(r.le_u16()?);
            folder_reserve = usize::from(r.u8()?);
            data_reserve = usize::from(r.u8()?);
            r.advance(header_reserve)?;
            // Signed cabinets keep their signature in the header reserve.
            cx.format_set("reserved_bytes", header_reserve);
        }
        if flags & 1 != 0 {
            cx.format_set("previous_cabinet", cstr(&mut r, false)?);
            cstr(&mut r, false)?;
        }
        if flags & 2 != 0 {
            cx.format_set("next_cabinet", cstr(&mut r, false)?);
            cstr(&mut r, false)?;
        }
        if flags & 3 != 0 || index > 0 {
            cx.format_set("set_id", set_id);
            cx.format_set("set_index", index);
        }
        let mut folders = Vec::new();
        for _ in 0..n_folders {
            folders.push(Folder { offset: u64::from(r.le_u32()?), blocks: r.le_u16()?, compression: r.le_u16()? });
            r.advance(folder_reserve)?;
        }
        let mut kinds: Vec<String> = Vec::new();
        for f in &folders {
            let k = compression_name(f.compression);
            if !kinds.contains(&k) {
                kinds.push(k);
            }
        }
        cx.format_set("folders", folders.len());
        if !kinds.is_empty() {
            cx.format_set("compression", kinds);
        }

        // The file list (usually right after the folders, in the head).
        let list = if files_at + u64::from(n_files) * 300 <= head.len() as u64 {
            head.clone()
        } else {
            src.read_vec(0, usize::try_from(len.min(files_at + (MAX_FILES as u64) * 300)).unwrap_or(0))?
        };
        let mut r = ByteReader::new(&list)
            .skip(usize::try_from(files_at).map_err(|_| ExtractError::malformed("CAB files"))?)?;
        let mut inv = Inventory::new();
        let mut files: Vec<(String, u64, u64, u16)> = Vec::new(); // name, size, offset in folder, folder
        for _ in 0..usize::from(n_files).min(MAX_FILES) {
            let size = u64::from(r.le_u32()?);
            let offset = u64::from(r.le_u32()?);
            let folder = r.le_u16()?;
            let (date, time, attribs) = (r.le_u16()?, r.le_u16()?, r.le_u16()?);
            let name = cstr(&mut r, attribs & 0x80 != 0)?;
            let method = folders.get(usize::from(folder)).map(|f| compression_name(f.compression));
            // 0xFFFD–0xFFFF: continued from or into a neighbouring cabinet.
            if folder >= 0xfffd {
                cx.format_set("spans_cabinets", true);
            }
            inv.push(Entry {
                path: name.clone(),
                kind: Kind::File,
                size: Some(size),
                compressed: None,
                modified: dos_time(date, time),
                method,
                ..Entry::default()
            });
            files.push((name, size, offset, folder));
        }
        inv.report(cx, len);

        // Children from uncompressed and MSZIP folders.
        let limit = cx.parse_limit();
        for (fi, f) in folders.iter().enumerate() {
            if cx.child_room() == 0 {
                break;
            }
            if f.compression & 0x0f > 1 {
                continue;
            }
            let mine: Vec<&(String, u64, u64, u16)> =
                files.iter().filter(|(_, size, _, folder)| usize::from(*folder) == fi && *size > 0).collect();
            if mine.is_empty()
                || !mine.iter().any(|(n, s, ..)| wanted(&Entry { path: n.clone(), size: Some(*s), ..Entry::default() }))
            {
                continue;
            }
            cx.checkpoint()?;
            let mut blocks: Vec<Vec<u8>> = Vec::new();
            let mut at = f.offset;
            let mut raw_total = 0usize;
            for _ in 0..f.blocks {
                let Ok(h) = src.read_vec(at, 8) else { break };
                let n = u64::from(u16::from_le_bytes([h[4], h[5]]));
                let data_at = at + 8 + data_reserve as u64;
                let Ok(data) = src.read_vec(data_at, usize::try_from(n).unwrap_or(0)) else { break };
                raw_total += usize::from(u16::from_le_bytes([h[6], h[7]]));
                blocks.push(data);
                at = data_at + n;
                if raw_total >= limit {
                    break;
                }
            }
            let (data, complete) = if f.compression.trailing_zeros() >= 4 {
                let data: Vec<u8> = blocks.concat();
                let n = data.len().min(limit);
                (data[..n].to_vec(), blocks.len() == usize::from(f.blocks) && n == data.len())
            } else {
                let slices: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
                let d = cx.decompress_mszip(&slices, limit)?;
                let ok = d.complete() && blocks.len() == usize::from(f.blocks);
                (d.data, ok)
            };
            for (name, size, offset, _) in mine {
                let start = usize::try_from(*offset).unwrap_or(usize::MAX).min(data.len());
                let end = usize::try_from(offset + size).unwrap_or(usize::MAX).min(data.len());
                if start >= end {
                    continue;
                }
                let whole = (end - start) as u64 == *size && (complete || end < data.len());
                if !child(cx, name, data[start..end].to_vec(), whole)? {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

crate::register_extractor!(Cab);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("cab");
}
