//! Home-computer disk images: Amiga DOS volumes (`.adf` floppies and
//! `.hdf` hard files; OFS and FFS, international and directory-cache
//! variants) and Commodore 1541 disks (`.d64`). The volume name, dates,
//! DOS variant and free space are reported, the directory tree goes into
//! the archive inventory (with C64 file types and block counts), and files are read along their block
//! chains and handed on.
//!
//! Specifications: "The ADF format" FAQ (Laurent Clévy, 2019) and the
//! AmigaDOS technical reference; the 1541 disk layout as documented in
//! "D64 (Electronic form of a physical 1541 disk)" (Peter Schepers).

use std::collections::HashSet;

use super::archive::{Entry, Inventory, Kind, MAX_ENTRIES, child, wanted};
use crate::plugin::volume::num::be32;
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source};

/// Extractor for Amiga and Commodore disk images.
pub struct Floppy;

static META: ExtractorMeta = ExtractorMeta {
    id: "disk.floppy",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "adf",
            name: "Amiga disk image",
            family: "disk",
            mimes: &["application/x-amiga-disk-format"],
            extensions: &["adf", "hdf"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "d64",
            name: "Commodore 1541 disk image",
            family: "disk",
            mimes: &["application/x-d64"],
            extensions: &["d64"],
            magic: &[],
            parent: None,
        },
    ],
};

/// D64 sizes: 35 or 40 tracks, with or without error bytes.
const D64_SIZES: [u64; 4] = [174_848, 175_531, 196_608, 197_376];
/// Folder depth followed.
const MAX_DEPTH: usize = 32;

impl Extractor for Floppy {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if probe.head.starts_with(b"DOS") && probe.head.get(3).is_some_and(|&f| f <= 7) && probe.len.is_multiple_of(512)
        {
            return Some(Sniff { format: "adf", confidence: 0.9 });
        }
        (probe.extension == Some("d64") && D64_SIZES.contains(&probe.len))
            .then_some(Sniff { format: "d64", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "d64" { d64(src, cx) } else { amiga(src, cx) }
    }
}

crate::register_extractor!(Floppy);

// ---------------------------------------------------------------- Amiga

/// An AmigaDOS date (days since 1978-01-01, minutes, ticks) as civil time.
fn amiga_date(b: &[u8], at: usize) -> Option<String> {
    let (days, mins, ticks) = (be32(b, at)?, be32(b, at + 4)?, be32(b, at + 8)?);
    if days == 0 && mins == 0 || mins >= 1440 {
        return None;
    }
    let secs = 252_460_800 + i64::from(days) * 86_400 + i64::from(mins) * 60 + i64::from(ticks / 50);
    let ts = jiff::Timestamp::from_second(secs).ok()?;
    Some(ts.strftime("%Y-%m-%dT%H:%M:%S").to_string())
}

/// A BCPL string: a length byte, then up to `max` Latin-1 characters.
fn bstr(b: &[u8], at: usize, max: usize) -> String {
    let n = usize::from(b.get(at).copied().unwrap_or(0)).min(max);
    b.get(at + 1..at + 1 + n).unwrap_or(&[]).iter().map(|&c| char::from(c)).collect()
}

struct Amiga {
    ffs: bool,
    blocks: u64,
}

impl Amiga {
    fn block(&self, src: &mut dyn Source, n: u32) -> Option<Vec<u8>> {
        (u64::from(n) < self.blocks && n > 1).then(|| src.read_vec(u64::from(n) * 512, 512).ok()).flatten()
    }

    /// A file's data, at most `max` bytes.
    fn data(&self, src: &mut dyn Source, header: &[u8], size: u64, max: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let want = usize::try_from(size.min(max)).unwrap_or(0);
        if self.ffs {
            // Data block pointers, last first, then extension blocks.
            let mut h = header.to_vec();
            let mut seen = HashSet::new();
            'blocks: loop {
                for i in (0..72).rev() {
                    let Some(p) = be32(&h, 24 + 4 * i).filter(|&p| p != 0) else { continue };
                    let Some(d) = self.block(src, p) else { break 'blocks };
                    out.extend_from_slice(&d[..(want - out.len()).min(512)]);
                    if out.len() >= want {
                        break 'blocks;
                    }
                }
                let Some(ext) = be32(&h, 504).filter(|&e| e != 0 && seen.insert(e)) else { break };
                let Some(e) = self.block(src, ext) else { break };
                h = e;
            }
        } else {
            // OFS: data blocks chained, each with a 24-byte header.
            let mut next = be32(header, 16).unwrap_or(0);
            let mut seen = HashSet::new();
            while next != 0 && seen.insert(next) && out.len() < want {
                let Some(d) = self.block(src, next) else { break };
                let n = (be32(&d, 12).unwrap_or(0) as usize).min(488);
                out.extend_from_slice(&d[24..24 + n.min(want - out.len())]);
                next = be32(&d, 16).unwrap_or(0);
            }
        }
        out
    }
}

#[allow(clippy::too_many_lines)] // boot block, root block, tree walk, children
fn amiga(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let boot = src.read_vec(0, 1024.min(usize::try_from(src.len()).unwrap_or(0)))?;
    let flags = boot.get(3).copied().unwrap_or(0);
    let variant = match flags {
        0 => "OFS",
        1 => "FFS",
        2 => "OFS-INTL",
        3 => "FFS-INTL",
        4 => "OFS-DC",
        5 => "FFS-DC",
        _ => "LNFS",
    };
    cx.format_set("dos_type", variant);
    let blocks = src.len() / 512;
    cx.format_set("blocks", blocks);
    cx.format_set(
        "medium",
        match src.len() {
            901_120 => "floppy_dd",
            1_802_240 => "floppy_hd",
            _ => "hard_file",
        },
    );
    let am = Amiga { ffs: flags & 1 == 1, blocks };
    // The root block is in the middle of the volume (the boot block's
    // pointer is often left at 880, a floppy's middle).
    let middle = u32::try_from(blocks / 2).unwrap_or(0);
    let root_n = [middle, be32(&boot, 8).unwrap_or(0)]
        .into_iter()
        .find(|&n| am.block(src, n).is_some_and(|r| be32(&r, 0) == Some(2) && be32(&r, 508) == Some(1)))
        .ok_or_else(|| ExtractError::malformed("no root block"))?;
    let root = am.block(src, root_n).unwrap_or_default();
    let name = bstr(&root, 432, 30);
    if !name.is_empty() {
        cx.format_set("volume_name", name.clone());
        cx.content().title(name);
    }
    if let Some(d) = amiga_date(&root, 484) {
        cx.format_set("created", d);
    }
    if let Some(d) = amiga_date(&root, 472) {
        cx.format_set("modified", d);
    }
    let mut inv = Inventory::new();
    let mut files: Vec<(String, Vec<u8>, u64)> = Vec::new();
    let mut stack = vec![(root_n, String::new(), 0usize)];
    let mut seen = HashSet::new();
    while let Some((dir, path, depth)) = stack.pop() {
        cx.checkpoint()?;
        let Some(d) = am.block(src, dir) else { continue };
        for i in 0..72 {
            let mut next = be32(&d, 24 + 4 * i).unwrap_or(0);
            while next != 0 && seen.insert(next) {
                let Some(h) = am.block(src, next) else { break };
                if be32(&h, 0) != Some(2) {
                    break;
                }
                if inv.entries >= MAX_ENTRIES as u64 {
                    inv.truncated = true;
                    break;
                }
                let name = bstr(&h, 432, 30);
                let sec = be32(&h, 508).unwrap_or(0).cast_signed();
                let modified = amiga_date(&h, 420);
                match sec {
                    2 => {
                        let p = format!("{path}{name}/");
                        inv.push(Entry {
                            path: p.clone(),
                            kind: Kind::Dir,
                            size: Some(0),
                            modified,
                            ..Entry::default()
                        });
                        if depth < MAX_DEPTH {
                            stack.push((next, p, depth + 1));
                        }
                    }
                    -3 => {
                        let size = u64::from(be32(&h, 324).unwrap_or(0));
                        let p = format!("{path}{name}");
                        let e = Entry {
                            path: p.clone(),
                            kind: Kind::File,
                            size: Some(size),
                            compressed: Some(size),
                            modified,
                            ..Entry::default()
                        };
                        if wanted(&e) && files.len() < cx.child_room() {
                            files.push((p, h.clone(), size));
                        }
                        inv.push(e);
                    }
                    3 => {
                        let target = h.get(24..).map(|t| {
                            String::from_utf8_lossy(&t[..t.iter().position(|&c| c == 0).unwrap_or(t.len())])
                                .into_owned()
                        });
                        inv.push(Entry {
                            path: format!("{path}{name}"),
                            kind: Kind::Symlink,
                            size: Some(0),
                            link: target,
                            modified,
                            ..Entry::default()
                        });
                    }
                    -4 | 4 => {
                        inv.push(Entry {
                            path: format!("{path}{name}"),
                            kind: Kind::Hardlink,
                            size: Some(0),
                            modified,
                            ..Entry::default()
                        });
                    }
                    _ => {}
                }
                next = be32(&h, 496).unwrap_or(0);
            }
        }
    }
    inv.report(cx, src.len());
    let limit = cx.parse_limit() as u64;
    for (p, h, size) in files {
        let data = am.data(src, &h, size, limit);
        let complete = data.len() as u64 == size;
        if !child(cx, &p, data, complete)? {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- D64

/// Byte offset of a 1541 track (1-based) and sector.
fn d64_offset(track: u8, sector: u8) -> Option<u64> {
    let per = |t: u8| match t {
        1..=17 => 21u64,
        18..=24 => 19,
        25..=30 => 18,
        31..=40 => 17,
        _ => 0,
    };
    if track == 0 || u64::from(sector) >= per(track) {
        return None;
    }
    let before: u64 = (1..track).map(per).sum();
    Some((before + u64::from(sector)) * 256)
}

/// PETSCII (as file names use it) to text, padding dropped.
fn petscii(b: &[u8]) -> String {
    b.iter()
        .take_while(|&&c| c != 0xA0)
        .map(|&c| match c {
            0x20..=0x5F => char::from(c),
            0xC1..=0xDA => char::from(c - 0x80),
            _ => '?',
        })
        .collect()
}

fn d64(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    if !D64_SIZES.contains(&len) {
        return Err(ExtractError::malformed("not a 1541 disk image size"));
    }
    let tracks = if len >= 196_608 { 40 } else { 35 };
    cx.format_set("tracks", tracks);
    if !len.is_multiple_of(256) {
        cx.format_set("error_info", true);
    }
    let bam = src.read_vec(d64_offset(18, 0).unwrap_or(0), 256)?;
    let name = petscii(&bam[0x90..0xA0]);
    if !name.trim().is_empty() {
        cx.format_set("disk_name", name.trim_end().to_string());
        cx.content().title(name.trim_end().to_string());
    }
    cx.format_set("disk_id", petscii(&bam[0xA2..0xA4]));
    cx.format_set("dos_type", petscii(&bam[0xA5..0xA7]));
    let free: u64 = (1..=35u8).filter(|&t| t != 18).map(|t| u64::from(bam[4 * usize::from(t)])).sum();
    cx.format_set("free_blocks", free);
    let mut inv = Inventory::new();
    let mut files = Vec::new();
    let (mut t, mut s) = (bam[0], bam[1]);
    let mut seen = HashSet::new();
    while t != 0 && seen.insert((t, s)) {
        let Some(at) = d64_offset(t, s) else { break };
        let d = src.read_vec(at, 256)?;
        for e in d.as_chunks::<32>().0 {
            let ty = e[2];
            if ty == 0 {
                continue;
            }
            let kind = match ty & 7 {
                0 => "DEL",
                1 => "SEQ",
                2 => "PRG",
                3 => "USR",
                4 => "REL",
                _ => "?",
            };
            let blocks = u64::from(u16::from_le_bytes([e[30], e[31]]));
            let name = petscii(&e[5..21]);
            let p = format!("{name}.{}", kind.to_ascii_lowercase());
            let entry = Entry {
                path: p.clone(),
                kind: Kind::File,
                size: Some(blocks * 254),
                compressed: Some(blocks * 256),
                method: Some(kind.into()),
                ..Entry::default()
            };
            if ty & 0x80 != 0 && kind != "DEL" && kind != "REL" && wanted(&entry) && files.len() < cx.child_room() {
                files.push((p, e[3], e[4]));
            }
            inv.push(entry);
        }
        (t, s) = (d[0], d[1]);
    }
    inv.report(cx, len);
    for (p, mut t, mut s) in files {
        let mut data = Vec::new();
        let mut seen = HashSet::new();
        while t != 0 && seen.insert((t, s)) {
            let Some(at) = d64_offset(t, s) else { break };
            let d = src.read_vec(at, 256)?;
            // The last sector says how far it is used.
            let end = if d[0] == 0 { usize::from(d[1]).clamp(1, 255) + 1 } else { 256 };
            data.extend_from_slice(&d[2..end.max(2)]);
            (t, s) = (d[0], d[1]);
        }
        if !child(cx, &p, data, true)? {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts() {
        assert_eq!(d64_offset(18, 0), Some(0x16500));
        assert_eq!(d64_offset(1, 21), None);
        assert_eq!(petscii(b"TIDES\xa0\xa0"), "TIDES");
        let mut b = vec![0u8; 12];
        b[7] = 1;
        assert_eq!(amiga_date(&b, 0).as_deref(), Some("1978-01-01T00:01:00"));
        assert_eq!(bstr(b"\x05TIDESxx", 0, 30), "TIDES");
    }

    crate::fixture_tests!("adf", "d64");
}
