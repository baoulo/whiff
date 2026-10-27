//! FAT12 / 16 / 32 directory trees, for the FAT volumes a disk image holds
//! (floppy images, USB sticks, EFI system partitions, El Torito boot
//! images): long file names, sizes, modification times and attributes into
//! the archive inventory, and files read along their cluster chains and
//! handed on as children within the limits.
//!
//! Specification: Microsoft "FAT: General Overview of On-Disk Format"
//! (2000, 2005), including VFAT long file names.

use std::collections::HashSet;

use super::archive::{Entry, Inventory, Kind, MAX_ENTRIES, dos_time, wanted};
use crate::plugin::volume::num::{le16, le32};
use crate::plugin::{Context, ExtractError, Source};

/// FAT bytes read at most (a 2 M-cluster FAT32).
const MAX_FAT: u64 = 8 << 20;
/// Folder depth followed.
const MAX_DEPTH: usize = 32;

/// A FAT volume: its geometry and its allocation table.
pub(super) struct Fat {
    g: crate::plugin::volume::FatGeometry,
    offset: u64,
    table: Vec<u8>,
}

impl Fat {
    pub(super) fn open(src: &mut dyn Source, offset: u64, len: u64) -> Result<Option<Self>, ExtractError> {
        let boot = src.read_vec(offset, usize::try_from(len.min(512)).unwrap_or(0))?;
        let Some(g) = crate::plugin::volume::fat_geometry(&boot) else { return Ok(None) };
        let fat_bytes = (u64::from(g.fat_sectors) * u64::from(g.sector)).min(MAX_FAT);
        let at = offset + u64::from(g.reserved) * u64::from(g.sector);
        let fat_bytes = fat_bytes.min(src.len().saturating_sub(at));
        let table = src.read_vec(at, usize::try_from(fat_bytes).unwrap_or(0))?;
        Ok(Some(Self { g, offset, table }))
    }

    /// The cluster after `n`, or `None` at the end of the chain.
    fn next(&self, n: u32) -> Option<u32> {
        let (v, end) = match self.g.kind {
            "fat12" => {
                let at = n as usize + n as usize / 2;
                let v = u32::from(le16(&self.table, at)?);
                (if n & 1 == 1 { v >> 4 } else { v & 0xFFF }, 0xFF7)
            }
            "fat16" => (u32::from(le16(&self.table, 2 * n as usize)?), 0xFFF7),
            _ => (le32(&self.table, 4 * n as usize)? & 0x0FFF_FFFF, 0x0FFF_FFF7),
        };
        (v >= 2 && v < end && v - 2 < self.g.clusters).then_some(v)
    }

    /// The clusters of a chain, at most `max` of them, stopping at a loop.
    fn chain(&self, first: u32, max: u64) -> Vec<u32> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut c = Some(first).filter(|&c| c >= 2 && c - 2 < self.g.clusters);
        while let Some(n) = c {
            if out.len() as u64 >= max || !seen.insert(n) {
                break;
            }
            out.push(n);
            c = self.next(n);
        }
        out
    }

    fn cluster_at(&self, n: u32) -> u64 {
        self.offset + self.g.data() + u64::from(n - 2) * self.g.cluster_bytes()
    }

    /// Read up to `size` bytes along the chain starting at `first`.
    pub(super) fn read(&self, src: &mut dyn Source, first: u32, size: u64) -> Result<Vec<u8>, ExtractError> {
        let cb = self.g.cluster_bytes();
        let mut out = Vec::new();
        for n in self.chain(first, size.div_ceil(cb).max(1)) {
            let take = (size - out.len() as u64).min(cb);
            let at = self.cluster_at(n);
            if at >= src.len() {
                break;
            }
            let take = take.min(src.len() - at);
            out.extend(src.read_vec(at, usize::try_from(take).unwrap_or(0))?);
            if out.len() as u64 >= size {
                break;
            }
        }
        Ok(out)
    }

    /// A directory's raw entries (`first` 0: the FAT12 / 16 root).
    fn dir(&self, src: &mut dyn Source, first: u32) -> Result<Vec<u8>, ExtractError> {
        if first == 0 {
            let n =
                (u64::from(self.g.root_entries) * 32).min(src.len().saturating_sub(self.offset + self.g.root_dir()));
            return Ok(src.read_vec(self.offset + self.g.root_dir(), usize::try_from(n).unwrap_or(0))?);
        }
        self.read(src, first, 4 << 20)
    }
}

/// One directory entry, with its long name when it has one.
struct DirEntry {
    name: String,
    dir: bool,
    first: u32,
    size: u32,
    modified: Option<String>,
}

/// Parse a directory's 32-byte entries.
fn entries(data: &[u8]) -> Vec<DirEntry> {
    let mut out = Vec::new();
    let mut long: Vec<u16> = Vec::new();
    for e in data.as_chunks::<32>().0 {
        match e[0] {
            0 => break,
            0xE5 => {
                long.clear();
                continue;
            }
            _ => {}
        }
        if e[11] & 0x3F == 0x0F {
            // Long-name pieces come last first.
            if e[0] & 0x40 != 0 {
                long.clear();
            }
            let mut part: Vec<u16> = Vec::new();
            for r in [1..11, 14..26, 28..32] {
                part.extend(e[r].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])));
            }
            part.retain(|&u| u != 0 && u != 0xFFFF);
            part.extend_from_slice(&long);
            long = part;
            continue;
        }
        if e[11] & 0x08 != 0 {
            long.clear();
            continue;
        }
        let short = || {
            let lower = |s: &[u8], flag: u8| {
                let t = String::from_utf8_lossy(s).trim_end().to_string();
                if e[12] & flag != 0 { t.to_lowercase() } else { t }
            };
            let mut base = e[..8].to_vec();
            if base[0] == 0x05 {
                base[0] = 0xE5;
            }
            let (b, x) = (lower(&base, 0x08), lower(&e[8..11], 0x10));
            if x.is_empty() { b } else { format!("{b}.{x}") }
        };
        let name = if long.is_empty() { short() } else { String::from_utf16_lossy(&long) };
        long.clear();
        if name == "." || name == ".." || name.is_empty() {
            continue;
        }
        out.push(DirEntry {
            name,
            dir: e[11] & 0x10 != 0,
            first: u32::from(le16(e, 26).unwrap_or(0)) | u32::from(le16(e, 20).unwrap_or(0)) << 16,
            size: le32(e, 28).unwrap_or(0),
            modified: dos_time(le16(e, 24).unwrap_or(0), le16(e, 22).unwrap_or(0)),
        });
    }
    out
}

/// Walk one FAT volume into `inv`, collecting the files to hand on as
/// `(path, first cluster, size)`.
pub(super) fn walk(
    fat: &Fat,
    src: &mut dyn Source,
    cx: &mut Context<'_>,
    prefix: &str,
    inv: &mut Inventory,
    files: &mut Vec<(String, u64, u64)>,
) -> Result<(), ExtractError> {
    let root = if fat.g.kind == "fat32" { fat.g.root_cluster } else { 0 };
    let mut stack = vec![(root, prefix.to_string(), 0usize)];
    let mut seen = HashSet::new();
    while let Some((first, path, depth)) = stack.pop() {
        cx.checkpoint()?;
        if !seen.insert(first) {
            continue;
        }
        let data = fat.dir(src, first)?;
        for d in entries(&data) {
            if inv.entries >= MAX_ENTRIES as u64 {
                inv.truncated = true;
                return Ok(());
            }
            let p = format!("{path}{}{}", d.name, if d.dir { "/" } else { "" });
            let e = Entry {
                path: p.clone(),
                kind: if d.dir { Kind::Dir } else { Kind::File },
                size: Some(if d.dir { 0 } else { u64::from(d.size) }),
                compressed: Some(if d.dir { 0 } else { u64::from(d.size) }),
                modified: d.modified,
                ..Entry::default()
            };
            if d.dir {
                if depth < MAX_DEPTH && d.first >= 2 {
                    stack.push((d.first, p, depth + 1));
                }
            } else if wanted(&e) && files.len() < cx.child_room() {
                files.push((p, u64::from(d.first), u64::from(d.size)));
            }
            inv.push(e);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_and_short_names() {
        let mut d = Vec::new();
        // "Tide tbl.txt" as one long-name entry before its short entry.
        let mut lfn = [0u8; 32];
        lfn[0] = 0x41;
        lfn[11] = 0x0F;
        let units: Vec<u16> = "Tide tbl.txt".encode_utf16().chain([0]).chain([0xFFFF; 12]).collect();
        let mut it = units.iter();
        for r in [1..11usize, 14..26, 28..32] {
            for c in lfn[r].as_chunks_mut::<2>().0.iter_mut() {
                c.copy_from_slice(&it.next().unwrap().to_le_bytes());
            }
        }
        d.extend_from_slice(&lfn);
        let mut short = [0x20u8; 32];
        short[..11].copy_from_slice(b"TIDETA~1TXT");
        short[11] = 0x20;
        short[12..].fill(0);
        short[26] = 3;
        short[28] = 12;
        d.extend_from_slice(&short);
        let mut lower = [0u8; 32];
        lower[..11].copy_from_slice(b"README  MD ");
        lower[12] = 0x18;
        d.extend_from_slice(&lower);
        let e = entries(&d);
        assert_eq!(e.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["Tide tbl.txt", "readme.md"]);
        assert_eq!((e[0].first, e[0].size, e[0].dir), (3, 12, false));
    }
}
