//! ext2 / ext3 / ext4 directory trees, for the ext volumes a disk image
//! holds (Linux disks, Android images): names, types, sizes, permissions,
//! modification times and symbolic link targets into the archive
//! inventory, and files read through their extent trees or block maps (or
//! inline data) and handed on within the limits.
//!
//! Specification: "ext4 Data Structures and Algorithms" (kernel.org
//! documentation: superblock, group descriptors, inodes, extent tree,
//! linear directories; hashed directories are read through their leaf
//! blocks, which hold ordinary entries).

use std::collections::HashSet;

use super::archive::{Entry, Inventory, Kind, MAX_ENTRIES, unix_time, wanted};
use crate::plugin::volume::num::{le16, le32};
use crate::plugin::{Context, ExtractError, Source};

/// Folder depth followed.
const MAX_DEPTH: usize = 64;
/// Directory bytes read at most.
const MAX_DIR: u64 = 16 << 20;
/// Extent-tree depth followed.
const MAX_TREE: u32 = 5;
/// Block runs kept per file.
const MAX_RUNS: usize = 1 << 16;

/// An ext volume: where it is and the geometry to find inodes.
pub(super) struct Ext {
    offset: u64,
    len: u64,
    block: u64,
    inodes_per_group: u64,
    inode_size: u64,
    /// Inode-table block of each group.
    tables: Vec<u64>,
}

/// An inode's fields that matter here.
struct Inode {
    mode: u16,
    size: u64,
    mtime: u32,
    flags: u32,
    blocks: [u8; 60],
}

impl Ext {
    pub(super) fn open(src: &mut dyn Source, offset: u64, len: u64) -> Result<Option<Self>, ExtractError> {
        if len < 2048 {
            return Ok(None);
        }
        let s = src.read_vec(offset + 1024, 1024)?;
        if le16(&s, 56) != Some(0xEF53) {
            return Ok(None);
        }
        let get = |at: usize| u64::from(le32(&s, at).unwrap_or(0));
        let log = get(24);
        if log > 6 {
            return Ok(None);
        }
        let block = 1024 << log;
        let (inodes, blocks_per_group, inodes_per_group) = (get(0), get(32), get(40));
        let inode_size = if get(76) >= 1 { u64::from(le16(&s, 88).unwrap_or(128)) } else { 128 };
        let wide = get(96) & 0x80 != 0;
        let desc = if wide { u64::from(le16(&s, 0xFE).unwrap_or(32)).max(32) } else { 32 };
        if blocks_per_group == 0 || inodes_per_group == 0 || !(128..=4096).contains(&inode_size) {
            return Ok(None);
        }
        let groups = inodes.div_ceil(inodes_per_group).min(1 << 16);
        let gdt = (get(20) + 1) * block;
        let raw = src.read_vec(offset + gdt, usize::try_from((groups * desc).min(len)).unwrap_or(0))?;
        let tables = raw
            .chunks_exact(usize::try_from(desc).unwrap_or(32))
            .map(|d| {
                u64::from(le32(d, 8).unwrap_or(0)) | if wide { u64::from(le32(d, 0x28).unwrap_or(0)) << 32 } else { 0 }
            })
            .collect();
        Ok(Some(Self { offset, len, block, inodes_per_group, inode_size, tables }))
    }

    fn read_at(&self, src: &mut dyn Source, at: u64, n: usize) -> Option<Vec<u8>> {
        (at.checked_add(n as u64)? <= self.len).then(|| src.read_vec(self.offset + at, n).ok()).flatten()
    }

    fn inode(&self, src: &mut dyn Source, n: u64) -> Option<Inode> {
        let g = (n.checked_sub(1)?) / self.inodes_per_group;
        let i = (n - 1) % self.inodes_per_group;
        let at =
            self.tables.get(usize::try_from(g).ok()?)?.checked_mul(self.block)?.checked_add(i * self.inode_size)?;
        let b = self.read_at(src, at, 128)?;
        Some(Inode {
            mode: le16(&b, 0)?,
            size: u64::from(le32(&b, 4)?) | u64::from(le32(&b, 108)?) << 32,
            mtime: le32(&b, 16)?,
            flags: le32(&b, 32)?,
            blocks: b[40..100].try_into().ok()?,
        })
    }

    /// The file's blocks as runs `(logical, physical, count)`.
    fn runs(&self, src: &mut dyn Source, ino: &Inode) -> Vec<(u64, u64, u64)> {
        let mut out = Vec::new();
        if ino.flags & 0x8_0000 != 0 {
            self.extents(src, &ino.blocks, 0, &mut out);
        } else {
            let ptrs: Vec<u64> = ino
                .blocks
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u64::from(u32::from_le_bytes([c[0], c[1], c[2], c[3]])))
                .collect();
            let per = self.block / 4;
            let mut logical = 0u64;
            for &p in &ptrs[..12] {
                if p != 0 {
                    out.push((logical, p, 1));
                }
                logical += 1;
            }
            for (level, &p) in ptrs[12..15].iter().enumerate() {
                let span = per.pow(u32::try_from(level).unwrap_or(0) + 1);
                if p != 0 {
                    self.indirect(src, p, u32::try_from(level).unwrap_or(0), logical, &mut out);
                }
                logical += span;
            }
        }
        out
    }

    fn indirect(&self, src: &mut dyn Source, block: u64, level: u32, first: u64, out: &mut Vec<(u64, u64, u64)>) {
        let Some(b) = block
            .checked_mul(self.block)
            .and_then(|at| self.read_at(src, at, usize::try_from(self.block).unwrap_or(0)))
        else {
            return;
        };
        let span = (self.block / 4).pow(level);
        for (i, c) in b.as_chunks::<4>().0.iter().enumerate() {
            if out.len() >= MAX_RUNS {
                return;
            }
            let p = u64::from(u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
            if p == 0 {
                continue;
            }
            let logical = first + i as u64 * span;
            if level == 0 {
                out.push((logical, p, 1));
            } else {
                self.indirect(src, p, level - 1, logical, out);
            }
        }
    }

    fn extents(&self, src: &mut dyn Source, node: &[u8], depth: u32, out: &mut Vec<(u64, u64, u64)>) {
        if le16(node, 0) != Some(0xF30A) || depth > MAX_TREE {
            return;
        }
        let entries = usize::from(le16(node, 2).unwrap_or(0));
        let leaf = le16(node, 6) == Some(0);
        for i in 0..entries {
            if out.len() >= MAX_RUNS {
                return;
            }
            let e = 12 + 12 * i;
            let (Some(lo), Some(hi16)) =
                (le32(node, e + if leaf { 8 } else { 4 }), le16(node, e + if leaf { 6 } else { 8 }))
            else {
                return;
            };
            let physical = u64::from(lo) | u64::from(hi16) << 32;
            if leaf {
                let logical = u64::from(le32(node, e).unwrap_or(0));
                let len = u64::from(le16(node, e + 4).unwrap_or(0));
                // Uninitialised extents read as zeros.
                if len <= 32768 {
                    out.push((logical, physical, len));
                }
            } else if let Some(child) = physical
                .checked_mul(self.block)
                .and_then(|at| self.read_at(src, at, usize::try_from(self.block).unwrap_or(0)))
            {
                self.extents(src, &child, depth + 1, out);
            }
        }
    }

    /// Up to `max` bytes of the file with this inode.
    fn data(&self, src: &mut dyn Source, ino: &Inode, max: u64) -> Vec<u8> {
        let want = ino.size.min(max);
        if ino.flags & 0x1000_0000 != 0 {
            return ino.blocks[..usize::try_from(want.min(60)).unwrap_or(0)].to_vec();
        }
        let mut out = vec![0u8; usize::try_from(want).unwrap_or(0)];
        for (logical, physical, count) in self.runs(src, ino) {
            let (Some(start), Some(at)) = (logical.checked_mul(self.block), physical.checked_mul(self.block)) else {
                continue;
            };
            if start >= want {
                continue;
            }
            let n = count.saturating_mul(self.block).min(want - start);
            if let Some(d) = self.read_at(src, at, usize::try_from(n).unwrap_or(0)) {
                let s = usize::try_from(start).unwrap_or(0);
                out[s..s + d.len()].copy_from_slice(&d);
            }
        }
        out
    }

    /// Walk the tree into `inv`, collecting `(path, inode, size)` to hand on.
    pub(super) fn walk(
        &self,
        src: &mut dyn Source,
        cx: &mut Context<'_>,
        prefix: &str,
        inv: &mut Inventory,
        files: &mut Vec<(String, u64, u64)>,
    ) -> Result<(), ExtractError> {
        let mut stack = vec![(2u64, prefix.to_string(), 0usize)];
        let mut seen = HashSet::new();
        while let Some((dir, path, depth)) = stack.pop() {
            cx.checkpoint()?;
            if !seen.insert(dir) {
                continue;
            }
            let Some(ino) = self.inode(src, dir) else { continue };
            let data = self.data(src, &ino, MAX_DIR);
            let mut at = 0;
            while at + 8 <= data.len() {
                let (Some(n), Some(rec)) = (le32(&data, at), le16(&data, at + 4)) else { break };
                let name_len = usize::from(data[at + 6]);
                let rec = usize::from(rec);
                if rec < 8 {
                    // Damaged: skip to the next block.
                    let block = usize::try_from(self.block).unwrap_or(1024);
                    at = (at / block + 1) * block;
                    continue;
                }
                let name = data.get(at + 8..at + 8 + name_len).map(|b| String::from_utf8_lossy(b).into_owned());
                at += rec;
                let Some(name) = name.filter(|n| n != "." && n != ".." && !n.is_empty()) else { continue };
                if n == 0 {
                    continue;
                }
                if inv.entries >= MAX_ENTRIES as u64 {
                    inv.truncated = true;
                    return Ok(());
                }
                let Some(child) = self.inode(src, u64::from(n)) else { continue };
                let p = format!("{path}{name}");
                let mode = Some(u32::from(child.mode));
                let modified = unix_time(i64::from(child.mtime));
                match Kind::from_mode(u32::from(child.mode)) {
                    Kind::Dir => {
                        inv.push(Entry {
                            path: format!("{p}/"),
                            kind: Kind::Dir,
                            size: Some(0),
                            modified,
                            mode,
                            ..Entry::default()
                        });
                        if depth < MAX_DEPTH {
                            stack.push((u64::from(n), format!("{p}/"), depth + 1));
                        }
                    }
                    Kind::Symlink => {
                        let target = if child.size < 60 && child.flags & 0x8_0000 == 0 {
                            child.blocks[..usize::try_from(child.size).unwrap_or(0)].to_vec()
                        } else {
                            self.data(src, &child, 4096)
                        };
                        let link = Some(String::from_utf8_lossy(&target).into_owned());
                        inv.push(Entry {
                            path: p,
                            kind: Kind::Symlink,
                            size: Some(0),
                            link,
                            modified,
                            mode,
                            ..Entry::default()
                        });
                    }
                    Kind::File => {
                        let e = Entry {
                            path: p.clone(),
                            kind: Kind::File,
                            size: Some(child.size),
                            compressed: Some(child.size),
                            modified,
                            mode,
                            ..Entry::default()
                        };
                        if wanted(&e) && files.len() < cx.child_room() {
                            files.push((p, u64::from(n), child.size));
                        }
                        inv.push(e);
                    }
                    k => inv.push(Entry { path: p, kind: k, size: Some(0), modified, mode, ..Entry::default() }),
                }
            }
        }
        Ok(())
    }

    /// A listed file's contents, at most `max` bytes.
    pub(super) fn read(
        &self,
        src: &mut dyn Source,
        cx: &mut Context<'_>,
        inode: u64,
        max: u64,
    ) -> Result<Vec<u8>, ExtractError> {
        cx.checkpoint()?;
        Ok(self.inode(src, inode).map(|i| self.data(src, &i, max)).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use crate::plugin::testing::report_for;

    #[test]
    fn huge_inode_table_address() {
        // A 64-bit ext4 superblock whose first group's inode table is at
        // block 2^64 - 1: listing must stop, not overflow.
        let mut d = vec![0u8; 8192];
        let sb = 1024;
        d[sb..sb + 4].copy_from_slice(&16u32.to_le_bytes());
        d[sb + 4..sb + 8].copy_from_slice(&8u32.to_le_bytes());
        d[sb + 20..sb + 24].copy_from_slice(&1u32.to_le_bytes());
        d[sb + 32..sb + 36].copy_from_slice(&8192u32.to_le_bytes());
        d[sb + 40..sb + 44].copy_from_slice(&16u32.to_le_bytes());
        d[sb + 56..sb + 58].copy_from_slice(&0xEF53u16.to_le_bytes());
        d[sb + 96..sb + 100].copy_from_slice(&0x80u32.to_le_bytes());
        d[sb + 0xFE..sb + 0x100].copy_from_slice(&64u16.to_le_bytes());
        d[2048 + 8..2048 + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        d[2048 + 0x28..2048 + 0x2C].copy_from_slice(&u32::MAX.to_le_bytes());
        let report = report_for("disk.ext4", &d);
        let json = serde_json::to_value(&report).unwrap();
        let runs = json["diagnostics"]["extractors"].as_array().unwrap();
        assert!(runs.iter().all(|r| r["status"] != "internal"), "{runs:?}");
    }
}
