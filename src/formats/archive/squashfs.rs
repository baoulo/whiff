//! squashfs 4.0 file systems (Linux live media, firmware, Snap packages,
//! AppImages): the superblock (version, compressor, block size, inode and
//! fragment counts, creation time, flags) and the directory tree, read
//! from the compressed inode and directory tables, into the archive
//! inventory; files are rebuilt from their data blocks and fragments and
//! handed on. gzip, LZMA, xz and zstd are read; LZO and LZ4 images are
//! listed only when their metadata is stored uncompressed.
//!
//! Specification: squashfs-tools `squashfs_fs.h` and the kernel's
//! `Documentation/filesystems/squashfs.rst`; the layout as described in
//! "SquashFS Binary Format" (David Oberhollenzer).

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value, json};

use super::{Entry, Inventory, Kind, MAX_ENTRIES, child, unix_time, wanted};
use crate::plugin::volume::num::{le16, le32, le64};
use crate::plugin::{Codec, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for squashfs images.
pub struct Squashfs;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.squashfs",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "squashfs",
        name: "squashfs file system",
        family: "archive",
        mimes: &["application/vnd.squashfs"],
        extensions: &["squashfs", "sqsh", "sfs", "sqfs"],
        magic: &[Magic::prefix(b"hsqs")],
        parent: None,
    }],
};

/// Metadata blocks hold at most this much.
const META_BLOCK: usize = 8192;
/// Folder depth followed.
const MAX_DEPTH: usize = 64;
/// Metadata blocks cached.
const MAX_CACHE: usize = 4096;

impl Extractor for Squashfs {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut fs = Image::open(src, 0)?;
        for (k, v) in fs.facts() {
            cx.format_set(&k, v);
        }
        let listed = fs.list(src, cx)?;
        listed.inventory.report(cx, src.len());
        fs.hand_on(src, cx, listed.files)
    }
}

crate::register_extractor!(Squashfs);

/// Where a regular file's data is.
#[derive(Debug, Clone)]
pub(crate) struct FileRef {
    start: u64,
    pub size: u64,
    /// `(fragment index, offset in it)`.
    fragment: Option<(u32, u32)>,
    blocks: Vec<u32>,
}

/// A listing: the inventory and the regular files, by path.
pub(crate) struct Listed {
    pub inventory: Inventory,
    pub files: Vec<(String, FileRef)>,
}

/// An open squashfs image at `base` in its source.
pub(crate) struct Image {
    base: u64,
    sb: Vec<u8>,
    block_size: u64,
    codec: Option<Codec>,
    cache: HashMap<u64, (Vec<u8>, u64)>,
    fragments: Option<Vec<(u64, u32)>>,
}

impl Image {
    /// Read the superblock of the image starting at `base`.
    pub fn open(src: &mut dyn Source, base: u64) -> Result<Self, ExtractError> {
        let sb = src.read_vec(base, 96)?;
        if &sb[..4] != b"hsqs" {
            return Err(ExtractError::malformed("no squashfs superblock"));
        }
        if le16(&sb, 28) != Some(4) {
            return Err(ExtractError::Unsupported(format!("squashfs version {}", le16(&sb, 28).unwrap_or(0))));
        }
        let block_size = u64::from(le32(&sb, 12).unwrap_or(0));
        if !block_size.is_power_of_two() || !(4096..=1 << 20).contains(&block_size) {
            return Err(ExtractError::malformed("block size"));
        }
        let codec = match le16(&sb, 20) {
            Some(1) => Some(Codec::Zlib),
            Some(2) => Some(Codec::LzmaAlone),
            Some(4) => Some(Codec::Xz),
            Some(6) => Some(Codec::Zstd),
            _ => None,
        };
        Ok(Self { base, sb, block_size, codec, cache: HashMap::new(), fragments: None })
    }

    fn u64_at(&self, at: usize) -> u64 {
        le64(&self.sb, at).unwrap_or(0)
    }

    /// The superblock facts.
    pub fn facts(&self) -> Map<String, Value> {
        let sb = &self.sb;
        let mut m = Map::new();
        m.insert("version".into(), json!(format!("{}.{}", le16(sb, 28).unwrap_or(0), le16(sb, 30).unwrap_or(0))));
        if let Some(c) = crate::plugin::volume::squashfs_compression(le16(sb, 20).unwrap_or(0)) {
            m.insert("compression".into(), json!(c));
        }
        m.insert("block_size".into(), json!(self.block_size));
        m.insert("inodes".into(), json!(le32(sb, 4).unwrap_or(0)));
        m.insert("fragments".into(), json!(le32(sb, 16).unwrap_or(0)));
        m.insert("bytes_used".into(), json!(self.u64_at(40)));
        if let Some(t) = unix_time(i64::from(le32(sb, 8).unwrap_or(0))) {
            m.insert("created".into(), json!(t));
        }
        let flags = le16(sb, 24).unwrap_or(0);
        let names: Vec<&str> =
            [(0x10, "no_fragments"), (0x40, "duplicates_removed"), (0x80, "exportable"), (0x200, "no_xattrs")]
                .into_iter()
                .filter(|(bit, _)| flags & bit != 0)
                .map(|(_, n)| n)
                .collect();
        m.insert("flags".into(), json!(names));
        m
    }

    /// Decompress a block (`stored` false) into at most `max` bytes.
    fn unpack(&self, cx: &mut Context<'_>, data: Vec<u8>, stored: bool, max: usize) -> Result<Vec<u8>, ExtractError> {
        if stored {
            return Ok(data);
        }
        let codec = self.codec.ok_or_else(|| ExtractError::Unsupported("squashfs compressor".into()))?;
        Ok(cx.decompress(&data, codec, max)?.data)
    }

    /// The metadata block at absolute position `pos` (from the image
    /// start), and the position of the next one.
    fn meta_block(
        &mut self,
        src: &mut dyn Source,
        cx: &mut Context<'_>,
        pos: u64,
    ) -> Result<(Vec<u8>, u64), ExtractError> {
        if let Some(b) = self.cache.get(&pos) {
            return Ok(b.clone());
        }
        let h = src.read_vec(self.base + pos, 2)?;
        let h = u16::from_le_bytes([h[0], h[1]]);
        let n = usize::from(h & 0x7FFF);
        let raw = src.read_vec(self.base + pos + 2, n)?;
        let data = self.unpack(cx, raw, h & 0x8000 != 0, META_BLOCK)?;
        let next = pos + 2 + n as u64;
        if self.cache.len() < MAX_CACHE {
            self.cache.insert(pos, (data.clone(), next));
        }
        Ok((data, next))
    }

    /// `n` bytes of a metadata table, from block `block` (relative to the
    /// table) and `offset` in it.
    fn meta(
        &mut self,
        src: &mut dyn Source,
        cx: &mut Context<'_>,
        table: u64,
        block: u64,
        offset: usize,
        n: usize,
    ) -> Result<Vec<u8>, ExtractError> {
        let mut out = Vec::with_capacity(n.min(1 << 20));
        let (mut pos, mut off) = (table + block, offset);
        while out.len() < n {
            let (data, next) = self.meta_block(src, cx, pos)?;
            if off >= data.len() {
                return Err(ExtractError::malformed("metadata offset"));
            }
            let take = (n - out.len()).min(data.len() - off);
            out.extend_from_slice(&data[off..off + take]);
            pos = next;
            off = 0;
        }
        Ok(out)
    }

    /// An inode: `(type, mode, mtime, body)`, the body long enough for the
    /// type's fixed fields plus `extra` bytes.
    fn inode(
        &mut self,
        src: &mut dyn Source,
        cx: &mut Context<'_>,
        r: u64,
    ) -> Result<(u16, u16, u32, Vec<u8>), ExtractError> {
        let table = self.u64_at(64);
        let (block, offset) = (r >> 16, (r & 0xFFFF) as usize);
        let head = self.meta(src, cx, table, block, offset, 16)?;
        let ty = le16(&head, 0).unwrap_or(0);
        let fixed = match ty {
            1 | 2 => 16,
            3 | 10 => 8,
            8 => 24,
            9 => 40,
            _ => 0,
        };
        let mut body = self.meta(src, cx, table, block, offset, 16 + fixed)?;
        // Variable parts: block sizes, symlink targets.
        let extra = match ty {
            2 | 9 => {
                let (size, frag) = if ty == 2 {
                    (u64::from(le32(&body, 28).unwrap_or(0)), le32(&body, 20).unwrap_or(0))
                } else {
                    (le64(&body, 24).unwrap_or(0), le32(&body, 44).unwrap_or(0))
                };
                let full = if frag == u32::MAX { size.div_ceil(self.block_size) } else { size / self.block_size };
                usize::try_from(full.min(1 << 20)).unwrap_or(0) * 4
            }
            3 | 10 => le32(&body, 20).unwrap_or(0).min(4096) as usize,
            _ => 0,
        };
        if extra > 0 {
            body = self.meta(src, cx, table, block, offset, 16 + fixed + extra)?;
        }
        Ok((ty, le16(&body, 2).unwrap_or(0), le32(&body, 8).unwrap_or(0), body))
    }

    /// List the whole tree.
    #[allow(clippy::too_many_lines)] // directory headers, entries, inode kinds
    pub fn list(&mut self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<Listed, ExtractError> {
        let mut inv = Inventory::new();
        let mut files = Vec::new();
        let dir_table = self.u64_at(72);
        let root = self.u64_at(32);
        let mut stack = vec![(root, String::new(), 0usize)];
        let mut seen = HashSet::new();
        while let Some((dir_ref, path, depth)) = stack.pop() {
            cx.checkpoint()?;
            if !seen.insert(dir_ref) {
                continue;
            }
            let (ty, _, _, dir) = self.inode(src, cx, dir_ref)?;
            let (block, size, offset) = match ty {
                1 => (
                    u64::from(le32(&dir, 16).unwrap_or(0)),
                    u64::from(le16(&dir, 24).unwrap_or(0)),
                    le16(&dir, 26).unwrap_or(0),
                ),
                8 => (
                    u64::from(le32(&dir, 24).unwrap_or(0)),
                    u64::from(le32(&dir, 20).unwrap_or(0)),
                    le16(&dir, 34).unwrap_or(0),
                ),
                _ => continue,
            };
            if size <= 3 {
                continue;
            }
            let listing =
                self.meta(src, cx, dir_table, block, usize::from(offset), usize::try_from(size - 3).unwrap_or(0))?;
            let mut at = 0;
            while at + 12 <= listing.len() {
                let count = le32(&listing, at).unwrap_or(0) as usize + 1;
                let start = u64::from(le32(&listing, at + 4).unwrap_or(0));
                at += 12;
                for _ in 0..count.min(256) {
                    let (Some(off), Some(name_len)) = (le16(&listing, at), le16(&listing, at + 6)) else { break };
                    let n = usize::from(name_len) + 1;
                    let Some(name) = listing.get(at + 8..at + 8 + n) else { break };
                    let name = String::from_utf8_lossy(name).into_owned();
                    at += 8 + n;
                    if inv.entries >= MAX_ENTRIES as u64 {
                        inv.truncated = true;
                        return Ok(Listed { inventory: inv, files });
                    }
                    let child_ref = start << 16 | u64::from(off);
                    let (cty, mode, mtime, cb) = self.inode(src, cx, child_ref)?;
                    let modified = unix_time(i64::from(mtime));
                    let p = format!("{path}{name}");
                    match cty {
                        1 | 8 => {
                            inv.push(Entry {
                                path: format!("{p}/"),
                                kind: Kind::Dir,
                                size: Some(0),
                                modified,
                                mode: Some(u32::from(mode)),
                                ..Entry::default()
                            });
                            if depth < MAX_DEPTH {
                                stack.push((child_ref, format!("{p}/"), depth + 1));
                            }
                        }
                        2 | 9 => {
                            let f = file_ref(cty, &cb);
                            // A file's tail shares a fragment block: no stored size of its own.
                            let compressed = f
                                .fragment
                                .is_none()
                                .then(|| f.blocks.iter().map(|&s| u64::from(s & 0x00FF_FFFF)).sum::<u64>());
                            let e = Entry {
                                path: p.clone(),
                                kind: Kind::File,
                                size: Some(f.size),
                                compressed,
                                modified,
                                mode: Some(u32::from(mode)),
                                ..Entry::default()
                            };
                            if wanted(&e) {
                                files.push((p, f));
                            }
                            inv.push(e);
                        }
                        3 | 10 => {
                            let n = le32(&cb, 20).unwrap_or(0) as usize;
                            let target = cb.get(24..24 + n).map(|t| String::from_utf8_lossy(t).into_owned());
                            inv.push(Entry {
                                path: p,
                                kind: Kind::Symlink,
                                size: Some(0),
                                link: target,
                                modified,
                                mode: Some(u32::from(mode)),
                                ..Entry::default()
                            });
                        }
                        _ => inv.push(Entry {
                            path: p,
                            kind: Kind::Special,
                            size: Some(0),
                            modified,
                            ..Entry::default()
                        }),
                    }
                }
            }
        }
        Ok(Listed { inventory: inv, files })
    }

    /// Fragment `i`: its position and stored size.
    fn fragment(
        &mut self,
        src: &mut dyn Source,
        cx: &mut Context<'_>,
        i: u32,
    ) -> Result<Option<(u64, u32)>, ExtractError> {
        if self.fragments.is_none() {
            let count = le32(&self.sb, 16).unwrap_or(0).min(1 << 20) as usize;
            let table = self.u64_at(80);
            let pointers = src.read_vec(self.base + table, count.div_ceil(512) * 8)?;
            let mut list = Vec::new();
            for p in pointers.as_chunks::<8>().0 {
                let pos = u64::from_le_bytes(*p);
                let (data, _) = self.meta_block(src, cx, pos)?;
                for e in data.as_chunks::<16>().0 {
                    list.push((le64(e, 0).unwrap_or(0), le32(e, 8).unwrap_or(0)));
                }
            }
            self.fragments = Some(list);
        }
        Ok(self.fragments.as_ref().and_then(|f| f.get(i as usize).copied()))
    }

    /// A file's contents, at most `max` bytes.
    pub fn read(
        &mut self,
        src: &mut dyn Source,
        cx: &mut Context<'_>,
        f: &FileRef,
        max: u64,
    ) -> Result<Vec<u8>, ExtractError> {
        let want = usize::try_from(f.size.min(max)).unwrap_or(0);
        let bs = usize::try_from(self.block_size).unwrap_or(0);
        let mut out = Vec::with_capacity(want.min(1 << 24));
        let mut pos = f.start;
        for &b in &f.blocks {
            if out.len() >= want {
                break;
            }
            cx.checkpoint()?;
            let n = u64::from(b & 0x00FF_FFFF);
            let data = if n == 0 {
                vec![0; bs]
            } else {
                let raw = src.read_vec(self.base + pos, usize::try_from(n).unwrap_or(0))?;
                self.unpack(cx, raw, b & 0x0100_0000 != 0, bs)?
            };
            pos += n;
            out.extend_from_slice(&data[..data.len().min(want - out.len())]);
        }
        if out.len() < want
            && let Some((i, off)) = f.fragment
            && let Some((at, size)) = self.fragment(src, cx, i)?
        {
            let raw = src.read_vec(self.base + at, (size & 0x00FF_FFFF) as usize)?;
            let data = self.unpack(cx, raw, size & 0x0100_0000 != 0, bs)?;
            let from = off as usize;
            let take = (want - out.len()).min(data.len().saturating_sub(from));
            out.extend_from_slice(data.get(from..from + take).unwrap_or(&[]));
        }
        Ok(out)
    }

    /// Hand the listed files on, as far as the limits allow.
    pub fn hand_on(
        &mut self,
        src: &mut dyn Source,
        cx: &mut Context<'_>,
        files: Vec<(String, FileRef)>,
    ) -> Result<(), ExtractError> {
        let limit = cx.parse_limit() as u64;
        for (path, f) in files {
            if cx.child_room() == 0 {
                break;
            }
            let data = match self.read(src, cx, &f, limit) {
                Ok(d) => d,
                Err(ExtractError::Unsupported(e)) => {
                    cx.warn(format!("file data not read: {e}"));
                    break;
                }
                Err(e) => return Err(e),
            };
            let complete = data.len() as u64 == f.size;
            if !child(cx, &path, data, complete)? {
                break;
            }
        }
        Ok(())
    }
}

/// Where a regular file inode's data is.
fn file_ref(ty: u16, b: &[u8]) -> FileRef {
    let (start, size, frag, frag_off, list) = if ty == 2 {
        (
            u64::from(le32(b, 16).unwrap_or(0)),
            u64::from(le32(b, 28).unwrap_or(0)),
            le32(b, 20).unwrap_or(u32::MAX),
            le32(b, 24).unwrap_or(0),
            32,
        )
    } else {
        (
            le64(b, 16).unwrap_or(0),
            le64(b, 24).unwrap_or(0),
            le32(b, 44).unwrap_or(u32::MAX),
            le32(b, 48).unwrap_or(0),
            56,
        )
    };
    let blocks = b
        .get(list..)
        .unwrap_or(&[])
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    FileRef { start, size, fragment: (frag != u32::MAX).then_some((frag, frag_off)), blocks }
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("squashfs");
}
