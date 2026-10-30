//! Finder `.DS_Store` files: the folder's entries named in the records
//! (first 200), record count, record types (icon positions, view
//! settings, Spotlight comments, sizes, dates), the folder's view style and
//! the range of modification dates Finder cached. Comment text is not
//! reported.
//!
//! Specification: Mark Mentovai and Wim Lewis, "`.DS_Store` file format"
//! (buddy allocator, `DSDB` B-tree, record value types).

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde_json::{Map, Value};

use super::unix_time;
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, truncate_chars};

/// Extractor for `.DS_Store` files.
pub struct DsStore;

static META: ExtractorMeta = ExtractorMeta {
    id: "apple.ds_store",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "ds_store",
        name: ".DS_Store",
        family: "apple",
        mimes: &[],
        extensions: &["ds_store"],
        magic: &[Magic::at(0, b"\0\0\0\x01Bud1")],
        parent: None,
    }],
};

/// Entry names listed.
const MAX_NAMES: usize = 200;
/// B-tree nodes visited.
const MAX_NODES: usize = 100_000;
/// Seconds from 1904-01-01 to 1970-01-01.
const MAC_EPOCH: i64 = 2_082_844_800;

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The buddy allocator: block addresses and the table of contents.
struct Buddy<'a> {
    data: &'a [u8],
    blocks: Vec<u32>,
}

impl<'a> Buddy<'a> {
    fn open(data: &'a [u8]) -> Option<(Self, BTreeMap<String, u32>)> {
        let root = usize::try_from(be32(data, 8)?).ok()? + 4;
        let count = usize::try_from(be32(data, root)?).ok()?;
        let mut at = root + 8;
        let blocks: Vec<u32> = (0..count.min(1 << 20)).map_while(|i| be32(data, at + 4 * i)).collect();
        // Addresses are stored in groups of 256.
        at += 4 * count.div_ceil(256).max(1) * 256;
        let n = be32(data, at)?;
        at += 4;
        let mut toc = BTreeMap::new();
        for _ in 0..n.min(1000) {
            let len = usize::from(*data.get(at)?);
            let name = String::from_utf8_lossy(data.get(at + 1..at + 1 + len)?).into_owned();
            toc.insert(name, be32(data, at + 1 + len)?);
            at += 5 + len;
        }
        Some((Self { data, blocks }, toc))
    }

    /// The bytes of block `id` (offset rounded to 32, size a power of two).
    fn block(&self, id: u32) -> Option<&'a [u8]> {
        let addr = *self.blocks.get(usize::try_from(id).ok()?)?;
        let off = usize::try_from(addr & !0x1f).ok()? + 4;
        let size = 1usize.checked_shl(addr & 0x1f)?;
        self.data.get(off..off.checked_add(size)?.min(self.data.len()))
    }
}

/// One record: file name, structure type and the value's type and bytes.
struct Record {
    name: String,
    kind: [u8; 4],
    value: Option<u64>,
}

/// Parse a record at `at`; returns it and the offset after it.
fn record(b: &[u8], at: usize) -> Option<(Record, usize)> {
    let n = usize::try_from(be32(b, at)?).ok()?;
    let units: Vec<u16> =
        b.get(at + 4..at + 4 + 2 * n)?.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
    let mut at = at + 4 + 2 * n;
    let kind: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
    let ty: [u8; 4] = b.get(at + 4..at + 8)?.try_into().ok()?;
    at += 8;
    let mut value = None;
    at += match &ty {
        b"bool" => 1,
        b"long" | b"shor" | b"type" => {
            value = be32(b, at).map(u64::from);
            4
        }
        b"comp" | b"dutc" => {
            value = Some(u64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?));
            8
        }
        b"blob" => 4 + usize::try_from(be32(b, at)?).ok()?,
        b"ustr" => 4 + 2 * usize::try_from(be32(b, at)?).ok()?,
        _ => return None,
    };
    (at <= b.len()).then(|| (Record { name: String::from_utf16_lossy(&units), kind, value }, at))
}

impl Extractor for DsStore {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (data, _) = cx.read_bytes(src)?;
        let (buddy, toc) = Buddy::open(&data).ok_or_else(|| ExtractError::malformed("buddy allocator"))?;
        let master = toc.get("DSDB").and_then(|&id| buddy.block(id)).ok_or_else(|| ExtractError::malformed("DSDB"))?;
        let root = be32(master, 0).ok_or_else(|| ExtractError::malformed("DSDB"))?;
        let declared = be32(master, 8).unwrap_or(0);
        let mut names: BTreeSet<String> = BTreeSet::new();
        let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
        let (mut records, mut lo, mut hi) = (0u64, u64::MAX, 0u64);
        let mut style = None;
        let mut seen = HashSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !seen.insert(id) || seen.len() > MAX_NODES {
                continue;
            }
            let Some(node) = buddy.block(id) else { continue };
            let (Some(p), Some(count)) = (be32(node, 0), be32(node, 4)) else { continue };
            let mut at = 8;
            for _ in 0..count.min(1 << 16) {
                if p != 0 {
                    let Some(child) = be32(node, at) else { break };
                    stack.push(child);
                    at += 4;
                }
                let Some((r, next)) = record(node, at) else { break };
                at = next;
                records += 1;
                *kinds.entry(String::from_utf8_lossy(&r.kind).into_owned()).or_default() += 1;
                if r.name == "." {
                    if &r.kind == b"vstl" {
                        style = r.value;
                    }
                } else if names.len() < 100_000 {
                    names.insert(r.name);
                }
                if matches!(&r.kind, b"modD" | b"moDD")
                    && let Some(v) = r.value
                {
                    lo = lo.min(v);
                    hi = hi.max(v);
                }
            }
            if p != 0 {
                stack.push(p);
            }
        }
        cx.format_set("records", records);
        if u64::from(declared) != records {
            cx.format_set("declared_records", declared);
        }
        cx.format_set("entries", names.len());
        let listed: Vec<String> = names.iter().take(MAX_NAMES).map(|n| truncate_chars(n, 255)).collect();
        if !listed.is_empty() {
            cx.format_set("names", listed);
        }
        if !kinds.is_empty() {
            let m: Map<String, Value> = kinds.into_iter().map(|(k, n)| (k, n.into())).collect();
            cx.format_set("record_types", Value::Object(m));
        }
        if let Some(s) = style.and_then(|v| u32::try_from(v).ok()) {
            let s = match &s.to_be_bytes() {
                b"icnv" => "icon".to_string(),
                b"clmv" => "column".to_string(),
                b"Nlsv" => "list".to_string(),
                b"glyv" => "gallery".to_string(),
                b"Flwv" => "cover_flow".to_string(),
                other => String::from_utf8_lossy(other).into_owned(),
            };
            cx.format_set("view_style", s);
        }
        // `dutc`: 1/65536 seconds since 1904.
        let time = |v: u64| i64::try_from(v >> 16).ok().and_then(|s| unix_time(s - MAC_EPOCH));
        if let (Some(a), Some(b)) = (time(lo), time(hi)) {
            cx.format_set("first_modified", a);
            cx.format_set("last_modified", b);
        }
        Ok(())
    }
}

crate::register_extractor!(DsStore);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records() {
        let mut r = Vec::new();
        r.extend(5u32.to_be_bytes());
        r.extend("a.txt".encode_utf16().flat_map(u16::to_be_bytes));
        r.extend(b"Ilocblob");
        r.extend(16u32.to_be_bytes());
        r.extend([0u8; 16]);
        let (rec, end) = record(&r, 0).unwrap();
        assert_eq!((rec.name.as_str(), &rec.kind, end), ("a.txt", b"Iloc", r.len()));
        assert!(record(&r[..r.len() - 1], 0).is_none());
    }

    crate::fixture_tests!("ds_store");
}
