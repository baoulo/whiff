//! tar archives: v7, ustar, pax (extended and global headers: path, link,
//! size, times, comment, extended attributes, sparse files) and GNU (long
//! names and links, base-256 numbers, sparse files, volume labels). Header
//! checksums are verified. Entries are stored as they are, so every file
//! is handed on (within the limits).
//!
//! Specifications: POSIX.1-2017 `pax` (ustar and pax interchange formats);
//! the GNU tar manual, "Basic Tar Format" and "GNU Extensions".

use std::collections::BTreeSet;

use super::{Entry, Inventory, Kind, child, unix_time, wanted};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, latin1_or_utf8,
};

/// Extractor for tar archives.
pub struct Tar;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.tar",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "tar",
        name: "tar archive",
        family: "archive",
        mimes: &["application/x-tar"],
        extensions: &["tar"],
        // v7 tar has no magic: the sniffer checks the header checksum.
        magic: &[],
        parent: None,
    }],
};

const BLOCK: u64 = 512;
/// Headers read at most.
const MAX_HEADERS: u64 = 1 << 20;
/// Largest pax or GNU long-name record read.
const MAX_META: u64 = 1 << 20;

/// A tar number: octal ASCII (space or NUL terminated) or GNU base-256.
fn number(field: &[u8]) -> Option<u64> {
    if let Some((&first, rest)) = field.split_first()
        && first & 0x80 != 0
    {
        if first & 0x40 != 0 {
            return None; // negative
        }
        let v =
            rest.iter().fold(u64::from(first & 0x3f), |a, &b| a.checked_shl(8).map_or(u64::MAX, |a| a | u64::from(b)));
        return Some(v);
    }
    let s = std::str::from_utf8(field).ok()?;
    let s = s.trim_matches(|c: char| c == ' ' || c == '\0');
    if s.is_empty() { Some(0) } else { u64::from_str_radix(s, 8).ok() }
}

fn text(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    latin1_or_utf8(&field[..end])
}

/// Whether `h` is a tar header with a valid checksum.
fn valid_header(h: &[u8]) -> bool {
    if h.len() < 512 || h[..512].iter().all(|&b| b == 0) {
        return false;
    }
    let Some(stored) = number(&h[148..156]) else { return false };
    let unsigned: u64 =
        h[..512].iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 32 } else { u64::from(b) }).sum();
    let signed: i64 = h[..512]
        .iter()
        .enumerate()
        .map(|(i, &b)| if (148..156).contains(&i) { 32 } else { i64::from(i8::from_le_bytes([b])) })
        .sum();
    stored == unsigned || i64::try_from(stored).is_ok_and(|s| s == signed)
}

/// pax records: `"<len> <key>=<value>\n"`.
fn pax_records(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let Some(sp) = data[at..].iter().position(|&b| b == b' ') else { break };
        let Some(len) = std::str::from_utf8(&data[at..at + sp]).ok().and_then(|s| s.parse::<usize>().ok()) else {
            break;
        };
        if len <= sp + 1 || at + len > data.len() {
            break;
        }
        let record = &data[at + sp + 1..at + len - 1];
        if let Some(eq) = record.iter().position(|&b| b == b'=') {
            out.push((String::from_utf8_lossy(&record[..eq]).into_owned(), record[eq + 1..].to_vec()));
        }
        at += len;
    }
    out
}

impl Extractor for Tar {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // ustar / GNU magic, or (v7) a valid checksum and a plausible name.
        if !valid_header(probe.head) {
            return None;
        }
        if probe.head.get(257..262) == Some(b"ustar") {
            return Some(Sniff { format: "tar", confidence: 0.85 });
        }
        let name = &probe.head[..100];
        let printable = name.iter().take_while(|&&b| b != 0).all(|&b| b >= 0x20);
        let confidence = if probe.extension == Some("tar") { 0.9 } else { 0.6 };
        (printable && name[0] != 0).then_some(Sniff { format: "tar", confidence })
    }

    #[allow(clippy::too_many_lines)] // one pass over the header kinds
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let mut inv = Inventory::new();
        let mut at = 0u64;
        let (mut pax, mut gnu, mut ustar) = (false, false, false);
        let mut long_name: Option<String> = None;
        let mut long_link: Option<String> = None;
        let mut local: Vec<(String, Vec<u8>)> = Vec::new();
        let mut global: Vec<(String, Vec<u8>)> = Vec::new();
        let mut owners: BTreeSet<String> = BTreeSet::new();
        let (mut xattrs, mut sparse) = (0u64, 0u64);
        let mut pending: Vec<(String, u64, u64)> = Vec::new(); // children: name, offset, size
        let mut headers = 0u64;
        let mut ended = false;
        while at + BLOCK <= len {
            headers += 1;
            if headers > MAX_HEADERS {
                inv.truncated = true;
                break;
            }
            if headers.is_multiple_of(1024) {
                cx.checkpoint()?;
            }
            let h = src.read_vec(at, 512)?;
            if h.iter().all(|&b| b == 0) {
                ended = true;
                break;
            }
            if !valid_header(&h) {
                cx.warn(format!("bad header checksum at offset {at}"));
                inv.truncated = true;
                break;
            }
            let magic = &h[257..265];
            ustar |= magic.starts_with(b"ustar");
            gnu |= magic == b"ustar  \0";
            let flag = h[156];
            let mut size = number(&h[124..136]).unwrap_or(0);
            let override_size = local
                .iter()
                .rev()
                .find(|(k, _)| k == "size")
                .and_then(|(_, v)| std::str::from_utf8(v).ok()?.parse().ok());
            if let Some(s) = override_size.filter(|_| !matches!(flag, b'x' | b'g')) {
                size = s;
            }
            // Old GNU sparse headers continue in extension blocks while byte
            // 482 (then 504 of each block) is set; the data follows them.
            let mut ext_blocks = 0u64;
            if flag == b'S' {
                let mut extended = h[482] != 0;
                while extended && ext_blocks < 1 << 16 && at + BLOCK * (ext_blocks + 2) <= len {
                    ext_blocks += 1;
                    extended = src.read_vec(at + BLOCK * ext_blocks, 512)?[504] != 0;
                }
            }
            let data_at = at + BLOCK * (1 + ext_blocks);
            let next = data_at.saturating_add(size.div_ceil(BLOCK) * BLOCK);
            match flag {
                b'x' | b'g' | b'L' | b'K' => {
                    let body =
                        src.read_vec(data_at, usize::try_from(size.min(MAX_META).min(len - data_at)).unwrap_or(0))?;
                    match flag {
                        b'x' => {
                            pax = true;
                            local = pax_records(&body);
                        }
                        b'g' => {
                            pax = true;
                            global.extend(pax_records(&body));
                        }
                        b'L' => {
                            gnu = true;
                            long_name = Some(text(&body));
                        }
                        _ => {
                            gnu = true;
                            long_link = Some(text(&body));
                        }
                    }
                    at = next;
                    continue;
                }
                b'V' => {
                    gnu = true;
                    cx.format_set("volume_label", text(&h[..100]));
                    at = next;
                    continue;
                }
                _ => {}
            }
            // A pax value ends at a NUL; an empty one removes the override.
            let get = |key: &str| {
                local.iter().rev().chain(global.iter().rev()).find(|(k, _)| k == key).and_then(|(_, v)| {
                    let v = v.split(|&b| b == 0).next().unwrap_or(&[]);
                    (!v.is_empty()).then(|| String::from_utf8_lossy(v).into_owned())
                })
            };
            let mut path = text(&h[..100]);
            if magic == b"ustar\x0000" || (magic.starts_with(b"ustar\0") && h[345] != 0) {
                let prefix = text(&h[345..500]);
                if !prefix.is_empty() {
                    path = format!("{prefix}/{path}");
                }
            }
            // pax sparse files (formats 0.1 and 1.0) keep the real name aside.
            let path = get("GNU.sparse.name").or_else(|| get("path")).or(long_name.take()).unwrap_or(path);
            let link =
                get("linkpath").or(long_link.take()).or_else(|| Some(text(&h[157..257])).filter(|l| !l.is_empty()));
            let mode = number(&h[100..108]).map(|m| (m & 0o7777) as u32);
            let mtime = get("mtime")
                .and_then(|t| t.split('.').next()?.parse::<i64>().ok())
                .or_else(|| number(&h[136..148]).and_then(|t| i64::try_from(t).ok()));
            if let Some(owner) = get("uname").or_else(|| Some(text(&h[265..297])).filter(|o| !o.is_empty()))
                && owners.len() < 64
            {
                owners.insert(owner);
            }
            xattrs += local
                .iter()
                .filter(|(k, _)| k.starts_with("SCHILY.xattr.") || k.starts_with("LIBARCHIVE.xattr."))
                .count() as u64;
            let is_sparse = flag == b'S' || local.iter().any(|(k, _)| k.starts_with("GNU.sparse."));
            sparse += u64::from(is_sparse);
            let kind = match flag {
                b'0' | b'\0' | b'7' | b'S' => {
                    if path.ends_with('/') {
                        Kind::Dir
                    } else {
                        Kind::File
                    }
                }
                b'1' => Kind::Hardlink,
                b'2' => Kind::Symlink,
                b'5' | b'D' => Kind::Dir,
                b'3' | b'4' | b'6' => Kind::Special,
                _ => Kind::File,
            };
            // Old GNU sparse headers keep the real size at 483.
            let gnu_real = if flag == b'S' { number(&h[483..495]) } else { None };
            let real_size = get("GNU.sparse.realsize")
                .or_else(|| get("GNU.sparse.size"))
                .and_then(|s| s.parse().ok())
                .or(gnu_real)
                .unwrap_or(size);
            let e = Entry {
                path: path.clone(),
                kind,
                size: Some(if kind == Kind::File { real_size } else { 0 }),
                compressed: Some(if kind == Kind::File { size } else { 0 }),
                modified: mtime.and_then(unix_time),
                mode,
                link: link.filter(|_| matches!(kind, Kind::Symlink | Kind::Hardlink)),
                encrypted: false,
                method: None,
            };
            if wanted(&e) && !is_sparse && pending.len() < cx.child_room() {
                pending.push((path, data_at, size));
            }
            inv.push(e);
            local.clear();
            at = next;
        }
        cx.format_set(
            "variant",
            if pax {
                "pax"
            } else if gnu {
                "gnu"
            } else if ustar {
                "ustar"
            } else {
                "v7"
            },
        );
        if let Some(c) =
            global.iter().find(|(k, _)| k == "comment").map(|(_, v)| String::from_utf8_lossy(v).into_owned())
        {
            cx.format_set("comment", c.clone());
            cx.content().description(c);
        }
        if !owners.is_empty() {
            if cx.privacy_strict() {
                cx.format_set("owners", owners.len());
            } else {
                cx.format_set("owners", owners.into_iter().collect::<Vec<_>>());
            }
        }
        if xattrs > 0 {
            cx.format_set("extended_attributes", xattrs);
        }
        if sparse > 0 {
            cx.format_set("sparse_files", sparse);
        }
        if !ended && !inv.truncated && at < len {
            inv.truncated = true;
        }
        if !ended && at >= len && inv.entries > 0 {
            cx.warn("no end-of-archive marker (the archive may be cut short)");
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

crate::register_extractor!(Tar);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_and_records() {
        assert_eq!(number(b"0000644\0"), Some(0o644));
        assert_eq!(number(b"   17 \0"), Some(15));
        assert_eq!(number(b"\0\0\0\0"), Some(0));
        assert_eq!(number(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]), Some(256));
        assert_eq!(number(b"9"), None);
        let recs = pax_records(b"30 path=harbour/long-name.txt\n20 mtime=1700000000\n");
        assert_eq!(recs[0], ("path".into(), b"harbour/long-name.txt".to_vec()));
        assert_eq!(recs[1].0, "mtime");
        assert_eq!(pax_records(b"99 path=x\n"), Vec::new());
    }

    crate::fixture_tests!("tar");
}
