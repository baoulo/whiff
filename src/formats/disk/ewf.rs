//! Forensic evidence files: Expert Witness / EnCase (`.E01`, EWF version
//! 1, including `.L01` logical evidence) and AFF (Advanced Forensic
//! Format). The case metadata the examiner
//! entered (case and evidence numbers, description, examiner, notes),
//! the acquisition (software and OS, acquisition and system dates, the
//! source device's model, serial number and label), the media (type,
//! sector size and count, chunk size, compression) and the acquisition
//! hashes (MD5, SHA-1) are reported. The evidence is read through its
//! chunk tables (E01, from the chunks in this segment) or pages (AFF), so
//! the partition table and file systems on the acquired disk are described
//! too.
//!
//! Specifications: libewf "Expert Witness Compression Format (EWF)"
//! (Joachim Metz); AFF: Garfinkel et al.,
//! "Advanced Forensic Format: an open, extensible format for disk
//! imaging" (2006) and afflib `aff_seg.cpp`.

use std::fmt::Write as _;

use serde_json::{Map, Value, json};

use super::{Block, BlockMap, Virtual, report_contents};
use crate::plugin::volume::num::{be32, le16, le32, le64};
use crate::plugin::volume::{guid_le, text_field, unix_time};
use crate::plugin::{
    Codec, Compression, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source,
    SourceError,
};

/// Extractor for forensic evidence files.
pub struct Ewf;

static META: ExtractorMeta = ExtractorMeta {
    id: "disk.ewf",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "e01",
            name: "Expert Witness / EnCase evidence file",
            family: "disk",
            mimes: &["application/x-ewf"],
            extensions: &["e01", "l01", "s01"],
            magic: &[Magic::prefix(b"EVF\x09\x0d\x0a\xff\x00"), Magic::prefix(b"LVF\x09\x0d\x0a\xff\x00")],
            parent: None,
        },
        FormatSpec {
            id: "aff",
            name: "Advanced Forensic Format",
            family: "disk",
            mimes: &["application/x-aff"],
            extensions: &["aff"],
            magic: &[Magic::prefix(b"AFF10\r\n\0")],
            parent: None,
        },
    ],
};

/// Sections walked at most.
const MAX_SECTIONS: usize = 4096;
/// Chunk-table entries kept at most (128 GiB of 32 KiB chunks).
const MAX_CHUNKS: usize = 1 << 22;
/// Header text inflated at most.
const MAX_HEADER: usize = 1 << 20;

impl Extractor for Ewf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "aff" => aff(src, cx),
            _ => e01(src, cx),
        }
    }
}

crate::register_extractor!(Ewf);

/// Case metadata keys of the header text, as report keys.
fn header_key(k: &str) -> Option<&'static str> {
    Some(match k {
        "c" => "case_number",
        "n" => "evidence_number",
        "a" => "description",
        "e" => "examiner",
        "t" => "notes",
        "md" => "device_model",
        "sn" => "device_serial",
        "l" => "device_label",
        "av" => "acquisition_software_version",
        "ov" => "acquisition_os",
        "m" => "acquired",
        "u" => "system_date",
        "pid" => "process_id",
        "dc" => "unknown_dc",
        "ext" => "extents",
        _ => return None,
    })
}

/// A header date: Unix seconds (EnCase 5 and later) or `Y M D h m s`.
fn header_date(value: &str) -> Option<String> {
    if let Ok(secs) = value.parse::<i64>() {
        return unix_time(secs);
    }
    let parts: Vec<u32> = value.split_whitespace().filter_map(|p| p.parse().ok()).collect();
    match parts[..] {
        [year, month, day, hour, minute, second] if (1..=12).contains(&month) && (1..=31).contains(&day) => {
            Some(format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"))
        }
        _ => None,
    }
}

/// The `main` category of a header: tab-separated keys, then values.
fn header_text(text: &str, out: &mut Map<String, Value>) {
    let lines: Vec<&str> = text.lines().map(|l| l.trim_end_matches('\r')).collect();
    let Some(main) = lines.iter().position(|l| *l == "main") else { return };
    let (Some(keys), Some(values)) = (lines.get(main + 1), lines.get(main + 2)) else { return };
    for (k, v) in keys.split('\t').zip(values.split('\t')) {
        let (Some(key), v) = (header_key(k), v.trim()) else { continue };
        if v.is_empty() || key == "unknown_dc" || key == "extents" || key == "process_id" {
            continue;
        }
        let v = if matches!(key, "acquired" | "system_date") {
            header_date(v).unwrap_or_else(|| v.to_string())
        } else {
            v.to_string()
        };
        out.entry(key).or_insert_with(|| json!(v));
    }
}

/// Write the case facts and dates.
fn case_facts(m: Map<String, Value>, cx: &mut Context<'_>) {
    if let Some(Value::String(d)) = m.get("description") {
        cx.content().title(d.clone());
    }
    if let Some(Value::String(e)) = m.get("examiner") {
        cx.content().author(e.clone());
    }
    if let Some(Value::String(t)) = m.get("acquired")
        && t.len() >= 19
    {
        cx.temporal().content_date(DateField::Created, t.clone(), t.ends_with('Z'));
    }
    for (k, v) in m {
        cx.format_set(&k, v);
    }
}

// ---------------------------------------------------------------- E01

struct ChunkMap {
    chunk: u64,
    /// `(offset, stored length, compressed)` per chunk.
    chunks: Vec<(u64, u64, bool)>,
    /// Which chunks are stored (AFF pages may be missing); `None`: all.
    present: Option<Vec<bool>>,
}

impl BlockMap for ChunkMap {
    fn block_size(&self) -> u64 {
        self.chunk
    }

    fn locate(&mut self, _: &mut dyn Source, n: u64) -> Result<Block, SourceError> {
        let i = usize::try_from(n).unwrap_or(usize::MAX);
        if self.present.as_ref().is_some_and(|p| !p.get(i).copied().unwrap_or(false)) {
            return Ok(Block::Zero);
        }
        Ok(match self.chunks.get(i) {
            Some(&(at, len, true)) => {
                Block::Compressed { at, len: usize::try_from(len).unwrap_or(0), codec: Codec::Zlib }
            }
            Some(&(at, _, false)) => Block::At(at),
            None => Block::Zero,
        })
    }
}

fn media_type(t: u8) -> &'static str {
    match t {
        0x00 => "removable",
        0x01 => "fixed",
        0x03 => "optical",
        0x0E => "logical",
        0x10 => "memory",
        _ => "other",
    }
}

#[allow(clippy::too_many_lines)] // section walk
fn e01(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let head = src.read_vec(0, 13)?;
    let logical = head.starts_with(b"LVF");
    cx.format_set("segment", le16(&head, 9).unwrap_or(0));
    if logical {
        cx.format_set("evidence", "logical");
    }
    let len = src.len();
    let mut case = Map::new();
    let (mut chunk, mut sectors, mut sector_size) = (0u64, 0u64, 0u64);
    let mut chunks: Vec<(u64, u64, bool)> = Vec::new();
    let mut sections = Vec::new();
    let mut at = 13u64;
    for _ in 0..MAX_SECTIONS {
        cx.checkpoint()?;
        let Ok(d) = src.read_vec(at, 76) else { break };
        let ty = text_field(&d[..16]).unwrap_or_default();
        let next = le64(&d, 16).unwrap_or(0);
        let size = le64(&d, 24).unwrap_or(0);
        let body = at + 76;
        let body_len = size.saturating_sub(76).min(len.saturating_sub(body));
        if sections.len() < 64 && !sections.contains(&ty) {
            sections.push(ty.clone());
        }
        match ty.as_str() {
            "header" | "header2" if body_len > 0 => {
                let data = src.read_vec(body, usize::try_from(body_len.min(1 << 20)).unwrap_or(0))?;
                if let Ok(text) = cx.inflate(&data, Compression::Zlib, MAX_HEADER) {
                    let text =
                        if ty == "header2" { utf16_text(&text) } else { String::from_utf8_lossy(&text).into_owned() };
                    header_text(&text, &mut case);
                }
            }
            "volume" | "disk" | "data" if body_len >= 64 => {
                let v = src.read_vec(body, 94.min(usize::try_from(body_len).unwrap_or(0)))?;
                cx.format_set("media_type", media_type(v[0]));
                sector_size = u64::from(le32(&v, 12).unwrap_or(0));
                chunk = u64::from(le32(&v, 8).unwrap_or(0)) * sector_size;
                sectors = le64(&v, 16).unwrap_or(0);
                cx.format_set("chunk_size", chunk);
                cx.format_set("bytes_per_sector", sector_size);
                cx.format_set("sectors", sectors);
                cx.format_set("media_bytes", sectors.saturating_mul(sector_size));
                if let Some(&flags) = v.get(36) {
                    cx.format_set("physical", flags & 0x02 != 0);
                    for (bit, name) in [(0x04, "fastbloc"), (0x08, "tableau")] {
                        if flags & bit != 0 {
                            cx.format_set("write_blocker", name);
                        }
                    }
                }
                if let Some(&level) = v.get(52) {
                    cx.format_set(
                        "compression",
                        match level {
                            0 => "none",
                            1 => "fast",
                            2 => "best",
                            _ => "other",
                        },
                    );
                }
                if let Some(g) = v.get(64..80).and_then(guid_le) {
                    cx.format_set("set_id", g);
                }
                cx.physical().uncompressed_bytes(sectors.saturating_mul(sector_size));
            }
            "table" if body_len >= 24 => {
                let t = src.read_vec(body, 24)?;
                let n = u64::from(le32(&t, 0).unwrap_or(0)).min((body_len - 24) / 4);
                let base = le64(&t, 8).unwrap_or(0);
                let n = usize::try_from(n).unwrap_or(0).min(MAX_CHUNKS - chunks.len().min(MAX_CHUNKS));
                let entries = src.read_vec(body + 24, n * 4)?;
                let first = chunks.len();
                for e in entries.as_chunks::<4>().0 {
                    let v = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
                    chunks.push((base + u64::from(v & 0x7FFF_FFFF), 0, v & 0x8000_0000 != 0));
                }
                // A chunk ends where the next starts; the last at this table.
                for i in first..chunks.len() {
                    let end = chunks.get(i + 1).filter(|_| i + 1 < chunks.len()).map_or(at, |c| c.0);
                    chunks[i].1 = end.saturating_sub(chunks[i].0);
                }
            }
            "hash" if body_len >= 16 => {
                let h = src.read_vec(body, 16)?;
                if h.iter().any(|&b| b != 0) {
                    case.insert("md5".into(), json!(hex(&h)));
                }
            }
            "digest" if body_len >= 36 => {
                let h = src.read_vec(body, 36)?;
                if h[..16].iter().any(|&b| b != 0) {
                    case.insert("md5".into(), json!(hex(&h[..16])));
                }
                if h[16..].iter().any(|&b| b != 0) {
                    case.insert("sha1".into(), json!(hex(&h[16..])));
                }
            }
            "error2" if body_len >= 4 => {
                let e = src.read_vec(body, 4)?;
                cx.format_set("read_errors", le32(&e, 0).unwrap_or(0));
            }
            _ => {}
        }
        if ty == "done" || ty == "next" || next <= at || next >= len {
            if ty == "next" {
                cx.format_set("more_segments", true);
            }
            break;
        }
        at = next;
    }
    cx.format_set("sections", sections);
    case_facts(case, cx);
    let size = sectors.saturating_mul(sector_size);
    if chunk.is_power_of_two() && chunk >= 512 && size > 0 && !chunks.is_empty() && !logical {
        match Virtual::new(src, ChunkMap { chunk, chunks, present: None }, size) {
            Ok(mut v) => report_contents(&mut v, cx),
            Err(e) => cx.warn(format!("evidence unreadable: {e}")),
        }
    }
    Ok(())
}

/// UTF-16LE text, byte-order mark dropped.
fn utf16_text(b: &[u8]) -> String {
    let b = b.strip_prefix(&[0xFF, 0xFE]).unwrap_or(b);
    let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

// ---------------------------------------------------------------- AFF

/// AFF segment names reported, as report keys.
fn aff_key(name: &str) -> Option<&'static str> {
    Some(match name {
        "case_num" => "case_number",
        "image_gid" => "image_id",
        "acquisition_commandline" => "acquisition_command",
        "acquisition_date" => "acquired",
        "acquisition_device" => "acquisition_device",
        "acquisition_seconds" => "acquisition_seconds",
        "acquisition_notes" => "notes",
        "examiner" => "examiner",
        "device_model" => "device_model",
        "device_sn" => "device_serial",
        "device_firmware" => "device_firmware",
        "device_sectors" | "devicesectors" => "sectors",
        "pagesize" | "segsize" => "page_size",
        "sectorsize" => "bytes_per_sector",
        "imagesize" => "media_bytes",
        "badsectors" => "bad_sectors",
        "md5" => "md5",
        "sha1" => "sha1",
        "sha256" => "sha256",
        "creator" => "creator",
        _ => return None,
    })
}

fn aff(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = src.len();
    let mut case = Map::new();
    let mut pages: Vec<(u64, u64, u64, bool)> = Vec::new();
    let mut page_size = 0u64;
    let mut at = 8u64;
    for _ in 0..MAX_SECTIONS * 16 {
        cx.checkpoint()?;
        let Ok(h) = src.read_vec(at, 16) else { break };
        if &h[..4] != b"AFF\0" {
            break;
        }
        let (name_len, data_len, arg) = (be32(&h, 4).unwrap_or(0), be32(&h, 8).unwrap_or(0), be32(&h, 12).unwrap_or(0));
        if name_len > 1024 {
            break;
        }
        let name = String::from_utf8_lossy(&src.read_vec(at + 16, name_len as usize)?).into_owned();
        let data_at = at + 16 + u64::from(name_len);
        let page = name.strip_prefix("page").or_else(|| name.strip_prefix("seg")).and_then(|n| n.parse::<u64>().ok());
        if let Some(n) = page {
            if pages.len() < MAX_CHUNKS {
                pages.push((n, data_at, u64::from(data_len), arg & 1 != 0));
            }
        } else if let Some(key) = aff_key(&name) {
            if key == "page_size" {
                page_size = u64::from(arg);
            }
            let v = if data_len == 0 {
                json!(arg)
            } else if data_len == 8 && matches!(key, "media_bytes" | "sectors") {
                let d = src.read_vec(data_at, 8)?;
                json!(u64::from(be32(&d, 4).unwrap_or(0)) << 32 | u64::from(be32(&d, 0).unwrap_or(0)))
            } else {
                let d = src.read_vec(data_at, data_len.min(4096) as usize)?;
                if matches!(key, "md5" | "sha1" | "sha256") {
                    json!(hex(&d))
                } else {
                    json!(text_field(&d).unwrap_or_default())
                }
            };
            case.entry(key).or_insert(v);
        }
        at = data_at + u64::from(data_len) + 8;
        if at >= len {
            break;
        }
    }
    cx.format_set("pages", pages.len());
    let size = case.get("media_bytes").and_then(Value::as_u64).unwrap_or(0);
    cx.physical().uncompressed_bytes(size);
    case_facts(case, cx);
    // Pages are numbered; an absent page is unwritten (zeros).
    if page_size.is_power_of_two() && page_size >= 512 && size > 0 && !pages.is_empty() {
        let mut chunks = vec![(0, 0, false); usize::try_from(size.div_ceil(page_size)).unwrap_or(0).min(MAX_CHUNKS)];
        let mut present = vec![false; chunks.len()];
        for (n, at, len, compressed) in pages {
            if let Some(c) = chunks.get_mut(usize::try_from(n).unwrap_or(usize::MAX)) {
                *c = (at, len, compressed);
                present[usize::try_from(n).unwrap_or(0)] = true;
            }
        }
        let map = ChunkMap { chunk: page_size, chunks, present: Some(present) };
        match Virtual::new(src, map, size) {
            Ok(mut v) => report_contents(&mut v, cx),
            Err(e) => cx.warn(format!("evidence unreadable: {e}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_text_main_category() {
        let text = "1\nmain\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\tr\nHB-7\t1\tTide gauge disk\tR. Keel\tsurvey\t6.1\tLinux\t1756728000\t2025 9 1 12 0 0\t0\tb\n\n";
        let mut m = Map::new();
        header_text(text, &mut m);
        assert_eq!(m["case_number"], "HB-7");
        assert_eq!(m["acquired"], "2025-09-01T12:00:00Z");
        assert_eq!(m["system_date"], "2025-09-01T12:00:00");
        assert_eq!(m["examiner"], "R. Keel");
        assert!(!m.contains_key("p"));
    }

    crate::fixture_tests!("e01", "aff");
}
