//! ZIP archives: the central directory (with Zip64 and self-extractor
//! prefixes), entries read on demand (stored or deflated, budgeted), and a
//! cheap name listing for sniffers.
//!
//! Specification: PKWARE APPNOTE.TXT 6.3.10.

use crate::io::{ByteReader, Source};
use crate::plugin::{Compression, Context, ExtractError, Probe};

const EOCD: &[u8; 4] = b"PK\x05\x06";
const EOCD64_LOCATOR: &[u8; 4] = b"PK\x06\x07";
const EOCD64: &[u8; 4] = b"PK\x06\x06";
const CENTRAL: &[u8; 4] = b"PK\x01\x02";
const LOCAL: &[u8; 4] = b"PK\x03\x04";
/// Largest central directory loaded (about 500 000 entries).
const MAX_CENTRAL_BYTES: u64 = 64 << 20;

/// One entry of the central directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    /// Entry name, `/`-separated (directories end with `/`).
    pub name: String,
    /// Compression method (0 stored, 8 deflate, 12 bzip2, 14 LZMA, 93 zstd, 99 AES).
    pub method: u16,
    /// General-purpose flags.
    pub flags: u16,
    /// Compressed size.
    pub compressed_size: u64,
    /// Uncompressed size.
    pub size: u64,
    /// CRC-32 of the uncompressed data.
    pub crc32: u32,
    /// Offset of the local header.
    pub local_offset: u64,
    /// Modification time from the DOS fields, as a civil `YYYY-MM-DDTHH:MM:SS`.
    pub modified: Option<String>,
    /// Unix mode bits, when the entry was made on Unix.
    pub unix_mode: Option<u32>,
}

impl ZipEntry {
    /// Whether the entry is a directory.
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }

    /// Whether the entry is encrypted (traditional PKWARE or AES).
    pub fn is_encrypted(&self) -> bool {
        self.flags & 1 != 0 || self.method == 99
    }

    /// Whether the entry is a symbolic link (Unix mode).
    pub fn is_symlink(&self) -> bool {
        self.unix_mode.is_some_and(|m| m & 0o170_000 == 0o120_000)
    }
}

/// A ZIP archive's central directory.
#[derive(Debug, Clone, Default)]
pub struct Zip {
    /// Entries in central-directory order.
    pub entries: Vec<ZipEntry>,
    /// Archive comment.
    pub comment: String,
    /// Whether the archive uses Zip64 records.
    pub zip64: bool,
    /// Bytes before the first entry (self-extracting stub, polyglot prefix).
    pub prefix_bytes: u64,
    /// Whether entries beyond the listing limit were dropped.
    pub truncated: bool,
    /// Entries the end record declares.
    pub declared_entries: u64,
}

fn dos_time(date: u16, time: u16) -> Option<String> {
    let (y, mo, d) = (1980 + (date >> 9), (date >> 5) & 15, date & 31);
    let (h, mi, s) = (time >> 11, (time >> 5) & 63, (time & 31) * 2);
    ((1..=12).contains(&mo) && (1..=31).contains(&d) && h < 24 && mi < 60 && s < 60)
        .then(|| format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}"))
}

fn entry_name(raw: &[u8], flags: u16) -> String {
    if flags & 0x800 != 0 { String::from_utf8_lossy(raw).into_owned() } else { crate::meta::latin1_or_utf8(raw) }
}

/// The end-of-central-directory record in `window` (the file's last bytes):
/// its offset in the window.
fn find_eocd(window: &[u8]) -> Option<usize> {
    if window.len() < 22 {
        return None;
    }
    (0..=window.len() - 22).rev().find(|&i| {
        window[i..].starts_with(EOCD) && {
            // The comment length must reach exactly to the end (or close to it:
            // some writers pad).
            let n = usize::from(u16::from_le_bytes([window[i + 20], window[i + 21]]));
            i + 22 + n <= window.len()
        }
    })
}

struct End {
    entries: u64,
    cd_size: u64,
    cd_offset: u64,
    comment: String,
    zip64: bool,
    /// File offset of the end record.
    at: u64,
}

#[allow(clippy::many_single_char_names)] // record field names
fn parse_end(window: &[u8], window_start: u64, i: usize) -> Result<End, ExtractError> {
    let mut r = ByteReader::new(&window[i..]).skip(10)?;
    let entries = u64::from(r.le_u16()?);
    let cd_size = u64::from(r.le_u32()?);
    let cd_offset = u64::from(r.le_u32()?);
    let n = usize::from(r.le_u16()?);
    let comment = crate::meta::latin1_or_utf8(r.bytes(n.min(r.remaining()))?);
    let mut end = End { entries, cd_size, cd_offset, comment, zip64: false, at: window_start + i as u64 };
    // Zip64: a locator right before the end record points at the Zip64 record.
    if i >= 20 && window[i - 20..].starts_with(EOCD64_LOCATOR) {
        let mut l = ByteReader::new(&window[i - 20..i]).skip(8)?;
        let rec = l.le_u64()?;
        if let Some(off) = rec.checked_sub(window_start).and_then(|o| usize::try_from(o).ok())
            && window.get(off..).is_some_and(|w| w.starts_with(EOCD64))
        {
            let mut z = ByteReader::new(&window[off..]).skip(32)?;
            end.entries = z.le_u64()?;
            end.cd_size = z.le_u64()?;
            end.cd_offset = z.le_u64()?;
            end.zip64 = true;
        }
    }
    Ok(end)
}

/// Zip64 extended information: replaces the 32-bit fields that are all ones.
fn zip64_extra(extra: &[u8], size: &mut u64, csize: &mut u64, offset: &mut u64) {
    let mut r = ByteReader::new(extra);
    while let (Ok(id), Ok(len)) = (r.le_u16(), r.le_u16()) {
        let Ok(body) = r.bytes(usize::from(len)) else { return };
        if id != 1 {
            continue;
        }
        let mut b = ByteReader::new(body);
        for field in [size, csize, offset] {
            if *field == u64::from(u32::MAX) {
                match b.le_u64() {
                    Ok(v) => *field = v,
                    Err(_) => return,
                }
            }
        }
        return;
    }
}

#[allow(clippy::many_single_char_names, clippy::similar_names)] // record field names (n, e, c; date, data)
fn parse_central(data: &[u8], max_entries: usize, zip: &mut Zip) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(data);
    while r.peek(4) == Some(CENTRAL) {
        if zip.entries.len() >= max_entries {
            zip.truncated = true;
            break;
        }
        let mut h = ByteReader::new(r.bytes(46)?).skip(4)?;
        let made_by = h.le_u16()?;
        let _needed = h.le_u16()?;
        let flags = h.le_u16()?;
        let method = h.le_u16()?;
        let time = h.le_u16()?;
        let date = h.le_u16()?;
        let crc32 = h.le_u32()?;
        let mut csize = u64::from(h.le_u32()?);
        let mut size = u64::from(h.le_u32()?);
        let (n, e, c) = (usize::from(h.le_u16()?), usize::from(h.le_u16()?), usize::from(h.le_u16()?));
        let _disk = h.le_u16()?;
        let _internal = h.le_u16()?;
        let external = h.le_u32()?;
        let mut offset = u64::from(h.le_u32()?);
        let name = entry_name(r.bytes(n)?, flags);
        zip64_extra(r.bytes(e)?, &mut size, &mut csize, &mut offset);
        r.advance(c)?;
        zip.entries.push(ZipEntry {
            name,
            method,
            flags,
            compressed_size: csize,
            size,
            crc32,
            local_offset: offset,
            modified: dos_time(date, time),
            unix_mode: (made_by >> 8 == 3).then_some(external >> 16).filter(|m| *m != 0),
        });
    }
    Ok(())
}

impl Zip {
    /// Read the central directory, keeping at most `max_entries` entries.
    pub fn open(src: &mut dyn Source, max_entries: usize) -> Result<Self, ExtractError> {
        let len = src.len();
        let window_len = len.min(65_557);
        let window_start = len - window_len;
        let window = src.read_vec(window_start, usize::try_from(window_len).unwrap_or(0))?;
        let i = find_eocd(&window).ok_or_else(|| ExtractError::Unsupported("zip (no end record)".into()))?;
        let end = parse_end(&window, window_start, i)?;
        // Self-extractors and archives with a prefix: offsets are relative
        // to the start of the archive, which sits `delta` bytes in.
        let cd_end = end.at.saturating_sub(if end.zip64 { 76 } else { 0 });
        let delta = cd_end.saturating_sub(end.cd_size).saturating_sub(end.cd_offset);
        let cd_at = end.cd_offset + delta;
        if end.cd_size > MAX_CENTRAL_BYTES || cd_at.checked_add(end.cd_size).is_none_or(|e| e > len) {
            return Err(ExtractError::malformed("central directory out of range"));
        }
        let cd = src.read_vec(cd_at, usize::try_from(end.cd_size).unwrap_or(0))?;
        let mut zip = Zip {
            comment: end.comment,
            zip64: end.zip64,
            prefix_bytes: delta,
            declared_entries: end.entries,
            ..Zip::default()
        };
        parse_central(&cd, max_entries, &mut zip)?;
        if delta > 0 {
            for e in &mut zip.entries {
                e.local_offset += delta;
            }
        }
        Ok(zip)
    }

    /// The entry named `name` (exact match).
    pub fn find(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// The entry named `name`, ignoring ASCII case and a leading `/`.
    pub fn find_ci(&self, name: &str) -> Option<&ZipEntry> {
        let name = name.trim_start_matches('/');
        self.entries.iter().find(|e| e.name.trim_start_matches('/').eq_ignore_ascii_case(name))
    }

    /// Entries whose name starts with `prefix`.
    pub fn under<'z>(&'z self, prefix: &'z str) -> impl Iterator<Item = &'z ZipEntry> + 'z {
        self.entries.iter().filter(move |e| e.name.starts_with(prefix) && !e.is_dir())
    }

    /// Total uncompressed size of all entries.
    pub fn uncompressed_bytes(&self) -> u64 {
        self.entries.iter().fold(0u64, |a, e| a.saturating_add(e.size))
    }

    /// The uncompressed data of `entry`, at most `max` bytes (stored or
    /// deflated; decompression is charged to the budget).
    pub fn read(
        &self,
        src: &mut dyn Source,
        entry: &ZipEntry,
        cx: &mut Context<'_>,
        max: usize,
    ) -> Result<Vec<u8>, ExtractError> {
        if entry.is_encrypted() {
            return Err(ExtractError::Encrypted);
        }
        let header = src.read_vec(entry.local_offset, 30)?;
        if !header.starts_with(LOCAL) {
            return Err(ExtractError::malformed(format!("{}: no local header", entry.name)));
        }
        let n = u64::from(u16::from_le_bytes([header[26], header[27]]));
        let e = u64::from(u16::from_le_bytes([header[28], header[29]]));
        let at = entry.local_offset + 30 + n + e;
        let csize = entry.compressed_size;
        match entry.method {
            0 => {
                if csize > max as u64 {
                    return Err(ExtractError::LimitExceeded(format!("{}: entry size", entry.name)));
                }
                Ok(src.read_vec(at, usize::try_from(csize).unwrap_or(0))?)
            }
            8 => {
                // Deflate rarely beats 1000:1 on real data; a larger claim is a bomb.
                let cap = max.min(usize::try_from(csize.saturating_mul(1032).saturating_add(4096)).unwrap_or(max));
                let data = src.read_vec(at, usize::try_from(csize).map_err(|_| ExtractError::malformed("size"))?)?;
                cx.inflate(&data, Compression::Deflate, cap)
            }
            m => Err(ExtractError::Unsupported(format!("{}: compression method {m}", entry.name))),
        }
    }

    /// [`read`](Self::read) of the entry named `name`, as text (UTF-8 or a BOM-marked encoding).
    pub fn read_text(
        &self,
        src: &mut dyn Source,
        name: &str,
        cx: &mut Context<'_>,
        max: usize,
    ) -> Option<Result<String, ExtractError>> {
        let entry = self.find(name).or_else(|| self.find_ci(name))?.clone();
        Some(self.read(src, &entry, cx, max).map(|b| crate::text::decode(&b).text))
    }
}

/// Entry names of the ZIP in `probe`, without reading anything: from the
/// central directory when it lies in the tail window, else from the local
/// headers in the head window. At most `max` names; empty for non-ZIPs.
pub fn names(probe: &Probe<'_>, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    if !probe.head.starts_with(LOCAL) && !probe.head.starts_with(EOCD) {
        return out;
    }
    let tail = probe.tail;
    let tail_start = probe.len - tail.len() as u64;
    if let Some(i) = find_eocd(tail)
        && let Ok(end) = parse_end(tail, tail_start, i)
    {
        let cd_end = end.at.saturating_sub(if end.zip64 { 76 } else { 0 });
        let delta = cd_end.saturating_sub(end.cd_size).saturating_sub(end.cd_offset);
        if let Some(cd) = (end.cd_offset + delta)
            .checked_sub(tail_start)
            .and_then(|o| usize::try_from(o).ok())
            .and_then(|o| tail.get(o..o + usize::try_from(end.cd_size).ok()?))
        {
            let mut zip = Zip::default();
            let _ = parse_central(cd, max, &mut zip);
            if !zip.entries.is_empty() {
                return zip.entries.into_iter().map(|e| e.name).collect();
            }
        }
    }
    let mut r = ByteReader::new(probe.head);
    while r.peek(4) == Some(LOCAL) && out.len() < max {
        let Ok(h) = r.bytes(30) else { break };
        let flags = u16::from_le_bytes([h[6], h[7]]);
        let csize = u32::from_le_bytes([h[18], h[19], h[20], h[21]]) as usize;
        let n = usize::from(u16::from_le_bytes([h[26], h[27]]));
        let e = usize::from(u16::from_le_bytes([h[28], h[29]]));
        let Ok(name) = r.bytes(n) else { break };
        out.push(entry_name(name, flags));
        // Data descriptors (flag 8) leave the size unknown: stop walking.
        if flags & 8 != 0 || r.advance(e).is_err() || r.advance(csize).is_err() {
            break;
        }
    }
    out
}

/// The content of the first entry when it is stored uncompressed and named
/// `name` (the `mimetype` entry of OpenDocument and EPUB files).
pub fn first_stored<'p>(head: &'p [u8], name: &str) -> Option<&'p [u8]> {
    let mut r = ByteReader::new(head);
    let h = r.bytes(30).ok()?;
    if &h[..4] != LOCAL || u16::from_le_bytes([h[8], h[9]]) != 0 {
        return None;
    }
    let csize = u32::from_le_bytes([h[18], h[19], h[20], h[21]]) as usize;
    let n = usize::from(u16::from_le_bytes([h[26], h[27]]));
    let e = usize::from(u16::from_le_bytes([h[28], h[29]]));
    (r.bytes(n).ok()? == name.as_bytes()).then_some(())?;
    r.advance(e).ok()?;
    r.bytes(csize.min(256)).ok()
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // test archives are small
pub(crate) mod tests {
    use super::*;

    /// A ZIP with the given (name, data, deflate?) entries, written in-house
    /// so tests need no zip crate. Deflated entries use stored deflate blocks.
    pub(crate) fn build(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data, deflate) in entries {
            let body = if *deflate { miniz_oxide::deflate::compress_to_vec(data, 6) } else { data.to_vec() };
            let offset = out.len() as u32;
            let method: u16 = if *deflate { 8 } else { 0 };
            let common = |v: &mut Vec<u8>| {
                v.extend_from_slice(&20u16.to_le_bytes());
                v.extend_from_slice(&0x800u16.to_le_bytes());
                v.extend_from_slice(&method.to_le_bytes());
                v.extend_from_slice(&0u16.to_le_bytes());
                v.extend_from_slice(&0x5921u16.to_le_bytes()); // 2024-09-01
                v.extend_from_slice(&0u32.to_le_bytes());
                v.extend_from_slice(&(body.len() as u32).to_le_bytes());
                v.extend_from_slice(&(data.len() as u32).to_le_bytes());
                v.extend_from_slice(&(name.len() as u16).to_le_bytes());
                v.extend_from_slice(&0u16.to_le_bytes());
            };
            out.extend_from_slice(LOCAL);
            common(&mut out);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&body);
            central.extend_from_slice(CENTRAL);
            central.extend_from_slice(&20u16.to_le_bytes());
            common(&mut central);
            central.extend_from_slice(&[0; 10]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(EOCD);
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn probe(data: &[u8]) -> Probe<'_> {
        Probe { head: data, tail: data, len: data.len() as u64, name: None, extension: None }
    }

    #[test]
    fn lists_and_finds_entries() {
        let z = build(&[("mimetype", b"application/epub+zip", false), ("a/b.xml", b"<x/>", true)]);
        assert_eq!(names(&probe(&z), 10), ["mimetype", "a/b.xml"]);
        assert_eq!(first_stored(&z, "mimetype"), Some(&b"application/epub+zip"[..]));
        assert_eq!(first_stored(&z, "other"), None);
        let mut prefixed = b"MZ stub".to_vec();
        prefixed.extend_from_slice(&z);
        let mut src = crate::io::BytesSource::new(None, prefixed, crate::io::Budget::unlimited());
        let zip = Zip::open(&mut src, 100).unwrap();
        assert_eq!(zip.prefix_bytes, 7);
        assert_eq!(zip.entries.len(), 2);
        assert_eq!(zip.entries[1].modified.as_deref(), Some("2024-09-01T00:00:00"));
        assert!(zip.find_ci("/A/B.XML").is_some());
    }

    #[test]
    fn rejects_non_zip() {
        let mut src =
            crate::io::BytesSource::new(None, b"not a zip at all, no".to_vec(), crate::io::Budget::unlimited());
        assert!(matches!(Zip::open(&mut src, 10), Err(ExtractError::Unsupported(_))));
        assert_eq!(names(&probe(b"PK\x03\x04"), 5), Vec::<String>::new());
    }

    #[test]
    fn dos_times() {
        assert_eq!(dos_time(0x5921, 0x6000).as_deref(), Some("2024-09-01T12:00:00"));
        assert_eq!(dos_time(0, 0), None);
    }
}
