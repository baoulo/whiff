//! 7z archives: the signature header, the header (plain, or packed and
//! decoded first), folders with their coder chains, substreams and the file
//! list (names, sizes, times, attributes, empty files and folders). Reports
//! the methods, solid blocks and encryption — AES on the header hides even
//! the names. Folders decoded with a copy, LZMA, LZMA2, deflate or bzip2
//! coder (optionally behind a delta or branch filter) are split into their
//! files, which are handed on (within the limits).
//!
//! Specification: the 7-Zip `7zFormat.txt` (LZMA SDK 24.08).

use lzma_rust2::filter::{FilterConfig, FilterType, StreamFilter};

use super::{Entry, Inventory, Kind, child, filetime};
use crate::plugin::{
    ByteReader, Codec, Context, Cost, End, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, codec,
};

/// Extractor for 7z archives.
pub struct SevenZ;

static META: ExtractorMeta = ExtractorMeta {
    id: "archive.7z",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "7z",
        name: "7-Zip archive",
        family: "archive",
        mimes: &["application/x-7z-compressed"],
        extensions: &["7z"],
        magic: &[Magic::prefix(b"7z\xbc\xaf\x27\x1c")],
        parent: None,
    }],
};

/// Largest header read (packed or not).
const MAX_HEADER: u64 = 64 << 20;
const MAX_FILES: u64 = 1 << 20;
const MAX_FOLDERS: u64 = 1 << 16;
const MAX_CODERS: u64 = 8;

fn bad(what: &str) -> ExtractError {
    ExtractError::malformed(format!("7z {what}"))
}

/// A 7z `NUMBER`: the leading one bits of the first byte say how many
/// little-endian bytes follow.
fn number(r: &mut ByteReader<'_>) -> Result<u64, ExtractError> {
    let first = r.u8()?;
    let n = first.leading_ones() as usize;
    let mut v = 0u64;
    for i in 0..n.min(8) {
        v |= u64::from(r.u8()?) << (8 * i);
    }
    // Seven leading ones leave no value bits in the first byte.
    if n < 7 {
        v |= u64::from(first & (0xff >> (n + 1))) << (8 * n);
    }
    Ok(v)
}

fn count(r: &mut ByteReader<'_>, max: u64, what: &str) -> Result<usize, ExtractError> {
    let n = number(r)?;
    if n > max {
        return Err(bad(what));
    }
    usize::try_from(n).map_err(|_| bad(what))
}

/// A bit vector of `n` bits, most significant first.
fn bits(r: &mut ByteReader<'_>, n: usize) -> Result<Vec<bool>, ExtractError> {
    let bytes = r.bytes(n.div_ceil(8))?;
    Ok((0..n).map(|i| bytes[i / 8] & (0x80 >> (i % 8)) != 0).collect())
}

/// "All defined" byte, then a bit vector unless it is set.
fn defined(r: &mut ByteReader<'_>, n: usize) -> Result<Vec<bool>, ExtractError> {
    if r.u8()? != 0 { Ok(vec![true; n]) } else { bits(r, n) }
}

fn digests(r: &mut ByteReader<'_>, n: usize) -> Result<(), ExtractError> {
    let d = defined(r, n)?;
    r.advance(4 * d.iter().filter(|&&b| b).count())?;
    Ok(())
}

#[derive(Debug, Clone, Default)]
struct Coder {
    id: Vec<u8>,
    props: Vec<u8>,
    ins: usize,
    outs: usize,
}

#[derive(Debug, Clone, Default)]
struct Folder {
    coders: Vec<Coder>,
    /// (in index, out index).
    binds: Vec<(usize, usize)>,
    packed: Vec<usize>,
    /// One size per coder output.
    sizes: Vec<u64>,
    /// Substreams (files) in the folder.
    streams: usize,
}

impl Folder {
    fn total_outs(&self) -> usize {
        self.coders.iter().map(|c| c.outs).sum()
    }

    /// The size of the output no bind pair consumes: the folder's result.
    fn unpack_size(&self) -> u64 {
        (0..self.total_outs())
            .find(|o| !self.binds.iter().any(|(_, out)| out == o))
            .and_then(|o| self.sizes.get(o).copied())
            .unwrap_or(0)
    }

    fn encrypted(&self) -> bool {
        self.coders.iter().any(|c| c.id == [0x06, 0xf1, 0x07, 0x01])
    }

    /// The coder that decompresses (not a filter), for the method shown.
    fn main_coder(&self) -> Option<&Coder> {
        self.coders.iter().find(|c| filter(c).is_none()).or(self.coders.first())
    }
}

#[derive(Debug, Default)]
struct Streams {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    folders: Vec<Folder>,
    /// Substream sizes, all folders in order.
    sub_sizes: Vec<u64>,
}

fn pack_info(r: &mut ByteReader<'_>, s: &mut Streams) -> Result<(), ExtractError> {
    s.pack_pos = number(r)?;
    let n = count(r, MAX_FOLDERS * 4, "pack streams")?;
    loop {
        match number(r)? {
            0x00 => return Ok(()),
            0x09 => s.pack_sizes = (0..n).map(|_| number(r)).collect::<Result<_, _>>()?,
            0x0a => digests(r, n)?,
            _ => return Err(bad("pack info")),
        }
    }
}

fn folder(r: &mut ByteReader<'_>) -> Result<Folder, ExtractError> {
    let mut f = Folder::default();
    let n = count(r, MAX_CODERS, "coders")?;
    for _ in 0..n {
        let flag = r.u8()?;
        let id = r.bytes(usize::from(flag & 0x0f))?.to_vec();
        let (ins, outs) =
            if flag & 0x10 != 0 { (count(r, 8, "coder streams")?, count(r, 8, "coder streams")?) } else { (1, 1) };
        let props = if flag & 0x20 != 0 {
            let n = count(r, 1 << 16, "coder properties")?;
            r.bytes(n)?.to_vec()
        } else {
            Vec::new()
        };
        f.coders.push(Coder { id, props, ins, outs });
    }
    let total_in: usize = f.coders.iter().map(|c| c.ins).sum();
    let total_out = f.total_outs();
    for _ in 1..total_out {
        f.binds.push((count(r, 64, "bind pair")?, count(r, 64, "bind pair")?));
    }
    let packed = total_in.checked_sub(f.binds.len()).ok_or_else(|| bad("folder streams"))?;
    if packed == 1 {
        f.packed = (0..total_in).filter(|i| !f.binds.iter().any(|(inp, _)| inp == i)).take(1).collect();
    } else {
        for _ in 0..packed {
            f.packed.push(count(r, 64, "packed stream")?);
        }
    }
    f.streams = 1;
    Ok(f)
}

fn unpack_info(r: &mut ByteReader<'_>, s: &mut Streams) -> Result<(), ExtractError> {
    if number(r)? != 0x0b {
        return Err(bad("unpack info"));
    }
    let n = count(r, MAX_FOLDERS, "folders")?;
    if r.u8()? != 0 {
        return Err(bad("external folders"));
    }
    s.folders = (0..n).map(|_| folder(r)).collect::<Result<_, _>>()?;
    if number(r)? != 0x0c {
        return Err(bad("unpack sizes"));
    }
    for f in &mut s.folders {
        f.sizes = (0..f.total_outs()).map(|_| number(r)).collect::<Result<_, _>>()?;
    }
    loop {
        match number(r)? {
            0x00 => return Ok(()),
            0x0a => digests(r, n)?,
            _ => return Err(bad("unpack info")),
        }
    }
}

fn substreams_info(r: &mut ByteReader<'_>, s: &mut Streams) -> Result<(), ExtractError> {
    let mut id = number(r)?;
    if id == 0x0d {
        for f in &mut s.folders {
            f.streams = count(r, MAX_FILES, "substreams")?;
        }
        id = number(r)?;
    }
    let mut sizes = Vec::new();
    for f in &s.folders {
        if f.streams == 0 {
            continue;
        }
        let total = f.unpack_size();
        let mut sum = 0u64;
        if id == 0x09 {
            for _ in 1..f.streams {
                let n = number(r)?;
                sum = sum.saturating_add(n);
                sizes.push(n);
            }
        }
        sizes.push(total.saturating_sub(sum));
    }
    if id == 0x09 {
        id = number(r)?;
    }
    while id != 0x00 {
        if id != 0x0a {
            return Err(bad("substreams info"));
        }
        // Digests of the streams whose CRC the folder does not give.
        let n = s.folders.iter().map(|f| f.streams).sum();
        digests(r, n)?;
        id = number(r)?;
    }
    s.sub_sizes = sizes;
    Ok(())
}

fn streams_info(r: &mut ByteReader<'_>) -> Result<Streams, ExtractError> {
    let mut s = Streams::default();
    let mut has_sub = false;
    loop {
        match number(r)? {
            0x00 => break,
            0x06 => pack_info(r, &mut s)?,
            0x07 => unpack_info(r, &mut s)?,
            0x08 => {
                substreams_info(r, &mut s)?;
                has_sub = true;
            }
            _ => return Err(bad("streams info")),
        }
    }
    if !has_sub {
        s.sub_sizes = s.folders.iter().map(Folder::unpack_size).collect();
    }
    Ok(s)
}

#[derive(Debug, Default)]
struct File {
    name: String,
    has_stream: bool,
    dir: bool,
    anti: bool,
    mtime: Option<u64>,
    attributes: Option<u32>,
}

fn files_info(r: &mut ByteReader<'_>) -> Result<Vec<File>, ExtractError> {
    let n = count(r, MAX_FILES, "files")?;
    let mut files: Vec<File> = (0..n).map(|_| File { has_stream: true, ..File::default() }).collect();
    let mut empty_streams = 0;
    let mut empty_file: Vec<bool> = Vec::new();
    loop {
        let id = number(r)?;
        if id == 0x00 {
            break;
        }
        let size = usize::try_from(number(r)?).map_err(|_| bad("property size"))?;
        let mut p = ByteReader::new(r.bytes(size)?);
        match id {
            0x0e => {
                let v = bits(&mut p, n)?;
                empty_streams = v.iter().filter(|&&b| b).count();
                for (f, e) in files.iter_mut().zip(v) {
                    f.has_stream = !e;
                }
            }
            0x0f => empty_file = bits(&mut p, empty_streams)?,
            0x10 => {
                let v = bits(&mut p, empty_streams)?;
                for (f, a) in files.iter_mut().filter(|f| !f.has_stream).zip(v) {
                    f.anti = a;
                }
            }
            0x11 => {
                if p.u8()? != 0 {
                    return Err(bad("external names"));
                }
                let raw = p.rest();
                let (pairs, _) = raw.as_chunks::<2>();
                let units: Vec<u16> = pairs.iter().map(|c| u16::from_le_bytes(*c)).collect();
                for (f, name) in files.iter_mut().zip(units.split(|&u| u == 0)) {
                    f.name = String::from_utf16_lossy(name);
                }
            }
            0x14 => {
                let d = defined(&mut p, n)?;
                if p.u8()? != 0 {
                    return Err(bad("external times"));
                }
                for (f, def) in files.iter_mut().zip(d) {
                    if def {
                        f.mtime = Some(p.le_u64()?);
                    }
                }
            }
            0x15 => {
                let d = defined(&mut p, n)?;
                if p.u8()? != 0 {
                    return Err(bad("external attributes"));
                }
                for (f, def) in files.iter_mut().zip(d) {
                    if def {
                        f.attributes = Some(p.le_u32()?);
                    }
                }
            }
            _ => {} // creation / access times, start positions, padding
        }
    }
    // An empty stream is a folder unless marked as an empty file.
    for (k, f) in files.iter_mut().filter(|f| !f.has_stream).enumerate() {
        f.dir = !empty_file.get(k).copied().unwrap_or(false);
    }
    for f in &mut files {
        if let Some(a) = f.attributes
            && a & 0x10 != 0
        {
            f.dir = true;
        }
    }
    Ok(files)
}

fn method_name(id: &[u8]) -> String {
    match id {
        [0x00] => "copy".into(),
        [0x03] => "delta".into(),
        [0x04] | [0x03, 0x03, 0x01, 0x03] => "BCJ".into(),
        [0x03, 0x03, 0x01, 0x1b] => "BCJ2".into(),
        [0x05] | [0x03, 0x03, 0x02, 0x05] => "PPC".into(),
        [0x06] | [0x03, 0x03, 0x04, 0x01] => "IA64".into(),
        [0x07] | [0x03, 0x03, 0x05, 0x01] => "ARM".into(),
        [0x08] | [0x03, 0x03, 0x07, 0x01] => "ARMT".into(),
        [0x09] | [0x03, 0x03, 0x08, 0x05] => "SPARC".into(),
        [0x0a] => "ARM64".into(),
        [0x0b] => "RISCV".into(),
        [0x21] => "LZMA2".into(),
        [0x03, 0x01, 0x01] => "LZMA".into(),
        [0x03, 0x04, 0x01] => "PPMd".into(),
        [0x04, 0x01, 0x08] => "Deflate".into(),
        [0x04, 0x01, 0x09] => "Deflate64".into(),
        [0x04, 0x02, 0x02] => "BZip2".into(),
        [0x04, 0xf7, 0x11, 0x01] => "Zstd".into(),
        [0x06, 0xf1, 0x07, 0x01] => "AES-256".into(),
        other => other.iter().fold(String::new(), |mut s, b| {
            let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02X}"));
            s
        }),
    }
}

/// The in-place filter a coder id names, if any.
fn filter(c: &Coder) -> Option<FilterConfig> {
    let filter_type = match c.id.as_slice() {
        [0x03] => FilterType::Delta,
        [0x04] | [0x03, 0x03, 0x01, 0x03] => FilterType::BcjX86,
        [0x05] | [0x03, 0x03, 0x02, 0x05] => FilterType::BcjPpc,
        [0x06] | [0x03, 0x03, 0x04, 0x01] => FilterType::BcjIa64,
        [0x07] | [0x03, 0x03, 0x05, 0x01] => FilterType::BcjArm,
        [0x08] | [0x03, 0x03, 0x07, 0x01] => FilterType::BcjArmThumb,
        [0x09] | [0x03, 0x03, 0x08, 0x05] => FilterType::BcjSparc,
        [0x0a] => FilterType::BcjArm64,
        [0x0b] => FilterType::BcjRiscv,
        _ => return None,
    };
    let property = match (filter_type, c.props.as_slice()) {
        (FilterType::Delta, [d]) => u32::from(*d) + 1,
        (FilterType::Delta, _) => 1,
        (_, [a, b, c, d]) => u32::from_le_bytes([*a, *b, *c, *d]),
        _ => 0,
    };
    Some(FilterConfig { filter_type, property })
}

/// The codec of a decompressing coder, for an output of `size` bytes.
fn codec_of(c: &Coder, size: u64) -> Option<Codec> {
    Some(match (c.id.as_slice(), c.props.as_slice()) {
        ([0x21], [d, ..]) => Codec::Lzma2 { dict_size: codec::lzma2_dict_size(*d)? },
        ([0x03, 0x01, 0x01], [props, a, b, c2, d, ..]) => {
            Codec::Lzma { props: *props, dict_size: u32::from_le_bytes([*a, *b, *c2, *d]), size: Some(size) }
        }
        ([0x04, 0x01, 0x08], _) => Codec::Deflate,
        ([0x04, 0x02, 0x02], _) => Codec::Bzip2,
        _ => return None,
    })
}

/// Decode a folder from its packed bytes, up to `max` bytes. Handles one
/// coder (copy or a decompressor), or a filter fed by a decompressor.
fn decode_folder(
    cx: &mut Context<'_>,
    f: &Folder,
    packed: &[u8],
    max: usize,
) -> Result<Option<(Vec<u8>, bool)>, ExtractError> {
    let size = f.unpack_size();
    if f.coders.iter().any(|c| c.ins != 1 || c.outs != 1) {
        return Ok(None);
    }
    // With one stream per coder, coder `i` reads in-stream `i` and writes
    // out-stream `i`. A filter reads what the decompressor writes, in
    // either order (7-Zip lists the decompressor first).
    let (main, main_out, filters): (&Coder, usize, Vec<FilterConfig>) = match f.coders.as_slice() {
        [c] => (c, 0, Vec::new()),
        [a, b] => {
            let Some((dec, filt)) = [(0usize, 1usize), (1, 0)].into_iter().find(|&(dec, filt)| {
                f.binds == [(filt, dec)] && f.packed == [dec] && filter(&f.coders[filt]).is_some()
            }) else {
                return Ok(None);
            };
            let cfg = filter(if filt == 0 { a } else { b }).into_iter().collect();
            (if dec == 0 { a } else { b }, dec, cfg)
        }
        _ => return Ok(None),
    };
    let (mut data, complete) = if main.id == [0x00] {
        let n = packed.len().min(max);
        (packed[..n].to_vec(), n == packed.len())
    } else {
        let Some(codec) = codec_of(main, f.sizes.get(main_out).copied().unwrap_or(size)) else { return Ok(None) };
        let d = cx.decompress(packed, codec, max)?;
        let complete = d.end == End::Complete || (d.end != End::Limit && d.data.len() as u64 == size);
        (d.data, complete)
    };
    for cfg in filters {
        let mut sf = StreamFilter::new(&cfg).map_err(|e| ExtractError::malformed(e.to_string()))?;
        sf.decode(&mut data);
        sf.finish();
    }
    Ok(Some((data, complete)))
}

impl Extractor for SevenZ {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // header, listing and children in one pass
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let sig = src.read_vec(0, 32)?;
        let mut r = ByteReader::new(&sig).skip(6)?;
        let (major, minor) = (r.u8()?, r.u8()?);
        cx.format_set("version", format!("{major}.{minor}"));
        r.le_u32()?;
        let next_offset = r.le_u64()?;
        let next_size = r.le_u64()?;
        if next_size == 0 {
            // An empty archive (or one still being written).
            Inventory::new().report(cx, len);
            return Ok(());
        }
        let at = next_offset.checked_add(32).ok_or_else(|| bad("header offset"))?;
        if next_size > MAX_HEADER || at.checked_add(next_size).is_none_or(|e| e > len) {
            return Err(bad("header out of range"));
        }
        let mut header = src.read_vec(at, usize::try_from(next_size).unwrap_or(0))?;
        let mut packed_header = false;
        let mut rr = ByteReader::new(&header);
        if number(&mut rr)? == 0x17 {
            packed_header = true;
            let s = streams_info(&mut rr)?;
            let f = s.folders.first().ok_or_else(|| bad("packed header"))?;
            if f.encrypted() {
                cx.format_set("headers_encrypted", true);
                cx.format_set("methods", f.coders.iter().map(|c| method_name(&c.id)).collect::<Vec<_>>());
                cx.security().encrypted(true);
                return Ok(());
            }
            let size = s.pack_sizes.first().copied().ok_or_else(|| bad("packed header"))?;
            let pos = 32 + s.pack_pos;
            if size > MAX_HEADER || pos.checked_add(size).is_none_or(|e| e > len) {
                return Err(bad("packed header out of range"));
            }
            let packed = src.read_vec(pos, usize::try_from(size).unwrap_or(0))?;
            let want = usize::try_from(f.unpack_size().min(MAX_HEADER)).unwrap_or(0);
            match decode_folder(cx, f, &packed, want)? {
                Some((h, true)) => header = h,
                _ => return Err(bad("packed header (unsupported coder)")),
            }
            rr = ByteReader::new(&header);
            if number(&mut rr)? != 0x01 {
                return Err(bad("header"));
            }
        }
        let mut streams = Streams::default();
        let mut files = Vec::new();
        loop {
            match number(&mut rr)? {
                0x00 => break,
                0x02 => {
                    // Archive properties: (type, size, data) until 0.
                    while number(&mut rr)? != 0 {
                        let n = usize::try_from(number(&mut rr)?).map_err(|_| bad("property"))?;
                        rr.advance(n)?;
                    }
                }
                0x03 => {
                    streams_info(&mut rr)?;
                }
                0x04 => streams = streams_info(&mut rr)?,
                0x05 => files = files_info(&mut rr)?,
                _ => return Err(bad("header")),
            }
        }
        if packed_header {
            cx.format_set("packed_header", true);
        }
        let mut methods: Vec<String> = Vec::new();
        for c in streams.folders.iter().flat_map(|f| &f.coders) {
            let m = method_name(&c.id);
            if !methods.contains(&m) {
                methods.push(m);
            }
        }
        if !methods.is_empty() {
            cx.format_set("methods", methods);
        }
        let solid = streams.folders.iter().filter(|f| f.streams > 1).count();
        cx.format_set("solid", solid > 0);
        cx.format_set("folders", streams.folders.len());
        let encrypted = streams.folders.iter().any(Folder::encrypted);

        // Files with data take the substreams in order; each substream
        // belongs to a folder.
        let mut stream_folder: Vec<usize> = Vec::new();
        for (i, f) in streams.folders.iter().enumerate() {
            stream_folder.extend(std::iter::repeat_n(i, f.streams));
        }
        let mut inv = Inventory::new();
        let mut placed: Vec<(usize, usize)> = Vec::new(); // (file index, substream index)
        let mut next_stream = 0usize;
        for (i, f) in files.iter().enumerate() {
            if f.anti {
                continue;
            }
            let (size, folder) = if f.has_stream {
                let s = next_stream;
                next_stream += 1;
                placed.push((i, s));
                (streams.sub_sizes.get(s).copied(), stream_folder.get(s).copied())
            } else {
                (Some(0), None)
            };
            let unix = f.attributes.filter(|a| a & 0x8000 != 0).map(|a| a >> 16);
            let kind = if f.dir { Kind::Dir } else { unix.map_or(Kind::File, Kind::from_mode) };
            let folder_enc = folder.and_then(|i| streams.folders.get(i)).is_some_and(Folder::encrypted);
            inv.push(Entry {
                path: f.name.clone(),
                kind,
                size: if f.dir { Some(0) } else { size },
                compressed: None,
                modified: f.mtime.and_then(filetime),
                mode: unix.map(|m| m & 0o7777),
                link: None,
                encrypted: folder_enc,
                method: folder
                    .and_then(|i| streams.folders.get(i))
                    .and_then(Folder::main_coder)
                    .map(|c| method_name(&c.id)),
            });
        }
        let compressed: u64 = streams.pack_sizes.iter().fold(0, |a, &b| a.saturating_add(b));
        if compressed > 0 {
            cx.format_set("packed_bytes", compressed);
        }
        if encrypted {
            cx.security().encrypted(true);
        }
        inv.report(cx, len);
        children(src, cx, &streams, &files, &placed, &stream_folder)
    }
}

crate::register_extractor!(SevenZ);

/// Decode folders and hand their files on, as far as the limits allow.
fn children(
    src: &mut dyn Source,
    cx: &mut Context<'_>,
    streams: &Streams,
    files: &[File],
    placed: &[(usize, usize)],
    stream_folder: &[usize],
) -> Result<(), ExtractError> {
    if cx.child_room() == 0 {
        return Ok(());
    }
    let limit = cx.parse_limit();
    // Each folder's packed streams follow one another from the pack position.
    let mut pack_at = 32 + streams.pack_pos;
    let mut pack_index = 0usize;
    let mut stream_index = 0usize;
    for (fi, f) in streams.folders.iter().enumerate() {
        let first = stream_index;
        stream_index += f.streams;
        let n_packed = f.packed.len().max(1);
        let sizes = streams.pack_sizes.get(pack_index..pack_index + n_packed).unwrap_or(&[]);
        let packed_len: u64 = sizes.iter().sum();
        let here = pack_at;
        pack_at = pack_at.saturating_add(packed_len);
        pack_index += n_packed;
        if cx.child_room() == 0 {
            break;
        }
        if f.encrypted() || n_packed != 1 || f.streams == 0 {
            continue;
        }
        let wanted: Vec<&(usize, usize)> = placed
            .iter()
            .filter(|(_, s)| (first..stream_index).contains(s) && stream_folder.get(*s) == Some(&fi))
            .collect();
        if wanted.iter().all(|(i, _)| files.get(*i).is_none_or(|f| f.dir)) {
            continue;
        }
        cx.checkpoint()?;
        let input = packed_len.min(src.len().saturating_sub(here));
        let packed = src.read_vec(here, usize::try_from(input.min(MAX_HEADER * 4)).unwrap_or(0))?;
        let Some((data, complete)) = decode_folder(cx, f, &packed, limit)? else { continue };
        let mut offset = 0usize;
        for &&(file, s) in &wanted {
            let size = usize::try_from(streams.sub_sizes.get(s).copied().unwrap_or(0)).unwrap_or(usize::MAX);
            let start = offset.min(data.len());
            let end = offset.saturating_add(size).min(data.len());
            offset = offset.saturating_add(size);
            if start >= end {
                if start >= data.len() {
                    break;
                }
                continue;
            }
            let whole = end - start == size && (complete || end < data.len());
            if !child(cx, &files[file].name, data[start..end].to_vec(), whole)? {
                return Ok(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        let mut r = ByteReader::new(&[0x05, 0x81, 0x02, 0xc0, 0x34, 0x12, 0xff, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(number(&mut r).unwrap(), 5);
        assert_eq!(number(&mut r).unwrap(), 0x102);
        assert_eq!(number(&mut r).unwrap(), 0x1234);
        assert_eq!(number(&mut r).unwrap(), 0x0807_0605_0403_0201);
        // Seven leading ones: seven bytes follow (a fuzzer find).
        assert_eq!(number(&mut ByteReader::new(&[0xfe, 1, 0, 0, 0, 0, 0, 2])).unwrap(), 0x0002_0000_0000_0001);
        assert_eq!(method_name(&[0x21]), "LZMA2");
        assert_eq!(method_name(&[0x99]), "99");
    }

    crate::fixture_tests!("7z");
}
