//! Optical disc images: ISO 9660 (with Joliet and Rock Ridge names) and
//! UDF, alone or as a bridge disc. The primary volume descriptor gives the
//! volume, publisher, preparer and application, the copyright / abstract /
//! bibliography files and the four volume dates; El Torito gives the boot
//! entries (platform, emulation, load size), and EFI boot images are handed
//! on (they are FAT images). UDF gives its revision, volume and logical
//! volume identifiers, block size and recording time. The directory tree
//! (UDF when the disc has it, else Rock Ridge, Joliet or plain ISO names)
//! goes into the archive inventory and files are handed on as children.
//! Hybrid images that also carry an MBR or GPT for USB booting report the
//! partition table.
//!
//! Specifications: ECMA-119 (ISO 9660), Joliet (Microsoft, 1995), IEEE
//! P1282 Rock Ridge (RRIP 1.12) over SUSP 1.12, El Torito 1.0; ECMA-167
//! and OSTA UDF 2.60.

use std::collections::HashSet;

use serde_json::{Map, Value, json};

use super::archive::{Entry, Inventory, Kind, MAX_ENTRIES, Stored, child, stored_children, wanted};
use crate::plugin::volume::num::{le16, le32, le64};
use crate::plugin::volume::{self, fat_geometry, text_field};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for ISO 9660 and UDF images.
pub struct Iso;

static META: ExtractorMeta = ExtractorMeta {
    id: "disk.iso",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "iso9660",
            name: "ISO 9660 disc image",
            family: "disk",
            mimes: &["application/x-iso9660-image"],
            extensions: &["iso"],
            magic: &[Magic::at(32769, b"CD001")],
            parent: None,
        },
        FormatSpec {
            id: "udf",
            name: "UDF disc image",
            family: "disk",
            mimes: &["application/x-udf-image"],
            extensions: &["udf"],
            magic: &[],
            parent: None,
        },
    ],
};

const SECTOR: u64 = 2048;
/// Volume descriptors read at most.
const MAX_DESCRIPTORS: u64 = 64;
/// Folder depth followed.
const MAX_DEPTH: usize = 64;
/// Directory bytes read at most.
const MAX_DIR: u64 = 16 << 20;
/// Boot entries listed at most.
const MAX_BOOT: usize = 32;

/// Whether the volume recognition sequence names UDF.
fn has_udf(head: &[u8]) -> bool {
    (16..24).any(|i| {
        let at = i * 2048 + 1;
        head.get(at..at + 5).is_some_and(|m| m == b"NSR02" || m == b"NSR03")
    })
}

impl Extractor for Iso {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let first = probe.head.get(32769..32774)?;
        (first == b"BEA01" && has_udf(probe.head)).then_some(Sniff { format: "udf", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        read(src, cx)
    }
}

crate::register_extractor!(Iso);

/// Read an ISO 9660 / UDF volume (an image file, or the user data of a raw
/// CD image) into the report.
pub(crate) fn read(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut iso = None;
    let mut boot_catalog = None;
    for i in 16..16 + MAX_DESCRIPTORS {
        let Ok(d) = src.read_vec(i * SECTOR, 2048) else { break };
        if &d[1..6] != b"CD001" {
            break;
        }
        match d[0] {
            0 if d[7..30] == *b"EL TORITO SPECIFICATION" => boot_catalog = le32(&d, 71),
            1 if iso.is_none() => iso = Some(IsoVolume::new(&d)),
            2 if matches!(&d[88..91], b"%/@" | b"%/C" | b"%/E") => {
                if let Some(v) = iso.as_mut() {
                    v.joliet = Some(d.clone());
                }
            }
            255 => break,
            _ => {}
        }
    }
    let udf = if has_udf(src.head()) || iso.is_none() { Udf::open(src) } else { None };
    if iso.is_none() && udf.is_none() {
        return Err(ExtractError::malformed("no ISO 9660 or UDF volume descriptors"));
    }
    if let Some(v) = &iso {
        v.report(cx);
    }
    if let Some(u) = &udf {
        u.report(cx, iso.is_none());
    }
    if let Some(lba) = boot_catalog {
        boot(src, cx, lba)?;
    }
    // A partition table for USB booting (isohybrid).
    let disk = volume::describe(src);
    if disk.contains_key("partition_table") {
        for (k, v) in disk {
            cx.format_set(&k, v);
        }
    }
    let mut inv = Inventory::new();
    let mut files: Vec<File> = Vec::new();
    let listed = match &udf {
        Some(u) => u.walk(src, cx, &mut inv, &mut files)?,
        None => false,
    };
    if !listed && let Some(v) = &iso {
        let names = v.walk(src, cx, &mut inv, &mut files)?;
        cx.format_set("names", names);
    }
    inv.report(cx, src.len());
    let mut stored = Vec::new();
    for f in files {
        match f {
            File::Stored(s) => stored.push(s),
            File::Inline(name, data) => {
                if !child(cx, &name, data, true)? {
                    return Ok(());
                }
            }
        }
    }
    stored_children(src, cx, stored)
}

/// A file to hand on.
enum File {
    Stored(Stored),
    /// Data kept in the file entry itself (UDF).
    Inline(String, Vec<u8>),
}

// ---------------------------------------------------------------- ISO 9660

/// A 17-byte volume date (`YYYYMMDDHHMMSScc` + offset in 15-minute units).
fn volume_date(b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b.get(..16)?).ok()?;
    if !s.bytes().all(|c| c.is_ascii_digit()) || s.starts_with("0000") {
        return None;
    }
    let off = i32::from(b.get(16)?.cast_signed()) * 15;
    Some(format!("{}-{}-{}T{}:{}:{}{}", &s[..4], &s[4..6], &s[6..8], &s[8..10], &s[10..12], &s[12..14], offset(off)))
}

fn offset(minutes: i32) -> String {
    if minutes == 0 {
        "Z".into()
    } else {
        let sign = if minutes < 0 { '-' } else { '+' };
        format!("{sign}{:02}:{:02}", minutes.abs() / 60, minutes.abs() % 60)
    }
}

/// A 7-byte directory-record date.
fn record_date(b: &[u8]) -> Option<String> {
    let b = b.get(..7)?;
    if b[..6].iter().all(|&x| x == 0) || !(1..=12).contains(&b[1]) || !(1..=31).contains(&b[2]) {
        return None;
    }
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}",
        1900 + u32::from(b[0]),
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        offset(i32::from(b[6].cast_signed()) * 15)
    ))
}

struct IsoVolume {
    pvd: Vec<u8>,
    joliet: Option<Vec<u8>>,
    block: u64,
}

impl IsoVolume {
    fn new(pvd: &[u8]) -> Self {
        let block = le16(pvd, 128).map_or(SECTOR, u64::from);
        Self {
            pvd: pvd.to_vec(),
            joliet: None,
            block: if block.is_power_of_two() && block >= 512 { block } else { SECTOR },
        }
    }

    fn report(&self, cx: &mut Context<'_>) {
        let p = &self.pvd;
        let jtext = |at: usize, n: usize| self.joliet.as_ref().and_then(|j| volume::utf16_field(&j[at..at + n], false));
        let text = |at: usize, n: usize| jtext(at, n).or_else(|| text_field(&p[at..at + n]));
        let label = text(40, 32);
        if let Some(l) = &label {
            cx.format_set("volume_id", l.clone());
            cx.content().title(l.clone());
        }
        for (key, at, n) in [
            ("system_id", 8, 32),
            ("volume_set_id", 190, 128),
            ("publisher", 318, 128),
            ("data_preparer", 446, 128),
            ("application", 574, 128),
            ("copyright_file", 702, 37),
            ("abstract_file", 739, 37),
            ("bibliographic_file", 776, 37),
        ] {
            // `_` starts a file name holding the value (ECMA-119 8.4.20).
            if let Some(v) = text(at, n) {
                cx.format_set(key, v);
            }
        }
        if let Some(pubr) = text(318, 128).filter(|s| !s.starts_with('_')) {
            cx.content().author(pubr);
        }
        let blocks = le32(p, 80).unwrap_or(0);
        cx.format_set("block_size", self.block);
        cx.format_set("volume_bytes", u64::from(blocks) * self.block);
        if self.joliet.is_some() {
            cx.format_set("joliet", true);
        }
        for (key, at, field) in [
            ("created", 813, Some(crate::plugin::DateField::Created)),
            ("modified", 830, Some(crate::plugin::DateField::Modified)),
            ("expires", 847, None),
            ("effective", 864, None),
        ] {
            if let Some(d) = volume_date(&p[at..at + 17]) {
                cx.format_set(key, d.clone());
                if let Some(field) = field {
                    cx.temporal().content_date(field, d, true);
                }
            }
        }
    }

    /// Walk the tree: Rock Ridge names when the root says so, else Joliet,
    /// else ISO names. Returns which names were used.
    fn walk(
        &self,
        src: &mut dyn Source,
        cx: &mut Context<'_>,
        inv: &mut Inventory,
        files: &mut Vec<File>,
    ) -> Result<&'static str, ExtractError> {
        let root = &self.pvd[156..190];
        let (extent, size) = (le32(root, 2).unwrap_or(0), le32(root, 10).unwrap_or(0));
        let rr_skip = self.rock_ridge(src, extent);
        let (desc, names) = match (&self.joliet, rr_skip) {
            (_, Some(_)) => (&self.pvd, "rock_ridge"),
            (Some(j), None) => (j, "joliet"),
            (None, None) => (&self.pvd, "iso9660"),
        };
        let root = &desc[156..190];
        let (extent, size) =
            if names == "joliet" { (le32(root, 2).unwrap_or(0), le32(root, 10).unwrap_or(0)) } else { (extent, size) };
        let w = Walker { block: self.block, joliet: names == "joliet", rr_skip };
        let mut stack = vec![(extent, size, String::new(), 0usize)];
        let mut seen = HashSet::new();
        while let Some((extent, size, path, depth)) = stack.pop() {
            cx.checkpoint()?;
            if !seen.insert(extent) {
                continue;
            }
            let n = u64::from(size).min(MAX_DIR);
            let Ok(data) = src.read_vec(u64::from(extent) * self.block, usize::try_from(n).unwrap_or(0)) else {
                cx.warn(format!("directory at block {extent} unreadable"));
                continue;
            };
            let mut pending: Option<(String, u64, u32, Option<String>)> = None;
            for r in w.records(src, &data) {
                if inv.entries >= MAX_ENTRIES as u64 {
                    inv.truncated = true;
                    return Ok(names);
                }
                if r.relocated {
                    continue;
                }
                // Files over 4 GiB span several records with one name.
                if let Some((name, sum, first, modified)) = pending.take() {
                    if name == r.name && !r.dir {
                        let sum = sum + u64::from(r.size);
                        if r.more {
                            pending = Some((name, sum, first, modified));
                        } else {
                            push_file(inv, &path, &name, sum, modified);
                        }
                        continue;
                    }
                    push_file(inv, &path, &name, sum, modified);
                }
                let p = format!("{path}{}", r.name);
                if r.dir {
                    inv.push(Entry {
                        path: format!("{p}/"),
                        kind: Kind::Dir,
                        size: Some(0),
                        modified: r.modified,
                        mode: r.mode,
                        ..Entry::default()
                    });
                    if depth < MAX_DEPTH {
                        stack.push((r.extent, r.size, format!("{p}/"), depth + 1));
                    }
                } else if let Some(target) = r.link {
                    inv.push(Entry {
                        path: p,
                        kind: Kind::Symlink,
                        size: Some(0),
                        link: Some(target),
                        modified: r.modified,
                        mode: r.mode,
                        ..Entry::default()
                    });
                } else if r.more {
                    pending = Some((r.name, u64::from(r.size), r.extent, r.modified));
                } else {
                    let at = (!r.interleaved).then(|| u64::from(r.extent) * self.block);
                    let e = Entry {
                        path: p.clone(),
                        kind: Kind::File,
                        size: Some(u64::from(r.size)),
                        compressed: Some(u64::from(r.size)),
                        modified: r.modified,
                        mode: r.mode,
                        ..Entry::default()
                    };
                    if let Some(at) = at
                        && wanted(&e)
                        && files.len() < cx.child_room()
                    {
                        files.push(File::Stored((p, at, u64::from(r.size))));
                    }
                    inv.push(e);
                }
            }
            if let Some((name, sum, _, modified)) = pending {
                push_file(inv, &path, &name, sum, modified);
            }
        }
        Ok(names)
    }

    /// The SUSP skip length when the root's `.` record starts with `SP`.
    fn rock_ridge(&self, src: &mut dyn Source, root: u32) -> Option<usize> {
        let d = src.read_vec(u64::from(root) * self.block, 256).ok()?;
        let len = usize::from(*d.first()?);
        let nl = usize::from(*d.get(32)?);
        let su = 33 + nl + usize::from(nl % 2 == 0);
        let sp = d.get(su..len)?;
        (sp.starts_with(b"SP") && sp.get(4..6) == Some(&[0xBE, 0xEF])).then(|| usize::from(sp[6]))
    }
}

/// A file spread over several extents: listed, not handed on.
fn push_file(inv: &mut Inventory, path: &str, name: &str, size: u64, modified: Option<String>) {
    inv.push(Entry {
        path: format!("{path}{name}"),
        kind: Kind::File,
        size: Some(size),
        compressed: Some(size),
        modified,
        ..Entry::default()
    });
}

/// One directory record, names resolved.
#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)] // the record's flags, as stored
struct Record {
    name: String,
    dir: bool,
    extent: u32,
    size: u32,
    modified: Option<String>,
    mode: Option<u32>,
    link: Option<String>,
    /// More records continue this file (multi-extent).
    more: bool,
    interleaved: bool,
    /// Rock Ridge: a directory moved elsewhere (`RE`), listed through its `CL` link.
    relocated: bool,
}

struct Walker {
    block: u64,
    joliet: bool,
    rr_skip: Option<usize>,
}

impl Walker {
    fn records(&self, src: &mut dyn Source, data: &[u8]) -> Vec<Record> {
        let mut out = Vec::new();
        let mut at = 0;
        let block = usize::try_from(self.block).unwrap_or(2048);
        while at < data.len() {
            let len = usize::from(data[at]);
            if len == 0 {
                // Records do not cross sector boundaries.
                at = (at / block + 1) * block;
                continue;
            }
            let Some(r) = data.get(at..at + len) else { break };
            at += len;
            if r.len() < 34 {
                continue;
            }
            let nl = usize::from(r[32]);
            let Some(raw) = r.get(33..33 + nl) else { continue };
            if nl == 1 && raw[0] <= 1 {
                continue;
            }
            let flags = r[25];
            let mut rec = Record {
                dir: flags & 0x02 != 0,
                extent: le32(r, 2).unwrap_or(0),
                size: le32(r, 10).unwrap_or(0),
                modified: record_date(&r[18..25]),
                more: flags & 0x80 != 0,
                interleaved: r[26] != 0,
                ..Record::default()
            };
            if flags & 0x04 != 0 {
                continue;
            }
            rec.name = if self.joliet { volume::utf16_field(raw, false).unwrap_or_default() } else { iso_name(raw) };
            if let Some(skip) = self.rr_skip {
                let su = 33 + nl + usize::from(nl % 2 == 0) + skip;
                if let Some(area) = r.get(su..) {
                    self.susp(src, area, &mut rec, 0);
                }
            }
            if rec.name.is_empty() {
                continue;
            }
            out.push(rec);
        }
        out
    }

    /// Rock Ridge entries in a system-use area.
    fn susp(&self, src: &mut dyn Source, mut area: &[u8], rec: &mut Record, depth: u32) {
        let mut nm = String::new();
        let mut link: Vec<String> = Vec::new();
        let mut piece = String::new();
        while area.len() >= 4 {
            let len = usize::from(area[2]);
            if len < 4 || len > area.len() {
                break;
            }
            let (sig, data) = (&area[..2], &area[4..len]);
            match sig {
                b"NM" if !data.is_empty() && data[0] & 0x06 == 0 => nm.push_str(&String::from_utf8_lossy(&data[1..])),
                b"PX" => rec.mode = le32(data, 0).map(|m| m & 0o7777),
                b"SL" if !data.is_empty() => {
                    let mut c = &data[1..];
                    while c.len() >= 2 {
                        let (f, n) = (c[0], usize::from(c[1]));
                        let Some(content) = c.get(2..2 + n) else { break };
                        match f & 0x0E {
                            0x02 => piece.push('.'),
                            0x04 => piece.push_str(".."),
                            0x08 => piece.push('/'),
                            _ => piece.push_str(&String::from_utf8_lossy(content)),
                        }
                        if f & 1 == 0 {
                            link.push(std::mem::take(&mut piece));
                        }
                        c = &c[2 + n..];
                    }
                }
                b"TF" if !data.is_empty() => {
                    let long = data[0] & 0x80 != 0;
                    let size = if long { 17 } else { 7 };
                    let skip = usize::from(data[0] & 1 != 0) * size;
                    if data[0] & 2 != 0
                        && let Some(t) = data.get(1 + skip..1 + skip + size)
                    {
                        rec.modified = if long { volume_date(t) } else { record_date(t) };
                    }
                }
                b"CL" => {
                    if let Some(l) = le32(data, 0) {
                        rec.extent = l;
                        rec.dir = true;
                        rec.size = u32::try_from(self.block).unwrap_or(2048);
                    }
                }
                b"RE" => rec.relocated = true,
                b"CE" if depth < 4 => {
                    if let (Some(b), Some(o), Some(n)) = (le32(data, 0), le32(data, 8), le32(data, 16))
                        && let Ok(more) = src.read_vec(
                            u64::from(b) * self.block + u64::from(o),
                            usize::try_from(n.min(4096)).unwrap_or(0),
                        )
                    {
                        self.susp(src, &more, rec, depth + 1);
                    }
                }
                b"ST" => break,
                _ => {}
            }
            area = &area[len..];
        }
        if !nm.is_empty() {
            rec.name = nm;
        }
        if !link.is_empty() {
            let mut t = String::new();
            for (i, p) in link.iter().enumerate() {
                if i > 0 && !t.ends_with('/') {
                    t.push('/');
                }
                t.push_str(p);
            }
            rec.link = Some(t);
        }
    }
}

/// An ISO 9660 file identifier without its `;1` version and empty extension.
fn iso_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let s = s.split(';').next().unwrap_or("");
    s.strip_suffix('.').unwrap_or(s).to_string()
}

// ---------------------------------------------------------------- El Torito

fn boot(src: &mut dyn Source, cx: &mut Context<'_>, lba: u32) -> Result<(), ExtractError> {
    let Ok(cat) = src.read_vec(u64::from(lba) * SECTOR, 2048) else { return Ok(()) };
    if cat[0] != 1 || cat[30..32] != [0x55, 0xAA] {
        return Ok(());
    }
    let mut entries = Vec::new();
    let mut platform = cat[1];
    let mut images = Vec::new();
    let mut add = |e: &[u8], platform: u8, entries: &mut Vec<Value>| {
        let media = match e[1] & 0x0F {
            0 => "no_emulation",
            1 => "floppy_1.2m",
            2 => "floppy_1.44m",
            3 => "floppy_2.88m",
            4 => "hard_disk",
            _ => "other",
        };
        let platform = match platform {
            0 => "x86",
            1 => "PowerPC",
            2 => "Mac",
            0xEF => "EFI",
            _ => "other",
        };
        let (count, rba) = (le16(e, 6).unwrap_or(0), le32(e, 8).unwrap_or(0));
        let mut m = Map::new();
        m.insert("platform".into(), json!(platform));
        m.insert("media".into(), json!(media));
        m.insert("bootable".into(), json!(e[0] == 0x88));
        m.insert("load_sectors".into(), json!(count));
        m.insert("image_block".into(), json!(rba));
        entries.push(Value::Object(m));
        images.push((platform, rba, count));
    };
    add(&cat[32..64], platform, &mut entries);
    let mut at = 64;
    while at + 32 <= cat.len() && entries.len() < MAX_BOOT {
        let h = &cat[at..at + 32];
        if h[0] != 0x90 && h[0] != 0x91 {
            break;
        }
        platform = h[1];
        let n = usize::from(le16(h, 2).unwrap_or(0));
        at += 32;
        for _ in 0..n {
            let Some(e) = cat.get(at..at + 32) else { break };
            if entries.len() < MAX_BOOT {
                add(e, platform, &mut entries);
            }
            at += 32;
        }
        if h[0] == 0x91 {
            break;
        }
    }
    cx.format_set("boot", entries);
    // EFI boot images are FAT volumes; their size is in their boot sector.
    for (i, (platform, rba, count)) in images.into_iter().enumerate() {
        if platform != "EFI" {
            continue;
        }
        let at = u64::from(rba) * SECTOR;
        let Ok(bs) = src.read_vec(at, 512) else { continue };
        let size = fat_geometry(&bs).map_or(u64::from(count) * 512, |g| u64::from(g.total) * u64::from(g.sector));
        let size = size.min(src.len().saturating_sub(at)).min(cx.parse_limit() as u64);
        if size == 0 {
            continue;
        }
        let data = src.read_vec(at, usize::try_from(size).unwrap_or(0))?;
        if !child(cx, &format!("[boot]/efi-{i}.img"), data, true)? {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- UDF

/// A UDF timestamp (ECMA-167 1/7.3).
fn udf_time(b: &[u8]) -> Option<String> {
    let tz = le16(b, 0)?;
    let year = le16(b, 2)?;
    let (mo, d, h, mi, s) = (*b.get(4)?, b[5], b[6], b[7], b[8]);
    if year == 0 || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let mut minutes = i32::from(tz & 0x0FFF);
    if minutes >= 0x800 {
        minutes -= 0x1000;
    }
    let off = if tz >> 12 == 1 && minutes != -2047 { offset(minutes) } else { "Z".into() };
    Some(format!("{year:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}{off}"))
}

/// A UDF `dstring` / `d-characters` field (compression id 8 or 16).
fn dchars(b: &[u8]) -> Option<String> {
    match *b.first()? {
        8 => Some(b[1..].iter().filter(|&&c| c != 0).map(|&c| char::from(c)).collect()),
        16 => volume::utf16_field(&b[1..], false),
        _ => None,
    }
    .filter(|s: &String| !s.is_empty())
}

/// A fixed-length `dstring` (its last byte is the length used).
fn dstring(b: &[u8]) -> Option<String> {
    let n = usize::from(*b.last()?);
    dchars(b.get(..n)?)
}

/// How a partition reference maps to the image.
#[derive(Debug, Clone)]
enum PartMap {
    /// A physical partition starting at this sector.
    Physical(u64),
    /// A metadata partition: the metadata file's extents (sector, bytes).
    Metadata(Vec<(u64, u64)>),
}

struct Udf {
    block: u64,
    revision: Option<u16>,
    volume_id: Option<String>,
    volume_set: Option<String>,
    logical_id: Option<String>,
    recorded: Option<String>,
    maps: Vec<PartMap>,
    fsd: Option<(u32, u16)>,
    partition_bytes: u64,
    /// A write-once disc's virtual partition (VAT).
    virtual_partition: bool,
}

impl Udf {
    fn open(src: &mut dyn Source) -> Option<Self> {
        // The anchor is at block 256 (or the last block), in the medium's
        // block size: 2048 for optical discs, 512 for hard-disk images.
        let len = src.len();
        let (block, avdp) = [2048u64, 512, 4096, 1024].into_iter().find_map(|bs| {
            [256, (len / bs).saturating_sub(1)].into_iter().find_map(|at| {
                let d = src.read_vec(at * bs, 512).ok()?;
                (le16(&d, 0)? == 2 && u64::from(le32(&d, 12)?) == at).then_some((bs, d))
            })
        })?;
        let (vds_len, vds_at) = (le32(&avdp, 16)?, le32(&avdp, 20)?);
        let mut u = Udf {
            block,
            revision: None,
            volume_id: None,
            volume_set: None,
            logical_id: None,
            recorded: None,
            maps: Vec::new(),
            fsd: None,
            partition_bytes: 0,
            virtual_partition: false,
        };
        let mut partitions: Vec<(u16, u64, u64)> = Vec::new();
        let mut map_table: Vec<u8> = Vec::new();
        let mut map_count = 0;
        for i in 0..(u64::from(vds_len) / block).min(MAX_DESCRIPTORS) {
            let Ok(d) = src.read_vec((u64::from(vds_at) + i) * block, usize::try_from(block.max(512)).ok()?) else {
                break;
            };
            match le16(&d, 0)? {
                1 => {
                    u.volume_id = dstring(&d[24..56]);
                    u.volume_set = dstring(&d[72..200]);
                    u.recorded = udf_time(&d[376..388]);
                }
                5 => partitions.push((le16(&d, 22)?, u64::from(le32(&d, 188)?), u64::from(le32(&d, 192)?))),
                6 => {
                    u.block = u64::from(le32(&d, 212)?).clamp(512, 65536);
                    u.logical_id = dstring(&d[84..212]);
                    if d[217..240].starts_with(b"*OSTA UDF Compliant") {
                        u.revision = le16(&d, 240);
                    }
                    u.fsd = Some((le32(&d, 252)?, le16(&d, 256)?));
                    let n = le32(&d, 264)? as usize;
                    map_count = le32(&d, 268)?;
                    map_table = d.get(440..(440 + n).min(d.len()))?.to_vec();
                }
                8 => break,
                _ => {}
            }
        }
        let start_of = |n: u16| partitions.iter().find(|p| p.0 == n).map(|p| (p.1, p.2));
        let mut at = 0;
        for _ in 0..map_count.min(16) {
            let (Some(&ty), Some(&len)) = (map_table.get(at), map_table.get(at + 1)) else { break };
            let m = &map_table[at..(at + usize::from(len)).min(map_table.len())];
            match ty {
                1 => {
                    let (start, len) = start_of(le16(m, 4)?)?;
                    u.partition_bytes += len * u.block;
                    u.maps.push(PartMap::Physical(start));
                }
                2 if m.get(5..28).is_some_and(|id| id.starts_with(b"*UDF Metadata Partition")) => {
                    let (start, len) = start_of(le16(m, 38)?)?;
                    u.partition_bytes += len * u.block;
                    let file = le32(m, 40)?;
                    // The metadata file's extents, relative to its partition.
                    let fe = src.read_vec((start + u64::from(file)) * u.block, usize::try_from(u.block).ok()?).ok()?;
                    let (_, ads, kind, _) = file_entry(&fe)?;
                    let extents =
                        extents(ads, kind).into_iter().map(|(lbn, n, _)| (start + u64::from(lbn), n)).collect();
                    u.maps.push(PartMap::Metadata(extents));
                }
                2 => {
                    // Sparable maps read as their physical partition (bad
                    // blocks aside); virtual (VAT) maps need the allocation
                    // table at the end of the last session: not listed.
                    if m.get(5..27).is_some_and(|id| id.starts_with(b"*UDF Virtual Partition")) {
                        u.virtual_partition = true;
                    }
                    let (start, _) = start_of(le16(m, 38)?)?;
                    u.maps.push(PartMap::Physical(start));
                }
                _ => break,
            }
            at += usize::from(len.max(1));
        }
        (!u.maps.is_empty()).then_some(u)
    }

    fn report(&self, cx: &mut Context<'_>, alone: bool) {
        let mut m = Map::new();
        if let Some(r) = self.revision {
            m.insert("revision".into(), json!(format!("{}.{:02x}", r >> 8, r & 0xFF)));
        }
        for (k, v) in [
            ("volume_id", &self.volume_id),
            ("volume_set_id", &self.volume_set),
            ("logical_volume_id", &self.logical_id),
            ("recorded", &self.recorded),
        ] {
            if let Some(v) = v {
                m.insert(k.into(), json!(v));
            }
        }
        m.insert("block_size".into(), json!(self.block));
        m.insert("partition_bytes".into(), json!(self.partition_bytes));
        if self.maps.iter().any(|p| matches!(p, PartMap::Metadata(_))) {
            m.insert("metadata_partition".into(), json!(true));
        }
        if self.virtual_partition {
            m.insert("virtual_partition".into(), json!(true));
        }
        if alone {
            if let Some(t) = self.logical_id.clone().or_else(|| self.volume_id.clone()) {
                cx.content().title(t);
            }
            if let Some(t) = &self.recorded {
                cx.temporal().content_date(crate::plugin::DateField::Created, t.clone(), true);
            }
        }
        if alone {
            for (k, v) in m {
                cx.format_set(&k, v);
            }
        } else {
            cx.format_set("udf", Value::Object(m));
        }
    }

    /// Image byte offset of logical block `lbn` in partition `part`.
    fn locate(&self, lbn: u32, part: u16) -> Option<u64> {
        match self.maps.get(usize::from(part))? {
            PartMap::Physical(start) => Some((start + u64::from(lbn)) * self.block),
            PartMap::Metadata(ext) => {
                let mut off = u64::from(lbn) * self.block;
                for &(sector, len) in ext {
                    if off < len {
                        return Some(sector * self.block + off);
                    }
                    off -= len;
                }
                None
            }
        }
    }

    fn read_block(&self, src: &mut dyn Source, lbn: u32, part: u16) -> Option<Vec<u8>> {
        src.read_vec(self.locate(lbn, part)?, usize::try_from(self.block).ok()?).ok()
    }

    /// Walk from the root; `false` when the root cannot be found.
    fn walk(
        &self,
        src: &mut dyn Source,
        cx: &mut Context<'_>,
        inv: &mut Inventory,
        files: &mut Vec<File>,
    ) -> Result<bool, ExtractError> {
        if self.virtual_partition {
            cx.warn("UDF virtual partition (VAT): files not listed");
            return Ok(false);
        }
        let Some((lbn, part)) = self.fsd else { return Ok(false) };
        let Some(fsd) = self.read_block(src, lbn, part) else { return Ok(false) };
        if le16(&fsd, 0) != Some(256) {
            return Ok(false);
        }
        let (Some(root), Some(root_part)) = (le32(&fsd, 404), le16(&fsd, 408)) else { return Ok(false) };
        let mut stack = vec![(root, root_part, String::new(), 0usize)];
        let mut seen = HashSet::new();
        while let Some((lbn, part, path, depth)) = stack.pop() {
            cx.checkpoint()?;
            if !seen.insert((lbn, part)) {
                continue;
            }
            let Some(fe) = self.read_block(src, lbn, part) else { continue };
            let Some((_, ads, kind, _)) = file_entry(&fe) else { continue };
            let data = self.data(src, ads, kind, part, MAX_DIR, cx)?;
            for fid in fids(&data) {
                if inv.entries >= MAX_ENTRIES as u64 {
                    inv.truncated = true;
                    return Ok(true);
                }
                let p = format!("{path}{}", fid.name);
                let Some(entry) = self.read_block(src, fid.lbn, fid.part) else { continue };
                let Some((info, ads, kind, ty)) = file_entry(&entry) else { continue };
                let modified = udf_time(&entry[if le16(&entry, 0) == Some(266) { 92 } else { 84 }..][..12]);
                match ty {
                    4 => {
                        inv.push(Entry {
                            path: format!("{p}/"),
                            kind: Kind::Dir,
                            size: Some(0),
                            modified,
                            ..Entry::default()
                        });
                        if depth < MAX_DEPTH {
                            stack.push((fid.lbn, fid.part, format!("{p}/"), depth + 1));
                        }
                    }
                    12 => {
                        let target = self.data(src, ads, kind, fid.part, 4096, cx)?;
                        inv.push(Entry {
                            path: p,
                            kind: Kind::Symlink,
                            size: Some(0),
                            link: symlink_target(&target),
                            modified,
                            ..Entry::default()
                        });
                    }
                    _ => {
                        let e = Entry {
                            path: p.clone(),
                            kind: Kind::File,
                            size: Some(info),
                            compressed: Some(info),
                            modified,
                            ..Entry::default()
                        };
                        if wanted(&e) && files.len() < cx.child_room() {
                            let ext = extents(ads, kind);
                            if kind == 3 {
                                files.push(File::Inline(
                                    p,
                                    ads.get(..usize::try_from(info).unwrap_or(0)).unwrap_or(ads).to_vec(),
                                ));
                            } else if let [(lbn, n, p2)] = ext[..]
                                && n >= info
                                && let Some(at) = self.locate(lbn, p2.unwrap_or(fid.part))
                            {
                                files.push(File::Stored((p, at, info)));
                            } else if !ext.is_empty() {
                                let limit = (cx.parse_limit() as u64).min(info);
                                let data = self.data(src, ads, kind, fid.part, limit, cx)?;
                                files.push(File::Inline(p, data));
                            }
                        }
                        inv.push(e);
                    }
                }
            }
        }
        Ok(true)
    }

    /// A file's data from its allocation descriptors, at most `max` bytes.
    fn data(
        &self,
        src: &mut dyn Source,
        ads: &[u8],
        kind: u16,
        part: u16,
        max: u64,
        cx: &mut Context<'_>,
    ) -> Result<Vec<u8>, ExtractError> {
        if kind == 3 {
            return Ok(ads.to_vec());
        }
        let mut out = Vec::new();
        for (lbn, n, p) in extents(ads, kind) {
            cx.checkpoint()?;
            let Some(at) = self.locate(lbn, p.unwrap_or(part)) else { break };
            let n = n.min(max - out.len() as u64).min(src.len().saturating_sub(at));
            out.extend(src.read_vec(at, usize::try_from(n).unwrap_or(0))?);
            if out.len() as u64 >= max {
                break;
            }
        }
        Ok(out)
    }
}

/// A file entry (tag 261) or extended file entry (tag 266): `(information
/// length, allocation descriptors, descriptor kind, file type)`.
fn file_entry(b: &[u8]) -> Option<(u64, &[u8], u16, u8)> {
    let (ea_at, base) = match le16(b, 0)? {
        261 => (168, 176),
        266 => (208, 216),
        _ => return None,
    };
    let ty = *b.get(16 + 11)?;
    let kind = le16(b, 16 + 18)? & 7;
    let info = le64(b, 56)?;
    let (ea, ad) = (le32(b, ea_at)? as usize, le32(b, ea_at + 4)? as usize);
    let ads = b.get(base + ea..base + ea + ad)?;
    Some((info, ads, kind, ty))
}

/// Recorded extents `(block, bytes, partition)` of short (0) or long (1)
/// allocation descriptors.
fn extents(ads: &[u8], kind: u16) -> Vec<(u32, u64, Option<u16>)> {
    let size = match kind {
        0 => 8,
        1 => 16,
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for ad in ads.chunks_exact(size).take(4096) {
        let len = le32(ad, 0).unwrap_or(0);
        let (ty, n) = (len >> 30, u64::from(len & 0x3FFF_FFFF));
        if n == 0 || ty == 3 {
            break;
        }
        let lbn = le32(ad, 4).unwrap_or(0);
        let part = (kind == 1).then(|| le16(ad, 8).unwrap_or(0));
        if ty == 0 {
            out.push((lbn, n, part));
        }
    }
    out
}

struct Fid {
    name: String,
    lbn: u32,
    part: u16,
}

/// File identifier descriptors of a directory.
fn fids(data: &[u8]) -> Vec<Fid> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 38 <= data.len() {
        if le16(data, at) != Some(257) {
            break;
        }
        let ch = data[at + 18];
        let lfi = usize::from(data[at + 19]);
        let liu = usize::from(le16(data, at + 36).unwrap_or(0));
        let name_at = at + 38 + liu;
        let len = (38 + liu + lfi + 3) & !3;
        if ch & 0x0C == 0
            && lfi > 0
            && let Some(name) = data.get(name_at..name_at + lfi).and_then(dchars)
        {
            out.push(Fid { name, lbn: le32(data, at + 24).unwrap_or(0), part: le16(data, at + 28).unwrap_or(0) });
        }
        at += len;
    }
    out
}

/// A UDF symbolic link's path components (ECMA-167 4/14.16).
fn symlink_target(b: &[u8]) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut at = 0;
    let mut absolute = false;
    while at + 4 <= b.len() {
        let (ty, n) = (b[at], usize::from(b[at + 1]));
        let id = b.get(at + 4..at + 4 + n)?;
        match ty {
            1 | 2 => {
                absolute = true;
                parts.clear();
            }
            3 => parts.push("..".into()),
            4 => parts.push(".".into()),
            5 => parts.push(dchars(id).unwrap_or_default()),
            _ => {}
        }
        at += 4 + n;
    }
    let joined = parts.join("/");
    (!joined.is_empty() || absolute).then(|| if absolute { format!("/{joined}") } else { joined })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_names() {
        assert_eq!(volume_date(b"2024061512304500\x08").as_deref(), Some("2024-06-15T12:30:45+02:00"));
        assert_eq!(volume_date(b"0000000000000000\0"), None);
        assert_eq!(record_date(&[124, 6, 15, 12, 30, 45, 0xFC]).as_deref(), Some("2024-06-15T12:30:45-01:00"));
        assert_eq!(iso_name(b"README.TXT;1"), "README.TXT");
        assert_eq!(iso_name(b"MAKEFILE.;1"), "MAKEFILE");
        let mut t = [0u8; 12];
        t[..2].copy_from_slice(&(0x1000u16 | 0x3C).to_le_bytes());
        t[2..4].copy_from_slice(&2024u16.to_le_bytes());
        t[4..9].copy_from_slice(&[6, 15, 12, 30, 45]);
        assert_eq!(udf_time(&t).as_deref(), Some("2024-06-15T12:30:45+01:00"));
        assert_eq!(dchars(b"\x08Tides").as_deref(), Some("Tides"));
        assert_eq!(dstring(b"\x08Tides\0\0\x06").as_deref(), Some("Tides"));
        let link = [2u8, 0, 0, 0, 5, 4, 0, 0, 8, b'e', b't', b'c'];
        assert_eq!(symlink_target(&link).as_deref(), Some("/etc"));
    }

    crate::fixture_tests!("iso9660", "udf");
}
