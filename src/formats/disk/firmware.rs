//! Firmware images: U-Boot legacy images (`uImage`: name, creation time,
//! OS, architecture, image type, compression, load and entry addresses,
//! header and data checksums checked), FIT images (a device tree whose
//! `/images` and `/configurations` nodes list the kernels, ramdisks and
//! device trees with their types, architectures, hashes and signatures),
//! Intel HEX and Motorola S-record files (records, data bytes, address
//! ranges, start address, header text, checksum errors) and UEFI capsules
//! (capsule kind and flags; FMP payloads: image type GUIDs, indexes,
//! sizes, signing and firmware versions). Image payloads are handed on.
//!
//! Specifications: U-Boot `include/image.h` and `doc/usage/fit/`; the
//! Devicetree Specification 0.4 (flattened format); Intel "Hexadecimal
//! Object File Format Specification" rev. A; Motorola S-record (`srec(5)`);
//! UEFI 2.10 §23 (capsules, FMP).

use serde_json::{Map, Value, json};

use super::archive::{Stored, stored_children};
use crate::plugin::volume::num::{be32, be64, le16, le32, le64};
use crate::plugin::volume::{guid_le, text_field, unix_time};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, codec,
};

/// Extractor for firmware images.
pub struct Firmware;

/// Capsule GUIDs (on-disk byte order): FMP, EFI, EFI 2, UEFI, Windows UX.
const CAPSULES: [(&[u8], &str); 5] = [
    (b"\xed\xd5\xcb\x6d\x2d\xe8\x44\x4c\xbd\xa1\x71\x94\x19\x9a\xd9\x2a", "fmp"),
    (b"\xbd\x86\x66\x3b\x76\x0d\x30\x40\xb7\x0e\xb5\x51\x9e\x2f\xc5\xa0", "efi"),
    (b"\x8b\xa6\x3c\x4a\x23\x77\xfb\x48\x80\x3d\x57\x8c\xc1\xfe\xc4\x4d", "efi2"),
    (b"\xb9\x82\x91\x53\xb5\xab\x91\x43\xb6\x9a\xe3\xa9\x43\xf7\x2f\xcc", "uefi"),
    (b"\x62\x81\x8c\x3b\x8c\x18\xa4\x46\xae\xc9\xbe\x43\xf1\xd6\x56\x97", "windows_ux"),
];

static META: ExtractorMeta = ExtractorMeta {
    id: "disk.firmware",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "uimage",
            name: "U-Boot legacy image",
            family: "disk",
            mimes: &["application/x-uboot-image"],
            extensions: &["uimg", "uimage", "ub"],
            magic: &[Magic::prefix(b"\x27\x05\x19\x56")],
            parent: None,
        },
        FormatSpec {
            id: "fit",
            name: "U-Boot FIT image",
            family: "disk",
            mimes: &["application/x-uboot-fit"],
            extensions: &["itb", "fit"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "intel_hex",
            name: "Intel HEX",
            family: "disk",
            mimes: &["text/x-hex"],
            extensions: &["hex", "ihex", "ihx"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "srec",
            name: "Motorola S-record",
            family: "disk",
            mimes: &["text/x-srecord"],
            extensions: &["srec", "s19", "s28", "s37", "mot"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "uefi_capsule",
            name: "UEFI capsule",
            family: "disk",
            mimes: &["application/x-uefi-capsule"],
            extensions: &["cap", "scap"],
            magic: &[
                Magic::prefix(CAPSULES[0].0),
                Magic::prefix(CAPSULES[1].0),
                Magic::prefix(CAPSULES[2].0),
                Magic::prefix(CAPSULES[3].0),
                Magic::prefix(CAPSULES[4].0),
            ],
            parent: None,
        },
    ],
};

/// Records read from a text firmware file at most.
const MAX_RECORDS: usize = 1 << 20;

impl Extractor for Firmware {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.starts_with(b"\xd0\x0d\xfe\xed") && h.windows(7).any(|w| w == b"\x01images") {
            return Some(Sniff { format: "fit", confidence: 0.95 });
        }
        let first: Vec<&[u8]> = h
            .split(|&b| b == b'\n')
            .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
            .filter(|l| !l.is_empty())
            .take(3)
            .collect();
        if first.len() >= 2 && first.iter().all(|l| ihex_record(l).is_some_and(|r| r.ok)) {
            return Some(Sniff { format: "intel_hex", confidence: 0.92 });
        }
        if first.len() >= 2 && first.iter().all(|l| srec_record(l).is_some_and(|r| r.ok)) {
            return Some(Sniff { format: "srec", confidence: 0.92 });
        }
        None
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "uimage" => uimage(src, cx),
            "fit" => fit(src, cx),
            "intel_hex" | "srec" => text_records(src, cx),
            _ => capsule(src, cx),
        }
    }
}

crate::register_extractor!(Firmware);

// ---------------------------------------------------------------- uImage

fn uimage_os(n: u8) -> &'static str {
    match n {
        1 => "OpenBSD",
        2 => "NetBSD",
        3 => "FreeBSD",
        5 => "Linux",
        8 => "Solaris",
        14 => "VxWorks",
        16 => "QNX",
        17 => "U-Boot",
        18 => "RTEMS",
        21 => "INTEGRITY",
        25 => "ARM Trusted Firmware",
        26 => "TEE",
        27 => "OpenSBI",
        28 => "EFI",
        _ => "other",
    }
}

fn uimage_arch(n: u8) -> &'static str {
    match n {
        1 => "alpha",
        2 => "arm",
        3 => "x86",
        4 => "ia64",
        5 => "mips",
        6 => "mips64",
        7 => "powerpc",
        8 => "s390",
        9 => "sh",
        10 => "sparc",
        11 => "sparc64",
        12 => "m68k",
        14 => "microblaze",
        15 => "nios2",
        19 => "sandbox",
        21 => "openrisc",
        22 => "arm64",
        23 => "arc",
        24 => "x86_64",
        25 => "xtensa",
        26 => "riscv",
        _ => "other",
    }
}

fn uimage_type(n: u8) -> &'static str {
    match n {
        1 => "standalone",
        2 => "kernel",
        3 => "ramdisk",
        4 => "multi",
        5 => "firmware",
        6 => "script",
        7 => "filesystem",
        8 => "flat_dt",
        _ => "other",
    }
}

fn uimage_comp(n: u8) -> &'static str {
    match n {
        0 => "none",
        1 => "gzip",
        2 => "bzip2",
        3 => "lzma",
        4 => "lzo",
        5 => "lz4",
        6 => "zstd",
        _ => "other",
    }
}

fn uimage(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 64)?;
    let size = u64::from(be32(&h, 12).unwrap_or(0));
    let mut copy = h.clone();
    copy[4..8].fill(0);
    cx.format_set("header_crc_ok", codec::crc32(&copy) == be32(&h, 4).unwrap_or(0));
    if let Some(n) = text_field(&h[32..64]) {
        cx.format_set("name", n.clone());
        cx.content().title(n);
    }
    if let Some(t) = unix_time(i64::from(be32(&h, 8).unwrap_or(0))) {
        cx.format_set("created", t.clone());
        cx.temporal().content_date(crate::plugin::DateField::Created, t, true);
    }
    cx.format_set("os", uimage_os(h[28]));
    cx.format_set("architecture", uimage_arch(h[29]));
    cx.format_set("image_type", uimage_type(h[30]));
    cx.format_set("compression", uimage_comp(h[31]));
    cx.format_set("load_address", format!("{:#x}", be32(&h, 16).unwrap_or(0)));
    cx.format_set("entry_point", format!("{:#x}", be32(&h, 20).unwrap_or(0)));
    cx.format_set("data_bytes", size);
    let len = src.len();
    if 64 + size > len {
        cx.warn("data runs past the end of the file");
        return Ok(());
    }
    if size <= cx.parse_limit() as u64 {
        let data = src.read_vec(64, usize::try_from(size).unwrap_or(0))?;
        cx.format_set("data_crc_ok", codec::crc32(&data) == be32(&h, 24).unwrap_or(0));
    }
    let mut parts: Vec<Stored> = Vec::new();
    if h[30] == 4 {
        // Multi-file: a zero-terminated size list, then each file, 4-aligned.
        let list = src.read_vec(64, usize::try_from(size.min(4096)).unwrap_or(0))?;
        let sizes: Vec<u64> = list
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u64::from(u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
            .take_while(|&n| n != 0)
            .take(64)
            .collect();
        cx.format_set("files", sizes.clone());
        let mut at = 64 + 4 * (sizes.len() as u64 + 1);
        for (i, n) in sizes.into_iter().enumerate() {
            parts.push((format!("part{i}"), at, n));
            at += n.div_ceil(4) * 4;
        }
    } else {
        parts.push(("payload".into(), 64, size));
    }
    stored_children(src, cx, parts)
}

// ---------------------------------------------------------------- FIT (FDT)

/// One device-tree node: its path and properties `(name, value offset, length)`.
struct Node {
    path: String,
    props: Vec<(String, u64, usize)>,
}

/// Walk a flattened device tree into its nodes.
fn fdt(b: &[u8]) -> Option<Vec<Node>> {
    let (st, strings) = (be32(b, 8)? as usize, be32(b, 12)? as usize);
    let st_len = be32(b, 36).map_or(b.len().saturating_sub(st), |n| n as usize);
    let s = b.get(st..st + st_len.min(b.len().saturating_sub(st)))?;
    let mut nodes: Vec<Node> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut at = 0;
    while at + 4 <= s.len() && nodes.len() < 4096 {
        let tok = be32(s, at)?;
        at += 4;
        match tok {
            1 => {
                let end = s[at..].iter().position(|&c| c == 0)? + at;
                let name = String::from_utf8_lossy(&s[at..end]).into_owned();
                at = (end + 4) & !3;
                let parent = stack.last().map_or("", |&i| nodes[i].path.as_str());
                let path = if stack.is_empty() {
                    "/".into()
                } else if parent == "/" {
                    format!("/{name}")
                } else {
                    format!("{parent}/{name}")
                };
                nodes.push(Node { path, props: Vec::new() });
                stack.push(nodes.len() - 1);
                if stack.len() > 32 {
                    return None;
                }
            }
            2 => {
                stack.pop();
            }
            3 => {
                let (len, nameoff) = (be32(s, at)? as usize, be32(s, at + 4)? as usize);
                let name_at = strings + nameoff;
                let name_end = b.get(name_at..)?.iter().position(|&c| c == 0)? + name_at;
                let name = String::from_utf8_lossy(&b[name_at..name_end]).into_owned();
                let value_at = st + at + 8;
                if let Some(&i) = stack.last() {
                    nodes[i].props.push((name, value_at as u64, len));
                }
                at = (at + 8 + len + 3) & !3;
            }
            4 => {}
            _ => break,
        }
    }
    Some(nodes)
}

fn fit(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 40)?;
    let total = u64::from(be32(&h, 4).unwrap_or(0)).min(src.len());
    let b = src.read_vec(0, usize::try_from(total.min(cx.parse_limit() as u64)).unwrap_or(0))?;
    let nodes = fdt(&b).ok_or_else(|| ExtractError::malformed("device tree structure"))?;
    let prop = |n: &Node, k: &str| {
        n.props
            .iter()
            .find(|p| p.0 == k)
            .and_then(|&(_, at, len)| b.get(usize::try_from(at).ok()?..usize::try_from(at).ok()? + len))
    };
    let text = |v: &[u8]| text_field(v);
    let num = |v: &[u8]| match v.len() {
        4 => be32(v, 0).map(u64::from),
        8 => be64(v, 0),
        _ => None,
    };
    if let Some(root) = nodes.first() {
        if let Some(d) = prop(root, "description").and_then(text) {
            cx.format_set("description", d.clone());
            cx.content().title(d);
        }
        if let Some(t) = prop(root, "timestamp").and_then(num).and_then(|t| unix_time(i64::try_from(t).ok()?)) {
            cx.format_set("created", t);
        }
    }
    let mut images = Vec::new();
    let mut stored: Vec<Stored> = Vec::new();
    let mut signed = false;
    for n in nodes.iter().filter(|n| n.path.starts_with("/images/") && n.path.matches('/').count() == 2) {
        let name = n.path.trim_start_matches("/images/");
        let mut m = Map::new();
        m.insert("name".into(), json!(name));
        for k in ["description", "type", "arch", "os", "compression"] {
            if let Some(v) = prop(n, k).and_then(text) {
                m.insert(k.into(), json!(v));
            }
        }
        for k in ["load", "entry"] {
            if let Some(v) = prop(n, k).and_then(num) {
                m.insert(k.into(), json!(format!("{v:#x}")));
            }
        }
        if let Some((_, at, len)) = n.props.iter().find(|p| p.0 == "data") {
            m.insert("data_bytes".into(), json!(len));
            stored.push((format!("{name}.bin"), *at, *len as u64));
        } else if let Some(sz) = prop(n, "data-size").and_then(num) {
            m.insert("data_bytes".into(), json!(sz));
            m.insert("external_data".into(), json!(true));
        }
        let prefix = format!("{}/", n.path);
        let algos: Vec<String> = nodes
            .iter()
            .filter(|c| c.path.starts_with(&prefix) && c.path[prefix.len()..].starts_with("hash"))
            .filter_map(|c| prop(c, "algo").and_then(text))
            .collect();
        if !algos.is_empty() {
            m.insert("hashes".into(), json!(algos));
        }
        if nodes.iter().any(|c| c.path.starts_with(&prefix) && c.path[prefix.len()..].starts_with("signature")) {
            m.insert("signed".into(), json!(true));
            signed = true;
        }
        images.push(Value::Object(m));
    }
    cx.format_set("images", images);
    let mut configs = Vec::new();
    for n in nodes.iter().filter(|n| n.path.starts_with("/configurations/") && n.path.matches('/').count() == 2) {
        let mut m = Map::new();
        m.insert("name".into(), json!(n.path.trim_start_matches("/configurations/")));
        for k in ["description", "kernel", "fdt", "ramdisk", "firmware", "loadables"] {
            if let Some(v) = prop(n, k).and_then(text) {
                m.insert(k.into(), json!(v));
            }
        }
        if nodes.iter().any(|c| c.path.starts_with(&format!("{}/signature", n.path))) {
            m.insert("signed".into(), json!(true));
            signed = true;
        }
        configs.push(Value::Object(m));
    }
    if let Some(d) = nodes.iter().find(|n| n.path == "/configurations").and_then(|n| prop(n, "default")).and_then(text)
    {
        cx.format_set("default_configuration", d);
    }
    cx.format_set("configurations", configs);
    cx.security().signed(signed);
    stored_children(src, cx, stored)
}

// ---------------------------------------------------------------- Intel HEX / S-record

/// One decoded text record.
struct Record {
    kind: u8,
    address: u32,
    data: Vec<u8>,
    ok: bool,
}

fn hex_bytes(s: &[u8]) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_chunks::<2>().0.iter().map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok()).collect()
}

/// `:LLAAAATT<data>CC`.
fn ihex_record(line: &[u8]) -> Option<Record> {
    let b = hex_bytes(line.strip_prefix(b":")?)?;
    let n = usize::from(*b.first()?);
    if b.len() != n + 5 {
        return None;
    }
    let sum = b.iter().fold(0u8, |a, &x| a.wrapping_add(x));
    Some(Record {
        kind: b[3],
        address: u32::from(u16::from_be_bytes([b[1], b[2]])),
        data: b[4..4 + n].to_vec(),
        ok: sum == 0 && b[3] <= 5,
    })
}

/// `S<t><count><address><data><checksum>`.
fn srec_record(line: &[u8]) -> Option<Record> {
    let rest = line.strip_prefix(b"S")?;
    let kind = rest.first()?.checked_sub(b'0').filter(|&k| k <= 9 && k != 4)?;
    let b = hex_bytes(&rest[1..])?;
    let n = usize::from(*b.first()?);
    let alen = match kind {
        0 | 1 | 5 | 9 => 2,
        2 | 6 | 8 => 3,
        _ => 4,
    };
    if b.len() != n + 1 || n < alen + 1 {
        return None;
    }
    let sum = b[..b.len() - 1].iter().fold(0u8, |a, &x| a.wrapping_add(x));
    let address = b[1..=alen].iter().fold(0u32, |a, &x| (a << 8) | u32::from(x));
    Some(Record { kind, address, data: b[1 + alen..b.len() - 1].to_vec(), ok: !sum == b[b.len() - 1] })
}

fn text_records(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let ihex = cx.format_id() == "intel_hex";
    let (bytes, _) = cx.read_bytes(src)?;
    let (mut records, mut data, mut bad, mut errors) = (0u64, 0u64, 0u64, 0u64);
    let mut kinds = [0u64; 10];
    let (mut base, mut start, mut eof, mut header) = (0u32, None, false, None);
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for line in bytes
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter(|l| !l.is_empty())
        .take(MAX_RECORDS)
    {
        let r = if ihex { ihex_record(line) } else { srec_record(line) };
        let Some(r) = r else {
            bad += 1;
            continue;
        };
        records += 1;
        if !r.ok {
            errors += 1;
        }
        kinds[usize::from(r.kind.min(9))] += 1;
        let addr = match (ihex, r.kind) {
            (true, 0) => Some(base.wrapping_add(r.address)),
            (false, 1..=3) => Some(r.address),
            _ => None,
        };
        if let Some(a) = addr
            && !r.data.is_empty()
        {
            data += r.data.len() as u64;
            let end = a.wrapping_add(u32::try_from(r.data.len()).unwrap_or(0));
            match ranges.last_mut() {
                Some(last) if last.1 == a => last.1 = end,
                _ => ranges.push((a, end)),
            }
        }
        match (ihex, r.kind) {
            (true, 1) => eof = true,
            (true, 2) if r.data.len() == 2 => base = u32::from(u16::from_be_bytes([r.data[0], r.data[1]])) << 4,
            (true, 4) if r.data.len() == 2 => base = u32::from(u16::from_be_bytes([r.data[0], r.data[1]])) << 16,
            (true, 3 | 5) if r.data.len() == 4 => {
                start = Some(u32::from_be_bytes([r.data[0], r.data[1], r.data[2], r.data[3]]));
            }
            (false, 0) => header = text_field(&r.data),
            (false, 7..=9) => {
                start = Some(r.address);
                eof = true;
            }
            _ => {}
        }
    }
    cx.format_set("records", records);
    cx.format_set("data_bytes", data);
    if let (Some(lo), Some(hi)) = (ranges.iter().map(|r| r.0).min(), ranges.iter().map(|r| r.1).max()) {
        cx.format_set("address_range", json!([format!("{lo:#x}"), format!("{:#x}", hi.wrapping_sub(1))]));
    }
    ranges.sort_unstable();
    ranges.dedup_by(|b, a| {
        if b.0 <= a.1 {
            a.1 = a.1.max(b.1);
            true
        } else {
            false
        }
    });
    cx.format_set("segments", ranges.len());
    if let Some(s) = start {
        cx.format_set("start_address", format!("{s:#x}"));
    }
    if let Some(h) = header {
        cx.format_set("header", h);
    }
    cx.format_set("end_record", eof);
    if errors > 0 {
        cx.format_set("checksum_errors", errors);
    }
    if bad > 0 {
        cx.format_set("malformed_lines", bad);
    }
    if !ihex {
        let counts: Map<String, Value> =
            kinds.iter().enumerate().filter(|(_, n)| **n > 0).map(|(k, n)| (format!("S{k}"), json!(n))).collect();
        cx.format_set("record_types", Value::Object(counts));
    }
    Ok(())
}

// ---------------------------------------------------------------- UEFI capsule

fn capsule(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 28)?;
    let kind = CAPSULES.iter().find(|(g, _)| h.starts_with(g)).map_or("other", |c| c.1);
    cx.format_set("capsule", kind);
    if let Some(g) = guid_le(&h[..16]) {
        cx.format_set("capsule_guid", g);
    }
    let header = u64::from(le32(&h, 16).unwrap_or(0));
    let flags = le32(&h, 20).unwrap_or(0);
    cx.format_set("header_bytes", header);
    cx.format_set("image_bytes", le32(&h, 24).unwrap_or(0));
    let mut names = Vec::new();
    for (bit, name) in [(16, "persist_across_reset"), (17, "populate_system_table"), (18, "initiate_reset")] {
        if flags >> bit & 1 == 1 {
            names.push(name);
        }
    }
    cx.format_set("flags", names);
    if kind != "fmp" {
        return Ok(());
    }
    // FMP: a list of payload offsets after the embedded drivers.
    let Ok(fmp) = src.read_vec(header, 8) else { return Ok(()) };
    let (drivers, items) = (le16(&fmp, 4).unwrap_or(0), le16(&fmp, 6).unwrap_or(0));
    cx.format_set("embedded_drivers", drivers);
    let n = usize::from(drivers) + usize::from(items.min(64));
    let offsets = src.read_vec(header + 8, n * 8)?;
    let mut images = Vec::new();
    let mut stored: Vec<Stored> = Vec::new();
    let mut signed = false;
    for i in usize::from(drivers)..n {
        let at = header + le64(&offsets, 8 * i).unwrap_or(0);
        let Ok(e) = src.read_vec(at, 48) else { continue };
        let version = le32(&e, 0).unwrap_or(0);
        let mut m = Map::new();
        if let Some(g) = guid_le(&e[4..20]) {
            m.insert("image_type_id".into(), json!(g));
        }
        m.insert("index".into(), json!(e[20]));
        let size = u64::from(le32(&e, 24).unwrap_or(0));
        m.insert("size_bytes".into(), json!(size));
        let header_len = match version {
            1 => 32,
            2 => 40,
            _ => 48,
        };
        if version >= 2 {
            m.insert("hardware_instance".into(), json!(le64(&e, 32).unwrap_or(0)));
        }
        let mut payload = at + header_len;
        // An authenticated image: a monotonic count, then a WIN_CERTIFICATE.
        if let Ok(a) = src.read_vec(payload, 32)
            && le16(&a, 14) == Some(0x0EF1)
        {
            signed = true;
            m.insert("signed".into(), json!(true));
            let cert = u64::from(le32(&a, 8).unwrap_or(0));
            payload += 8 + cert;
        }
        if let Ok(p) = src.read_vec(payload, 16)
            && p.starts_with(b"MSS1")
        {
            m.insert("firmware_version".into(), json!(le32(&p, 8).unwrap_or(0)));
            m.insert("lowest_supported_version".into(), json!(le32(&p, 12).unwrap_or(0)));
        }
        stored.push((format!("image{}.bin", e[20]), at + header_len, size));
        images.push(Value::Object(m));
    }
    cx.format_set("images", images);
    cx.security().signed(signed);
    stored_children(src, cx, stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_records() {
        let r = ihex_record(b":10010000214601360121470136007EFE09D2190140").unwrap();
        assert!(r.ok && r.kind == 0 && r.address == 0x100 && r.data.len() == 16);
        assert!(!ihex_record(b":10010000214601360121470136007EFE09D2190141").unwrap().ok);
        let s = srec_record(b"S1137AF00A0A0D0000000000000000000000000061").unwrap();
        assert!(s.ok && s.kind == 1 && s.address == 0x7AF0);
        assert!(srec_record(b"S00F000068656C6C6F202020202000003C").unwrap().ok);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // a short test tree
    fn device_tree() {
        // / { a = <1>; n { }; };
        let mut s = Vec::new();
        for t in [1u32, 0, 3, 4, 0, 1, 1] {
            s.extend_from_slice(&t.to_be_bytes());
        }
        s.extend_from_slice(b"n\0\0\0");
        for t in [2u32, 2, 9] {
            s.extend_from_slice(&t.to_be_bytes());
        }
        let mut b = vec![0u8; 40];
        b[..4].copy_from_slice(b"\xd0\x0d\xfe\xed");
        b[8..12].copy_from_slice(&40u32.to_be_bytes());
        b[12..16].copy_from_slice(&(40 + s.len() as u32).to_be_bytes());
        b[36..40].copy_from_slice(&(s.len() as u32).to_be_bytes());
        b.extend_from_slice(&s);
        b.extend_from_slice(b"a\0");
        let nodes = fdt(&b).unwrap();
        assert_eq!(nodes.iter().map(|n| n.path.as_str()).collect::<Vec<_>>(), ["/", "/n"]);
        assert_eq!(nodes[0].props[0].0, "a");
    }

    crate::fixture_tests!("uimage", "fit", "intel_hex", "srec", "uefi_capsule");
}
