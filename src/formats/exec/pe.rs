//! Windows and DOS executables: PE32 / PE32+ images (EXE, DLL, SYS, EFI,
//! .NET assemblies), COFF object files, and the MS-DOS family (MZ, NE, LE
//! / LX). PE images report machine, subsystem, link time, linker and OS
//! versions, image base and entry point; sections (with entropy); imported
//! libraries and functions, delay-loaded libraries, exports; resources by
//! type, the version information (company, product, file description,
//! versions, copyright) and the manifest's requested execution level;
//! the CodeView debug record (PDB path, GUID, age), reproducible builds;
//! TLS callbacks; hardening (ASLR, high-entropy ASLR, DEP, CFG, SafeSEH,
//! /GS cookie, CET shadow stack, force integrity, AppContainer); the CLR
//! header of .NET assemblies (runtime and metadata versions, IL-only,
//! strong name); the Authenticode signature (signer, digest, timestamp,
//! chain); the Rich header's tool records; data appended after the image
//! (self-extracting archives and installers, handed on); and the toolchain
//! scan. NE and LE / LX headers give the target OS, module name and
//! description.
//!
//! Specifications: Microsoft PE / COFF specification; Authenticode PE
//! signature format; ECMA-335 (CLI header); the NE and LE / LX formats
//! (Microsoft and IBM documentation).

use serde_json::{Map, Value, json};

use super::{Section, addr, cli, hex, names, report_overlay, report_sections, scan_toolchain, unix_time};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, der,
};

/// Extractor for PE, COFF and MS-DOS executables.
pub struct Pe;

static META: ExtractorMeta = ExtractorMeta {
    id: "exec.pe",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "pe",
            name: "Windows PE executable / DLL",
            family: "exec",
            mimes: &["application/vnd.microsoft.portable-executable", "application/x-msdownload"],
            extensions: &["exe", "dll", "sys", "scr", "ocx", "cpl", "efi", "drv", "mui"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "dotnet",
            name: ".NET assembly (CLI)",
            family: "bytecode",
            mimes: &["application/vnd.microsoft.portable-executable"],
            extensions: &["winmd"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "dos_exe",
            name: "MS-DOS / NE / LE executables",
            family: "exec",
            mimes: &["application/x-dosexec", "application/x-ms-ne-executable"],
            extensions: &["com", "exe", "386", "vxd"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "coff",
            name: "Static library / COFF object",
            family: "exec",
            mimes: &["application/x-coff"],
            extensions: &["obj"],
            magic: &[],
            parent: None,
        },
    ],
};

const MAX_SECTIONS: usize = 96;
const MAX_IMPORT_LIBS: u32 = 512;
const MAX_FUNCTIONS: usize = 100_000;

fn machine(m: u16) -> Option<&'static str> {
    Some(match m {
        0x014c => "x86",
        0x8664 => "x86_64",
        0xaa64 => "arm64",
        0xa641 => "arm64ec",
        0x01c0 | 0x01c2 => "arm",
        0x01c4 => "arm_thumb2",
        0x0200 => "ia64",
        0x5032 => "riscv32",
        0x5064 => "riscv64",
        0x6232 => "loongarch32",
        0x6264 => "loongarch64",
        0x0ebc => "efi_bytecode",
        0x0166 => "mips",
        0x01f0 | 0x01f1 => "powerpc",
        _ => return None,
    })
}

fn subsystem(s: u16) -> Option<&'static str> {
    Some(match s {
        1 => "native",
        2 => "windows_gui",
        3 => "windows_console",
        5 => "os2_console",
        7 => "posix_console",
        9 => "windows_ce",
        10 => "efi_application",
        11 => "efi_boot_service_driver",
        12 => "efi_runtime_driver",
        13 => "efi_rom",
        14 => "xbox",
        16 => "windows_boot_application",
        _ => return None,
    })
}

fn resource_type(id: u32) -> String {
    match id {
        1 => "cursor",
        2 => "bitmap",
        3 => "icon",
        4 => "menu",
        5 => "dialog",
        6 => "string",
        7 => "font_directory",
        8 => "font",
        9 => "accelerator",
        10 => "rcdata",
        11 => "message_table",
        12 => "group_cursor",
        14 => "group_icon",
        16 => "version",
        17 => "dialog_include",
        19 => "plug_and_play",
        20 => "vxd",
        21 => "animated_cursor",
        22 => "animated_icon",
        23 => "html",
        24 => "manifest",
        _ => return format!("type_{id}"),
    }
    .to_string()
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn le64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// A COFF section header.
struct Sec {
    name: String,
    vsize: u32,
    rva: u32,
    raw_size: u32,
    raw_ptr: u32,
    flags: u32,
}

/// An image's layout: sections and how RVAs map onto the file.
struct Image {
    sections: Vec<Sec>,
    wide: bool,
    base: u64,
    headers_size: u32,
}

impl Image {
    fn offset(&self, rva: u32) -> Option<u64> {
        if rva < self.headers_size {
            return Some(u64::from(rva));
        }
        self.sections
            .iter()
            .find(|s| rva >= s.rva && rva - s.rva < s.vsize.max(s.raw_size))
            .filter(|s| rva - s.rva < s.raw_size)
            .map(|s| u64::from(s.raw_ptr) + u64::from(rva - s.rva))
    }

    /// `len` bytes at an RVA (fewer at the end of the file).
    fn read(&self, src: &mut dyn Source, rva: u32, len: usize) -> Option<Vec<u8>> {
        let off = self.offset(rva)?;
        let n = (src.len().saturating_sub(off)).min(len as u64);
        src.read_vec(off, usize::try_from(n).ok()?).ok()
    }

    /// The NUL-terminated ASCII string at an RVA.
    fn string(&self, src: &mut dyn Source, rva: u32) -> Option<String> {
        let b = self.read(src, rva, 512)?;
        let end = b.iter().position(|&c| c == 0)?;
        Some(String::from_utf8_lossy(&b[..end]).into_owned())
    }
}

impl Extractor for Pe {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.starts_with(b"MZ") || h.starts_with(b"ZM") {
            let lfanew = le32(h, 0x3c).map_or(usize::MAX, |v| v as usize);
            return Some(match h.get(lfanew..lfanew.saturating_add(4)) {
                Some(b"PE\0\0") => {
                    let format = if clr_header_present(h, lfanew) { "dotnet" } else { "pe" };
                    Sniff { format, confidence: 0.95 }
                }
                _ => Sniff { format: "dos_exe", confidence: 0.8 },
            });
        }
        coff_object(h).then_some(Sniff { format: "coff", confidence: 0.75 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.read_vec(0, usize::try_from(src.len().min(4096)).unwrap_or(0))?;
        if !(head.starts_with(b"MZ") || head.starts_with(b"ZM")) {
            if coff_object(&head) {
                return coff(src, cx, &head);
            }
            return Err(ExtractError::malformed("no MZ header"));
        }
        let lfanew = u64::from(le32(&head, 0x3c).unwrap_or(0));
        let sig = if lfanew + 4 <= src.len() && lfanew >= 0x40 { src.read_vec(lfanew, 4)? } else { Vec::new() };
        match sig.get(..2) {
            Some(b"PE") if sig[2..] == [0, 0] => pe(src, cx, lfanew, &head),
            Some(b"NE") => ne(src, cx, lfanew),
            Some(b"LE" | b"LX") => le(src, cx, lfanew, &sig[..2]),
            _ => {
                dos(cx, &head, src.len());
                Ok(())
            }
        }
    }
}

crate::register_extractor!(Pe);

/// The CLR data directory (14) is non-empty: a .NET assembly.
fn clr_header_present(h: &[u8], lfanew: usize) -> bool {
    let opt = lfanew + 24;
    let (dirs, count) = match le16(h, opt) {
        Some(0x10b) => (opt + 96, le32(h, opt + 92)),
        Some(0x20b) => (opt + 112, le32(h, opt + 108)),
        _ => return false,
    };
    count.is_some_and(|n| n > 14) && le32(h, dirs + 14 * 8 + 4).is_some_and(|s| s >= 72)
}

/// A COFF object file: a known machine, no optional header, sane counts.
fn coff_object(h: &[u8]) -> bool {
    let (Some(m), Some(n), Some(opt), Some(sym)) = (le16(h, 0), le16(h, 2), le16(h, 16), le32(h, 8)) else {
        return false;
    };
    machine(m).is_some() && m != 0 && (1..=MAX_SECTIONS).contains(&usize::from(n)) && opt == 0 && sym != 0 && {
        // Every section's raw data must lie in the head's view of the file or after it.
        let s = 20;
        h.get(s..s + 8).is_some_and(|name| {
            name.iter().all(|&c| c == 0 || c.is_ascii_graphic()) && name[0] == b'.' || name[0] == b'/'
        })
    }
}

fn sections(h: &[u8], at: usize, n: usize, strtab: Option<&[u8]>) -> Vec<Sec> {
    (0..n.min(MAX_SECTIONS))
        .filter_map(|i| {
            let s = h.get(at + i * 40..at + i * 40 + 40)?;
            let raw = &s[..8];
            let mut name = String::from_utf8_lossy(&raw[..raw.iter().position(|&c| c == 0).unwrap_or(8)]).into_owned();
            // `/123`: a long name in the COFF string table.
            if let (Some(n), Some(t)) = (name.strip_prefix('/').and_then(|n| n.parse::<usize>().ok()), strtab)
                && let Some(rest) = t.get(n..)
            {
                name =
                    String::from_utf8_lossy(&rest[..rest.iter().position(|&c| c == 0).unwrap_or(rest.len()).min(256)])
                        .into_owned();
            }
            Some(Sec {
                name,
                vsize: le32(s, 8)?,
                rva: le32(s, 12)?,
                raw_size: le32(s, 16)?,
                raw_ptr: le32(s, 20)?,
                flags: le32(s, 36)?,
            })
        })
        .collect()
}

fn to_sections(secs: &[Sec]) -> Vec<Section> {
    secs.iter()
        .map(|s| Section {
            name: s.name.clone(),
            offset: u64::from(s.raw_ptr),
            size: u64::from(s.raw_size),
            address: u64::from(s.rva),
            memory_size: if s.vsize == 0 { u64::from(s.raw_size) } else { u64::from(s.vsize) },
            read: s.flags & 0x4000_0000 != 0,
            write: s.flags & 0x8000_0000 != 0,
            execute: s.flags & 0x2000_0000 != 0,
        })
        .collect()
}

#[allow(clippy::too_many_lines)] // the headers, then one data directory after another
fn pe(src: &mut dyn Source, cx: &mut Context<'_>, lfanew: u64, dos_head: &[u8]) -> Result<(), ExtractError> {
    let bad = || ExtractError::malformed("PE header");
    let h =
        src.read_vec(lfanew, usize::try_from((src.len() - lfanew).min(4096 + 40 * MAX_SECTIONS as u64)).unwrap_or(0))?;
    let m = le16(&h, 4).ok_or_else(bad)?;
    let nsec = usize::from(le16(&h, 6).ok_or_else(bad)?);
    let stamp = le32(&h, 8).ok_or_else(bad)?;
    let opt_size = usize::from(le16(&h, 20).ok_or_else(bad)?);
    let chars = le16(&h, 22).ok_or_else(bad)?;
    let opt = 24;
    let magic = le16(&h, opt).ok_or_else(bad)?;
    let wide = match magic {
        0x10b => false,
        0x20b => true,
        0x107 => return Err(ExtractError::malformed("ROM image")),
        _ => return Err(bad()),
    };
    cx.format_set("architecture", machine(m).map_or_else(|| format!("machine_{m:#06x}"), str::to_string));
    cx.format_set("bits", if wide { 64 } else { 32 });
    cx.format_set("pe_type", if wide { "PE32+" } else { "PE32" });

    let entry = le32(&h, opt + 16).unwrap_or(0);
    let image_base = if wide { le64(&h, opt + 24) } else { le32(&h, opt + 28).map(u64::from) }.unwrap_or(0);
    let headers_size = le32(&h, opt + 60).unwrap_or(0);
    let sub = le16(&h, opt + 68).unwrap_or(0);
    let dllc = le16(&h, opt + 70).unwrap_or(0);
    let (dirs_at, ndirs) = if wide { (opt + 112, le32(&h, opt + 108)) } else { (opt + 96, le32(&h, opt + 92)) };
    let ndirs = ndirs.unwrap_or(0).min(16) as usize;
    let dir = |i: usize| -> (u32, u32) {
        if i >= ndirs {
            return (0, 0);
        }
        (le32(&h, dirs_at + i * 8).unwrap_or(0), le32(&h, dirs_at + i * 8 + 4).unwrap_or(0))
    };
    let secs = sections(&h, opt + opt_size, nsec, None);
    let img = Image { sections: secs, wide, base: image_base, headers_size };

    let dll = chars & 0x2000 != 0;
    let kind = if dll {
        "shared_library"
    } else if matches!(sub, 10..=13) {
        "efi_image"
    } else if sub == 1 {
        "driver"
    } else {
        "executable"
    };
    cx.format_set("kind", kind);
    if let Some(s) = subsystem(sub) {
        cx.format_set("subsystem", s);
    }
    if entry != 0 {
        cx.format_set("entry_point", addr(u64::from(entry)));
    }
    cx.format_set("image_base", addr(image_base));
    if let (Some(a), Some(b)) = (h.get(opt + 2), h.get(opt + 3)) {
        cx.format_set("linker_version", format!("{a}.{b}"));
    }
    if let (Some(a), Some(b)) = (le16(&h, opt + 40), le16(&h, opt + 42)) {
        cx.format_set("os_version", format!("{a}.{b}"));
    }
    if let (Some(a), Some(b)) = (le16(&h, opt + 48), le16(&h, opt + 50)) {
        cx.format_set("subsystem_version", format!("{a}.{b}"));
    }
    if chars & 0x0020 != 0 {
        cx.format_set("large_address_aware", true);
    }
    if let Some(c) = le32(&h, opt + 64).filter(|&c| c != 0) {
        cx.format_set("checksum", format!("{c:#010x}"));
    }

    report_sections(src, cx, &to_sections(&img.sections))?;

    // Debug directory first: a reproducible build's time stamp is a hash.
    let (debug_rva, debug_size) = dir(6);
    let debug = debug_directory(src, cx, &img, debug_rva, debug_size);
    if !debug.reproducible
        && let Some(t) = unix_time(i64::from(stamp))
    {
        cx.format_set("link_time", t.clone());
        cx.temporal().content_date(DateField::Created, t, true);
    }

    let mut hard = Map::new();
    let relocs_stripped = chars & 0x0001 != 0;
    hard.insert("aslr".into(), (dllc & 0x0040 != 0 && !relocs_stripped).into());
    if wide {
        hard.insert("high_entropy_aslr".into(), (dllc & 0x0020 != 0).into());
    }
    hard.insert("dep".into(), (dllc & 0x0100 != 0).into());
    hard.insert("cfg".into(), (dllc & 0x4000 != 0).into());
    if dllc & 0x0080 != 0 {
        hard.insert("force_integrity".into(), true.into());
    }
    if dllc & 0x1000 != 0 {
        hard.insert("appcontainer".into(), true.into());
    }
    if dllc & 0x0400 != 0 {
        hard.insert("no_seh".into(), true.into());
    }
    if let Some(cet) = debug.cet {
        hard.insert("shadow_stack".into(), cet.into());
    }
    let (lc_rva, lc_size) = dir(10);
    if lc_rva != 0
        && let Some(lc) = img.read(src, lc_rva, usize::try_from(lc_size.clamp(64, 512)).unwrap_or(64))
    {
        let cookie = if wide { le64(&lc, 0x58) } else { le32(&lc, 0x3c).map(u64::from) };
        hard.insert("stack_canary".into(), cookie.is_some_and(|c| c != 0).into());
        if !wide {
            let handlers = le32(&lc, 0x44).unwrap_or(0);
            hard.insert("safe_seh".into(), (handlers > 0).into());
        }
    }

    // Imports.
    let (imp_rva, _) = dir(1);
    let mut libraries = Vec::new();
    let mut functions = Vec::new();
    if imp_rva != 0 {
        for i in 0..MAX_IMPORT_LIBS {
            let Some(d) = img.read(src, imp_rva.saturating_add(i * 20), 20) else { break };
            if d.len() < 20 || d.iter().all(|&b| b == 0) {
                break;
            }
            let ilt = le32(&d, 0).unwrap_or(0);
            let name_rva = le32(&d, 12).unwrap_or(0);
            let iat = le32(&d, 16).unwrap_or(0);
            let Some(lib) = img.string(src, name_rva) else { break };
            libraries.push(lib);
            if functions.len() < MAX_FUNCTIONS {
                thunks(src, &img, if ilt != 0 { ilt } else { iat }, &mut functions);
            }
        }
    }
    let (delay_rva, _) = dir(13);
    let mut delayed = Vec::new();
    if delay_rva != 0 {
        for i in 0..MAX_IMPORT_LIBS {
            let Some(d) = img.read(src, delay_rva.saturating_add(i * 32), 32) else { break };
            if d.len() < 32 || d.iter().all(|&b| b == 0) {
                break;
            }
            let rva_based = le32(&d, 0).unwrap_or(0) & 1 != 0;
            let mut name = le32(&d, 4).unwrap_or(0);
            if !rva_based {
                name = u32::try_from(u64::from(name).saturating_sub(image_base)).unwrap_or(0);
            }
            match img.string(src, name) {
                Some(n) => delayed.push(n),
                None => break,
            }
        }
    }
    if !libraries.is_empty() {
        cx.format_set("library_count", libraries.len());
        cx.format_set("libraries", names(&libraries));
    }
    if !delayed.is_empty() {
        cx.format_set("delay_loaded_libraries", names(&delayed));
    }
    if !functions.is_empty() {
        cx.format_set("imported_symbol_count", functions.len());
        functions.sort();
        functions.dedup();
        cx.format_set("imports", names(&functions));
    }
    if kind == "executable" && sub == 1 && libraries.iter().any(|l| l.eq_ignore_ascii_case("ntoskrnl.exe")) {
        cx.format_set("kind", "driver");
    }

    exports(src, cx, &img, dir(0).0);
    let (res_rva, _) = dir(2);
    if res_rva != 0 {
        resources(src, cx, &img, res_rva);
    }
    tls(src, cx, &img, dir(9).0);
    let (clr_rva, clr_size) = dir(14);
    if clr_rva != 0 && clr_size >= 72 {
        dotnet(src, cx, &img, clr_rva);
    }

    // Authenticode: the security directory holds a file offset, not an RVA.
    let (cert_off, cert_size) = dir(4);
    let mut image_end = img.sections.iter().map(|s| u64::from(s.raw_ptr) + u64::from(s.raw_size)).max().unwrap_or(0);
    image_end = image_end.max(u64::from(headers_size));
    let mut data_end = src.len();
    if cert_off != 0 && cert_size >= 8 && u64::from(cert_off) + u64::from(cert_size) <= src.len() {
        if u64::from(cert_off) >= image_end {
            data_end = data_end.min(u64::from(cert_off));
        }
        authenticode(src, cx, u64::from(cert_off), cert_size)?;
    }
    if let Some(r) = rich(dos_head, usize::try_from(lfanew).unwrap_or(0)) {
        cx.format_set("rich_header", r);
    }
    cx.format_set("hardening", Value::Object(hard));
    report_overlay(src, cx, image_end, data_end)?;
    scan_toolchain(src, cx)?.write(cx);
    Ok(())
}

/// Function names from an import lookup table.
fn thunks(src: &mut dyn Source, img: &Image, rva: u32, out: &mut Vec<String>) {
    let w = if img.wide { 8 } else { 4 };
    let Some(table) = img.read(src, rva, 4096 * w) else { return };
    for c in table.chunks_exact(w) {
        let v = if img.wide { le64(c, 0).unwrap_or(0) } else { u64::from(le32(c, 0).unwrap_or(0)) };
        if v == 0 || out.len() >= MAX_FUNCTIONS {
            break;
        }
        let ordinal = if img.wide { v >> 63 == 1 } else { v >> 31 == 1 };
        if ordinal {
            out.push(format!("#{}", v & 0xffff));
        } else if let Some(n) = u32::try_from(v & 0x7fff_ffff).ok().and_then(|r| img.string(src, r + 2)) {
            out.push(n);
        }
    }
}

fn exports(src: &mut dyn Source, cx: &mut Context<'_>, img: &Image, rva: u32) {
    if rva == 0 {
        return;
    }
    let Some(d) = img.read(src, rva, 40) else { return };
    if let Some(n) = le32(&d, 12).and_then(|r| img.string(src, r)) {
        cx.format_set("export_name", n);
    }
    let count = le32(&d, 24).unwrap_or(0);
    let total = le32(&d, 20).unwrap_or(0);
    cx.format_set("exported_symbol_count", total);
    let names_rva = le32(&d, 32).unwrap_or(0);
    let n = usize::try_from(count).unwrap_or(0).min(super::MAX_NAMES);
    if let Some(table) = img.read(src, names_rva, n * 4) {
        let list: Vec<String> =
            table.as_chunks::<4>().0.iter().filter_map(|c| img.string(src, u32::from_le_bytes(*c))).collect();
        if !list.is_empty() {
            cx.format_set("exports", names(&list));
        }
    }
}

#[derive(Default)]
struct Debug {
    reproducible: bool,
    cet: Option<bool>,
}

fn debug_directory(src: &mut dyn Source, cx: &mut Context<'_>, img: &Image, rva: u32, size: u32) -> Debug {
    let mut out = Debug::default();
    if rva == 0 {
        return out;
    }
    let Some(d) = img.read(src, rva, usize::try_from(size.min(28 * 32)).unwrap_or(0)) else { return out };
    for e in d.as_chunks::<28>().0 {
        let (Some(kind), Some(len), Some(ptr)) = (le32(e, 12), le32(e, 16), le32(e, 24)) else { continue };
        match kind {
            2 => {
                let Ok(cv) = src.read_vec(u64::from(ptr), usize::try_from(len.min(1024)).unwrap_or(0)) else {
                    continue;
                };
                if cv.starts_with(b"RSDS") && cv.len() > 24 {
                    let g = &cv[4..20];
                    let guid = format!(
                        "{:08x}-{:04x}-{:04x}-{}-{}",
                        le32(g, 0).unwrap_or(0),
                        le16(g, 4).unwrap_or(0),
                        le16(g, 6).unwrap_or(0),
                        hex(&g[8..10]),
                        hex(&g[10..16])
                    );
                    let path = &cv[24..];
                    let path =
                        String::from_utf8_lossy(&path[..path.iter().position(|&c| c == 0).unwrap_or(path.len())])
                            .into_owned();
                    let shown = if cx.privacy_strict() {
                        path.rsplit(['\\', '/']).next().unwrap_or("").to_string()
                    } else {
                        path
                    };
                    cx.format_set(
                        "debug",
                        json!({"pdb": shown, "pdb_guid": guid, "pdb_age": le32(&cv, 20).unwrap_or(0)}),
                    );
                }
            }
            16 => {
                out.reproducible = true;
                cx.format_set("reproducible", true);
            }
            20 => {
                if let Ok(b) = src.read_vec(u64::from(ptr), 4) {
                    out.cet = Some(le32(&b, 0).unwrap_or(0) & 1 != 0);
                }
            }
            _ => {}
        }
    }
    out
}

/// Walk the resource tree: counts per type, the version information and the manifest.
fn resources(src: &mut dyn Source, cx: &mut Context<'_>, img: &Image, base: u32) {
    let Some(root) = img.read(src, base, 16 + 8 * 64) else { return };
    let mut counts = Map::new();
    let mut version = None;
    let mut manifest = None;
    let entries = |d: &[u8]| -> Vec<(u32, u32)> {
        let n = usize::from(le16(d, 12).unwrap_or(0)) + usize::from(le16(d, 14).unwrap_or(0));
        (0..n.min(64)).filter_map(|i| Some((le32(d, 16 + i * 8)?, le32(d, 20 + i * 8)?))).collect()
    };
    for (id, off) in entries(&root) {
        let ty = if id & 0x8000_0000 != 0 { "named".to_string() } else { resource_type(id) };
        if off & 0x8000_0000 == 0 {
            continue;
        }
        let Some(names_dir) = img.read(src, base + (off & 0x7fff_ffff), 16 + 8 * 256) else { continue };
        let mut n = 0u64;
        for (_, off2) in entries(&names_dir) {
            n += 1;
            // The first language of the first name of the version and manifest types.
            if (id == 16 && version.is_none()) || (id == 24 && manifest.is_none()) {
                let leaf = if off2 & 0x8000_0000 != 0 {
                    img.read(src, base + (off2 & 0x7fff_ffff), 24).and_then(|l| entries(&l).first().map(|e| e.1))
                } else {
                    Some(off2)
                };
                if let Some(leaf) = leaf.filter(|l| l & 0x8000_0000 == 0)
                    && let Some(de) = img.read(src, base + leaf, 16)
                    && let (Some(rva), Some(size)) = (le32(&de, 0), le32(&de, 4))
                {
                    let data = img.read(src, rva, usize::try_from(size.min(1 << 16)).unwrap_or(0));
                    if id == 16 {
                        version = data;
                    } else {
                        manifest = data;
                    }
                }
            }
        }
        counts.insert(ty, n.into());
    }
    if !counts.is_empty() {
        cx.format_set("resources", Value::Object(counts));
    }
    if let Some(v) = version {
        version_info(cx, &v);
    }
    if let Some(m) = manifest {
        manifest_facts(cx, &String::from_utf8_lossy(&m));
    }
}

/// One `VS_VERSIONINFO`-style block: key, value bytes, children, length.
fn block(b: &[u8], at: usize) -> Option<(String, &[u8], usize, usize, bool)> {
    let len = usize::from(le16(b, at)?);
    let vlen = usize::from(le16(b, at + 2)?);
    let text = le16(b, at + 4)? == 1;
    if len < 6 || at + len > b.len() {
        return None;
    }
    let mut k = at + 6;
    let mut units = Vec::new();
    while let Some(u) = le16(b, k) {
        k += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    let key = String::from_utf16_lossy(&units);
    let v_at = (k + 3) & !3;
    let v_bytes = if text { vlen * 2 } else { vlen };
    let value = b.get(v_at..(v_at + v_bytes).min(at + len)).unwrap_or(&[]);
    let children = ((v_at + v_bytes) + 3) & !3;
    Some((key, value, children, at + len, text))
}

const VERSION_STRINGS: &[(&str, &str)] = &[
    ("CompanyName", "company"),
    ("FileDescription", "file_description"),
    ("FileVersion", "file_version"),
    ("InternalName", "internal_name"),
    ("LegalCopyright", "copyright"),
    ("LegalTrademarks", "trademarks"),
    ("OriginalFilename", "original_filename"),
    ("ProductName", "product_name"),
    ("ProductVersion", "product_version"),
    ("Comments", "comments"),
];

fn version_info(cx: &mut Context<'_>, b: &[u8]) {
    let Some((key, value, children, end, _)) = block(b, 0) else { return };
    if key != "VS_VERSION_INFO" {
        return;
    }
    let mut out = Map::new();
    if value.len() >= 52 && le32(value, 0) == Some(0xfeef_04bd) {
        let v = |hi: usize, lo: usize| {
            let (h, l) = (le32(value, hi).unwrap_or(0), le32(value, lo).unwrap_or(0));
            format!("{}.{}.{}.{}", h >> 16, h & 0xffff, l >> 16, l & 0xffff)
        };
        out.insert("file_version_number".into(), v(8, 12).into());
        out.insert("product_version_number".into(), v(16, 20).into());
    }
    // StringFileInfo → string tables → strings (first table only).
    let mut at = children;
    while at < end {
        let Some((k, _, kids, next, _)) = block(b, at) else { break };
        if k == "StringFileInfo"
            && let Some((lang, _, strings, table_end, _)) = block(b, kids)
        {
            out.insert("language".into(), lang.into());
            let mut s = strings;
            while s < table_end && out.len() < 32 {
                let Some((name, value, _, next_s, _)) = block(b, s) else { break };
                let units: Vec<u16> =
                    value.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|&u| u != 0).collect();
                let text = String::from_utf16_lossy(&units).trim().to_string();
                if let Some(&(_, out_key)) = VERSION_STRINGS.iter().find(|(n, _)| *n == name)
                    && !text.is_empty()
                {
                    out.insert(out_key.into(), text.into());
                }
                s = (next_s + 3) & !3;
            }
        }
        at = (next + 3) & !3;
    }
    if out.is_empty() {
        return;
    }
    let get = |k: &str| out.get(k).and_then(Value::as_str).map(str::to_string);
    if let Some(t) = get("product_name").or_else(|| get("file_description")) {
        cx.content().title(t);
    }
    if let Some(d) = get("file_description") {
        cx.content().description(d);
    }
    if let Some(c) = get("company") {
        cx.content().author(c);
    }
    if let Some(c) = get("copyright") {
        cx.rights().copyright(c);
    }
    cx.format_set("version_info", Value::Object(out));
}

fn attr<'t>(xml: &'t str, element: &str, name: &str) -> Option<&'t str> {
    let at = xml.find(element)?;
    let rest = &xml[at..];
    let end = rest.find('>')?;
    let tag = &rest[..end];
    let key = format!("{name}=");
    let v = &tag[tag.find(&key)? + key.len()..];
    let quote = v.chars().next()?;
    let v = &v[1..];
    Some(&v[..v.find(quote)?])
}

fn manifest_facts(cx: &mut Context<'_>, xml: &str) {
    let mut m = Map::new();
    if let Some(level) = attr(xml, "requestedExecutionLevel", "level") {
        m.insert("requested_execution_level".into(), level.into());
        if level == "requireAdministrator" {
            cx.security().risk("requests_elevation", Some("manifest requests requireAdministrator".into()));
        }
    }
    if attr(xml, "requestedExecutionLevel", "uiAccess") == Some("true") {
        m.insert("ui_access".into(), true.into());
    }
    if let Some(n) = attr(xml, "assemblyIdentity", "name") {
        m.insert("assembly_name".into(), n.into());
    }
    if let Some(v) = attr(xml, "assemblyIdentity", "version") {
        m.insert("assembly_version".into(), v.into());
    }
    let os = xml.matches("supportedOS").count();
    if os > 0 {
        m.insert("supported_os_count".into(), os.into());
    }
    if !m.is_empty() {
        cx.format_set("manifest", Value::Object(m));
    }
}

fn tls(src: &mut dyn Source, cx: &mut Context<'_>, img: &Image, rva: u32) {
    if rva == 0 {
        return;
    }
    let Some(d) = img.read(src, rva, 40) else { return };
    let callbacks_va = if img.wide { le64(&d, 24) } else { le32(&d, 12).map(u64::from) }.unwrap_or(0);
    let Some(cb_rva) = callbacks_va.checked_sub(img.base).and_then(|r| u32::try_from(r).ok()) else { return };
    let w = if img.wide { 8 } else { 4 };
    let Some(list) = img.read(src, cb_rva, 64 * w) else { return };
    let n = list
        .chunks_exact(w)
        .take_while(|c| if img.wide { le64(c, 0) } else { le32(c, 0).map(u64::from) }.is_some_and(|v| v != 0))
        .count();
    if n > 0 {
        cx.format_set("tls_callbacks", n);
        cx.security().risk("tls_callbacks", Some(format!("{n} TLS callback(s)")));
    }
}

fn dotnet(src: &mut dyn Source, cx: &mut Context<'_>, img: &Image, rva: u32) {
    let Some(h) = img.read(src, rva, 72) else { return };
    let mut d = Map::new();
    if let (Some(a), Some(b)) = (le16(&h, 4), le16(&h, 6)) {
        d.insert("runtime_version".into(), format!("{a}.{b}").into());
    }
    let flags = le32(&h, 16).unwrap_or(0);
    d.insert("il_only".into(), (flags & 1 != 0).into());
    if flags & 2 != 0 {
        d.insert("requires_32bit".into(), true.into());
    }
    if flags & 0x2_0000 != 0 {
        d.insert("prefers_32bit".into(), true.into());
    }
    d.insert("strong_name_signed".into(), (flags & 8 != 0).into());
    // A ReadyToRun image carries precompiled native code beside the IL.
    if le32(&h, 64).is_some_and(|r| r != 0) && le32(&h, 68).is_some_and(|s| s != 0) {
        d.insert("ready_to_run".into(), true.into());
    }
    let size = le32(&h, 12).unwrap_or(0) as usize;
    if size > cx.parse_limit() {
        cx.warn("the .NET metadata is larger than the parse limit; names past it are not read");
    }
    if let Some(md) = le32(&h, 8).and_then(|r| img.read(src, r, size.min(cx.parse_limit())))
        && le32(&md, 0) == Some(0x424a_5342)
    {
        let n = le32(&md, 12).unwrap_or(0) as usize;
        if let Some(v) = md.get(16..16 + n.min(240)) {
            let v = String::from_utf8_lossy(&v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())]).into_owned();
            d.insert("metadata_version".into(), v.into());
        }
        match cli::Metadata::parse(&md) {
            Some(m) => {
                if let Some(o) = cli::report(&m, le32(&h, 20).unwrap_or(0), &mut d) {
                    cx.security().risk("obfuscated_code", Some(format!("processed by {o}")));
                }
            }
            None => cx.warn("the .NET metadata tables could not be read"),
        }
    }
    cx.format_set("dotnet", Value::Object(d));
}

fn authenticode(src: &mut dyn Source, cx: &mut Context<'_>, off: u64, size: u32) -> Result<(), ExtractError> {
    let data = src.read_vec(off, usize::try_from(size.min(1 << 20)).unwrap_or(0))?;
    let mut at = 0;
    let mut signatures = Vec::new();
    while at + 8 <= data.len() && signatures.len() < 8 {
        let len = le32(&data, at).unwrap_or(0) as usize;
        let kind = le16(&data, at + 6).unwrap_or(0);
        if len < 8 || at + len > data.len() {
            break;
        }
        if kind == 2
            && let Some(s) = der::signed_data(&data[at + 8..at + len])
        {
            let mut f = s.facts();
            f.insert("kind".into(), "authenticode".into());
            signatures.push(Value::Object(f));
        }
        at = (at + len + 7) & !7;
    }
    if let Some(first) = signatures.first().cloned() {
        cx.security().signed(true);
        cx.format_set("signature", first);
        if signatures.len() > 1 {
            cx.format_set("signature_count", signatures.len());
        }
    } else {
        cx.warn("certificate table holds no readable signature");
    }
    Ok(())
}

/// The Rich header between the DOS stub and the PE header: the tools
/// (product id, build, count) that built the objects.
fn rich(head: &[u8], lfanew: usize) -> Option<Value> {
    let area = head.get(0x80..lfanew.min(head.len()))?;
    let at = area.windows(4).position(|w| w == b"Rich")?;
    let key = le32(area, at + 4)?;
    let mut start = None;
    let mut i = at;
    while i >= 4 {
        i -= 4;
        if le32(area, i)? ^ key == 0x536e_6144 {
            start = Some(i);
            break;
        }
    }
    let start = start?;
    let tools: Vec<Value> = area
        .get(start + 16..at)?
        .as_chunks::<8>()
        .0
        .iter()
        .take(64)
        .filter_map(|c| {
            let id = le32(c, 0)? ^ key;
            let count = le32(c, 4)? ^ key;
            Some(json!({"product": id >> 16, "build": id & 0xffff, "count": count}))
        })
        .collect();
    Some(json!({"tools": tools}))
}

fn coff(src: &mut dyn Source, cx: &mut Context<'_>, h: &[u8]) -> Result<(), ExtractError> {
    let m = le16(h, 0).unwrap_or(0);
    let n = usize::from(le16(h, 2).unwrap_or(0));
    let symtab = le32(h, 8).unwrap_or(0);
    let nsyms = le32(h, 12).unwrap_or(0);
    cx.format_set("kind", "object");
    cx.format_set("architecture", machine(m).unwrap_or("unknown"));
    // The string table follows the symbols (18 bytes each).
    let strtab_at = u64::from(symtab) + u64::from(nsyms) * 18;
    let strtab = if strtab_at + 4 <= src.len() {
        let len = src.read_vec(strtab_at, 4)?;
        let len = u64::from(le32(&len, 0).unwrap_or(0)).min(1 << 20).min(src.len() - strtab_at);
        src.read_vec(strtab_at, usize::try_from(len).unwrap_or(0))?
    } else {
        Vec::new()
    };
    let secs = sections(h, 20, n, Some(&strtab));
    cx.format_set("symbol_count", nsyms);
    report_sections(src, cx, &to_sections(&secs))?;
    if secs.iter().any(|s| s.name == ".drectve") {
        cx.format_set("linker_directives", true);
    }
    scan_toolchain(src, cx)?.write(cx);
    Ok(())
}

fn dos(cx: &mut Context<'_>, h: &[u8], len: u64) {
    let last = u64::from(le16(h, 2).unwrap_or(0));
    let pages = u64::from(le16(h, 4).unwrap_or(0));
    let image = if last == 0 { pages * 512 } else { pages.saturating_sub(1) * 512 + last };
    cx.format_set("kind", "dos_executable");
    cx.format_set("image_bytes", image);
    cx.format_set("relocations", le16(h, 6).unwrap_or(0));
    if let (Some(ip), Some(cs)) = (le16(h, 0x14), le16(h, 0x16)) {
        cx.format_set("entry_point", format!("{cs:04x}:{ip:04x}"));
    }
    if len > image && image > 0 {
        cx.format_set("overlay_bytes", len - image);
    }
}

fn target_os(v: u8) -> Option<&'static str> {
    Some(match v {
        1 => "os2",
        2 => "windows",
        3 => "dos4",
        4 => "windows386",
        5 => "bos",
        _ => return None,
    })
}

/// A length-prefixed name (NE and LE name tables).
fn pascal(b: &[u8]) -> Option<String> {
    let n = usize::from(*b.first()?);
    b.get(1..1 + n).map(|s| String::from_utf8_lossy(s).into_owned())
}

fn ne(src: &mut dyn Source, cx: &mut Context<'_>, at: u64) -> Result<(), ExtractError> {
    let h = src.read_vec(at, usize::try_from((src.len() - at).min(64)).unwrap_or(0))?;
    cx.format_set("kind", "ne_executable");
    if let (Some(&a), Some(&b)) = (h.get(2), h.get(3)) {
        cx.format_set("linker_version", format!("{a}.{b}"));
    }
    if let Some(os) = h.get(0x36).and_then(|&o| target_os(o)) {
        cx.format_set("os", os);
    }
    if let (Some(&minor), Some(&major)) = (h.get(0x3e), h.get(0x3f))
        && major > 0
    {
        cx.format_set("windows_version", format!("{major}.{minor}"));
    }
    if le16(&h, 0x0c).is_some_and(|f| f & 0x8000 != 0) {
        cx.format_set("kind", "ne_library");
    }
    cx.format_set("segments", le16(&h, 0x1c).unwrap_or(0));
    cx.format_set("module_references", le16(&h, 0x1e).unwrap_or(0));
    if let Some(res) = le16(&h, 0x26)
        && let Ok(b) = src.read_vec(
            at + u64::from(res),
            256.min(usize::try_from(src.len().saturating_sub(at + u64::from(res))).unwrap_or(0)),
        )
        && let Some(name) = pascal(&b)
    {
        cx.format_set("module_name", name);
    }
    if let Some(nonres) = le32(&h, 0x2c).map(u64::from).filter(|&o| o < src.len())
        && let Ok(b) = src.read_vec(nonres, usize::try_from((src.len() - nonres).min(256)).unwrap_or(0))
        && let Some(desc) = pascal(&b).filter(|d| !d.is_empty())
    {
        cx.content().description(desc.clone());
        cx.format_set("description", desc);
    }
    Ok(())
}

fn le(src: &mut dyn Source, cx: &mut Context<'_>, at: u64, sig: &[u8]) -> Result<(), ExtractError> {
    let h = src.read_vec(at, usize::try_from((src.len() - at).min(0xb0)).unwrap_or(0))?;
    cx.format_set("kind", if sig == b"LX" { "lx_executable" } else { "le_executable" });
    let cpu = match le16(&h, 0x08) {
        Some(1) => "i286",
        Some(2) => "i386",
        Some(3) => "i486",
        _ => "unknown",
    };
    cx.format_set("architecture", cpu);
    if let Some(os) = le16(&h, 0x0a).and_then(|o| u8::try_from(o).ok()).and_then(target_os) {
        cx.format_set("os", os);
    }
    let flags = le32(&h, 0x10).unwrap_or(0);
    let module = match flags & 0x38000 {
        0 => "program",
        0x8000 => "library",
        0x18000 => "protected_memory_library",
        0x20000 => "physical_device_driver",
        0x28000 => "virtual_device_driver",
        _ => "other",
    };
    cx.format_set("module_type", module);
    cx.format_set("pages", le32(&h, 0x14).unwrap_or(0));
    if let Some(res) = le32(&h, 0x58)
        && let Ok(b) = src.read_vec(
            at + u64::from(res),
            256.min(usize::try_from(src.len().saturating_sub(at + u64::from(res))).unwrap_or(0)),
        )
        && let Some(name) = pascal(&b)
    {
        cx.format_set("module_name", name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_blocks() {
        // A String block: length, value length (in characters), type 1, key, value.
        let mut b = Vec::new();
        let key: Vec<u8> = "ProductName\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let value: Vec<u8> = "Tides\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        // The value starts on a 4-byte boundary: 6 + 24 bytes of key, 2 of padding.
        let len = 6 + key.len() + 2 + value.len();
        b.extend(u16::try_from(len).unwrap().to_le_bytes());
        b.extend(6u16.to_le_bytes());
        b.extend(1u16.to_le_bytes());
        b.extend(&key);
        b.extend([0, 0]);
        b.extend(&value);
        let (k, v, _, end, text) = block(&b, 0).unwrap();
        assert_eq!((k.as_str(), v.len(), end, text), ("ProductName", 12, len, true));
    }

    #[test]
    fn manifest_attributes() {
        let xml = r#"<assembly><assemblyIdentity name="Saltmere.Tides" version="1.0.0.0"/>
            <requestedExecutionLevel level='asInvoker' uiAccess="false"/></assembly>"#;
        assert_eq!(attr(xml, "requestedExecutionLevel", "level"), Some("asInvoker"));
        assert_eq!(attr(xml, "assemblyIdentity", "version"), Some("1.0.0.0"));
        assert_eq!(attr(xml, "missing", "x"), None);
    }

    #[test]
    fn coff_objects_need_sane_headers() {
        let mut h = vec![0u8; 64];
        h[..2].copy_from_slice(&0x8664u16.to_le_bytes());
        h[2] = 1;
        h[8] = 0x40;
        h[20..25].copy_from_slice(b".text");
        assert!(coff_object(&h));
        h[2] = 0;
        assert!(!coff_object(&h));
    }

    crate::fixture_tests!("pe", "dotnet", "dos_exe", "coff");
}
