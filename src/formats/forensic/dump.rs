//! Crash and memory dumps:
//! * minidumps (`MDMP`, Windows and Breakpad / Crashpad): time, flags, the
//!   system (OS, version, build, service pack, CPU architecture and count),
//!   the exception (code and name, address, thread) and the module it hit,
//!   the modules (name, version, size; the main executable), thread count,
//!   the process ID and start time, the streams present. Memory, the
//!   environment and command lines are never reported;
//! * Windows kernel crash dumps (`PAGEDUMP` / `PAGEDU64`): build, machine,
//!   processors, bug check code and parameters;
//! * `LiME` memory images: ranges, total bytes, address span;
//! * hibernation files (`hiberfil.sys`): state.
//!
//! Specifications: Microsoft `minidumpapiset.h` (`MINIDUMP_*`), Breakpad
//! `minidump_format.h`; `DUMP_HEADER32` / `DUMP_HEADER64` as documented
//! by the Volatility and rekall projects; `LiME`'s `lime.h`.

use serde_json::{Map, Value, json};

use super::{le, unix_time, user_path, utf16z};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for crash and memory dumps.
pub struct Dump;

static META: ExtractorMeta = ExtractorMeta {
    id: "forensic.dump",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "minidump",
            name: "Minidump",
            family: "forensic",
            mimes: &["application/x-dmp"],
            extensions: &["dmp", "mdmp"],
            magic: &[Magic::prefix(b"MDMP\x93\xa7")],
            parent: None,
        },
        FormatSpec {
            id: "windows_crash_dump",
            name: "Windows kernel crash dump",
            family: "forensic",
            mimes: &[],
            extensions: &["dmp"],
            magic: &[Magic::prefix(b"PAGEDU64"), Magic::prefix(b"PAGEDUMP")],
            parent: None,
        },
        FormatSpec {
            id: "lime",
            name: "LiME memory image",
            family: "forensic",
            mimes: &[],
            extensions: &["lime", "mem"],
            magic: &[Magic::prefix(b"EMiL")],
            parent: None,
        },
        FormatSpec {
            id: "hiberfil",
            name: "Windows hibernation file",
            family: "forensic",
            mimes: &[],
            extensions: &["sys"],
            magic: &[Magic::prefix(b"hibr"), Magic::prefix(b"HIBR"), Magic::prefix(b"wake"), Magic::prefix(b"WAKE")],
            parent: None,
        },
    ],
};

/// Modules listed.
const MAX_MODULES: usize = 64;

fn u32_at(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 4).map_or(0, le)
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8).map_or(0, le)
}

fn stream_name(t: u64) -> String {
    match t {
        3 => "thread_list".into(),
        4 => "module_list".into(),
        5 => "memory_list".into(),
        6 => "exception".into(),
        7 => "system_info".into(),
        8 => "thread_ex_list".into(),
        9 => "memory64_list".into(),
        10 => "comment_a".into(),
        11 => "comment_w".into(),
        12 => "handle_data".into(),
        13 => "function_table".into(),
        14 => "unloaded_module_list".into(),
        15 => "misc_info".into(),
        16 => "memory_info_list".into(),
        17 => "thread_info_list".into(),
        18 => "handle_operation_list".into(),
        19 => "token".into(),
        21 => "system_memory_info".into(),
        22 => "process_vm_counters".into(),
        24 => "thread_names".into(),
        0x4767_0001 => "breakpad_info".into(),
        0x4767_0002 => "assertion_info".into(),
        0x4767_0003 => "linux_cpu_info".into(),
        0x4767_0004 => "linux_proc_status".into(),
        0x4767_0005 => "linux_lsb_release".into(),
        0x4767_0006 => "linux_cmd_line".into(),
        0x4767_0007 => "linux_environ".into(),
        0x4767_0008 => "linux_auxv".into(),
        0x4767_0009 => "linux_maps".into(),
        0x4767_000a => "linux_dso_debug".into(),
        0x4350_0001 => "crashpad_info".into(),
        t => format!("stream_{t:#x}"),
    }
}

fn arch(a: u64) -> &'static str {
    match a {
        0 => "x86",
        5 => "arm",
        6 => "ia64",
        9 => "x86_64",
        12 | 0x8003 => "arm64",
        0x8001 => "sparc",
        0x8002 => "ppc64",
        0x8004 => "mips",
        _ => "unknown",
    }
}

fn platform(p: u64) -> &'static str {
    match p {
        0..=2 => "windows",
        0x8101 => "macos",
        0x8102 => "ios",
        0x8201 => "linux",
        0x8202 => "solaris",
        0x8203 => "android",
        0x8204 => "ps3",
        0x8205 => "nacl",
        0x8206 => "fuchsia",
        _ => "unknown",
    }
}

fn exception_name(code: u64, os: &str) -> Option<&'static str> {
    if os != "windows" {
        return Some(match code {
            4 => "SIGILL",
            5 => "SIGTRAP",
            6 => "SIGABRT",
            7 => "SIGBUS",
            8 => "SIGFPE",
            11 => "SIGSEGV",
            1 => "EXC_BAD_ACCESS",
            _ => return None,
        });
    }
    Some(match code {
        0xc000_0005 => "access_violation",
        0x8000_0003 => "breakpoint",
        0x8000_0004 => "single_step",
        0xc000_001d => "illegal_instruction",
        0xc000_0094 => "integer_divide_by_zero",
        0xc000_00fd => "stack_overflow",
        0xc000_0409 => "stack_buffer_overrun",
        0xc000_0374 => "heap_corruption",
        0xe06d_7363 => "cpp_exception",
        0xc000_0602 => "fail_fast",
        0x4000_0015 => "abort",
        0x8000_0002 => "datatype_misalignment",
        _ => return None,
    })
}

/// A `MINIDUMP_STRING` (byte length, then UTF-16) at `rva`.
fn md_string(b: &[u8], rva: u64) -> Option<String> {
    let at = usize::try_from(rva).ok()?;
    let n = usize::try_from(u32_at(b, at)).ok()?.min(4096);
    Some(utf16z(b.get(at + 4..at + 4 + n)?))
}

fn version(ms: u64, ls: u64) -> String {
    format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff)
}

impl Extractor for Dump {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "windows_crash_dump" => crash_dump(src, cx),
            "lime" => lime(src, cx),
            "hiberfil" => {
                let mut h = [0u8; 4];
                src.read_exact_at(0, &mut h).map_err(|_| ExtractError::malformed("hibernation header"))?;
                let state = match &h {
                    b"hibr" | b"HIBR" => "hibernated",
                    _ => "resumed",
                };
                cx.format_set("state", state);
                Ok(())
            }
            _ => minidump(src, cx),
        }
    }
}

#[allow(clippy::too_many_lines)] // one block per stream
fn minidump(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = usize::try_from(src.len().min(cx.parse_limit() as u64)).unwrap_or(0);
    let b = src.read_vec(0, len)?;
    let streams = usize::try_from(u32_at(&b, 8)).unwrap_or(0).min(4096);
    let dir = usize::try_from(u32_at(&b, 12)).unwrap_or(0);
    if let Some(t) = i64::try_from(u32_at(&b, 20)).ok().and_then(unix_time) {
        cx.format_set("created", t.clone());
        cx.temporal().source("forensic.dump").content_date(crate::plugin::DateField::Created, t, true);
    }
    cx.format_set("flags", format!("{:#x}", u64_at(&b, 24)));
    let mut names = Vec::new();
    let mut found: Map<String, Value> = Map::new();
    let (mut os, mut exc_addr) = ("windows".to_string(), None);
    let mut modules: Vec<(u64, u64, String, Option<String>)> = Vec::new();
    for i in 0..streams {
        let e = dir + 12 * i;
        let (kind, size, rva) = (u32_at(&b, e), u32_at(&b, e + 4), u32_at(&b, e + 8));
        if kind == 0 {
            continue;
        }
        names.push(stream_name(kind));
        let Ok(at) = usize::try_from(rva) else { continue };
        let Some(s) = b.get(at..at + usize::try_from(size).unwrap_or(0)) else {
            continue;
        };
        match kind {
            7 => {
                let p = u32_at(s, 20);
                os = platform(p).to_string();
                let mut m = Map::new();
                m.insert("platform".into(), os.clone().into());
                m.insert("version".into(), format!("{}.{}.{}", u32_at(s, 8), u32_at(s, 12), u32_at(s, 16)).into());
                if let Some(csd) = md_string(&b, u32_at(s, 24)).filter(|c| !c.is_empty()) {
                    m.insert("service_pack".into(), csd.into());
                }
                m.insert("architecture".into(), arch(s.get(..2).map_or(0, le)).into());
                m.insert("processors".into(), s.get(6).copied().unwrap_or(0).into());
                if p <= 2 {
                    m.insert(
                        "product_type".into(),
                        match s.get(7) {
                            Some(1) => "workstation",
                            Some(2) => "domain_controller",
                            Some(3) => "server",
                            _ => "unknown",
                        }
                        .into(),
                    );
                }
                found.insert("system".into(), Value::Object(m));
            }
            6 => {
                let code = u32_at(s, 8);
                let addr = u64_at(s, 24);
                exc_addr = Some(addr);
                let mut m = Map::new();
                m.insert("thread_id".into(), u32_at(s, 0).into());
                m.insert("code".into(), format!("{code:#010x}").into());
                m.insert("address".into(), format!("{addr:#x}").into());
                found.insert("exception".into(), Value::Object(m));
                found.insert("exception_code".into(), code.into());
            }
            4 => {
                let n = usize::try_from(u32_at(s, 0)).unwrap_or(0).min(100_000);
                for k in 0..n {
                    let Some(m) = s.get(4 + 108 * k..4 + 108 * (k + 1)) else { break };
                    let name = md_string(&b, u32_at(m, 20)).unwrap_or_default();
                    let ver = (u32_at(m, 24) == 0xfeef_04bd)
                        .then(|| version(u32_at(m, 32), u32_at(m, 36)))
                        .filter(|v| v != "0.0.0.0");
                    modules.push((u64_at(m, 0), u32_at(m, 8), name, ver));
                }
            }
            3 => {
                found.insert("threads".into(), u32_at(s, 0).into());
            }
            15 => {
                let flags = u32_at(s, 4);
                if flags & 1 != 0 {
                    found.insert("process_id".into(), u32_at(s, 8).into());
                }
                if flags & 2 != 0
                    && let Some(t) = i64::try_from(u32_at(s, 12)).ok().and_then(unix_time)
                {
                    found.insert("process_created".into(), t.into());
                }
            }
            _ => {}
        }
    }
    cx.format_set("streams", names);
    if let Some(Value::Object(mut e)) = found.remove("exception") {
        if let Some(code) = found.remove("exception_code").and_then(|c| c.as_u64())
            && let Some(n) = exception_name(code, &os)
        {
            e.insert("name".into(), n.into());
        }
        if let Some(a) = exc_addr
            && let Some((base, _, name, _)) = modules.iter().find(|(base, size, _, _)| a >= *base && a < base + size)
        {
            e.insert("module".into(), base_name(name).into());
            e.insert("module_offset".into(), format!("{:#x}", a - base).into());
        }
        cx.format_set("exception", Value::Object(e));
    }
    for (k, v) in found {
        if k != "exception_code" {
            cx.format_set(&k, v);
        }
    }
    if !modules.is_empty() {
        cx.format_set("module_count", modules.len());
        if let Some((_, _, main, ver)) = modules.first() {
            cx.format_set("main_module", user_path(cx, main));
            cx.content().source("forensic.dump").title(base_name(main));
            if let Some(v) = ver {
                cx.format_set("main_module_version", v.clone());
            }
        }
        let list: Vec<Value> = modules
            .iter()
            .take(MAX_MODULES)
            .map(|(_, size, name, ver)| {
                let mut m = Map::new();
                m.insert("name".into(), base_name(name).into());
                m.insert("size".into(), (*size).into());
                if let Some(v) = ver {
                    m.insert("version".into(), v.clone().into());
                }
                Value::Object(m)
            })
            .collect();
        cx.format_set("modules", list);
    }
    Ok(())
}

fn base_name(p: &str) -> String {
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_string()
}

fn crash_dump(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut h = vec![0u8; 0x2000.min(usize::try_from(src.len()).unwrap_or(0))];
    src.read_exact_at(0, &mut h).map_err(|_| ExtractError::malformed("crash dump header"))?;
    let wide = h.get(4..8) == Some(b"DU64");
    cx.format_set("bits", if wide { 64 } else { 32 });
    cx.format_set("build", u32_at(&h, 12));
    cx.format_set("checked_build", u32_at(&h, 8) == 0x0c);
    let (machine, cpus, code, params, step) = if wide { (48, 52, 56, 64, 8) } else { (32, 36, 40, 44, 4) };
    cx.format_set(
        "machine",
        match u32_at(&h, machine) {
            0x14c => "x86",
            0x8664 => "x86_64",
            0xaa64 => "arm64",
            0x1c4 => "arm",
            _ => "unknown",
        },
    );
    cx.format_set("processors", u32_at(&h, cpus));
    let params: Vec<Value> = (0..4)
        .map(|i| {
            json!(format!("{:#x}", if wide { u64_at(&h, params + i * step) } else { u32_at(&h, params + i * step) }))
        })
        .collect();
    cx.format_set("bug_check", json!({ "code": format!("{:#010x}", u32_at(&h, code)), "parameters": params }));
    Ok(())
}

fn lime(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut at = 0u64;
    let (mut ranges, mut bytes, mut lo, mut hi) = (0u64, 0u64, u64::MAX, 0u64);
    let mut h = [0u8; 32];
    let mut version = None;
    while at + 32 <= src.len() && ranges < 1 << 20 {
        if src.read_exact_at(at, &mut h).is_err() || &h[..4] != b"EMiL" {
            break;
        }
        version.get_or_insert(u32_at(&h, 4));
        let (start, end) = (u64_at(&h, 8), u64_at(&h, 16));
        if end < start {
            cx.warn("a LiME range ends before it starts");
            break;
        }
        ranges += 1;
        bytes += end - start + 1;
        lo = lo.min(start);
        hi = hi.max(end);
        at += 32 + (end - start + 1);
    }
    if ranges == 0 {
        return Err(ExtractError::malformed("LiME header"));
    }
    if let Some(v) = version {
        cx.format_set("version", v);
    }
    cx.format_set("ranges", ranges);
    cx.format_set("memory_bytes", bytes);
    cx.format_set("lowest_address", format!("{lo:#x}"));
    cx.format_set("highest_address", format!("{hi:#x}"));
    if at != src.len() {
        cx.warn("the image does not end where its last range does");
    }
    Ok(())
}

crate::register_extractor!(Dump);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("minidump", "windows_crash_dump", "lime", "hiberfil");
}
