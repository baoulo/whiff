//! Bytecode of smaller virtual machines:
//! * Lua (`luac` 5.1 to 5.4) and LuaJIT: the Lua version, the chunk's
//!   source name, whether debug information was stripped, the number
//!   sizes, LuaJIT's FFI and GC64 flags;
//! * Erlang BEAM: the module name (and Elixir modules), exports and
//!   imported modules, attributes (behaviours, `vsn`), the compiler
//!   version, options and source path, the chunks present (debug
//!   information, documentation);
//! * Emacs Lisp byte code (`.elc`): the Emacs version, the functions it
//!   defines and the features it provides;
//! * mruby (RITE): the binary format and compiler, sections, the source
//!   file names of the debug section;
//! * Ruby YARV instruction sequences (`YARB`): the Ruby version, byte
//!   order and word size, instruction sequences;
//! * OCaml compiled files: what kind (interface, bytecode object or
//!   library, native object, typed tree, executable) and the magic
//!   version with its OCaml release.
//!
//! Specifications: Lua's `ldump.c` (5.1 to 5.4) and LuaJIT's
//! `lj_bcdump.h`; Erlang's `beam_lib` and the external term format; Emacs's
//! `bytecomp.el`; mruby's `doc/internal/mrb_format.md`; CRuby's
//! `compile.c` (`ibf_header`); OCaml's `utils/config.mlp` magic numbers.

use serde_json::{Map, Value};

use super::{names, source_path, uleb};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for Lua, BEAM, Emacs Lisp, mruby, YARV and OCaml bytecode.
pub struct Vm;

static META: ExtractorMeta = ExtractorMeta {
    id: "bytecode.vm",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "luac",
            name: "Lua bytecode / LuaJIT",
            family: "bytecode",
            mimes: &["application/x-lua-bytecode"],
            extensions: &["luac", "ljbc"],
            magic: &[Magic::prefix(b"\x1bLua"), Magic::prefix(b"\x1bLJ")],
            parent: None,
        },
        FormatSpec {
            id: "beam",
            name: "Erlang BEAM",
            family: "bytecode",
            mimes: &["application/x-erlang-binary"],
            extensions: &["beam"],
            magic: &[Magic::at(8, b"BEAM")],
            parent: None,
        },
        FormatSpec {
            id: "elc",
            name: "Emacs Lisp byte code",
            family: "bytecode",
            mimes: &["application/x-elc"],
            extensions: &["elc"],
            magic: &[Magic::prefix(b";ELC")],
            parent: None,
        },
        FormatSpec {
            id: "mruby",
            name: "mruby bytecode (RITE)",
            family: "bytecode",
            mimes: &["application/x-mruby"],
            extensions: &["mrb"],
            magic: &[Magic::prefix(b"RITE")],
            parent: None,
        },
        FormatSpec {
            id: "yarv",
            name: "Ruby YARV instruction sequence",
            family: "bytecode",
            mimes: &[],
            extensions: &["yarb"],
            magic: &[Magic::prefix(b"YARB")],
            parent: None,
        },
        FormatSpec {
            id: "ocaml_bytecode",
            name: "OCaml compiled interface / object",
            family: "bytecode",
            mimes: &[],
            extensions: &["cmi", "cmo", "cma", "cmx", "cmxa", "cmt", "cmti"],
            magic: &[Magic::prefix(b"Caml1999")],
            parent: None,
        },
    ],
};

/// Erlang term nesting followed before giving up.
const MAX_DEPTH: u32 = 32;

impl Extractor for Vm {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len().min(cx.parse_limit() as u64);
        let b = src.read_vec(0, usize::try_from(len).unwrap_or(0))?;
        if b.starts_with(b"\x1bLua") {
            lua(&b, cx);
        } else if b.starts_with(b"\x1bLJ") {
            luajit(&b, cx);
        } else if b.get(8..12) == Some(b"BEAM") {
            beam(&b, cx);
        } else if b.starts_with(b";ELC") {
            elc(&b, cx);
        } else if b.starts_with(b"RITE") {
            mruby(&b, cx);
        } else if b.starts_with(b"YARB") {
            yarv(&b, cx);
        } else if b.starts_with(b"Caml1999") {
            ocaml(&b, cx);
        } else {
            return Err(ExtractError::malformed("unknown bytecode header"));
        }
        Ok(())
    }
}

crate::register_extractor!(Vm);

fn le32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
}

/// A chunk name as the report shows it: `@file` and `=name` lose their
/// prefix.
fn chunk_name(cx: &Context<'_>, raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let s = s.trim_end_matches('\0');
    match s.strip_prefix('@') {
        Some(path) => source_path(cx, path),
        None => s.strip_prefix('=').unwrap_or(s).to_string(),
    }
}

fn lua(b: &[u8], cx: &mut Context<'_>) {
    let Some(&v) = b.get(4) else { return };
    let version = format!("{}.{}", v >> 4, v & 0xf);
    cx.format_set("implementation", "Lua");
    cx.format_set("lua_version", version);
    let mut sizes = Map::new();
    // Where the main function's source name is, and how its length is coded.
    let source: Option<(usize, u8)> = match v {
        0x51 => {
            if let [endian, int, size_t, ins, num, integral] = b.get(6..12).unwrap_or_default()[..] {
                cx.format_set("byte_order", if endian == 1 { "little_endian" } else { "big_endian" });
                sizes.insert("int".into(), int.into());
                sizes.insert("size_t".into(), size_t.into());
                sizes.insert("instruction".into(), ins.into());
                sizes.insert("number".into(), num.into());
                cx.format_set("number_type", if integral == 1 { "integer" } else { "float" });
                Some((12, size_t))
            } else {
                None
            }
        }
        0x52 => {
            if let [_, int, size_t, ins, num, integral] = b.get(6..12).unwrap_or_default()[..] {
                sizes.insert("int".into(), int.into());
                sizes.insert("size_t".into(), size_t.into());
                sizes.insert("instruction".into(), ins.into());
                sizes.insert("number".into(), num.into());
                cx.format_set("number_type", if integral == 1 { "integer" } else { "float" });
            }
            None
        }
        0x53 => {
            if let [int, size_t, ins, integer, num] = b.get(12..17).unwrap_or_default()[..] {
                sizes.insert("int".into(), int.into());
                sizes.insert("size_t".into(), size_t.into());
                sizes.insert("instruction".into(), ins.into());
                sizes.insert("integer".into(), integer.into());
                sizes.insert("number".into(), num.into());
            }
            Some((33 + 1, 0))
        }
        0x54 => {
            if let [ins, integer, num] = b.get(12..15).unwrap_or_default()[..] {
                sizes.insert("instruction".into(), ins.into());
                sizes.insert("integer".into(), integer.into());
                sizes.insert("number".into(), num.into());
            }
            Some((31 + 1, 1))
        }
        _ => None,
    };
    if !sizes.is_empty() {
        cx.format_set("sizes", Value::Object(sizes));
    }
    let Some((at, coding)) = source else { return };
    // 5.1: a size_t length counting the NUL; 5.3: one byte (0xFF: a size_t
    // follows), counting one more than the characters; 5.4: a big-endian
    // base-128 number, likewise.
    let name = match coding {
        0 => b.get(at).and_then(|&n| match n {
            0 => Some(None),
            0xff => None,
            n => b.get(at + 1..at + usize::from(n)).map(Some),
        }),
        1 => {
            let mut n = 0usize;
            let mut i = at;
            loop {
                let Some(&x) = b.get(i) else { break None };
                i += 1;
                n = (n << 7) | usize::from(x & 0x7f);
                if x & 0x80 != 0 || n > 1 << 20 {
                    break Some(n);
                }
            }
            .and_then(|n| if n == 0 { Some(None) } else { b.get(i..i + n - 1).map(Some) })
        }
        size_t => {
            let n = if size_t == 8 {
                b.get(at..at + 8).map(|x| u64::from_le_bytes(x.try_into().unwrap_or_default()))
            } else {
                le32(b, at).map(u64::from)
            };
            n.and_then(|n| {
                let n = usize::try_from(n).ok()?;
                let start = at + usize::from(size_t);
                if n == 0 { Some(None) } else { b.get(start..start + n - 1).map(Some) }
            })
        }
    };
    match name {
        Some(Some(raw)) => {
            cx.format_set("source", chunk_name(cx, raw));
            cx.format_set("stripped", false);
        }
        Some(None) => cx.format_set("stripped", true),
        None => {}
    }
}

fn luajit(b: &[u8], cx: &mut Context<'_>) {
    cx.format_set("implementation", "LuaJIT");
    let Some(&v) = b.get(3) else { return };
    cx.format_set("bytecode_version", v);
    let mut at = 4;
    let Some((flags, n)) = uleb(b.get(at..).unwrap_or_default()) else { return };
    at += n;
    cx.format_set("byte_order", if flags & 1 != 0 { "big_endian" } else { "little_endian" });
    if flags & 4 != 0 {
        cx.format_set("ffi", true);
    }
    if flags & 8 != 0 {
        cx.format_set("gc64", true);
    }
    let stripped = flags & 2 != 0;
    cx.format_set("stripped", stripped);
    if !stripped
        && let Some((len, n)) = uleb(b.get(at..).unwrap_or_default())
        && let Some(raw) = usize::try_from(len).ok().and_then(|len| b.get(at + n..at + n + len))
    {
        cx.format_set("source", chunk_name(cx, raw));
    }
}

/// A decoded Erlang term, as far as the report needs it.
#[derive(Debug, Clone, PartialEq)]
enum Term {
    Atom(String),
    Int(i64),
    Str(String),
    List(Vec<Term>),
    Tuple(Vec<Term>),
    Other,
}

impl Term {
    fn text(&self) -> Option<String> {
        match self {
            Term::Atom(s) | Term::Str(s) => Some(s.clone()),
            Term::Int(i) => Some(i.to_string()),
            Term::List(l) if l.iter().all(|t| matches!(t, Term::Int(0..=255))) => Some(
                l.iter()
                    .filter_map(|t| if let Term::Int(c) = t { u8::try_from(*c).ok().map(char::from) } else { None })
                    .collect(),
            ),
            _ => None,
        }
    }

    /// A property list's `{key, value}` pairs.
    fn pairs(&self) -> Vec<(String, Term)> {
        let Term::List(items) = self else { return Vec::new() };
        items
            .iter()
            .filter_map(|t| match t {
                Term::Tuple(kv) if kv.len() == 2 => match &kv[0] {
                    Term::Atom(k) => Some((k.clone(), kv[1].clone())),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }
}

/// The external term format (`term_to_binary`), bounded.
fn term(b: &[u8], at: &mut usize, depth: u32) -> Option<Term> {
    if depth > MAX_DEPTH {
        return None;
    }
    let take = |at: &mut usize, n: usize| -> Option<&[u8]> {
        let s = b.get(*at..at.checked_add(n)?)?;
        *at += n;
        Some(s)
    };
    let tag = *take(at, 1)?.first()?;
    let u16be = |s: &[u8]| usize::from(u16::from_be_bytes([s[0], s[1]]));
    let u32be = |s: &[u8]| u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as usize;
    Some(match tag {
        97 => Term::Int(i64::from(take(at, 1)?[0])),
        98 => Term::Int(i64::from(i32::from_be_bytes(take(at, 4)?.try_into().ok()?))),
        100 | 118 => {
            let n = u16be(take(at, 2)?);
            Term::Atom(String::from_utf8_lossy(take(at, n)?).into_owned())
        }
        115 | 119 => {
            let n = usize::from(take(at, 1)?[0]);
            Term::Atom(String::from_utf8_lossy(take(at, n)?).into_owned())
        }
        104 | 105 => {
            let n = if tag == 104 { usize::from(take(at, 1)?[0]) } else { u32be(take(at, 4)?) };
            Term::Tuple((0..n).map(|_| term(b, at, depth + 1)).collect::<Option<_>>()?)
        }
        106 => Term::List(Vec::new()),
        107 => {
            let n = u16be(take(at, 2)?);
            Term::Str(String::from_utf8_lossy(take(at, n)?).into_owned())
        }
        108 => {
            let n = u32be(take(at, 4)?);
            if n > b.len() {
                return None;
            }
            let items = (0..n).map(|_| term(b, at, depth + 1)).collect::<Option<Vec<_>>>()?;
            term(b, at, depth + 1)?;
            Term::List(items)
        }
        109 => {
            let n = u32be(take(at, 4)?);
            Term::Str(String::from_utf8_lossy(take(at, n)?).into_owned())
        }
        110 => {
            let n = usize::from(take(at, 1)?[0]);
            take(at, n + 1)?;
            Term::Other
        }
        70 => {
            take(at, 8)?;
            Term::Other
        }
        116 => {
            let n = u32be(take(at, 4)?);
            for _ in 0..n.min(b.len()) * 2 {
                term(b, at, depth + 1)?;
            }
            Term::Other
        }
        _ => return None,
    })
}

/// A chunk's term (`131` then the term).
fn chunk_term(data: &[u8]) -> Option<Term> {
    let mut at = 1;
    (data.first() == Some(&131)).then(|| term(data, &mut at, 0)).flatten()
}

#[allow(clippy::too_many_lines)] // one chunk kind after another
fn beam(b: &[u8], cx: &mut Context<'_>) {
    let mut chunks = Vec::new();
    let mut behaviours: Vec<String> = Vec::new();
    let mut atoms: Vec<String> = Vec::new();
    let mut exports = Vec::new();
    let mut imported: Vec<String> = Vec::new();
    let (mut imports, mut functions) = (Vec::new(), None);
    let mut at = 12;
    while at + 8 <= b.len() && chunks.len() < 64 {
        let id = String::from_utf8_lossy(&b[at..at + 4]).into_owned();
        let size = be32(b, at + 4).unwrap_or(0) as usize;
        let Some(data) = b.get(at + 8..(at + 8).saturating_add(size)) else {
            cx.warn(format!("chunk {id} runs past the end of the file"));
            break;
        };
        match id.as_str() {
            "AtU8" | "Atom" => {
                let count = data.get(..4).map_or(0, |c| i32::from_be_bytes([c[0], c[1], c[2], c[3]]));
                let mut p = 4;
                for _ in 0..count.unsigned_abs().min(1 << 20) {
                    // OTP 28 codes lengths as compact terms (a negative count).
                    let len = if count < 0 {
                        let Some(&x) = data.get(p) else { break };
                        p += 1;
                        if x & 0x08 == 0 {
                            usize::from(x >> 4)
                        } else {
                            let Some(&y) = data.get(p) else { break };
                            p += 1;
                            (usize::from(x >> 5) << 8) | usize::from(y)
                        }
                    } else {
                        let Some(&x) = data.get(p) else { break };
                        p += 1;
                        usize::from(x)
                    };
                    let Some(s) = data.get(p..p + len) else { break };
                    p += len;
                    atoms.push(String::from_utf8_lossy(s).into_owned());
                }
            }
            "ExpT" => {
                let n = be32(data, 0).unwrap_or(0) as usize;
                for i in 0..n.min(1 << 16) {
                    let (Some(f), Some(a)) = (be32(data, 4 + i * 12), be32(data, 8 + i * 12)) else { break };
                    exports.push((f, a));
                }
            }
            "ImpT" => {
                let n = be32(data, 0).unwrap_or(0) as usize;
                for i in 0..n.min(1 << 16) {
                    let Some(m) = be32(data, 4 + i * 12) else { break };
                    imports.push(m);
                }
            }
            "Code" => functions = be32(data, 16),
            "Attr" => {
                if let Some(t) = chunk_term(data) {
                    for (k, v) in t.pairs() {
                        match k.as_str() {
                            "vsn" => {
                                if let Some(s) = match &v {
                                    Term::List(l) => l.first().and_then(Term::text),
                                    other => other.text(),
                                } {
                                    cx.format_set("vsn", s);
                                }
                            }
                            "behaviour" | "behavior" => {
                                // One attribute per `-behaviour` line.
                                if let Term::List(l) = v {
                                    behaviours.extend(l.iter().filter_map(Term::text));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            "CInf" => {
                if let Some(t) = chunk_term(data) {
                    for (k, v) in t.pairs() {
                        match (k.as_str(), v) {
                            ("version", v) => {
                                if let Some(s) = v.text() {
                                    cx.format_set("compiler_version", s);
                                }
                            }
                            ("source", v) => {
                                if let Some(s) = v.text() {
                                    cx.format_set("source", source_path(cx, &s));
                                }
                            }
                            ("options", Term::List(l)) => {
                                let list: Vec<String> = l
                                    .iter()
                                    .filter_map(|o| match o {
                                        Term::Atom(a) => Some(a.clone()),
                                        Term::Tuple(t) => t.first().and_then(Term::text),
                                        _ => None,
                                    })
                                    .collect();
                                if !list.is_empty() {
                                    cx.format_set("compile_options", names(&list));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
        chunks.push(id);
        at += 8 + size.div_ceil(4) * 4;
    }
    let atom = |i: u32| atoms.get((i as usize).checked_sub(1)?).cloned();
    if let Some(m) = atom(1) {
        if m.starts_with("Elixir.") {
            cx.format_set("language", "elixir");
        }
        cx.format_set("module", m);
    }
    let list: Vec<String> = exports
        .iter()
        .filter_map(|&(f, a)| Some(format!("{}/{a}", atom(f)?)))
        .filter(|e| e != "module_info/0" && e != "module_info/1")
        .collect();
    cx.format_set("exports", names(&list));
    for m in imports.iter().filter_map(|&m| atom(m)) {
        if !imported.contains(&m) && m != "erlang" {
            imported.push(m);
        }
    }
    if !imported.is_empty() {
        imported.sort();
        cx.format_set("imported_modules", names(&imported));
    }
    if let Some(n) = functions {
        cx.format_set("functions", n);
    }
    cx.format_set("debug_info", chunks.iter().any(|c| c == "Dbgi" || c == "Abst"));
    if chunks.iter().any(|c| c == "Docs") {
        cx.format_set("documentation", true);
    }
    if !behaviours.is_empty() {
        cx.format_set("behaviours", names(&behaviours));
    }
    cx.format_set("chunks", names(&chunks));
}

fn elc(b: &[u8], cx: &mut Context<'_>) {
    if let Some(&v) = b.get(4) {
        cx.format_set("bytecode_version", v);
    }
    let text = String::from_utf8_lossy(&b[..b.len().min(1 << 20)]);
    if let Some(v) = text.lines().take(16).find_map(|l| l.strip_prefix(";;; in Emacs version ")) {
        cx.format_set("emacs_version", v.trim());
    }
    let defined = |prefixes: &[&str]| {
        let mut out: Vec<String> = Vec::new();
        for prefix in prefixes {
            for (i, _) in text.match_indices(prefix).take(10_000) {
                let rest = &text[i + prefix.len()..];
                let name: String = rest.chars().take_while(|c| !c.is_whitespace() && *c != ')').collect();
                if !name.is_empty() && !out.contains(&name) {
                    out.push(name);
                }
            }
        }
        out
    };
    let functions = defined(&["(defalias '"]);
    let variables = defined(&["(defvar ", "(defconst "]);
    let features = defined(&["(provide '"]);
    cx.format_set("functions", names(&functions));
    if !variables.is_empty() {
        cx.format_set("variables", names(&variables));
    }
    if !features.is_empty() {
        cx.format_set("provides", names(&features));
    }
}

fn mruby(b: &[u8], cx: &mut Context<'_>) {
    let ascii = |r: std::ops::Range<usize>| b.get(r).map(|s| String::from_utf8_lossy(s).into_owned());
    let Some(version) = ascii(4..8) else { return };
    cx.format_set("format_version", version.clone());
    // RITE0300 headers are 20 bytes; older ones have a CRC before the size.
    let (size_at, compiler_at) = if version.as_str() >= "0200" { (8, 12) } else { (10, 14) };
    if let (Some(name), Some(cv)) = (ascii(compiler_at..compiler_at + 4), ascii(compiler_at + 4..compiler_at + 8)) {
        cx.format_set("compiler", format!("{name} {cv}"));
    }
    let size = be32(b, size_at).unwrap_or(0) as usize;
    if size as u64 != b.len() as u64 {
        cx.warn(format!("header gives {size} bytes, the file has {}", b.len()));
    }
    let mut at = compiler_at + 8;
    let mut sections = Vec::new();
    let mut files = Vec::new();
    while at + 8 <= b.len() && sections.len() < 32 {
        let id = String::from_utf8_lossy(&b[at..at + 4]).trim_end_matches('\0').to_string();
        let len = be32(b, at + 4).unwrap_or(0) as usize;
        if id == "DBG" {
            let count = b.get(at + 8..at + 10).map_or(0, |c| u16::from_be_bytes([c[0], c[1]]));
            let mut p = at + 10;
            for _ in 0..count.min(256) {
                let Some(n) = b.get(p..p + 2).map(|c| usize::from(u16::from_be_bytes([c[0], c[1]]))) else { break };
                let Some(name) = b.get(p + 2..p + 2 + n) else { break };
                files.push(source_path(cx, &String::from_utf8_lossy(name)));
                p += 2 + n;
            }
        }
        let end = id == "END";
        sections.push(id);
        if end || len < 8 {
            break;
        }
        at += len;
    }
    cx.format_set("sections", names(&sections));
    cx.format_set("debug_info", sections.iter().any(|s| s == "DBG"));
    if !files.is_empty() {
        cx.format_set("source_files", names(&files));
    }
}

fn yarv(b: &[u8], cx: &mut Context<'_>) {
    let (Some(major), Some(minor)) = (le32(b, 4), le32(b, 8)) else { return };
    cx.format_set("ruby_version", format!("{major}.{minor}"));
    if let Some(n) = le32(b, 20) {
        cx.format_set("instruction_sequences", n);
    }
    if let Some(&[endian, word]) = b.get(36..38).and_then(|s| <&[u8; 2]>::try_from(s).ok()) {
        cx.format_set("byte_order", if endian == b'l' { "little_endian" } else { "big_endian" });
        cx.format_set("word_size", word);
    }
}

/// OCaml releases by magic-number version: each release bumps every
/// file kind's number together (4.10 = 027 … 5.3 = 035).
fn ocaml_release(n: u32) -> Option<&'static str> {
    Some(match n {
        27 => "4.10",
        28 => "4.11",
        29 => "4.12",
        30 => "4.13",
        31 => "4.14",
        32 => "5.0",
        33 => "5.1",
        34 => "5.2",
        35 => "5.3",
        _ => return None,
    })
}

fn ocaml(b: &[u8], cx: &mut Context<'_>) {
    let Some(&k) = b.get(8) else { return };
    let kind = match k {
        b'I' => "interface",
        b'O' => "bytecode_object",
        b'A' => "bytecode_library",
        b'Y' => "native_object",
        b'Z' => "native_library",
        b'X' => "bytecode_executable",
        b'T' => "typed_tree",
        b'D' => "native_shared_library",
        b'M' => "ast_implementation",
        b'N' => "ast_interface",
        _ => "other",
    };
    cx.format_set("kind", kind);
    let digits = b.get(9..12).and_then(|d| std::str::from_utf8(d).ok()).unwrap_or("");
    cx.format_set("magic", String::from_utf8_lossy(&b[..12.min(b.len())]).into_owned());
    if let Some(r) = digits.parse().ok().and_then(ocaml_release) {
        cx.format_set("ocaml_version", r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erlang_terms_decode_property_lists() {
        // [{version,"8.5"},{options,[debug_info]}]
        let mut b = vec![131, 108, 0, 0, 0, 2, 104, 2, 119, 7];
        b.extend_from_slice(b"version");
        b.extend_from_slice(&[107, 0, 3]);
        b.extend_from_slice(b"8.5");
        b.extend_from_slice(&[104, 2, 119, 7]);
        b.extend_from_slice(b"options");
        b.extend_from_slice(&[108, 0, 0, 0, 1, 119, 10]);
        b.extend_from_slice(b"debug_info");
        b.extend_from_slice(&[106, 106]);
        let pairs = chunk_term(&b).unwrap().pairs();
        assert_eq!(pairs[0], ("version".into(), Term::Str("8.5".into())));
        assert_eq!(pairs[1].1, Term::List(vec![Term::Atom("debug_info".into())]));
    }

    #[test]
    fn erlang_terms_stop_at_depth() {
        let b: Vec<u8> = std::iter::once(131).chain(std::iter::repeat_n([104, 1], 100).flatten()).collect();
        assert_eq!(chunk_term(&b), None);
    }

    #[test]
    fn every_behaviour_attribute_is_kept() {
        // A module `tides` with two `-behaviour` lines (two attribute tuples).
        let chunk = |id: &[u8], data: &[u8]| {
            let mut c = id.to_vec();
            c.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
            c.extend_from_slice(data);
            c.resize(c.len().div_ceil(4) * 4, 0);
            c
        };
        let mut attr = vec![131, 108, 0, 0, 0, 2];
        for b in [&b"gen_server"[..], b"supervisor"] {
            attr.extend_from_slice(&[104, 2, 119, 9]);
            attr.extend_from_slice(b"behaviour");
            attr.extend_from_slice(&[108, 0, 0, 0, 1, 119, u8::try_from(b.len()).unwrap()]);
            attr.extend_from_slice(b);
            attr.push(106);
        }
        attr.push(106);
        let mut body = b"BEAM".to_vec();
        body.extend(chunk(b"AtU8", b"\0\0\0\x01\x05tides"));
        body.extend(chunk(b"Attr", &attr));
        let mut beam = b"FOR1".to_vec();
        beam.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        beam.extend(body);
        let r = crate::plugin::testing::report_for("tides.beam", &beam);
        let f = &r.format["beam"];
        assert_eq!(f["module"], "tides");
        assert_eq!(f["behaviours"], serde_json::json!(["gen_server", "supervisor"]));
    }

    #[test]
    fn ocaml_magic_versions() {
        assert_eq!(ocaml_release(31), Some("4.14"));
        assert_eq!(ocaml_release(99), None);
    }

    crate::fixture_tests!("luac", "beam", "elc", "mruby", "yarv", "ocaml_bytecode");
}
