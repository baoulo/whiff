//! Python bytecode (`.pyc`): the magic number and the Python version it
//! belongs to (release or development build), how the cache is validated
//! (source timestamp and size, or a checked / unchecked source hash), and
//! from the module's code object: the source file name, the module
//! docstring, the modules it imports and the functions and classes it
//! defines.
//!
//! The `marshal` stream is walked by a bounded reader that builds only
//! names and strings; nothing is unmarshalled into Python objects and no
//! bytecode is run. Imports come from the `IMPORT_NAME` instructions of
//! each code object (CPython 2.0 to 3.14).
//!
//! Specification: CPython's `Python/marshal.c`, `Lib/importlib/
//! _bootstrap_external.py` (magic numbers) and PEP 552 (hash-based pycs).

use std::rc::Rc;

use super::{hex, names, source_path, unix_time};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source};

/// Extractor for Python bytecode.
pub struct Pyc;

static META: ExtractorMeta = ExtractorMeta {
    id: "bytecode.python",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "pyc",
        name: "Python bytecode",
        family: "bytecode",
        mimes: &["application/x-python-code"],
        extensions: &["pyc", "pyo"],
        magic: &[],
        parent: None,
    }],
};

/// Objects read before the walk stops.
const MAX_OBJECTS: usize = 500_000;
/// Nesting followed before the walk stops.
const MAX_DEPTH: u32 = 64;
/// Code objects visited for imports and definitions.
const MAX_CODE: usize = 20_000;

/// Magic-number ranges per release (first, last = the release's own).
const VERSIONS: &[(u16, u16, &str)] = &[
    (20121, 20121, "1.5"),
    (50428, 50428, "1.6"),
    (50823, 50823, "2.0"),
    (60202, 60202, "2.1"),
    (60717, 60717, "2.2"),
    (62011, 62021, "2.3"),
    (62041, 62061, "2.4"),
    (62071, 62131, "2.5"),
    (62151, 62161, "2.6"),
    (62171, 62211, "2.7"),
    (3000, 3131, "3.0"),
    (3141, 3151, "3.1"),
    (3160, 3180, "3.2"),
    (3190, 3230, "3.3"),
    (3250, 3310, "3.4"),
    (3320, 3351, "3.5"),
    (3360, 3379, "3.6"),
    (3390, 3394, "3.7"),
    (3400, 3413, "3.8"),
    (3420, 3425, "3.9"),
    (3430, 3439, "3.10"),
    (3450, 3495, "3.11"),
    (3500, 3531, "3.12"),
    (3550, 3571, "3.13"),
    (3600, 3627, "3.14"),
    (3650, 3699, "3.15"),
];

/// The Python release of a magic number, and whether it is the release's
/// final number (rather than an alpha or beta build's).
fn version(magic: u16) -> Option<(&'static str, bool)> {
    VERSIONS.iter().find(|(lo, hi, _)| (*lo..=*hi).contains(&magic)).map(|(_, hi, v)| (*v, magic == *hi))
}

/// (major, minor) of a release string.
fn release(v: &str) -> (u8, u8) {
    let (a, b) = v.split_once('.').unwrap_or((v, "0"));
    (a.parse().unwrap_or(0), b.parse().unwrap_or(0))
}

/// `IMPORT_NAME` and `EXTENDED_ARG`, and whether instructions are two-byte
/// words (3.6+) rather than an opcode with an optional 2-byte argument.
fn import_opcodes(v: (u8, u8)) -> Option<(u8, u8, bool)> {
    Some(match v {
        (2, _) => (108, 145, false),
        (3, 0..=5) => (108, 144, false),
        (3, 6..=12) => (108, 144, true),
        (3, 13) => (75, 71, true),
        (3, 14) => (73, 69, true),
        _ => return None,
    })
}

/// A marshalled object, as far as the report needs it.
#[derive(Debug, Clone)]
enum Obj {
    Null,
    Str(Rc<str>),
    Bytes(Rc<[u8]>),
    Tuple(Rc<[Obj]>),
    Code(Rc<Code>),
    Other,
}

impl Obj {
    fn str(&self) -> Option<Rc<str>> {
        match self {
            Obj::Str(s) => Some(s.clone()),
            _ => None,
        }
    }

    fn items(self) -> Vec<Obj> {
        match self {
            Obj::Tuple(t) => t.to_vec(),
            _ => Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
struct Code {
    bytecode: Rc<[u8]>,
    consts: Vec<Obj>,
    names: Vec<Obj>,
    filename: Option<Rc<str>>,
    name: Option<Rc<str>>,
    qualname: Option<Rc<str>>,
}

/// A bounded walk over a `marshal` stream.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
    /// Objects flagged for back-references (`r`), in reading order.
    refs: Vec<Obj>,
    /// Python 2's interned strings (`R`).
    interned: Vec<Obj>,
    objects: usize,
    v: (u8, u8),
}

impl Reader<'_> {
    fn bytes(&mut self, n: usize) -> Option<&[u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    fn i32(&mut self) -> Option<i32> {
        self.bytes(4).map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn len(&mut self) -> Option<usize> {
        usize::try_from(self.i32()?).ok()
    }

    fn text(&mut self, n: usize, latin1: bool) -> Option<Obj> {
        let b = self.bytes(n)?;
        let s: String =
            if latin1 { b.iter().map(|&c| char::from(c)).collect() } else { String::from_utf8_lossy(b).into() };
        Some(Obj::Str(s.into()))
    }

    fn many(&mut self, n: usize, depth: u32) -> Option<Vec<Obj>> {
        let mut v = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            v.push(self.obj(depth + 1)?);
        }
        Some(v)
    }

    #[allow(clippy::too_many_lines)] // one arm per marshal type
    fn obj(&mut self, depth: u32) -> Option<Obj> {
        if depth > MAX_DEPTH || self.objects >= MAX_OBJECTS {
            return None;
        }
        self.objects += 1;
        let t = self.u8()?;
        let slot = (t & 0x80 != 0).then(|| {
            self.refs.push(Obj::Other);
            self.refs.len() - 1
        });
        let o = match t & 0x7f {
            b'0' => Obj::Null,
            b'N' | b'F' | b'T' | b'S' | b'.' => Obj::Other,
            b'i' => {
                self.bytes(4)?;
                Obj::Other
            }
            b'I' | b'g' => {
                self.bytes(8)?;
                Obj::Other
            }
            b'y' => {
                self.bytes(16)?;
                Obj::Other
            }
            b'l' => {
                let n = self.i32()?.unsigned_abs() as usize;
                self.bytes(n.checked_mul(2)?)?;
                Obj::Other
            }
            b'f' => {
                let n = usize::from(self.u8()?);
                self.bytes(n)?;
                Obj::Other
            }
            b'x' => {
                for _ in 0..2 {
                    let n = usize::from(self.u8()?);
                    self.bytes(n)?;
                }
                Obj::Other
            }
            b's' => {
                let n = self.len()?;
                Obj::Bytes(self.bytes(n)?.into())
            }
            b't' if self.v.0 == 2 => {
                let n = self.len()?;
                let s = self.text(n, true)?;
                self.interned.push(s.clone());
                s
            }
            b'R' => {
                let i = self.len()?;
                self.interned.get(i)?.clone()
            }
            b't' | b'u' => {
                let n = self.len()?;
                self.text(n, false)?
            }
            b'a' | b'A' => {
                let n = self.len()?;
                self.text(n, true)?
            }
            b'z' | b'Z' => {
                let n = usize::from(self.u8()?);
                self.text(n, true)?
            }
            b'(' => {
                let n = self.len()?;
                Obj::Tuple(self.many(n, depth)?.into())
            }
            b')' => {
                let n = usize::from(self.u8()?);
                Obj::Tuple(self.many(n, depth)?.into())
            }
            b'[' | b'<' | b'>' => {
                let n = self.len()?;
                self.many(n, depth)?;
                Obj::Other
            }
            b'{' => {
                while !matches!(self.obj(depth + 1)?, Obj::Null) {
                    self.obj(depth + 1)?;
                }
                Obj::Other
            }
            b':' => {
                self.many(3, depth)?;
                Obj::Other
            }
            b'c' => Obj::Code(self.code(depth)?.into()),
            b'r' => {
                let i = self.len()?;
                self.refs.get(i)?.clone()
            }
            _ => return None,
        };
        if let Some(s) = slot {
            self.refs[s] = o.clone();
        }
        Some(o)
    }

    /// A code object's fields, by release.
    fn code(&mut self, depth: u32) -> Option<Code> {
        let v = self.v;
        let (ints, between, wide) = match v {
            (2, _) => (4, 3, false),
            (3, 0..=7) => (5, 3, false),
            (3, 8..=10) => (6, 3, false),
            _ => (5, 2, true),
        };
        for _ in 0..ints {
            self.i32()?;
        }
        let d = depth + 1;
        let bytecode = match self.obj(d)? {
            Obj::Bytes(b) => b,
            _ => Rc::from(&[][..]),
        };
        let consts = self.obj(d)?.items();
        let names = self.obj(d)?.items();
        for _ in 0..between {
            self.obj(d)?;
        }
        let filename = self.obj(d)?.str();
        let name = self.obj(d)?.str();
        let qualname = if wide { self.obj(d)?.str() } else { None };
        self.i32()?;
        self.obj(d)?;
        if wide {
            self.obj(d)?;
        }
        Some(Code { bytecode, consts, names, filename, name, qualname })
    }
}

/// The module names `IMPORT_NAME` instructions load.
fn imports(c: &Code, ops: (u8, u8, bool), out: &mut Vec<String>) {
    let (import, extended, words) = ops;
    let b = &c.bytecode;
    let mut push = |arg: u32| {
        if let Some(n) = c.names.get(arg as usize).and_then(Obj::str)
            && !out.iter().any(|o| **o == *n)
        {
            out.push(n.to_string());
        }
    };
    let mut ext = 0u32;
    if words {
        for w in b.as_chunks::<2>().0 {
            let arg = ext | u32::from(w[1]);
            if w[0] == extended {
                ext = arg << 8;
                continue;
            }
            ext = 0;
            if w[0] == import {
                push(arg);
            }
        }
    } else {
        let mut i = 0;
        while i < b.len() {
            let op = b[i];
            if op < 90 {
                i += 1;
                continue;
            }
            let Some(a) = b.get(i + 1..i + 3) else { break };
            i += 3;
            let arg = ext | u32::from(u16::from_le_bytes([a[0], a[1]]));
            if op == extended {
                ext = arg << 16;
                continue;
            }
            ext = 0;
            if op == import {
                push(arg);
            }
        }
    }
}

impl Extractor for Pyc {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let magic = u16::from_le_bytes([*h.first()?, *h.get(1)?]);
        (h.get(2..4) == Some(b"\r\n") && version(magic).is_some()).then_some(Sniff { format: "pyc", confidence: 0.8 })
    }

    #[allow(clippy::too_many_lines)] // header, then the code objects
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len().min(cx.parse_limit() as u64);
        let b = src.read_vec(0, usize::try_from(len).unwrap_or(0))?;
        if b.len() < 8 || b[2..4] != *b"\r\n" {
            return Err(ExtractError::malformed("no .pyc magic"));
        }
        let magic = u16::from_le_bytes([b[0], b[1]]);
        cx.format_set("magic", magic);
        let Some((ver, is_final)) = version(magic) else {
            cx.warn("unknown magic number");
            return Ok(());
        };
        cx.format_set("python_version", ver);
        if !is_final {
            cx.format_set("development_build", true);
        }
        let v = release(ver);
        let le32 = |at: usize| b.get(at..at + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]));
        let start = if magic >= 3392 && v.0 == 3 {
            let flags = le32(4).unwrap_or(0);
            if flags & 1 != 0 {
                let mode = if flags & 2 != 0 { "checked_hash" } else { "unchecked_hash" };
                cx.format_set("invalidation", mode);
                cx.format_set("source_hash", hex(&b[8..16.min(b.len())]));
            } else {
                cx.format_set("invalidation", "timestamp");
                source_stamp(cx, le32(8), le32(12));
            }
            16
        } else {
            cx.format_set("invalidation", "timestamp");
            if v >= (3, 3) {
                source_stamp(cx, le32(4), le32(8));
                12
            } else {
                source_stamp(cx, le32(4), None);
                8
            }
        };
        let mut r = Reader { b: &b, at: start, refs: Vec::new(), interned: Vec::new(), objects: 0, v };
        let Some(Obj::Code(top)) = r.obj(0) else {
            cx.warn("the module's code object could not be read");
            return Ok(());
        };
        if let Some(f) = &top.filename {
            cx.format_set("source_file", source_path(cx, f));
        }
        if let Some(Obj::Str(doc)) = top.consts.first()
            && top.names.iter().any(|n| n.str().as_deref() == Some("__doc__"))
        {
            cx.content().description(crate::plugin::truncate_chars(doc.trim(), 2000));
        }
        let ops = import_opcodes(v);
        let mut found = Vec::new();
        let mut defined = Vec::new();
        let mut queue = vec![top.clone()];
        let mut seen = 0usize;
        while let Some(c) = queue.pop() {
            seen += 1;
            if seen > MAX_CODE {
                break;
            }
            if let Some(ops) = ops {
                imports(&c, ops, &mut found);
            }
            for k in &c.consts {
                if let Obj::Code(inner) = k {
                    if Rc::ptr_eq(&c, &top)
                        && let Some(n) = inner.qualname.as_ref().or(inner.name.as_ref())
                        && !n.starts_with('<')
                    {
                        defined.push(n.to_string());
                    }
                    queue.push(inner.clone());
                }
            }
        }
        cx.format_set("code_objects", seen);
        if !found.is_empty() {
            cx.format_set("imports", names(&found));
        }
        if !defined.is_empty() {
            cx.format_set("definitions", names(&defined));
        }
        Ok(())
    }
}

/// The source file's modification time and size a timestamp pyc records.
fn source_stamp(cx: &mut Context<'_>, mtime: Option<u32>, size: Option<u32>) {
    if let Some(t) = mtime.and_then(|t| unix_time(i64::from(t))) {
        cx.format_set("source_modified", t);
    }
    if let Some(s) = size {
        cx.format_set("source_size", s);
    }
}

crate::register_extractor!(Pyc);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_numbers_name_releases() {
        assert_eq!(version(62211), Some(("2.7", true)));
        assert_eq!(version(3413), Some(("3.8", true)));
        assert_eq!(version(3627), Some(("3.14", true)));
        assert_eq!(version(3600), Some(("3.14", false)));
        assert_eq!(version(4000), None);
    }

    #[test]
    fn imports_follow_extended_arguments() {
        // names[0x102] via EXTENDED_ARG 1 then IMPORT_NAME 2 (3.12 opcodes).
        let mut names: Vec<Obj> = (0..0x103).map(|_| Obj::Other).collect();
        names[0x102] = Obj::Str("json".into());
        names[1] = Obj::Str("os".into());
        let c = Code { bytecode: Rc::from(&[144, 1, 108, 2, 108, 1, 108, 1][..]), names, ..Code::default() };
        let mut out = Vec::new();
        imports(&c, (108, 144, true), &mut out);
        assert_eq!(out, ["json", "os"]);
        // Python 2: three-byte instructions.
        let c = Code { bytecode: Rc::from(&[100, 0, 0, 108, 1, 0, 1][..]), names: c.names, ..Code::default() };
        let mut out = Vec::new();
        imports(&c, (108, 145, false), &mut out);
        assert_eq!(out, ["os"]);
    }

    #[test]
    fn marshal_back_references_resolve() {
        // A tuple of a flagged short string and a reference to it.
        let b = [b')', 2, b'Z' | 0x80, 4, b't', b'i', b'd', b'e', b'r', 0, 0, 0, 0];
        let mut r = Reader { b: &b, at: 0, refs: Vec::new(), interned: Vec::new(), objects: 0, v: (3, 12) };
        let items = r.obj(0).unwrap().items();
        assert_eq!(items[1].str().as_deref(), Some("tide"));
    }

    crate::fixture_tests!("pyc");
}
