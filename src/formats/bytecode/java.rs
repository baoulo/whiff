//! Java class files: the class-file version and the Java release it
//! targets (preview features), what the file defines (class, interface,
//! enum, record, annotation or module), its name, superclass, interfaces
//! and access flags; field and method counts with the method names; the
//! source file, record components, permitted subclasses of a sealed type,
//! nest and inner classes, annotations (and from them the source language:
//! Kotlin, Scala, Groovy), the packages it references; debug information
//! (line numbers, local variables); a module descriptor's requires,
//! exports, opens, uses, provides and main class.
//!
//! Specification: The Java Virtual Machine Specification, chapter 4 ("The
//! class File Format"), Java SE 25 edition.

use serde_json::{Map, Value};

use super::{java_name, java_release, mutf8, names, package_of};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source};

/// Extractor for Java class files.
pub struct JavaClass;

static META: ExtractorMeta = ExtractorMeta {
    id: "bytecode.java",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "class",
        name: "Java class",
        family: "bytecode",
        mimes: &["application/java-vm", "application/x-java-class"],
        extensions: &["class"],
        magic: &[],
        parent: None,
    }],
};

/// Annotation nesting followed before giving up.
const MAX_DEPTH: u32 = 32;

/// A constant-pool entry, as far as the report needs it.
#[derive(Debug, Clone, Copy)]
enum Cp {
    Utf8(usize, usize),
    Class(u16),
    Module(u16),
    Package(u16),
    Other,
}

/// A bounds-checked big-endian cursor.
struct Cur<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cur<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.at)?;
        self.at += 1;
        Some(v)
    }

    fn u16(&mut self) -> Option<u16> {
        let v = self.b.get(self.at..self.at + 2)?;
        self.at += 2;
        Some(u16::from_be_bytes([v[0], v[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let v = self.b.get(self.at..self.at + 4)?;
        self.at += 4;
        Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let v = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(v)
    }
}

struct Pool<'a> {
    b: &'a [u8],
    entries: Vec<Cp>,
}

impl Pool<'_> {
    fn utf8(&self, i: u16) -> Option<String> {
        match self.entries.get(usize::from(i))? {
            Cp::Utf8(at, len) => Some(mutf8(&self.b[*at..*at + *len])),
            _ => None,
        }
    }

    /// The name a Class, Module or Package entry points to.
    fn named(&self, i: u16) -> Option<String> {
        match self.entries.get(usize::from(i))? {
            Cp::Class(n) | Cp::Module(n) | Cp::Package(n) => self.utf8(*n),
            _ => None,
        }
    }

    fn class(&self, i: u16) -> Option<String> {
        self.named(i).map(|n| java_name(&n))
    }
}

fn pool<'a>(c: &mut Cur<'a>) -> Option<Pool<'a>> {
    let count = c.u16()?;
    let mut entries = vec![Cp::Other];
    while entries.len() < usize::from(count) {
        let tag = c.u8()?;
        let e = match tag {
            1 => {
                let len = usize::from(c.u16()?);
                let at = c.at;
                c.bytes(len)?;
                Cp::Utf8(at, len)
            }
            7 => Cp::Class(c.u16()?),
            19 => Cp::Module(c.u16()?),
            20 => Cp::Package(c.u16()?),
            8 | 16 => {
                c.u16()?;
                Cp::Other
            }
            15 => {
                c.bytes(3)?;
                Cp::Other
            }
            3 | 4 | 9..=12 | 17 | 18 => {
                c.u32()?;
                Cp::Other
            }
            5 | 6 => {
                c.bytes(8)?;
                entries.push(Cp::Other);
                Cp::Other
            }
            _ => return None,
        };
        entries.push(e);
    }
    Some(Pool { b: c.b, entries })
}

/// Skip one `element_value` of an annotation.
fn skip_value(c: &mut Cur<'_>, depth: u32) -> Option<()> {
    if depth > MAX_DEPTH {
        return None;
    }
    match c.u8()? {
        b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z' | b's' | b'c' => {
            c.u16()?;
        }
        b'e' => {
            c.u32()?;
        }
        b'@' => {
            skip_annotation(c, depth + 1)?;
        }
        b'[' => {
            for _ in 0..c.u16()? {
                skip_value(c, depth + 1)?;
            }
        }
        _ => return None,
    }
    Some(())
}

/// Skip one annotation, returning its type index.
fn skip_annotation(c: &mut Cur<'_>, depth: u32) -> Option<u16> {
    let ty = c.u16()?;
    for _ in 0..c.u16()? {
        c.u16()?;
        skip_value(c, depth)?;
    }
    Some(ty)
}

/// The annotation type names of a `Runtime(In)VisibleAnnotations` attribute.
fn annotations(p: &Pool<'_>, data: &[u8], out: &mut Vec<String>) {
    let mut c = Cur { b: data, at: 0 };
    let Some(n) = c.u16() else { return };
    for _ in 0..n {
        let Some(ty) = skip_annotation(&mut c, 0) else { return };
        if let Some(t) = p.utf8(ty) {
            out.push(java_name(&t));
        }
    }
}

/// What the members (fields and methods) and their attributes add up to.
#[derive(Default)]
struct Members {
    names: Vec<String>,
    count: u16,
    line_numbers: bool,
    local_variables: bool,
    code_bytes: u64,
}

fn members(c: &mut Cur<'_>, p: &Pool<'_>, methods: bool, annots: &mut Vec<String>) -> Option<Members> {
    let mut m = Members { count: c.u16()?, ..Members::default() };
    for _ in 0..m.count {
        let _access = c.u16()?;
        let name = p.utf8(c.u16()?).unwrap_or_default();
        c.u16()?;
        for _ in 0..c.u16()? {
            let attr = p.utf8(c.u16()?).unwrap_or_default();
            let len = c.u32()? as usize;
            let data = c.bytes(len)?;
            match attr.as_str() {
                "Code" => code(data, p, &mut m),
                "RuntimeVisibleAnnotations" | "RuntimeInvisibleAnnotations" if annots.len() < 256 => {
                    annotations(p, data, annots);
                }
                _ => {}
            }
        }
        if methods && name != "<init>" && name != "<clinit>" && !name.starts_with("lambda$") {
            m.names.push(name);
        }
    }
    Some(m)
}

/// A method's `Code` attribute: its length and the debug tables inside.
fn code(data: &[u8], p: &Pool<'_>, m: &mut Members) {
    let mut c = Cur { b: data, at: 4 };
    let Some(len) = c.u32() else { return };
    m.code_bytes += u64::from(len);
    let Some(exceptions) = c.bytes(len as usize).and_then(|_| c.u16()) else { return };
    if c.bytes(usize::from(exceptions) * 8).is_none() {
        return;
    }
    let Some(n) = c.u16() else { return };
    for _ in 0..n {
        let (Some(name), Some(len)) = (c.u16(), c.u32()) else { return };
        match p.utf8(name).as_deref() {
            Some("LineNumberTable") => m.line_numbers = true,
            Some("LocalVariableTable") => m.local_variables = true,
            _ => {}
        }
        if c.bytes(len as usize).is_none() {
            return;
        }
    }
}

/// A `Module` attribute.
fn module(p: &Pool<'_>, data: &[u8]) -> Option<Map<String, Value>> {
    let mut c = Cur { b: data, at: 0 };
    let mut m = Map::new();
    m.insert("name".into(), p.named(c.u16()?)?.into());
    let flags = c.u16()?;
    if flags & 0x20 != 0 {
        m.insert("open".into(), true.into());
    }
    if let Some(v) = p.utf8(c.u16()?) {
        m.insert("version".into(), v.into());
    }
    let mut requires = Vec::new();
    for _ in 0..c.u16()? {
        let name = p.named(c.u16()?).unwrap_or_default();
        let flags = c.u16()?;
        let version = p.utf8(c.u16()?);
        // `java.base` is implicit (mandated) in every module.
        if flags & 0x8000 == 0 {
            let mut r = name;
            if flags & 0x20 != 0 {
                r.insert_str(0, "transitive ");
            }
            if flags & 0x40 != 0 {
                r.insert_str(0, "static ");
            }
            if let Some(v) = version.filter(|_| !r.starts_with("java.") && !r.starts_with("jdk.")) {
                r = format!("{r}@{v}");
            }
            requires.push(r);
        }
    }
    m.insert("requires".into(), names(&requires));
    for key in ["exports", "opens"] {
        let mut list = Vec::new();
        for _ in 0..c.u16()? {
            let pkg = p.named(c.u16()?).unwrap_or_default().replace('/', ".");
            c.u16()?;
            let to = c.u16()?;
            c.bytes(usize::from(to) * 2)?;
            list.push(if to > 0 { format!("{pkg} (qualified)") } else { pkg });
        }
        if !list.is_empty() {
            m.insert(key.into(), names(&list));
        }
    }
    let mut uses = Vec::new();
    for _ in 0..c.u16()? {
        uses.push(p.class(c.u16()?).unwrap_or_default());
    }
    if !uses.is_empty() {
        m.insert("uses".into(), names(&uses));
    }
    let mut provides = Vec::new();
    for _ in 0..c.u16()? {
        let service = p.class(c.u16()?).unwrap_or_default();
        let n = c.u16()?;
        let with: Vec<String> = (0..n).filter_map(|_| c.u16()).filter_map(|i| p.class(i)).collect();
        provides.push(format!("{service} with {}", with.join(", ")));
    }
    if !provides.is_empty() {
        m.insert("provides".into(), names(&provides));
    }
    Some(m)
}

impl Extractor for JavaClass {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        // Mach-O universal binaries share the magic; their next word is a
        // small architecture count where a class file has its version.
        let major = u16::from_be_bytes([*h.get(6)?, *h.get(7)?]);
        (h.starts_with(b"\xca\xfe\xba\xbe") && (45..=120).contains(&major))
            .then_some(Sniff { format: "class", confidence: 0.9 })
    }

    #[allow(clippy::too_many_lines)] // the class file, front to back
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len().min(cx.parse_limit() as u64);
        let data = src.read_vec(0, usize::try_from(len).unwrap_or(0))?;
        let mut c = Cur { b: &data, at: 0 };
        if c.u32() != Some(0xcafe_babe) {
            return Err(ExtractError::malformed("no class-file magic"));
        }
        let (Some(minor), Some(major)) = (c.u16(), c.u16()) else {
            return Err(ExtractError::malformed("class-file version"));
        };
        cx.format_set("version", format!("{major}.{minor}"));
        if let Some(r) = java_release(major) {
            cx.format_set("java_release", r);
        }
        if minor == 0xffff {
            cx.format_set("preview_features", true);
        }
        let Some(p) = pool(&mut c) else {
            return Err(ExtractError::malformed("constant pool"));
        };
        cx.format_set("constant_pool_entries", p.entries.len().saturating_sub(1));
        let truncated = || ExtractError::malformed("class file ends early");
        let access = c.u16().ok_or_else(truncated)?;
        let this = p.class(c.u16().ok_or_else(truncated)?).unwrap_or_default();
        let sup = c.u16().ok_or_else(truncated)?;
        let sup = if sup == 0 { None } else { p.class(sup) };
        let n = c.u16().ok_or_else(truncated)?;
        let interfaces: Vec<String> = (0..n).filter_map(|_| c.u16()).filter_map(|i| p.class(i)).collect();

        let mut annots = Vec::new();
        let fields = members(&mut c, &p, false, &mut annots).ok_or_else(truncated)?;
        let methods = members(&mut c, &p, true, &mut annots);
        let mut kind = if access & 0x8000 != 0 {
            "module"
        } else if access & 0x2000 != 0 {
            "annotation"
        } else if access & 0x0200 != 0 {
            "interface"
        } else if access & 0x4000 != 0 {
            "enum"
        } else {
            "class"
        };
        let mut f = Map::new();
        let mut source_file = None;
        let mut language = None;
        let mut deprecated = false;
        let mut class_annots = Vec::new();
        if methods.is_some()
            && let Some(n) = c.u16()
        {
            for _ in 0..n {
                let (Some(name), Some(len)) = (c.u16(), c.u32()) else { break };
                let Some(a) = c.bytes(len as usize) else { break };
                let mut ac = Cur { b: a, at: 0 };
                match p.utf8(name).as_deref() {
                    Some("SourceFile") => source_file = ac.u16().and_then(|i| p.utf8(i)),
                    Some("Module") => {
                        if let Some(m) = module(&p, a) {
                            f.insert("module".into(), Value::Object(m));
                        }
                    }
                    Some("ModuleMainClass") => {
                        if let Some(m) = ac.u16().and_then(|i| p.class(i)) {
                            f.insert("main_class".into(), m.into());
                        }
                    }
                    Some("ModulePackages") => {
                        if let Some(n) = ac.u16() {
                            f.insert("module_packages".into(), n.into());
                        }
                    }
                    Some("Record") => {
                        kind = "record";
                        let mut list = Vec::new();
                        for _ in 0..ac.u16().unwrap_or(0) {
                            let Some(n) = ac.u16() else { break };
                            list.push(p.utf8(n).unwrap_or_default());
                            if ac.u16().is_none() {
                                break;
                            }
                            for _ in 0..ac.u16().unwrap_or(0) {
                                let (Some(_), Some(l)) = (ac.u16(), ac.u32()) else { break };
                                if ac.bytes(l as usize).is_none() {
                                    break;
                                }
                            }
                        }
                        f.insert("record_components".into(), names(&list));
                    }
                    Some("PermittedSubclasses") => {
                        let n = ac.u16().unwrap_or(0);
                        let list: Vec<String> = (0..n).filter_map(|_| ac.u16()).filter_map(|i| p.class(i)).collect();
                        f.insert("sealed".into(), true.into());
                        f.insert("permitted_subclasses".into(), names(&list));
                    }
                    Some("NestMembers") => {
                        f.insert("nest_members".into(), ac.u16().unwrap_or(0).into());
                    }
                    Some("NestHost") => {
                        if let Some(h) = ac.u16().and_then(|i| p.class(i)) {
                            f.insert("nest_host".into(), h.into());
                        }
                    }
                    Some("InnerClasses") => {
                        f.insert("inner_classes".into(), ac.u16().unwrap_or(0).into());
                    }
                    Some("Deprecated") => deprecated = true,
                    Some("RuntimeVisibleAnnotations" | "RuntimeInvisibleAnnotations") => {
                        annotations(&p, a, &mut class_annots);
                    }
                    Some("ScalaSig" | "Scala" | "TASTY") => language = Some("scala"),
                    Some("SourceDebugExtension") if a.starts_with(b"SMAP") && a.windows(6).any(|w| w == b"Kotlin") => {
                        language = Some("kotlin");
                    }
                    _ => {}
                }
            }
        } else {
            cx.warn("class file ends before its attributes");
        }

        cx.format_set("kind", kind);
        if kind != "module" {
            cx.format_set("class_name", this.clone());
        }
        let mut flags = Vec::new();
        for (bit, name) in [(0x0001, "public"), (0x0010, "final"), (0x0400, "abstract"), (0x1000, "synthetic")] {
            if access & bit != 0 && !(bit == 0x0400 && matches!(kind, "interface" | "annotation")) {
                flags.push(name);
            }
        }
        if !flags.is_empty() {
            cx.format_set("access", names(&flags));
        }
        if let Some(s) = sup.filter(|s| s != "java.lang.Object" && s != "java.lang.Record" && s != "java.lang.Enum") {
            cx.format_set("super_class", s);
        }
        if !interfaces.is_empty() {
            cx.format_set("interfaces", names(&interfaces));
        }
        cx.format_set("fields", fields.count);
        if let Some(m) = &methods {
            cx.format_set("methods", m.count);
            if !m.names.is_empty() {
                cx.format_set("method_names", names(&m.names));
            }
            cx.format_set("code_bytes", m.code_bytes);
        }
        if let Some(s) = &source_file {
            cx.format_set("source_file", s.clone());
        }
        for (k, v) in f {
            cx.format_set(&k, v);
        }
        if deprecated {
            cx.format_set("deprecated", true);
        }
        if !class_annots.is_empty() {
            if class_annots.iter().any(|a| a == "kotlin.Metadata") {
                language = Some("kotlin");
            } else if class_annots.iter().any(|a| a == "scala.reflect.ScalaSignature") {
                language = Some("scala");
            }
            cx.format_set("annotations", names(&class_annots));
        }
        if interfaces.iter().any(|i| i == "groovy.lang.GroovyObject") {
            language = Some("groovy");
        }
        if let Some(l) = language {
            cx.format_set("language", l);
        }

        // Packages the class refers to, other than its own.
        let own = package_of(&this).unwrap_or("");
        let mut packages: Vec<String> = Vec::new();
        let mut classes = 0u32;
        for e in &p.entries {
            if let Cp::Class(n) = e
                && let Some(name) = p.utf8(*n)
                && !name.starts_with('[')
            {
                classes += 1;
                let name = java_name(&name);
                if let Some(pkg) = package_of(&name)
                    && pkg != own
                    && !packages.iter().any(|q| q == pkg)
                {
                    packages.push(pkg.to_string());
                }
            }
        }
        cx.format_set("referenced_classes", classes);
        if !packages.is_empty() {
            packages.sort();
            cx.format_set("referenced_packages", names(&packages));
        }
        if let Some(m) = &methods {
            let mut debug = Map::new();
            debug.insert("source_file".into(), source_file.is_some().into());
            debug.insert("line_numbers".into(), (m.line_numbers || fields.line_numbers).into());
            debug.insert("local_variables".into(), (m.local_variables || fields.local_variables).into());
            cx.format_set("debug", Value::Object(debug));
        }
        Ok(())
    }
}

crate::register_extractor!(JavaClass);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_counts_wide_constants_twice() {
        // count 5: Utf8 "Tide", Long (two slots), Class -> #1.
        let b = [0, 5, 1, 0, 4, b'T', b'i', b'd', b'e', 5, 0, 0, 0, 0, 0, 0, 0, 1, 7, 0, 1];
        let mut c = Cur { b: &b, at: 0 };
        let p = pool(&mut c).unwrap();
        assert_eq!(p.entries.len(), 5);
        assert_eq!(p.class(4).as_deref(), Some("Tide"));
        assert_eq!(c.at, b.len());
    }

    #[test]
    fn annotations_skip_nested_values() {
        // Pool: #1 "LGauge;", #2 "value".
        let mut b = vec![0, 3, 1, 0, 7];
        b.extend_from_slice(b"LGauge;");
        b.extend_from_slice(&[1, 0, 5]);
        b.extend_from_slice(b"value");
        let mut c = Cur { b: &b, at: 0 };
        let p = pool(&mut c).unwrap();
        // Two annotations; the first has an array of nested annotations.
        let a = [0, 2, 0, 1, 0, 1, 0, 2, b'[', 0, 1, b'@', 0, 1, 0, 0, 0, 1, 0, 0];
        let mut out = Vec::new();
        annotations(&p, &a, &mut out);
        assert_eq!(out, ["Gauge", "Gauge"]);
    }

    crate::fixture_tests!("class");
}
