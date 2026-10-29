//! .NET (CLI) metadata, read for `exec.pe` from an assembly's metadata
//! root: the assembly's name, version, culture and public-key token; the
//! module name and MVID; referenced assemblies, native modules and the
//! functions imported through P/Invoke; counts of types, methods, fields,
//! properties, events and manifest resources; the namespaces and types
//! defined; the entry point; and the assembly-level attributes (target
//! framework, title, company, product, copyright, informational and file
//! versions, `InternalsVisibleTo`). Attributes or types a known obfuscator
//! leaves name it.
//!
//! Specification: ECMA-335, 6th edition, partition II §22 (metadata
//! tables), §23.2 (blobs and signatures), §23.3 (custom attributes) and
//! §24 (physical layout).

use serde_json::{Map, Value};

use super::{hex, names};
use crate::plugin::{der, guid};

/// Table numbers.
const MODULE: usize = 0x00;
const TYPE_REF: usize = 0x01;
const TYPE_DEF: usize = 0x02;
const FIELD: usize = 0x04;
const METHOD_DEF: usize = 0x06;
const MEMBER_REF: usize = 0x0a;
const CUSTOM_ATTRIBUTE: usize = 0x0c;
const EVENT: usize = 0x14;
const PROPERTY: usize = 0x17;
const MODULE_REF: usize = 0x1a;
const IMPL_MAP: usize = 0x1c;
const ASSEMBLY: usize = 0x20;
const ASSEMBLY_REF: usize = 0x23;
const MANIFEST_RESOURCE: usize = 0x28;
const TABLES: usize = 0x2d;

/// Rows walked per table for names and attributes.
const MAX_ROWS: u32 = 1 << 20;

/// Coded indexes (§24.2.6): tag bits and the tables a tag selects.
#[derive(Clone, Copy)]
enum Coded {
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef,
}

/// No table (unused tags).
const NONE: usize = usize::MAX;

impl Coded {
    fn tables(self) -> (u32, &'static [usize]) {
        match self {
            Coded::TypeDefOrRef => (2, &[TYPE_DEF, TYPE_REF, 0x1b]),
            Coded::HasConstant => (2, &[FIELD, 0x08, PROPERTY]),
            Coded::HasCustomAttribute => (
                5,
                &[
                    METHOD_DEF,
                    FIELD,
                    TYPE_REF,
                    TYPE_DEF,
                    0x08,
                    0x09,
                    MEMBER_REF,
                    MODULE,
                    0x0e,
                    PROPERTY,
                    EVENT,
                    0x11,
                    MODULE_REF,
                    0x1b,
                    ASSEMBLY,
                    ASSEMBLY_REF,
                    0x26,
                    0x27,
                    MANIFEST_RESOURCE,
                    0x2a,
                    0x2c,
                    0x2b,
                ],
            ),
            Coded::HasFieldMarshal => (1, &[FIELD, 0x08]),
            Coded::HasDeclSecurity => (2, &[TYPE_DEF, METHOD_DEF, ASSEMBLY]),
            Coded::MemberRefParent => (3, &[TYPE_DEF, TYPE_REF, MODULE_REF, METHOD_DEF, 0x1b]),
            Coded::HasSemantics => (1, &[EVENT, PROPERTY]),
            Coded::MethodDefOrRef => (1, &[METHOD_DEF, MEMBER_REF]),
            Coded::MemberForwarded => (1, &[FIELD, METHOD_DEF]),
            Coded::Implementation => (2, &[0x26, ASSEMBLY_REF, 0x27]),
            Coded::CustomAttributeType => (3, &[NONE, NONE, METHOD_DEF, MEMBER_REF, NONE]),
            Coded::ResolutionScope => (2, &[MODULE, MODULE_REF, ASSEMBLY_REF, TYPE_REF]),
            Coded::TypeOrMethodDef => (1, &[TYPE_DEF, METHOD_DEF]),
        }
    }
}

/// A column of a metadata table.
#[derive(Clone, Copy)]
enum Col {
    U16,
    U32,
    Str,
    Guid,
    Blob,
    Idx(usize),
    Code(Coded),
}

use Coded as C;
use Col::{Blob, Code, Guid, Idx, Str, U16, U32};

/// The tables' columns (§22), 0x00 to 0x2C.
const SCHEMA: [&[Col]; TABLES] = [
    &[U16, Str, Guid, Guid, Guid],                                        // Module
    &[Code(C::ResolutionScope), Str, Str],                                // TypeRef
    &[U32, Str, Str, Code(C::TypeDefOrRef), Idx(FIELD), Idx(METHOD_DEF)], // TypeDef
    &[Idx(FIELD)],                                                        // FieldPtr
    &[U16, Str, Blob],                                                    // Field
    &[Idx(METHOD_DEF)],                                                   // MethodPtr
    &[U32, U16, U16, Str, Blob, Idx(0x08)],                               // MethodDef
    &[Idx(0x08)],                                                         // ParamPtr
    &[U16, U16, Str],                                                     // Param
    &[Idx(TYPE_DEF), Code(C::TypeDefOrRef)],                              // InterfaceImpl
    &[Code(C::MemberRefParent), Str, Blob],                               // MemberRef
    &[U16, Code(C::HasConstant), Blob],                                   // Constant
    &[Code(C::HasCustomAttribute), Code(C::CustomAttributeType), Blob],   // CustomAttribute
    &[Code(C::HasFieldMarshal), Blob],                                    // FieldMarshal
    &[U16, Code(C::HasDeclSecurity), Blob],                               // DeclSecurity
    &[U16, U32, Idx(TYPE_DEF)],                                           // ClassLayout
    &[U32, Idx(FIELD)],                                                   // FieldLayout
    &[Blob],                                                              // StandAloneSig
    &[Idx(TYPE_DEF), Idx(EVENT)],                                         // EventMap
    &[Idx(EVENT)],                                                        // EventPtr
    &[U16, Str, Code(C::TypeDefOrRef)],                                   // Event
    &[Idx(TYPE_DEF), Idx(PROPERTY)],                                      // PropertyMap
    &[Idx(PROPERTY)],                                                     // PropertyPtr
    &[U16, Str, Blob],                                                    // Property
    &[U16, Idx(METHOD_DEF), Code(C::HasSemantics)],                       // MethodSemantics
    &[Idx(TYPE_DEF), Code(C::MethodDefOrRef), Code(C::MethodDefOrRef)],   // MethodImpl
    &[Str],                                                               // ModuleRef
    &[Blob],                                                              // TypeSpec
    &[U16, Code(C::MemberForwarded), Str, Idx(MODULE_REF)],               // ImplMap
    &[U32, Idx(FIELD)],                                                   // FieldRVA
    &[U32, U32],                                                          // EncLog
    &[U32],                                                               // EncMap
    &[U32, U16, U16, U16, U16, U32, Blob, Str, Str],                      // Assembly
    &[U32],                                                               // AssemblyProcessor
    &[U32, U32, U32],                                                     // AssemblyOS
    &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob],                     // AssemblyRef
    &[U32, Idx(ASSEMBLY_REF)],                                            // AssemblyRefProcessor
    &[U32, U32, U32, Idx(ASSEMBLY_REF)],                                  // AssemblyRefOS
    &[U32, Str, Blob],                                                    // File
    &[U32, U32, Str, Str, Code(C::Implementation)],                       // ExportedType
    &[U32, U32, Str, Code(C::Implementation)],                            // ManifestResource
    &[Idx(TYPE_DEF), Idx(TYPE_DEF)],                                      // NestedClass
    &[U16, U16, Code(C::TypeOrMethodDef), Str],                           // GenericParam
    &[Code(C::MethodDefOrRef), Blob],                                     // MethodSpec
    &[Idx(0x2a), Code(C::TypeDefOrRef)],                                  // GenericParamConstraint
];

/// Attributes or types an obfuscator leaves behind, and its name.
const OBFUSCATORS: &[(&str, &str)] = &[
    ("ConfusedByAttribute", "ConfuserEx"),
    ("DotfuscatorAttribute", "Dotfuscator"),
    ("PoweredByAttribute", "SmartAssembly"),
    ("ObfuscatedByGoliath", "Goliath .NET"),
    ("BabelObfuscatorAttribute", "Babel"),
    ("BabelAttribute", "Babel"),
    ("YanoAttribute", "Yano"),
    ("CryptoObfuscator.ProtectedWithCryptoObfuscatorAttribute", "Crypto Obfuscator"),
    ("ProcessedByXenocode", "Xenocode"),
    ("ObfuscatedByAgileDotNetAttribute", "Agile.NET"),
    ("DotNetPatcherObfuscatorAttribute", "DotNetPatcher"),
    ("NETGuard.Attribute", "NETGuard"),
    ("ZYXDNGuarder", "DNGuard"),
    ("__.NET Reactor", ".NET Reactor"),
];

/// The metadata root and its heaps.
pub(crate) struct Metadata<'a> {
    tables: &'a [u8],
    strings: &'a [u8],
    blob: &'a [u8],
    guid: &'a [u8],
    /// Heap index widths: bit 0 strings, 1 GUIDs, 2 blobs (4 bytes when set).
    heaps: u8,
    rows: [u32; TABLES],
    /// Every table lies within what was read.
    complete: bool,
    offsets: [usize; TABLES],
    widths: [Vec<usize>; TABLES],
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at + 2).map(|v| u16::from_le_bytes([v[0], v[1]]))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

/// A compressed unsigned integer (§23.2) and its length.
fn compressed(b: &[u8]) -> Option<(u32, usize)> {
    let x = *b.first()?;
    if x & 0x80 == 0 {
        Some((u32::from(x), 1))
    } else if x & 0xc0 == 0x80 {
        Some(((u32::from(x & 0x3f) << 8) | u32::from(*b.get(1)?), 2))
    } else if x & 0xe0 == 0xc0 {
        let v = b.get(1..4)?;
        Some(((u32::from(x & 0x1f) << 24) | (u32::from(v[0]) << 16) | (u32::from(v[1]) << 8) | u32::from(v[2]), 4))
    } else {
        None
    }
}

impl<'a> Metadata<'a> {
    /// Parse the metadata root (`BSJB`) and the `#~` / `#-` table stream.
    pub(crate) fn parse(md: &'a [u8]) -> Option<Self> {
        if le32(md, 0)? != 0x424a_5342 {
            return None;
        }
        let vlen = le32(md, 12)? as usize;
        let mut at = 16usize.checked_add(vlen)?;
        let streams = le16(md, at + 2)?;
        at += 4;
        let (mut tables, mut strings, mut blob, mut guid_heap) = (None, &[][..], &[][..], &[][..]);
        for _ in 0..streams.min(16) {
            let (off, size) = (le32(md, at)? as usize, le32(md, at + 4)? as usize);
            let name_at = at + 8;
            let end = md.get(name_at..)?.iter().take(32).position(|&c| c == 0)?;
            let name = &md[name_at..name_at + end];
            at = name_at + (end + 4) / 4 * 4;
            // Streams past what was read (the parse limit) come back short or empty.
            let end = off.saturating_add(size).min(md.len());
            let data = md.get(off.min(end)..end).unwrap_or_default();
            match name {
                b"#~" | b"#-" => tables = Some(data),
                b"#Strings" => strings = data,
                b"#Blob" => blob = data,
                b"#GUID" => guid_heap = data,
                _ => {}
            }
        }
        let t = tables?;
        let heaps = *t.get(6)?;
        let valid = u64::from_le_bytes(t.get(8..16)?.try_into().ok()?);
        let mut rows = [0u32; TABLES];
        let mut at = 24;
        for (i, r) in rows.iter_mut().enumerate() {
            if valid >> i & 1 != 0 {
                *r = le32(t, at)?;
                at += 4;
            }
        }
        // Tables past 0x2C (portable PDB) cannot be sized here.
        if valid >> TABLES != 0 {
            return None;
        }
        if heaps & 0x40 != 0 {
            at += 4;
        }
        let mut m = Metadata {
            tables: t,
            strings,
            blob,
            guid: guid_heap,
            heaps,
            rows,
            complete: false,
            offsets: [0; TABLES],
            widths: std::array::from_fn(|_| Vec::new()),
        };
        for i in 0..TABLES {
            m.widths[i] = SCHEMA[i].iter().map(|c| m.width(*c)).collect();
            m.offsets[i] = at;
            let row: usize = m.widths[i].iter().sum();
            at = at.checked_add(row.checked_mul(rows[i] as usize)?)?;
        }
        m.complete = at <= t.len();
        Some(m)
    }

    fn width(&self, c: Col) -> usize {
        let small = |n: u32, bits: u32| n < (1 << (16 - bits));
        match c {
            U16 => 2,
            U32 => 4,
            Str => 2 + 2 * usize::from(self.heaps & 1 != 0),
            Guid => 2 + 2 * usize::from(self.heaps & 2 != 0),
            Blob => 2 + 2 * usize::from(self.heaps & 4 != 0),
            Idx(t) => {
                if small(self.rows[t], 0) {
                    2
                } else {
                    4
                }
            }
            Code(k) => {
                let (bits, tables) = k.tables();
                let max = tables.iter().filter(|&&t| t != NONE).map(|&t| self.rows[t]).max().unwrap_or(0);
                if small(max, bits) { 2 } else { 4 }
            }
        }
    }

    fn rows(&self, t: usize) -> u32 {
        self.rows[t]
    }

    /// Column `col` of row `row` (1-based) of table `t`.
    fn get(&self, t: usize, row: u32, col: usize) -> Option<u32> {
        if row == 0 || row > self.rows[t] {
            return None;
        }
        let w = &self.widths[t];
        let size: usize = w.iter().sum();
        let at = self.offsets[t] + (row as usize - 1) * size + w[..col].iter().sum::<usize>();
        match w[col] {
            2 => le16(self.tables, at).map(u32::from),
            _ => le32(self.tables, at),
        }
    }

    fn string(&self, i: u32) -> Option<String> {
        let b = self.strings.get(i as usize..)?;
        let end = b.iter().take(4096).position(|&c| c == 0)?;
        Some(String::from_utf8_lossy(&b[..end]).into_owned())
    }

    fn str_col(&self, t: usize, row: u32, col: usize) -> String {
        self.get(t, row, col).and_then(|i| self.string(i)).unwrap_or_default()
    }

    fn blob(&self, i: u32) -> Option<&'a [u8]> {
        let b = self.blob.get(i as usize..)?;
        let (len, n) = compressed(b)?;
        b.get(n..n + len as usize)
    }

    fn guid(&self, i: u32) -> Option<String> {
        let at = (i as usize).checked_sub(1)? * 16;
        guid(self.guid.get(at..at + 16)?.try_into().ok()?)
    }

    /// Decode a coded index into (table, row).
    fn coded(k: Coded, v: u32) -> Option<(usize, u32)> {
        let (bits, tables) = k.tables();
        let t = *tables.get((v & ((1 << bits) - 1)) as usize)?;
        (t != NONE).then_some((t, v >> bits))
    }

    /// `Namespace.Name` of a `TypeDef` or `TypeRef` row.
    fn type_name(&self, t: usize, row: u32) -> Option<String> {
        if t != TYPE_DEF && t != TYPE_REF {
            return None;
        }
        let n = self.str_col(t, row, 1);
        let ns = self.str_col(t, row, 2);
        Some(if ns.is_empty() { n } else { format!("{ns}.{n}") })
    }

    fn version(&self, t: usize, row: u32, first: usize) -> String {
        let p: Vec<String> = (0..4).map(|i| self.get(t, row, first + i).unwrap_or(0).to_string()).collect();
        p.join(".")
    }
}

/// A custom attribute's first fixed argument, when it is a string or a
/// Boolean (§23.3).
fn first_argument(sig: &[u8], value: &[u8]) -> Option<Value> {
    if value.get(..2)? != [1, 0] {
        return None;
    }
    let (count, n) = compressed(sig.get(1..)?)?;
    let params = sig.get(1 + n..)?;
    if count == 0 || params.first() != Some(&1) {
        return None;
    }
    match params.get(1)? {
        0x0e => {
            let v = value.get(2..)?;
            if v.first() == Some(&0xff) {
                return None;
            }
            let (len, n) = compressed(v)?;
            Some(String::from_utf8_lossy(v.get(n..n + len as usize)?).into_owned().into())
        }
        0x02 => Some((*value.get(2)? != 0).into()),
        _ => None,
    }
}

fn token(key: &[u8]) -> String {
    let mut t = der::sha1(key)[12..].to_vec();
    t.reverse();
    hex(&t)
}

/// What the metadata adds to the report's `dotnet` object; also the
/// obfuscator, if one is named.
#[allow(clippy::too_many_lines)] // one table after another
pub(crate) fn report(m: &Metadata<'_>, entry_token: u32, d: &mut Map<String, Value>) -> Option<&'static str> {
    let mut counts = Map::new();
    for (key, t) in [
        ("types", TYPE_DEF),
        ("methods", METHOD_DEF),
        ("fields", FIELD),
        ("properties", PROPERTY),
        ("events", EVENT),
        ("type_references", TYPE_REF),
        ("member_references", MEMBER_REF),
        ("resources", MANIFEST_RESOURCE),
    ] {
        // The first TypeDef row is the `<Module>` pseudo-type.
        let n = if t == TYPE_DEF { m.rows(t).saturating_sub(1) } else { m.rows(t) };
        counts.insert(key.into(), n.into());
    }
    d.insert("counts".into(), Value::Object(counts));
    // Tables cut off by the parse limit give their row counts only.
    if !m.complete {
        return None;
    }
    if m.rows(MODULE) > 0 {
        d.insert("module".into(), m.str_col(MODULE, 1, 1).into());
        if let Some(g) = m.get(MODULE, 1, 2).and_then(|i| m.guid(i)) {
            d.insert("mvid".into(), g.into());
        }
    }
    if m.rows(ASSEMBLY) > 0 {
        let mut a = Map::new();
        a.insert("name".into(), m.str_col(ASSEMBLY, 1, 7).into());
        a.insert("version".into(), m.version(ASSEMBLY, 1, 1).into());
        let culture = m.str_col(ASSEMBLY, 1, 8);
        a.insert("culture".into(), (if culture.is_empty() { "neutral".into() } else { culture }).into());
        if let Some(key) = m.get(ASSEMBLY, 1, 6).and_then(|i| m.blob(i)).filter(|k| !k.is_empty()) {
            a.insert("public_key_token".into(), token(key).into());
        }
        let flags = m.get(ASSEMBLY, 1, 5).unwrap_or(0);
        if flags & 0x100 != 0 {
            a.insert("retargetable".into(), true.into());
        }
        if flags & 0x0e00 == 0x0200 {
            a.insert("windows_runtime".into(), true.into());
        }
        d.insert("assembly".into(), Value::Object(a));
    }
    let refs: Vec<String> = (1..=m.rows(ASSEMBLY_REF).min(MAX_ROWS))
        .map(|r| format!("{} {}", m.str_col(ASSEMBLY_REF, r, 6), m.version(ASSEMBLY_REF, r, 0)))
        .collect();
    if !refs.is_empty() {
        d.insert("assembly_reference_count".into(), refs.len().into());
        d.insert("assembly_references".into(), names(&refs));
    }
    let modules: Vec<String> = (1..=m.rows(MODULE_REF).min(MAX_ROWS)).map(|r| m.str_col(MODULE_REF, r, 0)).collect();
    if !modules.is_empty() {
        d.insert("native_modules".into(), names(&modules));
    }
    let pinvoke: Vec<String> = (1..=m.rows(IMPL_MAP).min(MAX_ROWS))
        .map(|r| {
            let module = m.get(IMPL_MAP, r, 3).map(|i| m.str_col(MODULE_REF, i, 0)).unwrap_or_default();
            format!("{module}!{}", m.str_col(IMPL_MAP, r, 2))
        })
        .collect();
    if !pinvoke.is_empty() {
        d.insert("pinvoke_imports".into(), names(&pinvoke));
    }

    // Types and namespaces defined; obfuscator marks among all type names.
    let mut namespaces: Vec<String> = Vec::new();
    let mut types = Vec::new();
    let mut obfuscator = None;
    let check = |name: &str, found: &mut Option<&'static str>| {
        if found.is_none() {
            *found = OBFUSCATORS.iter().find(|(mark, _)| name.ends_with(mark)).map(|(_, o)| *o);
        }
    };
    for r in 2..=m.rows(TYPE_DEF).min(MAX_ROWS) {
        let ns = m.str_col(TYPE_DEF, r, 2);
        let name = m.str_col(TYPE_DEF, r, 1);
        check(&name, &mut obfuscator);
        // Visibility 2 to 7 marks a nested type.
        let visibility = m.get(TYPE_DEF, r, 0).unwrap_or(0) & 0x7;
        if name.starts_with('<') || visibility >= 2 {
            continue;
        }
        if !ns.is_empty() && !namespaces.contains(&ns) {
            namespaces.push(ns.clone());
        }
        if visibility == 1 {
            types.push(if ns.is_empty() { name } else { format!("{ns}.{name}") });
        }
    }
    for r in 1..=m.rows(TYPE_REF).min(MAX_ROWS) {
        check(&m.type_name(TYPE_REF, r).unwrap_or_default(), &mut obfuscator);
    }
    if !namespaces.is_empty() {
        namespaces.sort();
        d.insert("namespaces".into(), names(&namespaces));
    }
    if !types.is_empty() {
        d.insert("public_types".into(), names(&types));
    }

    // The entry point: a MethodDef token (0x06…), named with its type.
    if usize::try_from(entry_token >> 24) == Ok(METHOD_DEF) {
        let row = entry_token & 0x00ff_ffff;
        let method = m.str_col(METHOD_DEF, row, 3);
        let owner = (1..=m.rows(TYPE_DEF).min(MAX_ROWS))
            .rev()
            .find(|&t| m.get(TYPE_DEF, t, 5).is_some_and(|first| first <= row))
            .and_then(|t| m.type_name(TYPE_DEF, t));
        if !method.is_empty() {
            d.insert("entry_point".into(), owner.map_or(method.clone(), |o| format!("{o}.{method}")).into());
        }
    }

    // Assembly-level attributes.
    let mut attrs = Map::new();
    let mut other = Vec::new();
    let mut friends = Vec::new();
    for r in 1..=m.rows(CUSTOM_ATTRIBUTE).min(MAX_ROWS) {
        let parent = m.get(CUSTOM_ATTRIBUTE, r, 0).and_then(|v| Metadata::coded(Coded::HasCustomAttribute, v));
        let Some((ctor_t, ctor_r)) =
            m.get(CUSTOM_ATTRIBUTE, r, 1).and_then(|v| Metadata::coded(Coded::CustomAttributeType, v))
        else {
            continue;
        };
        let (ty, sig) = match ctor_t {
            MEMBER_REF => {
                let class = m.get(MEMBER_REF, ctor_r, 0).and_then(|v| Metadata::coded(Coded::MemberRefParent, v));
                let ty = class.and_then(|(t, row)| m.type_name(t, row));
                (ty, m.get(MEMBER_REF, ctor_r, 2).and_then(|i| m.blob(i)))
            }
            _ => (None, m.get(METHOD_DEF, ctor_r, 4).and_then(|i| m.blob(i))),
        };
        let Some(ty) = ty else { continue };
        check(&ty, &mut obfuscator);
        if parent != Some((ASSEMBLY, 1)) {
            continue;
        }
        let short = ty.rsplit('.').next().unwrap_or(&ty).trim_end_matches("Attribute");
        let key = match short {
            "TargetFramework" => "target_framework",
            "AssemblyTitle" => "title",
            "AssemblyDescription" => "description",
            "AssemblyCompany" => "company",
            "AssemblyProduct" => "product",
            "AssemblyCopyright" => "copyright",
            "AssemblyTrademark" => "trademark",
            "AssemblyInformationalVersion" => "informational_version",
            "AssemblyFileVersion" => "file_version",
            "AssemblyConfiguration" => "configuration",
            "Guid" => "com_guid",
            "InternalsVisibleTo" => "internals_visible_to",
            _ => {
                if other.len() < 64 && !other.contains(&ty) {
                    other.push(ty.clone());
                }
                continue;
            }
        };
        let value = m.get(CUSTOM_ATTRIBUTE, r, 2).and_then(|i| m.blob(i));
        let Some(v) = sig.zip(value).and_then(|(s, v)| first_argument(s, v)) else { continue };
        if key == "internals_visible_to" {
            friends.push(v.as_str().unwrap_or("").split(',').next().unwrap_or("").to_string());
        } else if v.as_str().is_none_or(|s| !s.is_empty()) {
            attrs.insert(key.into(), v);
        }
    }
    if !friends.is_empty() {
        attrs.insert("internals_visible_to".into(), names(&friends));
    }
    if let Some(tf) = attrs.remove("target_framework") {
        d.insert("target_framework".into(), tf);
    }
    if !attrs.is_empty() {
        d.insert("attributes".into(), Value::Object(attrs));
    }
    if !other.is_empty() {
        d.insert("other_attributes".into(), names(&other));
    }
    if let Some(o) = obfuscator {
        d.insert("obfuscator".into(), o.into());
    }
    obfuscator
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_integers() {
        assert_eq!(compressed(&[0x03]), Some((3, 1)));
        assert_eq!(compressed(&[0x80, 0x80]), Some((0x80, 2)));
        assert_eq!(compressed(&[0xc0, 0x00, 0x40, 0x00]), Some((0x4000, 4)));
        assert_eq!(compressed(&[0xff]), None);
    }

    #[test]
    fn sha1_matches_the_reference() {
        assert_eq!(hex(&der::sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        // The ECMA standard public key (16 bytes) has the well-known token.
        let ecma = [0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(token(&ecma), "b77a5c561934e089");
    }

    #[test]
    fn attribute_string_argument() {
        // .ctor(string): HASTHIS, 1 param, void, string.
        let sig = [0x20, 1, 1, 0x0e];
        let value = [1, 0, 5, b'T', b'i', b'd', b'e', b's', 0, 0];
        assert_eq!(first_argument(&sig, &value), Some(Value::from("Tides")));
        assert_eq!(first_argument(&sig, &[1, 0, 0xff, 0, 0]), None);
    }

    #[test]
    fn tables_past_the_read_give_counts_only() {
        // A metadata root whose `#~` stream announces one Module row and two
        // AssemblyRef rows, cut off before the rows themselves.
        let mut tables = vec![0, 0, 0, 0, 2, 0, 0, 1];
        tables.extend_from_slice(&(1u64 | 1 << ASSEMBLY_REF).to_le_bytes());
        tables.extend_from_slice(&0u64.to_le_bytes());
        tables.extend_from_slice(&1u32.to_le_bytes());
        tables.extend_from_slice(&2u32.to_le_bytes());
        let mut md = b"BSJB".to_vec();
        md.extend_from_slice(&[1, 0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 0]);
        md.extend_from_slice(b"v4\0\0");
        md.extend_from_slice(&[0, 0, 1, 0]);
        md.extend_from_slice(&36u32.to_le_bytes());
        md.extend_from_slice(&u32::try_from(tables.len()).unwrap().to_le_bytes());
        md.extend_from_slice(b"#~\0\0");
        md.extend(tables);
        let m = Metadata::parse(&md).unwrap();
        assert!(!m.complete);
        let mut d = Map::new();
        assert_eq!(report(&m, 0, &mut d), None);
        assert_eq!(d["counts"]["types"], 0);
        assert!(!d.contains_key("assembly_references") && !d.contains_key("module"));
    }

    #[test]
    fn coded_indexes_decode() {
        // HasCustomAttribute: tag 14 = Assembly, row 1.
        assert_eq!(Metadata::coded(Coded::HasCustomAttribute, (1 << 5) | 0x0e), Some((ASSEMBLY, 1)));
        assert_eq!(Metadata::coded(Coded::CustomAttributeType, (7 << 3) | 0x3), Some((MEMBER_REF, 7)));
        assert_eq!(Metadata::coded(Coded::CustomAttributeType, 1), None);
    }
}
