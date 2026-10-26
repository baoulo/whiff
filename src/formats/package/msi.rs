//! Windows Installer databases: packages (`.msi`), merge modules (`.msm`)
//! and patches (`.msp`). The summary information gives the title,
//! manufacturer, platform and languages, package code, minimum installer
//! version, the creating tool and save times; the database tables (read
//! through `_Columns` and the string pool) give the `Property` table
//! (product name, version, manufacturer, product and upgrade codes,
//! support links), file, component, feature and directory counts with the
//! installed size, the custom actions that run code (DLLs, programs,
//! JScript, VBScript — install-time scripts), the merge module's
//! signature and the media table's cabinets. `\x05DigitalSignature` is the
//! Authenticode signature. Embedded cabinets are handed on (and listed by
//! the cabinet extractor).
//!
//! Specifications: Windows Installer SDK ("Database tables", "Custom
//! action types", "Summary Information Stream"); MS-CFB; the stream-name
//! and string-pool encoding as documented by Wine's `msi` and msitools.

use std::collections::HashMap;

use super::Package;
use crate::plugin::{
    Cfb, CfbEntry, CfbKind, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff,
    Source, oleps,
};

/// Extractor for Windows Installer files.
pub struct Msi;

macro_rules! spec {
    ($id:literal, $name:literal, $mime:literal, $ext:literal) => {
        FormatSpec {
            id: $id,
            name: $name,
            family: "package",
            mimes: &[$mime],
            extensions: &[$ext],
            magic: &[],
            parent: Some("cfb"),
        }
    };
}

static META: ExtractorMeta = ExtractorMeta {
    id: "package.msi",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec!("msi", "Windows Installer package", "application/x-msi", "msi"),
        spec!("msm", "Windows Installer merge module", "application/x-msi", "msm"),
        spec!("msp", "Windows Installer patch", "application/x-msi", "msp"),
    ],
};

/// Class ids of the root storage.
const CLSID_MSI: &str = "000C1084-0000-0000-C000-000000000046";
const CLSID_MSP: &str = "000C1086-0000-0000-C000-000000000046";
/// Largest table or string pool stream read.
const MAX_STREAM: usize = 64 << 20;
/// Rows read per table at most.
const MAX_ROWS: usize = 1 << 18;

/// The character an MSI stream-name code stands for (0–63).
fn mime(x: u32) -> char {
    match x {
        0..=9 => char::from_u32(u32::from(b'0') + x).unwrap_or('_'),
        10..=35 => char::from_u32(u32::from(b'A') + x - 10).unwrap_or('_'),
        36..=61 => char::from_u32(u32::from(b'a') + x - 36).unwrap_or('_'),
        62 => '.',
        _ => '_',
    }
}

/// A stream name as Windows Installer encodes it, decoded: two characters
/// per code in U+3800–U+47FF, one in U+4800–U+483F; U+4840 marks a table
/// (written `!`).
fn decode_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        let u = c as u32;
        match u {
            0x3800..0x4800 => {
                out.push(mime((u - 0x3800) & 0x3f));
                out.push(mime((u - 0x3800) >> 6));
            }
            0x4800..0x4840 => out.push(mime(u - 0x4800)),
            0x4840 => out.push('!'),
            _ => out.push(c),
        }
    }
    out
}

/// A column value.
#[derive(Debug, Clone, PartialEq)]
enum Cell {
    Null,
    Int(i64),
    Str(String),
}

impl Cell {
    fn str(&self) -> Option<&str> {
        match self {
            Self::Str(s) if !s.is_empty() => Some(s),
            _ => None,
        }
    }

    fn int(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            _ => None,
        }
    }
}

/// The database: decoded stream names, the string pool, column types.
struct Database {
    streams: HashMap<String, CfbEntry>,
    strings: Vec<String>,
    /// Bytes per string reference (2, or 3 for large pools).
    sref: usize,
    /// Column types per table, in column order.
    columns: HashMap<String, Vec<u16>>,
}

impl Database {
    fn open(cfb: &Cfb, src: &mut dyn Source) -> Result<Self, ExtractError> {
        let streams: HashMap<String, CfbEntry> = cfb
            .entries
            .iter()
            .filter(|e| e.kind == CfbKind::Stream && e.parent == Some(0))
            .map(|e| (decode_name(&e.name), e.clone()))
            .collect();
        let mut db = Self { streams, strings: vec![String::new()], sref: 2, columns: HashMap::new() };
        let pool = db.stream(cfb, src, "!_StringPool")?.unwrap_or_default();
        let data = db.stream(cfb, src, "!_StringData")?.unwrap_or_default();
        let words: Vec<u32> = pool.as_chunks::<2>().0.iter().map(|w| u32::from(u16::from_le_bytes(*w))).collect();
        let codepage = words.first().copied().unwrap_or(0) | (words.get(1).copied().unwrap_or(0) & 0x7fff) << 16;
        if words.get(1).is_some_and(|w| w & 0x8000 != 0) {
            db.sref = 3;
        }
        let decode = |b: &[u8]| -> String {
            if codepage == 65001 || codepage == 0 {
                String::from_utf8_lossy(b).into_owned()
            } else {
                let enc = encoding_rs::Encoding::for_label(format!("windows-{codepage}").as_bytes())
                    .unwrap_or(encoding_rs::WINDOWS_1252);
                enc.decode_without_bom_handling(b).0.into_owned()
            }
        };
        let (mut i, mut offset) = (1usize, 0usize);
        let count = words.len() / 2;
        while i < count && db.strings.len() < 1 << 20 {
            let (len, refs) = (words[i * 2] as usize, words[i * 2 + 1]);
            let len = if len == 0 && refs == 0 {
                i += 1;
                db.strings.push(String::new());
                continue;
            } else if len == 0 {
                // A string over 64 KiB: the length's high word is in this
                // entry's reference count, its low word in the next entry.
                let l = (words.get(i * 2 + 3).copied().unwrap_or(0) as usize) << 16
                    | words.get(i * 2 + 2).copied().unwrap_or(0) as usize;
                i += 2;
                l
            } else {
                i += 1;
                len
            };
            let s = data.get(offset..offset + len).map(decode).unwrap_or_default();
            offset += len;
            db.strings.push(s);
        }
        // `_Columns`: Table (string), Number (i2), Name (string), Type (i2).
        let fixed = [0x0d40u16 | 64, 0x0502, 0x0d40 | 64, 0x0502];
        let rows = db.rows(cfb, src, "_Columns", &fixed)?;
        let mut cols: Vec<(String, i64, u16)> = rows
            .into_iter()
            .filter_map(|r| Some((r[0].str()?.to_string(), r[1].int()?, u16::try_from(r[3].int()?).ok()?)))
            .collect();
        cols.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        for (table, _, ty) in cols {
            db.columns.entry(table).or_default().push(ty);
        }
        Ok(db)
    }

    fn stream(&self, cfb: &Cfb, src: &mut dyn Source, name: &str) -> Result<Option<Vec<u8>>, ExtractError> {
        match self.streams.get(name) {
            Some(e) => Ok(Some(cfb.read(src, e, MAX_STREAM)?)),
            None => Ok(None),
        }
    }

    /// Bytes a column of `ty` takes per row.
    fn width(&self, ty: u16) -> usize {
        // Binary (stream) columns hold a 2-byte reference.
        if ty & !0x1000 == 0x0900 {
            2
        } else if ty & 0x0800 != 0 {
            self.sref
        } else if ty & 0xff <= 2 {
            2
        } else {
            4
        }
    }

    /// The rows of `table`, with `types` (from `_Columns`, or fixed).
    fn rows(
        &self,
        cfb: &Cfb,
        src: &mut dyn Source,
        table: &str,
        types: &[u16],
    ) -> Result<Vec<Vec<Cell>>, ExtractError> {
        let Some(data) = self.stream(cfb, src, &format!("!{table}"))? else { return Ok(Vec::new()) };
        let row: usize = types.iter().map(|&t| self.width(t)).sum();
        if row == 0 {
            return Ok(Vec::new());
        }
        let rows = (data.len() / row).min(MAX_ROWS);
        let mut out = vec![Vec::with_capacity(types.len()); rows];
        // Tables are stored column by column.
        let mut at = 0usize;
        for &ty in types {
            let width = self.width(ty);
            for row in &mut out {
                let Some(bytes) = data.get(at..at + width) else { break };
                let value = bytes.iter().rev().fold(0u64, |acc, &x| acc << 8 | u64::from(x));
                let cell = if ty & 0x0800 != 0 && ty & !0x1000 != 0x0900 {
                    match self.strings.get(usize::try_from(value).unwrap_or(usize::MAX)) {
                        Some(s) if value != 0 => Cell::Str(s.clone()),
                        _ => Cell::Null,
                    }
                } else if ty & 0x0800 != 0 || value == 0 {
                    Cell::Null
                } else if width == 2 {
                    // Integers are stored with the sign bit flipped.
                    Cell::Int(i64::from((u16::try_from(value).unwrap_or(0) ^ 0x8000).cast_signed()))
                } else {
                    Cell::Int(i64::from((u32::try_from(value).unwrap_or(0) ^ 0x8000_0000).cast_signed()))
                };
                row.push(cell);
                at += width;
            }
        }
        Ok(out)
    }

    fn table(&self, cfb: &Cfb, src: &mut dyn Source, table: &str) -> Result<Vec<Vec<Cell>>, ExtractError> {
        match self.columns.get(table) {
            Some(types) => self.rows(cfb, src, table, &types.clone()),
            None => Ok(Vec::new()),
        }
    }
}

/// What a custom action of `ty` runs, if it runs code.
fn action_kind(ty: i64) -> Option<&'static str> {
    Some(match ty & 0x3f {
        1 | 17 => "dll",
        2 | 18 | 34 | 50 => "exe",
        5 | 21 | 37 | 53 => "jscript",
        6 | 22 | 38 | 54 => "vbscript",
        _ => return None,
    })
}

/// The root storage's class id, read from the head (for the sniffer).
fn head_clsid(head: &[u8]) -> Option<String> {
    if !Cfb::is_cfb(head) {
        return None;
    }
    let shift = u16::from_le_bytes([*head.get(30)?, *head.get(31)?]);
    if !(9..=12).contains(&shift) {
        return None;
    }
    let size = 1usize << shift;
    let first = u32::from_le_bytes(head.get(48..52)?.try_into().ok()?) as usize;
    let root = (first + 1).checked_mul(size)?;
    let id: [u8; 16] = head.get(root + 0x50..root + 0x60)?.try_into().ok()?;
    crate::plugin::guid(&id)
}

impl Extractor for Msi {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let id = head_clsid(probe.head)?;
        let format = match id.as_str() {
            CLSID_MSP => "msp",
            CLSID_MSI if probe.extension == Some("msm") => "msm",
            CLSID_MSI => "msi",
            _ => return None,
        };
        Some(Sniff { format, confidence: 0.97 })
    }

    #[allow(clippy::too_many_lines)] // summary, properties, tables, media
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let cfb = Cfb::open(src)?;
        let db = Database::open(&cfb, src)?;
        let mut pkg = Package::new("windows_installer");
        // Summary information.
        if let Some(e) = cfb.find("\u{5}SummaryInformation").cloned()
            && let Ok(sections) = oleps::parse(&cfb.read(src, &e, 1 << 20)?)
            && let Some(s) = sections.first()
        {
            let get = |id: u32| s.get(id).and_then(oleps::PropValue::as_str).map(str::to_string);
            // Title is the database kind ("Installation Database"), Subject the product.
            pkg.name = get(3);
            pkg.summary = get(6);
            pkg.authors.extend(get(4));
            if let Some(t) = get(2) {
                pkg.set("database_title", t);
            }
            let patch = cx.format_id() == "msp";
            if let Some(t) = get(7).filter(|_| patch) {
                // A patch's `Template` lists the product codes it applies to.
                pkg.set("target_products", t.split(';').filter(|c| !c.is_empty()).collect::<Vec<_>>());
            } else if let Some(t) = get(7) {
                // `Template`: "platform;languages".
                let (platform, langs) = t.split_once(';').unwrap_or((&t, ""));
                if !platform.is_empty() {
                    pkg.architecture = Some(platform.to_string());
                }
                if !langs.is_empty() {
                    pkg.set("languages", langs.split(',').collect::<Vec<_>>());
                }
            }
            if let Some(code) = get(9) {
                pkg.set("package_code", code);
            }
            if let Some(v) = s.get(14).and_then(oleps::PropValue::as_int) {
                pkg.set("minimum_installer_version", format!("{}.{}", v / 100, v % 100));
            }
            if let Some(w) = s.get(15).and_then(oleps::PropValue::as_int).filter(|_| !patch) {
                pkg.set("compressed", w & 2 != 0);
                if w & 4 != 0 {
                    pkg.set("administrative_image", true);
                }
            }
            if let Some(a) = get(18) {
                pkg.set("creating_application", a);
            }
            for (id, field, key) in [(12, DateField::Created, "created"), (13, DateField::Modified, "saved")] {
                if let Some(t) = s.get(id).map(oleps::PropValue::to_json).and_then(|v| v.as_str().map(str::to_string)) {
                    pkg.set(key, t.clone());
                    cx.temporal().content_date(field, t, true);
                }
            }
            if let Some(k) = get(5) {
                pkg.set("keywords", k);
            }
        }
        // The Property table.
        let props: HashMap<String, String> = db
            .table(&cfb, src, "Property")?
            .into_iter()
            .filter_map(|r| Some((r.first()?.str()?.to_string(), r.get(1)?.str()?.to_string())))
            .collect();
        let prop = |k: &str| props.get(k).cloned();
        pkg.name = prop("ProductName").or(pkg.name.take());
        pkg.version = prop("ProductVersion");
        if let Some(m) = prop("Manufacturer") {
            pkg.authors.retain(|a| a != &m);
            pkg.authors.insert(0, m);
        }
        pkg.homepage = prop("ARPURLINFOABOUT").or_else(|| prop("ARPHELPLINK"));
        for (k, out) in [
            ("ProductCode", "product_code"),
            ("UpgradeCode", "upgrade_code"),
            ("ProductLanguage", "product_language"),
            ("ALLUSERS", "all_users"),
            ("ARPCONTACT", "contact"),
            ("ARPHELPLINK", "help_link"),
        ] {
            if let Some(v) = prop(k) {
                pkg.set(out, v);
            }
        }
        // Merge modules name themselves in `ModuleSignature` (ModuleID, Language, Version).
        if let Some(r) = db.table(&cfb, src, "ModuleSignature")?.first() {
            pkg.name = pkg.name.or_else(|| r.first().and_then(Cell::str).map(str::to_string));
            pkg.version = pkg.version.or_else(|| r.get(2).and_then(Cell::str).map(str::to_string));
        }
        // Counts and the installed size.
        let files = db.table(&cfb, src, "File")?;
        if !files.is_empty() {
            pkg.set("files", files.len());
            let size: i64 = files.iter().filter_map(|r| r.get(3).and_then(Cell::int)).filter(|&n| n > 0).sum();
            pkg.set("installed_size_bytes", size);
        }
        for (table, key) in [
            ("Component", "components"),
            ("Feature", "features"),
            ("Directory", "directories"),
            ("Registry", "registry_entries"),
            ("ServiceInstall", "services"),
        ] {
            let n = db.table(&cfb, src, table)?.len();
            if n > 0 {
                pkg.set(key, n);
            }
        }
        // Custom actions that run code.
        for r in db.table(&cfb, src, "CustomAction")? {
            if let (Some(name), Some(kind)) =
                (r.first().and_then(Cell::str), r.get(1).and_then(Cell::int).and_then(action_kind))
                && pkg.scripts.len() < 100
            {
                pkg.scripts.push(format!("{name} ({kind})"));
            }
        }
        let tables = db.columns.len();
        pkg.set("tables", tables);
        // Signature and cabinets.
        let signed = cfb.find("\u{5}DigitalSignature").is_some();
        pkg.signed = Some(signed);
        if signed {
            pkg.signatures.push("authenticode".into());
        }
        let cabinets: Vec<String> = db
            .table(&cfb, src, "Media")?
            .iter()
            .filter_map(|r| r.get(3).and_then(Cell::str).map(str::to_string))
            .collect();
        if !cabinets.is_empty() {
            pkg.set("cabinets", cabinets.clone());
        }
        pkg.write(cx);
        for cab in cabinets.iter().filter_map(|c| c.strip_prefix('#')) {
            if cx.child_room() == 0 {
                break;
            }
            if let Some(e) = db.streams.get(cab) {
                let data = cfb.read(src, e, cx.parse_limit())?;
                cx.emit_child(cab, data)?;
            }
        }
        Ok(())
    }
}

crate::register_extractor!(Msi);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_names() {
        // "_StringPool" as a table: U+4840, then pairs of codes.
        let encoded: String = std::iter::once('\u{4840}')
            .chain("_StringPool".as_bytes().chunks(2).map(|p| {
                let code = |c: u8| match c {
                    b'0'..=b'9' => u32::from(c - b'0'),
                    b'A'..=b'Z' => u32::from(c - b'A') + 10,
                    b'a'..=b'z' => u32::from(c - b'a') + 36,
                    b'.' => 62,
                    _ => 63,
                };
                match p {
                    [a, b] => char::from_u32(0x3800 + code(*a) + (code(*b) << 6)).unwrap_or('?'),
                    [a] => char::from_u32(0x4800 + code(*a)).unwrap_or('?'),
                    _ => '?',
                }
            }))
            .collect();
        assert_eq!(decode_name(&encoded), "!_StringPool");
        assert_eq!(decode_name("\u{5}SummaryInformation"), "\u{5}SummaryInformation");
    }

    #[test]
    fn custom_actions() {
        assert_eq!(action_kind(1), Some("dll"));
        assert_eq!(action_kind(3074), Some("exe"));
        assert_eq!(action_kind(38), Some("vbscript"));
        assert_eq!(action_kind(51), None);
    }

    crate::fixture_tests!("msi", "msm", "msp");
}
