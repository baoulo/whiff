//! Microsoft Access databases (Jet 3 `.mdb` to ACE 16 `.accdb`): the
//! engine version and the Access release it belongs to, code page,
//! creation date, whether the file is encoded, and from the `MSysObjects`
//! catalog the user tables (with row counts and columns), linked tables,
//! queries, forms, reports, macros and VBA modules. Macros and modules are
//! active content. Rows of user tables are never read.
//!
//! Specifications: the mdbtools "HACKING" notes and Jackcess's `JetFormat`
//! (page, table definition and row layouts).

use serde_json::{Map, Value, json};

use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for Access databases.
pub struct Access;

static META: ExtractorMeta = ExtractorMeta {
    id: "db.access",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "access",
        name: "Microsoft Access database",
        family: "db",
        mimes: &["application/vnd.ms-access", "application/x-msaccess"],
        extensions: &["mdb", "accdb", "mde", "accde", "mda"],
        magic: &[
            Magic::at(0, b"\x00\x01\x00\x00Standard Jet DB\x00"),
            Magic::at(0, b"\x00\x01\x00\x00Standard ACE DB\x00"),
        ],
        parent: None,
    }],
};

/// RC4 key of the header mask (Jackcess `BASE_HEADER_MASK` source).
const HEADER_KEY: [u8; 4] = [0xc7, 0xda, 0x39, 0x6b];
/// The catalog's table definition page.
const CATALOG_TDEF: u32 = 2;
/// User tables described in full.
const MAX_TABLES: usize = 256;
/// Columns listed per table.
const MAX_COLUMNS: usize = 128;

fn rc4(key: &[u8], data: &mut [u8]) {
    let mut s: [u8; 256] = std::array::from_fn(|i| u8::try_from(i).unwrap_or(0));
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, usize::from(j));
    }
    let (mut i, mut j) = (0u8, 0u8);
    for b in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[usize::from(i)]);
        s.swap(usize::from(i), usize::from(j));
        *b ^= s[usize::from(s[usize::from(i)].wrapping_add(s[usize::from(j)]))];
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<usize> {
    b.get(at..at + 2).map(|v| usize::from(u16::from_le_bytes([v[0], v[1]])))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

/// Offsets of one engine generation's structures (Jackcess `JetFormat`).
struct Layout {
    jet3: bool,
    page_size: usize,
    row_count: usize,
    num_cols: usize,
    /// Real indexes; their entries come before the column headers.
    num_indexes: usize,
    tdef_header: usize,
    index_entry: usize,
    col_header: usize,
    col_type: usize,
    col_number: usize,
    col_var_index: usize,
    col_flags: usize,
    col_fixed_offset: usize,
    col_length: usize,
    row_offsets: usize,
}

const JET3: Layout = Layout {
    jet3: true,
    page_size: 2048,
    row_count: 12,
    num_cols: 25,
    num_indexes: 31,
    tdef_header: 43,
    index_entry: 8,
    col_header: 18,
    col_type: 0,
    col_number: 1,
    col_var_index: 3,
    col_flags: 13,
    col_fixed_offset: 14,
    col_length: 16,
    row_offsets: 10,
};

const JET4: Layout = Layout {
    jet3: false,
    page_size: 4096,
    row_count: 16,
    num_cols: 45,
    num_indexes: 51,
    tdef_header: 63,
    index_entry: 12,
    col_header: 25,
    col_type: 0,
    col_number: 5,
    col_var_index: 7,
    col_flags: 15,
    col_fixed_offset: 21,
    col_length: 23,
    row_offsets: 14,
};

/// A column of a table definition.
#[derive(Debug, Clone)]
struct Col {
    name: String,
    kind: u8,
    number: usize,
    var_index: usize,
    fixed: bool,
    fixed_offset: usize,
    length: usize,
}

fn type_name(t: u8) -> &'static str {
    match t {
        1 => "boolean",
        2 => "byte",
        3 => "integer",
        4 => "long",
        5 => "currency",
        6 => "single",
        7 => "double",
        8 => "datetime",
        9 => "binary",
        10 => "text",
        11 => "ole",
        12 => "memo",
        15 => "guid",
        16 => "decimal",
        17 => "unknown_11",
        18 => "complex",
        20 => "big_int",
        _ => "unknown",
    }
}

/// Text in the engine's encoding: Jet 3 a code page (Latin-1 read),
/// Jet 4+ UCS-2, possibly in the `FF FE` compressed form.
fn text(jet3: bool, b: &[u8]) -> String {
    if jet3 {
        return b.iter().map(|&c| char::from(c)).collect();
    }
    let mut units: Vec<u16> = Vec::new();
    if let Some(rest) = b.strip_prefix(&[0xff, 0xfe]) {
        let mut compressed = true;
        for seg in rest.split(|&c| c == 0) {
            if compressed {
                units.extend(seg.iter().map(|&c| u16::from(c)));
            } else {
                units.extend(seg.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)));
            }
            compressed = !compressed;
        }
    } else {
        units.extend(b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)));
    }
    String::from_utf16_lossy(&units)
}

struct File<'s> {
    src: &'s mut dyn Source,
    l: &'static Layout,
    pages: u32,
    reads: usize,
    max_reads: usize,
}

impl File<'_> {
    fn page(&mut self, n: u32) -> Option<Vec<u8>> {
        if n >= self.pages || self.reads >= self.max_reads {
            return None;
        }
        self.reads += 1;
        let mut buf = vec![0; self.l.page_size];
        self.src.read_exact_at(u64::from(n) * self.l.page_size as u64, &mut buf).ok()?;
        Some(buf)
    }

    /// A table definition, its continuation pages joined.
    fn tdef(&mut self, n: u32) -> Option<Vec<u8>> {
        let mut buf = self.page(n)?;
        if buf.first() != Some(&2) {
            return None;
        }
        let mut next = u32_at(&buf, 4)?;
        let mut hops = 0;
        while next != 0 && hops < 64 {
            let p = self.page(next)?;
            next = u32_at(&p, 4)?;
            buf.extend_from_slice(&p[8..]);
            hops += 1;
        }
        Some(buf)
    }

    fn text(&self, b: &[u8]) -> String {
        text(self.l.jet3, b)
    }

    fn columns(&self, t: &[u8]) -> Option<(Vec<Col>, u32)> {
        let l = self.l;
        let rows = u32_at(t, l.row_count)?;
        let ncols = u16_at(t, l.num_cols)?;
        let indexes = usize::try_from(u32_at(t, l.num_indexes)?).ok()?.min(1000);
        let mut at = l.tdef_header + indexes * l.index_entry;
        let headers = at;
        at += ncols * l.col_header;
        let mut cols = Vec::with_capacity(ncols);
        for i in 0..ncols {
            let h = t.get(headers + i * l.col_header..headers + (i + 1) * l.col_header)?;
            let name_len = if l.jet3 { usize::from(*t.get(at)?) } else { u16_at(t, at)? };
            let skip = if l.jet3 { 1 } else { 2 };
            let name = self.text(t.get(at + skip..at + skip + name_len)?);
            at += skip + name_len;
            cols.push(Col {
                name,
                kind: h[l.col_type],
                number: u16_at(h, l.col_number)?,
                var_index: u16_at(h, l.col_var_index)?,
                fixed: h[l.col_flags] & 0x01 != 0,
                fixed_offset: u16_at(h, l.col_fixed_offset)?,
                length: u16_at(h, l.col_length)?,
            });
        }
        Some((cols, rows))
    }

    /// The rows of a data page that belong to table `owner`, as byte
    /// ranges of the page (overflow rows followed one step).
    fn rows(&mut self, page: &[u8], owner: u32) -> Vec<Vec<u8>> {
        let l = self.l;
        if page.first() != Some(&1) || u32_at(page, 4) != Some(owner) {
            return Vec::new();
        }
        let count = u16_at(page, l.row_offsets - 2).unwrap_or(0);
        let mut out = Vec::new();
        for i in 0..count {
            let Some(raw) = u16_at(page, l.row_offsets + 2 * i) else { break };
            let start = raw & 0x1fff;
            let end =
                if i == 0 { l.page_size } else { u16_at(page, l.row_offsets + 2 * (i - 1)).unwrap_or(0) & 0x1fff };
            if raw & 0x8000 != 0 || start >= end || end > page.len() {
                continue; // deleted
            }
            let row = &page[start..end];
            if raw & 0x4000 != 0 {
                // An overflow pointer: row number, then the page (24 bits).
                let Some(ptr) = u32_at(row, 0) else { continue };
                let (pg, n) = (ptr >> 8, usize::try_from(ptr & 0xff).unwrap_or(0));
                if let Some(other) = self.page(pg)
                    && let Some(r) = row_at(l, &other, n)
                {
                    out.push(r);
                }
                continue;
            }
            out.push(row.to_vec());
        }
        out
    }
}

fn row_at(l: &Layout, page: &[u8], i: usize) -> Option<Vec<u8>> {
    let raw = u16_at(page, l.row_offsets + 2 * i)?;
    let start = raw & 0x1fff;
    let end = if i == 0 { l.page_size } else { u16_at(page, l.row_offsets + 2 * (i - 1))? & 0x1fff };
    page.get(start..end).map(<[u8]>::to_vec)
}

/// The variable-column offsets and null mask of a row.
struct Cracked<'a> {
    row: &'a [u8],
    var: Vec<usize>,
    nulls: &'a [u8],
}

fn crack<'a>(l: &Layout, row: &'a [u8]) -> Option<Cracked<'a>> {
    let n = row.len();
    if l.jet3 {
        let cols = usize::from(*row.first()?);
        let mask = cols.div_ceil(8);
        let nulls = row.get(n.checked_sub(mask)?..)?;
        let var_cols = usize::from(*row.get(n.checked_sub(mask + 1)?)?);
        let mut jumps = (n - 1) / 256;
        let col_ptr = n.checked_sub(mask + jumps + 2)?;
        if col_ptr.checked_sub(var_cols)? / 256 < jumps {
            jumps = jumps.saturating_sub(1);
        }
        let mut used = 0;
        let mut var = Vec::with_capacity(var_cols + 1);
        for i in 0..=var_cols {
            while used < jumps && i == usize::from(*row.get(n - mask - used - 2)?) {
                used += 1;
            }
            var.push(usize::from(*row.get(col_ptr.checked_sub(i)?)?) + used * 256);
        }
        Some(Cracked { row, var, nulls })
    } else {
        let cols = u16_at(row, 0)?;
        let mask = cols.div_ceil(8);
        let nulls = row.get(n.checked_sub(mask)?..)?;
        let var_cols = u16_at(row, n.checked_sub(mask + 2)?)?;
        let mut var = Vec::with_capacity(var_cols + 1);
        for i in 0..=var_cols {
            var.push(u16_at(row, n.checked_sub(mask + 4 + 2 * i)?)?);
        }
        Some(Cracked { row, var, nulls })
    }
}

impl Cracked<'_> {
    fn present(&self, c: &Col) -> bool {
        self.nulls.get(c.number / 8).is_some_and(|b| b & (1 << (c.number % 8)) != 0)
    }

    fn bytes(&self, l: &Layout, c: &Col) -> Option<&[u8]> {
        if !self.present(c) {
            return None;
        }
        if c.fixed {
            let at = if l.jet3 { 1 } else { 2 } + c.fixed_offset;
            self.row.get(at..at + c.length)
        } else {
            let (a, b) = (*self.var.get(c.var_index)?, *self.var.get(c.var_index + 1)?);
            self.row.get(a..b.max(a))
        }
    }
}

impl Extractor for Access {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut h = vec![0u8; 256];
        src.read_exact_at(0, &mut h).map_err(|_| ExtractError::malformed("Access header"))?;
        let version = u32_at(&h, 0x14).unwrap_or(0);
        let (engine, release) = match version {
            0 => ("Jet 3", "Access 97"),
            1 => ("Jet 4", "Access 2000-2003"),
            2 => ("ACE 12", "Access 2007"),
            3 => ("ACE 14", "Access 2010"),
            4 => ("ACE 15", "Access 2013"),
            5 => ("ACE 16", "Access 2016 or later"),
            _ => ("unknown", "unknown"),
        };
        cx.format_set("engine", engine);
        cx.format_set("access_version", release);
        let l: &'static Layout = if version == 0 { &JET3 } else { &JET4 };
        rc4(&HEADER_KEY, &mut h[0x18..0x18 + if l.jet3 { 126 } else { 128 }]);
        if let Some(cp) = u16_at(&h, 0x3c) {
            cx.format_set("code_page", cp);
        }
        // A non-zero database key: the pages are RC4-encoded ("Encode
        // Database"); ACE files encrypted with a password say so elsewhere.
        let key = u32_at(&h, 0x3e).unwrap_or(0);
        let encoded = key != 0 && version < 2;
        cx.format_set("encoded", encoded);
        if !l.jet3 {
            let days = f64::from_bits(u64::from_le_bytes(h[0x72..0x7a].try_into().unwrap_or_default()));
            if days.is_finite() && days > 1.0 && days < 2_958_465.0 {
                // OLE automation date: days since 1899-12-30.
                #[allow(clippy::cast_possible_truncation)]
                let secs = ((days - 25_569.0) * 86_400.0).round() as i64;
                if let Some(t) = super::unix_time(secs) {
                    cx.format_set("created", t.clone());
                    cx.temporal().source("db.access").content_date(crate::plugin::DateField::Created, t, false);
                }
            }
        }
        if encoded {
            cx.security().encrypted(true);
            cx.warn("the database is encoded: its catalog is not read");
            return Ok(());
        }
        let pages = u32::try_from(src.len() / l.page_size as u64).unwrap_or(u32::MAX);
        cx.format_set("pages", pages);
        let mut f = File { src, l, pages, reads: 0, max_reads: (cx.parse_limit() / l.page_size).max(8) };
        catalog(&mut f, cx)
    }
}

/// `MSysObjects`: one row per object.
#[allow(clippy::too_many_lines)] // catalog rows, then each table's definition
fn catalog(f: &mut File<'_>, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let l = f.l;
    let t = f.tdef(CATALOG_TDEF).ok_or_else(|| ExtractError::malformed("MSysObjects definition"))?;
    let (cols, _) = f.columns(&t).ok_or_else(|| ExtractError::malformed("MSysObjects columns"))?;
    let find = |n: &str| cols.iter().find(|c| c.name.eq_ignore_ascii_case(n)).cloned();
    let (Some(id_c), Some(name_c), Some(type_c), flags_c) = (find("Id"), find("Name"), find("Type"), find("Flags"))
    else {
        return Err(ExtractError::malformed("MSysObjects columns"));
    };
    let mut objects: Vec<(u32, String, i16, u32)> = Vec::new();
    let mut complete = true;
    for n in 1..f.pages {
        let Some(page) = f.page(n) else {
            complete = false;
            break;
        };
        for row in f.rows(&page, CATALOG_TDEF) {
            let Some(c) = crack(l, &row) else { continue };
            let id = c.bytes(l, &id_c).and_then(|b| u32_at(b, 0)).unwrap_or(0);
            let name = c.bytes(l, &name_c).map(|b| f.text(b)).unwrap_or_default();
            let kind = c.bytes(l, &type_c).and_then(|b| b.get(..2)).map_or(0, |v| i16::from_le_bytes([v[0], v[1]]));
            let flags = flags_c.as_ref().and_then(|fc| c.bytes(l, fc)).and_then(|b| u32_at(b, 0)).unwrap_or(0);
            objects.push((id, name, kind, flags));
        }
        if n % 1024 == 0 {
            cx.checkpoint()?;
        }
    }
    if !complete {
        cx.warn("the page budget ran out before the whole catalog was read");
    }
    // System objects: the MSys / USys prefixes or the system flags.
    let system = |name: &str, flags: u32| {
        name.starts_with("MSys") || name.starts_with("USys") || name.starts_with('~') || flags & 0x8000_0002 != 0
    };
    let mut tables = Vec::new();
    let (mut linked, mut queries, mut counts) = (Vec::new(), Vec::new(), Map::new());
    for (id, name, kind, flags) in &objects {
        match kind {
            1 if !system(name, *flags) => tables.push((*id & 0x00ff_ffff, name.clone())),
            4 | 6 => linked.push(Value::from(name.clone())),
            5 if !name.starts_with('~') => queries.push(Value::from(name.clone())),
            -32768 | -32764 | -32766 | -32761 => {
                let key = match kind {
                    -32768 => "forms",
                    -32764 => "reports",
                    -32766 => "macros",
                    _ => "modules",
                };
                let n = counts.get(key).and_then(Value::as_u64).unwrap_or(0);
                counts.insert(key.into(), (n + 1).into());
            }
            _ => {}
        }
    }
    let mut list = Vec::new();
    for (page, name) in tables.iter().take(MAX_TABLES) {
        let mut m = Map::new();
        m.insert("name".into(), name.clone().into());
        if let Some(t) = f.tdef(*page)
            && let Some((cols, rows)) = f.columns(&t)
        {
            m.insert("rows".into(), rows.into());
            let mut sorted = cols;
            sorted.sort_by_key(|c| c.number);
            let shown: Vec<Value> = sorted
                .iter()
                .take(MAX_COLUMNS)
                .map(|c| json!({ "name": c.name, "type": type_name(c.kind), "length": c.length }))
                .collect();
            m.insert("columns".into(), shown.into());
        }
        list.push(Value::Object(m));
        cx.checkpoint()?;
    }
    cx.format_set("table_count", tables.len());
    cx.format_set("tables", list);
    if !linked.is_empty() {
        cx.format_set("linked_tables", linked);
    }
    if !queries.is_empty() {
        cx.format_set("query_count", queries.len());
        queries.truncate(64);
        cx.format_set("queries", queries);
    }
    let macros = counts.get("macros").and_then(Value::as_u64).unwrap_or(0);
    let modules = counts.get("modules").and_then(Value::as_u64).unwrap_or(0);
    for (k, v) in counts {
        cx.format_set(&k, v);
    }
    if macros + modules > 0 {
        cx.security().active_content("macros");
        cx.security().risk("macros", Some(format!("Access: {macros} macros, {modules} VBA modules")));
    }
    Ok(())
}

crate::register_extractor!(Access);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_matches_the_reference() {
        // RFC 6229 test vector: key 0x0102030405, first output bytes.
        let mut d = [0u8; 8];
        rc4(&[1, 2, 3, 4, 5], &mut d);
        assert_eq!(d, [0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27]);
    }

    #[test]
    fn compressed_unicode_text() {
        assert_eq!(text(false, b"\xff\xfeTide\0\x3a\x04\0s"), "Tide\u{43a}s");
        assert_eq!(text(false, &[0x54, 0, 0x69, 0]), "Ti");
    }

    crate::fixture_tests!("access");
}
