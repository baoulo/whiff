//! `dBASE` / FoxPro / Visual FoxPro tables (`.dbf`, also the attribute table
//! of every shapefile): the variant, last update, record count and size,
//! the code page, whether a memo file goes with it, the field descriptors
//! (name, type, length, decimals) and how many records are marked deleted.
//!
//! Specification: dBASE III+ / IV / 7 file structure (dbase.com), Visual
//! FoxPro "Table File Structure" (`.dbc`, `.dbf`, `.frx`, …).

use serde_json::{Map, Value};

use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source};

/// Extractor for DBF tables.
pub struct Dbf;

static META: ExtractorMeta = ExtractorMeta {
    id: "db.dbf",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "dbf",
        name: "dBASE / FoxPro table",
        family: "db",
        mimes: &["application/dbase", "application/x-dbf"],
        extensions: &["dbf"],
        magic: &[],
        parent: None,
    }],
};

/// Most fields read.
const MAX_FIELDS: usize = 2048;
/// Records whose deletion flag is read.
const MAX_SCAN: u64 = 10_000_000;

fn variant(v: u8) -> Option<&'static str> {
    Some(match v {
        0x02 | 0xfb => "FoxBASE",
        0x03 => "dBASE III",
        0x04 => "dBASE IV",
        0x05 => "dBASE V",
        0x30..=0x32 => "Visual FoxPro",
        0x43 | 0x63 => "dBASE IV SQL",
        0x83 => "dBASE III with memo",
        0x8b => "dBASE IV with memo",
        0x8c => "dBASE 7 with memo",
        0xcb => "dBASE IV SQL with memo",
        0xe5 => "Clipper SIX with memo",
        0xf5 => "FoxPro 2 with memo",
        _ => return None,
    })
}

fn code_page(ldid: u8) -> Option<&'static str> {
    Some(match ldid {
        0x03 | 0x57 => "cp1252",
        0x04 => "mac_roman",
        0x01 | 0x08..=0x0b | 0x0d..=0x12 | 0x14..=0x16 => "cp437",
        0x13 | 0x7b => "cp932",
        0x02 | 0x17..=0x1b | 0x1d | 0x1f | 0x22 | 0x25 | 0x37 | 0x40 => "cp850",
        0x26 | 0x65 => "cp866",
        0x64 => "cp852",
        0x66 => "cp865",
        0x67 => "cp861",
        0x6a => "cp737",
        0x6b => "cp857",
        0x78 => "cp950",
        0x79 => "cp949",
        0x7a => "cp936",
        0x7c => "cp874",
        0x7d => "cp1255",
        0x7e => "cp1256",
        0xc8 => "cp1250",
        0xc9 => "cp1251",
        0xca => "cp1254",
        0xcb => "cp1253",
        0xcc => "cp1257",
        _ => return None,
    })
}

fn field_type(t: u8) -> &'static str {
    match t {
        b'C' => "character",
        b'N' => "numeric",
        b'F' => "float",
        b'L' => "logical",
        b'D' => "date",
        b'M' => "memo",
        b'G' => "general",
        b'B' => "binary",
        b'I' => "integer",
        b'Y' => "currency",
        b'T' => "datetime",
        b'@' => "timestamp",
        b'+' => "autoincrement",
        b'O' => "double",
        b'V' => "varchar",
        b'Q' => "varbinary",
        b'W' => "blob",
        b'P' => "picture",
        _ => "unknown",
    }
}

#[allow(clippy::struct_field_names)] // the format's own names
struct Header {
    version: u8,
    date: Option<String>,
    records: u32,
    header_len: usize,
    record_len: usize,
    /// `dBASE` 7: 48-byte field descriptors from offset 68.
    level7: bool,
}

fn header(b: &[u8], file_len: u64) -> Option<Header> {
    let version = *b.first()?;
    variant(version)?;
    let (yy, mm, dd) = (u32::from(*b.get(1)?), u32::from(b[2]), u32::from(b[3]));
    let records = u32::from_le_bytes(b.get(4..8)?.try_into().ok()?);
    let header_len = usize::from(u16::from_le_bytes([b[8], b[9]]));
    let record_len = usize::from(u16::from_le_bytes([b[10], b[11]]));
    if header_len < 33 || record_len == 0 || mm > 12 || dd > 31 {
        return None;
    }
    // The records fill the file, give or take the end-of-file mark.
    let body = file_len.checked_sub(header_len as u64)?;
    let want = u64::from(records) * record_len as u64;
    if body < want || body > want + 1 + 512 {
        return None;
    }
    let level7 = version & 0x07 == 4 && b.get(32..36).is_some() && (header_len - 68).is_multiple_of(48);
    // dBASE counts years since 1900 (2025 is 125); FoxPro writers often
    // keep two digits (25).
    let year = if yy < 70 { 2000 + yy } else { 1900 + yy };
    let date = (mm >= 1 && dd >= 1).then(|| format!("{year:04}-{mm:02}-{dd:02}"));
    Some(Header { version, date, records, header_len, record_len, level7: level7 && header_len >= 68 })
}

impl Extractor for Dbf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = header(probe.head, probe.len)?;
        // A terminated field list confirms it.
        let fields = probe.head.get(32..h.header_len.min(probe.head.len()))?;
        fields.contains(&0x0d).then_some(Sniff { format: "dbf", confidence: 0.75 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut head = vec![0u8; 32];
        src.read_exact_at(0, &mut head).map_err(|_| ExtractError::malformed("DBF header"))?;
        let mut h = header(&head, src.len()).ok_or_else(|| ExtractError::malformed("DBF header"))?;
        let mut fields_area = vec![0u8; h.header_len];
        src.read_exact_at(0, &mut fields_area).map_err(|_| ExtractError::malformed("DBF field descriptors"))?;
        if h.version & 0x07 == 4 && fields_area.get(68 - 1).is_some() && fields_area[32..68].iter().any(|&c| c != 0) {
            // dBASE 7 keeps a language driver name at 32..64.
            h.level7 = true;
        }
        cx.format_set("variant", variant(h.version).unwrap_or("dBASE"));
        cx.format_set("version_byte", format!("0x{:02x}", h.version));
        if let Some(d) = &h.date {
            cx.format_set("last_update", d.clone());
        }
        cx.format_set("records", h.records);
        cx.format_set("record_length", h.record_len);
        let ldid = head[29];
        if ldid != 0 {
            cx.format_set("language_driver", format!("0x{ldid:02x}"));
            if let Some(cp) = code_page(ldid) {
                cx.format_set("code_page", cp);
            }
        }
        let memo =
            h.version & 0x80 != 0 || matches!(h.version, 0xf5 | 0xe5) || (h.version == 0x30 && head[28] & 0x02 != 0);
        cx.format_set("memo_file", memo);
        if h.version >= 0x30 && h.version <= 0x32 && head[28] & 0x01 != 0 {
            cx.format_set("structural_index", true);
        }
        let (start, size, name_len) = if h.level7 { (68, 48, 32) } else { (32, 32, 11) };
        let mut fields = Vec::new();
        let mut at = start;
        let mut total = 1usize; // the deletion flag
        while at + size <= fields_area.len() && fields_area[at] != 0x0d && fields.len() < MAX_FIELDS {
            let d = &fields_area[at..at + size];
            let name_raw = &d[..name_len];
            let name: String = name_raw.iter().take_while(|&&c| c != 0).map(|&c| char::from(c)).collect();
            let t = d[name_len];
            let (len, dec) = if h.level7 { (d[33], d[34]) } else { (d[16], d[17]) };
            let mut m = Map::new();
            m.insert("name".into(), name.trim().into());
            m.insert("type".into(), field_type(t).into());
            m.insert("length".into(), len.into());
            if dec > 0 {
                m.insert("decimals".into(), dec.into());
            }
            total += usize::from(len);
            // Visual FoxPro's hidden null-flags field.
            if t != b'0' {
                fields.push(Value::Object(m));
            }
            at += size;
        }
        if total != h.record_len {
            cx.warn(format!("the fields add up to {total} bytes, the records are {}", h.record_len));
        }
        let memo_field =
            fields.iter().any(|f| ["memo", "general", "picture", "blob"].contains(&f["type"].as_str().unwrap_or("")));
        if memo_field {
            cx.format_set("memo_file", true);
        }
        cx.format_set("field_count", fields.len());
        cx.format_set("fields", fields);
        // The first byte of each record: '*' when deleted.
        let n = u64::from(h.records).min(MAX_SCAN);
        let budget = (cx.parse_limit() as u64) / h.record_len.max(1) as u64;
        if n <= budget {
            let mut deleted = 0u64;
            let chunk = (1 << 20) / h.record_len * h.record_len;
            let mut buf = vec![0u8; chunk.max(h.record_len)];
            let mut done = 0u64;
            while done < n {
                let count = (buf.len() / h.record_len).min(usize::try_from(n - done).unwrap_or(usize::MAX));
                let off = h.header_len as u64 + done * h.record_len as u64;
                if src.read_exact_at(off, &mut buf[..count * h.record_len]).is_err() {
                    break;
                }
                deleted +=
                    buf[..count * h.record_len].iter().step_by(h.record_len).filter(|&&c| c == b'*').count() as u64;
                done += count as u64;
                cx.checkpoint()?;
            }
            cx.format_set("deleted_records", deleted);
        }
        Ok(())
    }
}

crate::register_extractor!(Dbf);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("dbf");
}
