//! OLE property sets (MS-OLEPS): the `\x05SummaryInformation` and
//! `\x05DocumentSummaryInformation` streams of compound files (title,
//! author, dates, counts, company…), including user-defined properties.
//!
//! Values are decoded by type (integers, reals, booleans, strings in the
//! set's code page, FILETIMEs, vectors); binary values are reported by size.

use serde_json::{Value, json};

use super::cfb::filetime;
use crate::io::ByteReader;
use crate::plugin::{ExtractError, Map};

/// `SummaryInformation` format id.
pub const FMTID_SUMMARY: &str = "F29F85E0-4FF9-1068-AB91-08002B27B3D9";
/// `DocumentSummaryInformation` format id.
pub const FMTID_DOC_SUMMARY: &str = "D5CDD502-2E9C-101B-9397-08002B2CF9AE";
/// User-defined properties (second section of `DocumentSummaryInformation`).
pub const FMTID_USER: &str = "D5CDD505-2E9C-101B-9397-08002B2CF9AE";
/// Hangul (HWP) summary information: the `SummaryInformation` property ids
/// under Hancom's own format id.
pub const FMTID_HWP_SUMMARY: &str = "9FA2B660-1061-11D4-B4C6-006097C09D8C";

const MAX_PROPERTIES: usize = 1000;
const MAX_VECTOR: usize = 1000;

/// A decoded property value.
#[derive(Debug, Clone, PartialEq)]
pub enum PropValue {
    /// Any integer type.
    Int(i64),
    /// `VT_R4` / `VT_R8`.
    Float(f64),
    /// `VT_BOOL`.
    Bool(bool),
    /// `VT_LPSTR` / `VT_LPWSTR` / `VT_BSTR`.
    Str(String),
    /// `VT_FILETIME`: raw 100 ns ticks (a date, or a duration for edit time).
    Time(u64),
    /// `VT_VECTOR` of values.
    List(Vec<PropValue>),
    /// Binary data (`VT_BLOB`, `VT_CF` thumbnails): size only.
    Binary(usize),
}

impl PropValue {
    /// As JSON (dates as RFC 3339).
    pub fn to_json(&self) -> Value {
        match self {
            Self::Int(v) => json!(v),
            Self::Float(v) => json!(v),
            Self::Bool(v) => json!(v),
            Self::Str(s) => json!(s),
            Self::Time(t) => filetime(*t).map_or(Value::Null, Value::String),
            Self::List(v) => Value::Array(v.iter().map(Self::to_json).collect()),
            Self::Binary(n) => json!({ "binary_bytes": n }),
        }
    }

    /// The string value, if any (trimmed of NULs, non-empty).
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()).filter(|s| !s.is_empty()),
            _ => None,
        }
    }

    /// The integer value, if any.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }
}

/// One property section.
#[derive(Debug, Clone, Default)]
pub struct Section {
    /// Format id (GUID).
    pub fmtid: String,
    /// `(property id, value)` pairs in stream order.
    pub values: Vec<(u32, PropValue)>,
    /// Names of user-defined properties (the dictionary, property 0).
    pub names: Vec<(u32, String)>,
}

impl Section {
    /// The value of property `id`.
    pub fn get(&self, id: u32) -> Option<&PropValue> {
        self.values.iter().find(|(i, _)| *i == id).map(|(_, v)| v)
    }
}

fn encoding_for(code_page: i64) -> &'static encoding_rs::Encoding {
    let label: &[u8] = match code_page {
        874 => b"windows-874",
        932 => b"shift_jis",
        936 => b"gbk",
        949 => b"euc-kr",
        950 => b"big5",
        1250..=1258 => {
            return encoding_rs::Encoding::for_label(format!("windows-{code_page}").as_bytes())
                .unwrap_or(encoding_rs::WINDOWS_1252);
        }
        10000 => b"macintosh",
        20866 => b"koi8-r",
        28591 => b"iso-8859-1",
        28592 => b"iso-8859-2",
        65001 => b"utf-8",
        _ => b"windows-1252",
    };
    encoding_rs::Encoding::for_label(label).unwrap_or(encoding_rs::WINDOWS_1252)
}

fn clean(s: &str) -> String {
    s.trim_end_matches('\0').trim().to_string()
}

struct Reader<'a> {
    data: &'a [u8],
    code_page: i64,
}

impl Reader<'_> {
    fn lpstr(&self, r: &mut ByteReader<'_>) -> Result<String, ExtractError> {
        let n = r.le_u32()? as usize;
        if self.code_page == 1200 {
            let b = r.bytes(n.min(r.remaining()))?;
            let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            return Ok(clean(&String::from_utf16_lossy(&units)));
        }
        let b = r.bytes(n.min(r.remaining()))?;
        Ok(clean(&encoding_for(self.code_page).decode_without_bom_handling(b).0))
    }

    fn lpwstr(r: &mut ByteReader<'_>) -> Result<String, ExtractError> {
        let n = r.le_u32()? as usize;
        let b = r.bytes(n.saturating_mul(2).min(r.remaining()))?;
        let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        Ok(clean(&String::from_utf16_lossy(&units)))
    }

    /// One typed value (`vt` already read), leaving `r` after it (4-byte aligned).
    fn value(&self, vt: u16, r: &mut ByteReader<'_>, depth: u8) -> Result<PropValue, ExtractError> {
        if vt & 0x1000 != 0 && depth == 0 {
            let n = r.le_u32()? as usize;
            let mut items = Vec::new();
            for _ in 0..n.min(MAX_VECTOR) {
                let item_vt = if vt & 0xFFF == 12 {
                    let t = r.le_u16()?;
                    r.advance(2)?;
                    t
                } else {
                    vt & 0xFFF
                };
                items.push(self.value(item_vt, r, 1)?);
                if vt & 0xFFF == 30 || vt & 0xFFF == 31 {
                    align(r);
                }
            }
            return Ok(PropValue::List(items));
        }
        let v = match vt {
            2 => PropValue::Int(i64::from(r.le_i16()?)),
            18 => PropValue::Int(i64::from(r.le_u16()?)),
            3 | 22 => PropValue::Int(i64::from(r.le_i32()?)),
            19 | 23 => PropValue::Int(i64::from(r.le_u32()?)),
            20 | 21 => PropValue::Int(i64::from_le_bytes(r.array::<8>()?)),
            16 => PropValue::Int(i64::from(r.u8()?.cast_signed())),
            17 => PropValue::Int(i64::from(r.u8()?)),
            4 => PropValue::Float(f64::from(f32::from_le_bytes(r.array::<4>()?))),
            5 => PropValue::Float(f64::from_le_bytes(r.array::<8>()?)),
            11 => PropValue::Bool(r.le_u16()? != 0),
            8 | 30 => PropValue::Str(self.lpstr(r)?),
            31 => PropValue::Str(Self::lpwstr(r)?),
            64 => PropValue::Time(r.le_u64()?),
            65 | 71 => {
                let n = r.le_u32()? as usize;
                r.advance(n.min(r.remaining()))?;
                PropValue::Binary(n)
            }
            other => return Err(ExtractError::malformed(format!("property type {other:#x}"))),
        };
        Ok(v)
    }
}

fn align(r: &mut ByteReader<'_>) {
    let pad = (4 - r.position() % 4) % 4;
    let _ = r.advance(pad.min(r.remaining()));
}

#[allow(clippy::many_single_char_names)] // MS-OLEPS field names
fn section(data: &[u8], fmtid: String, offset: usize) -> Result<Section, ExtractError> {
    let body = data.get(offset..).ok_or_else(|| ExtractError::malformed("section offset"))?;
    let mut r = ByteReader::new(body);
    let size = (r.le_u32()? as usize).min(body.len());
    let body = &body[..size];
    let count = r.le_u32()? as usize;
    let mut index = Vec::new();
    for _ in 0..count.min(MAX_PROPERTIES) {
        index.push((r.le_u32()?, r.le_u32()? as usize));
    }
    let code_page = index
        .iter()
        .find(|(id, _)| *id == 1)
        .and_then(|&(_, off)| body.get(off + 4..off + 6))
        .map_or(1252, |b| i64::from(u16::from_le_bytes([b[0], b[1]])));
    let reader = Reader { data: body, code_page };
    let mut s = Section { fmtid, ..Section::default() };
    for (id, off) in index {
        let Some(at) = reader.data.get(off..) else { continue };
        let mut v = ByteReader::new(at);
        if id == 0 {
            // Dictionary: count, then (id, length, name) entries.
            let Ok(n) = v.le_u32() else { continue };
            for _ in 0..(n as usize).min(MAX_PROPERTIES) {
                let (Ok(pid), Ok(len)) = (v.le_u32(), v.le_u32()) else { break };
                let name = if code_page == 1200 {
                    let Ok(b) = v.bytes((len as usize).saturating_mul(2).min(v.remaining())) else { break };
                    let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                    align(&mut v);
                    clean(&String::from_utf16_lossy(&units))
                } else {
                    let Ok(b) = v.bytes((len as usize).min(v.remaining())) else { break };
                    clean(&encoding_for(code_page).decode_without_bom_handling(b).0)
                };
                s.names.push((pid, name));
            }
            continue;
        }
        let Ok(vt) = v.le_u16() else { continue };
        if v.advance(2).is_err() {
            continue;
        }
        if let Ok(value) = reader.value(vt, &mut v, 0) {
            s.values.push((id, value));
        }
    }
    Ok(s)
}

/// Parse a property-set stream into its sections.
pub fn parse(data: &[u8]) -> Result<Vec<Section>, ExtractError> {
    let mut r = ByteReader::new(data);
    if r.le_u16()? != 0xFFFE {
        return Err(ExtractError::malformed("property set byte order"));
    }
    r.advance(22)?;
    let n = r.le_u32()? as usize;
    let mut out = Vec::new();
    for _ in 0..n.min(4) {
        let id = r.array::<16>()?;
        let offset = r.le_u32()? as usize;
        let fmtid = super::cfb::guid(&id).unwrap_or_default();
        out.push(section(data, fmtid, offset)?);
    }
    Ok(out)
}

/// Standard names of `SummaryInformation` properties.
pub fn summary_name(id: u32) -> Option<&'static str> {
    Some(match id {
        2 => "Title",
        3 => "Subject",
        4 => "Author",
        5 => "Keywords",
        6 => "Comments",
        7 => "Template",
        8 => "LastAuthor",
        9 => "RevisionNumber",
        10 => "TotalEditTime",
        11 => "LastPrinted",
        12 => "CreateDate",
        13 => "ModifyDate",
        14 => "Pages",
        15 => "Words",
        16 => "Characters",
        17 => "Thumbnail",
        18 => "Application",
        19 => "Security",
        _ => return None,
    })
}

/// Standard names of `DocumentSummaryInformation` properties.
pub fn doc_summary_name(id: u32) -> Option<&'static str> {
    Some(match id {
        2 => "Category",
        3 => "PresentationFormat",
        4 => "Bytes",
        5 => "Lines",
        6 => "Paragraphs",
        7 => "Slides",
        8 => "Notes",
        9 => "HiddenSlides",
        10 => "MultimediaClips",
        11 => "ScaleCrop",
        12 => "HeadingPairs",
        13 => "TitlesOfParts",
        14 => "Manager",
        15 => "Company",
        16 => "LinksUpToDate",
        17 => "CharactersWithSpaces",
        19 => "SharedDocument",
        22 => "HyperlinksChanged",
        23 => "AppVersion",
        26 => "ContentType",
        27 => "ContentStatus",
        28 => "Language",
        29 => "DocumentVersion",
        _ => return None,
    })
}

/// The sections of a summary stream as one map with standard names: known
/// properties by name, user-defined ones under `custom` by their dictionary
/// names. Edit time is in seconds (`TotalEditTime_s`), the application
/// version as `major.minor`, the security flags as a list.
pub fn named(sections: &[Section]) -> Map {
    let mut out = Map::new();
    for s in sections {
        let user = s.fmtid == FMTID_USER;
        let fmtid = if s.fmtid == FMTID_HWP_SUMMARY { FMTID_SUMMARY } else { s.fmtid.as_str() };
        let mut custom = Map::new();
        for (id, v) in &s.values {
            if *id == 1 {
                continue; // code page
            }
            let name = match fmtid {
                FMTID_SUMMARY => summary_name(*id).map(str::to_string),
                FMTID_DOC_SUMMARY => doc_summary_name(*id).map(str::to_string),
                _ => s.names.iter().find(|(i, _)| i == id).map(|(_, n)| n.clone()),
            };
            let Some(name) = name else { continue };
            let value = match (fmtid, *id, v) {
                (FMTID_SUMMARY, 10, PropValue::Time(t)) => {
                    out.insert("TotalEditTime_s".into(), json!(t / 10_000_000));
                    continue;
                }
                (FMTID_SUMMARY, 19, PropValue::Int(f)) => {
                    let flags: Vec<&str> =
                        [(1, "password_protected"), (2, "read_only_recommended"), (4, "read_only"), (8, "locked")]
                            .iter()
                            .filter(|(b, _)| f & b != 0)
                            .map(|(_, n)| *n)
                            .collect();
                    json!(flags)
                }
                (FMTID_DOC_SUMMARY, 23, PropValue::Int(v)) => json!(format!("{}.{}", v >> 16, v & 0xFFFF)),
                (_, _, PropValue::Str(s)) if s.is_empty() => continue,
                _ => v.to_json(),
            };
            if user {
                custom.insert(name, value);
            } else {
                out.insert(name, value);
            }
        }
        if !custom.is_empty() {
            out.insert("custom".into(), Value::Object(custom));
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // test property sets are small
pub(crate) mod tests {
    use super::*;

    /// A property-set stream with one section of `(id, vt, raw value)` properties.
    pub(crate) fn build(fmtid: [u8; 16], props: &[(u32, u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        let header_len = 8 + props.len() * 8;
        let mut index = Vec::new();
        for (id, vt, raw) in props {
            index.push((*id, (header_len + body.len()) as u32));
            body.extend_from_slice(&vt.to_le_bytes());
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(raw);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut section = Vec::new();
        section.extend_from_slice(&((header_len + body.len()) as u32).to_le_bytes());
        section.extend_from_slice(&(props.len() as u32).to_le_bytes());
        for (id, off) in index {
            section.extend_from_slice(&id.to_le_bytes());
            section.extend_from_slice(&off.to_le_bytes());
        }
        section.extend_from_slice(&body);
        let mut out = vec![0xFE, 0xFF, 0, 0, 2, 0, 0, 0];
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&fmtid);
        out.extend_from_slice(&48u32.to_le_bytes());
        out.extend_from_slice(&section);
        out
    }

    /// `SummaryInformation`'s format id in stream byte order.
    pub(crate) const SUMMARY: [u8; 16] =
        [0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9];

    pub(crate) fn lpstr(s: &str) -> Vec<u8> {
        let mut v = ((s.len() + 1) as u32).to_le_bytes().to_vec();
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        v
    }

    #[test]
    fn decodes_summary_information() {
        let stream = build(
            SUMMARY,
            &[
                (1, 2, 1252u16.to_le_bytes().to_vec()),
                (2, 30, lpstr("Quarterly report")),
                (4, 30, lpstr("Ana Lima")),
                (10, 64, (600u64 * 10_000_000).to_le_bytes().to_vec()),
                (12, 64, 133_000_000_000_000_000u64.to_le_bytes().to_vec()),
                (14, 3, 7i32.to_le_bytes().to_vec()),
                (19, 3, 2i32.to_le_bytes().to_vec()),
            ],
        );
        let sections = parse(&stream).unwrap();
        assert_eq!(sections[0].fmtid, FMTID_SUMMARY);
        let m = named(&sections);
        assert_eq!(m["Title"], "Quarterly report");
        assert_eq!(m["Author"], "Ana Lima");
        assert_eq!(m["TotalEditTime_s"], 600);
        assert_eq!(m["Pages"], 7);
        assert_eq!(m["Security"], json!(["read_only_recommended"]));
        assert!(m["CreateDate"].as_str().unwrap().starts_with("2022-"));
        assert!(parse(b"\x00\x00rubbish").is_err());
    }
}
