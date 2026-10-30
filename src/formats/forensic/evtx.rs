//! Windows event logs: EVTX (Vista and later) and the older EVT. EVTX gives
//! the file header (version, chunks, next record, dirty / full flags), the
//! record count and number range from the chunk headers, the time range,
//! and from each record's binary XML (its template and substitution
//! values) histograms of channels, providers, event IDs and levels, and
//! the number of computers. Event data (the `EventData` / `UserData`
//! values) is never reported. EVT gives the record count, time range,
//! sources and event IDs.
//!
//! Specifications: Microsoft "MS-EVEN6" binary XML; libyal "Windows XML
//! Event Log (EVTX) format" and "Windows Event Log (EVT) format".

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::Value;

use super::{filetime, le, le_usize, unix_time, utf16z};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for Windows event logs.
pub struct Evtx;

static META: ExtractorMeta = ExtractorMeta {
    id: "forensic.evtx",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "evtx",
            name: "Windows XML event log",
            family: "forensic",
            mimes: &["application/x-ms-evtx"],
            extensions: &["evtx"],
            magic: &[Magic::prefix(b"ElfFile\0")],
            parent: None,
        },
        FormatSpec {
            id: "evt",
            name: "Windows event log (EVT)",
            family: "forensic",
            mimes: &[],
            extensions: &["evt"],
            magic: &[Magic::at(4, b"LfLe")],
            parent: None,
        },
    ],
};

const CHUNK: usize = 65536;
/// Histogram entries kept.
const TOP: usize = 30;

/// Where a field of `System` comes from in a template.
#[derive(Debug, Clone)]
enum Src {
    Literal(String),
    Sub(usize),
}

/// The `System` fields a template defines.
#[derive(Debug, Clone, Default)]
struct Template {
    fields: HashMap<&'static str, Src>,
}

/// An element or attribute name at `off` in the chunk.
fn name_at(c: &[u8], off: usize) -> Option<String> {
    let n = usize::from(u16::from_le_bytes(c.get(off + 6..off + 8)?.try_into().ok()?));
    Some(utf16z(c.get(off + 8..off + 8 + 2 * n)?))
}

/// Size of an inline name structure.
fn name_size(c: &[u8], off: usize) -> Option<usize> {
    let n = usize::from(u16::from_le_bytes(c.get(off + 6..off + 8)?.try_into().ok()?));
    Some(8 + 2 * n + 2)
}

fn field_key(path: &[String], attr: Option<&str>) -> Option<&'static str> {
    let n = path.len();
    let last = path.last()?.as_str();
    let parent = n.checked_sub(2).and_then(|i| path.get(i)).map(String::as_str);
    match (parent, last, attr) {
        (Some("System"), "Provider", Some("Name")) => Some("provider"),
        (Some("System"), "EventID", None) => Some("event_id"),
        (Some("System"), "Channel", None) => Some("channel"),
        (Some("System"), "Level", None) => Some("level"),
        (Some("System"), "Computer", None) => Some("computer"),
        _ => None,
    }
}

/// Walk a template definition's binary XML from `pos` to `end` and note
/// where the `System` fields come from.
fn template(c: &[u8], mut pos: usize, end: usize) -> Template {
    let mut t = Template::default();
    let mut path: Vec<String> = Vec::new();
    let mut attr: Option<String> = None;
    let mut steps = 0;
    while pos < end.min(c.len()) && steps < 10_000 {
        steps += 1;
        let tok = c[pos];
        match tok & 0xbf {
            0x0f => pos += 4,
            0x01 => {
                let Some(off) = c.get(pos + 7..pos + 11).map(le_usize) else { break };
                pos += 11;
                let name = name_at(c, off).unwrap_or_default();
                if off == pos {
                    pos += name_size(c, off).unwrap_or(0);
                }
                if tok & 0x40 != 0 {
                    pos += 4;
                }
                path.push(name);
                attr = None;
            }
            0x02 => {
                attr = None;
                pos += 1;
            }
            0x03 | 0x04 => {
                path.pop();
                attr = None;
                pos += 1;
            }
            0x06 => {
                let Some(off) = c.get(pos + 1..pos + 5).map(le_usize) else { break };
                pos += 5;
                attr = name_at(c, off);
                if off == pos {
                    pos += name_size(c, off).unwrap_or(0);
                }
            }
            0x05 => {
                let kind = c.get(pos + 1).copied().unwrap_or(0);
                pos += 2;
                if kind != 1 {
                    break;
                }
                let Some(n) = c.get(pos..pos + 2).map(le_usize) else { break };
                let s = utf16z(c.get(pos + 2..pos + 2 + 2 * n).unwrap_or_default());
                pos += 2 + 2 * n;
                if let Some(k) = field_key(&path, attr.as_deref()) {
                    t.fields.insert(k, Src::Literal(s));
                }
            }
            0x0d | 0x0e => {
                let Some(i) = c.get(pos + 1..pos + 3).map(le_usize) else { break };
                pos += 4;
                if let Some(k) = field_key(&path, attr.as_deref()) {
                    t.fields.entry(k).or_insert(Src::Sub(i));
                }
            }
            // CDATA and processing-instruction data: a counted string.
            0x07 | 0x0b => {
                let Some(n) = c.get(pos + 1..pos + 3).map(le_usize) else { break };
                pos += 3 + 2 * n;
            }
            0x08 => pos += 3,
            0x09 | 0x0a => pos += 5,
            _ => break,
        }
    }
    t
}

/// A substitution value as text.
fn value(kind: u8, v: &[u8]) -> Option<String> {
    Some(match kind {
        0x01 => utf16z(v),
        0x02 => super::asciiz(v),
        0x04 => v.first()?.to_string(),
        0x03 => i8::from_le_bytes([*v.first()?]).to_string(),
        0x05 | 0x06 => le(v.get(..2)?).to_string(),
        0x07 | 0x08 => le(v.get(..4)?).to_string(),
        0x09 | 0x0a => le(v.get(..8)?).to_string(),
        _ => return None,
    })
}

/// The `System` facts of the record whose binary XML starts at `pos`.
fn record_fields(c: &[u8], pos: usize, cache: &mut HashMap<usize, Template>) -> Option<HashMap<&'static str, String>> {
    let mut pos = pos;
    if c.get(pos) == Some(&0x0f) {
        pos += 4;
    }
    if c.get(pos)? & 0xbf != 0x0c {
        return None;
    }
    let def = le_usize(c.get(pos + 6..pos + 10)?);
    pos += 10;
    let size = le_usize(c.get(def + 20..def + 24)?);
    if def == pos {
        pos += 24 + size;
    }
    let t = cache.entry(def).or_insert_with(|| template(c, def + 24, def + 24 + size)).clone();
    let count = le_usize(c.get(pos..pos + 4)?);
    if count > 4096 {
        return None;
    }
    let descs = c.get(pos + 4..pos + 4 + 4 * count)?;
    let mut at = pos + 4 + 4 * count;
    let mut values: Vec<(u8, &[u8])> = Vec::with_capacity(count);
    for d in descs.as_chunks::<4>().0 {
        let n = usize::from(u16::from_le_bytes([d[0], d[1]]));
        values.push((d[2], c.get(at..at + n)?));
        at += n;
    }
    let mut out = HashMap::new();
    for (k, src) in t.fields {
        let v = match src {
            Src::Literal(s) => Some(s),
            Src::Sub(i) => values.get(i).and_then(|(kind, v)| value(*kind, v)),
        };
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            out.insert(k, v);
        }
    }
    Some(out)
}

#[derive(Default)]
struct Tally {
    channels: BTreeMap<String, u64>,
    providers: BTreeMap<String, u64>,
    event_ids: BTreeMap<String, u64>,
    levels: BTreeMap<String, u64>,
    computers: HashSet<String>,
    parsed: u64,
}

fn top(m: BTreeMap<String, u64>) -> Value {
    let mut v: Vec<(String, u64)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Value::Object(v.into_iter().take(TOP).map(|(k, n)| (k, n.into())).collect())
}

fn level_name(l: &str) -> String {
    match l {
        "0" => "log_always".into(),
        "1" => "critical".into(),
        "2" => "error".into(),
        "3" => "warning".into(),
        "4" => "information".into(),
        "5" => "verbose".into(),
        other => format!("level_{other}"),
    }
}

impl Extractor for Evtx {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // header, chunk walk, then the tallies
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "evt" {
            return evt(src, cx);
        }
        let mut h = vec![0u8; 128];
        src.read_exact_at(0, &mut h).map_err(|_| ExtractError::malformed("EVTX header"))?;
        cx.format_set("version", format!("{}.{}", le(&h[38..40]), le(&h[36..38])));
        let flags = le(&h[120..124]);
        cx.format_set("dirty", flags & 1 != 0);
        cx.format_set("full", flags & 2 != 0);
        cx.format_set("next_record_id", le(&h[24..32]));
        let block = usize::try_from(le(&h[40..42])).unwrap_or(4096).max(4096);
        let chunks = usize::try_from((src.len().saturating_sub(block as u64)) / CHUNK as u64).unwrap_or(0);
        let budget = (cx.parse_limit() / CHUNK).max(1);
        let (mut records, mut lo_id, mut hi_id) = (0u64, u64::MAX, 0u64);
        let (mut first, mut last) = (u64::MAX, 0u64);
        let mut tally = Tally::default();
        let mut used = 0usize;
        let mut buf = vec![0u8; CHUNK];
        for i in 0..chunks {
            let off = block as u64 + (i * CHUNK) as u64;
            if src.read_exact_at(off, &mut buf[..512]).is_err() || &buf[..8] != b"ElfChnk\0" {
                continue;
            }
            let (a, b) = (le(&buf[24..32]), le(&buf[32..40]));
            if b >= a && a > 0 {
                records += b - a + 1;
                lo_id = lo_id.min(a);
                hi_id = hi_id.max(b);
            }
            let full = used < budget;
            let n = if full { CHUNK } else { 512 };
            if full {
                used += 1;
                if src.read_exact_at(off, &mut buf[..n]).is_err() {
                    continue;
                }
            }
            // Record timestamps: every record of a read chunk; otherwise the
            // first and last record of the chunk.
            let free = (le_usize(&buf[48..52])).min(CHUNK);
            let last_rec = le_usize(&buf[44..48]);
            let mut cache = HashMap::new();
            let mut at = 512;
            if full {
                while at + 24 <= free {
                    if buf[at..at + 4] != [0x2a, 0x2a, 0, 0] {
                        break;
                    }
                    let size = le_usize(&buf[at + 4..at + 8]);
                    let t = le(&buf[at + 16..at + 24]);
                    first = first.min(t);
                    last = last.max(t);
                    if let Some(f) = record_fields(&buf[..CHUNK], at + 24, &mut cache) {
                        tally.parsed += 1;
                        if let Some(v) = f.get("channel") {
                            *tally.channels.entry(v.clone()).or_default() += 1;
                        }
                        if let Some(v) = f.get("provider") {
                            *tally.providers.entry(v.clone()).or_default() += 1;
                        }
                        if let Some(v) = f.get("event_id") {
                            *tally.event_ids.entry(v.clone()).or_default() += 1;
                        }
                        if let Some(v) = f.get("level") {
                            *tally.levels.entry(level_name(v)).or_default() += 1;
                        }
                        if let Some(v) = f.get("computer")
                            && tally.computers.len() < 100_000
                        {
                            tally.computers.insert(v.clone());
                        }
                    }
                    if size < 24 {
                        break;
                    }
                    at += size;
                }
            } else {
                let mut t = [0u8; 8];
                for rec in [512usize, last_rec] {
                    if rec >= 512 && src.read_exact_at(off + rec as u64 + 16, &mut t).is_ok() {
                        first = first.min(le(&t));
                        last = last.max(le(&t));
                    }
                }
            }
            if i % 64 == 63 {
                cx.checkpoint()?;
            }
        }
        cx.format_set("chunks", chunks);
        // A dirty log's header lags behind: the chunks after its count
        // were written but not yet recorded.
        let declared = usize::try_from(le(&h[42..44])).unwrap_or(0);
        if declared != chunks && declared > 0 {
            cx.format_set("header_chunks", declared);
        }
        cx.format_set("records", records);
        if records > 0 {
            cx.format_set("first_record_id", lo_id);
            cx.format_set("last_record_id", hi_id);
        }
        if let (Some(a), Some(b)) = (filetime(first), filetime(last)) {
            cx.format_set("first_event", a.clone());
            cx.format_set("last_event", b);
            cx.temporal().source("forensic.evtx").content_date(crate::plugin::DateField::Created, a, true);
        }
        if used < chunks {
            cx.format_set("records_analysed", tally.parsed);
        }
        if !tally.channels.is_empty() {
            if tally.channels.len() == 1
                && let Some(c) = tally.channels.keys().next()
            {
                cx.content().source("forensic.evtx").title(c.clone());
            }
            cx.format_set("channels", top(tally.channels));
        }
        if !tally.providers.is_empty() {
            cx.format_set("providers", top(tally.providers));
        }
        if !tally.event_ids.is_empty() {
            cx.format_set("event_ids", top(tally.event_ids));
        }
        if !tally.levels.is_empty() {
            cx.format_set("levels", top(tally.levels));
        }
        if !tally.computers.is_empty() {
            cx.format_set("computers", tally.computers.len());
        }
        Ok(())
    }
}

/// EVT: a header, then records of a fixed part and two UTF-16 names.
fn evt(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let len = usize::try_from(src.len().min(cx.parse_limit() as u64)).unwrap_or(0);
    let b = src.read_vec(0, len)?;
    if b.len() < 48 {
        return Err(ExtractError::malformed("EVT header"));
    }
    cx.format_set("version", format!("{}.{}", le(&b[8..12]), le(&b[12..16])));
    let flags = le(&b[36..40]);
    cx.format_set("dirty", flags & 1 != 0);
    cx.format_set("wrapped", flags & 2 != 0);
    let (mut records, mut first, mut last) = (0u64, u64::MAX, 0u64);
    let mut sources: BTreeMap<String, u64> = BTreeMap::new();
    let mut ids: BTreeMap<String, u64> = BTreeMap::new();
    let mut at = 48;
    while at + 56 <= b.len() {
        let size = le_usize(&b[at..at + 4]);
        if &b[at + 4..at + 8] != b"LfLe" || size < 56 || at + size > b.len() {
            // Skip forward to the next record signature (wrapped logs): a
            // record starts four bytes before it, always past this one.
            match b.get(at + 5..).and_then(|r| r.windows(4).position(|w| w == b"LfLe")) {
                Some(p) => {
                    at += 1 + p;
                    continue;
                }
                None => break,
            }
        }
        records += 1;
        let t = le(&b[at + 12..at + 16]);
        first = first.min(t);
        last = last.max(t);
        let id = le(&b[at + 20..at + 24]) & 0xffff;
        let source = utf16z(&b[at + 56..at + size]);
        *sources.entry(source).or_default() += 1;
        *ids.entry(id.to_string()).or_default() += 1;
        at += size;
    }
    cx.format_set("records", records);
    let t = |v: u64| i64::try_from(v).ok().and_then(unix_time);
    if let (Some(a), Some(z)) = (t(first), t(last)) {
        cx.format_set("first_event", a);
        cx.format_set("last_event", z);
    }
    if !sources.is_empty() {
        cx.format_set("sources", top(sources));
        cx.format_set("event_ids", top(ids));
    }
    Ok(())
}

crate::register_extractor!(Evtx);

#[cfg(test)]
mod tests {
    use super::*;

    fn name(off: usize, s: &str) -> Vec<u8> {
        let _ = off;
        let mut v = vec![0, 0, 0, 0, 0, 0];
        v.extend(u16::try_from(s.len()).unwrap().to_le_bytes());
        for u in s.encode_utf16() {
            v.extend(u.to_le_bytes());
        }
        v.extend([0, 0]);
        v
    }

    /// Open an element whose name follows inline.
    fn open(c: &mut Vec<u8>, s: &str, attrs: bool) {
        c.push(if attrs { 0x41 } else { 0x01 });
        c.extend([0, 0, 0, 0, 0, 0]);
        let off = c.len() + 4;
        c.extend(u32::try_from(off).unwrap().to_le_bytes());
        c.extend(name(off, s));
        if attrs {
            c.extend([0, 0, 0, 0]);
        }
    }

    #[test]
    fn template_and_substitutions() {
        // <Event><System><Provider Name=%0/><EventID>%1</EventID>
        // <Channel>Harbour</Channel></System></Event>
        let mut c = vec![0u8; 16];
        let def = c.len();
        c.extend([0u8; 24]);
        let body = c.len();
        c.extend([0x0f, 1, 1, 0]);
        open(&mut c, "Event", false);
        c.push(0x02);
        open(&mut c, "System", false);
        c.push(0x02);
        open(&mut c, "Provider", true);
        c.push(0x06);
        let off = c.len() + 4;
        c.extend(u32::try_from(off).unwrap().to_le_bytes());
        c.extend(name(off, "Name"));
        c.extend([0x0e, 0, 0, 0x01]);
        c.push(0x03);
        open(&mut c, "EventID", false);
        c.push(0x02);
        c.extend([0x0e, 1, 0, 0x06]);
        c.push(0x04);
        open(&mut c, "Channel", false);
        c.push(0x02);
        c.extend([0x05, 0x01, 7, 0]);
        for u in "Harbour".encode_utf16() {
            c.extend(u.to_le_bytes());
        }
        c.extend([0x04, 0x04, 0x04, 0x00]);
        let size = c.len() - body;
        c[def + 20..def + 24].copy_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
        // The record: fragment header, a template instance pointing back.
        let rec = c.len();
        c.extend([0x0f, 1, 1, 0, 0x0c, 1, 0, 0, 0, 0]);
        c.extend(u32::try_from(def).unwrap().to_le_bytes());
        c.extend(2u32.to_le_bytes());
        c.extend([10, 0, 0x01, 0, 2, 0, 0x06, 0]);
        for u in "Gauge".encode_utf16() {
            c.extend(u.to_le_bytes());
        }
        c.extend(4624u16.to_le_bytes());
        let f = record_fields(&c, rec, &mut HashMap::new()).unwrap();
        assert_eq!(f["provider"], "Gauge");
        assert_eq!(f["event_id"], "4624");
        assert_eq!(f["channel"], "Harbour");
    }

    crate::fixture_tests!("evtx", "evt");
}
