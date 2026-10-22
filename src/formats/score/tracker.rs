//! Tracker modules: ProTracker-style MOD (4 to 32 channels), FastTracker 2
//! XM, Scream Tracker 3 S3M, Impulse Tracker IT and OpenMPT MPTM. The title,
//! tracker, channels, orders, patterns, instruments and samples with their
//! names (where composers write their messages), the IT song message, and
//! the duration of one pass through the song: the patterns are walked for
//! the commands that change timing (speed, tempo, position jump, pattern
//! break, pattern loop, pattern delay) until the song ends or loops.
//!
//! Specifications: the ProTracker MOD format, the XM format notes by
//! Mr.H / Triton, the Scream Tracker 3.20 and Impulse Tracker 2.14 technical
//! documents, OpenMPT's notes on its extensions.

use std::collections::HashSet;

use serde_json::{Map, Value, json};

use super::ms;
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source, TextRole,
    truncate_chars,
};

/// Extractor for tracker modules.
pub struct Tracker;

/// ProTracker-family signatures at byte 1080.
const MOD_TAGS: &[Magic] = &[
    Magic::at(1080, b"M.K."),
    Magic::at(1080, b"M!K!"),
    Magic::at(1080, b"M&K!"),
    Magic::at(1080, b"FLT4"),
    Magic::at(1080, b"FLT8"),
    Magic::at(1080, b"4CHN"),
    Magic::at(1080, b"6CHN"),
    Magic::at(1080, b"8CHN"),
    Magic::at(1080, b"CD81"),
    Magic::at(1080, b"OKTA"),
    Magic::at(1080, b"OCTA"),
];

static META: ExtractorMeta = ExtractorMeta {
    id: "score.tracker",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "mod",
            name: "ProTracker module",
            family: "audio.score",
            mimes: &["audio/x-mod"],
            extensions: &["mod"],
            magic: MOD_TAGS,
            parent: None,
        },
        FormatSpec {
            id: "xm",
            name: "FastTracker 2 module",
            family: "audio.score",
            mimes: &["audio/x-xm"],
            extensions: &["xm"],
            magic: &[Magic::prefix(b"Extended Module: ")],
            parent: None,
        },
        FormatSpec {
            id: "s3m",
            name: "Scream Tracker 3 module",
            family: "audio.score",
            mimes: &["audio/x-s3m"],
            extensions: &["s3m"],
            magic: &[Magic::at(44, b"SCRM")],
            parent: None,
        },
        FormatSpec {
            id: "it",
            name: "Impulse Tracker module",
            family: "audio.score",
            mimes: &["audio/x-it"],
            extensions: &["it"],
            magic: &[Magic::prefix(b"IMPM")],
            parent: None,
        },
        FormatSpec {
            id: "mptm",
            name: "OpenMPT module",
            family: "audio.score",
            mimes: &["audio/x-mptm"],
            extensions: &["mptm"],
            magic: &[],
            parent: Some("it"),
        },
    ],
};

/// Rows walked when timing the song.
const MAX_ROWS: u64 = 1 << 20;
/// Names listed.
const MAX_NAMES: usize = 128;

impl Extractor for Tracker {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.starts_with(b"IMPM") && probe.extension.is_some_and(|e| e.eq_ignore_ascii_case("mptm")) {
            return Some(Sniff { format: "mptm", confidence: 0.95 });
        }
        // `xxCH` / `xxCN` (10 to 32 channels) and `TDZx`.
        let tag = h.get(1080..1084)?;
        let digits = tag[..2].iter().all(u8::is_ascii_digit);
        let ok = (digits && (&tag[2..] == b"CH" || &tag[2..] == b"CN"))
            || (&tag[..3] == b"TDZ" && tag[3].is_ascii_digit())
            || (tag[0].is_ascii_digit() && &tag[1..] == b"CHN");
        ok.then_some(Sniff { format: "mod", confidence: 0.85 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (b, _) = cx.read_bytes(src)?;
        let module = match cx.format_id() {
            "xm" => xm(&b),
            "s3m" => s3m(&b),
            "it" | "mptm" => it(&b),
            _ => protracker(&b),
        }
        .ok_or_else(|| ExtractError::malformed("module header"))?;
        cx.checkpoint()?;
        module.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Tracker);

/// A command that changes the timing of the song.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Timing {
    Speed(u8),
    Tempo(u8),
    Jump(u8),
    Break(u8),
    LoopStart,
    Loop(u8),
    Delay(u8),
}

/// One pattern: per row, the timing commands of its channels (`(channel, command)`).
type Pattern = Vec<Vec<(u8, Timing)>>;

#[derive(Default)]
struct Module {
    title: String,
    tracker: Option<String>,
    channels: u32,
    /// Order list: pattern numbers; `None` skips (`+++`), and the list ends
    /// at the first end marker.
    orders: Vec<Option<usize>>,
    patterns: Vec<Pattern>,
    declared_patterns: usize,
    instruments: Vec<String>,
    samples: Vec<String>,
    speed: u8,
    tempo: u8,
    message: Option<String>,
    flags: Vec<&'static str>,
    extra: Map<String, Value>,
}

/// Text in a fixed-width field: up to the first NUL, Latin-1, trimmed.
fn field(d: &[u8]) -> String {
    let end = d.iter().position(|&b| b == 0).unwrap_or(d.len());
    d[..end].iter().map(|&b| char::from(b)).collect::<String>().trim().to_string()
}

fn le16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(at)?, *d.get(at + 1)?]))
}

fn le32(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

/// A BCD-style row number (`D32` breaks to row 32).
fn bcd(p: u8) -> u8 {
    (p >> 4) * 10 + (p & 0x0f)
}

/// MOD / XM effect `kind` with parameter `p`.
fn protracker_timing(kind: u8, p: u8, xm: bool) -> Option<Timing> {
    Some(match kind {
        0x0b => Timing::Jump(p),
        0x0d => Timing::Break(bcd(p)),
        0x0e if p >> 4 == 6 => {
            if p.trailing_zeros() >= 4 {
                Timing::LoopStart
            } else {
                Timing::Loop(p & 0x0f)
            }
        }
        0x0e if p >> 4 == 0x0e => Timing::Delay(p & 0x0f),
        0x0f if p == 0 => return None,
        0x0f if p < 32 => Timing::Speed(p),
        0x0f if xm || p >= 32 => Timing::Tempo(p),
        _ => return None,
    })
}

/// S3M / IT command letter (`A` = 1) with parameter `p`.
fn scream_timing(cmd: u8, p: u8, it: bool) -> Option<Timing> {
    Some(match cmd {
        1 if p > 0 => Timing::Speed(p),
        2 => Timing::Jump(p),
        3 => Timing::Break(if it { p } else { bcd(p) }),
        19 if p >> 4 == 0x0b => {
            if p.trailing_zeros() >= 4 {
                Timing::LoopStart
            } else {
                Timing::Loop(p & 0x0f)
            }
        }
        19 if p >> 4 == 0x0e => Timing::Delay(p & 0x0f),
        20 if p >= 0x20 => Timing::Tempo(p),
        _ => return None,
    })
}

fn protracker(b: &[u8]) -> Option<Module> {
    let tag = b.get(1080..1084)?;
    let channels: u32 = match tag {
        b"M.K." | b"M!K!" | b"M&K!" | b"FLT4" | b"4CHN" => 4,
        b"6CHN" => 6,
        b"8CHN" | b"FLT8" | b"CD81" | b"OKTA" | b"OCTA" => 8,
        t if &t[..3] == b"TDZ" => u32::from(t[3] - b'0'),
        t if &t[1..] == b"CHN" => u32::from(t[0] - b'0'),
        t => std::str::from_utf8(&t[..2]).ok()?.parse().ok()?,
    };
    if !(1..=32).contains(&channels) {
        return None;
    }
    let mut m = Module { title: field(&b[..20]), channels, speed: 6, tempo: 125, ..Module::default() };
    m.extra.insert("signature".into(), json!(String::from_utf8_lossy(tag)));
    for i in 0..31 {
        m.samples.push(field(&b[20 + i * 30..42 + i * 30]));
    }
    let length = usize::from(b[950]).min(128);
    let table = &b[952..1080];
    let patterns = usize::from(table.iter().copied().max().unwrap_or(0)) + 1;
    m.declared_patterns = patterns;
    m.orders = table[..length].iter().map(|&p| Some(usize::from(p))).collect();
    let row_bytes = 4 * channels as usize;
    for p in 0..patterns {
        let at = 1084 + p * 64 * row_bytes;
        let Some(data) = b.get(at..at + 64 * row_bytes) else { break };
        let rows = data
            .chunks_exact(row_bytes)
            .map(|row| {
                row.as_chunks::<4>()
                    .0
                    .iter()
                    .enumerate()
                    .filter_map(|(c, cell)| {
                        let t = protracker_timing(cell[2] & 0x0f, cell[3], false)?;
                        Some((u8::try_from(c).ok()?, t))
                    })
                    .collect()
            })
            .collect();
        m.patterns.push(rows);
    }
    m.tracker = Some(if tag == b"M.K." || tag == b"M!K!" { "ProTracker" } else { "unknown" }.to_string())
        .filter(|t| t != "unknown");
    Some(m)
}

#[allow(clippy::too_many_lines)] // header, patterns, instruments
fn xm(b: &[u8]) -> Option<Module> {
    if b.len() < 80 || &b[..17] != b"Extended Module: " {
        return None;
    }
    let header = le32(b, 60)? as usize;
    let (length, channels, npat, nins) =
        (usize::from(le16(b, 64)?), le16(b, 68)?, usize::from(le16(b, 70)?), usize::from(le16(b, 72)?));
    let flags = le16(b, 74)?;
    let mut m = Module {
        title: field(&b[17..37]),
        tracker: Some(field(&b[38..58])).filter(|t| !t.is_empty()),
        channels: u32::from(channels),
        speed: u8::try_from(le16(b, 76)?).unwrap_or(6),
        tempo: u8::try_from(le16(b, 78)?).unwrap_or(125),
        declared_patterns: npat,
        ..Module::default()
    };
    let version = le16(b, 58)?;
    m.extra.insert("format_version".into(), json!(format!("{}.{:02x}", version >> 8, version & 0xff)));
    if flags & 1 != 0 {
        m.flags.push("linear_frequencies");
    }
    m.orders = b.get(80..80 + length.min(256))?.iter().map(|&p| Some(usize::from(p))).collect();
    let mut at = 60usize.checked_add(header)?;
    for _ in 0..npat.min(256) {
        let hl = le32(b, at)? as usize;
        let rows = usize::from(le16(b, at + 5)?);
        let packed = usize::from(le16(b, at + 7)?);
        let data = b.get(at + hl..(at + hl).saturating_add(packed).min(b.len()))?;
        at = at.saturating_add(hl).saturating_add(packed);
        let mut pattern: Pattern = vec![Vec::new(); rows];
        let (mut i, mut cell) = (0usize, 0usize);
        let ch = usize::from(channels.max(1));
        while i < data.len() && cell < rows * ch {
            let first = data[i];
            let (mut kind, mut param) = (0u8, 0u8);
            if first & 0x80 != 0 {
                i += 1;
                for bit in 0..5 {
                    if first & (1 << bit) != 0 {
                        let v = data.get(i).copied().unwrap_or(0);
                        i += 1;
                        match bit {
                            3 => kind = v,
                            4 => param = v,
                            _ => {}
                        }
                    }
                }
            } else {
                kind = data.get(i + 3).copied().unwrap_or(0);
                param = data.get(i + 4).copied().unwrap_or(0);
                i += 5;
            }
            if let Some(t) = protracker_timing(kind, param, true) {
                pattern[cell / ch].push((u8::try_from(cell % ch).unwrap_or(0), t));
            }
            cell += 1;
        }
        m.patterns.push(pattern);
    }
    for _ in 0..nins.min(256) {
        let size = le32(b, at)? as usize;
        let Some(name) = b.get(at + 4..at + 26) else { break };
        m.instruments.push(field(name));
        let nsamples = usize::from(le16(b, at + 27).unwrap_or(0));
        let sample_header = if nsamples > 0 { le32(b, at + 29).unwrap_or(40) as usize } else { 0 };
        at = at.checked_add(size.max(4))?;
        let mut data = 0usize;
        for s in 0..nsamples.min(64) {
            let h = at + s * sample_header;
            data = data.saturating_add(le32(b, h).unwrap_or(0) as usize);
            if let Some(n) = b.get(h + 18..h + 40) {
                m.samples.push(field(n));
            }
        }
        at = at.saturating_add(nsamples * sample_header).saturating_add(data);
    }
    Some(m)
}

/// Text of an IT / S3M parapointer target.
fn s3m(b: &[u8]) -> Option<Module> {
    if b.get(44..48)? != b"SCRM" {
        return None;
    }
    let (ordnum, insnum, patnum) = (usize::from(le16(b, 32)?), usize::from(le16(b, 34)?), usize::from(le16(b, 36)?));
    let cwt = le16(b, 40)?;
    let channels = b.get(64..96)?.iter().filter(|&&c| c < 16).count();
    let mut m = Module {
        title: field(&b[..28]),
        tracker: Some(tracker_name(cwt, false)),
        channels: u32::try_from(channels).unwrap_or(0),
        speed: b[49],
        tempo: b[50],
        declared_patterns: patnum,
        ..Module::default()
    };
    let orders = b.get(96..96 + ordnum)?;
    m.orders = orders.iter().take_while(|&&o| o != 255).map(|&o| (o != 254).then_some(usize::from(o))).collect();
    let pointers = 96 + ordnum;
    for i in 0..insnum.min(256) {
        let at = usize::from(le16(b, pointers + i * 2)?) * 16;
        if let Some(n) = b.get(at + 48..at + 76) {
            m.instruments.push(field(n));
        }
    }
    for p in 0..patnum.min(256) {
        let at = usize::from(le16(b, pointers + insnum * 2 + p * 2)?) * 16;
        let mut pattern: Pattern = vec![Vec::new(); 64];
        if at > 0 {
            let len = usize::from(le16(b, at).unwrap_or(0));
            let data = b.get(at + 2..(at + 2 + len).min(b.len())).unwrap_or_default();
            let (mut i, mut row) = (0usize, 0usize);
            while i < data.len() && row < 64 {
                let what = data[i];
                i += 1;
                if what == 0 {
                    row += 1;
                    continue;
                }
                if what & 0x20 != 0 {
                    i += 2;
                }
                if what & 0x40 != 0 {
                    i += 1;
                }
                if what & 0x80 != 0 {
                    let (cmd, p) = (data.get(i).copied().unwrap_or(0), data.get(i + 1).copied().unwrap_or(0));
                    i += 2;
                    if let Some(t) = scream_timing(cmd, p, false) {
                        pattern[row].push((what & 31, t));
                    }
                }
            }
        }
        m.patterns.push(pattern);
    }
    if b[51] & 0x80 != 0 {
        m.flags.push("stereo");
    }
    Some(m)
}

/// The tracker that wrote an S3M or IT file, from its `Cwt/v` field.
fn tracker_name(cwt: u16, it: bool) -> String {
    let (major, minor) = ((cwt >> 8) & 0x0f, cwt & 0xff);
    if it {
        return match cwt >> 12 {
            0 if cwt == 0x0888 || cwt == 0x0889 => "OpenMPT".to_string(),
            0 => format!("Impulse Tracker {major}.{minor:02x}"),
            1 => "Schism Tracker".to_string(),
            5 => "OpenMPT".to_string(),
            _ => format!("unknown (0x{cwt:04x})"),
        };
    }
    match cwt >> 12 {
        1 => format!("Scream Tracker {major}.{minor:02x}"),
        2 => "Imago Orpheus".to_string(),
        3 => "Impulse Tracker".to_string(),
        4 => "Schism Tracker".to_string(),
        5 => "OpenMPT".to_string(),
        6 => "BeRoTracker".to_string(),
        7 => "CreamTracker".to_string(),
        _ => format!("unknown (0x{cwt:04x})"),
    }
}

// The bytes `b` and module `m` stay in scope; `cwt` / `cmwt` are the IT
// field names.
#[allow(clippy::too_many_lines, clippy::many_single_char_names, clippy::similar_names)] // header, message, names, patterns
fn it(b: &[u8]) -> Option<Module> {
    if b.get(..4)? != b"IMPM" {
        return None;
    }
    let (ordnum, insnum, smpnum, patnum) =
        (usize::from(le16(b, 32)?), usize::from(le16(b, 34)?), usize::from(le16(b, 36)?), usize::from(le16(b, 38)?));
    let (cwt, cmwt, flags, special) = (le16(b, 40)?, le16(b, 42)?, le16(b, 44)?, le16(b, 46)?);
    let channels = b.get(64..128)?.iter().filter(|&&p| p < 128).count();
    let mut m = Module {
        title: field(&b[4..30]),
        tracker: Some(tracker_name(cwt, true)),
        channels: u32::try_from(channels).unwrap_or(0),
        speed: *b.get(50)?,
        tempo: *b.get(51)?,
        declared_patterns: patnum,
        ..Module::default()
    };
    m.extra.insert("compatible_with".into(), json!(format!("{}.{:02x}", cmwt >> 8, cmwt & 0xff)));
    for (bit, name) in [(0x04, "instruments"), (0x08, "linear_slides"), (0x10, "old_effects")] {
        if flags & bit != 0 {
            m.flags.push(name);
        }
    }
    if special & 1 != 0 {
        let len = usize::from(le16(b, 54)?);
        let at = le32(b, 56)? as usize;
        if let Some(msg) = b.get(at..at.saturating_add(len).min(b.len())) {
            let text = field(msg).replace('\r', "\n");
            m.message = Some(text).filter(|t| !t.trim().is_empty());
        }
    }
    let orders = b.get(192..192 + ordnum)?;
    m.orders = orders.iter().take_while(|&&o| o != 255).map(|&o| (o != 254).then_some(usize::from(o))).collect();
    let base = 192 + ordnum;
    for i in 0..insnum.min(256) {
        let at = le32(b, base + i * 4)? as usize;
        if b.get(at..at + 4) == Some(b"IMPI")
            && let Some(n) = b.get(at + 32..at + 58)
        {
            m.instruments.push(field(n));
        }
    }
    for i in 0..smpnum.min(256) {
        let at = le32(b, base + insnum * 4 + i * 4)? as usize;
        if b.get(at..at + 4) == Some(b"IMPS")
            && let Some(n) = b.get(at + 20..at + 46)
        {
            m.samples.push(field(n));
        }
    }
    for p in 0..patnum.min(256) {
        let at = le32(b, base + (insnum + smpnum) * 4 + p * 4)? as usize;
        if at == 0 {
            m.patterns.push(vec![Vec::new(); 64]);
            continue;
        }
        let (len, rows) = (usize::from(le16(b, at).unwrap_or(0)), usize::from(le16(b, at + 2).unwrap_or(64)));
        let data = b.get(at + 8..(at + 8 + len).min(b.len())).unwrap_or_default();
        let mut pattern: Pattern = vec![Vec::new(); rows.min(200)];
        let (mut masks, mut last_cmd) = ([0u8; 64], [(0u8, 0u8); 64]);
        let (mut i, mut row) = (0usize, 0usize);
        while i < data.len() && row < pattern.len() {
            let v = data[i];
            i += 1;
            if v == 0 {
                row += 1;
                continue;
            }
            let ch = usize::from((v - 1) & 63);
            if v & 0x80 != 0 {
                masks[ch] = data.get(i).copied().unwrap_or(0);
                i += 1;
            }
            let mask = masks[ch];
            for (bit, n) in [(1u8, 1usize), (2, 1), (4, 1)] {
                if mask & bit != 0 {
                    i += n;
                }
            }
            let mut cmd = None;
            if mask & 8 != 0 {
                let c = (data.get(i).copied().unwrap_or(0), data.get(i + 1).copied().unwrap_or(0));
                i += 2;
                last_cmd[ch] = c;
                cmd = Some(c);
            } else if mask & 128 != 0 {
                cmd = Some(last_cmd[ch]);
            }
            if let Some((c, p)) = cmd
                && let Some(t) = scream_timing(c, p, true)
            {
                pattern[row].push((u8::try_from(ch).unwrap_or(0), t));
            }
        }
        m.patterns.push(pattern);
    }
    Some(m)
}

impl Module {
    /// The length of one pass through the song, in seconds, and whether the
    /// song loops back (a jump to a position already played).
    fn duration(&self) -> (f64, bool) {
        let (mut speed, mut tempo) = (if self.speed == 0 { 6 } else { self.speed }, self.tempo.max(32));
        let (mut order, mut row, mut secs, mut rows) = (0usize, 0usize, 0.0f64, 0u64);
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        // Pattern loops: per channel, the start row and the repeats left.
        let mut loop_start = [0usize; 64];
        let mut loop_left = [0u8; 64];
        loop {
            rows += 1;
            if rows > MAX_ROWS {
                return (secs, false);
            }
            let Some(slot) = self.orders.get(order) else { return (secs, false) };
            let Some(p) = slot else {
                order += 1;
                row = 0;
                continue;
            };
            let Some(pattern) = self.patterns.get(*p) else {
                // A missing pattern plays as 64 empty rows.
                secs += 64.0 * f64::from(speed) * 2.5 / f64::from(tempo);
                order += 1;
                row = 0;
                continue;
            };
            if row >= pattern.len() {
                order += 1;
                row = 0;
                continue;
            }
            let looping = loop_left.iter().any(|&n| n > 0);
            if !looping && !seen.insert((order, row)) {
                return (secs, true);
            }
            let (mut jump, mut brk, mut delay, mut back) = (None, None, 0u8, None);
            for &(ch, t) in &pattern[row] {
                let c = usize::from(ch) & 63;
                match t {
                    Timing::Speed(s) => speed = s,
                    Timing::Tempo(t) => tempo = t.max(32),
                    Timing::Jump(o) => jump = Some(usize::from(o)),
                    Timing::Break(r) => brk = Some(usize::from(r)),
                    Timing::Delay(d) => delay = delay.max(d),
                    Timing::LoopStart => loop_start[c] = row,
                    Timing::Loop(n) => {
                        if loop_left[c] == 0 {
                            loop_left[c] = n;
                            back = Some(loop_start[c]);
                        } else {
                            loop_left[c] -= 1;
                            if loop_left[c] > 0 {
                                back = Some(loop_start[c]);
                            } else {
                                loop_start[c] = row + 1;
                            }
                        }
                    }
                }
            }
            secs += f64::from(speed) * f64::from(1 + delay) * 2.5 / f64::from(tempo);
            if let Some(r) = back {
                row = r;
            } else if let Some(o) = jump {
                if o <= order && brk.is_none() && seen.contains(&(o, 0)) {
                    return (secs, true);
                }
                order = o;
                row = brk.unwrap_or(0);
                loop_start = [0; 64];
            } else if let Some(r) = brk {
                order += 1;
                row = r;
                loop_start = [0; 64];
            } else {
                row += 1;
            }
        }
    }

    fn report(self, cx: &mut Context<'_>) {
        let (secs, loops) = self.duration();
        if secs > 0.0 && secs.is_finite() {
            cx.physical().duration_s(ms(secs));
        }
        if !self.title.is_empty() {
            cx.content().source("module.title").title(truncate_chars(&self.title, 200));
            cx.emit_text(TextRole::Title, &self.title);
        }
        // Instrument and sample names are where composers leave messages.
        let names: Vec<&String> = self.instruments.iter().chain(&self.samples).filter(|n| !n.is_empty()).collect();
        let mut text: String = names.iter().flat_map(|n| [n.as_str(), "\n"]).collect();
        if let Some(msg) = &self.message {
            text.push_str(msg);
        }
        if !text.trim().is_empty() {
            cx.emit_text(TextRole::Comment, &text);
        }
        let mut f = Map::new();
        let mut put = |k: &str, v: Value| {
            if !v.is_null() && v != json!([]) {
                f.insert(k.into(), v);
            }
        };
        put("tracker", json!(self.tracker));
        put("channels", json!(self.channels));
        put("orders", json!(self.orders.len()));
        put("patterns", json!(self.declared_patterns));
        put("instruments", json!(self.instruments.len()));
        put("samples", json!(self.samples.len()));
        put("initial_speed", json!(self.speed));
        put("initial_tempo_bpm", json!(self.tempo));
        put("flags", json!(self.flags));
        if loops {
            put("loops", json!(true));
        }
        let listed = |v: &[String]| -> Vec<String> {
            v.iter().filter(|n| !n.is_empty()).take(MAX_NAMES).map(|n| truncate_chars(n, 40)).collect()
        };
        put("instrument_names", json!(listed(&self.instruments)));
        put("sample_names", json!(listed(&self.samples)));
        put("message", json!(self.message.as_deref().map(|m| truncate_chars(m, 4000))));
        let mut extra = self.extra;
        f.append(&mut extra);
        cx.format().append(&mut f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("mod", "xm", "s3m", "it", "mptm");

    fn row(cmds: &[(u8, Timing)]) -> Vec<(u8, Timing)> {
        cmds.to_vec()
    }

    #[test]
    fn timing_walk() {
        // Two 4-row patterns at speed 6, 125 bpm: 0.12 s a row.
        let mut m = Module { speed: 6, tempo: 125, orders: vec![Some(0), Some(1)], ..Module::default() };
        m.patterns = vec![vec![row(&[]); 4], vec![row(&[]); 4]];
        assert_eq!(m.duration(), (8.0 * 0.12, false));
        // A loop of the second row twice more, then a break to row 2 of the
        // next pattern, which jumps back to the start: the song loops.
        m.patterns[0][0] = row(&[(0, Timing::LoopStart)]);
        m.patterns[0][1] = row(&[(0, Timing::Loop(2))]);
        m.patterns[0][3] = row(&[(1, Timing::Break(2)), (2, Timing::Speed(3))]);
        m.patterns[1][3] = row(&[(0, Timing::Jump(0))]);
        let (secs, loops) = m.duration();
        // Rows 0 and 1 play three times and row 2 once at 0.12 s; row 3 sets
        // speed 3 for itself (0.06 s) and rows 2 and 3 of pattern 1.
        assert!((secs - (7.0 * 0.12 + 3.0 * 0.06)).abs() < 1e-9, "{secs}");
        assert!(loops);
        // A pattern delay of 3 plays its row four times.
        m.patterns[1][2] = row(&[(0, Timing::Delay(3))]);
        assert!((m.duration().0 - (7.0 * 0.12 + 0.06 + 4.0 * 0.06 + 0.06)).abs() < 1e-9);
    }

    #[test]
    fn commands() {
        assert_eq!(protracker_timing(0x0f, 0x7d, false), Some(Timing::Tempo(125)));
        assert_eq!(protracker_timing(0x0f, 0x06, false), Some(Timing::Speed(6)));
        assert_eq!(protracker_timing(0x0d, 0x32, false), Some(Timing::Break(32)));
        assert_eq!(protracker_timing(0x0e, 0x63, false), Some(Timing::Loop(3)));
        assert_eq!(scream_timing(3, 0x20, true), Some(Timing::Break(32)));
        assert_eq!(scream_timing(3, 0x20, false), Some(Timing::Break(20)));
        assert_eq!(scream_timing(20, 0x10, true), None);
        assert_eq!(tracker_name(0x1320, false), "Scream Tracker 3.20");
        assert_eq!(tracker_name(0x0214, true), "Impulse Tracker 2.14");
        assert_eq!(field(b"Harbour\0junk"), "Harbour");
    }
}
