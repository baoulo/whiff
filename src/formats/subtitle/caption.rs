//! Broadcast captions: Scenarist SCC (CEA-608 byte pairs, decoded to text
//! for channel 1 with pop-on, roll-up and paint-on captions) and EBU STL
//! (Tech 3264: the GSI block's titles, language, dates, frame rate and
//! counts, and the TTI blocks' cues in ISO 6937 or ISO 8859 text).
//!
//! Specifications: CTA-608-E, EBU Tech 3264-E.

use super::{Cue, Subtitles, head_text, language_code, plain_text};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
};

/// Extractor for SCC and EBU STL captions.
pub struct Caption;

static META: ExtractorMeta = ExtractorMeta {
    id: "subtitle.caption",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "scc",
            name: "Scenarist closed captions",
            family: "text.subtitle",
            mimes: &["text/x-scc"],
            extensions: &["scc"],
            magic: &[Magic::prefix(b"Scenarist_SCC V1.0"), Magic::prefix(b"\xEF\xBB\xBFScenarist_SCC V1.0")],
            parent: None,
        },
        FormatSpec {
            id: "ebu_stl",
            name: "EBU STL subtitles",
            family: "text.subtitle",
            mimes: &["application/x-ebu-stl"],
            extensions: &["stl"],
            magic: &[Magic::at(3, b"STL25.01"), Magic::at(3, b"STL30.01")],
            parent: None,
        },
    ],
};

impl Extractor for Caption {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // Other frame rates than the two the specification names.
        let h = probe.head;
        let stl =
            h.len() >= 1024 && &h[3..6] == b"STL" && h[6..8].iter().all(u8::is_ascii_digit) && &h[8..11] == b".01";
        if stl {
            return Some(Sniff { format: "ebu_stl", confidence: 0.9 });
        }
        head_text(&h[..h.len().min(64)])
            .starts_with("Scenarist_SCC")
            .then_some(Sniff { format: "scc", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let subs = if cx.format_id() == "scc" {
            let text = cx.read_text(src)?.text;
            scc(&text)
        } else {
            let (bytes, _) = cx.read_bytes(src)?;
            stl(&bytes, cx)?
        };
        cx.checkpoint()?;
        if subs.cues.is_empty() {
            cx.warn("no captions found");
        }
        subs.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Caption);

// --- SCC / CEA-608 ---------------------------------------------------------

/// Seconds per frame at 29.97 frames per second.
const FRAME: f64 = 1001.0 / 30_000.0;

/// `HH:MM:SS:FF` or `HH:MM:SS;FF` (drop frame) as seconds.
fn timecode(tc: &str) -> Option<(f64, bool)> {
    let drop = tc.contains(';');
    let parts: Vec<u32> = tc.split([':', ';', '.']).map(|p| p.parse().ok()).collect::<Option<_>>()?;
    let [h, m, s, f] = parts[..] else { return None };
    (m < 60 && s < 60 && f < 60).then(|| (f64::from(h * 3600 + m * 60 + s) + f64::from(f) * FRAME, drop))
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    PopOn,
    RollUp,
    PaintOn,
}

/// CEA-608 channel 1 state.
struct Decoder {
    mode: Mode,
    /// Pop-on text being loaded.
    hidden: String,
    /// Text on screen and when it appeared.
    shown: Option<(f64, String)>,
    /// The roll-up / paint-on row being written and when it started.
    row: Option<(f64, String)>,
    /// Data channel of the last control code (1 or 2).
    channel: u8,
    last_control: Option<u16>,
    cues: Vec<Cue>,
    channel2: bool,
    modes: std::collections::BTreeSet<&'static str>,
}

impl Decoder {
    /// Where characters go: pop-on memory, or the row being written (begun at `t`).
    fn target(&mut self, t: f64) -> &mut String {
        match self.mode {
            Mode::PopOn => &mut self.hidden,
            _ => &mut self.row.get_or_insert_with(|| (t, String::new())).1,
        }
    }

    fn put(&mut self, t: f64, s: &str) {
        if self.channel != 1 {
            self.channel2 = true;
            return;
        }
        self.target(t).push_str(s);
    }

    /// Show text from `start`, ending what was on screen.
    fn show(&mut self, t: f64, text: String) {
        self.clear(t);
        if !text.trim().is_empty() {
            self.shown = Some((t, text));
        }
    }

    fn clear(&mut self, t: f64) {
        if let Some((start, text)) = self.shown.take() {
            self.cues.push(Cue { start, end: Some(t.max(start)), text, speaker: None });
        }
    }

    /// The roll-up or paint-on row is complete.
    fn commit_row(&mut self) {
        if let Some((start, text)) = self.row.take()
            && !text.trim().is_empty()
        {
            self.clear(start);
            self.shown = Some((start, text));
        }
    }

    fn control(&mut self, t: f64, a: u8, b: u8) {
        let code = u16::from(a) << 8 | u16::from(b);
        // Control codes are sent twice; the repeat is ignored.
        if self.last_control == Some(code) {
            self.last_control = None;
            return;
        }
        self.last_control = Some(code);
        self.channel = if a & 0x08 == 0 { 1 } else { 2 };
        if self.channel != 1 {
            self.channel2 = true;
            return;
        }
        let a = a & 0xf7;
        match (a, b) {
            (0x14 | 0x15, 0x20) => {
                self.mode = Mode::PopOn;
                self.modes.insert("pop_on");
            }
            (0x14 | 0x15, 0x25..=0x27) => {
                self.mode = Mode::RollUp;
                self.modes.insert("roll_up");
            }
            (0x14 | 0x15, 0x29) => {
                self.mode = Mode::PaintOn;
                self.modes.insert("paint_on");
            }
            (0x14 | 0x15, 0x21) => {
                self.target(t).pop();
            }
            (0x14 | 0x15, 0x2c) => {
                self.commit_row();
                self.clear(t);
            }
            (0x14 | 0x15, 0x2d) => {
                if self.mode == Mode::PopOn {
                    self.hidden.push('\n');
                } else {
                    self.commit_row();
                }
            }
            (0x14 | 0x15, 0x2e) => self.hidden.clear(),
            (0x14 | 0x15, 0x2f) => {
                let text = std::mem::take(&mut self.hidden);
                self.show(t, text);
            }
            // Preamble address code: a new row.
            (0x10..=0x17, 0x40..=0x7f) => {
                if self.mode == Mode::PopOn || self.row.is_some() {
                    let target = self.target(t);
                    if !target.is_empty() && !target.ends_with('\n') {
                        target.push('\n');
                    }
                }
            }
            // Mid-row codes and tab offsets: shown as a space.
            (0x11, 0x20..=0x2f) | (0x17, 0x21..=0x23) => self.put(t, " "),
            (0x11, 0x30..=0x3f) => self.put(t, SPECIAL[usize::from(b - 0x30)]),
            (0x12 | 0x13, 0x20..=0x3f) => {
                // Extended characters replace the standard one sent before them.
                self.target(t).pop();
                let table = if a == 0x12 { &EXTENDED_12 } else { &EXTENDED_13 };
                self.put(t, table[usize::from(b - 0x20)]);
            }
            _ => {}
        }
    }
}

const SPECIAL: [&str; 16] = ["®", "°", "½", "¿", "™", "¢", "£", "♪", "à", " ", "è", "â", "ê", "î", "ô", "û"];
const EXTENDED_12: [&str; 32] = [
    "Á", "É", "Ó", "Ú", "Ü", "ü", "‘", "¡", "*", "'", "—", "©", "℠", "•", "“", "”", "À", "Â", "Ç", "È", "Ê", "Ë", "ë",
    "Î", "Ï", "ï", "Ô", "Ù", "ù", "Û", "«", "»",
];
const EXTENDED_13: [&str; 32] = [
    "Ã", "ã", "Í", "Ì", "ì", "Ò", "ò", "Õ", "õ", "{", "}", "\\", "^", "_", "|", "~", "Ä", "ä", "Ö", "ö", "ß", "¥", "¤",
    "¦", "Å", "å", "Ø", "ø", "┌", "┐", "└", "┘",
];

/// A CEA-608 basic character (parity already removed).
fn basic(c: u8) -> Option<char> {
    Some(match c {
        0x2a => 'á',
        0x5c => 'é',
        0x5e => 'í',
        0x5f => 'ó',
        0x60 => 'ú',
        0x7b => 'ç',
        0x7c => '÷',
        0x7d => 'Ñ',
        0x7e => 'ñ',
        0x7f => '█',
        0x20..=0x7e => char::from(c),
        _ => return None,
    })
}

fn scc(text: &str) -> Subtitles {
    let mut subs = Subtitles::new("eia_608");
    let mut dec = Decoder {
        mode: Mode::PopOn,
        hidden: String::new(),
        shown: None,
        row: None,
        channel: 1,
        last_control: None,
        cues: Vec::new(),
        channel2: false,
        modes: std::collections::BTreeSet::new(),
    };
    let (mut lines, mut drop, mut last) = (0u64, false, 0.0f64);
    for line in text.lines().skip(1) {
        let Some((tc, data)) = line.split_once(char::is_whitespace) else { continue };
        let Some((t0, df)) = timecode(tc.trim()) else { continue };
        lines += 1;
        drop |= df;
        for (index, word) in data.split_whitespace().enumerate() {
            let Ok(pair) = u16::from_str_radix(word, 16) else { continue };
            let t = t0 + index as f64 * FRAME;
            last = last.max(t);
            #[allow(clippy::cast_possible_truncation)] // the two bytes of a word
            let (a, b) = (((pair >> 8) as u8) & 0x7f, (pair as u8) & 0x7f);
            if a == 0 && b == 0 {
                continue;
            }
            if (0x10..=0x1f).contains(&a) {
                dec.control(t, a, b);
                continue;
            }
            dec.last_control = None;
            for c in [a, b] {
                if let Some(ch) = basic(c) {
                    dec.put(t, ch.encode_utf8(&mut [0; 4]));
                }
            }
        }
    }
    dec.commit_row();
    dec.clear(last + FRAME);
    let mut markup = std::collections::BTreeSet::new();
    for c in std::mem::take(&mut dec.cues) {
        let text = plain_text(&c.text, &mut markup);
        subs.push(Cue { text, ..c });
    }
    subs.frame_rate = Some(30_000.0 / 1001.0);
    subs.set("timecode_lines", lines);
    subs.set("drop_frame", drop);
    subs.set("caption_modes", dec.modes.into_iter().collect::<Vec<_>>());
    if dec.channel2 {
        subs.set("channel_2", true);
    }
    subs
}

// --- EBU STL -----------------------------------------------------------------

/// GSI block length and TTI block length.
const GSI: usize = 1024;
const TTI: usize = 128;

/// EBU Tech 3264 language codes (Appendix 3) as ISO 639-1.
fn ebu_language(code: &str) -> Option<&'static str> {
    Some(match u8::from_str_radix(code.trim(), 16).ok()? {
        0x01 => "sq",
        0x02 => "br",
        0x03 => "ca",
        0x04 => "hr",
        0x05 => "cy",
        0x06 => "cs",
        0x07 => "da",
        0x08 => "de",
        0x09 => "en",
        0x0a => "es",
        0x0b => "eo",
        0x0c => "et",
        0x0d => "eu",
        0x0e => "fo",
        0x0f => "fr",
        0x10 => "fy",
        0x11 => "ga",
        0x12 => "gd",
        0x13 => "gl",
        0x14 => "is",
        0x15 => "it",
        0x16 => "se",
        0x17 => "la",
        0x18 => "lv",
        0x19 => "lb",
        0x1a => "lt",
        0x1b => "hu",
        0x1c => "mt",
        0x1d | 0x2a => "nl",
        0x1e => "no",
        0x1f => "oc",
        0x20 => "pl",
        0x21 => "pt",
        0x22 => "ro",
        0x23 => "rm",
        0x24 => "sr",
        0x25 => "sk",
        0x26 => "sl",
        0x27 => "fi",
        0x28 => "sv",
        0x29 => "tr",
        0x2b => "wa",
        0x45 => "zu",
        0x46 => "vi",
        0x47 => "uz",
        0x48 => "ur",
        0x49 => "uk",
        0x4a => "th",
        0x4b => "te",
        0x4c => "tt",
        0x4d => "ta",
        0x4e => "tg",
        0x4f => "sw",
        0x51 => "so",
        0x52 => "si",
        0x53 => "sn",
        0x56 => "ru",
        0x57 => "qu",
        0x58 => "ps",
        0x59 => "pa",
        0x5a => "fa",
        0x5c => "or",
        0x5d => "ne",
        0x5f => "mr",
        0x61 => "ms",
        0x62 => "mg",
        0x63 => "mk",
        0x64 => "lo",
        0x65 => "ko",
        0x66 => "km",
        0x67 => "kk",
        0x68 => "kn",
        0x69 => "ja",
        0x6a => "id",
        0x6b => "hi",
        0x6c => "he",
        0x6d => "ha",
        0x6e => "gn",
        0x6f => "gu",
        0x70 => "el",
        0x71 => "ka",
        0x72 => "ff",
        0x75 => "zh",
        0x76 => "my",
        0x77 => "bg",
        0x78 => "bn",
        0x79 => "be",
        0x7a => "bm",
        0x7b => "az",
        0x7c => "as",
        0x7d => "hy",
        0x7e => "ar",
        0x7f => "am",
        _ => return None,
    })
}

/// A GSI text field: ASCII with any other byte read as Windows-1252, trimmed.
fn gsi_text(b: &[u8]) -> Option<String> {
    let (t, _, _) = encoding_rs::WINDOWS_1252.decode(b);
    let t = t.trim_matches(|c: char| c.is_whitespace() || c == '\0').to_string();
    (!t.is_empty()).then_some(t)
}

/// Text of a TTI block's text field. `table` is the GSI character code
/// table: `00` ISO 6937 Latin, `01`–`04` ISO 8859-5 / 6 / 7 / 8.
fn tti_text(tf: &[u8], table: &str, markup: &mut std::collections::BTreeSet<&'static str>) -> String {
    let high: Option<&'static encoding_rs::Encoding> = match table {
        "01" => Some(encoding_rs::ISO_8859_5),
        "02" => Some(encoding_rs::ISO_8859_6),
        "03" => Some(encoding_rs::ISO_8859_7),
        "04" => Some(encoding_rs::ISO_8859_8),
        _ => None,
    };
    let mut out = String::new();
    let mut accent: Option<u8> = None;
    for &c in tf {
        match c {
            0x8f => break,
            0x8a => out.push('\n'),
            0x80 | 0x81 => {
                markup.insert("italic");
            }
            0x82 | 0x83 => {
                markup.insert("underline");
            }
            // Teletext spacing attributes (colours, size, boxing) show as spaces.
            0x00..=0x1f => {
                if c <= 0x07 {
                    markup.insert("colour");
                }
                out.push(' ');
            }
            0x20..=0x7e => {
                let ch = char::from(c);
                match accent.take() {
                    Some(a) => out.push_str(&compose(a, ch)),
                    None => out.push(ch),
                }
            }
            0xa0..=0xff if high.is_some() => {
                if let Some(enc) = high {
                    out.push_str(&enc.decode_without_bom_handling(&[c]).0);
                }
            }
            0xc1..=0xcf => accent = Some(c),
            0xa0..=0xff => out.push(iso6937_g2(c)),
            _ => {}
        }
    }
    out
}

/// ISO 6937 supplementary characters other than the diacritical marks.
fn iso6937_g2(c: u8) -> char {
    const A0: &str = " ¡¢£$¥#§¤‘“«←↑→↓°±²³×µ¶·÷’”»¼½¾¿";
    const D0: &str = "―¹®©™♪¬¦    ⅛⅜⅝⅞ΩÆĐªĦ ĲĿŁØŒºÞŦŊŉĸæđðħıĳŀłøœßþŧŋ\u{ad}";
    let (table, base) = match c {
        0xa0..=0xbf => (A0, 0xa0),
        0xd0..=0xff => (D0, 0xd0),
        _ => return ' ',
    };
    table.chars().nth(usize::from(c - base)).unwrap_or(' ')
}

/// Letter `ch` with ISO 6937 non-spacing mark `mark` (0xC1 grave … 0xCF
/// caron), precomposed where Unicode has the letter.
fn compose(mark: u8, ch: char) -> String {
    let (bases, composed): (&str, &str) = match mark {
        0xc1 => ("AEIOUaeiou", "ÀÈÌÒÙàèìòù"),
        0xc2 => ("AEIOUYaeiouyCcNnSsZzLlRr", "ÁÉÍÓÚÝáéíóúýĆćŃńŚśŹźĹĺŔŕ"),
        0xc3 => ("AEIOUaeiouCcGgHhJjSsWwYy", "ÂÊÎÔÛâêîôûĈĉĜĝĤĥĴĵŜŝŴŵŶŷ"),
        0xc4 => ("ANOanoIiUu", "ÃÑÕãñõĨĩŨũ"),
        0xc5 => ("AEIOUaeiou", "ĀĒĪŌŪāēīōū"),
        0xc6 => ("AaGgUu", "ĂăĞğŬŭ"),
        0xc7 => ("CcEeGgIZz", "ĊċĖėĠġİŻż"),
        0xc8 => ("AEIOUaeiouy", "ÄËÏÖÜäëïöüÿ"),
        0xca => ("AaUu", "ÅåŮů"),
        0xcb => ("CcSsTtGKkLlNnRr", "ÇçŞşŢţĢĶķĻļŅņŖŗ"),
        0xcd => ("OoUu", "ŐőŰű"),
        0xce => ("AaEeIiUu", "ĄąĘęĮįŲų"),
        0xcf => ("CcDdEeNnRrSsTtZzLl", "ČčĎďĚěŇňŘřŠšŤťŽžĽľ"),
        _ => ("", ""),
    };
    match bases.chars().position(|b| b == ch).and_then(|i| composed.chars().nth(i)) {
        Some(c) => c.to_string(),
        None => ch.to_string(),
    }
}

#[allow(clippy::too_many_lines)] // the GSI fields, then the TTI blocks
fn stl(bytes: &[u8], cx: &mut Context<'_>) -> Result<Subtitles, ExtractError> {
    let gsi = bytes.get(..GSI).ok_or_else(|| ExtractError::malformed("GSI block"))?;
    let mut subs = Subtitles::new("ebu_stl");
    let field = |a: usize, z: usize| gsi_text(&gsi[a..z]);
    let dfc = field(3, 11).unwrap_or_default();
    let fps: f64 = dfc.get(3..5).and_then(|r| r.parse().ok()).filter(|r| *r > 0.0).unwrap_or(25.0);
    subs.frame_rate = Some(fps);
    subs.set("disk_format", dfc.clone());
    subs.set(
        "display_standard",
        match gsi[11] {
            b'0' => "open_subtitling",
            b'1' => "teletext_level_1",
            b'2' => "teletext_level_2",
            _ => "undefined",
        },
    );
    let table = field(12, 14).unwrap_or_else(|| "00".into());
    subs.set(
        "character_table",
        match table.as_str() {
            "00" => "latin",
            "01" => "latin_cyrillic",
            "02" => "latin_arabic",
            "03" => "latin_greek",
            "04" => "latin_hebrew",
            _ => "unknown",
        },
    );
    if let Some(code) = field(14, 16).as_deref().and_then(ebu_language) {
        subs.declare_language(code, "stl.LC");
    } else if let Some(l) = field(14, 16).and_then(|l| language_code(&l)) {
        subs.declare_language(&l, "stl.LC");
    }
    subs.title = field(16, 48).or_else(|| field(80, 112));
    subs.set("episode_title", field(48, 80));
    subs.set("translated_title", field(80, 112));
    subs.set("translated_episode_title", field(112, 144));
    subs.set("translator", field(144, 176));
    subs.set("subtitle_list_reference", field(208, 224));
    subs.set("revision", field(236, 238).and_then(|r| r.parse::<u32>().ok()));
    let declared_blocks = field(238, 243).and_then(|n| n.parse::<u64>().ok());
    subs.set("declared_subtitles", field(243, 248).and_then(|n| n.parse::<u64>().ok()));
    subs.set("max_chars_per_row", field(251, 253).and_then(|n| n.parse::<u32>().ok()));
    subs.set("max_rows", field(253, 255).and_then(|n| n.parse::<u32>().ok()));
    subs.set("country", field(274, 277));
    subs.set("publisher", field(277, 309));
    subs.set("editor", field(309, 341));
    for (a, key, kind) in [(224, "creation_date", DateField::Created), (230, "revision_date", DateField::Modified)] {
        if let Some(d) = field(a, a + 6).filter(|d| d.len() == 6 && d.bytes().all(|c| c.is_ascii_digit())) {
            let yy: u32 = d[..2].parse().unwrap_or(0);
            let year = if yy < 70 { 2000 + yy } else { 1900 + yy };
            let iso = format!("{year}-{}-{}", &d[2..4], &d[4..6]);
            if iso.parse::<jiff::civil::Date>().is_ok() {
                cx.temporal().source(format!("stl.{key}")).content_date(kind, iso.clone(), false);
                subs.set(key, iso);
            }
        }
    }
    let tc = |t: &[u8]| -> Option<f64> {
        let [hours, minutes, secs, frames] = t[..] else { return None };
        (minutes < 60 && secs < 60)
            .then(|| f64::from(hours) * 3600.0 + f64::from(minutes) * 60.0 + f64::from(secs) + f64::from(frames) / fps)
    };
    let programme_start = field(256, 264).filter(|t| t.len() == 8).and_then(|t| {
        let n: Vec<u8> = (0..4).map(|i| t[i * 2..i * 2 + 2].parse::<u8>().ok()).collect::<Option<_>>()?;
        subs.set("timecode_start", format!("{}:{}:{}:{}", &t[..2], &t[2..4], &t[4..6], &t[6..8]));
        tc(&n)
    });
    // TTI blocks; extension blocks (EBN ≠ 0xFF) continue a subtitle.
    let mut cues: Vec<(f64, f64, String)> = Vec::new();
    let (mut comments, mut blocks) = (0u64, 0u64);
    let mut pending: Option<(f64, f64, String, bool)> = None;
    let mut markup = std::collections::BTreeSet::new();
    for (i, t) in bytes[GSI..].as_chunks::<TTI>().0.iter().enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint()?;
        }
        blocks += 1;
        let ebn = t[3];
        if ebn == 0xfe {
            continue; // user data
        }
        let (start, end) = (tc(&t[5..9]), tc(&t[9..13]));
        let comment = t[15] != 0;
        let text = tti_text(&t[16..], &table, &mut markup);
        match pending.as_mut() {
            Some(p) => p.2.push_str(&text),
            None => pending = Some((start.unwrap_or(0.0), end.unwrap_or(0.0), text, comment)),
        }
        if ebn == 0xff
            && let Some((a, z, text, comment)) = pending.take()
        {
            if comment {
                comments += 1;
            } else {
                cues.push((a, z, text));
            }
        }
    }
    subs.markup = markup;
    let first = cues.iter().map(|c| c.0).fold(f64::INFINITY, f64::min);
    let offset = programme_start.filter(|&p| p <= first).unwrap_or(0.0);
    let mut m = std::collections::BTreeSet::new();
    for (a, z, raw) in cues {
        let text = plain_text(&raw, &mut m);
        subs.push(Cue { start: a - offset, end: Some((z - offset).max(a - offset)), text, speaker: None });
    }
    if offset > 0.0 {
        subs.set("times_relative_to_timecode_start", true);
    }
    if comments > 0 {
        subs.set("comment_subtitles", comments);
    }
    if declared_blocks.is_some_and(|d| d != blocks) {
        subs.set("declared_tti_blocks", declared_blocks);
        subs.set("tti_blocks", blocks);
    }
    Ok(subs)
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("scc", "ebu_stl");

    /// A CEA-608 word with odd parity.
    fn word(a: u8, b: u8) -> String {
        let p = |c: u8| if c.count_ones().is_multiple_of(2) { c | 0x80 } else { c };
        format!("{:02x}{:02x}", p(a), p(b))
    }

    #[test]
    fn scc_pop_on_and_roll_up() {
        let text =
            |s: &str| s.as_bytes().chunks(2).map(|c| word(c[0], *c.get(1).unwrap_or(&0))).collect::<Vec<_>>().join(" ");
        let rcl = word(0x14, 0x20);
        let eoc = word(0x14, 0x2f);
        let edm = word(0x14, 0x2c);
        let ru2 = word(0x14, 0x25);
        let cr = word(0x14, 0x2d);
        let file = format!(
            "Scenarist_SCC V1.0\n\n00:00:01;00\t{rcl} {rcl} {} {} {eoc} {eoc}\n\n00:00:03;00\t{edm} {edm}\n\n\
             00:00:04;00\t{ru2} {ru2} {} {cr} {cr}\n00:00:06;00\t{} {}\n",
            text("Hi"),
            word(0x11, 0x37),
            text("Roll"),
            text("Co"),
            word(0x12, 0x20), // `Á` replacing the `o`
        );
        let s = scc(&file);
        assert_eq!(s.cues.iter().map(|c| c.text.as_str()).collect::<Vec<_>>(), ["Hi♪", "Roll", "CÁ"]);
        assert!((s.cues[0].start - (1.0 + 4.0 * FRAME)).abs() < 1e-9);
        assert_eq!(s.cues[0].end, Some(3.0));
        assert_eq!(s.cues[1].end, Some(6.0));
        assert_eq!(s.format["caption_modes"], serde_json::json!(["pop_on", "roll_up"]));
        assert_eq!(timecode("01:00:00:15"), Some((3600.0 + 15.0 * FRAME, false)));
        assert_eq!(timecode("bad"), None);
    }

    #[test]
    fn iso6937() {
        let mut m = std::collections::BTreeSet::new();
        assert_eq!(tti_text(b"Caf\xc2e\x8a\x80na\xc4ive\x81 \xd5\x8f\x8f", "00", &mut m), "Café\nnaĩve ♪");
        assert!(m.contains("italic"));
        assert_eq!(compose(0xcf, 'Z'), "Ž");
        assert_eq!(compose(0xcf, 'q'), "q");
        assert_eq!(ebu_language("09"), Some("en"));
        assert_eq!(ebu_language("zz"), None);
        assert_eq!(iso6937_g2(0xa3), '£');
    }
}
