//! Text from page content streams (ISO 32000-2 §9): the text operators,
//! font encodings (standard, WinAnsi, MacRoman, `/Differences`) and
//! `/ToUnicode` CMaps. Layout is approximated: a new line when the baseline
//! moves, a space for wide gaps. Fonts without a Unicode mapping (CID fonts
//! lacking `/ToUnicode`) produce no text.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use super::doc::Doc;
use super::object::{Dict, Lexer, Obj, Token};
use crate::plugin::ExtractError;

/// A font's code → text mapping.
pub(crate) struct Font {
    /// Bytes per code (1 for simple fonts, usually 2 for Type0).
    width: usize,
    to_unicode: HashMap<u32, String>,
    simple: Option<[Option<char>; 256]>,
}

impl Font {
    fn decode(&self, bytes: &[u8], out: &mut String) {
        if self.width == 2 {
            for c in bytes.chunks(2) {
                let code = c.iter().fold(0u32, |a, &b| a << 8 | u32::from(b));
                if let Some(s) = self.to_unicode.get(&code) {
                    out.push_str(s);
                }
            }
            return;
        }
        for &b in bytes {
            if let Some(s) = self.to_unicode.get(&u32::from(b)) {
                out.push_str(s);
            } else if let Some(Some(c)) = self.simple.as_ref().map(|t| t[usize::from(b)]) {
                out.push(c);
            }
        }
    }
}

/// Per-document state: fonts already built, keyed by object number.
#[derive(Default)]
pub(crate) struct Fonts {
    cache: HashMap<u32, Rc<Font>>,
}

const MAX_PAGE_CHARS: usize = 200_000;
const MAX_FORM_DEPTH: usize = 4;

/// The text of one page.
pub(crate) fn page_text(
    doc: &mut Doc<'_, '_>,
    fonts: &mut Fonts,
    page: &Dict,
    resources: &Obj,
) -> Result<String, ExtractError> {
    let contents = doc.key(page, "Contents");
    let mut data = Vec::new();
    let parts: Vec<Obj> = match &contents {
        Obj::Array(a) => a.clone(),
        Obj::Null => return Ok(String::new()),
        _ => vec![page.get("Contents").cloned().unwrap_or(Obj::Null)],
    };
    for p in parts {
        match doc.stream_of(&p, 64 << 20) {
            Ok(d) => {
                data.extend_from_slice(&d);
                data.push(b'\n');
            }
            Err(ExtractError::LimitExceeded(e)) => return Err(ExtractError::LimitExceeded(e)),
            Err(_) => {}
        }
    }
    let mut out = String::new();
    let resources = doc.resolve(resources);
    let mut seen = HashSet::new();
    run(doc, fonts, &data, resources.as_dict(), &mut out, 0, &mut seen)?;
    Ok(tidy(&out))
}

struct State {
    font: Option<Rc<Font>>,
    line_y: Option<f64>,
    /// Text written since the last line break.
    on_line: bool,
}

#[allow(clippy::too_many_lines)] // one match over the text operators
fn run(
    doc: &mut Doc<'_, '_>,
    fonts: &mut Fonts,
    data: &[u8],
    resources: Option<&Dict>,
    out: &mut String,
    depth: usize,
    seen: &mut HashSet<u32>,
) -> Result<(), ExtractError> {
    let font_dict = resources.map(|r| doc.key(r, "Font"));
    let xobjects = resources.map(|r| doc.key(r, "XObject"));
    let mut st = State { font: None, line_y: None, on_line: false };
    let mut ops: Vec<Obj> = Vec::new();
    let mut lx = Lexer::new(data);
    let mut n = 0usize;
    loop {
        n += 1;
        if n.is_multiple_of(4096) {
            doc.cx.checkpoint()?;
        }
        if out.len() > MAX_PAGE_CHARS {
            break;
        }
        let tok = match lx.token() {
            Ok(Some(t)) => t,
            Ok(None) => break,
            Err(_) => {
                lx.pos += 1;
                continue;
            }
        };
        match tok {
            Token::Obj(o) => {
                if ops.len() < 64 {
                    ops.push(o);
                }
            }
            Token::ArrayOpen | Token::DictOpen => {
                lx.pos -= if tok == Token::ArrayOpen { 1 } else { 2 };
                match lx.object() {
                    Ok(o) if ops.len() < 64 => ops.push(o),
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            Token::ArrayClose | Token::DictClose => {}
            Token::Keyword(k) => {
                match k {
                    b"Tf" => {
                        let name = ops.iter().rev().find_map(Obj::as_name).map(str::to_string);
                        st.font = match (name, &font_dict) {
                            (Some(name), Some(Obj::Dict(fd))) => {
                                fd.get(&name).cloned().and_then(|r| font(doc, fonts, &r))
                            }
                            _ => None,
                        };
                    }
                    b"Td" | b"TD" => {
                        let ty = ops.get(1).and_then(Obj::as_f64).unwrap_or(0.0);
                        let tx = ops.first().and_then(Obj::as_f64).unwrap_or(0.0);
                        if ty.abs() > 0.01 {
                            newline(&mut st, out);
                        } else if tx > 0.01 && st.on_line {
                            space(out);
                        }
                    }
                    b"T*" => newline(&mut st, out),
                    b"Tm" => {
                        let y = ops.get(5).and_then(Obj::as_f64);
                        if let (Some(y), Some(prev)) = (y, st.line_y)
                            && (y - prev).abs() > 0.5
                        {
                            newline(&mut st, out);
                        } else if st.on_line {
                            space(out);
                        }
                        st.line_y = y;
                    }
                    b"Tj" => {
                        if show(&st, ops.last(), out) {
                            st.on_line = true;
                        }
                    }
                    b"'" | b"\"" => {
                        newline(&mut st, out);
                        if show(&st, ops.last(), out) {
                            st.on_line = true;
                        }
                    }
                    b"TJ" => {
                        if let Some(Obj::Array(items)) = ops.last() {
                            for it in items {
                                match it {
                                    Obj::Str(_) => {
                                        if show(&st, Some(it), out) {
                                            st.on_line = true;
                                        }
                                    }
                                    o => {
                                        if o.as_f64().is_some_and(|v| v < -180.0) && st.on_line {
                                            space(out);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    b"Do" if depth < MAX_FORM_DEPTH => {
                        if let (Some(name), Some(Obj::Dict(xo))) = (ops.last().and_then(Obj::as_name), &xobjects)
                            && let Some(Obj::Ref(num, _)) = xo.get(name)
                            && seen.insert(*num)
                        {
                            let r = Obj::Ref(*num, 0);
                            let form = doc.resolve(&r);
                            if form.as_dict().is_some_and(|d| d.name("Subtype") == Some("Form")) {
                                let res =
                                    form.as_dict().map(|d| doc.key(d, "Resources")).filter(|r| r.as_dict().is_some());
                                if let Ok(body) = doc.stream_of(&r, 16 << 20) {
                                    let mut inner = body;
                                    inner.push(b'\n');
                                    let res_dict = res.as_ref().and_then(Obj::as_dict).or(resources);
                                    let res_dict = res_dict.cloned();
                                    run(doc, fonts, &inner, res_dict.as_ref(), out, depth + 1, seen)?;
                                }
                            }
                        }
                    }
                    b"BI" => skip_inline_image(&mut lx),
                    _ => {}
                }
                ops.clear();
            }
        }
    }
    Ok(())
}

fn newline(st: &mut State, out: &mut String) {
    if st.on_line {
        out.push('\n');
        st.on_line = false;
    }
}

fn space(out: &mut String) {
    if !out.ends_with([' ', '\n']) {
        out.push(' ');
    }
}

fn show(st: &State, s: Option<&Obj>, out: &mut String) -> bool {
    let (Some(f), Some(Obj::Str(bytes))) = (&st.font, s) else { return false };
    let before = out.len();
    f.decode(bytes, out);
    out.len() > before
}

/// Skip `BI … ID <binary> EI`.
fn skip_inline_image(lx: &mut Lexer<'_>) {
    let buf = lx.buf;
    let mut i = lx.pos;
    // Past the `ID` keyword.
    while i + 2 < buf.len() {
        if &buf[i..i + 2] == b"ID"
            && super::object::is_white(buf[i + 2])
            && (i == 0 || super::object::is_white(buf[i - 1]))
        {
            i += 3;
            break;
        }
        i += 1;
    }
    while i + 2 < buf.len() {
        if super::object::is_white(buf[i])
            && &buf[i + 1..i + 3] == b"EI"
            && buf.get(i + 3).is_none_or(|b| super::object::is_white(*b))
        {
            lx.pos = i + 3;
            return;
        }
        i += 1;
    }
    lx.pos = buf.len();
}

/// Collapse runs of spaces and blank lines.
fn tidy(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.lines() {
        let l = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if !l.is_empty() {
            out.push_str(&l);
            out.push('\n');
        }
    }
    out
}

fn font(doc: &mut Doc<'_, '_>, fonts: &mut Fonts, r: &Obj) -> Option<Rc<Font>> {
    let key = match r {
        Obj::Ref(n, _) => Some(*n),
        _ => None,
    };
    if let Some(k) = key
        && let Some(f) = fonts.cache.get(&k)
    {
        return Some(f.clone());
    }
    let obj = doc.resolve(r);
    let d = obj.as_dict()?;
    let f = Rc::new(build_font(doc, d));
    if let Some(k) = key
        && fonts.cache.len() < 10_000
    {
        fonts.cache.insert(k, f.clone());
    }
    Some(f)
}

fn build_font(doc: &mut Doc<'_, '_>, d: &Dict) -> Font {
    let type0 = d.name("Subtype") == Some("Type0");
    let mut to_unicode = HashMap::new();
    let mut width = if type0 { 2 } else { 1 };
    if let Some(tu) = d.get("ToUnicode").filter(|o| matches!(o, Obj::Ref(..)))
        && let Ok(cmap) = doc.stream_of(tu, 4 << 20)
    {
        let (map, w) = parse_cmap(&cmap);
        to_unicode = map;
        if let Some(w) = w {
            width = w;
        }
    }
    if type0 {
        // Without /ToUnicode, predefined CMaps map to CIDs, not Unicode: no text.
        return Font { width, to_unicode, simple: None };
    }
    let base_name = match doc.key(d, "Encoding") {
        Obj::Name(n) => Some(n),
        Obj::Dict(e) => e.name("BaseEncoding").map(str::to_string),
        _ => None,
    };
    let base_font = d.name("BaseFont").unwrap_or("");
    let symbolic = base_font.contains("Symbol") || base_font.contains("Dingbats");
    let mut table: [Option<char>; 256] = std::array::from_fn(|i| {
        let b = u8::try_from(i).unwrap_or(0);
        match base_name.as_deref() {
            Some("WinAnsiEncoding") => win_ansi(b),
            Some("MacRomanEncoding") => mac_roman(b),
            _ if symbolic => None,
            _ => standard(b),
        }
    });
    if let Obj::Dict(e) = doc.key(d, "Encoding")
        && let Some(diffs) = e.get("Differences").and_then(Obj::as_array)
    {
        let mut code = 0usize;
        for item in diffs {
            match item {
                Obj::Int(n) => code = usize::try_from(*n).unwrap_or(256),
                Obj::Name(g) => {
                    if code < 256 {
                        table[code] = glyph_char(g);
                    }
                    code += 1;
                }
                _ => {}
            }
        }
    }
    Font { width, to_unicode, simple: Some(table) }
}

/// A `/ToUnicode` CMap: `bfchar` and `bfrange` entries, plus the code width
/// from `codespacerange`.
pub(crate) fn parse_cmap(data: &[u8]) -> (HashMap<u32, String>, Option<usize>) {
    let mut map = HashMap::new();
    let mut width = None;
    let mut lx = Lexer::new(data);
    let mut ops: Vec<Obj> = Vec::new();
    let code = |s: &[u8]| s.iter().fold(0u32, |a, &b| a << 8 | u32::from(b));
    let utf16 = |s: &[u8]| {
        let units: Vec<u16> = s.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])).collect();
        String::from_utf16_lossy(&units)
    };
    loop {
        let tok = match lx.token() {
            Ok(Some(t)) => t,
            Ok(None) => break,
            Err(_) => {
                lx.pos += 1;
                continue;
            }
        };
        match tok {
            Token::Obj(o) => ops.push(o),
            Token::ArrayOpen => {
                lx.pos -= 1;
                match lx.object() {
                    Ok(o) => ops.push(o),
                    Err(_) => break,
                }
            }
            Token::Keyword(k) => {
                match k {
                    b"endcodespacerange" => {
                        if let Some(Obj::Str(s)) = ops.first() {
                            width = Some(s.len().clamp(1, 4));
                        }
                    }
                    b"endbfchar" => {
                        for pair in ops.as_chunks::<2>().0 {
                            if let (Obj::Str(c), Obj::Str(u)) = (&pair[0], &pair[1]) {
                                map.insert(code(c), utf16(u));
                            }
                        }
                    }
                    b"endbfrange" => {
                        for tri in ops.as_chunks::<3>().0 {
                            let (Obj::Str(lo), Obj::Str(hi)) = (&tri[0], &tri[1]) else { continue };
                            let (lo, hi) = (code(lo), code(hi));
                            if hi < lo || hi - lo > 65_535 {
                                continue;
                            }
                            match &tri[2] {
                                Obj::Str(dst) if !dst.is_empty() => {
                                    let mut units: Vec<u16> = dst
                                        .chunks(2)
                                        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                                        .collect();
                                    for c in lo..=hi {
                                        map.insert(c, String::from_utf16_lossy(&units));
                                        if let Some(last) = units.last_mut() {
                                            *last = last.wrapping_add(1);
                                        }
                                    }
                                }
                                Obj::Array(items) => {
                                    for (c, it) in (lo..=hi).zip(items) {
                                        if let Some(s) = it.as_str() {
                                            map.insert(c, utf16(s));
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
                ops.clear();
                if map.len() > 200_000 {
                    break;
                }
            }
            _ => {}
        }
    }
    (map, width)
}

fn win_ansi(b: u8) -> Option<char> {
    const HIGH: [u16; 32] = [
        0x20AC, 0, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0, 0x017D,
        0, 0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0,
        0x017E, 0x0178,
    ];
    match b {
        0x20..=0x7E | 0xA0..=0xFF => Some(char::from(b)),
        0x80..=0x9F => char::from_u32(u32::from(HIGH[usize::from(b - 0x80)])).filter(|&c| c != '\0'),
        b'\t' | b'\n' | b'\r' => Some(' '),
        _ => None,
    }
}

fn mac_roman(b: u8) -> Option<char> {
    const HIGH: &str = "ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄€‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ\u{F8FF}ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ";
    match b {
        0x20..=0x7E => Some(char::from(b)),
        0x80..=0xFF => HIGH.chars().nth(usize::from(b - 0x80)),
        _ => None,
    }
}

fn standard(b: u8) -> Option<char> {
    Some(match b {
        0x27 => '\u{2019}',
        0x60 => '\u{2018}',
        0x20..=0x7E => char::from(b),
        0xA1 => '¡',
        0xA2 => '¢',
        0xA3 => '£',
        0xA5 => '¥',
        0xA7 => '§',
        0xA9 => '\'',
        0xAA => '\u{201C}',
        0xAB => '«',
        0xAE => '\u{FB01}',
        0xAF => '\u{FB02}',
        0xB1 => '\u{2013}',
        0xB2 => '\u{2020}',
        0xB3 => '\u{2021}',
        0xB7 => '\u{2022}',
        0xB9 => '\u{201E}',
        0xBA => '\u{201D}',
        0xBB => '»',
        0xBC => '\u{2026}',
        0xBD => '\u{2030}',
        0xD0 => '\u{2014}',
        0xE1 => 'Æ',
        0xE9 => 'Ø',
        0xEA => 'Œ',
        0xF1 => 'æ',
        0xF5 => 'ı',
        0xF9 => 'ø',
        0xFA => 'œ',
        0xFB => 'ß',
        _ => return None,
    })
}

/// A glyph name (Adobe Glyph List subset) as a character.
#[allow(clippy::too_many_lines)] // the glyph-name table
pub(crate) fn glyph_char(name: &str) -> Option<char> {
    const NAMES: &[(&str, char)] = &[
        ("space", ' '),
        ("exclam", '!'),
        ("quotedbl", '"'),
        ("numbersign", '#'),
        ("dollar", '$'),
        ("percent", '%'),
        ("ampersand", '&'),
        ("quotesingle", '\''),
        ("quoteright", '\u{2019}'),
        ("quoteleft", '\u{2018}'),
        ("parenleft", '('),
        ("parenright", ')'),
        ("asterisk", '*'),
        ("plus", '+'),
        ("comma", ','),
        ("hyphen", '-'),
        ("period", '.'),
        ("slash", '/'),
        ("zero", '0'),
        ("one", '1'),
        ("two", '2'),
        ("three", '3'),
        ("four", '4'),
        ("five", '5'),
        ("six", '6'),
        ("seven", '7'),
        ("eight", '8'),
        ("nine", '9'),
        ("colon", ':'),
        ("semicolon", ';'),
        ("less", '<'),
        ("equal", '='),
        ("greater", '>'),
        ("question", '?'),
        ("at", '@'),
        ("bracketleft", '['),
        ("backslash", '\\'),
        ("bracketright", ']'),
        ("asciicircum", '^'),
        ("underscore", '_'),
        ("grave", '`'),
        ("braceleft", '{'),
        ("bar", '|'),
        ("braceright", '}'),
        ("asciitilde", '~'),
        ("bullet", '\u{2022}'),
        ("endash", '\u{2013}'),
        ("emdash", '\u{2014}'),
        ("quotedblleft", '\u{201C}'),
        ("quotedblright", '\u{201D}'),
        ("quotesinglbase", '\u{201A}'),
        ("quotedblbase", '\u{201E}'),
        ("ellipsis", '\u{2026}'),
        ("fi", '\u{FB01}'),
        ("fl", '\u{FB02}'),
        ("ff", '\u{FB00}'),
        ("ffi", '\u{FB03}'),
        ("ffl", '\u{FB04}'),
        ("dagger", '\u{2020}'),
        ("daggerdbl", '\u{2021}'),
        ("trademark", '\u{2122}'),
        ("copyright", '©'),
        ("registered", '®'),
        ("degree", '°'),
        ("section", '§'),
        ("paragraph", '¶'),
        ("sterling", '£'),
        ("yen", '¥'),
        ("Euro", '€'),
        ("euro", '€'),
        ("cent", '¢'),
        ("minus", '\u{2212}'),
        ("multiply", '×'),
        ("divide", '÷'),
        ("plusminus", '±'),
        ("nbspace", '\u{A0}'),
        ("periodcentered", '·'),
        ("guillemotleft", '«'),
        ("guillemotright", '»'),
        ("dotlessi", 'ı'),
        ("germandbls", 'ß'),
        ("ae", 'æ'),
        ("AE", 'Æ'),
        ("oe", 'œ'),
        ("OE", 'Œ'),
        ("oslash", 'ø'),
        ("Oslash", 'Ø'),
        ("aring", 'å'),
        ("Aring", 'Å'),
        ("ccedilla", 'ç'),
        ("Ccedilla", 'Ç'),
        ("ntilde", 'ñ'),
        ("Ntilde", 'Ñ'),
        ("eacute", 'é'),
        ("Eacute", 'É'),
        ("egrave", 'è'),
        ("Egrave", 'È'),
        ("ecircumflex", 'ê'),
        ("edieresis", 'ë'),
        ("aacute", 'á'),
        ("Aacute", 'Á'),
        ("agrave", 'à'),
        ("Agrave", 'À'),
        ("acircumflex", 'â'),
        ("adieresis", 'ä'),
        ("Adieresis", 'Ä'),
        ("atilde", 'ã'),
        ("iacute", 'í'),
        ("igrave", 'ì'),
        ("icircumflex", 'î'),
        ("idieresis", 'ï'),
        ("oacute", 'ó'),
        ("Oacute", 'Ó'),
        ("ograve", 'ò'),
        ("ocircumflex", 'ô'),
        ("odieresis", 'ö'),
        ("Odieresis", 'Ö'),
        ("otilde", 'õ'),
        ("uacute", 'ú'),
        ("Uacute", 'Ú'),
        ("ugrave", 'ù'),
        ("ucircumflex", 'û'),
        ("udieresis", 'ü'),
        ("Udieresis", 'Ü'),
        ("yacute", 'ý'),
        ("ydieresis", 'ÿ'),
        ("scaron", 'š'),
        ("Scaron", 'Š'),
        ("zcaron", 'ž'),
        ("Zcaron", 'Ž'),
        ("lslash", 'ł'),
        ("Lslash", 'Ł'),
        ("exclamdown", '¡'),
        ("questiondown", '¿'),
        ("ordfeminine", 'ª'),
        ("ordmasculine", 'º'),
        ("mu", 'µ'),
        ("onehalf", '½'),
        ("onequarter", '¼'),
        ("threequarters", '¾'),
        ("perthousand", '\u{2030}'),
        ("florin", 'ƒ'),
        ("guilsinglleft", '\u{2039}'),
        ("guilsinglright", '\u{203A}'),
        ("tab", ' '),
    ];
    let base = name.split('.').next().unwrap_or(name);
    if base.chars().count() == 1 {
        return base.chars().next();
    }
    if let Some(hex) = base.strip_prefix("uni").filter(|h| h.len() == 4) {
        return u32::from_str_radix(hex, 16).ok().and_then(char::from_u32);
    }
    if let Some(hex) =
        base.strip_prefix('u').filter(|h| (4..=6).contains(&h.len()) && h.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return u32::from_str_radix(hex, 16).ok().and_then(char::from_u32);
    }
    NAMES.iter().find(|(n, _)| *n == base).map(|(_, c)| *c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_to_unicode_cmaps() {
        let cmap = b"1 begincodespacerange <0000><FFFF> endcodespacerange
            2 beginbfchar <0003> <0020> <0011> <00410042> endbfchar
            1 beginbfrange <0020><0022><0061> endbfrange
            1 beginbfrange <0030> <0031> [<0058> <0059>] endbfrange\n";
        let (map, width) = parse_cmap(cmap);
        assert_eq!(width, Some(2));
        assert_eq!(map.get(&3).map(String::as_str), Some(" "));
        assert_eq!(map.get(&0x11).map(String::as_str), Some("AB"));
        assert_eq!(map.get(&0x22).map(String::as_str), Some("c"));
        assert_eq!(map.get(&0x31).map(String::as_str), Some("Y"));
    }

    #[test]
    fn glyph_names() {
        assert_eq!(glyph_char("A"), Some('A'));
        assert_eq!(glyph_char("uni20AC"), Some('€'));
        assert_eq!(glyph_char("quotedblleft"), Some('\u{201C}'));
        assert_eq!(glyph_char("eacute.sc"), Some('é'));
        assert_eq!(mac_roman(0x8E), Some('é'));
        assert_eq!(win_ansi(0x93), Some('\u{201C}'));
    }
}
