//! PDF objects and the tokenizer / parser for them (ISO 32000-2 §7.2–7.3).

/// A PDF object. Streams keep their dictionary and where the data starts;
/// the data itself is read on demand.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Obj {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    Str(Vec<u8>),
    Name(String),
    Array(Vec<Obj>),
    Dict(Dict),
    Ref(u32, u16),
    /// A stream: its dictionary and where its data starts (read on demand).
    Stream(Dict, Data),
}

/// Where a stream's data starts in the file.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Data {
    At(u64),
}

/// A dictionary, in file order (small; looked up linearly).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Dict(pub Vec<(String, Obj)>);

impl Dict {
    pub(crate) fn get(&self, key: &str) -> Option<&Obj> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub(crate) fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// A name value (`/Type /Page` → `Page`).
    pub(crate) fn name(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Obj::as_name)
    }

    pub(crate) fn int(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(Obj::as_int)
    }
}

impl Obj {
    pub(crate) fn as_name(&self) -> Option<&str> {
        match self {
            Self::Name(n) => Some(n),
            _ => None,
        }
    }

    pub(crate) fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            #[allow(clippy::cast_possible_truncation)] // integral reals only
            Self::Real(r) if r.fract() == 0.0 && r.abs() < 1e15 => Some(*r as i64),
            _ => None,
        }
    }

    pub(crate) fn as_f64(&self) -> Option<f64> {
        match self {
            #[allow(clippy::cast_precision_loss)] // page geometry
            Self::Int(n) => Some(*n as f64),
            Self::Real(r) => Some(*r),
            _ => None,
        }
    }

    pub(crate) fn as_dict(&self) -> Option<&Dict> {
        match self {
            Self::Dict(d) | Self::Stream(d, _) => Some(d),
            _ => None,
        }
    }

    pub(crate) fn as_array(&self) -> Option<&[Obj]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&[u8]> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Why parsing stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// The buffer ended inside the object: read more and retry.
    Incomplete,
    /// Not a valid object.
    Invalid,
}

const MAX_DEPTH: usize = 64;

pub(crate) fn is_white(b: u8) -> bool {
    matches!(b, 0 | 9 | 10 | 12 | 13 | 32)
}

pub(crate) fn is_delim(b: u8) -> bool {
    matches!(b, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%')
}

/// A cursor over PDF syntax.
pub(crate) struct Lexer<'a> {
    pub(crate) buf: &'a [u8],
    pub(crate) pos: usize,
}

/// A content-stream or file-level token.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Token<'a> {
    Obj(Obj),
    /// A bare keyword: `obj`, `R`, `stream`, `Tj`, `BT`…
    Keyword(&'a [u8]),
    ArrayOpen,
    ArrayClose,
    DictOpen,
    DictClose,
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn at(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    pub(crate) fn skip_ws(&mut self) {
        while let Some(&b) = self.buf.get(self.pos) {
            if is_white(b) {
                self.pos += 1;
            } else if b == b'%' {
                while let Some(&c) = self.buf.get(self.pos) {
                    if c == b'\n' || c == b'\r' {
                        break;
                    }
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    fn regular(&mut self) -> &'a [u8] {
        let start = self.pos;
        while let Some(&b) = self.buf.get(self.pos) {
            if is_white(b) || is_delim(b) {
                break;
            }
            self.pos += 1;
        }
        &self.buf[start..self.pos]
    }

    /// The next token, `Ok(None)` at the end of the buffer.
    pub(crate) fn token(&mut self) -> Result<Option<Token<'a>>, ParseError> {
        self.skip_ws();
        let Some(&b) = self.buf.get(self.pos) else {
            return Ok(None);
        };
        Ok(Some(match b {
            b'/' => {
                self.pos += 1;
                Token::Obj(Obj::Name(decode_name(self.regular())))
            }
            b'(' => Token::Obj(Obj::Str(self.literal()?)),
            b'<' if self.buf.get(self.pos + 1) == Some(&b'<') => {
                self.pos += 2;
                Token::DictOpen
            }
            b'<' => Token::Obj(Obj::Str(self.hex()?)),
            b'>' if self.buf.get(self.pos + 1) == Some(&b'>') => {
                self.pos += 2;
                Token::DictClose
            }
            b'>' if self.pos + 1 >= self.buf.len() => return Err(ParseError::Incomplete),
            b'[' => {
                self.pos += 1;
                Token::ArrayOpen
            }
            b']' => {
                self.pos += 1;
                Token::ArrayClose
            }
            b'{' | b'}' | b')' | b'>' => {
                self.pos += 1;
                Token::Keyword(&self.buf[self.pos - 1..self.pos])
            }
            _ => {
                let word = self.regular();
                if self.pos >= self.buf.len() {
                    // A number or keyword cut by the buffer end may be longer.
                    return Err(ParseError::Incomplete);
                }
                match number(word) {
                    Some(n) => Token::Obj(n),
                    None => match word {
                        b"true" => Token::Obj(Obj::Bool(true)),
                        b"false" => Token::Obj(Obj::Bool(false)),
                        b"null" => Token::Obj(Obj::Null),
                        _ => Token::Keyword(word),
                    },
                }
            }
        }))
    }

    fn literal(&mut self) -> Result<Vec<u8>, ParseError> {
        self.pos += 1;
        let mut out = Vec::new();
        let mut depth = 1u32;
        loop {
            let b = *self.buf.get(self.pos).ok_or(ParseError::Incomplete)?;
            self.pos += 1;
            match b {
                b'(' => {
                    depth += 1;
                    out.push(b);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(out);
                    }
                    out.push(b);
                }
                b'\\' => {
                    let e = *self.buf.get(self.pos).ok_or(ParseError::Incomplete)?;
                    self.pos += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'\r' => {
                            if self.buf.get(self.pos) == Some(&b'\n') {
                                self.pos += 1;
                            }
                        }
                        b'\n' => {}
                        b'0'..=b'7' => {
                            let mut v = u32::from(e - b'0');
                            for _ in 0..2 {
                                match self.buf.get(self.pos) {
                                    Some(&d @ b'0'..=b'7') => {
                                        v = v * 8 + u32::from(d - b'0');
                                        self.pos += 1;
                                    }
                                    _ => break,
                                }
                            }
                            #[allow(clippy::cast_possible_truncation)] // high bits ignored by the spec
                            out.push(v as u8);
                        }
                        other => out.push(other),
                    }
                }
                _ => out.push(b),
            }
        }
    }

    fn hex(&mut self) -> Result<Vec<u8>, ParseError> {
        self.pos += 1;
        let mut out = Vec::new();
        let mut hi: Option<u8> = None;
        loop {
            let b = *self.buf.get(self.pos).ok_or(ParseError::Incomplete)?;
            self.pos += 1;
            if b == b'>' {
                if let Some(h) = hi {
                    out.push(h << 4);
                }
                return Ok(out);
            }
            let Some(v) = hex_digit(b) else {
                if is_white(b) {
                    continue;
                }
                return Err(ParseError::Invalid);
            };
            match hi.take() {
                Some(h) => out.push(h << 4 | v),
                None => hi = Some(v),
            }
        }
    }

    /// One complete object, joining `n g R` into a reference.
    pub(crate) fn object(&mut self) -> Result<Obj, ParseError> {
        self.object_at_depth(0)
    }

    fn object_at_depth(&mut self, depth: usize) -> Result<Obj, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError::Invalid);
        }
        match self.token()?.ok_or(ParseError::Incomplete)? {
            Token::Obj(Obj::Int(n)) => Ok(self.maybe_ref(n)?.unwrap_or(Obj::Int(n))),
            Token::Obj(o) => Ok(o),
            Token::ArrayOpen => {
                let mut items = Vec::new();
                loop {
                    self.skip_ws();
                    match self.buf.get(self.pos) {
                        None => return Err(ParseError::Incomplete),
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Obj::Array(items));
                        }
                        _ => {
                            let before = self.pos;
                            match self.object_at_depth(depth + 1) {
                                Ok(o) => items.push(o),
                                // Junk inside an array: skip a byte and go on.
                                Err(ParseError::Invalid) if self.pos == before => self.pos += 1,
                                Err(ParseError::Invalid) => {}
                                Err(e) => return Err(e),
                            }
                        }
                    }
                }
            }
            Token::DictOpen => Ok(Obj::Dict(self.dict_body(depth)?)),
            Token::Keyword(_) | Token::ArrayClose | Token::DictClose => Err(ParseError::Invalid),
        }
    }

    /// The entries of a dictionary after `<<`, through `>>`.
    pub(crate) fn dict_body(&mut self, depth: usize) -> Result<Dict, ParseError> {
        let mut entries = Vec::new();
        loop {
            match self.token()?.ok_or(ParseError::Incomplete)? {
                Token::DictClose => return Ok(Dict(entries)),
                Token::Obj(Obj::Name(key)) => {
                    self.skip_ws();
                    if self.buf.get(self.pos..self.pos + 2) == Some(b">>") {
                        // A key without a value.
                        entries.push((key, Obj::Null));
                        continue;
                    }
                    let value = match self.object_at_depth(depth + 1) {
                        Ok(v) => v,
                        Err(ParseError::Invalid) => Obj::Null,
                        Err(e) => return Err(e),
                    };
                    if entries.len() < 4096 {
                        entries.push((key, value));
                    }
                }
                // Stray values or keywords: ignore (repairs common damage).
                Token::Obj(_) | Token::Keyword(_) | Token::ArrayClose => {}
                Token::ArrayOpen => {
                    self.pos -= 1;
                    let _ = self.object_at_depth(depth + 1)?;
                }
                Token::DictOpen => {
                    let _ = self.dict_body(depth + 1)?;
                }
            }
        }
    }

    /// After an integer: `g R` makes a reference.
    fn maybe_ref(&mut self, num: i64) -> Result<Option<Obj>, ParseError> {
        let save = self.pos;
        let mut look = Lexer::at(self.buf, self.pos);
        let r = (|| {
            let Ok(Some(Token::Obj(Obj::Int(g)))) = look.token() else { return Ok(None) };
            match look.token() {
                Ok(Some(Token::Keyword(b"R"))) => Ok(Some((g, look.pos))),
                Err(ParseError::Incomplete) => Err(ParseError::Incomplete),
                _ => Ok(None),
            }
        })();
        match r {
            Ok(Some((g, end))) => {
                self.pos = end;
                match (u32::try_from(num), u16::try_from(g)) {
                    (Ok(n), Ok(g)) => Ok(Some(Obj::Ref(n, g))),
                    _ => Ok(Some(Obj::Null)),
                }
            }
            Ok(None) => {
                self.pos = save;
                Ok(None)
            }
            // Near the buffer end we cannot tell; the caller reads more.
            Err(e) => {
                self.pos = save;
                if self.buf.len() - save < 32 { Err(e) } else { Ok(None) }
            }
        }
    }
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// A name with `#xx` escapes decoded (lossy UTF-8).
fn decode_name(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'#'
            && let (Some(h), Some(l)) =
                (raw.get(i + 1).copied().and_then(hex_digit), raw.get(i + 2).copied().and_then(hex_digit))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(raw[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn number(word: &[u8]) -> Option<Obj> {
    if word.is_empty() || !word.iter().all(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.')) {
        return None;
    }
    let s = std::str::from_utf8(word).ok()?;
    if !s.contains('.')
        && let Ok(n) = s.parse::<i64>()
    {
        return Some(Obj::Int(n));
    }
    // Reals; also repairs `--5` and `5.-` style damage.
    let cleaned: String = {
        let neg = s.starts_with('-');
        let body: String = s.chars().filter(|c| c.is_ascii_digit() || *c == '.').collect();
        let mut seen = false;
        let body: String = body.chars().filter(|&c| c != '.' || !std::mem::replace(&mut seen, true)).collect();
        if neg { format!("-{body}") } else { body }
    };
    if cleaned.trim_start_matches('-').is_empty() || cleaned == "." || cleaned == "-." {
        return Some(Obj::Int(0));
    }
    cleaned.parse::<f64>().ok().filter(|f| f.is_finite()).map(Obj::Real)
}

/// Text strings (§7.9.2.2): UTF-16BE or UTF-8 with a BOM, else PDFDocEncoding.
pub(crate) fn text_string(raw: &[u8]) -> String {
    if raw.len() >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
        let units: Vec<u16> = raw[2..].as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
        return strip_language_escapes(&String::from_utf16_lossy(&units));
    }
    if raw.len() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
        let units: Vec<u16> = raw[2..].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        return String::from_utf16_lossy(&units);
    }
    if let Some(rest) = raw.strip_prefix(b"\xEF\xBB\xBF") {
        return String::from_utf8_lossy(rest).into_owned();
    }
    raw.iter().map(|&b| pdfdoc_char(b)).filter(|&c| c != '\0').collect()
}

/// UTF-16 text strings may carry `ESC lang ESC` language codes; drop them.
fn strip_language_escapes(s: &str) -> String {
    if !s.contains('\u{1b}') {
        return s.to_string();
    }
    let mut out = String::new();
    let mut skip = false;
    for c in s.chars() {
        if c == '\u{1b}' {
            skip = !skip;
        } else if !skip {
            out.push(c);
        }
    }
    out
}

/// PDFDocEncoding (Annex D): Latin-1 except for 0x18–0x1F and 0x80–0xA0.
pub(crate) fn pdfdoc_char(b: u8) -> char {
    const HIGH: [char; 33] = [
        '\u{2022}', '\u{2020}', '\u{2021}', '\u{2026}', '\u{2014}', '\u{2013}', '\u{0192}', '\u{2044}', '\u{2039}',
        '\u{203A}', '\u{2212}', '\u{2030}', '\u{201E}', '\u{201C}', '\u{201D}', '\u{2018}', '\u{2019}', '\u{201A}',
        '\u{2122}', '\u{FB01}', '\u{FB02}', '\u{0141}', '\u{0152}', '\u{0160}', '\u{0178}', '\u{017D}', '\u{0131}',
        '\u{0142}', '\u{0153}', '\u{0161}', '\u{017E}', '\u{FFFD}', '\u{20AC}',
    ];
    const LOW: [char; 8] =
        ['\u{02D8}', '\u{02C7}', '\u{02C6}', '\u{02D9}', '\u{02DD}', '\u{02DB}', '\u{02DA}', '\u{02DC}'];
    match b {
        0x18..=0x1F => LOW[usize::from(b - 0x18)],
        0x80..=0xA0 => HIGH[usize::from(b - 0x80)],
        _ => char::from(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Obj {
        Lexer::new(s.as_bytes()).object().unwrap()
    }

    #[test]
    fn parses_objects() {
        let o =
            parse("<< /Type /Page /Kids [1 0 R 2 0 R] /Count 2 /T (a\\(b\\)\\101) /H <48 65 6c> /N /A#20B /R -1.5 >> ");
        let d = o.as_dict().unwrap();
        assert_eq!(d.name("Type"), Some("Page"));
        assert_eq!(d.get("Kids"), Some(&Obj::Array(vec![Obj::Ref(1, 0), Obj::Ref(2, 0)])));
        assert_eq!(d.int("Count"), Some(2));
        assert_eq!(d.get("T").and_then(Obj::as_str), Some(&b"a(b)A"[..]));
        assert_eq!(d.get("H").and_then(Obj::as_str), Some(&b"Hel"[..]));
        assert_eq!(d.name("N"), Some("A B"));
        assert_eq!(d.get("R"), Some(&Obj::Real(-1.5)));
    }

    #[test]
    fn incomplete_input_asks_for_more() {
        assert_eq!(Lexer::new(b"<< /A (unterminated").object(), Err(ParseError::Incomplete));
        assert_eq!(Lexer::new(b"[1 0").object(), Err(ParseError::Incomplete));
    }

    #[test]
    fn decodes_text_strings() {
        assert_eq!(text_string(b"\xFE\xFF\x00H\x00i"), "Hi");
        assert_eq!(text_string(b"caf\xE9 \x8Dq\x8E \x93"), "café \u{201C}q\u{201D} \u{FB01}");
    }
}
