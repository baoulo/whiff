//! Text data formats without a parser crate, read by one tokenizer with
//! per-language rules and small parsers into a bounded tree for the shared
//! report (top-level type and keys, inferred schema, value count, depth,
//! tags):
//! * RON (Rusty Object Notation): struct names, tuples, maps, `Some`;
//! * KDL: nodes with arguments, properties and children (node names
//!   counted);
//! * HOCON: path keys, `include`s and `${substitutions}` counted;
//! * EDN: maps, vectors, sets, keywords, tagged literals counted;
//! * S-expressions: lists, with the head symbols counted;
//! * protobuf text format: fields, repeated fields, the `proto-file` /
//!   `proto-message` header comments;
//! * Amazon Ion text: structs, lists, s-expressions, annotations counted.
//!
//! Specifications: ron-rs grammar; KDL 2.0; Lightbend HOCON.md; edn-format
//! spec; Rivest S-expressions draft; protobuf.dev "Text Format Language
//! Specification"; Amazon Ion 1.0 text encoding.

use serde_json::{Map, Value, json};

use super::{Decoded, Fail, KEEP, Walk, report};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, truncate_chars,
};

/// Extractor for text data formats.
pub struct TextData;

const fn spec(id: &'static str, name: &'static str, extensions: &'static [&'static str]) -> FormatSpec {
    FormatSpec { id, name, family: "data.binser", mimes: &[], extensions, magic: &[], parent: Some("text") }
}

static META: ExtractorMeta = ExtractorMeta {
    id: "data.text",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        spec("ron", "RON", &["ron"]),
        spec("kdl", "KDL", &["kdl"]),
        spec("hocon", "HOCON", &["hocon"]),
        spec("edn", "EDN", &["edn"]),
        spec("sexp", "S-expressions data", &["sexp", "sx"]),
        spec("textproto", "Protobuf text format", &["textproto", "pbtxt", "txtpb", "prototxt"]),
        spec("ion_text", "Ion text", &["ion"]),
    ],
};

/// A token.
#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Str(String),
    Num(String),
    Word(String),
    P(char),
    Nl,
    /// HOCON `${path}`.
    Subst,
    /// EDN `#tag`.
    Tag(String),
    /// EDN `#_`.
    Discard,
    /// EDN `#{`.
    SetOpen,
    /// Ion `::`.
    Annot,
}

/// Tokenizer rules of one language.
#[allow(clippy::struct_excessive_bools)] // independent lexical switches
struct Rules {
    line_comments: &'static [&'static str],
    block_comments: bool,
    newlines: bool,
    punct: &'static str,
    edn: bool,
    single_quotes: bool,
    /// `#"…"#` raw strings (KDL).
    raw_hash: bool,
    /// `${…}` substitutions (HOCON).
    subst: bool,
    /// `{{ … }}` blobs and clobs (Ion).
    lobs: bool,
}

fn rules(format: &str) -> Rules {
    let base = Rules {
        line_comments: &["//"],
        block_comments: true,
        newlines: false,
        punct: "{}[](),:",
        edn: false,
        single_quotes: false,
        raw_hash: false,
        subst: false,
        lobs: false,
    };
    match format {
        "ron" => Rules { punct: "()[]{}:,", single_quotes: true, ..base },
        "kdl" => Rules { newlines: true, punct: "(){};=", raw_hash: true, ..base },
        "hocon" => Rules {
            line_comments: &["#", "//"],
            block_comments: false,
            newlines: true,
            punct: "[]{}:=,",
            subst: true,
            ..base
        },
        "edn" => Rules { line_comments: &[";"], block_comments: false, punct: "()[]{}", edn: true, ..base },
        "sexp" => Rules { line_comments: &[";"], block_comments: false, punct: "()[]{}", ..base },
        "textproto" => {
            Rules { line_comments: &["#"], block_comments: false, punct: "{}[]<>:,;", single_quotes: true, ..base }
        }
        _ => Rules { single_quotes: true, lobs: true, ..base },
    }
}

/// Characters of text tokenized.
const MAX_TOKENS: usize = 4_000_000;

#[allow(clippy::too_many_lines)] // one branch per lexical form
fn tokenize(text: &str, r: &Rules) -> Result<Vec<Tok>, Fail> {
    let c: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let delim = |ch: char| ch.is_whitespace() || r.punct.contains(ch) || ch == '"' || (r.edn && ch == ',');
    while i < c.len() {
        if out.len() > MAX_TOKENS {
            return Err("too many tokens");
        }
        let ch = c[i];
        let rest: String = c[i..c.len().min(i + 3)].iter().collect();
        if ch == '\n' {
            if r.newlines {
                out.push(Tok::Nl);
            }
            i += 1;
            continue;
        }
        if ch == '\\' && r.newlines && c.get(i + 1) == Some(&'\n') {
            i += 2;
            continue;
        }
        if ch.is_whitespace() || (r.edn && ch == ',') {
            i += 1;
            continue;
        }
        if r.line_comments.iter().any(|lc| rest.starts_with(lc)) {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if r.block_comments && rest.starts_with("/*") {
            i += 2;
            while i + 1 < c.len() && !(c[i] == '*' && c[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            continue;
        }
        // Strings: triple-quoted, raw (`r#"…"#`, `#"…"#`), double and single quoted.
        let triple = rest == "\"\"\"" || (r.single_quotes && rest == "'''");
        if triple {
            let q = ch;
            i += 3;
            let start = i;
            while i + 2 < c.len() && !(c[i] == q && c[i + 1] == q && c[i + 2] == q) {
                i += 1;
            }
            out.push(Tok::Str(c[start..i.min(c.len())].iter().collect()));
            i += 3;
            continue;
        }
        let raw_start = (ch == 'r' && !r.raw_hash && matches!(c.get(i + 1), Some('"' | '#')))
            || (ch == '#' && r.raw_hash && matches!(c.get(i + 1), Some('"' | '#')));
        if raw_start {
            let mut j = i + usize::from(ch == 'r');
            let mut hashes = 0;
            while c.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if c.get(j) == Some(&'"') {
                j += 1;
                let start = j;
                let close: Vec<char> = std::iter::once('"').chain(std::iter::repeat_n('#', hashes)).collect();
                while j < c.len() && !c[j..].starts_with(&close) {
                    j += 1;
                }
                out.push(Tok::Str(c[start..j.min(c.len())].iter().collect()));
                i = j + close.len();
                continue;
            }
        }
        if ch == '"' || (r.single_quotes && ch == '\'') {
            let mut s = String::new();
            i += 1;
            while i < c.len() && c[i] != ch {
                if c[i] == '\\' && i + 1 < c.len() {
                    i += 1;
                    s.push(match c[i] {
                        'n' => '\n',
                        't' => '\t',
                        other => other,
                    });
                } else {
                    s.push(c[i]);
                }
                i += 1;
            }
            i += 1;
            out.push(Tok::Str(s));
            continue;
        }
        if r.edn && ch == '#' {
            match c.get(i + 1) {
                Some('{') => {
                    out.push(Tok::SetOpen);
                    i += 2;
                }
                Some('_') => {
                    out.push(Tok::Discard);
                    i += 2;
                }
                _ => {
                    let start = i + 1;
                    i = start;
                    while i < c.len() && !delim(c[i]) {
                        i += 1;
                    }
                    out.push(Tok::Tag(c[start..i].iter().collect()));
                }
            }
            continue;
        }
        if r.subst && ch == '$' && c.get(i + 1) == Some(&'{') {
            while i < c.len() && c[i] != '}' {
                i += 1;
            }
            i += 1;
            out.push(Tok::Subst);
            continue;
        }
        if ch == ':' && c.get(i + 1) == Some(&':') && !r.edn {
            out.push(Tok::Annot);
            i += 2;
            continue;
        }
        if r.lobs && ch == '{' && c.get(i + 1) == Some(&'{') {
            // Ion blob / clob.
            while i + 1 < c.len() && !(c[i] == '}' && c[i + 1] == '}') {
                i += 1;
            }
            i += 2;
            out.push(Tok::Str("<lob>".into()));
            continue;
        }
        if r.punct.contains(ch) {
            out.push(Tok::P(ch));
            i += 1;
            continue;
        }
        let start = i;
        // Ion timestamps (`2025-01-01T00:00Z`) run through colons.
        let stamp = r.lobs && ch.is_ascii_digit();
        while i < c.len()
            && (!delim(c[i]) || (stamp && c[i] == ':'))
            && !(c[i] == ':' && c.get(i + 1) == Some(&':') && !r.edn)
        {
            i += 1;
        }
        let word: String = c[start..i].iter().collect();
        let numeric = word.chars().next().is_some_and(|f| f.is_ascii_digit())
            || (word.len() > 1
                && word.starts_with(['-', '+', '.'])
                && word[1..].starts_with(|x: char| x.is_ascii_digit()));
        out.push(if numeric { Tok::Num(word) } else { Tok::Word(word) });
    }
    Ok(out)
}

/// A parser over tokens.
struct P<'w> {
    t: Vec<Tok>,
    i: usize,
    w: &'w mut Walk,
}

fn number(s: &str) -> Value {
    let clean: String = s.chars().filter(|&c| c != '_').collect();
    if let Ok(n) = clean.parse::<i64>() {
        return json!(n);
    }
    if let Some(h) = clean.strip_prefix("0x").and_then(|h| i64::from_str_radix(h, 16).ok()) {
        return json!(h);
    }
    match clean.trim_end_matches(['f', 'M', 'N']).parse::<f64>() {
        Ok(f) if f.is_finite() && !clean.contains([':', 'T']) => json!(f),
        _ => Value::String(truncate_chars(s, 100)),
    }
}

/// Add a field that may repeat: the second occurrence turns it into a list.
fn repeated(m: &mut Map<String, Value>, name: String, v: Value) {
    let room = m.len() < KEEP;
    match m.get_mut(&name) {
        Some(Value::Array(a)) => {
            if a.len() < KEEP {
                a.push(v);
            }
        }
        Some(old) => {
            let first = old.take();
            *old = Value::Array(vec![first, v]);
        }
        None if room => {
            m.insert(name, v);
        }
        None => {}
    }
}

impl P<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.t.get(self.i).cloned();
        self.i += 1;
        t
    }

    fn eat(&mut self, p: char) -> bool {
        if self.peek() == Some(&Tok::P(p)) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn skip_seps(&mut self) {
        while matches!(self.peek(), Some(Tok::Nl | Tok::P(',' | ';'))) {
            self.i += 1;
        }
    }

    fn string(&mut self, s: &str) -> Value {
        self.w.string(s);
        Value::String(truncate_chars(s, 2000))
    }

    fn scalar(&mut self, t: Tok) -> Value {
        match t {
            Tok::Str(s) => self.string(&s),
            Tok::Num(n) => number(&n),
            Tok::Word(w) => match w.as_str() {
                "true" | "#true" => json!(true),
                "false" | "#false" => json!(false),
                "nil" | "null" | "None" | "#null" | "null.null" => Value::Null,
                _ => Value::String(truncate_chars(&w, 200)),
            },
            _ => Value::Null,
        }
    }

    // EDN and S-expressions ---------------------------------------------------

    fn lisp(&mut self, heads: bool) -> Result<Value, Fail> {
        self.w.value()?;
        let t = self.next().ok_or("truncated")?;
        Ok(match t {
            Tok::P(open @ ('(' | '[' | '{')) => {
                let close = match open {
                    '(' => ')',
                    '[' => ']',
                    _ => '}',
                };
                let items = self.lisp_items(close, heads, heads && open == '(')?;
                if open == '{' {
                    let mut m = Map::new();
                    let mut it = items.into_iter();
                    while let (Some(k), Some(v)) = (it.next(), it.next()) {
                        m.insert(super::key_of(&k), v);
                    }
                    Value::Object(m)
                } else {
                    Value::Array(items)
                }
            }
            Tok::SetOpen => {
                self.w.tag("set");
                Value::Array(self.lisp_items('}', heads, false)?)
            }
            Tok::Tag(tag) => {
                self.w.tag(format!("#{}", truncate_chars(&tag, 40)));
                self.lisp(heads)?
            }
            Tok::Discard => {
                self.lisp(heads)?;
                return self.lisp(heads);
            }
            Tok::P(_) => return Err("unexpected closing bracket"),
            t => self.scalar(t),
        })
    }

    /// Values up to `close`; `head` counts the first symbol.
    fn lisp_items(&mut self, close: char, heads: bool, head: bool) -> Result<Vec<Value>, Fail> {
        self.w.enter()?;
        let mut items = Vec::new();
        while !self.eat(close) {
            if self.peek().is_none() {
                return Err("unbalanced");
            }
            if self.peek() == Some(&Tok::Discard) {
                self.i += 1;
                self.lisp(heads)?;
                continue;
            }
            let v = self.lisp(heads)?;
            if head
                && items.is_empty()
                && let Value::String(h) = &v
            {
                self.w.tag(format!("head:{}", truncate_chars(h, 40)));
            }
            if items.len() < 2 * KEEP {
                items.push(v);
            }
        }
        self.w.leave();
        Ok(items)
    }

    // RON ---------------------------------------------------------------------

    fn ron(&mut self) -> Result<Value, Fail> {
        self.w.value()?;
        let t = self.next().ok_or("truncated")?;
        Ok(match t {
            Tok::Word(name) if self.peek() == Some(&Tok::P('(')) => {
                self.i += 1;
                if name == "Some" {
                    let v = self.ron()?;
                    self.eat(',');
                    if !self.eat(')') {
                        return Err("unclosed Some(");
                    }
                    return Ok(v);
                }
                self.w.tag(format!("struct:{}", truncate_chars(&name, 60)));
                self.ron_parens()?
            }
            Tok::P('(') => self.ron_parens()?,
            Tok::P('[') => {
                self.w.enter()?;
                let mut items = Vec::new();
                loop {
                    self.skip_seps();
                    if self.eat(']') {
                        break;
                    }
                    let v = self.ron()?;
                    if items.len() < KEEP {
                        items.push(v);
                    }
                }
                self.w.leave();
                Value::Array(items)
            }
            Tok::P('{') => {
                self.w.enter()?;
                let mut m = Map::new();
                loop {
                    self.skip_seps();
                    if self.eat('}') {
                        break;
                    }
                    let k = self.ron()?;
                    if !self.eat(':') {
                        return Err("expected ':' in a map");
                    }
                    let v = self.ron()?;
                    if m.len() < KEEP {
                        m.insert(super::key_of(&k), v);
                    }
                }
                self.w.leave();
                Value::Object(m)
            }
            Tok::P(_) => return Err("unexpected punctuation"),
            t => self.scalar(t),
        })
    }

    /// The inside of `( … )`: named fields make an object, else a tuple.
    fn ron_parens(&mut self) -> Result<Value, Fail> {
        self.w.enter()?;
        let named = matches!(self.peek(), Some(Tok::Word(_))) && self.t.get(self.i + 1) == Some(&Tok::P(':'));
        let (mut m, mut items) = (Map::new(), Vec::new());
        loop {
            self.skip_seps();
            if self.eat(')') {
                break;
            }
            if named {
                let Some(Tok::Word(k)) = self.next() else { return Err("expected a field name") };
                if !self.eat(':') {
                    return Err("expected ':' after a field name");
                }
                let v = self.ron()?;
                if m.len() < KEEP {
                    m.insert(k, v);
                }
            } else {
                let v = self.ron()?;
                if items.len() < KEEP {
                    items.push(v);
                }
            }
        }
        self.w.leave();
        Ok(if named { Value::Object(m) } else { Value::Array(items) })
    }

    // HOCON -------------------------------------------------------------------

    fn hocon_object(&mut self, close: Option<char>) -> Result<Value, Fail> {
        self.w.enter()?;
        let mut m = Map::new();
        loop {
            self.skip_seps();
            match self.peek() {
                None if close.is_none() => break,
                None => return Err("unclosed object"),
                Some(Tok::P(c)) if Some(*c) == close => {
                    self.i += 1;
                    break;
                }
                _ => {}
            }
            let key = match self.next() {
                Some(Tok::Word(w)) if w == "include" => {
                    self.w.tag("include");
                    while !matches!(self.peek(), None | Some(Tok::Nl | Tok::P(',' | '}'))) {
                        self.i += 1;
                    }
                    continue;
                }
                Some(Tok::Word(w) | Tok::Str(w) | Tok::Num(w)) => w,
                _ => return Err("expected a key"),
            };
            let key = key.trim_end_matches("+=").to_string();
            if !(self.eat(':') || self.eat('=')) && self.peek() != Some(&Tok::P('{')) {
                if let Some(Tok::Word(w)) = self.peek()
                    && w == "+="
                {
                    self.i += 1;
                } else if !matches!(self.peek(), Some(Tok::P('{'))) {
                    return Err("expected ':' or '=' after a key");
                }
            }
            let v = self.hocon_value()?;
            // `a.b.c = v` sets a nested path.
            let parts: Vec<&str> = key.split('.').filter(|p| !p.is_empty()).collect();
            let mut target = &mut m;
            for p in parts.iter().take(parts.len().saturating_sub(1)) {
                let e = target.entry((*p).to_string()).or_insert_with(|| Value::Object(Map::new()));
                if !e.is_object() {
                    *e = Value::Object(Map::new());
                }
                target = e.as_object_mut().expect("object");
            }
            let last = parts.last().map_or_else(|| key.clone(), |p| (*p).to_string());
            let room = target.len() < KEEP;
            match (target.get_mut(&last), v) {
                (Some(Value::Object(old)), Value::Object(new)) => old.extend(new),
                (_, v) if room => {
                    target.insert(last, v);
                }
                _ => {}
            }
        }
        self.w.leave();
        Ok(Value::Object(m))
    }

    fn hocon_value(&mut self) -> Result<Value, Fail> {
        self.w.value()?;
        if self.eat('{') {
            return self.hocon_object(Some('}'));
        }
        if self.eat('[') {
            self.w.enter()?;
            let mut items = Vec::new();
            loop {
                self.skip_seps();
                if self.eat(']') {
                    break;
                }
                if self.peek().is_none() {
                    return Err("unclosed array");
                }
                let v = self.hocon_value()?;
                if items.len() < KEEP {
                    items.push(v);
                }
            }
            self.w.leave();
            return Ok(Value::Array(items));
        }
        // A concatenation of simple values up to the end of the field.
        let mut parts = Vec::new();
        while let Some(t) = self.peek() {
            if matches!(t, Tok::Nl | Tok::P(',' | '}' | ']')) {
                break;
            }
            let t = self.next().ok_or("truncated")?;
            if t == Tok::Subst {
                self.w.tag("substitution");
            }
            parts.push(t);
        }
        Ok(match parts.len() {
            0 => Value::Null,
            1 => {
                let t = parts.pop().ok_or("truncated")?;
                if t == Tok::Subst { Value::String("${…}".into()) } else { self.scalar(t) }
            }
            _ => {
                let s: Vec<String> = parts
                    .into_iter()
                    .map(|t| match t {
                        Tok::Str(s) | Tok::Num(s) | Tok::Word(s) => s,
                        _ => "${…}".into(),
                    })
                    .collect();
                self.string(&s.join(" "))
            }
        })
    }

    // KDL ---------------------------------------------------------------------

    fn kdl_nodes(&mut self, nested: bool) -> Result<Value, Fail> {
        self.w.enter()?;
        let mut m = Map::new();
        loop {
            self.skip_seps();
            match self.peek() {
                None if !nested => break,
                None => return Err("unclosed children block"),
                Some(Tok::P('}')) if nested => {
                    self.i += 1;
                    break;
                }
                _ => {}
            }
            let dashed = self.slashdash();
            let (name, node) = self.kdl_node()?;
            if dashed {
                continue;
            }
            self.w.tag(format!("node:{}", truncate_chars(&name, 40)));
            repeated(&mut m, name, node);
        }
        self.w.leave();
        Ok(Value::Object(m))
    }

    /// A `/-` comment on the next node, entry or block (consumed).
    fn slashdash(&mut self) -> bool {
        let Some(Tok::Word(w)) = self.peek() else { return false };
        if w == "/-" {
            self.i += 1;
            return true;
        }
        if let Some(rest) = w.strip_prefix("/-") {
            self.t[self.i] = Tok::Word(rest.to_string());
            return true;
        }
        false
    }

    fn kdl_annotation(&mut self) {
        if self.peek() == Some(&Tok::P('(')) {
            while !matches!(self.next(), None | Some(Tok::P(')'))) {}
        }
    }

    fn kdl_node(&mut self) -> Result<(String, Value), Fail> {
        self.w.value()?;
        self.kdl_annotation();
        let Some(Tok::Word(name) | Tok::Str(name) | Tok::Num(name)) = self.next() else {
            return Err("expected a node name");
        };
        let (mut args, mut props) = (Vec::new(), Map::new());
        let mut children = None;
        loop {
            match self.peek() {
                None | Some(Tok::Nl | Tok::P(';' | '}')) => break,
                Some(Tok::P('{')) => {
                    self.i += 1;
                    children = Some(self.kdl_nodes(true)?);
                    continue;
                }
                _ => {}
            }
            let dashed = self.slashdash();
            if dashed && self.eat('{') {
                self.kdl_nodes(true)?;
                continue;
            }
            self.kdl_annotation();
            let t = self.next().ok_or("truncated")?;
            if self.eat('=') {
                self.kdl_annotation();
                let v = self.next().ok_or("truncated")?;
                let v = self.scalar(v);
                if !dashed && let Tok::Word(k) | Tok::Str(k) = t {
                    props.insert(k, v);
                }
            } else {
                let v = self.scalar(t);
                if !dashed && args.len() < KEEP {
                    args.push(v);
                }
            }
        }
        let mut node = Map::new();
        if !args.is_empty() {
            node.insert("args".into(), Value::Array(args));
        }
        node.extend(props);
        if let Some(c) = children {
            node.insert("children".into(), c);
        }
        Ok((name, Value::Object(node)))
    }

    // Protobuf text format ----------------------------------------------------

    fn textproto(&mut self, close: Option<char>) -> Result<Value, Fail> {
        self.w.enter()?;
        let mut m = Map::new();
        loop {
            self.skip_seps();
            match self.peek() {
                None if close.is_none() => break,
                None => return Err("unclosed message"),
                Some(Tok::P(c)) if Some(*c) == close => {
                    self.i += 1;
                    break;
                }
                _ => {}
            }
            let name = match self.next() {
                Some(Tok::Word(w)) => w,
                Some(Tok::P('[')) => {
                    let mut n = String::new();
                    while let Some(t) = self.next() {
                        match t {
                            Tok::P(']') => break,
                            Tok::Word(w) => n.push_str(&w),
                            _ => {}
                        }
                    }
                    format!("[{n}]")
                }
                _ => return Err("expected a field name"),
            };
            self.eat(':');
            let v = self.textproto_value()?;
            repeated(&mut m, name, v);
        }
        self.w.leave();
        Ok(Value::Object(m))
    }

    fn textproto_value(&mut self) -> Result<Value, Fail> {
        self.w.value()?;
        if self.eat('{') {
            return self.textproto(Some('}'));
        }
        if self.eat('<') {
            return self.textproto(Some('>'));
        }
        if self.eat('[') {
            let mut items = Vec::new();
            loop {
                self.skip_seps();
                if self.eat(']') {
                    break;
                }
                if self.peek().is_none() {
                    return Err("unclosed list");
                }
                let v = self.textproto_value()?;
                if items.len() < KEEP {
                    items.push(v);
                }
            }
            return Ok(Value::Array(items));
        }
        let t = self.next().ok_or("truncated")?;
        // Adjacent strings concatenate.
        if let Tok::Str(mut s) = t {
            while let Some(Tok::Str(more)) = self.peek().cloned() {
                s.push_str(&more);
                self.i += 1;
            }
            return Ok(self.string(&s));
        }
        if matches!(t, Tok::P(_)) {
            return Err("expected a value");
        }
        Ok(self.scalar(t))
    }

    // Ion text ----------------------------------------------------------------

    fn ion(&mut self) -> Result<Value, Fail> {
        self.w.value()?;
        while matches!(self.peek(), Some(Tok::Word(_) | Tok::Str(_))) && self.t.get(self.i + 1) == Some(&Tok::Annot) {
            if let Some(Tok::Word(a) | Tok::Str(a)) = self.next() {
                self.w.tag(format!("annotation:{}", truncate_chars(&a, 40)));
            }
            self.i += 1;
        }
        let t = self.next().ok_or("truncated")?;
        Ok(match t {
            Tok::P('{') => {
                self.w.enter()?;
                let mut m = Map::new();
                loop {
                    self.skip_seps();
                    if self.eat('}') {
                        break;
                    }
                    let Some(Tok::Word(k) | Tok::Str(k)) = self.next() else {
                        return Err("expected a field name");
                    };
                    if !self.eat(':') {
                        return Err("expected ':'");
                    }
                    let v = self.ion()?;
                    if m.len() < KEEP {
                        m.insert(k, v);
                    }
                }
                self.w.leave();
                Value::Object(m)
            }
            Tok::P(open @ ('[' | '(')) => {
                let close = if open == '[' { ']' } else { ')' };
                self.w.enter()?;
                let mut items = Vec::new();
                loop {
                    self.skip_seps();
                    if self.eat(close) {
                        break;
                    }
                    if self.peek().is_none() {
                        return Err("unclosed list");
                    }
                    let v = self.ion()?;
                    if items.len() < KEEP {
                        items.push(v);
                    }
                }
                self.w.leave();
                Value::Array(items)
            }
            Tok::P(_) => return Err("unexpected punctuation"),
            t => self.scalar(t),
        })
    }
}

impl Extractor for TextData {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let ext = probe.extension?;
        let format = META.formats.iter().find(|f| f.extensions.contains(&ext))?.id;
        // Binary Ion is `data.binser`'s.
        if format == "ion_text" && probe.head.starts_with(b"\xe0\x01\x00\xea") {
            return None;
        }
        std::str::from_utf8(&probe.head[..probe.head.len().min(4096)]).ok()?;
        Some(Sniff { format, confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.emit_text(TextRole::Data, &text);
        let format = cx.format_id().to_string();
        let mut text = text.trim_start_matches('\u{feff}').to_string();
        if format == "ron" {
            // `#![enable(…)]` attributes.
            while let Some(rest) = text.trim_start().strip_prefix("#!") {
                let end = rest.find(']').map_or(rest.len(), |i| i + 1);
                cx.format_set("extensions_enabled", true);
                text = rest[end..].to_string();
            }
        }
        if format == "textproto" {
            for line in text.lines().take_while(|l| l.starts_with('#') || l.trim().is_empty()) {
                for (k, out) in [("proto-file:", "proto_file"), ("proto-message:", "proto_message")] {
                    if let Some(v) = line.trim_start_matches(['#', ' ']).strip_prefix(k) {
                        cx.format_set(out, truncate_chars(v.trim(), 300));
                    }
                }
            }
        }
        let toks = tokenize(&text, &rules(&format)).map_err(ExtractError::malformed)?;
        let mut w = Walk::default();
        let mut p = P { t: toks, i: 0, w: &mut w };
        let mut d = Decoded::default();
        let push = |d: &mut Decoded, r: Result<Value, Fail>| -> bool {
            match r {
                Ok(v) => {
                    d.documents += 1;
                    if d.docs.len() < super::SAMPLE_DOCS {
                        d.docs.push(v);
                    }
                    true
                }
                Err(e) => {
                    d.error = Some(e);
                    false
                }
            }
        };
        match format.as_str() {
            "hocon" => {
                p.skip_seps();
                let r = match p.peek() {
                    Some(Tok::P('{')) => {
                        p.i += 1;
                        p.hocon_object(Some('}'))
                    }
                    Some(Tok::P('[')) => p.hocon_value(),
                    _ => p.hocon_object(None),
                };
                push(&mut d, r);
            }
            "kdl" => {
                let r = p.kdl_nodes(false);
                push(&mut d, r);
            }
            "textproto" => {
                let r = p.textproto(None);
                push(&mut d, r);
            }
            _ => loop {
                p.skip_seps();
                if p.peek().is_none() {
                    break;
                }
                if format == "ion_text" && p.peek() == Some(&Tok::Word("$ion_1_0".into())) {
                    p.i += 1;
                    continue;
                }
                let r = match format.as_str() {
                    "ron" => p.ron(),
                    "ion_text" => p.ion(),
                    f => p.lisp(f == "sexp"),
                };
                if !push(&mut d, r) {
                    break;
                }
            },
        }
        if d.documents == 0 {
            return Err(ExtractError::malformed(d.error.unwrap_or("no value")));
        }
        cx.checkpoint()?;
        report(cx, &d, &w);
        Ok(())
    }
}

crate::register_extractor!(TextData);

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(format: &str, text: &str) -> Value {
        let mut w = Walk::default();
        let mut p = P { t: tokenize(text, &rules(format)).unwrap(), i: 0, w: &mut w };
        match format {
            "ron" => p.ron(),
            "kdl" => p.kdl_nodes(false),
            "hocon" => p.hocon_object(None),
            "textproto" => p.textproto(None),
            "ion_text" => p.ion(),
            f => p.lisp(f == "sexp"),
        }
        .unwrap()
    }

    #[test]
    fn ron() {
        let v = parse("ron", "Tide(height: 1.5, name: \"neap\", next: Some((1, 2)), tags: [\"a\"], m: {\"k\": true})");
        assert_eq!(v, json!({ "height": 1.5, "name": "neap", "next": [1, 2], "tags": ["a"], "m": { "k": true } }));
    }

    #[test]
    fn kdl() {
        let v = parse("kdl", "harbour \"North\" depth=12 {\n  buoy 1\n  buoy 2\n}\n/-ignored 3\n");
        assert_eq!(
            v,
            json!({ "harbour": { "args": ["North"], "depth": 12, "children": { "buoy": [{ "args": [1] }, { "args": [2] }] } } })
        );
    }

    #[test]
    fn hocon() {
        let v = parse("hocon", "include \"base.conf\"\na.b = 1\na { c: x y }\nlist = [1, 2]\nref = ${a.b}\n");
        assert_eq!(v, json!({ "a": { "b": 1, "c": "x y" }, "list": [1, 2], "ref": "${…}" }));
    }

    #[test]
    fn edn_and_sexp() {
        let v = parse("edn", "{:tide #inst \"2025-01-01\" :levels [1 2] :set #{:a} #_ :gone :k nil}");
        assert_eq!(v, json!({ ":tide": "2025-01-01", ":levels": [1, 2], ":set": [":a"], ":k": null }));
        assert_eq!(parse("sexp", "(define (f x) (* x 2))"), json!(["define", ["f", "x"], ["*", "x", 2]]));
    }

    #[test]
    fn textproto_and_ion() {
        let v = parse("textproto", "name: \"tide\" level { height: 3 } level < height: 4 > tags: [\"a\", \"b\"]");
        assert_eq!(v, json!({ "name": "tide", "level": [{ "height": 3 }, { "height": 4 }], "tags": ["a", "b"] }));
        let v = parse("ion_text", "tide::{ height: 1.5, at: 2025-01-01T00:00Z, tags: [a, 'b c'], s: (+ 1 2) }");
        assert_eq!(v, json!({ "height": 1.5, "at": "2025-01-01T00:00Z", "tags": ["a", "b c"], "s": ["+", 1, 2] }));
    }

    #[test]
    fn unbalanced_input_fails() {
        let mut w = Walk::default();
        let mut p = P { t: tokenize("[1 2", &rules("edn")).unwrap(), i: 0, w: &mut w };
        assert!(p.lisp(false).is_err());
    }

    crate::fixture_tests!("ron", "kdl", "hocon", "edn", "sexp", "textproto", "ion_text");
}
