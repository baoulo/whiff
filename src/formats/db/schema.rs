//! The column list of a `CREATE TABLE` statement, read the way SQLite
//! reads it: a column is a name, an optional type (any words up to the
//! first constraint keyword) and constraints; table constraints add primary
//! keys and foreign keys. Not a full SQL parser: expressions inside
//! `CHECK`, `DEFAULT` and generated columns are skipped by bracket depth.
//!
//! Specification: SQLite "CREATE TABLE" (`column-def`, `table-constraint`).

use serde_json::{Map, Value};

/// One column.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Column {
    pub name: String,
    /// Declared type exactly as written; empty when none.
    pub kind: String,
    pub primary_key: bool,
    pub not_null: bool,
    /// Table named by `REFERENCES`.
    pub references: Option<String>,
}

impl Column {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("name".into(), self.name.clone().into());
        if !self.kind.is_empty() {
            m.insert("type".into(), self.kind.clone().into());
        }
        if self.primary_key {
            m.insert("primary_key".into(), true.into());
        }
        if self.not_null {
            m.insert("not_null".into(), true.into());
        }
        if let Some(r) = &self.references {
            m.insert("references".into(), r.clone().into());
        }
        Value::Object(m)
    }
}

/// What a `CREATE TABLE` says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Table {
    pub columns: Vec<Column>,
    pub without_rowid: bool,
    pub strict: bool,
    /// `CREATE VIRTUAL TABLE … USING module(…)`.
    pub module: Option<String>,
    /// `CREATE TABLE … AS SELECT`.
    pub as_select: bool,
}

/// Most columns read from one statement.
const MAX_COLUMNS: usize = 2000;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok<'a> {
    Word(&'a str),
    /// A quoted identifier or string, unquoted.
    Quoted(String),
    Open,
    Close,
    Comma,
    Other,
}

/// The tokens of `sql` with their byte spans.
fn tokens(sql: &str) -> (Vec<Tok<'_>>, Vec<(usize, usize)>) {
    let b = sql.as_bytes();
    let mut out = Vec::new();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let (before, start) = (out.len(), i);
        match c {
            b'(' => {
                out.push(Tok::Open);
                i += 1;
            }
            b')' => {
                out.push(Tok::Close);
                i += 1;
            }
            b',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            b'-' if b.get(i + 1) == Some(&b'-') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            b'"' | b'\'' | b'`' | b'[' => {
                let close = if c == b'[' { b']' } else { c };
                let mut s = Vec::new();
                i += 1;
                while i < b.len() {
                    if b[i] == close {
                        // Doubled quotes stand for one (not inside brackets).
                        if close != b']' && b.get(i + 1) == Some(&close) {
                            s.push(close);
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    s.push(b[i]);
                    i += 1;
                }
                i += 1;
                out.push(Tok::Quoted(String::from_utf8_lossy(&s).into_owned()));
            }
            c if c.is_ascii_whitespace() => i += 1,
            c if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c >= 0x80 => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$' || b[i] >= 0x80) {
                    i += 1;
                }
                // Split only on character boundaries (the loop never stops in
                // the middle of a UTF-8 sequence: continuation bytes are >= 0x80).
                out.push(Tok::Word(&sql[start..i]));
            }
            _ => {
                out.push(Tok::Other);
                i += 1;
            }
        }
        if out.len() > before {
            spans.push((start, i.min(b.len())));
        }
    }
    (out, spans)
}

fn word_is(t: &Tok<'_>, w: &str) -> bool {
    matches!(t, Tok::Word(x) if x.eq_ignore_ascii_case(w))
}

fn text(t: &Tok<'_>) -> Option<String> {
    match t {
        Tok::Word(w) => Some((*w).to_string()),
        Tok::Quoted(q) => Some(q.clone()),
        _ => None,
    }
}

/// Words that end a column's type and start its constraints.
const CONSTRAINT_WORDS: &[&str] =
    &["CONSTRAINT", "PRIMARY", "NOT", "NULL", "UNIQUE", "CHECK", "DEFAULT", "COLLATE", "REFERENCES", "GENERATED", "AS"];

/// Type names SQLite knows by name (the STRICT types).
const STANDARD_TYPES: &[&str] = &["INT", "INTEGER", "REAL", "TEXT", "BLOB", "ANY"];

/// Words that start a table constraint.
const TABLE_CONSTRAINTS: &[&str] = &["CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN"];

/// Parse a `CREATE [TEMP] [VIRTUAL] TABLE` statement.
pub(crate) fn create_table(sql: &str) -> Option<Table> {
    let (t, spans) = tokens(sql);
    let mut table = Table::default();
    let open = t.iter().position(|x| *x == Tok::Open);
    let using = t.iter().position(|x| word_is(x, "USING"));
    if t.iter().take(4).any(|x| word_is(x, "VIRTUAL")) {
        table.module = using.and_then(|u| t.get(u + 1)).and_then(text).map(|m| m.to_ascii_lowercase());
        return Some(table);
    }
    let as_at = t.iter().position(|x| word_is(x, "AS"));
    if as_at.is_some_and(|a| open.is_none_or(|o| a < o)) {
        table.as_select = true;
        return Some(table);
    }
    let open = open?;
    // Split the body at depth-1 commas.
    let mut depth = 0usize;
    let mut parts: Vec<(usize, usize)> = Vec::new();
    let mut start = open + 1;
    let mut end = t.len();
    for (i, tok) in t.iter().enumerate().skip(open) {
        match tok {
            Tok::Open => depth += 1,
            Tok::Close => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    parts.push((start, i));
                    end = i;
                    break;
                }
            }
            Tok::Comma if depth == 1 => {
                parts.push((start, i));
                start = i + 1;
            }
            _ => {}
        }
    }
    for opt in &t[end.min(t.len())..] {
        table.without_rowid |= word_is(opt, "ROWID");
        table.strict |= word_is(opt, "STRICT");
    }
    for (from, to) in parts {
        let part = &t[from..to];
        let Some(first) = part.first() else { continue };
        if matches!(first, Tok::Word(_)) && TABLE_CONSTRAINTS.iter().any(|w| word_is(first, w)) {
            table_constraint(part, &mut table.columns);
            continue;
        }
        if table.columns.len() >= MAX_COLUMNS {
            continue;
        }
        let Some(name) = text(first) else { continue };
        let mut col = Column { name, ..Column::default() };
        // The type: everything before the first constraint word outside
        // brackets, kept as written.
        let mut i = 1;
        let mut depth = 0usize;
        while i < part.len() {
            match &part[i] {
                Tok::Word(w) if depth == 0 && CONSTRAINT_WORDS.iter().any(|c| w.eq_ignore_ascii_case(c)) => break,
                Tok::Open => depth += 1,
                Tok::Close => depth = depth.saturating_sub(1),
                _ => {}
            }
            i += 1;
        }
        if i > 1 {
            let (a, b) = (spans[from + 1].0, spans[from + i - 1].1);
            col.kind = sql[a..b].to_string();
            // SQLite spells its own type names in capitals (`integer` is
            // reported as `INTEGER`); any other type stays as written.
            if STANDARD_TYPES.iter().any(|t| t.eq_ignore_ascii_case(&col.kind)) {
                col.kind.make_ascii_uppercase();
            }
        }
        // Constraints, skipping parenthesised expressions.
        let mut depth = 0usize;
        for (j, tok) in part.iter().enumerate().skip(i) {
            match tok {
                Tok::Open => depth += 1,
                Tok::Close => depth = depth.saturating_sub(1),
                _ if depth > 0 => {}
                x if word_is(x, "PRIMARY") => col.primary_key = true,
                x if word_is(x, "NULL") && j > 0 && word_is(&part[j - 1], "NOT") => col.not_null = true,
                x if word_is(x, "REFERENCES") => col.references = part.get(j + 1).and_then(text),
                _ => {}
            }
        }
        table.columns.push(col);
    }
    // The primary key of a WITHOUT ROWID or STRICT table cannot be NULL,
    // unless it is the rowid itself (a lone INTEGER PRIMARY KEY).
    let keys = table.columns.iter().filter(|c| c.primary_key).count();
    if table.without_rowid || table.strict {
        let rowid_alias = |c: &Column| !table.without_rowid && keys == 1 && c.kind == "INTEGER";
        let alias: Vec<bool> = table.columns.iter().map(rowid_alias).collect();
        for (c, a) in table.columns.iter_mut().zip(alias) {
            if c.primary_key && !a {
                c.not_null = true;
            }
        }
    }
    Some(table)
}

/// `PRIMARY KEY (a, b)` and `FOREIGN KEY (a) REFERENCES t` at table level.
fn table_constraint(part: &[Tok<'_>], cols: &mut [Column]) {
    let at = |w: &str| part.iter().position(|x| word_is(x, w));
    let names_after = |i: usize| -> Vec<String> {
        let mut out = Vec::new();
        let mut depth = 0;
        for tok in &part[i..] {
            match tok {
                Tok::Open => depth += 1,
                Tok::Close => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                x if depth == 1 => {
                    // The first word of each element (`a COLLATE x DESC`).
                    if let Some(n) = text(x)
                        && !matches!(x, Tok::Word(w) if ["COLLATE", "ASC", "DESC"].iter().any(|k| w.eq_ignore_ascii_case(k)))
                    {
                        out.push(n);
                    }
                }
                _ => {}
            }
        }
        out
    };
    if let Some(p) = at("PRIMARY") {
        for n in names_after(p) {
            if let Some(c) = cols.iter_mut().find(|c| c.name.eq_ignore_ascii_case(&n)) {
                c.primary_key = true;
            }
        }
    }
    if let (Some(f), Some(r)) = (at("FOREIGN"), at("REFERENCES")) {
        let target = part.get(r + 1).and_then(text);
        for n in names_after(f) {
            if let Some(c) = cols.iter_mut().find(|c| c.name.eq_ignore_ascii_case(&n)) {
                c.references.clone_from(&target);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_types_and_constraints() {
        let t = create_table(
            "CREATE TABLE \"tide readings\" (\n  id INTEGER PRIMARY KEY AUTOINCREMENT,\n  [station] TEXT NOT NULL \
             REFERENCES stations(id),\n  height DOUBLE PRECISION DEFAULT (0.0),\n  note VARCHAR(40, 2) COLLATE nocase,\n  \
             raw, -- untyped\n  CONSTRAINT k UNIQUE (station, raw),\n  FOREIGN KEY (raw) REFERENCES blobs\n) STRICT",
        )
        .unwrap();
        let names: Vec<&str> = t.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["id", "station", "height", "note", "raw"]);
        assert_eq!(t.columns[0].kind, "INTEGER");
        assert_eq!(t.columns[1].kind, "TEXT");
        assert!(t.columns[0].primary_key);
        assert!(t.columns[1].not_null);
        assert_eq!(t.columns[1].references.as_deref(), Some("stations"));
        assert_eq!(t.columns[2].kind, "DOUBLE PRECISION");
        assert_eq!(t.columns[3].kind, "VARCHAR(40, 2)");
        assert_eq!(t.columns[4].kind, "");
        assert_eq!(t.columns[4].references.as_deref(), Some("blobs"));
        assert!(t.strict && !t.without_rowid);
    }

    #[test]
    fn table_primary_key_virtual_and_as_select() {
        let t = create_table("CREATE TABLE k(a, b text, PRIMARY KEY(a DESC, b)) WITHOUT ROWID").unwrap();
        assert_eq!(t.columns[1].kind, "TEXT");
        assert!(t.columns[0].not_null, "WITHOUT ROWID keys are NOT NULL");
        assert!(t.columns.iter().all(|c| c.primary_key) && t.without_rowid);
        // STRICT: keys are NOT NULL, except the rowid alias.
        let s = create_table("CREATE TABLE s(id integer PRIMARY KEY, k TEXT) STRICT").unwrap();
        assert!(!s.columns[0].not_null);
        let s = create_table("CREATE TABLE s(a ANY, b INT, PRIMARY KEY(a, b)) STRICT").unwrap();
        assert!(s.columns.iter().all(|c| c.not_null));
        let v = create_table("CREATE VIRTUAL TABLE docs USING fts5(title, body)").unwrap();
        assert_eq!(v.module.as_deref(), Some("fts5"));
        assert!(create_table("CREATE TABLE c AS SELECT * FROM k").unwrap().as_select);
    }
}
