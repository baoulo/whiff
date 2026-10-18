//! Content lines shared by iCalendar (RFC 5545), vCalendar 1.0, and vCard
//! 2.1 / 3.0 / 4.0 (RFC 6350): unfolding, `NAME;PARAM=VALUE:value`
//! splitting, parameter quoting, text escapes, vCard 2.1
//! quoted-printable, and `BEGIN` / `END` nesting.

/// One property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Prop {
    /// Upper-cased name, without a group prefix (`item1.EMAIL` → `EMAIL`).
    pub(crate) name: String,
    /// Upper-cased parameter names with their values; vCard 2.1 bare types
    /// (`TEL;CELL`) become `TYPE=CELL`.
    pub(crate) params: Vec<(String, String)>,
    /// The raw value (escapes still in place, see [`text`]).
    pub(crate) value: String,
}

impl Prop {
    pub(crate) fn param(&self, name: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// Whether any `TYPE` parameter lists `t` (case-insensitive).
    pub(crate) fn has_type(&self, t: &str) -> bool {
        self.params
            .iter()
            .filter(|(k, _)| k == "TYPE")
            .any(|(_, v)| v.split(',').any(|x| x.trim().eq_ignore_ascii_case(t)))
    }

    /// The value as text: escapes resolved (`\n`, `\,`, `\;`, `\\`).
    pub(crate) fn text(&self) -> String {
        text(&self.value)
    }
}

/// A component (`VEVENT`, `VCARD` …) with its properties and children.
#[derive(Debug, Clone, Default)]
pub(crate) struct Component {
    pub(crate) name: String,
    pub(crate) props: Vec<Prop>,
    pub(crate) children: Vec<Component>,
}

impl Component {
    pub(crate) fn get(&self, name: &str) -> Option<&Prop> {
        self.props.iter().find(|p| p.name == name)
    }

    pub(crate) fn all<'c>(&'c self, name: &'c str) -> impl Iterator<Item = &'c Prop> + 'c {
        self.props.iter().filter(move |p| p.name == name)
    }

    pub(crate) fn text(&self, name: &str) -> Option<String> {
        self.get(name).map(Prop::text).map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
    }

    /// Descendants named `name`, in document order (iteratively).
    pub(crate) fn find_all<'c>(&'c self, name: &str) -> Vec<&'c Component> {
        let mut out = Vec::new();
        let mut stack: Vec<&Component> = self.children.iter().rev().collect();
        while let Some(c) = stack.pop() {
            if c.name == name {
                out.push(c);
            }
            stack.extend(c.children.iter().rev());
        }
        out
    }
}

/// Resolve text escapes.
pub(crate) fn text(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n' | 'N') => out.push('\n'),
                Some(o) => out.push(o),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Split on unescaped `sep` (structured values: `N:Family;Given;;;`).
pub(crate) fn split(v: &str, sep: char) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut esc = false;
    for c in v.chars() {
        if esc {
            if let Some(s) = out.last_mut() {
                s.push('\\');
                s.push(c);
            }
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == sep {
            out.push(String::new());
        } else if let Some(s) = out.last_mut() {
            s.push(c);
        }
    }
    out.into_iter().map(|s| text(&s)).collect()
}

fn quoted_printable(v: &str, charset: Option<&str>) -> String {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'='
            && let Some(h) = v.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(h);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    match charset.map(str::to_ascii_lowercase).as_deref() {
        Some("utf-8") | None => String::from_utf8_lossy(&out).into_owned(),
        Some(cs) => encoding_rs::Encoding::for_label(cs.as_bytes())
            .unwrap_or(encoding_rs::WINDOWS_1252)
            .decode_without_bom_handling(&out)
            .0
            .into_owned(),
    }
}

/// Logical lines: folded lines joined, and vCard 2.1 quoted-printable
/// soft breaks (`=` at the end of a line) followed.
fn unfold(input: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut qp_continue = false;
    for raw in input.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if qp_continue {
            if let Some(last) = lines.last_mut() {
                last.pop(); // the soft-break `=`
                last.push_str(raw.trim_start());
            }
        } else if (raw.starts_with(' ') || raw.starts_with('\t')) && !lines.is_empty() {
            if let Some(last) = lines.last_mut() {
                last.push_str(&raw[1..]);
            }
        } else {
            lines.push(raw.to_string());
        }
        qp_continue =
            lines.last().is_some_and(|l| l.ends_with('=') && l.to_ascii_uppercase().contains("QUOTED-PRINTABLE"));
        if lines.len() > 2_000_000 {
            break;
        }
    }
    lines
}

/// One content line.
fn parse_line(line: &str) -> Option<Prop> {
    // The value starts at the first `:` outside a quoted parameter.
    let mut in_quote = false;
    let mut colon = None;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quote = !in_quote,
            ':' if !in_quote => {
                colon = Some(i);
                break;
            }
            _ => {}
        }
    }
    let colon = colon?;
    let (head, value) = (&line[..colon], &line[colon + 1..]);
    let mut parts = Vec::new();
    let mut cur = String::new();
    in_quote = false;
    for c in head.chars() {
        match c {
            '"' => in_quote = !in_quote,
            ';' if !in_quote => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    let name = parts.first()?.trim();
    let name = name.rsplit('.').next().unwrap_or(name).to_ascii_uppercase();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    let mut params = Vec::new();
    for p in &parts[1..] {
        match p.split_once('=') {
            Some((k, v)) => params.push((k.trim().to_ascii_uppercase(), v.trim().to_string())),
            None if !p.trim().is_empty() => {
                let bare = p.trim().to_ascii_uppercase();
                if matches!(bare.as_str(), "QUOTED-PRINTABLE" | "BASE64" | "8BIT" | "7BIT" | "B") {
                    params.push(("ENCODING".into(), bare));
                } else {
                    params.push(("TYPE".into(), bare));
                }
            }
            None => {}
        }
    }
    let qp = params.iter().any(|(k, v)| k == "ENCODING" && v.eq_ignore_ascii_case("QUOTED-PRINTABLE"));
    let value = if qp {
        let charset = params.iter().find(|(k, _)| k == "CHARSET").map(|(_, v)| v.as_str());
        quoted_printable(value, charset)
    } else {
        value.to_string()
    };
    Some(Prop { name, params, value })
}

/// The components of a document; properties outside any component are
/// dropped. At most `max_components` components are kept.
pub(crate) fn parse(input: &str, max_components: usize) -> Vec<Component> {
    let mut roots = Vec::new();
    let mut stack: Vec<Component> = Vec::new();
    let mut kept = 0usize;
    for line in unfold(input.trim_start_matches('\u{feff}')) {
        if line.trim().is_empty() {
            continue;
        }
        let Some(p) = parse_line(&line) else { continue };
        match p.name.as_str() {
            "BEGIN" => {
                if stack.len() >= 16 {
                    continue;
                }
                stack.push(Component { name: p.value.trim().to_ascii_uppercase(), ..Component::default() });
            }
            "END" => {
                let name = p.value.trim().to_ascii_uppercase();
                // Close up to the matching BEGIN (repairs missing ENDs).
                if !stack.iter().any(|c| c.name == name) {
                    continue;
                }
                while let Some(c) = stack.pop() {
                    let done = c.name == name;
                    kept += 1;
                    if kept <= max_components {
                        match stack.last_mut() {
                            Some(parent) => parent.children.push(c),
                            None => roots.push(c),
                        }
                    }
                    if done {
                        break;
                    }
                }
            }
            _ => {
                if let Some(c) = stack.last_mut()
                    && c.props.len() < 10_000
                {
                    c.props.push(p);
                }
            }
        }
    }
    // Unterminated components.
    while let Some(c) = stack.pop() {
        match stack.last_mut() {
            Some(parent) => parent.children.push(c),
            None => roots.push(c),
        }
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_lines() {
        let doc = "BEGIN:VCARD\r\nVERSION:2.1\r\nN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:Castell;Mira=\r\n;;;\r\nTEL;CELL;VOICE:+1 555\r\nitem1.EMAIL;TYPE=INTERNET:mira@example.org\r\nNOTE:Line one\\nLine\r\n  two\\, with comma\r\nX-PARAM;LABEL=\"a:b\":v\r\nEND:VCARD\r\n";
        let cards = parse(doc, 100);
        assert_eq!(cards.len(), 1);
        let c = &cards[0];
        assert_eq!(c.name, "VCARD");
        assert_eq!(split(&c.get("N").unwrap().value, ';'), ["Castell", "Mira", "", "", ""]);
        assert!(c.get("TEL").unwrap().has_type("cell"));
        assert_eq!(c.text("EMAIL").as_deref(), Some("mira@example.org"));
        assert_eq!(c.text("NOTE").as_deref(), Some("Line one\nLine two, with comma"));
        assert_eq!(c.get("X-PARAM").unwrap().param("LABEL"), Some("a:b"));
    }

    #[test]
    fn nests_components() {
        let doc = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:A\nBEGIN:VALARM\nACTION:DISPLAY\nEND:VALARM\nEND:VEVENT\nBEGIN:VEVENT\nSUMMARY:B\nEND:VCALENDAR\n";
        let cal = parse(doc, 100);
        assert_eq!(cal.len(), 1);
        let events = cal[0].find_all("VEVENT");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].children[0].name, "VALARM");
    }
}
