//! Lenient text from HTML and XHTML (ebook chapters, MOBI text, e-mail
//! bodies): tags
//! removed, `script` / `style` skipped, block elements as line breaks,
//! entities decoded, `h1`–`h6` reported as headings. It never fails, so
//! malformed markup and HTML entities in "XHTML" do not lose the text.

/// Text and headings `(level, text)` of a markup document, at most `max` bytes of text.
pub fn html_text(html: &str, max: usize) -> (String, Vec<(u8, String)>) {
    let mut out = String::with_capacity(html.len().min(max) / 2);
    let mut headings = Vec::new();
    let mut heading: Option<(u8, String)> = None;
    let mut skip: Option<String> = None;
    let mut rest = html;
    while !rest.is_empty() && out.len() < max {
        let Some(lt) = rest.find('<') else {
            push_text(&mut out, &mut heading, rest, skip.is_some());
            break;
        };
        push_text(&mut out, &mut heading, &rest[..lt], skip.is_some());
        rest = &rest[lt..];
        if let Some(body) = rest.strip_prefix("<!--") {
            rest = body.find("-->").map_or("", |e| &body[e + 3..]);
            continue;
        }
        if let Some(body) = rest.strip_prefix("<![CDATA[") {
            let end = body.find("]]>").unwrap_or(body.len());
            push_text(&mut out, &mut heading, &body[..end], skip.is_some());
            rest = body.get(end + 3..).unwrap_or("");
            continue;
        }
        let end = tag_end(rest);
        // An unterminated tag runs to the end (`rest` starts with the 1-byte `<`).
        let tag = rest.get(1..end.saturating_sub(1)).filter(|_| rest[..end].ends_with('>')).unwrap_or(&rest[1..]);
        rest = &rest[end..];
        let closing = tag.starts_with('/');
        let name: String = tag
            .trim_start_matches('/')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == ':' || *c == '-')
            .collect::<String>()
            .to_ascii_lowercase();
        let local = name.rsplit(':').next().unwrap_or(&name).to_string();
        if let Some(s) = &skip {
            if closing && *s == local {
                skip = None;
            }
            continue;
        }
        match local.as_str() {
            "script" | "style" | "head" | "title" if !closing && !tag.ends_with('/') => skip = Some(local),
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                let level = local.as_bytes()[1] - b'0';
                if closing {
                    if let Some((l, t)) = heading.take() {
                        let t = super::squash_whitespace(&t);
                        if !t.is_empty() && headings.len() < 10_000 {
                            headings.push((l, t));
                        }
                    }
                } else {
                    heading = Some((level, String::new()));
                }
                block(&mut out);
            }
            "p" | "div" | "br" | "li" | "tr" | "section" | "article" | "blockquote" | "pre" | "table" | "ul" | "ol"
            | "dt" | "dd" | "hr" | "body" | "header" | "footer" | "aside" | "nav" | "figure" | "figcaption" => {
                block(&mut out);
            }
            "td" | "th" => out.push('\t'),
            _ => {}
        }
    }
    (out, headings)
}

/// Index just past the `>` closing the tag at the start of `s` (quotes respected).
fn tag_end(s: &str) -> usize {
    let mut quote: Option<u8> = None;
    for (i, b) in s.bytes().enumerate().skip(1) {
        match (quote, b) {
            (Some(q), _) if b == q => quote = None,
            (None, b'"' | b'\'') => quote = Some(b),
            (None, b'>') => return i + 1,
            _ => {}
        }
    }
    s.len()
}

fn block(out: &mut String) {
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
}

fn push_text(out: &mut String, heading: &mut Option<(u8, String)>, raw: &str, skipped: bool) {
    if skipped || raw.is_empty() {
        return;
    }
    let decoded = decode_entities(raw);
    let mut last_space = out.ends_with([' ', '\n', '\t']);
    for c in decoded.chars() {
        if c.is_whitespace() && c != '\u{A0}' {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(c);
            last_space = false;
        }
    }
    if let Some((_, t)) = heading.as_mut()
        && t.len() < 1000
    {
        t.push_str(&decoded);
    }
}

/// Decode character and the common named entities.
pub fn decode_entities(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.contains('&') {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let end = rest[1..].find(|c: char| c == ';' || c == '&' || c == '<' || c.is_whitespace()).map(|e| e + 1);
        let decoded =
            end.filter(|&e| rest.as_bytes().get(e) == Some(&b';')).and_then(|e| entity(&rest[1..e]).map(|c| (c, e)));
        if let Some((c, e)) = decoded {
            out.push(c);
            rest = &rest[e + 1..];
        } else {
            out.push('&');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    std::borrow::Cow::Owned(out)
}

fn entity(name: &str) -> Option<char> {
    if let Some(num) = name.strip_prefix('#') {
        let v = match num.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => num.parse().ok()?,
        };
        return char::from_u32(v);
    }
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => '\u{A0}',
        "mdash" => '\u{2014}',
        "ndash" => '\u{2013}',
        "hellip" => '\u{2026}',
        "lsquo" => '\u{2018}',
        "rsquo" => '\u{2019}',
        "ldquo" => '\u{201C}',
        "rdquo" => '\u{201D}',
        "laquo" => '«',
        "raquo" => '»',
        "copy" => '©',
        "reg" => '®',
        "trade" => '\u{2122}',
        "deg" => '°',
        "middot" => '·',
        "bull" => '\u{2022}',
        "shy" => '\u{AD}',
        "eacute" => 'é',
        "egrave" => 'è',
        "aacute" => 'á',
        "agrave" => 'à',
        "uuml" => 'ü',
        "ouml" => 'ö',
        "auml" => 'ä',
        "szlig" => 'ß',
        "ccedil" => 'ç',
        "euro" => '€',
        "pound" => '£',
        _ => return None,
    })
}

/// Why opening a file with this name is risky: `executable` (programs,
/// scripts, shortcuts, installers), `macro_document` (Office formats that
/// carry macros), `double_extension` (`invoice.pdf.exe`); `None` otherwise.
pub fn risky_file_name(name: &str) -> Option<&'static str> {
    const EXECUTABLE: &[&str] = &[
        "exe", "dll", "scr", "com", "pif", "cpl", "msi", "msp", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse",
        "wsf", "wsh", "hta", "jar", "lnk", "url", "reg", "sh", "app", "command", "iso", "img", "vhd", "appx", "msix",
        "chm", "scf", "inf",
    ];
    const MACRO: &[&str] = &["docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm"];
    let lower = name.trim().trim_end_matches(['.', ' ']).to_ascii_lowercase();
    let mut parts = lower.rsplit('.');
    let ext = parts.next().filter(|_| lower.contains('.'))?;
    if EXECUTABLE.contains(&ext) {
        let inner = parts.next().unwrap_or("");
        let looks_like_document =
            ["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "zip", "rtf"].contains(&inner);
        return Some(if looks_like_document && lower.matches('.').count() >= 2 {
            "double_extension"
        } else {
            "executable"
        });
    }
    MACRO.contains(&ext).then_some("macro_document")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unterminated_tags_at_a_multibyte_end() {
        assert_eq!(html_text("ab<é", 100).0, "ab");
        assert_eq!(html_text("<p>x</p><a href='é", 100).0, "x\n");
    }

    #[test]
    fn risky_names() {
        assert_eq!(risky_file_name("setup.EXE"), Some("executable"));
        assert_eq!(risky_file_name("invoice.pdf.exe"), Some("double_extension"));
        assert_eq!(risky_file_name("budget.xlsm"), Some("macro_document"));
        assert_eq!(risky_file_name("berths.csv"), None);
        assert_eq!(risky_file_name("README"), None);
    }

    #[test]
    fn strips_markup() {
        let (t, h) = html_text(
            "<html><head><title>x</title><style>p{}</style></head><body><h1>Tide &amp; time</h1>\
             <p>High&nbsp;water <b>at</b> noon.</p><script>var a = '<p>';</script><p>Low&#x20;water</p></body></html>",
            10_000,
        );
        assert_eq!(h, [(1, "Tide & time".to_string())]);
        assert!(t.contains("High\u{A0}water at noon."), "{t}");
        assert!(t.contains("Low water"));
        assert!(!t.contains("var a"));
    }
}
