//! LaTeX to plain text for the extractors that meet it (LaTeX sources,
//! BibTeX fields): commands dropped, their text arguments kept, markup-only
//! arguments (`\\label{…}`, `\\cite{…}`, `\\begin{…}`) dropped, TeX
//! ligatures (``` `` ```, `''`, `--`, `---`) turned into characters.

use super::squash_whitespace;

/// The `{…}` argument starting at byte `i` (after optional spaces), balanced,
/// and the index after it.
pub fn latex_argument(s: &str, i: usize) -> Option<(String, usize)> {
    let b = s.as_bytes();
    let mut j = i;
    while j < b.len() && b[j].is_ascii_whitespace() {
        j += 1;
    }
    if b.get(j) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    let start = j + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 1,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((s[start..j].to_string(), j + 1));
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
}

/// An optional `[…]` argument at byte `i`, and the index after it.
pub fn latex_option(s: &str, i: usize) -> Option<(String, usize)> {
    let rest = s.get(i..)?;
    let t = rest.trim_start();
    let skip = rest.len() - t.len();
    if !t.starts_with('[') {
        return None;
    }
    let end = t.find(']')?;
    Some((t[1..end].to_string(), i + skip + end + 1))
}

/// Commands whose (first) argument is markup, not text.
const DROP_ARG: &[&str] = &[
    "begin",
    "end",
    "label",
    "ref",
    "eqref",
    "pageref",
    "cite",
    "citep",
    "citet",
    "parencite",
    "textcite",
    "autocite",
    "footcite",
    "includegraphics",
    "bibliographystyle",
    "bibliography",
    "addbibresource",
    "usepackage",
    "documentclass",
    "input",
    "include",
    "vspace",
    "hspace",
    "setlength",
    "newcommand",
    "renewcommand",
    "pagestyle",
    "thispagestyle",
];

/// Plain text from a LaTeX fragment: commands dropped, arguments kept.
pub fn latex_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let mut name = String::new();
                while let Some(&n) = chars.peek() {
                    if n.is_ascii_alphabetic() {
                        name.push(n);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if name.is_empty() {
                    match chars.next() {
                        Some('\\' | '~' | ',' | ' ') => out.push(' '),
                        Some(sym @ ('%' | '&' | '$' | '#' | '_' | '{' | '}')) => out.push(sym),
                        _ => {}
                    }
                } else if DROP_ARG.contains(&name.as_str()) {
                    // `\begin{figure}`, `\label{x}`, `\cite[p. 2]{y}`: the argument is not text.
                    let rest: String = chars.clone().collect();
                    let (_, k) = latex_option(&rest, 0).unwrap_or_default();
                    if let Some((_, mut end)) = latex_argument(&rest, k) {
                        // `\begin{figure}[h]`: placement options follow the argument.
                        if name == "begin"
                            && let Some((_, e)) = latex_option(&rest, end)
                        {
                            end = e;
                        }
                        for _ in 0..rest[..end].chars().count() {
                            chars.next();
                        }
                    }
                    out.push(' ');
                } else {
                    match name.as_str() {
                        "and" | "quad" | "qquad" | "newline" | "par" => out.push(' '),
                        "ldots" | "dots" => out.push('\u{2026}'),
                        "LaTeX" => out.push_str("LaTeX"),
                        "TeX" => out.push_str("TeX"),
                        _ => {}
                    }
                }
            }
            '{' | '}' => {}
            '~' => out.push(' '),
            '%' => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        break;
                    }
                }
            }
            _ => out.push(c),
        }
    }
    squash_whitespace(
        &out.replace("``", "\u{201C}").replace("''", "\u{201D}").replace("---", "\u{2014}").replace("--", "\u{2013}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latex_to_text() {
        assert_eq!(latex_text(r"The \emph{outer} mole~--- see \cite{x}."), "The outer mole \u{2014} see .");
        assert_eq!(latex_text(r"\begin{figure}[h] \caption{Tide ``curve''}"), "Tide \u{201C}curve\u{201D}");
        assert_eq!(latex_argument("{a{b}c} rest", 0), Some(("a{b}c".into(), 7)));
        assert_eq!(latex_option(" [11pt]{article}", 0), Some(("11pt".into(), 7)));
    }
}
