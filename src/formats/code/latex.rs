//! LaTeX sources: document class and options, packages, the title block,
//! the abstract, the sectioning outline, included files, counts of
//! figures, tables, equations, citations and labels, and the prose of the
//! document body as text.

use std::collections::BTreeMap;

use serde_json::json;

use crate::plugin::{
    Context, DateField, ExtractError, Map, TextRole, latex_argument as braced, latex_option as bracketed,
    latex_text as detex, parse_date, truncate_chars,
};

const MAX_LISTED: usize = 200;

fn strip_comments(s: &str) -> String {
    s.lines()
        .map(|l| {
            let b = l.as_bytes();
            let mut cut = l.len();
            for i in 0..b.len() {
                if b[i] == b'%' && (i == 0 || b[i - 1] != b'\\') {
                    cut = i;
                    break;
                }
            }
            &l[..cut]
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[allow(clippy::too_many_lines, clippy::many_single_char_names)] // one pass over the commands
pub(crate) fn extract(src: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let text = strip_comments(src);
    let mut format = Map::new();
    let mut packages: Vec<String> = Vec::new();
    let mut includes: Vec<String> = Vec::new();
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut sections: Vec<(u8, String)> = Vec::new();
    let mut title = None;
    let mut authors: Vec<String> = Vec::new();
    let mut date = None;
    let b = text.as_bytes();
    let mut i = 0;
    let mut steps = 0u32;
    while i < b.len() {
        steps = steps.wrapping_add(1);
        if steps.is_multiple_of(65_536) {
            cx.checkpoint()?;
        }
        if b[i] != b'\\' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        while j < b.len() && b[j].is_ascii_alphabetic() {
            j += 1;
        }
        let name = &text[start..j];
        let star = b.get(j) == Some(&b'*');
        let after = if star { j + 1 } else { j };
        i = j.max(i + 1);
        match name {
            "documentclass" => {
                let (opts, k) = bracketed(&text, after).unwrap_or_default();
                if let Some((class, _)) = braced(&text, if k > 0 { k } else { after }) {
                    format.insert("document_class".into(), json!(class.trim()));
                    if !opts.trim().is_empty() {
                        let o: Vec<&str> = opts.split(',').map(str::trim).filter(|o| !o.is_empty()).collect();
                        format.insert("class_options".into(), json!(o));
                    }
                }
            }
            "usepackage" | "RequirePackage" => {
                let (_, k) = bracketed(&text, after).unwrap_or_default();
                if let Some((pkgs, _)) = braced(&text, if k > 0 { k } else { after }) {
                    for p in pkgs.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                        if packages.len() < MAX_LISTED && !packages.iter().any(|x| x == p) {
                            packages.push(p.to_string());
                        }
                    }
                }
            }
            "title" if title.is_none() => {
                let (_, k) = bracketed(&text, after).unwrap_or_default();
                title = braced(&text, if k > 0 { k } else { after }).map(|(t, _)| detex(&t));
            }
            "author" if authors.is_empty() => {
                if let Some((a, _)) = braced(&text, after) {
                    for part in a.split("\\and") {
                        // Drop affiliations and footnotes after the first line break.
                        let first = part.split("\\\\").next().unwrap_or(part);
                        let first = first.split("\\thanks").next().unwrap_or(first);
                        let n = detex(first);
                        if !n.is_empty() && authors.len() < 100 {
                            authors.push(n);
                        }
                    }
                }
            }
            "date" if date.is_none() => date = braced(&text, after).map(|(d, _)| detex(&d)),
            "part" | "chapter" | "section" | "subsection" | "subsubsection" | "paragraph" => {
                let level = match name {
                    "part" => 0,
                    "chapter" => 1,
                    "section" => 2,
                    "subsection" => 3,
                    "subsubsection" => 4,
                    _ => 5,
                };
                let (_, k) = bracketed(&text, after).unwrap_or_default();
                if let Some((h, _)) = braced(&text, if k > 0 { k } else { after }) {
                    let h = detex(&h);
                    if !h.is_empty() && sections.len() < crate::plugin::MAX_OUTLINE {
                        sections.push((level, truncate_chars(&h, 300)));
                    }
                }
            }
            "input" | "include" | "bibliography" | "addbibresource" | "includegraphics" | "subfile" => {
                let (_, k) = bracketed(&text, after).unwrap_or_default();
                if let Some((f, _)) = braced(&text, if k > 0 { k } else { after }) {
                    if name == "includegraphics" {
                        *counts.entry("graphics").or_default() += 1;
                    } else if includes.len() < MAX_LISTED {
                        for f in f.split(',').map(str::trim).filter(|f| !f.is_empty()) {
                            includes.push(f.to_string());
                        }
                    }
                }
            }
            "begin" => {
                if let Some((env, _)) = braced(&text, after) {
                    let key = match env.trim_end_matches('*') {
                        "figure" => Some("figures"),
                        "table" => Some("tables"),
                        "equation" | "align" | "gather" | "multline" => Some("equations"),
                        "theorem" | "lemma" | "proposition" | "corollary" => Some("theorems"),
                        "abstract" => {
                            if let Some(end) = text[after..].find("\\end{abstract}") {
                                let body = &text[after..after + end];
                                let body = body.split_once('}').map_or(body, |(_, r)| r);
                                let a = detex(body);
                                if !a.is_empty() {
                                    cx.content().source("latex.abstract").description(truncate_chars(&a, 5000));
                                }
                            }
                            None
                        }
                        _ => None,
                    };
                    if let Some(k) = key {
                        *counts.entry(k).or_default() += 1;
                    }
                }
            }
            "cite" | "citep" | "citet" | "parencite" | "textcite" | "autocite" | "footcite" => {
                *counts.entry("citations").or_default() += 1;
            }
            "label" => *counts.entry("labels").or_default() += 1,
            "footnote" => *counts.entry("footnotes").or_default() += 1,
            _ => {}
        }
    }
    if let Some(t) = title.filter(|t| !t.is_empty()) {
        cx.content().source("latex.title").title(&t);
        cx.emit_text(TextRole::Title, &t);
    }
    for a in &authors {
        cx.content().source("latex.author").author(a);
        cx.rights().source("latex.author").creator(a);
    }
    if let Some(d) = date.filter(|d| !d.is_empty() && !d.contains("today")) {
        // Free-form dates: keep a parse only when it kept the written year.
        let year = d.split(|c: char| !c.is_ascii_digit()).find(|w| w.len() == 4);
        match parse_date(&d).filter(|(v, _)| year.is_some_and(|y| v.starts_with(y))) {
            Some((v, tz)) => {
                cx.temporal().source("latex.date").content_date(DateField::Created, v, tz);
            }
            None => {
                format.insert("date".into(), json!(d));
            }
        }
    }
    // Outline levels relative to the highest sectioning command used.
    let top = sections.iter().map(|(l, _)| *l).min().unwrap_or(0);
    for (l, h) in &sections {
        cx.emit_heading((l - top + 1).min(9), h);
    }
    if !packages.is_empty() {
        format.insert("packages".into(), json!(packages));
    }
    if !includes.is_empty() {
        format.insert("includes".into(), json!(includes));
    }
    for (k, v) in counts {
        format.insert(k.into(), json!(v));
    }
    // Body text: between \begin{document} and \end{document}, environments
    // of verbatim / math dropped.
    let expanded = expand_macros(&text);
    let body = expanded.find("\\begin{document}").map_or(expanded.as_str(), |s| &expanded[s + 16..]);
    let body = body.find("\\end{document}").map_or(body, |e| &body[..e]);
    let mut prose = String::new();
    for para in body.split("\n\n") {
        let p = para.trim();
        if p.is_empty() || p.starts_with("\\begin{verbatim") || p.starts_with("\\begin{lstlisting") {
            continue;
        }
        let t = detex(&strip_math(p));
        if !t.is_empty() {
            prose.push_str(&t);
            prose.push('\n');
        }
        if prose.len() > cx.options().limits.max_text_bytes {
            break;
        }
    }
    if !prose.is_empty() {
        cx.emit_text(TextRole::Body, &prose);
    }
    cx.format().extend(format);
    Ok(())
}

/// Expand argument-free `\\newcommand{\\name}{text}` / `\\def\\name{text}`
/// macros once, so their text reaches the body text.
fn expand_macros(text: &str) -> String {
    let mut macros: Vec<(String, String)> = Vec::new();
    for def in ["\\newcommand", "\\renewcommand", "\\def"] {
        let mut from = 0;
        while let Some(p) = text[from..].find(def) {
            let at = from + p + def.len();
            from = at;
            let rest = &text[at..];
            let rest_trim = rest.trim_start();
            let (name, after) = if let Some(r) = rest_trim.strip_prefix('{') {
                let Some(end) = r.find('}') else { continue };
                (&r[..end], &r[end + 1..])
            } else {
                let n = rest_trim
                    .char_indices()
                    .skip(1)
                    .find(|(_, c)| !c.is_ascii_alphabetic())
                    .map_or(rest_trim.len(), |(i, _)| i);
                (&rest_trim[..n], &rest_trim[n..])
            };
            // Macros with arguments (`[1]`) are left alone.
            if !name.starts_with('\\') || name.len() < 2 || after.trim_start().starts_with('[') {
                continue;
            }
            if let Some((body, _)) = braced(after, 0)
                && body.len() <= 200
                && !body.contains('#')
                && macros.len() < 200
            {
                macros.push((name.to_string(), body));
            }
        }
    }
    if macros.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(p) = rest.find('\\') {
        out.push_str(&rest[..p]);
        rest = &rest[p..];
        let n = rest.char_indices().skip(1).find(|(_, c)| !c.is_ascii_alphabetic()).map_or(rest.len(), |(i, _)| i);
        let name = &rest[..n.max(1)];
        if let Some((_, body)) = macros.iter().find(|(m, _)| m == name) {
            out.push_str(body);
            rest = &rest[name.len()..];
            if let Some(r) = rest.strip_prefix("{}") {
                rest = r;
            }
        } else {
            out.push_str(name);
            rest = &rest[name.len()..];
        }
    }
    out.push_str(rest);
    out
}

/// Remove display math (`\[…\]`, `$$…$$`); inline math (`$…$`, `\(…\)`) keeps its content.
fn strip_math(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    loop {
        let Some(open) = [rest.find("\\["), rest.find("$$")].into_iter().flatten().min() else {
            out.push_str(&inline(rest));
            break;
        };
        out.push_str(&inline(&rest[..open]));
        rest = &rest[open + 2..];
        let Some(close) = [rest.find("\\]"), rest.find("$$")].into_iter().flatten().min() else { break };
        rest = &rest[close + 2..];
    }
    out
}

/// Inline math delimiters removed, content kept.
fn inline(s: &str) -> String {
    s.replace("\\$", "\u{1}").replace("\\(", " ").replace("\\)", " ").replace('$', "").replace('\u{1}', "$")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_simple_macros() {
        let t = expand_macros(
            "\\newcommand{\\harbour}{the old harbour}\\def\\x{X}\\newcommand{\\f}[1]{#1}Traffic in \\harbour{} and \\x.",
        );
        assert!(t.ends_with("Traffic in the old harbour and X."), "{t}");
    }

    #[test]
    fn strips_math() {
        assert_eq!(strip_math(r"Height $h = 5.2$ m \[ x^2 \] and $$y$$ \(z\)."), "Height h = 5.2 m  and   z .");
    }

    #[test]
    fn reads_latex() {
        let tex = r"\documentclass[a4paper,11pt]{article}
\usepackage{amsmath,graphicx}
\title{Tides at Saltmere}
\author{Ana Lighthouse \and Ben Gull\thanks{Harbour office}}
\begin{document}
\maketitle
\begin{abstract}A short note on tides.\end{abstract}
\section{Spring tides}
Spring tides reach $5.2$ metres. % a comment
\subsection{At the mole}
\begin{figure}\includegraphics{chart.png}\end{figure}
\end{document}";
        let r = crate::plugin::testing::report_for("tides.tex", tex.as_bytes());
        assert_eq!(r.identification.format, "latex");
        assert_eq!(r.content.title.as_deref(), Some("Tides at Saltmere"));
        assert_eq!(r.content.authors, ["Ana Lighthouse", "Ben Gull"]);
        assert_eq!(
            r.content.outline.iter().map(|h| (h.level, h.text.as_str())).collect::<Vec<_>>(),
            [(1, "Spring tides"), (2, "At the mole")]
        );
        let f = &r.format["latex"];
        assert_eq!(f["document_class"], "article");
        assert_eq!(f["packages"], json!(["amsmath", "graphicx"]));
        assert_eq!(f["figures"], 1);
    }
}
