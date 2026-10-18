//! FictionBook 2 (`.fb2`, and `.fbz` / `.fb2.zip` holding one).
//!
//! Reads `<description>` (`title-info`, `document-info`, `publish-info`),
//! the section titles of the main `<body>` as headings and its paragraphs as
//! text; embedded `<binary>` images are counted.

use serde_json::json;

use super::super::xml::{Ev, Flow, walk};
use super::Book;
use crate::plugin::{Context, ExtractError, Source, Zip, truncate_chars};

pub(super) fn extract_zip(src: &mut dyn Source, cx: &mut Context<'_>, book: &mut Book) -> Result<(), ExtractError> {
    let zip = Zip::open(src, 1000)?;
    let entry = zip
        .entries
        .iter()
        .find(|e| e.name.to_ascii_lowercase().ends_with(".fb2"))
        .cloned()
        .ok_or_else(|| ExtractError::malformed("no .fb2 entry"))?;
    let data = zip.read(src, &entry, cx, cx.parse_limit())?;
    let xml = crate::plugin::decode_text(&data).text;
    book.format.insert("entry".into(), json!(entry.name));
    extract(&xml, cx, book)
}

#[allow(clippy::too_many_lines)] // one pass over the FictionBook XML
pub(super) fn extract(xml: &str, cx: &mut Context<'_>, book: &mut Book) -> Result<(), ExtractError> {
    let budget = cx.options().limits.max_text_bytes;
    let mut path: Vec<String> = Vec::new();
    let mut text = String::new();
    // Author parts collected per <author>.
    let mut author: Vec<(String, String)> = Vec::new();
    let mut body_index = 0usize;
    let mut section_depth = 0u8;
    let mut title_buf: Option<String> = None;
    let mut para = String::new();
    let mut body = String::new();
    let mut binaries = 0u64;
    let mut genres = Vec::new();
    let mut annotation = String::new();
    walk(xml, cx, |ev| {
        match ev {
            Ev::Open(t, empty) => {
                let parent = path.last().map(String::as_str).unwrap_or_default();
                match t.name.as_str() {
                    "body" => body_index += 1,
                    "section" if body_index == 1 => section_depth = section_depth.saturating_add(1),
                    "title" if body_index == 1 && path.iter().any(|p| p == "body") => title_buf = Some(String::new()),
                    "sequence" if path.iter().any(|p| p == "title-info") => {
                        if let Some(name) = t.attr("name") {
                            book.series = Some((name.to_string(), t.attr("number").map(str::to_string)));
                        }
                    }
                    "date" if path.iter().any(|p| p == "title-info") && book.published.is_none() => {
                        book.published = t.attr("value").map(str::to_string);
                    }
                    "binary" => {
                        binaries += 1;
                        // Binaries follow the bodies: the text is complete.
                        if body.len() >= budget {
                            return Flow::Stop;
                        }
                    }
                    "image" if parent == "coverpage" => {
                        if let Some(href) = t.attr("href") {
                            book.cover = Some(json!({ "binary": href.trim_start_matches('#') }));
                        }
                    }
                    _ => {}
                }
                if !empty {
                    path.push(t.name.clone());
                }
                text.clear();
            }
            Ev::Text(s) => {
                if text.len() < 64 * 1024 {
                    text.push_str(s);
                }
                if let Some(t) = title_buf.as_mut() {
                    t.push_str(s);
                    t.push(' ');
                }
                if body_index == 1 && path.iter().any(|p| p == "body") && para.len() < 1 << 20 {
                    para.push_str(s);
                }
                if path.iter().any(|p| p == "annotation") && path.iter().any(|p| p == "title-info") {
                    annotation.push_str(s);
                    annotation.push(' ');
                }
            }
            Ev::Close(name) => {
                let value = text.trim().to_string();
                let in_title_info = path.iter().any(|p| p == "title-info");
                let in_doc_info = path.iter().any(|p| p == "document-info");
                let in_publish = path.iter().any(|p| p == "publish-info");
                match name {
                    "first-name" | "middle-name" | "last-name" | "nickname" if in_title_info || in_doc_info => {
                        author.push((name.to_string(), value.clone()));
                    }
                    "author" | "translator" => {
                        let get = |k: &str| author.iter().find(|(n, _)| n == k).map_or("", |(_, v)| v.as_str());
                        let full = [get("first-name"), get("middle-name"), get("last-name")]
                            .iter()
                            .filter(|p| !p.is_empty())
                            .copied()
                            .collect::<Vec<_>>()
                            .join(" ");
                        let full = if full.is_empty() { get("nickname").to_string() } else { full };
                        if in_title_info && !full.is_empty() {
                            book.creator(&full, if name == "translator" { "trl" } else { "aut" });
                        } else if in_doc_info && !full.is_empty() {
                            book.format.insert("document_author".into(), json!(truncate_chars(&full, 200)));
                        }
                        author.clear();
                    }
                    "book-title" if in_title_info && !value.is_empty() => {
                        book.title = Some(truncate_chars(&value, 500));
                    }
                    "genre" if in_title_info && !value.is_empty() && genres.len() < 50 => genres.push(value.clone()),
                    "keywords" if in_title_info => {
                        for k in value.split(',').map(str::trim).filter(|k| !k.is_empty()).take(100) {
                            book.subjects.push(k.to_string());
                        }
                    }
                    "lang" if in_title_info && !value.is_empty() => book.language = Some(value.clone()),
                    "src-lang" if in_title_info && !value.is_empty() => {
                        book.format.insert("source_language".into(), json!(value));
                    }
                    "date" if in_title_info && !value.is_empty() && book.published.is_none() => {
                        book.published = Some(value.clone());
                    }
                    "program-used" if in_doc_info && !value.is_empty() => {
                        book.format.insert("program_used".into(), json!(truncate_chars(&value, 200)));
                    }
                    "id" if in_doc_info && !value.is_empty() => book.identifier("fb2", &value),
                    "version" if in_doc_info && !value.is_empty() => {
                        book.format.insert("document_version".into(), json!(value));
                    }
                    "date" if in_doc_info && !value.is_empty() => {
                        book.format.insert("document_date".into(), json!(value));
                    }
                    "publisher" if in_publish && !value.is_empty() => {
                        book.publisher = Some(truncate_chars(&value, 300));
                    }
                    "isbn" if in_publish => book.identifier("isbn", &value),
                    "year" if in_publish && !value.is_empty() && book.published.is_none() => {
                        book.published = Some(value.clone());
                    }
                    "title" => {
                        if let Some(t) = title_buf.take() {
                            let t = crate::plugin::squash_whitespace(&t);
                            if !t.is_empty() && book.toc.len() < crate::plugin::MAX_OUTLINE && section_depth > 0 {
                                book.toc.push((section_depth.clamp(1, 9), truncate_chars(&t, 300)));
                            }
                        }
                    }
                    "section" if body_index == 1 => section_depth = section_depth.saturating_sub(1),
                    "p" | "v" | "subtitle" | "text-author" if body_index == 1 => {
                        let p = crate::plugin::squash_whitespace(&para);
                        if !p.is_empty() && body.len() < budget {
                            body.push_str(&p);
                            body.push('\n');
                        }
                        para.clear();
                    }
                    _ => {}
                }
                if path.last().is_some_and(|p| p == name) {
                    path.pop();
                }
                text.clear();
                if name == "p" {
                    para.clear();
                }
            }
        }
        Flow::Continue
    })?;
    if !annotation.trim().is_empty() {
        book.description = Some(truncate_chars(&crate::plugin::squash_whitespace(&annotation), 10_000));
    }
    if !genres.is_empty() {
        book.format.insert("genres".into(), json!(genres));
    }
    if binaries > 0 {
        book.format.insert("binaries".into(), json!(binaries));
    }
    if body_index > 1 {
        book.format.insert("bodies".into(), json!(body_index));
    }
    book.add_text(&body, budget);
    Ok(())
}
