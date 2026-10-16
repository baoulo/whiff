//! Markdown (`CommonMark` + GFM), including MDX, R Markdown and Quarto.
//!
//! Front matter (YAML `---` or TOML `+++`) fills title, description,
//! authors, dates, tags and licence; headings become the outline; links,
//! images, code blocks, tables and task lists are counted.
//!
//! Specification: <https://spec.commonmark.org/>, <https://github.github.com/gfm/>

use std::collections::BTreeMap;

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, MetadataBlockKind, Options, Parser, Tag, TagEnd};
use serde_json::{Map, Value, json};

use super::url_host;
use crate::plugin::{
    AnyValue, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, MAX_NESTING, Source,
    TextRole, dotted_key_depth, find_copyright, nesting_depth, parse_date, truncate_chars,
};

/// Extractor for Markdown.
pub struct Markdown;

static META: ExtractorMeta = ExtractorMeta {
    id: "text.markdown",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "markdown",
        name: "Markdown",
        family: "text.markdown",
        mimes: &["text/markdown"],
        extensions: &["md", "markdown", "mdown", "mkd", "mkdn", "mdwn", "mdx", "rmd", "qmd"],
        magic: &[],
        parent: Some("text"),
    }],
};

impl Extractor for Markdown {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        let options = Options::ENABLE_TABLES
            | Options::ENABLE_FOOTNOTES
            | Options::ENABLE_STRIKETHROUGH
            | Options::ENABLE_TASKLISTS
            | Options::ENABLE_YAML_STYLE_METADATA_BLOCKS
            | Options::ENABLE_PLUSES_DELIMITED_METADATA_BLOCKS
            | Options::ENABLE_GFM;
        let mut s = Scan::default();
        for (n, event) in Parser::new_ext(&text, options).enumerate() {
            if n % 4096 == 0 {
                cx.checkpoint()?;
            }
            s.event(event, cx);
        }
        s.flush_paragraph(cx);
        if let Some((kind, raw)) = s.front_matter.take() {
            front_matter(kind, &raw, cx);
        }
        if let Some(h1) = &s.first_h1 {
            cx.content().title(h1.clone());
        }
        if let Some(c) = find_copyright(&text) {
            cx.rights().copyright(c);
        }
        s.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Markdown);

#[derive(Default)]
struct Scan {
    front_matter: Option<(MetadataBlockKind, String)>,
    in_metadata: Option<MetadataBlockKind>,
    metadata_text: String,
    heading: Option<(u8, String)>,
    headings: u64,
    first_h1: Option<String>,
    paragraph: String,
    in_code: bool,
    in_image: bool,
    alt: String,
    links_internal: u64,
    links_external: u64,
    hosts: BTreeMap<String, u64>,
    images: u64,
    images_with_alt: u64,
    code_blocks: u64,
    languages: BTreeMap<String, u64>,
    tables: u64,
    tasks: u64,
    tasks_done: u64,
    footnotes: u64,
    html_blocks: u64,
    components: BTreeMap<String, u64>,
    scripts: bool,
}

impl Scan {
    fn event(&mut self, event: Event<'_>, cx: &mut Context<'_>) {
        match event {
            Event::Start(Tag::MetadataBlock(kind)) => {
                self.in_metadata = Some(kind);
                self.metadata_text.clear();
            }
            Event::End(TagEnd::MetadataBlock(_)) => {
                if let Some(kind) = self.in_metadata.take()
                    && self.front_matter.is_none()
                {
                    self.front_matter = Some((kind, std::mem::take(&mut self.metadata_text)));
                }
            }
            Event::Start(Tag::Heading { level, .. }) => {
                self.flush_paragraph(cx);
                self.heading = Some((level_number(level), String::new()));
            }
            Event::End(TagEnd::Heading(_)) => {
                if let Some((level, text)) = self.heading.take() {
                    self.headings += 1;
                    if level == 1 && self.first_h1.is_none() {
                        self.first_h1 = Some(text.trim().to_string());
                    }
                    cx.emit_heading(level, &text);
                }
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                self.flush_paragraph(cx);
                self.in_code = true;
                self.code_blocks += 1;
                if let CodeBlockKind::Fenced(info) = kind {
                    // ```rust,ignore / ```{r setup} / ```python title="x"
                    let lang: String = info
                        .trim_start_matches('{')
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || matches!(c, '+' | '-' | '#' | '_'))
                        .collect::<String>()
                        .to_lowercase();
                    if !lang.is_empty() {
                        *self.languages.entry(lang).or_default() += 1;
                    }
                }
            }
            Event::End(TagEnd::CodeBlock) => self.in_code = false,
            Event::Start(Tag::Link { dest_url, .. }) => self.link(&dest_url),
            Event::Start(Tag::Image { .. }) => {
                self.images += 1;
                self.in_image = true;
                self.alt.clear();
            }
            Event::End(TagEnd::Image) => {
                self.in_image = false;
                if !self.alt.trim().is_empty() {
                    self.images_with_alt += 1;
                    cx.emit_text(TextRole::Caption, self.alt.trim());
                }
            }
            Event::Start(Tag::Table(_)) => self.tables += 1,
            Event::TaskListMarker(done) => {
                self.tasks += 1;
                self.tasks_done += u64::from(done);
            }
            Event::FootnoteReference(_) => self.footnotes += 1,
            Event::Html(h) | Event::InlineHtml(h) => {
                self.html_blocks += 1;
                let lower = h.to_ascii_lowercase();
                if lower.contains("<script") {
                    self.scripts = true;
                }
                // MDX / JSX components: `<Chart data={x} />`.
                for part in h.split('<').skip(1) {
                    let name: String = part.chars().take_while(|c| c.is_alphanumeric() || *c == '.').collect();
                    if name.starts_with(|c: char| c.is_ascii_uppercase()) {
                        *self.components.entry(name).or_default() += 1;
                    }
                }
            }
            Event::Text(t) | Event::Code(t) => self.text(&t, cx),
            Event::SoftBreak | Event::HardBreak => self.text(" ", cx),
            Event::End(TagEnd::Paragraph | TagEnd::Item | TagEnd::TableCell | TagEnd::BlockQuote(_)) => {
                self.flush_paragraph(cx);
            }
            _ => {}
        }
    }

    fn text(&mut self, t: &str, cx: &mut Context<'_>) {
        if self.in_metadata.is_some() {
            self.metadata_text.push_str(t);
        } else if let Some((_, h)) = &mut self.heading {
            h.push_str(t);
        } else if self.in_code {
            cx.emit_text(TextRole::Code, t);
        } else if self.in_image {
            self.alt.push_str(t);
        } else {
            self.paragraph.push_str(t);
        }
    }

    fn flush_paragraph(&mut self, cx: &mut Context<'_>) {
        let p = self.paragraph.trim();
        if !p.is_empty() {
            cx.emit_text(TextRole::Body, p);
        }
        self.paragraph.clear();
    }

    fn link(&mut self, url: &str) {
        if let Some(host) = url_host(url) {
            self.links_external += 1;
            *self.hosts.entry(host).or_default() += 1;
        } else if !url.to_ascii_lowercase().starts_with("mailto:") {
            self.links_internal += 1;
        }
    }

    fn report(&self, cx: &mut Context<'_>) {
        if self.scripts {
            cx.security().active_content("javascript").risk("inline_script", Some("raw <script> in Markdown".into()));
        }
        cx.security().external_references(self.links_external);
        let fmt = cx.format();
        let mut put = |k: &str, v: Value| {
            fmt.insert(k.to_string(), v);
        };
        put("headings", json!(self.headings));
        put("links", json!({ "internal": self.links_internal, "external": self.links_external }));
        if !self.hosts.is_empty() {
            put("top_link_hosts", top(&self.hosts, 10));
        }
        put("images", json!({ "count": self.images, "with_alt": self.images_with_alt }));
        put("code_blocks", json!(self.code_blocks));
        if !self.languages.is_empty() {
            put("code_languages", json!(self.languages));
        }
        put("tables", json!(self.tables));
        if self.tasks > 0 {
            put("tasks", json!({ "total": self.tasks, "done": self.tasks_done }));
        }
        if self.footnotes > 0 {
            put("footnotes", json!(self.footnotes));
        }
        if self.html_blocks > 0 {
            put("html_fragments", json!(self.html_blocks));
        }
        if !self.components.is_empty() {
            put("components", top(&self.components, 25));
        }
    }
}

fn top(map: &BTreeMap<String, u64>, n: usize) -> Value {
    let mut v: Vec<(&String, &u64)> = map.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    Value::Object(v.into_iter().take(n).map(|(k, n)| (k.clone(), json!(n))).collect())
}

fn level_number(level: HeadingLevel) -> u8 {
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

/// Parse front matter and map the common keys (Jekyll, Hugo, Astro, Quarto…).
fn front_matter(kind: MetadataBlockKind, raw: &str, cx: &mut Context<'_>) {
    if nesting_depth(raw) > MAX_NESTING || dotted_key_depth(raw) > MAX_NESTING {
        cx.warn("front matter nested too deeply; not parsed");
        return;
    }
    let (parsed, syntax) = match kind {
        MetadataBlockKind::YamlStyle => {
            // YAML 1.2 booleans; the last of duplicate keys wins.
            let mut options = serde_saphyr::Options::default();
            options.strict_booleans = true;
            options.duplicate_keys = serde_saphyr::DuplicateKeyPolicy::LastWins;
            (serde_saphyr::from_str_with_options::<AnyValue>(raw, options).map_err(|e| e.to_string()), "yaml")
        }
        MetadataBlockKind::PlusesStyle => (toml::from_str::<AnyValue>(raw).map_err(|e| e.to_string()), "toml"),
    };
    cx.format_set("front_matter", syntax);
    let map = match parsed {
        Ok(AnyValue(Value::Object(m))) => m,
        Ok(_) => return,
        Err(e) => {
            cx.warn(format!("front matter: {}", truncate_chars(&e, 200)));
            return;
        }
    };
    let get = |keys: &[&str]| keys.iter().find_map(|k| map.get(*k).filter(|v| !v.is_null()));
    let src = |k: &str| format!("front_matter.{k}");
    if let Some(t) = get(&["title"]).and_then(Value::as_str) {
        cx.content().source(src("title")).title(t);
    }
    if let Some(d) = get(&["description", "summary", "excerpt", "subtitle"]).and_then(Value::as_str) {
        cx.content().source(src("description")).description(d);
    }
    for key in ["author", "authors", "creator"] {
        for name in names(map.get(key)) {
            cx.content().source(src(key)).author(name.clone());
            cx.rights().source(src(key)).creator(name);
        }
    }
    for (keys, field) in [
        (&["date", "published", "pubDate", "publishDate", "created"][..], DateField::Published),
        (&["updated", "lastmod", "modified", "last_modified", "dateModified"][..], DateField::Modified),
        (&["expiryDate", "expires"][..], DateField::Expires),
    ] {
        for key in keys {
            if let Some(v) = map.get(*key).and_then(scalar_text)
                && let Some((d, tz)) = parse_date(&v)
            {
                cx.temporal().source(src(key)).content_date(field, d, tz);
                break;
            }
        }
    }
    for key in ["tags", "categories", "category", "topics", "series"] {
        for t in names(map.get(key)) {
            cx.content().source(src(key)).tag(t);
        }
    }
    for k in names(map.get("keywords")) {
        cx.content().source(src("keywords")).keyword(k);
    }
    if let Some(l) = get(&["lang", "language", "locale"]).and_then(Value::as_str) {
        let code = l.split(['-', '_']).next().unwrap_or(l).to_ascii_lowercase();
        if (2..=3).contains(&code.len()) {
            cx.content().source(src("lang")).language(code, 1.0);
        }
    }
    if let Some(l) = get(&["license", "licence"]).and_then(Value::as_str) {
        let url = l.starts_with("http").then_some(l);
        cx.rights().source(src("license")).license((!l.starts_with("http")).then_some(l), url);
    }
    if let Some(c) = get(&["copyright", "rights"]).and_then(Value::as_str) {
        cx.rights().source(src("copyright")).copyright(c);
    }
    if let Some(d) = get(&["draft"]).and_then(Value::as_bool) {
        cx.format_set("draft", d);
    }
    let keys: Vec<&String> = map.keys().take(50).collect();
    cx.format_set("front_matter_keys", json!(keys));
    let compact: Map<String, Value> = map.iter().take(50).map(|(k, v)| (k.clone(), compact(v, 0))).collect();
    *cx.metadata("front_matter") = compact;
}

/// Names from a string, a list of strings, or objects with a `name`.
fn names(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect(),
        Some(Value::Array(a)) => a.iter().take(50).flat_map(|x| names(Some(x))).collect(),
        Some(Value::Object(o)) => o.get("name").and_then(Value::as_str).map(str::to_string).into_iter().collect(),
        _ => Vec::new(),
    }
}

fn scalar_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Values cut down for the report: long strings shortened, lists capped.
fn compact(v: &Value, depth: usize) -> Value {
    match v {
        Value::String(s) => json!(truncate_chars(s, 500)),
        Value::Array(a) if depth < 4 => Value::Array(a.iter().take(50).map(|x| compact(x, depth + 1)).collect()),
        Value::Object(o) if depth < 4 => {
            Value::Object(o.iter().take(50).map(|(k, x)| (k.clone(), compact(x, depth + 1))).collect())
        }
        Value::Array(_) | Value::Object(_) => json!("…"),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(names(Some(&json!("a, b"))), ["a", "b"]);
        assert_eq!(names(Some(&json!([{"name": "Ada"}, "Bob"]))), ["Ada", "Bob"]);
        assert_eq!(compact(&json!({"a": "x".repeat(600)}), 0)["a"].as_str().map(|s| s.chars().count()), Some(501));
    }

    crate::fixture_tests!("markdown");
}
