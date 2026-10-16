//! Feeds and site indexes: RSS (0.9x, 1.0, 2.0), Atom, JSON Feed, OPML and
//! XML sitemaps. Title, description, language, authors and the date range of
//! the items, plus the latest item titles; podcasts are recognised by their
//! enclosures.
//!
//! Specifications: <https://www.rssboard.org/rss-specification>,
//! <https://www.rfc-editor.org/rfc/rfc4287>, <https://www.jsonfeed.org/version/1.1/>,
//! <http://opml.org/spec2.opml>, <https://www.sitemaps.org/protocol.html>

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

use super::{XmlNode, XmlTree, decode_xml, start_tag, url_host, xml_root};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole,
    parse_date, squash_whitespace, truncate_chars,
};

/// Extractor for feeds, OPML and sitemaps.
pub struct Feed;

static META: ExtractorMeta = ExtractorMeta {
    id: "text.feed",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "rss",
            name: "RSS feed",
            family: "text.feed",
            mimes: &["application/rss+xml"],
            extensions: &["rss"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "atom",
            name: "Atom feed",
            family: "text.feed",
            mimes: &["application/atom+xml"],
            extensions: &["atom"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "json_feed",
            name: "JSON Feed",
            family: "text.feed",
            mimes: &["application/feed+json"],
            extensions: &[],
            magic: &[],
            parent: Some("json"),
        },
        FormatSpec {
            id: "opml",
            name: "OPML outline",
            family: "text.feed",
            mimes: &["text/x-opml"],
            extensions: &["opml"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "sitemap",
            name: "XML sitemap",
            family: "text.feed",
            mimes: &["application/xml"],
            extensions: &[],
            magic: &[],
            parent: Some("xml"),
        },
    ],
};

/// Items whose titles are listed in the report.
const LATEST: usize = 10;

impl Extractor for Feed {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let found = |format| Some(Sniff { format, confidence: 0.95 });
        let head = &probe.head[..probe.head.len().min(4096)];
        let text = String::from_utf8_lossy(head);
        let trimmed = text.trim_start_matches('\u{feff}').trim_start();
        if trimmed.starts_with('{') {
            return if text.contains("jsonfeed.org/version/") { found("json_feed") } else { None };
        }
        let root = xml_root(head)?;
        match root.rsplit(':').next().unwrap_or(&root) {
            "rss" => found("rss"),
            "RDF" if text.contains("purl.org/rss/1.0") => found("rss"),
            "feed" if start_tag(head, &root).is_some_and(|t| t.contains("www.w3.org/2005/Atom")) => found("atom"),
            "opml" => found("opml"),
            "urlset" | "sitemapindex" => found("sitemap"),
            _ => None,
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, _) = cx.read_bytes(src)?;
        let text = decode_xml(&bytes);
        if cx.format_id() == "json_feed" {
            let v: Value = serde_json::from_str(&text).map_err(|e| ExtractError::malformed(e.to_string()))?;
            json_feed(&v, cx);
            return Ok(());
        }
        let tree = XmlTree::parse(&text).map_err(ExtractError::malformed)?;
        cx.checkpoint()?;
        match cx.format_id() {
            "opml" => opml(&tree, cx),
            "sitemap" => sitemap(&tree, cx),
            _ => xml_feed(&tree, cx),
        }
        Ok(())
    }
}

crate::register_extractor!(Feed);

/// One feed item, in any dialect.
#[derive(Default)]
struct Item {
    title: Option<String>,
    link: Option<String>,
    date: Option<(String, bool)>,
    summary: Option<String>,
    authors: Vec<String>,
    categories: Vec<String>,
    enclosure: Option<String>,
}

/// Feed-level facts, in any dialect.
#[derive(Default)]
struct Channel {
    dialect: &'static str,
    version: Option<String>,
    title: Option<String>,
    link: Option<String>,
    description: Option<String>,
    language: Option<String>,
    updated: Option<(String, bool)>,
    generator: Option<String>,
    copyright: Option<String>,
    authors: Vec<String>,
    image: Option<String>,
    podcast: bool,
    items: Vec<Item>,
}

fn xml_feed(tree: &XmlTree, cx: &mut Context<'_>) {
    let root = tree.root();
    let mut ch = Channel::default();
    match root.name.as_str() {
        "feed" => atom(tree, root, &mut ch),
        _ => rss(tree, root, &mut ch),
    }
    report(&ch, cx);
}

fn rss(tree: &XmlTree, root: &XmlNode, ch: &mut Channel) {
    ch.dialect = if root.name == "RDF" { "rss_1.0" } else { "rss" };
    ch.version = root.attr("version").map(str::to_string).or_else(|| (root.name == "RDF").then(|| "1.0".into()));
    let Some(channel) = tree.child(root, "channel") else { return };
    ch.title = tree.text(channel, "title").map(str::to_string);
    ch.link = tree.text(channel, "link").map(str::to_string);
    ch.description = tree.text(channel, "description").map(str::to_string);
    ch.language = tree.text(channel, "language").map(str::to_string);
    ch.generator = tree.text(channel, "generator").map(str::to_string);
    ch.copyright = tree.text(channel, "copyright").or_else(|| tree.text(channel, "rights")).map(str::to_string);
    ch.updated = ["lastBuildDate", "pubDate", "date"].iter().find_map(|k| tree.text(channel, k)).and_then(parse_date);
    for key in ["managingEditor", "creator", "author"] {
        if let Some(a) = tree.text(channel, key) {
            ch.authors.push(person(a));
        }
    }
    ch.image = tree.child(channel, "image").and_then(|i| tree.text(i, "url")).map(str::to_string);
    ch.podcast = tree.children(channel, "*").any(|c| c.qname.starts_with("itunes:"));
    // RSS 1.0 puts items next to the channel; 2.0 inside it.
    let items = tree.children(channel, "item").chain(tree.children(root, "item"));
    for it in items {
        ch.items.push(Item {
            title: tree.text(it, "title").map(str::to_string),
            link: tree.text(it, "link").or_else(|| tree.text(it, "guid")).map(str::to_string),
            date: ["pubDate", "date", "published", "updated"]
                .iter()
                .find_map(|k| tree.text(it, k))
                .and_then(parse_date),
            summary: tree.text(it, "description").or_else(|| tree.text(it, "summary")).map(strip_tags),
            authors: ["author", "creator"].iter().filter_map(|k| tree.text(it, k)).map(person).collect(),
            categories: tree.children(it, "category").map(|c| c.text.trim().to_string()).collect(),
            enclosure: tree.child(it, "enclosure").and_then(|e| e.attr("type")).map(str::to_string),
        });
    }
}

fn atom(tree: &XmlTree, root: &XmlNode, ch: &mut Channel) {
    ch.dialect = "atom";
    ch.version = Some("1.0".into());
    let alternate = |node: &XmlNode| {
        tree.children(node, "link")
            .find(|l| l.attr("rel").is_none_or(|r| r == "alternate"))
            .and_then(|l| l.attr("href"))
            .map(str::to_string)
    };
    ch.title = tree.text(root, "title").map(str::to_string);
    ch.link = alternate(root);
    ch.description = tree.text(root, "subtitle").map(str::to_string);
    ch.language = root.attr("lang").map(str::to_string);
    ch.generator = tree.text(root, "generator").map(str::to_string);
    ch.copyright = tree.text(root, "rights").map(str::to_string);
    ch.updated = tree.text(root, "updated").and_then(parse_date);
    ch.authors = tree.children(root, "author").filter_map(|a| tree.text(a, "name")).map(str::to_string).collect();
    ch.image = tree.text(root, "logo").or_else(|| tree.text(root, "icon")).map(str::to_string);
    for e in tree.children(root, "entry") {
        ch.items.push(Item {
            title: tree.text(e, "title").map(str::to_string),
            link: alternate(e),
            date: tree.text(e, "published").or_else(|| tree.text(e, "updated")).and_then(parse_date),
            summary: tree.text(e, "summary").or_else(|| tree.text(e, "content")).map(strip_tags),
            authors: tree.children(e, "author").filter_map(|a| tree.text(a, "name")).map(str::to_string).collect(),
            categories: tree.children(e, "category").filter_map(|c| c.attr("term")).map(str::to_string).collect(),
            enclosure: tree
                .children(e, "link")
                .find(|l| l.attr("rel") == Some("enclosure"))
                .and_then(|l| l.attr("type"))
                .map(str::to_string),
        });
    }
}

fn json_feed(v: &Value, cx: &mut Context<'_>) {
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let names = |v: &Value| -> Vec<String> {
        let mut out: Vec<String> = v
            .get("authors")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.get("name").and_then(Value::as_str)).map(str::to_string).collect())
            .unwrap_or_default();
        if let Some(n) = v.get("author").and_then(|a| a.get("name")).and_then(Value::as_str) {
            out.push(n.to_string());
        }
        out
    };
    let mut ch = Channel {
        dialect: "json_feed",
        version: s(v, "version").map(|u| u.rsplit('/').next().unwrap_or(&u).to_string()),
        title: s(v, "title"),
        link: s(v, "home_page_url"),
        description: s(v, "description"),
        language: s(v, "language"),
        authors: names(v),
        image: s(v, "icon"),
        ..Channel::default()
    };
    for it in v.get("items").and_then(Value::as_array).into_iter().flatten() {
        ch.items.push(Item {
            title: s(it, "title"),
            link: s(it, "url"),
            date: s(it, "date_published").or_else(|| s(it, "date_modified")).and_then(|d| parse_date(&d)),
            summary: s(it, "summary")
                .or_else(|| s(it, "content_text"))
                .or_else(|| s(it, "content_html").map(|h| strip_tags(&h))),
            authors: names(it),
            categories: it
                .get("tags")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default(),
            enclosure: it
                .get("attachments")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(|a| s(a, "mime_type")),
        });
    }
    report(&ch, cx);
}

fn report(ch: &Channel, cx: &mut Context<'_>) {
    if let Some(t) = &ch.title {
        cx.content().source("feed.title").title(t.clone());
        cx.emit_text(TextRole::Title, t);
    }
    if let Some(d) = &ch.description {
        let d = strip_tags(d);
        cx.content().source("feed.description").description(d.clone());
        cx.emit_text(TextRole::Body, &d);
    }
    if let Some(l) = &ch.language {
        let code = l.split(['-', '_']).next().unwrap_or(l).to_ascii_lowercase();
        if (2..=3).contains(&code.len()) {
            cx.content().source("feed.language").language(code, 1.0);
        }
    }
    for a in &ch.authors {
        cx.content().source("feed.author").author(a.clone());
    }
    if let Some(c) = &ch.copyright {
        cx.rights().source("feed.copyright").copyright(c.clone());
    }
    if let Some((d, tz)) = ch.updated.clone() {
        cx.temporal().source("feed.updated").content_date(DateField::Modified, d, tz);
    }

    let mut dated: Vec<&(String, bool)> = ch.items.iter().filter_map(|i| i.date.as_ref()).collect();
    dated.sort_by(|a, b| a.0.cmp(&b.0));
    if let (Some(oldest), Some(newest)) = (dated.first(), dated.last()) {
        cx.temporal().source("feed.oldest_item").content_date(DateField::Created, oldest.0.clone(), oldest.1);
        cx.temporal().source("feed.newest_item").content_date(DateField::Published, newest.0.clone(), newest.1);
    }
    let mut categories: BTreeMap<String, u64> = BTreeMap::new();
    let mut enclosures: BTreeMap<String, u64> = BTreeMap::new();
    for it in &ch.items {
        if let Some(t) = &it.title {
            cx.emit_text(TextRole::Heading(2), t);
        }
        if let Some(s) = &it.summary {
            cx.emit_text(TextRole::Body, s);
        }
        for c in it.categories.iter().filter(|c| !c.is_empty()) {
            *categories.entry(c.clone()).or_default() += 1;
        }
        if let Some(e) = &it.enclosure {
            *enclosures.entry(e.clone()).or_default() += 1;
        }
    }
    let mut top: Vec<(&String, &u64)> = categories.iter().collect();
    top.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    for (c, _) in top.iter().take(10) {
        cx.content().source("feed.category").tag((*c).clone());
    }

    let mut items: Vec<&Item> = ch.items.iter().collect();
    items.sort_by(|a, b| b.date.as_ref().map(|d| &d.0).cmp(&a.date.as_ref().map(|d| &d.0)));
    let latest: Vec<Value> = items
        .iter()
        .take(LATEST)
        .map(|i| json!({ "title": i.title, "link": i.link, "date": i.date.as_ref().map(|d| &d.0) }))
        .collect();
    let authors: std::collections::BTreeSet<&String> = ch.items.iter().flat_map(|i| i.authors.iter()).collect();
    let fmt = cx.format();
    let mut put = |k: &str, v: Value| {
        if !v.is_null() {
            fmt.insert(k.to_string(), v);
        }
    };
    put("dialect", json!(ch.dialect));
    put("version", json!(ch.version));
    put("link", json!(ch.link));
    put("generator", json!(ch.generator));
    put("image", json!(ch.image));
    put("items", json!(ch.items.len()));
    put("newest_item", json!(dated.last().map(|d| &d.0)));
    put("oldest_item", json!(dated.first().map(|d| &d.0)));
    put("item_authors", json!(authors.len()));
    if !top.is_empty() {
        put("top_categories", Value::Object(top.iter().take(10).map(|(k, n)| ((*k).clone(), json!(n))).collect()));
    }
    if !enclosures.is_empty() {
        put("enclosure_types", json!(enclosures));
    }
    put("podcast", json!(ch.podcast || enclosures.keys().any(|t| t.starts_with("audio/") || t.starts_with("video/"))));
    put("latest", Value::Array(latest));
}

fn opml(tree: &XmlTree, cx: &mut Context<'_>) {
    let root = tree.root();
    let head = tree.child(root, "head");
    if let Some(t) = head.and_then(|h| tree.text(h, "title")) {
        cx.content().source("opml.title").title(t);
    }
    if let Some(o) = head.and_then(|h| tree.text(h, "ownerName")) {
        cx.content().source("opml.ownerName").author(o);
    }
    for (key, field) in [("dateCreated", DateField::Created), ("dateModified", DateField::Modified)] {
        if let Some((d, tz)) = head.and_then(|h| tree.text(h, key)).and_then(parse_date) {
            cx.temporal().source(format!("opml.{key}")).content_date(field, d, tz);
        }
    }
    let Some(body) = tree.child(root, "body") else { return };
    // Walk outlines iteratively: (node, depth).
    let mut stack: Vec<(&XmlNode, u8)> = tree.children(body, "outline").map(|o| (o, 1)).collect();
    stack.reverse();
    let (mut outlines, mut feeds, mut max_depth) = (0u64, 0u64, 0u8);
    let mut hosts: BTreeMap<String, u64> = BTreeMap::new();
    while let Some((node, depth)) = stack.pop() {
        outlines += 1;
        max_depth = max_depth.max(depth);
        let text = node.attr("text").or_else(|| node.attr("title")).unwrap_or("");
        if let Some(url) = node.attr("xmlUrl") {
            feeds += 1;
            if let Some(h) = url_host(url) {
                *hosts.entry(h).or_default() += 1;
            }
        } else if !text.is_empty() {
            cx.emit_heading(depth, text);
        }
        if !text.is_empty() {
            cx.emit_text(TextRole::Body, text);
        }
        let mut kids: Vec<(&XmlNode, u8)> =
            tree.children(node, "outline").map(|o| (o, depth.saturating_add(1))).collect();
        kids.reverse();
        stack.extend(kids);
    }
    cx.format_set("outlines", outlines);
    cx.format_set("feeds", feeds);
    cx.format_set("max_depth", max_depth);
    if !hosts.is_empty() {
        cx.format_set("feed_hosts", hosts.len());
    }
}

fn sitemap(tree: &XmlTree, cx: &mut Context<'_>) {
    let root = tree.root();
    let index = root.name == "sitemapindex";
    let entries: Vec<&XmlNode> = tree.children(root, if index { "sitemap" } else { "url" }).collect();
    let mut hosts: BTreeMap<String, u64> = BTreeMap::new();
    let mut changefreq: BTreeMap<String, u64> = BTreeMap::new();
    let mut dates: Vec<(String, bool)> = Vec::new();
    let (mut priority_sum, mut priorities) = (0.0, 0u32);
    for e in &entries {
        if let Some(h) = tree.text(e, "loc").and_then(url_host) {
            *hosts.entry(h).or_default() += 1;
        }
        if let Some(d) = tree.text(e, "lastmod").and_then(parse_date) {
            dates.push(d);
        }
        if let Some(c) = tree.text(e, "changefreq") {
            *changefreq.entry(c.to_ascii_lowercase()).or_default() += 1;
        }
        if let Some(p) = tree.text(e, "priority").and_then(|p| p.parse::<f64>().ok()) {
            priority_sum += p;
            priorities += 1;
        }
    }
    dates.sort();
    if let (Some(first), Some(last)) = (dates.first(), dates.last()) {
        cx.temporal().source("sitemap.lastmod").content_date(DateField::Modified, last.0.clone(), last.1);
        cx.format_set("lastmod_range", json!([first.0, last.0]));
    }
    cx.format_set("kind", if index { "index" } else { "urlset" });
    cx.format_set(if index { "sitemaps" } else { "urls" }, entries.len());
    cx.format_set("hosts", json!(hosts));
    if !changefreq.is_empty() {
        cx.format_set("changefreq", json!(changefreq));
    }
    if priorities > 0 {
        cx.format_set("mean_priority", (priority_sum / f64::from(priorities) * 1000.0).round() / 1000.0);
    }
    cx.security().external_references(entries.len() as u64);
}

/// `editor@example.org (Ada Lovelace)` → `Ada Lovelace`; e-mail-only stays as is.
fn person(s: &str) -> String {
    let s = s.trim();
    match (s.find('('), s.rfind(')')) {
        (Some(a), Some(b)) if b > a + 1 => s[a + 1..b].trim().to_string(),
        _ => s.split('<').next().unwrap_or(s).trim().to_string(),
    }
}

/// HTML fragments in descriptions → plain text.
fn strip_tags(s: &str) -> String {
    static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]{0,2000}>").expect("valid"));
    let text = TAG.replace_all(s, " ");
    let text = text
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    truncate_chars(&squash_whitespace(&text), 2000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(person("editor@example.org (Ada Lovelace)"), "Ada Lovelace");
        assert_eq!(person("Ada <ada@example.org>"), "Ada");
        assert_eq!(strip_tags("<p>Hello &amp; <b>welcome</b></p>"), "Hello & welcome");
    }

    crate::fixture_tests!("rss", "atom", "json_feed", "opml", "sitemap");
}
