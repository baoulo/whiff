//! SVG and SVGZ: size and viewBox, `<title>` / `<desc>`, the `<metadata>`
//! RDF (sent to the XMP decoder), the editor (Inkscape, Illustrator,
//! Sketch, Figma…), element statistics, embedded and linked resources, the
//! visible text, and active content (scripts, event handlers,
//! `foreignObject`, external references), which is flagged as a risk.
//!
//! Specification: SVG 1.1 / SVG 2 (W3C).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use quick_xml::events::{BytesStart, Event};
use serde_json::{Value, json};

use crate::plugin::{
    BlockKind, Compression, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source,
    TextRole, truncate_chars,
};

/// Extractor for SVG and SVGZ.
pub struct Svg;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.svg",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "svg",
            name: "SVG image",
            family: "image.vector",
            mimes: &["image/svg+xml"],
            extensions: &["svg"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "svgz",
            name: "Compressed SVG image",
            family: "image.vector",
            mimes: &["image/svg+xml-compressed"],
            extensions: &["svgz"],
            magic: &[],
            parent: None,
        },
    ],
};

const MAX_EVENTS: usize = 2_000_000;
/// Decompressed size of an SVGZ.
const MAX_SVGZ: usize = 64 << 20;
const MAX_TEXT: usize = 256 * 1024;

impl Extractor for Svg {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if probe.head.starts_with(&[0x1f, 0x8b]) {
            return (probe.extension == Some("svgz")).then_some(Sniff { format: "svgz", confidence: 0.9 });
        }
        let text = String::from_utf8_lossy(&probe.head[..probe.head.len().min(8192)]);
        let root = after_prolog(&text)?;
        let is_svg =
            root.starts_with("<svg") && root[4..].starts_with(|c: char| c.is_whitespace() || c == '>' || c == '/');
        let prefixed = root.starts_with('<')
            && root.split(|c: char| c.is_whitespace() || c == '>').next().is_some_and(|n| n.ends_with(":svg"));
        (is_svg || prefixed).then_some(Sniff { format: "svg", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, _) = cx.read_bytes(src)?;
        let bytes = if cx.format_id() == "svgz" || bytes.starts_with(&[0x1f, 0x8b]) {
            let b = cx.inflate(&bytes, Compression::Gzip, MAX_SVGZ)?;
            cx.format_set("compressed_bytes", bytes.len());
            b
        } else {
            bytes
        };
        let text = crate::plugin::decode_text(&bytes).text;
        let mut s = Scan::default();
        s.run(&text, cx)?;
        s.report(&text, cx);
        Ok(())
    }
}

crate::register_extractor!(Svg);

/// The document after the XML declaration, comments and doctype.
fn after_prolog(text: &str) -> Option<&str> {
    let mut s = text.trim_start_matches('\u{feff}').trim_start();
    loop {
        if let Some(rest) = s.strip_prefix("<?") {
            s = rest.split_once("?>")?.1.trim_start();
        } else if let Some(rest) = s.strip_prefix("<!--") {
            s = rest.split_once("-->")?.1.trim_start();
        } else if s.get(..9).is_some_and(|p| p.eq_ignore_ascii_case("<!doctype")) {
            // Internal subsets end with `]>`.
            let end = if s[..s.find('>')?].contains('[') { s.find("]>")? + 2 } else { s.find('>')? + 1 };
            s = s[end..].trim_start();
        } else {
            return Some(s);
        }
    }
}

fn local(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_string()
}

#[derive(Default)]
struct Scan {
    root: Option<BTreeMap<String, String>>,
    elements: u64,
    names: BTreeMap<String, u64>,
    depth: usize,
    /// Depth of the open `<title>` / `<desc>` / `<text>` element, if any.
    capture: Option<(String, usize)>,
    captured: String,
    title: Option<String>,
    desc: Option<String>,
    texts: String,
    /// Byte range of the first `<metadata>` element's content.
    metadata: Option<(usize, usize)>,
    metadata_start: Option<(usize, usize)>,
    scripts: u64,
    handlers: u64,
    foreign_objects: u64,
    external_refs: Vec<String>,
    data_uris: u64,
    images: u64,
    layers: Vec<String>,
    fonts: BTreeMap<String, u64>,
    error: Option<String>,
    entities: bool,
}

impl Scan {
    fn run(&mut self, text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut reader = quick_xml::Reader::from_str(text);
        reader.config_mut().check_end_names = false;
        for n in 0..MAX_EVENTS {
            if n % 4096 == 0 {
                cx.checkpoint()?;
            }
            let before = usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX);
            match reader.read_event() {
                Ok(Event::Start(e)) => {
                    self.open(&e);
                    self.depth += 1;
                    if local(e.name().as_ref()) == "metadata" && self.metadata_start.is_none() {
                        self.metadata_start =
                            Some((usize::try_from(reader.buffer_position()).unwrap_or(usize::MAX), self.depth));
                    }
                }
                Ok(Event::Empty(e)) => self.open(&e),
                Ok(Event::End(e)) => {
                    if let Some((start, d)) = self.metadata_start
                        && d == self.depth
                        && self.metadata.is_none()
                    {
                        self.metadata = Some((start, before));
                    }
                    let name = local(e.name().as_ref());
                    if let Some((cap, d)) = &self.capture
                        && *cap == name
                        && *d == self.depth
                    {
                        let t = crate::plugin::squash_whitespace(&std::mem::take(&mut self.captured));
                        match name.as_str() {
                            "title" if self.title.is_none() && !t.is_empty() => self.title = Some(t),
                            "desc" if self.desc.is_none() && !t.is_empty() => self.desc = Some(t),
                            "text" if self.texts.len() < MAX_TEXT && !t.is_empty() => {
                                self.texts.push_str(&t);
                                self.texts.push('\n');
                            }
                            _ => {}
                        }
                        self.capture = None;
                    }
                    self.depth = self.depth.saturating_sub(1);
                }
                Ok(Event::Text(t)) => {
                    if self.capture.is_some() && self.captured.len() < 64 * 1024 {
                        self.captured.push_str(&t.xml10_content());
                    }
                }
                Ok(Event::CData(t)) => {
                    if self.capture.is_some() && self.captured.len() < 64 * 1024 {
                        self.captured.push_str(&t.xml10_content());
                    }
                }
                Ok(Event::GeneralRef(r)) => {
                    if self.capture.is_some() {
                        match &*r {
                            "amp" => self.captured.push('&'),
                            "lt" => self.captured.push('<'),
                            "gt" => self.captured.push('>'),
                            "quot" => self.captured.push('"'),
                            "apos" => self.captured.push('\''),
                            _ => {
                                if let Ok(Some(c)) = r.resolve_char_ref() {
                                    self.captured.push(c);
                                }
                            }
                        }
                    }
                }
                Ok(Event::DocType(d)) => self.entities |= d.xml10_content().contains("<!ENTITY"),
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(e) => {
                    self.error = Some(e.to_string());
                    break;
                }
            }
        }
        Ok(())
    }

    fn open(&mut self, e: &BytesStart<'_>) {
        let qname = e.name().as_ref().to_string();
        let name = local(&qname);
        self.elements += 1;
        if self.names.len() < 200 || self.names.contains_key(&name) {
            *self.names.entry(name.clone()).or_default() += 1;
        }
        let mut attrs = BTreeMap::new();
        for a in e.attributes().flatten().take(256) {
            let key = a.key.as_ref().to_string();
            let value = a
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map(std::borrow::Cow::into_owned)
                .unwrap_or_default();
            let lk = local(&key);
            if lk.len() > 2 && lk.starts_with("on") && !key.contains(':') {
                self.handlers += 1;
            }
            if lk == "href" || key == "src" {
                let v = value.trim();
                if v.starts_with("data:") {
                    self.data_uris += 1;
                } else if v.starts_with("javascript:") {
                    self.handlers += 1;
                } else if (v.starts_with("http:")
                    || v.starts_with("https:")
                    || v.starts_with("//")
                    || v.starts_with("file:"))
                    && self.external_refs.len() < 32
                {
                    self.external_refs.push(truncate_chars(v, 300));
                }
            }
            if lk == "font-family" {
                *self.fonts.entry(value.trim_matches(['\'', '"', ' ']).to_string()).or_default() += 1;
            }
            if attrs.len() < 64 {
                attrs.insert(key, value);
            }
        }
        if self.root.is_none() {
            self.root = Some(attrs.clone());
        }
        match name.as_str() {
            "script" => self.scripts += 1,
            "foreignObject" => self.foreign_objects += 1,
            "image" => self.images += 1,
            "title" | "desc" | "text" if self.capture.is_none() => {
                self.capture = Some((name.clone(), self.depth + 1));
                self.captured.clear();
            }
            "g" if attrs.get("inkscape:groupmode").is_some_and(|m| m == "layer") && self.layers.len() < 64 => {
                self.layers.push(attrs.get("inkscape:label").cloned().unwrap_or_default());
            }
            _ => {}
        }
    }

    fn report(&mut self, text: &str, cx: &mut Context<'_>) {
        let root = self.root.take().unwrap_or_default();
        let get = |k: &str| root.get(k).map(String::as_str);
        let view_box: Option<Vec<f64>> =
            get("viewBox").map(|v| v.split([' ', ',']).filter_map(|n| n.trim().parse().ok()).collect());
        let (w, h) = (get("width").and_then(length), get("height").and_then(length));
        let size = match (w, h, view_box.as_deref()) {
            (Some(w), Some(h), _) => Some((w, h)),
            (_, _, Some([_, _, vw, vh])) => Some((*vw, *vh)),
            _ => None,
        };
        if let Some((w, h)) = size
            && w > 0.0
            && h > 0.0
        {
            cx.physical().image(super::px(w), super::px(h));
        }
        cx.format_set("width", get("width"));
        cx.format_set("height", get("height"));
        if let Some(v) = view_box {
            cx.format_set("view_box", json!(v));
        }
        if let Some(v) = get("version") {
            cx.format_set("version", v);
        }
        let editor = if let Some(v) = get("inkscape:version") {
            Some(format!("Inkscape {}", v.split_whitespace().next().unwrap_or(v)))
        } else if text.contains("Generator: Adobe Illustrator") {
            text.split("Generator: Adobe Illustrator").nth(1).map(|r| {
                format!("Adobe Illustrator {}", r.split([',', ' ']).find(|s| !s.is_empty()).unwrap_or(""))
                    .trim()
                    .to_string()
            })
        } else if text.contains("Generator: Sketch") || root.keys().any(|k| k.starts_with("xmlns:sketch")) {
            Some("Sketch".to_string())
        } else if text.contains("<!-- Created with Vectornator") {
            Some("Vectornator".to_string())
        } else {
            None
        };
        if let Some(e) = editor {
            cx.format_set("software", e);
        }
        if let Some(d) = get("sodipodi:docname") {
            cx.format_set("document_name", d);
        }
        if !self.layers.is_empty() {
            cx.format_set("layers", json!(self.layers));
        }
        if let Some(t) = self.title.take() {
            cx.content().source("svg.title").title(truncate_chars(&t, 2000));
            cx.emit_text(TextRole::Title, &t);
        }
        if let Some(d) = self.desc.take() {
            cx.content().source("svg.desc").description(truncate_chars(&d, 4000));
            cx.emit_text(TextRole::Caption, &d);
        }
        if !self.texts.is_empty() {
            cx.emit_text(TextRole::Body, &self.texts);
        }
        if let Some((a, b)) = self.metadata
            && let Some(m) = text.get(a..b)
            && m.contains("RDF")
        {
            // The RDF's namespaces are usually declared on `<svg>`: carry
            // them over so the fragment parses on its own.
            let mut packet = String::from("<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"");
            for (k, v) in root.iter().filter(|(k, _)| k.starts_with("xmlns:")) {
                let _ = write!(packet, " {k}=\"{}\"", v.replace('&', "&amp;").replace('"', "&quot;"));
            }
            packet.push('>');
            packet.push_str(m.trim());
            packet.push_str("</x:xmpmeta>");
            cx.emit_block(BlockKind::XMP, packet.into_bytes());
        }
        cx.format_set("elements", self.elements);
        let mut top: Vec<(&String, &u64)> = self.names.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        cx.format_set(
            "element_counts",
            top.iter().take(20).map(|(k, v)| ((*k).clone(), json!(v))).collect::<serde_json::Map<String, Value>>(),
        );
        cx.format_set("embedded_images", self.data_uris);
        cx.format_set("image_elements", self.images);
        if !self.fonts.is_empty() {
            cx.format_set("fonts", json!(self.fonts.keys().take(32).collect::<Vec<_>>()));
        }
        if let Some(e) = self.error.take() {
            cx.warn(format!("XML error: {e}"));
            cx.format_set("well_formed", false);
        }
        self.risks(cx);
    }

    /// Active content and external references.
    fn risks(&self, cx: &mut Context<'_>) {
        if self.scripts > 0 {
            cx.format_set("scripts", self.scripts);
            cx.security().risk("script", Some(format!("{} <script> element(s)", self.scripts)));
        }
        if self.handlers > 0 {
            cx.format_set("event_handlers", self.handlers);
            cx.security().risk("script", Some(format!("{} event handler / javascript: attribute(s)", self.handlers)));
        }
        if self.foreign_objects > 0 {
            cx.format_set("foreign_objects", self.foreign_objects);
            cx.security().risk("active_content", Some(format!("{} <foreignObject> element(s)", self.foreign_objects)));
        }
        if !self.external_refs.is_empty() {
            cx.format_set("external_references", json!(self.external_refs));
            cx.security().risk("external_reference", Some(format!("{} external link(s)", self.external_refs.len())));
        }
        if self.entities {
            cx.security().risk("xml_entities", Some("DOCTYPE declares entities".into()));
        }
    }
}

/// An SVG length in user units (px); relative units give `None`.
fn length(v: &str) -> Option<f64> {
    let v = v.trim();
    let split = v
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == '+' || c == 'e' || c == 'E'))
        .unwrap_or(v.len());
    let (n, unit) = v.split_at(split);
    let n: f64 = n.parse().ok()?;
    let k = match unit.trim() {
        "" | "px" => 1.0,
        "pt" => 4.0 / 3.0,
        "pc" => 16.0,
        "mm" => 96.0 / 25.4,
        "cm" => 96.0 / 2.54,
        "in" => 96.0,
        _ => return None,
    };
    Some(n * k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_and_prolog() {
        assert_eq!(length("100"), Some(100.0));
        assert_eq!(length("1in"), Some(96.0));
        assert_eq!(length("50%"), None);
        assert!(
            after_prolog("<?xml version='1.0'?>\n<!-- c -->\n<!DOCTYPE svg [ <!ENTITY a 'b'> ]>\n<svg>")
                .unwrap()
                .starts_with("<svg")
        );
    }

    crate::fixture_tests!("svg", "svgz");
}
