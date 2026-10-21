//! Markup subtitles: TTML (TTML 1 / 2, DFXP, IMSC, SMPTE-TT, EBU-TT), SAMI,
//! and YouTube timed text (srv1 / srv2 / srv3 XML, json3). Cues with
//! nested TTML timing (time containers, frames, ticks), agents as
//! speakers, styles and regions, document metadata, image cues; SAMI
//! classes and their languages.
//!
//! Specifications: <https://www.w3.org/TR/ttml2/>, <https://www.w3.org/TR/ttml-imsc1.2/>,
//! EBU Tech 3350, SMPTE ST 2052-1, Microsoft SAMI 1.0.

use std::collections::BTreeMap;

use quick_xml::events::{BytesStart, Event};
use serde_json::{Value, json};

use super::super::text::{decode_xml, entity_text, local, xml_root};
use super::{Cue, Subtitles, clock, head_text, plain_text};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, truncate_chars,
};

/// Extractor for markup subtitles.
pub struct Markup;

static META: ExtractorMeta = ExtractorMeta {
    id: "subtitle.markup",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "ttml",
            name: "TTML timed text",
            family: "text.subtitle",
            mimes: &["application/ttml+xml"],
            extensions: &["ttml", "dfxp"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "sami",
            name: "SAMI captions",
            family: "text.subtitle",
            mimes: &["application/x-sami"],
            extensions: &["smi", "sami"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "srv3",
            name: "YouTube timed text",
            family: "text.subtitle",
            mimes: &["application/x-youtube-timedtext"],
            extensions: &["srv3", "srv2", "srv1"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "json3",
            name: "YouTube timed text (JSON)",
            family: "text.subtitle",
            mimes: &["application/x-youtube-json3"],
            extensions: &["json3"],
            magic: &[],
            parent: Some("json"),
        },
    ],
};

/// XML elements read before giving up on a TTML document.
const MAX_ELEMENTS: usize = 2_000_000;
/// Element nesting followed in a TTML document.
const MAX_DEPTH: usize = 256;

impl Extractor for Markup {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let found = |format| Some(Sniff { format, confidence: 0.95 });
        let text = head_text(probe.head);
        let t = text.trim_start();
        if t.starts_with('{') {
            let head = super::prefix(t, 4096);
            return if head.contains("\"wireMagic\"") || (head.contains("\"events\"") && head.contains("\"tStartMs\"")) {
                found("json3")
            } else {
                None
            };
        }
        if t.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("<sami")) {
            return found("sami");
        }
        let root = xml_root(probe.head)?;
        match local(&root).as_str() {
            "tt" => found("ttml"),
            "timedtext" => found("srv3"),
            "transcript" if t.contains("<text start=") => found("srv3"),
            _ => None,
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, _) = cx.read_bytes(src)?;
        let subs = match cx.format_id() {
            "sami" => sami(&crate::plugin::decode_text(&bytes).text),
            "json3" => {
                let text = crate::plugin::decode_text(&bytes).text;
                let v: Value = serde_json::from_str(&text).map_err(|e| ExtractError::malformed(e.to_string()))?;
                json3(&v)
            }
            "srv3" => srv(&decode_xml(&bytes)).map_err(ExtractError::malformed)?,
            _ => {
                let text = decode_xml(&bytes);
                cx.checkpoint()?;
                ttml(&text, cx)?
            }
        };
        if subs.cues.is_empty() {
            cx.warn("no cues found");
        }
        subs.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Markup);

fn attrs(e: &BytesStart<'_>) -> Vec<(String, String)> {
    e.attributes()
        .flatten()
        .take(64)
        .map(|a| {
            let v = a
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map(std::borrow::Cow::into_owned)
                .unwrap_or_default();
            (a.key.as_ref().to_string(), v)
        })
        .collect()
}

/// Attribute by qualified or local name.
fn attr<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs.iter().find(|(k, _)| k == name || local(k) == name).map(|(_, v)| v.as_str())
}

/// How a TTML document counts time.
#[derive(Debug, Clone, Copy)]
struct Clock {
    /// Effective frame rate (frame rate × multiplier).
    fps: f64,
    /// Sub-frames per frame.
    sub: f64,
    /// Ticks per second.
    ticks: f64,
}

impl Clock {
    /// A TTML time expression: clock time (`00:00:01.5`, `00:00:01:12`) or
    /// offset time (`1.5s`, `300ms`, `25f`, `9000t`).
    fn parse(&self, s: &str) -> Option<f64> {
        let s = s.trim();
        if s.contains(':') {
            let parts: Vec<&str> = s.split(':').collect();
            return match parts.len() {
                3 => clock(s),
                4 => {
                    let base = clock(&parts[..3].join(":"))?;
                    let (f, sub) = parts[3].split_once('.').unwrap_or((parts[3], "0"));
                    let frames: f64 = f.parse().ok()?;
                    let sub: f64 = sub.parse().unwrap_or(0.0);
                    Some(base + (frames + sub / self.sub) / self.fps)
                }
                _ => None,
            };
        }
        let at = s.find(|c: char| c.is_ascii_alphabetic())?;
        let (n, unit) = s.split_at(at);
        let n: f64 = n.parse().ok().filter(|n: &f64| n.is_finite())?;
        Some(match unit {
            "h" => n * 3600.0,
            "m" => n * 60.0,
            "s" => n,
            "ms" => n / 1000.0,
            "f" => n / self.fps,
            "t" => n / self.ticks,
            _ => return None,
        })
    }
}

/// One open TTML element: its absolute begin and end, and what it is.
struct Open {
    name: String,
    begin: f64,
    end: Option<f64>,
    /// Inside a `p` (text is collected), with the paragraph's agent.
    in_p: bool,
}

#[allow(clippy::too_many_lines)] // one event loop over the document
fn ttml(text: &str, cx: &mut Context<'_>) -> Result<Subtitles, ExtractError> {
    let mut s = Subtitles::new("ttml");
    let mut reader = quick_xml::Reader::from_str(text);
    let cfg = reader.config_mut();
    cfg.check_end_names = false;
    cfg.expand_empty_elements = true;
    let mut clock = Clock { fps: 30.0, sub: 1.0, ticks: 1.0 };
    let mut stack: Vec<Open> = Vec::new();
    let (mut styles, mut regions, mut images, mut elements) = (0u64, 0u64, 0u64, 0usize);
    let mut agents: BTreeMap<String, String> = BTreeMap::new();
    let mut agent_id: Option<String> = None;
    let mut meta_text: Option<String> = None;
    let mut meta_field = String::new();
    let mut ebu: serde_json::Map<String, Value> = serde_json::Map::new();
    // The paragraph being collected: begin, end, raw text, agent.
    let mut para: Option<(f64, Option<f64>, String, Option<String>)> = None;
    loop {
        let ev = match reader.read_event() {
            Ok(ev) => ev,
            Err(e) if stack.is_empty() && elements == 0 => return Err(ExtractError::malformed(e.to_string())),
            Err(_) => break,
        };
        match ev {
            Event::Start(e) => {
                elements += 1;
                if elements > MAX_ELEMENTS || stack.len() >= MAX_DEPTH {
                    break;
                }
                if elements.is_multiple_of(1 << 14) {
                    cx.checkpoint()?;
                }
                let qname = e.name().as_ref().to_string();
                let name = local(&qname);
                let a = attrs(&e);
                let parent = stack.last();
                let (pb, pe) = parent.map_or((0.0, None), |p| (p.begin, p.end));
                if stack.is_empty() {
                    root_facts(&a, &mut s, &mut clock);
                }
                let begin = pb + attr(&a, "begin").and_then(|t| clock.parse(t)).unwrap_or(0.0);
                let end = match (
                    attr(&a, "end").and_then(|t| clock.parse(t)),
                    attr(&a, "dur").and_then(|t| clock.parse(t)),
                ) {
                    (Some(e), _) => Some(pb + e),
                    (None, Some(d)) => Some(begin + d),
                    (None, None) => pe,
                };
                let end = match (end, pe) {
                    (Some(e), Some(p)) => Some(e.min(p)),
                    (e, _) => e,
                };
                if a.iter().any(|(k, _)| local(k) == "backgroundImage")
                    || name == "image" && stack.iter().any(|o| o.name == "body")
                {
                    images += 1;
                }
                let in_p = parent.is_some_and(|p| p.in_p) || name == "p";
                match name.as_str() {
                    "style" if stack.iter().any(|o| o.name == "head") => styles += 1,
                    "region" if stack.iter().any(|o| o.name == "head") => regions += 1,
                    "agent" => agent_id = attr(&a, "id").map(str::to_string),
                    "name" | "title" | "desc" | "copyright"
                        if qname.contains(':') || stack.iter().any(|o| o.name == "metadata") =>
                    {
                        meta_field.clone_from(&name);
                        meta_text = Some(String::new());
                    }
                    n if qname.starts_with("ebuttm:") && n.starts_with("document") => {
                        meta_field.clone_from(&qname);
                        meta_text = Some(String::new());
                    }
                    "p" => {
                        let agent = attr(&a, "agent").map(str::to_string);
                        para = Some((begin, end, String::new(), agent));
                    }
                    "br" => {
                        if let Some(p) = para.as_mut() {
                            p.2.push('\n');
                        }
                    }
                    "span" => {
                        if let (Some(p), Some(ag)) = (para.as_mut(), attr(&a, "agent")) {
                            p.3.get_or_insert_with(|| ag.to_string());
                        }
                    }
                    _ => {}
                }
                stack.push(Open { name, begin, end, in_p });
            }
            Event::End(_) => {
                let Some(open) = stack.pop() else { break };
                if let Some(t) = meta_text.take_if(|_| meta_field.ends_with(open.name.as_str())) {
                    let t = t.trim().to_string();
                    match open.name.as_str() {
                        "name" => {
                            if let Some(id) = agent_id.clone() {
                                agents.insert(id, t);
                            }
                        }
                        "title" => s.title = Some(t),
                        "desc" => s.set("description", t),
                        "copyright" => s.copyright = Some(t),
                        _ => {
                            let key = meta_field.trim_start_matches("ebuttm:document").to_string();
                            if !t.is_empty() && ebu.len() < 32 {
                                ebu.insert(snake(&key), json!(truncate_chars(&t, 200)));
                            }
                        }
                    }
                    meta_field.clear();
                }
                if open.name == "p"
                    && let Some((begin, end, raw, agent)) = para.take()
                {
                    let text = plain_text(&raw, &mut s.markup);
                    let speaker = agent.map(|id| agents.get(&id).cloned().unwrap_or(id));
                    s.push(Cue { start: begin, end, text, speaker });
                }
                if open.name == "agent" {
                    agent_id = None;
                }
            }
            Event::Text(t) => {
                let t = t.xml10_content();
                push_text(&mut para, &mut meta_text, &stack, &t);
            }
            Event::CData(t) => {
                let t = t.xml10_content();
                push_text(&mut para, &mut meta_text, &stack, &t);
            }
            Event::GeneralRef(r) => {
                if let Some(t) = entity_text(&r) {
                    push_text(&mut para, &mut meta_text, &stack, &t);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if elements == 0 {
        return Err(ExtractError::malformed("no root element"));
    }
    s.cues.sort_by(|a, b| a.start.total_cmp(&b.start));
    for (k, v) in [("style_definitions", styles), ("regions", regions), ("image_cues", images)] {
        if v > 0 {
            s.set(k, v);
        }
    }
    if !agents.is_empty() {
        s.set("agents", agents.len());
    }
    s.set("ebu_metadata", Value::Object(ebu));
    Ok(s)
}

fn push_text(
    para: &mut Option<(f64, Option<f64>, String, Option<String>)>,
    meta: &mut Option<String>,
    stack: &[Open],
    t: &str,
) {
    if let Some(m) = meta.as_mut()
        && m.len() < 4096
    {
        m.push_str(t);
    }
    if stack.last().is_some_and(|o| o.in_p)
        && let Some(p) = para.as_mut()
        && p.2.len() < 1 << 16
    {
        // Line breaks in the source are white space; `br` breaks lines.
        p.2.push_str(&t.replace(['\n', '\r'], " "));
    }
}

/// `OriginalProgrammeTitle` → `original_programme_title`.
fn snake(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Root `tt` attributes: language, the time base, the profile and dialect.
fn root_facts(a: &[(String, String)], s: &mut Subtitles, clock: &mut Clock) {
    if let Some(l) = attr(a, "xml:lang").or_else(|| attr(a, "lang")) {
        s.declare_language(l, "ttml.xml:lang");
    }
    let num = |k: &str| attr(a, k).and_then(|v| v.trim().parse::<f64>().ok()).filter(|v| *v > 0.0 && v.is_finite());
    let rate = num("frameRate");
    let multiplier = attr(a, "frameRateMultiplier")
        .and_then(|m| {
            let (n, d) = m.split_once(' ')?;
            Some(n.trim().parse::<f64>().ok()? / d.trim().parse::<f64>().ok()?)
        })
        .filter(|m| m.is_finite() && *m > 0.0)
        .unwrap_or(1.0);
    if let Some(r) = rate {
        clock.fps = r * multiplier;
        s.frame_rate = Some(clock.fps);
    }
    clock.sub = num("subFrameRate").unwrap_or(1.0);
    clock.ticks = num("tickRate").unwrap_or(if rate.is_some() { clock.fps * clock.sub } else { 1.0 });
    if let Some(t) = attr(a, "timeBase") {
        s.set("time_base", t);
    }
    let ns: Vec<&str> = a.iter().filter(|(k, _)| k.starts_with("xmlns")).map(|(_, v)| v.as_str()).collect();
    let profile = attr(a, "profile").unwrap_or("");
    let dialect = if profile.contains("imsc") || ns.iter().any(|n| n.contains("ttml/profile/imsc")) {
        "imsc"
    } else if ns.iter().any(|n| n.starts_with("urn:ebu:tt")) {
        "ebu_tt"
    } else if ns.iter().any(|n| n.contains("smpte-tt")) {
        "smpte_tt"
    } else if ns.iter().any(|n| n.contains("/2006/10/ttaf1") || n.contains("/2006/04/ttaf1")) {
        "dfxp"
    } else {
        "ttml"
    };
    s.set("dialect", dialect);
    if !profile.is_empty() {
        s.set("profile", profile);
    }
}

/// YouTube timed text XML: srv3 (`<p t= d=>`, milliseconds), srv2
/// (`<text t= d=>`) and srv1 (`<text start= dur=>`, seconds).
fn srv(text: &str) -> Result<Subtitles, String> {
    let mut s = Subtitles::new("srv3");
    let mut reader = quick_xml::Reader::from_str(text);
    let cfg = reader.config_mut();
    cfg.check_end_names = false;
    cfg.expand_empty_elements = true;
    let mut cue: Option<(f64, Option<f64>, String)> = None;
    let (mut root, mut windows) = (true, 0u64);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = local(e.name().as_ref());
                let a = attrs(&e);
                if root {
                    root = false;
                    s.set("version", attr(&a, "format").unwrap_or(if name == "transcript" { "1" } else { "2" }));
                }
                let num = |k: &str| attr(&a, k).and_then(|v| v.parse::<f64>().ok()).filter(|v| v.is_finite());
                match name.as_str() {
                    "p" | "text" if cue.is_none() => {
                        let (start, dur) = match (num("t"), num("start")) {
                            (Some(t), _) => (t / 1000.0, num("d").map(|d| d / 1000.0)),
                            (None, Some(st)) => (st, num("dur")),
                            _ => continue,
                        };
                        cue = Some((start, dur.map(|d| start + d), String::new()));
                    }
                    "br" => {
                        if let Some(c) = cue.as_mut() {
                            c.2.push('\n');
                        }
                    }
                    "ws" | "wp" => windows += 1,
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = local(e.name().as_ref());
                if matches!(name.as_str(), "p" | "text")
                    && let Some((start, end, raw)) = cue.take()
                {
                    let text = plain_text(&raw, &mut s.markup);
                    s.push(Cue { start, end, text, speaker: None });
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(c) = cue.as_mut() {
                    c.2.push_str(&t.xml10_content());
                }
            }
            Ok(Event::GeneralRef(r)) => {
                if let (Some(c), Some(t)) = (cue.as_mut(), entity_text(&r)) {
                    c.2.push_str(&t);
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) if root => return Err(e.to_string()),
            Err(_) => break,
        }
    }
    if root {
        return Err("no root element".into());
    }
    if windows > 0 {
        s.set("window_styles", windows);
    }
    Ok(s)
}

/// YouTube json3: `events[]` with `tStartMs`, `dDurationMs` and `segs[].utf8`.
fn json3(v: &Value) -> Subtitles {
    let mut s = Subtitles::new("json3");
    let mut appended = 0u64;
    for ev in v.get("events").and_then(Value::as_array).into_iter().flatten() {
        let Some(segs) = ev.get("segs").and_then(Value::as_array) else { continue };
        let raw: String = segs.iter().filter_map(|g| g.get("utf8").and_then(Value::as_str)).collect();
        if ev.get("aAppend").is_some() {
            appended += 1;
            continue;
        }
        if raw.trim().is_empty() {
            continue;
        }
        let ms = |k: &str| ev.get(k).and_then(Value::as_f64).filter(|v| v.is_finite());
        let Some(start) = ms("tStartMs") else { continue };
        let end = ms("dDurationMs").map(|d| (start + d) / 1000.0);
        let text = plain_text(&raw, &mut s.markup);
        s.push(Cue { start: start / 1000.0, end, text, speaker: None });
    }
    if appended > 0 {
        s.set("append_events", appended);
    }
    if let Some(p) = v.get("pens").and_then(Value::as_array) {
        s.set("pens", p.len());
    }
    s
}

/// SAMI: `<SYNC Start=ms>` blocks holding one `<P Class=…>` per language.
/// A block of only `&nbsp;` clears the screen.
fn sami(text: &str) -> Subtitles {
    let mut s = Subtitles::new("sami");
    let lower = text.to_ascii_lowercase();
    if let Some(t) = between(text, &lower, "<title>", "</title>") {
        s.title = Some(t.trim().to_string());
    }
    // Classes: `.ENUSCC { Name: English; lang: en-US; }`.
    let mut classes: Vec<(String, Option<String>, Option<String>)> = Vec::new();
    if let Some(css) = between(text, &lower, "<style", "</style>") {
        for rule in css.split('}') {
            let Some((sel, body)) = rule.split_once('{') else { continue };
            let sel = sel.trim().trim_start_matches("<!--").trim();
            let Some(class) = sel.strip_prefix('.') else { continue };
            let prop = |name: &str| {
                body.split(';').find_map(|d| {
                    let (k, v) = d.split_once(':')?;
                    k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                })
            };
            classes.push((class.trim().to_string(), prop("name"), prop("lang")));
        }
    }
    s.styles = classes.iter().map(|c| c.0.clone()).collect();
    let languages: Vec<String> = classes.iter().filter_map(|c| c.2.clone()).collect();
    if let Some(first) = languages.first() {
        s.declare_language(first, "sami.lang");
    }
    s.set("languages", languages);
    // A SYNC holds a paragraph per class (language); the class of the first
    // paragraph is the one whose cues are read.
    let mut syncs: Vec<Sync<'_>> = Vec::new();
    let mut at = 0;
    while let Some(i) = lower[at..].find("<sync") {
        let start = at + i;
        let Some(tag_end) = lower[start..].find('>').map(|j| start + j) else { break };
        let ms = attribute(&lower[start..tag_end], "start")
            .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse::<f64>().ok());
        let body_end = lower[tag_end..]
            .find("<sync")
            .map_or_else(|| lower[tag_end..].find("</body").map_or(lower.len(), |j| tag_end + j), |j| tag_end + j);
        if let Some(ms) = ms {
            syncs.push((ms / 1000.0, paragraphs(text, &lower, tag_end + 1, body_end)));
        }
        at = body_end;
    }
    let main = syncs.iter().flat_map(|s| s.1.iter()).find_map(|p| p.0.clone());
    let mine = |p: &&(Option<String>, &str)| p.0.is_none() || main.is_none() || p.0 == main;
    let timeline: Vec<(f64, String)> = syncs
        .iter()
        .filter_map(|(t, ps)| {
            let texts: Vec<&str> = ps.iter().filter(mine).map(|p| p.1).collect();
            (!texts.is_empty()).then(|| (*t, texts.join("\n")))
        })
        .collect();
    let others = syncs.iter().flat_map(|s| s.1.iter()).filter(|p| !mine(p)).count();
    for (i, (start, body)) in timeline.iter().enumerate() {
        let raw = body.replace("<br>", "\n").replace("<BR>", "\n").replace("<br/>", "\n").replace("<br />", "\n");
        let text = plain_text(&raw, &mut s.markup).replace('\u{a0}', " ").trim().to_string();
        if text.is_empty() {
            continue;
        }
        let end = timeline.get(i + 1).map(|n| n.0).filter(|e| *e >= *start);
        s.push(Cue { start: *start, end, text, speaker: None });
    }
    s.set("syncs", syncs.len());
    if others > 0 {
        s.set("other_language_paragraphs", others);
    }
    s
}

/// A SAMI SYNC: its start, and its paragraphs with their classes.
type Sync<'t> = (f64, Vec<(Option<String>, &'t str)>);

/// The value of `name=` in a lowercase tag, unquoted, up to the next
/// separator.
fn attribute<'t>(tag: &'t str, name: &str) -> Option<&'t str> {
    let mut rest = tag;
    while let Some(i) = rest.find(name) {
        let after = rest[i + name.len()..].trim_start();
        let before_ok = i == 0 || rest.as_bytes()[i - 1].is_ascii_whitespace();
        if before_ok && let Some(v) = after.strip_prefix('=') {
            let v = v.trim_start().trim_start_matches(['"', '\'']);
            let end = v.find(|c: char| c.is_whitespace() || matches!(c, '>' | '"' | '\'')).unwrap_or(v.len());
            return Some(&v[..end]);
        }
        rest = &rest[i + name.len()..];
    }
    None
}

/// The `<P Class=…>` paragraphs of a SYNC body (`a..z` in `text`), or the
/// whole body when it has none.
fn paragraphs<'t>(text: &'t str, lower: &str, a: usize, z: usize) -> Vec<(Option<String>, &'t str)> {
    let starts: Vec<usize> = lower[a..z]
        .match_indices("<p")
        .map(|(i, _)| a + i)
        .filter(|&i| lower.as_bytes().get(i + 2).is_some_and(|c| c.is_ascii_whitespace() || *c == b'>'))
        .collect();
    if starts.is_empty() {
        return text.get(a..z).map(|t| vec![(None, t)]).unwrap_or_default();
    }
    let mut out = Vec::new();
    for (k, &p) in starts.iter().enumerate() {
        let end = starts.get(k + 1).copied().unwrap_or(z);
        let Some(tag_end) = lower[p..end].find('>').map(|j| p + j) else { continue };
        let class = attribute(&lower[p..tag_end], "class").map(str::to_string);
        if let Some(body) = text.get(tag_end + 1..end) {
            out.push((class, body));
        }
    }
    out
}

/// Text between the first `open` and the following `close` (matched on the
/// lowercase copy, cut from the original).
fn between<'t>(text: &'t str, lower: &str, open: &str, close: &str) -> Option<&'t str> {
    let a = lower.find(open)? + open.len();
    let a = if open.ends_with('>') { a } else { lower[a..].find('>')? + a + 1 };
    let b = lower[a..].find(close)? + a;
    text.get(a..b)
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("ttml", "sami", "srv3", "json3");

    #[test]
    fn ttml_timing() {
        let c = Clock { fps: 25.0, sub: 1.0, ticks: 10_000_000.0 };
        assert_eq!(c.parse("00:00:01:05"), Some(1.2));
        assert_eq!(c.parse("1.5s"), Some(1.5));
        assert_eq!(c.parse("250ms"), Some(0.25));
        assert_eq!(c.parse("50f"), Some(2.0));
        assert_eq!(c.parse("20000000t"), Some(2.0));
        assert_eq!(c.parse("2m"), Some(120.0));
        assert_eq!(c.parse("x"), None);
        assert_eq!(c.parse("1:2"), None);
    }

    #[test]
    fn srv_and_json3() {
        let s = srv("<timedtext format=\"3\"><body><p t=\"1000\" d=\"1500\">Hi<br/>there</p><p t=\"3000\">x</p></body></timedtext>").unwrap();
        assert_eq!(s.cues[0], Cue { start: 1.0, end: Some(2.5), text: "Hi\nthere".into(), speaker: None });
        assert_eq!(s.format["version"], "3");
        let s1 = srv("<transcript><text start=\"1.5\" dur=\"2\">a &amp; b</text></transcript>").unwrap();
        assert_eq!((s1.cues[0].end, s1.cues[0].text.as_str()), (Some(3.5), "a & b"));
        assert!(srv("nope").is_err());
        let j: Value = serde_json::from_str(
            r#"{"wireMagic":"pb3","events":[{"tStartMs":0,"dDurationMs":1000,"segs":[{"utf8":"one "},{"utf8":"two"}]},{"tStartMs":500,"aAppend":1,"segs":[{"utf8":"\n"}]},{"tStartMs":9}]}"#,
        )
        .unwrap();
        let s = json3(&j);
        assert_eq!(s.cues.len(), 1);
        assert_eq!(s.cues[0].text, "one two");
        assert_eq!(s.format["append_events"], 1);
    }

    #[test]
    fn sami_classes() {
        let s = sami(
            "<SAMI><HEAD><TITLE>Demo</TITLE><STYLE TYPE=\"text/css\"><!--\n.ENCC { Name: English; lang: en-US; }\n.FRCC { Name: French; lang: fr-FR; }\n--></STYLE></HEAD>\
             <BODY><SYNC Start=1000><P Class=ENCC>Hello<br>world</SYNC><SYNC Start=1000><P Class=FRCC>Bonjour\
             <SYNC Start=2500><P Class=ENCC>&nbsp;<SYNC Start=3000><P Class=ENCC>Bye</BODY></SAMI>",
        );
        assert_eq!(s.title.as_deref(), Some("Demo"));
        assert_eq!(s.language, Some(("en".into(), "sami.lang")));
        assert_eq!(s.cues.len(), 2);
        assert_eq!((s.cues[0].start, s.cues[0].end, s.cues[0].text.as_str()), (1.0, Some(2.5), "Hello\nworld"));
        assert_eq!(s.format["other_language_paragraphs"], 1);
        assert_eq!(s.styles, ["ENCC", "FRCC"]);
    }
}
