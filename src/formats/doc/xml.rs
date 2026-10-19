//! A small event walker over the XML parts of office documents and ebooks:
//! local names only (prefixes vary between writers), attributes by local
//! name, entity and character references resolved, a cap on events and a
//! deadline check, and no recursion.

use quick_xml::events::{BytesStart, Event};

use crate::plugin::{Context, ExtractError};

/// Events walked per part at most.
const MAX_EVENTS: usize = 4_000_000;

/// An element's local name and attributes (by local name, except `xml:lang`
/// and namespaced attributes such as `r:id`, which keep their prefix).
#[derive(Debug, Clone, Default)]
pub(crate) struct Tag {
    pub(crate) name: String,
    pub(crate) attrs: Vec<(String, String)>,
}

impl Tag {
    /// Attribute value by local name (`id` matches `r:id` too).
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .or_else(|| self.attrs.iter().find(|(k, _)| k.rsplit(':').next() == Some(name)))
            .map(|(_, v)| v.as_str())
    }

    /// Attribute value by its full (prefixed) name.
    pub(crate) fn qattr(&self, qname: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == qname).map(|(_, v)| v.as_str())
    }
}

/// One walker event.
#[derive(Debug)]
pub(crate) enum Ev<'t> {
    /// An opening tag (`empty` for `<x/>`, which gets no `End`).
    Open(&'t Tag, bool),
    /// A closing tag (local name).
    Close(&'t str),
    /// Character data (text, CDATA, resolved references).
    Text(&'t str),
}

/// What the callback wants next.
pub(crate) enum Flow {
    Continue,
    Stop,
}

fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn tag(e: &BytesStart<'_>) -> Tag {
    let name = local(e.name().as_ref()).to_string();
    let attrs = e
        .attributes()
        .flatten()
        .take(128)
        .map(|a| {
            let key = a.key.as_ref().to_string();
            let key = if key.contains(':') && !key.starts_with("xmlns") { key } else { local(&key).to_string() };
            let value = a
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map(std::borrow::Cow::into_owned)
                .unwrap_or_default();
            (key, value)
        })
        .collect();
    Tag { name, attrs }
}

/// Walk `xml`, calling `f` for every element and text run. Malformed XML
/// ends the walk with an error after the events seen so far.
pub(crate) fn walk(xml: &str, cx: &Context<'_>, mut f: impl FnMut(Ev<'_>) -> Flow) -> Result<(), ExtractError> {
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().check_end_names = false;
    let mut text = String::new();
    let flush = |text: &mut String, f: &mut dyn FnMut(Ev<'_>) -> Flow| {
        if text.is_empty() {
            return Flow::Continue;
        }
        let flow = f(Ev::Text(text));
        text.clear();
        flow
    };
    for n in 0..MAX_EVENTS {
        if n.is_multiple_of(8192) {
            cx.checkpoint()?;
        }
        let ev = reader.read_event().map_err(|e| ExtractError::malformed(format!("XML: {e}")))?;
        let flow = match ev {
            Event::Start(e) => {
                if let Flow::Stop = flush(&mut text, &mut f) {
                    return Ok(());
                }
                f(Ev::Open(&tag(&e), false))
            }
            Event::Empty(e) => {
                if let Flow::Stop = flush(&mut text, &mut f) {
                    return Ok(());
                }
                f(Ev::Open(&tag(&e), true))
            }
            Event::End(e) => {
                if let Flow::Stop = flush(&mut text, &mut f) {
                    return Ok(());
                }
                f(Ev::Close(local(e.name().as_ref())))
            }
            Event::Text(t) => {
                text.push_str(&t.xml10_content());
                Flow::Continue
            }
            Event::CData(t) => {
                text.push_str(&t.xml10_content());
                Flow::Continue
            }
            Event::GeneralRef(r) => {
                match &*r {
                    "amp" => text.push('&'),
                    "lt" => text.push('<'),
                    "gt" => text.push('>'),
                    "quot" => text.push('"'),
                    "apos" => text.push('\''),
                    "nbsp" => text.push('\u{a0}'),
                    _ => {
                        if let Ok(Some(c)) = r.resolve_char_ref() {
                            text.push(c);
                        }
                    }
                }
                Flow::Continue
            }
            Event::Eof => {
                flush(&mut text, &mut f);
                return Ok(());
            }
            _ => Flow::Continue,
        };
        if let Flow::Stop = flow {
            return Ok(());
        }
    }
    Err(ExtractError::LimitExceeded("xml events".into()))
}

/// Text of the elements with local name `name` that are direct value
/// holders (`<dc:title>…</dc:title>`): `(attributes, text)` pairs in order.
pub(crate) fn values(xml: &str, cx: &Context<'_>, names: &[&str]) -> Result<Vec<(String, Tag, String)>, ExtractError> {
    let mut out = Vec::new();
    let mut open: Option<(String, Tag, String)> = None;
    walk(xml, cx, |ev| {
        match ev {
            Ev::Open(t, empty) if names.contains(&t.name.as_str()) => {
                if empty {
                    out.push((t.name.clone(), t.clone(), String::new()));
                } else {
                    open = Some((t.name.clone(), t.clone(), String::new()));
                }
            }
            Ev::Text(s) => {
                if let Some((_, _, buf)) = open.as_mut()
                    && buf.len() < 64 * 1024
                {
                    buf.push_str(s);
                }
            }
            Ev::Close(n) => {
                if open.as_ref().is_some_and(|(o, _, _)| o == n)
                    && let Some((name, t, v)) = open.take()
                {
                    out.push((name, t, v.trim().to_string()));
                }
            }
            Ev::Open(..) => {}
        }
        Flow::Continue
    })?;
    Ok(out)
}

/// The XML root element's local name and attributes (after the prolog), from
/// the start of a document; for sniffers.
pub(crate) fn root(head: &[u8]) -> Option<Tag> {
    let text = String::from_utf8_lossy(&head[..head.len().min(8192)]);
    let mut reader = quick_xml::Reader::from_str(&text);
    for _ in 0..64 {
        match reader.read_event() {
            Ok(Event::Start(e) | Event::Empty(e)) => return Some(tag(&e)),
            Ok(Event::Eof) | Err(_) => return None,
            Ok(_) => {}
        }
    }
    None
}
