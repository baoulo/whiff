//! Localisation tables:
//! * `.strings` (old-style text, UTF-8 or UTF-16, or a compiled binary
//!   plist): key count, format specifiers, comments;
//! * `.stringsdict` (XML plist): keys, plural categories used;
//! * `.xcstrings` (Xcode string catalog, JSON): source language, the
//!   languages translated, key count, translation states, keys marked not
//!   to translate.
//!
//! The source-language values are emitted as body text.
//!
//! Specifications: Apple "String Resources" (strings file format),
//! "Localizing strings that contain plurals" (stringsdict), Xcode 15
//! string catalog (`.xcstrings`) JSON.

use std::collections::{BTreeMap, BTreeSet};

use plist::Value as Plist;
use serde_json::{Map, Value};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, proplist,
};

/// Extractor for localisation tables.
pub struct Strings;

static META: ExtractorMeta = ExtractorMeta {
    id: "apple.strings",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "apple_strings",
            name: "Apple .strings / .stringsdict / .xcstrings",
            family: "apple",
            mimes: &[],
            extensions: &["strings"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "stringsdict",
            name: "Apple .stringsdict",
            family: "apple",
            mimes: &[],
            extensions: &["stringsdict"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "xcstrings",
            name: "Xcode string catalog",
            family: "apple",
            mimes: &[],
            extensions: &["xcstrings"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

/// Characters of source text emitted.
const MAX_TEXT: usize = 200_000;

impl Extractor for Strings {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let format = match probe.extension? {
            "strings" => {
                let text = h.starts_with(b"\xff\xfe") || h.starts_with(b"\xfe\xff") || {
                    let t = String::from_utf8_lossy(&h[..h.len().min(4096)]);
                    let t = t.trim_start_matches('\u{feff}').trim_start();
                    t.starts_with('"') || t.starts_with("/*") || t.starts_with("//") || t.is_empty()
                };
                (text || proplist::encoding(h).is_some_and(|e| e != proplist::Encoding::Ascii))
                    .then_some("apple_strings")?
            }
            "stringsdict" => proplist::encoding(h).map(|_| "stringsdict")?,
            "xcstrings" => h.windows(16).any(|w| w == b"\"sourceLanguage\"").then_some("xcstrings")?,
            _ => return None,
        };
        Some(Sniff { format, confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "xcstrings" => {
                let text = cx.read_text(src)?.text;
                let v: Value =
                    serde_json::from_str(&text).map_err(|_| ExtractError::malformed("string catalog JSON"))?;
                catalog(&v, cx);
            }
            "stringsdict" => {
                let (data, _) = cx.read_bytes(src)?;
                let (p, enc) = proplist::parse(&data).ok_or_else(|| ExtractError::malformed("stringsdict plist"))?;
                cx.format_set("encoding", enc.as_str());
                stringsdict(&p, cx);
            }
            _ => {
                let (data, _) = cx.read_bytes(src)?;
                let plist = proplist::encoding(&data).filter(|e| *e != proplist::Encoding::Ascii);
                let (p, enc, comments) = if plist.is_some() {
                    let (p, enc) = proplist::parse(&data).ok_or_else(|| ExtractError::malformed("strings plist"))?;
                    (p, enc.as_str(), 0)
                } else {
                    let text = crate::plugin::decode_text(&data).text;
                    let comments =
                        text.matches("/*").count() + text.lines().filter(|l| l.trim_start().starts_with("//")).count();
                    // A strings file is the inside of an old-style dictionary.
                    let body = text.trim_start_matches('\u{feff}');
                    // Most have no outer braces; some old ones do.
                    let braced = proplist::encoding(body.as_bytes()) == Some(proplist::Encoding::Ascii);
                    let wrapped = if braced { body.to_string() } else { format!("{{\n{body}\n}}") };
                    let (p, _) =
                        proplist::parse(wrapped.as_bytes()).ok_or_else(|| ExtractError::malformed("strings file"))?;
                    (p, "text", comments)
                };
                cx.format_set("encoding", enc);
                let d = p.as_dictionary().ok_or_else(|| ExtractError::malformed("strings table"))?;
                cx.format_set("keys", d.len());
                if comments > 0 {
                    cx.format_set("comments", comments);
                }
                let values: Vec<&str> = d.values().filter_map(Plist::as_string).collect();
                let specifiers: usize =
                    values.iter().map(|v| v.matches('%').count() - 2 * v.matches("%%").count()).sum();
                if specifiers > 0 {
                    cx.format_set("format_specifiers", specifiers);
                }
                emit(cx, values);
            }
        }
        Ok(())
    }
}

crate::register_extractor!(Strings);

fn emit<'a>(cx: &mut Context<'_>, values: impl IntoIterator<Item = &'a str>) {
    let mut text = String::new();
    for v in values {
        if text.len() + v.len() > MAX_TEXT {
            break;
        }
        text.push_str(v);
        text.push('\n');
    }
    if !text.is_empty() {
        cx.emit_text(TextRole::Body, &text);
    }
}

fn stringsdict(p: &Plist, cx: &mut Context<'_>) {
    let Some(d) = p.as_dictionary() else { return };
    cx.format_set("keys", d.len());
    let mut categories: BTreeSet<&str> = BTreeSet::new();
    let mut variables = 0usize;
    let mut texts = Vec::new();
    for entry in d.values().filter_map(Plist::as_dictionary) {
        for (k, var) in entry {
            if k == "NSStringLocalizedFormatKey" {
                continue;
            }
            let Some(var) = var.as_dictionary() else { continue };
            variables += 1;
            for (cat, v) in var {
                if ["zero", "one", "two", "few", "many", "other"].contains(&cat.as_str()) {
                    categories.insert(cat.as_str());
                    if let Some(s) = v.as_string() {
                        texts.push(s);
                    }
                }
            }
        }
    }
    cx.format_set("variables", variables);
    if !categories.is_empty() {
        let order = ["zero", "one", "two", "few", "many", "other"];
        let v: Vec<&str> = order.into_iter().filter(|c| categories.contains(c)).collect();
        cx.format_set("plural_categories", v);
    }
    emit(cx, texts);
}

fn catalog(v: &Value, cx: &mut Context<'_>) {
    let source = v.get("sourceLanguage").and_then(Value::as_str).unwrap_or("");
    if !source.is_empty() {
        cx.format_set("source_language", source);
    }
    if let Some(ver) = v.get("version").and_then(Value::as_str) {
        cx.format_set("catalog_version", ver);
    }
    let strings = v.get("strings").and_then(Value::as_object);
    cx.format_set("keys", strings.map_or(0, Map::len));
    let mut languages: BTreeSet<&str> = BTreeSet::new();
    let mut states: BTreeMap<&str, u64> = BTreeMap::new();
    let (mut no_translate, mut stale) = (0u64, 0u64);
    let mut texts = Vec::new();
    for (key, entry) in strings.into_iter().flatten() {
        if entry.get("shouldTranslate") == Some(&Value::Bool(false)) {
            no_translate += 1;
        }
        if entry.get("extractionState").and_then(Value::as_str) == Some("stale") {
            stale += 1;
        }
        let locs = entry.get("localizations").and_then(Value::as_object);
        let mut source_text = None;
        for (lang, l) in locs.into_iter().flatten() {
            languages.insert(lang.as_str());
            let unit = l.get("stringUnit");
            if let Some(s) = unit.and_then(|u| u.get("state")).and_then(Value::as_str) {
                *states.entry(s).or_default() += 1;
            }
            if lang == source {
                source_text = unit.and_then(|u| u.get("value")).and_then(Value::as_str);
            }
        }
        texts.push(source_text.unwrap_or(key.as_str()));
    }
    if !languages.is_empty() {
        cx.format_set("languages", languages.into_iter().collect::<Vec<_>>());
    }
    if !states.is_empty() {
        let m: Map<String, Value> = states.into_iter().map(|(k, n)| (k.to_string(), n.into())).collect();
        cx.format_set("states", Value::Object(m));
    }
    if no_translate > 0 {
        cx.format_set("not_translated", no_translate);
    }
    if stale > 0 {
        cx.format_set("stale", stale);
    }
    emit(cx, texts);
}

#[cfg(test)]
mod tests {
    use crate::plugin::testing::report_for;

    #[test]
    fn strings_text_and_utf16() {
        let text = "/* Greeting */\n\"hello\" = \"Bonjour %@\";\n\"bye\" = \"Au revoir\";\n";
        let r = report_for("Localizable.strings", text.as_bytes());
        assert_eq!(r.format["apple_strings"]["keys"], 2);
        let mut utf16 = vec![0xff, 0xfe];
        utf16.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        let r = report_for("Localizable.strings", &utf16);
        assert_eq!(r.format["apple_strings"]["keys"], 2);
    }

    #[test]
    fn strings_with_outer_braces() {
        // Some old .strings files are a whole old-style dictionary (found by the oracle).
        let text = "{\n\t\"FileTypeErr\"\t= \"the file\";\n\t\"b\" = \"c\";\n}\n";
        let mut utf16 = vec![0xff, 0xfe];
        utf16.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        let r = report_for("SSViewer.strings", &utf16);
        assert_eq!(r.format["apple_strings"]["keys"], 2);
    }

    #[test]
    fn strings_as_xml_plist() {
        // .strings files may be XML plists (found by the oracle in iMovie's `.localized` folders).
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
            <key>Tides</key><string>Marées</string></dict></plist>";
        let r = report_for("fr.strings", xml.as_bytes());
        assert_eq!(
            (r.format["apple_strings"]["encoding"].as_str(), r.format["apple_strings"]["keys"].as_u64()),
            (Some("xml"), Some(1))
        );
    }

    crate::fixture_tests!("apple_strings", "stringsdict", "xcstrings");
}
