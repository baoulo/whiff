//! vCard 2.1 / 3.0 / 4.0 (RFC 6350): contacts with names, organisations,
//! titles, e-mail addresses (domains only under strict privacy), phone
//! numbers and postal addresses (counted, or listed when privacy is off),
//! birthdays (only when privacy is off), photos, categories and notes.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::contentline::{Component, parse, split};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Map, Source, TextRole, truncate_chars,
};

/// Extractor for vCard files.
pub struct Contact;

static META: ExtractorMeta = ExtractorMeta {
    id: "text.contact",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[FormatSpec {
        id: "vcf",
        name: "vCard",
        family: "text.contact",
        mimes: &["text/vcard", "text/x-vcard", "text/directory"],
        extensions: &["vcf", "vcard"],
        magic: &[
            Magic::prefix(b"BEGIN:VCARD"),
            Magic::prefix(b"\xEF\xBB\xBFBEGIN:VCARD"),
            Magic::prefix(b"begin:vcard"),
        ],
        parent: None,
    }],
};

const MAX_LISTED: usize = 50;

impl Extractor for Contact {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // one pass over the cards, then the totals
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.checkpoint()?;
        let cards: Vec<Component> = parse(&text, 500_000).into_iter().filter(|c| c.name == "VCARD").collect();
        if cards.is_empty() {
            return Err(ExtractError::malformed("no VCARD"));
        }
        let strict = cx.privacy_strict();
        let mut f = Map::new();
        let mut versions = BTreeSet::new();
        let mut generators = BTreeSet::new();
        let mut kinds: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
        let (mut emails, mut phones, mut addresses, mut photos, mut birthdays) = (0u64, 0u64, 0u64, 0u64, 0u64);
        let mut domains = BTreeSet::new();
        let mut phone_types: std::collections::BTreeMap<&'static str, u64> = std::collections::BTreeMap::new();
        let mut orgs = BTreeSet::new();
        let mut listed = Vec::new();
        let mut notes = String::new();
        for (i, card) in cards.iter().enumerate() {
            if i.is_multiple_of(1024) {
                cx.checkpoint()?;
            }
            if let Some(v) = card.text("VERSION") {
                versions.insert(v);
            }
            if let Some(p) = card.text("PRODID") {
                generators.insert(truncate_chars(&p, 200));
            }
            let kind = card
                .text("KIND")
                .or_else(|| card.text("X-ADDRESSBOOKSERVER-KIND"))
                .unwrap_or_else(|| "individual".into())
                .to_ascii_lowercase();
            *kinds.entry(kind.clone()).or_default() += 1;
            let name = card.text("FN").or_else(|| {
                let n = split(&card.get("N")?.value, ';');
                let parts: Vec<&str> = [n.get(3), n.get(1), n.get(2), n.first(), n.get(4)]
                    .into_iter()
                    .flatten()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                (!parts.is_empty()).then(|| parts.join(" "))
            });
            let org = card
                .get("ORG")
                .map(|o| {
                    split(&o.value, ';').into_iter().filter(|s| !s.trim().is_empty()).collect::<Vec<_>>().join(", ")
                })
                .filter(|o| !o.is_empty());
            if let Some(o) = &org
                && orgs.len() < 10_000
            {
                orgs.insert(o.clone());
            }
            let card_emails: Vec<Value> = card
                .all("EMAIL")
                .map(super::contentline::Prop::text)
                .filter(|e| e.contains('@'))
                .inspect(|e| {
                    if let Some((_, d)) = e.rsplit_once('@') {
                        domains.insert(d.trim().to_ascii_lowercase());
                    }
                })
                .map(|e| cx.mailbox(None, Some(&e)))
                .collect();
            emails += card_emails.len() as u64;
            let card_phones: Vec<String> = card
                .all("TEL")
                .map(|t| t.text().trim().trim_start_matches("tel:").to_string())
                .filter(|t| !t.is_empty())
                .collect();
            phones += card_phones.len() as u64;
            for t in card.all("TEL") {
                for (ty, key) in [("CELL", "cell"), ("HOME", "home"), ("WORK", "work"), ("FAX", "fax")] {
                    if t.has_type(ty) {
                        *phone_types.entry(key).or_default() += 1;
                    }
                }
            }
            let card_adrs: Vec<Vec<String>> = card.all("ADR").map(|a| split(&a.value, ';')).collect();
            addresses += card_adrs.len() as u64;
            if card.get("PHOTO").is_some() || card.get("LOGO").is_some() {
                photos += 1;
            }
            let bday = card.text("BDAY");
            if bday.is_some() {
                birthdays += 1;
            }
            if let Some(n) = card.text("NOTE")
                && notes.len() < 256 * 1024
            {
                notes.push_str(&n);
                notes.push('\n');
            }
            if listed.len() < MAX_LISTED {
                let mut m = Map::new();
                if let Some(n) = &name {
                    m.insert("name".into(), json!(truncate_chars(n, 200)));
                }
                if kind != "individual" {
                    m.insert("kind".into(), json!(kind));
                }
                if let Some(o) = &org {
                    m.insert("organization".into(), json!(truncate_chars(o, 200)));
                }
                for (key, out) in
                    [("TITLE", "title"), ("ROLE", "role"), ("NICKNAME", "nickname"), ("CATEGORIES", "categories")]
                {
                    if let Some(v) = card.text(key) {
                        m.insert(out.into(), json!(truncate_chars(&v, 200)));
                    }
                }
                if !card_emails.is_empty() {
                    m.insert("emails".into(), Value::Array(card_emails));
                }
                if !card_phones.is_empty() {
                    if strict {
                        m.insert("phones".into(), json!(card_phones.len()));
                    } else {
                        m.insert("phones".into(), json!(card_phones));
                    }
                }
                if !card_adrs.is_empty() {
                    // ADR: PO box; extended; street; locality; region; postal code; country.
                    let places: Vec<Value> = card_adrs
                        .iter()
                        .map(|a| {
                            let g = |i: usize| a.get(i).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
                            let mut p = Map::new();
                            if !strict {
                                for (i, k) in [(2, "street"), (5, "postal_code"), (4, "region")] {
                                    if let Some(v) = g(i) {
                                        p.insert(k.into(), json!(v));
                                    }
                                }
                            }
                            if let Some(v) = g(3) {
                                p.insert("locality".into(), json!(v));
                            }
                            if let Some(v) = g(6) {
                                p.insert("country".into(), json!(v));
                            }
                            Value::Object(p)
                        })
                        .collect();
                    m.insert("addresses".into(), Value::Array(places));
                }
                if let Some(b) = bday.filter(|_| !strict) {
                    m.insert("birthday".into(), json!(b));
                }
                if let Some(u) = card.text("URL") {
                    m.insert("url".into(), json!(truncate_chars(&u, 300)));
                }
                if let Some(p) = card.get("PHOTO") {
                    let mut ph = Map::new();
                    let inline =
                        p.param("ENCODING").is_some_and(|e| matches!(e.to_ascii_uppercase().as_str(), "B" | "BASE64"))
                            || p.value.starts_with("data:");
                    ph.insert("inline".into(), json!(inline));
                    if let Some(t) = p.param("TYPE").or_else(|| p.param("MEDIATYPE")) {
                        ph.insert("type".into(), json!(t.to_ascii_lowercase()));
                    }
                    if inline {
                        ph.insert("encoded_bytes".into(), json!(p.value.len()));
                    }
                    m.insert("photo".into(), Value::Object(ph));
                }
                listed.push(Value::Object(m));
            }
        }
        if cards.len() == 1
            && let Some(Value::String(n)) = listed.first().and_then(|c| c.get("name"))
        {
            cx.content().source("vcard.FN").title(n);
        }
        f.insert("contacts".into(), json!(cards.len()));
        if !versions.is_empty() {
            f.insert("versions".into(), json!(versions));
        }
        if !generators.is_empty() {
            f.insert("generators".into(), json!(generators.iter().take(10).collect::<Vec<_>>()));
        }
        if kinds.len() > 1 || !kinds.contains_key("individual") {
            f.insert("kinds".into(), json!(kinds));
        }
        f.insert("emails".into(), json!(emails));
        f.insert("phones".into(), json!(phones));
        if !phone_types.is_empty() {
            f.insert("phone_types".into(), json!(phone_types));
        }
        f.insert("addresses".into(), json!(addresses));
        if photos > 0 {
            f.insert("photos".into(), json!(photos));
        }
        if birthdays > 0 {
            f.insert("birthdays".into(), json!(birthdays));
        }
        if !domains.is_empty() {
            f.insert("email_domains".into(), json!(domains.iter().take(MAX_LISTED).collect::<Vec<_>>()));
        }
        if !orgs.is_empty() {
            f.insert("organizations".into(), json!(orgs.len()));
        }
        f.insert("list".into(), Value::Array(listed));
        cx.physical().entries(cards.len() as u64);
        if !notes.is_empty() {
            cx.emit_text(TextRole::Comment, &notes);
        }
        cx.format().extend(f);
        Ok(())
    }
}

crate::register_extractor!(Contact);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("vcf");

    #[test]
    fn reads_contacts_under_strict_privacy() {
        let vcf = "BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//Saltmere//Contacts//EN\r\nN:Castell;Mira;;;\r\nFN:Mira Castell\r\n\
ORG:Example Ferries;Timetables\r\nTITLE:Scheduler\r\nEMAIL;TYPE=INTERNET:mira@example.org\r\nTEL;TYPE=CELL:+1-555-0100\r\n\
ADR;TYPE=WORK:;;1 Quay Street;Saltmere;;SM1 1AA;Freedonia\r\nBDAY:1980-02-03\r\nEND:VCARD\r\n\
BEGIN:VCARD\r\nVERSION:2.1\r\nN:Gull;Ben\r\nTEL;HOME:+1-555-0101\r\nEND:VCARD\r\n";
        let r = crate::plugin::testing::report_for("crew.vcf", vcf.as_bytes());
        assert_eq!(r.identification.format, "vcf");
        let f = &r.format["vcf"];
        assert_eq!(f["contacts"], 2);
        assert_eq!(f["phones"], 2);
        let first = &f["list"][0];
        assert_eq!(first["name"], "Mira Castell");
        assert_eq!(first["organization"], "Example Ferries, Timetables");
        assert_eq!(first["emails"][0]["domain"], "example.org");
        assert_eq!(first["phones"], 1);
        assert_eq!(first["addresses"][0]["locality"], "Saltmere");
        assert!(first["addresses"][0].get("street").is_none());
        assert!(first.get("birthday").is_none());
        assert_eq!(f["list"][1]["name"], "Ben Gull");
    }
}
