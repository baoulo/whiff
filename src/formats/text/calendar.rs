//! iCalendar (RFC 5545) and vCalendar 1.0: calendar name and generator,
//! the invitation method, component counts, time zones, events and to-dos
//! (summary, start, end, all-day, recurrence, location, organizer and
//! attendees through the privacy rules), the date range, and alarms that
//! run a procedure.

use serde_json::{Value, json};

use super::contentline::{Component, Prop, parse};
use crate::plugin::{
    Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Map, Probe, Sniff, Source,
    TextRole, truncate_chars,
};

/// Extractor for iCalendar and vCalendar files.
pub struct Calendar;

static META: ExtractorMeta = ExtractorMeta {
    id: "text.calendar",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "ics",
            name: "iCalendar",
            family: "text.calendar",
            mimes: &["text/calendar"],
            extensions: &["ics", "ifb", "ical", "icalendar"],
            magic: &[Magic::prefix(b"BEGIN:VCALENDAR"), Magic::prefix(b"\xEF\xBB\xBFBEGIN:VCALENDAR")],
            parent: None,
        },
        FormatSpec {
            id: "vcs",
            name: "vCalendar 1.0",
            family: "text.calendar",
            mimes: &["text/x-vcalendar"],
            extensions: &["vcs"],
            magic: &[],
            parent: Some("ics"),
        },
    ],
};

const MAX_LISTED: usize = 50;

impl Extractor for Calendar {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let head = String::from_utf8_lossy(&probe.head[..probe.head.len().min(2048)]).to_ascii_uppercase();
        if !head.trim_start_matches('\u{feff}').trim_start().starts_with("BEGIN:VCALENDAR") {
            return None;
        }
        head.contains("VERSION:1.0").then_some(Sniff { format: "vcs", confidence: 0.95 })
    }

    #[allow(clippy::too_many_lines)] // calendar fields, then one pass over the items
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        cx.checkpoint()?;
        let roots = parse(&text, 200_000);
        let cals: Vec<&Component> = roots.iter().filter(|c| c.name == "VCALENDAR").collect();
        let Some(cal) = cals.first() else { return Err(ExtractError::malformed("no VCALENDAR")) };
        let mut f = Map::new();
        if cals.len() > 1 {
            f.insert("calendars".into(), json!(cals.len()));
        }
        for (key, out) in [
            ("VERSION", "version"),
            ("PRODID", "generator"),
            ("METHOD", "method"),
            ("CALSCALE", "calendar_scale"),
            ("X-WR-TIMEZONE", "default_timezone"),
        ] {
            if let Some(v) = cal.text(key) {
                f.insert(out.into(), json!(truncate_chars(&v, 300)));
            }
        }
        let name = cal.text("X-WR-CALNAME").or_else(|| cal.text("NAME"));
        if let Some(d) = cal.text("X-WR-CALDESC").or_else(|| cal.text("DESCRIPTION")) {
            cx.content().source("ical.X-WR-CALDESC").description(truncate_chars(&d, 2000));
        }
        // Component counts.
        let mut counts: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
        for c in cals.iter().flat_map(|c| c.children.iter()) {
            *counts.entry(c.name.to_ascii_lowercase()).or_default() += 1;
        }
        f.insert("components".into(), json!(counts));
        let tzids: Vec<String> =
            cals.iter().flat_map(|c| c.find_all("VTIMEZONE")).filter_map(|t| t.text("TZID")).take(MAX_LISTED).collect();
        if !tzids.is_empty() {
            f.insert("timezones".into(), json!(tzids));
        }
        let items: Vec<&Component> = cals
            .iter()
            .flat_map(|c| c.children.iter())
            .filter(|c| matches!(c.name.as_str(), "VEVENT" | "VTODO" | "VJOURNAL"))
            .collect();
        let mut listed = Vec::new();
        let mut text = String::new();
        let (mut first, mut last): (Option<String>, Option<String>) = (None, None);
        let (mut recurring, mut private, mut attendees_total, mut links) = (0u64, 0u64, 0u64, 0u64);
        for (i, item) in items.iter().enumerate() {
            if i.is_multiple_of(1024) {
                cx.checkpoint()?;
            }
            let start = item.get("DTSTART").and_then(when);
            let end = item.get("DTEND").or_else(|| item.get("DUE")).and_then(when);
            if let Some((s, _, _)) = &start
                && first.as_ref().is_none_or(|f| s < f)
            {
                first = Some(s.clone());
            }
            if let Some((e, _, _)) = end.as_ref().or(start.as_ref())
                && last.as_ref().is_none_or(|l| e > l)
            {
                last = Some(e.clone());
            }
            if item.get("RRULE").is_some() || item.get("RDATE").is_some() {
                recurring += 1;
            }
            if item.text("CLASS").is_some_and(|c| matches!(c.to_ascii_uppercase().as_str(), "PRIVATE" | "CONFIDENTIAL"))
            {
                private += 1;
            }
            let attendees: Vec<&Prop> = item.all("ATTENDEE").collect();
            attendees_total += attendees.len() as u64;
            let summary = item.text("SUMMARY");
            let description = item.text("DESCRIPTION");
            if text.len() < 1 << 20 {
                for t in [&summary, &item.text("LOCATION"), &description].into_iter().flatten() {
                    text.push_str(t);
                    text.push('\n');
                }
            }
            links += description.as_deref().map_or(0, |d| d.matches("http://").count() + d.matches("https://").count())
                as u64;
            links += u64::from(item.get("URL").is_some());
            if listed.len() < MAX_LISTED {
                let mut m = Map::new();
                m.insert("type".into(), json!(item.name.trim_start_matches('V').to_ascii_lowercase()));
                if let Some(s) = &summary {
                    m.insert("summary".into(), json!(truncate_chars(s, 300)));
                }
                if let Some((s, all_day, tz)) = &start {
                    m.insert("start".into(), json!(s));
                    if *all_day {
                        m.insert("all_day".into(), json!(true));
                    }
                    if let Some(tz) = tz {
                        m.insert("timezone".into(), json!(tz));
                    }
                }
                if let Some((e, _, _)) = &end {
                    m.insert("end".into(), json!(e));
                }
                if let Some(r) = item.text("RRULE") {
                    m.insert("recurrence".into(), json!(truncate_chars(&r, 200)));
                }
                for (key, out) in [("LOCATION", "location"), ("STATUS", "status"), ("CATEGORIES", "categories")] {
                    if let Some(v) = item.text(key) {
                        m.insert(out.into(), json!(truncate_chars(&v, 300)));
                    }
                }
                if let Some(o) = item.get("ORGANIZER") {
                    m.insert("organizer".into(), person(cx, o));
                }
                if !attendees.is_empty() {
                    m.insert("attendees".into(), json!(attendees.len()));
                    let sample: Vec<Value> = attendees.iter().take(10).map(|a| person(cx, a)).collect();
                    m.insert("attendee_list".into(), Value::Array(sample));
                }
                listed.push(Value::Object(m));
            }
            // Alarms that run a program (vCalendar `AALARM`/`PALARM`, iCalendar `ACTION:PROCEDURE`).
            let procedure =
                item.children.iter().any(|a| {
                    a.name == "VALARM" && a.text("ACTION").is_some_and(|x| x.eq_ignore_ascii_case("PROCEDURE"))
                }) || item.get("PALARM").is_some();
            if procedure {
                cx.security()
                    .active_content("alarm_procedure")
                    .risk("alarm_procedure", summary.clone().map(|s| truncate_chars(&s, 100)));
            }
            for att in item.all("ATTACH") {
                if att.param("VALUE").is_none_or(|v| !v.eq_ignore_ascii_case("BINARY")) && att.value.contains("://") {
                    links += 1;
                }
            }
        }
        let title = name.or_else(|| (items.len() == 1).then(|| items[0].text("SUMMARY")).flatten());
        if let Some(t) = &title {
            cx.content().source("ical.name").title(t);
            cx.emit_text(TextRole::Title, t);
        }
        if items.len() == 1 {
            let only = items[0];
            if let Some(g) = only.text("GEO")
                && let Some((lat, lon)) = g.split_once([';', ','])
                && let (Ok(lat), Ok(lon)) = (lat.trim().parse::<f64>(), lon.trim().parse::<f64>())
                && (-90.0..=90.0).contains(&lat)
                && (-180.0..=180.0).contains(&lon)
            {
                cx.content().source("ical.GEO").location(lat, lon, None);
            }
            for (key, field) in [("CREATED", DateField::Created), ("LAST-MODIFIED", DateField::Modified)] {
                if let Some((v, _, _)) = only.get(key).and_then(when) {
                    let tz = v.ends_with('Z') || v.contains('+');
                    cx.temporal().source(format!("ical.{key}")).content_date(field, v, tz);
                }
            }
        }
        f.insert("items".into(), json!(items.len()));
        if let (Some(a), Some(b)) = (&first, &last) {
            f.insert("date_range".into(), json!([a, b]));
        }
        if recurring > 0 {
            f.insert("recurring".into(), json!(recurring));
        }
        if private > 0 {
            f.insert("private_items".into(), json!(private));
        }
        if attendees_total > 0 {
            f.insert("attendees".into(), json!(attendees_total));
        }
        if links > 0 {
            cx.security().external_references(links);
        }
        if !listed.is_empty() {
            f.insert("events".into(), Value::Array(listed));
        }
        if !text.is_empty() {
            cx.emit_text(TextRole::Body, &text);
        }
        cx.format().extend(f);
        Ok(())
    }
}

crate::register_extractor!(Calendar);

/// An ORGANIZER / ATTENDEE: `CN` and the `mailto:` address, through the privacy rules.
fn person(cx: &Context<'_>, p: &Prop) -> Value {
    let addr = p.value.trim();
    let addr = addr.strip_prefix("mailto:").or_else(|| addr.strip_prefix("MAILTO:")).unwrap_or(addr);
    let mut v = cx.mailbox(p.param("CN").map(|c| c.trim_matches('"')), Some(addr));
    if let (Value::Object(m), Some(role)) = (&mut v, p.param("PARTSTAT")) {
        m.insert("status".into(), json!(role.to_ascii_lowercase()));
    }
    v
}

/// A DATE / DATE-TIME property: (ISO value, all-day, TZID).
fn when(p: &Prop) -> Option<(String, bool, Option<String>)> {
    let v = p.value.trim();
    let tz = p.param("TZID").map(|t| t.trim_matches('"').to_string());
    let d = v.as_bytes();
    if d.len() < 8 || !d[..8].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let date = format!("{}-{}-{}", &v[..4], &v[4..6], &v[6..8]);
    if d.len() == 8 || p.param("VALUE").is_some_and(|x| x.eq_ignore_ascii_case("DATE")) {
        return Some((date, true, None));
    }
    let t = v.get(9..15)?;
    if !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let utc = v.ends_with('Z');
    Some((format!("{date}T{}:{}:{}{}", &t[..2], &t[2..4], &t[4..6], if utc { "Z" } else { "" }), false, tz))
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("ics", "vcs");

    #[test]
    fn reads_a_calendar() {
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Saltmere//Tides 1.0//EN\r\nMETHOD:REQUEST\r\nX-WR-CALNAME:Harbour events\r\n\
BEGIN:VTIMEZONE\r\nTZID:Europe/Paris\r\nEND:VTIMEZONE\r\n\
BEGIN:VEVENT\r\nUID:1@saltmere.example\r\nDTSTART;TZID=Europe/Paris:20240509T100000\r\nDTEND;TZID=Europe/Paris:20240509T170000\r\n\
SUMMARY:Regatta\r\nLOCATION:Outer mole\r\nORGANIZER;CN=Harbour Office:mailto:office@saltmere.example\r\n\
ATTENDEE;CN=Mira Castell;PARTSTAT=ACCEPTED:mailto:mira@example.org\r\nRRULE:FREQ=YEARLY\r\nEND:VEVENT\r\n\
BEGIN:VEVENT\r\nDTSTART;VALUE=DATE:20240601\r\nSUMMARY:Lighthouse open day\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let r = crate::plugin::testing::report_for("harbour.ics", ics.as_bytes());
        assert_eq!(r.identification.format, "ics");
        assert_eq!(r.content.title.as_deref(), Some("Harbour events"));
        let f = &r.format["ics"];
        assert_eq!(f["method"], "REQUEST");
        assert_eq!(f["items"], 2);
        assert_eq!(f["recurring"], 1);
        assert_eq!(f["date_range"][0], "2024-05-09T10:00:00");
        assert_eq!(f["date_range"][1], "2024-06-01");
        assert_eq!(f["events"][0]["organizer"]["domain"], "saltmere.example");
        assert!(f["events"][0]["organizer"].get("address").is_none());
        assert_eq!(f["events"][0]["attendee_list"][0]["status"], "accepted");
        assert_eq!(f["events"][1]["all_day"], true);
        assert_eq!(f["timezones"][0], "Europe/Paris");
    }
}
