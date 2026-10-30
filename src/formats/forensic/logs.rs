//! Logs and traces that summarise as counts and time ranges:
//! * Linux `utmp` / `wtmp` / `btmp`: records by type, logins, boots,
//!   failed logins, time range, how many users and remote hosts (never the
//!   names);
//! * systemd journal files: state, compression, entries, sequence numbers,
//!   time range, machine and boot IDs;
//! * Snort `unified2` alerts: record types, events, time range, top
//!   signatures (generator:signature:revision), priorities, blocked events;
//! * Snort / Suricata rule files: rules, disabled rules, actions,
//!   protocols, class types, SID range and duplicate SIDs;
//! * HAR (HTTP archive) files: creator, browser, pages, entries, methods,
//!   status codes, content types, host count, time range, transferred
//!   bytes; requests carrying credentials (Authorization, cookies) are
//!   counted and flagged, URLs and values are never reported;
//! * Apple `.ips` crash reports: app, version, bundle, OS, time, bug type,
//!   exception, termination reason, the crashed thread's top frames;
//! * Zeek TSV logs: log type, fields, records, time range;
//! * macOS `FSEvents` pages (`.fseventsd`, inside their gzip): version,
//!   records, event-flag histogram (paths are not listed).
//!
//! Specifications: glibc `bits/utmp.h`; systemd "Journal File Format";
//! Snort 2.9 `Unified2_common.h`; Snort / Suricata rule syntax; W3C HAR
//! 1.2; Apple "Interpreting the JSON format of a crash report"; Zeek
//! ASCII writer; libfsevents notes.

use std::collections::{BTreeMap, HashSet};

use serde_json::{Map, Value, json};

use super::{Window, be, hex, le, le_usize, unix_time, user_path};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for logs, alerts and traces.
pub struct Logs;

static META: ExtractorMeta = ExtractorMeta {
    id: "forensic.logs",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "utmp",
            name: "Linux utmp / wtmp / btmp",
            family: "forensic",
            mimes: &[],
            extensions: &["wtmp", "btmp", "utmp"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "systemd_journal",
            name: "systemd journal",
            family: "forensic",
            mimes: &[],
            extensions: &["journal", "journal~"],
            magic: &[Magic::prefix(b"LPKSHHRH")],
            parent: None,
        },
        FormatSpec {
            id: "unified2",
            name: "Snort unified2 alerts",
            family: "forensic",
            mimes: &[],
            extensions: &["u2", "unified2"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "ids_rules",
            name: "Snort / Suricata rules",
            family: "forensic",
            mimes: &[],
            extensions: &["rules"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "har",
            name: "HTTP archive (HAR)",
            family: "forensic",
            mimes: &["application/har+json"],
            extensions: &["har"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "ips_crash",
            name: "Apple crash report (.ips)",
            family: "forensic",
            mimes: &[],
            extensions: &["ips"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "zeek_log",
            name: "Zeek log",
            family: "forensic",
            mimes: &[],
            extensions: &["log"],
            magic: &[Magic::prefix(b"#separator \\x09")],
            parent: None,
        },
        FormatSpec {
            id: "fsevents",
            name: "macOS FSEvents page",
            family: "forensic",
            mimes: &[],
            extensions: &[],
            magic: &[Magic::prefix(b"1SLD"), Magic::prefix(b"2SLD"), Magic::prefix(b"3SLD")],
            parent: None,
        },
    ],
};

/// Histogram entries kept.
const TOP: usize = 20;
/// `struct utmp`: 384 bytes where the time is 32-bit (x86, `x86_64`, arm),
/// 400 where it is a 64-bit `timeval` (aarch64 and most other 64-bit ports).
const UTMP: usize = 384;
const UTMP64: usize = 400;

/// The record size of a utmp file of `len` bytes starting with `h`.
fn utmp_size(h: &[u8], len: u64) -> Option<usize> {
    let ok = |size: usize| {
        len.is_multiple_of(size as u64)
            && h.get(size..size + 2).is_none_or(|t| le(t) <= 9)
            && le(h.get(..2).unwrap_or(&[0xff, 0xff])) <= 9
    };
    [UTMP64, UTMP].into_iter().find(|&s| len >= s as u64 && ok(s))
}

fn top(m: BTreeMap<String, u64>) -> Value {
    let mut v: Vec<(String, u64)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Value::Object(v.into_iter().take(TOP).map(|(k, n)| (k, n.into())).collect())
}

fn bump(m: &mut BTreeMap<String, u64>, k: impl Into<String>) {
    *m.entry(k.into()).or_default() += 1;
}

fn time_range(cx: &mut Context<'_>, lo: i64, hi: i64) {
    if let (Some(a), Some(b)) = (unix_time(lo), unix_time(hi)) {
        cx.format_set("first", a.clone());
        cx.format_set("last", b);
        cx.temporal().source("forensic.logs").content_date(crate::plugin::DateField::Created, a, true);
    }
}

/// The first non-comment line of a rule file is a rule.
fn is_rule(line: &str) -> bool {
    let l = line.trim_start_matches(['#', ' ']).trim_start();
    let mut w = l.split_whitespace();
    matches!(
        w.next(),
        Some("alert" | "drop" | "pass" | "reject" | "log" | "sdrop" | "rejectsrc" | "rejectdst" | "rejectboth")
    ) && w.next().is_some()
        && l.contains("(msg:") | l.contains("( msg:") | l.contains("sid:")
}

impl Extractor for Logs {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let name = probe.name.map_or("", |n| n.rsplit(['/', '\\']).next().unwrap_or(n));
        let lower = name.to_ascii_lowercase();
        if ["wtmp", "btmp", "utmp"].iter().any(|n| lower.starts_with(n)) && utmp_size(h, probe.len).is_some() {
            return Some(Sniff { format: "utmp", confidence: 0.9 });
        }
        if let Ok(text) =
            std::str::from_utf8(&h[..h.len().min(8192)]).or_else(|e| std::str::from_utf8(&h[..e.valid_up_to()]))
        {
            let t = text.trim_start();
            if t.starts_with('{') && t.contains("\"log\"") && t.contains("\"entries\"") && t.contains("\"creator\"") {
                return Some(Sniff { format: "har", confidence: 0.95 });
            }
            if t.starts_with('{')
                && t.lines().next().is_some_and(|l| l.contains("\"bug_type\"") && l.contains("\"timestamp\""))
            {
                return Some(Sniff { format: "ips_crash", confidence: 0.95 });
            }
            if let Some(first) =
                t.lines().find(|l| !l.trim().is_empty() && !l.trim_start().starts_with("# ") && l.trim() != "#")
                && is_rule(first)
            {
                return Some(Sniff { format: "ids_rules", confidence: 0.9 });
            }
        }
        // unified2: two plausible records in a row.
        let rec = |at: usize| -> Option<usize> {
            let (t, n) = (be(h.get(at..at + 4)?), be(h.get(at + 4..at + 8)?));
            matches!(t, 2 | 7 | 72 | 104 | 105 | 110 | 111).then_some(usize::try_from(n).ok()?).filter(|&n| n < 65536)
        };
        let n = rec(0)?;
        (probe.len == 8 + n as u64 || rec(8 + n).is_some()).then_some(Sniff { format: "unified2", confidence: 0.75 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "utmp" => utmp(src, cx),
            "systemd_journal" => journal(src, cx),
            "unified2" => unified2(src, cx),
            "fsevents" => fsevents(src, cx),
            id => {
                let id = id.to_string();
                let (b, _) = cx.read_bytes(src)?;
                let text = String::from_utf8_lossy(&b);
                match id.as_str() {
                    "ids_rules" => rules(&text, cx),
                    "har" => har(&text, cx),
                    "ips_crash" => ips(&text, cx),
                    _ => {
                        zeek(&text, cx);
                        Ok(())
                    }
                }
            }
        }
    }
}

fn utmp(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut w = Window::new(src);
    let len = w.len();
    let head = w.get(0, (UTMP64 + 2).min(usize::try_from(len).unwrap_or(0))).unwrap_or_default().to_vec();
    let size = utmp_size(&head, len).ok_or_else(|| ExtractError::malformed("utmp record size"))?;
    // The time: 32-bit seconds at 340, or a 64-bit timeval at 344.
    let time_at = if size == UTMP { 340 } else { 344 };
    cx.format_set("record_size", size);
    let n = len / size as u64;
    let (mut lo, mut hi) = (i64::MAX, i64::MIN);
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let (mut users, mut hosts) = (HashSet::new(), HashSet::new());
    for i in 0..n.min(10_000_000) {
        let Some(r) = w.get(i * size as u64, size) else { break };
        let kind = le(&r[0..2]);
        let name = match kind {
            0 => "empty",
            1 => "run_level",
            2 => "boot",
            3 => "new_time",
            4 => "old_time",
            5 => "init_process",
            6 => "login_process",
            7 => "user_process",
            8 => "dead_process",
            9 => "accounting",
            _ => "unknown",
        };
        bump(&mut types, name);
        let user = super::asciiz(&r[44..76]);
        let host = super::asciiz(&r[76..332]);
        if kind == 7 || kind == 6 {
            users.insert(user);
            if !host.is_empty() {
                hosts.insert(host);
            }
        }
        let t = if size == UTMP {
            i64::from(i32::from_le_bytes(r[time_at..time_at + 4].try_into().unwrap_or_default()))
        } else {
            i64::from_le_bytes(r[time_at..time_at + 8].try_into().unwrap_or_default())
        };
        if t > 0 {
            lo = lo.min(t);
            hi = hi.max(t);
        }
        if i % 65_536 == 65_535 {
            cx.checkpoint()?;
        }
    }
    cx.format_set("records", n);
    cx.format_set("record_types", top(types));
    cx.format_set("users", users.len());
    cx.format_set("remote_hosts", hosts.len());
    time_range(cx, lo, hi);
    Ok(())
}

fn journal(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut h = vec![0u8; 240.min(usize::try_from(src.len()).unwrap_or(0))];
    src.read_exact_at(0, &mut h).map_err(|_| ExtractError::malformed("journal header"))?;
    let u = |at: usize| h.get(at..at + 8).map_or(0, le);
    cx.format_set(
        "state",
        match h.get(16) {
            Some(0) => "offline",
            Some(1) => "online",
            Some(2) => "archived",
            _ => "unknown",
        },
    );
    let incompat = h.get(12..16).map_or(0, le);
    let mut flags = Vec::new();
    for (bit, name) in
        [(1, "compressed_xz"), (2, "compressed_lz4"), (4, "keyed_hash"), (8, "compressed_zstd"), (16, "compact")]
    {
        if incompat & bit != 0 {
            flags.push(name);
        }
    }
    if h.get(8..12).map_or(0, le) & 1 != 0 {
        flags.push("sealed");
    }
    cx.format_set("flags", flags);
    cx.format_set("machine_id", hex(h.get(40..56).unwrap_or_default()));
    cx.format_set("boot_id", hex(h.get(56..72).unwrap_or_default()));
    cx.format_set("entries", u(152));
    cx.format_set("objects", u(144));
    cx.format_set("head_seqnum", u(168));
    cx.format_set("tail_seqnum", u(160));
    let us = |v: u64| i64::try_from(v / 1_000_000).unwrap_or(0);
    time_range(cx, us(u(184)), us(u(192)));
    Ok(())
}

#[allow(clippy::too_many_lines)] // record loop
fn unified2(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut w = Window::new(src);
    let mut at = 0u64;
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut sigs: BTreeMap<String, u64> = BTreeMap::new();
    let mut prios: BTreeMap<String, u64> = BTreeMap::new();
    let (mut events, mut blocked, mut lo, mut hi) = (0u64, 0u64, i64::MAX, i64::MIN);
    let mut records = 0u64;
    while records < 50_000_000 {
        let Some(h) = w.get(at, 8) else { break };
        let (kind, len) = (be(&h[..4]), be(&h[4..8]));
        let name = match kind {
            2 => "packet",
            7 => "event",
            72 => "event_ipv6",
            104 => "event_v2",
            105 => "event_v2_ipv6",
            110 => "extra_data",
            111 => "event_appid",
            _ => {
                cx.warn(format!("unknown record type {kind} at offset {at}"));
                break;
            }
        };
        records += 1;
        bump(&mut types, name);
        if matches!(kind, 7 | 72 | 104 | 105) {
            let Some(e) = w.get(at + 8, usize::try_from(len.min(64)).unwrap_or(0)) else { break };
            let n = |a: usize| e.get(a..a + 4).map_or(0, be);
            events += 1;
            let t = i64::try_from(n(8)).unwrap_or(0);
            lo = lo.min(t);
            hi = hi.max(t);
            bump(&mut sigs, format!("{}:{}:{}", n(20), n(16), n(24)));
            bump(&mut prios, n(32).to_string());
            // `blocked` sits after the addresses, ports, protocol and impact.
            let addr = if kind == 7 || kind == 104 { 4 } else { 16 };
            let blocked_at = 36 + 2 * addr + 4 + 1 + 1 + 1;
            if e.get(blocked_at).is_some_and(|&b| b != 0) {
                blocked += 1;
            }
        }
        at += 8 + len;
        if records.is_multiple_of(65_536) {
            cx.checkpoint()?;
        }
    }
    if records == 0 {
        return Err(ExtractError::malformed("unified2 record"));
    }
    cx.format_set("records", records);
    cx.format_set("record_types", top(types));
    cx.format_set("events", events);
    if events > 0 {
        cx.format_set("signatures", top(sigs));
        cx.format_set("priorities", top(prios));
        cx.format_set("blocked", blocked);
        time_range(cx, lo, hi);
    }
    Ok(())
}

fn rules(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let (mut active, mut disabled) = (0u64, 0u64);
    let mut actions: BTreeMap<String, u64> = BTreeMap::new();
    let mut protocols: BTreeMap<String, u64> = BTreeMap::new();
    let mut classes: BTreeMap<String, u64> = BTreeMap::new();
    let mut sids: HashSet<u64> = HashSet::new();
    let (mut dup, mut lo, mut hi) = (0u64, u64::MAX, 0u64);
    for line in text.lines() {
        let l = line.trim();
        if !is_rule(l) {
            continue;
        }
        if l.starts_with('#') {
            disabled += 1;
            continue;
        }
        active += 1;
        let mut w = l.split_whitespace();
        bump(&mut actions, w.next().unwrap_or(""));
        bump(&mut protocols, w.next().unwrap_or("").to_ascii_lowercase());
        let opts = l.split_once('(').map_or("", |(_, o)| o);
        for o in opts.split(';') {
            let Some((k, v)) = o.trim().split_once(':') else { continue };
            match k.trim() {
                "sid" => {
                    if let Ok(s) = v.trim().parse::<u64>() {
                        if !sids.insert(s) {
                            dup += 1;
                        }
                        lo = lo.min(s);
                        hi = hi.max(s);
                    }
                }
                "classtype" => bump(&mut classes, v.trim()),
                _ => {}
            }
        }
    }
    if active + disabled == 0 {
        return Err(ExtractError::malformed("no rule"));
    }
    cx.format_set("rules", active);
    cx.format_set("disabled_rules", disabled);
    cx.format_set("actions", top(actions));
    cx.format_set("protocols", top(protocols));
    if !classes.is_empty() {
        cx.format_set("class_types", top(classes));
    }
    if lo <= hi {
        cx.format_set("sid_min", lo);
        cx.format_set("sid_max", hi);
    }
    if dup > 0 {
        cx.format_set("duplicate_sids", dup);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // entry loop
fn har(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let v: Value = serde_json::from_str(text).map_err(|_| ExtractError::malformed("HAR JSON"))?;
    let log = v.get("log").ok_or_else(|| ExtractError::malformed("HAR without log"))?;
    if let Some(s) = log.get("version").and_then(Value::as_str) {
        cx.format_set("version", s);
    }
    for k in ["creator", "browser"] {
        if let Some(c) = log.get(k) {
            let name = c.get("name").and_then(Value::as_str).unwrap_or("");
            let ver = c.get("version").and_then(Value::as_str).unwrap_or("");
            cx.format_set(k, json!({ "name": name, "version": ver }));
        }
    }
    cx.format_set("pages", log.get("pages").and_then(Value::as_array).map_or(0, Vec::len));
    let entries = log.get("entries").and_then(Value::as_array).cloned().unwrap_or_default();
    cx.format_set("entries", entries.len());
    let mut methods: BTreeMap<String, u64> = BTreeMap::new();
    let mut statuses: BTreeMap<String, u64> = BTreeMap::new();
    let mut types: BTreeMap<String, u64> = BTreeMap::new();
    let mut hosts = HashSet::new();
    let (mut first, mut last): (Option<String>, Option<String>) = (None, None);
    let (mut bytes, mut auth, mut cookies, mut posts) = (0i64, 0u64, 0u64, 0u64);
    for e in &entries {
        let req = &e["request"];
        let res = &e["response"];
        bump(&mut methods, req["method"].as_str().unwrap_or("?"));
        if let Some(s) = res["status"].as_i64() {
            bump(&mut statuses, s.to_string());
        }
        if let Some(m) = res["content"]["mimeType"].as_str() {
            bump(&mut types, m.split(';').next().unwrap_or("").trim().to_ascii_lowercase());
        }
        if let Some(u) = req["url"].as_str() {
            let host = u.split("://").nth(1).unwrap_or(u).split(['/', '?', '#']).next().unwrap_or("");
            hosts.insert(host.rsplit('@').next().unwrap_or(host).to_ascii_lowercase());
        }
        if let Some(t) = e["startedDateTime"].as_str() {
            if first.as_deref().is_none_or(|f| t < f) {
                first = Some(t.to_string());
            }
            if last.as_deref().is_none_or(|l| t > l) {
                last = Some(t.to_string());
            }
        }
        let size = res["_transferSize"].as_i64().or_else(|| res["bodySize"].as_i64()).unwrap_or(0);
        bytes += size.max(0);
        let headers = req["headers"].as_array().cloned().unwrap_or_default();
        if headers.iter().any(|h| h["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case("authorization"))) {
            auth += 1;
        }
        if req["cookies"].as_array().is_some_and(|c| !c.is_empty())
            || headers.iter().any(|h| h["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case("cookie")))
        {
            cookies += 1;
        }
        if req.get("postData").is_some() {
            posts += 1;
        }
    }
    cx.format_set("methods", top(methods));
    cx.format_set("status_codes", top(statuses));
    cx.format_set("content_types", top(types));
    cx.format_set("hosts", hosts.len());
    cx.format_set("transferred_bytes", bytes);
    if let (Some(a), Some(b)) = (first, last) {
        cx.format_set("first", a);
        cx.format_set("last", b);
    }
    cx.format_set("requests_with_authorization", auth);
    cx.format_set("requests_with_cookies", cookies);
    cx.format_set("requests_with_body", posts);
    if auth + cookies > 0 {
        cx.security().risk("embedded_secret", Some("HAR credentials (Authorization or cookies)".into()));
    }
    Ok(())
}

fn ips(text: &str, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let (head, body) = text.split_once('\n').unwrap_or((text, ""));
    let h: Value = serde_json::from_str(head).map_err(|_| ExtractError::malformed("crash report header"))?;
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    for (k, key) in [
        ("app_name", "app"),
        ("app_version", "app_version"),
        ("build_version", "build"),
        ("bundleID", "bundle_id"),
        ("bug_type", "bug_type"),
        ("os_version", "os"),
        ("timestamp", "timestamp"),
        ("incident_id", "incident_id"),
    ] {
        if let Some(v) = s(&h, k) {
            cx.format_set(key, v);
        }
    }
    if let Some(a) = s(&h, "app_name").or_else(|| s(&h, "name")) {
        cx.content().source("forensic.logs").title(a);
    }
    let Ok(b) = serde_json::from_str::<Value>(body) else { return Ok(()) };
    if let Some(p) = s(&b, "procPath") {
        cx.format_set("process_path", user_path(cx, &p));
    }
    if let Some(e) = b.get("exception") {
        let mut m = Map::new();
        for k in ["type", "signal", "codes", "subtype"] {
            if let Some(v) = e.get(k) {
                m.insert(k.into(), v.clone());
            }
        }
        cx.format_set("exception", Value::Object(m));
    }
    if let Some(t) = b.get("termination") {
        let mut m = Map::new();
        for k in ["namespace", "code", "indicator"] {
            if let Some(v) = t.get(k) {
                m.insert(k.into(), v.clone());
            }
        }
        cx.format_set("termination", Value::Object(m));
    }
    let images = b.get("usedImages").and_then(Value::as_array).cloned().unwrap_or_default();
    cx.format_set("images", images.len());
    if let Some(i) = b.get("faultingThread").and_then(Value::as_u64)
        && let Some(th) = b.get("threads").and_then(|t| t.get(usize::try_from(i).ok()?))
    {
        let frames: Vec<Value> = th
            .get("frames")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(5)
            .map(|f| {
                let image = f["imageIndex"]
                    .as_u64()
                    .and_then(|k| images.get(usize::try_from(k).ok()?))
                    .and_then(|im| im["name"].as_str());
                json!({ "symbol": f["symbol"].as_str(), "image": image })
            })
            .collect();
        cx.format_set("crashed_thread", json!({ "index": i, "frames": frames }));
    }
    Ok(())
}

fn zeek(text: &str, cx: &mut Context<'_>) {
    let mut fields: Vec<&str> = Vec::new();
    let (mut records, mut lo, mut hi) = (0u64, f64::MAX, f64::MIN);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix('#') {
            let (k, v) = rest.split_once(['\t', ' ']).unwrap_or((rest, ""));
            match k {
                "path" => cx.format_set("log_type", v.trim()),
                "fields" => fields = v.split('\t').collect(),
                "open" => cx.format_set("opened", v.trim()),
                "close" => cx.format_set("closed", v.trim()),
                _ => {}
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        records += 1;
        if fields.first() == Some(&"ts")
            && let Some(t) = line.split('\t').next().and_then(|t| t.parse::<f64>().ok())
        {
            lo = lo.min(t);
            hi = hi.max(t);
        }
    }
    cx.format_set("fields", fields.iter().take(64).map(|f| Value::from(*f)).collect::<Vec<_>>());
    cx.format_set("records", records);
    #[allow(clippy::cast_possible_truncation)]
    if lo <= hi {
        time_range(cx, lo.floor() as i64, hi.floor() as i64);
    }
}

fn fsevents(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let (b, _) = cx.read_bytes(src)?;
    let mut at = 0;
    let (mut pages, mut records) = (0u64, 0u64);
    let mut flags: BTreeMap<String, u64> = BTreeMap::new();
    let mut version = 0u8;
    while at + 12 <= b.len() && b[at + 1..at + 4] == *b"SLD" {
        let v = b[at] - b'0';
        version = version.max(v);
        let size = le_usize(&b[at + 8..at + 12]);
        let end = (at + size).min(b.len());
        pages += 1;
        let mut p = at + 12;
        let tail = match v {
            1 => 12,
            2 => 20,
            _ => 24,
        };
        while p < end {
            let Some(nul) = b[p..end].iter().position(|&c| c == 0) else { break };
            p += nul + 1;
            let Some(r) = b.get(p..p + tail) else { break };
            let f = le(&r[8..12]);
            records += 1;
            for (bit, name) in [
                (0x1, "created"),
                (0x2, "removed"),
                (0x8, "renamed"),
                (0x10, "modified"),
                (0x40, "inode_meta_modified"),
                (0x800, "finder_info_modified"),
                (0x1_0000, "file"),
                (0x2_0000, "directory"),
                (0x4_0000, "symlink"),
                (0x10_0000, "hard_link"),
            ] {
                if f & bit != 0 {
                    bump(&mut flags, name);
                }
            }
            p += tail;
        }
        if size < 12 {
            break;
        }
        at += size;
    }
    if pages == 0 {
        return Err(ExtractError::malformed("FSEvents page"));
    }
    cx.format_set("version", version);
    cx.format_set("pages", pages);
    cx.format_set("records", records);
    cx.format_set("event_flags", top(flags));
    Ok(())
}

crate::register_extractor!(Logs);

#[cfg(test)]
mod tests {
    use crate::plugin::testing::report_for;

    #[test]
    fn har_credentials_are_counted_not_shown() {
        let har = r#"{"log":{"version":"1.2","creator":{"name":"Harbour","version":"1"},"pages":[],"entries":[
            {"startedDateTime":"2025-09-01T12:00:00Z","request":{"method":"GET","url":"https://tides.saltmere.example/a",
             "headers":[{"name":"Authorization","value":"Bearer c2VjcmV0"}],"cookies":[]},
             "response":{"status":200,"content":{"mimeType":"text/html"},"bodySize":120}}]}}"#;
        let r = report_for("session.har", har.as_bytes());
        let f = &r.format["har"];
        assert_eq!(f["entries"], 1);
        assert_eq!(f["hosts"], 1);
        assert_eq!(f["requests_with_authorization"], 1);
        assert!(r.security.risks.iter().any(|x| x.kind == "embedded_secret"));
        assert!(!serde_json::to_string(&r).unwrap().contains("c2VjcmV0"));
    }

    crate::fixture_tests!(
        "utmp",
        "systemd_journal",
        "unified2",
        "ids_rules",
        "har",
        "ips_crash",
        "zeek_log",
        "fsevents"
    );
}
