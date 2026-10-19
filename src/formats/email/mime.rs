//! RFC 5322 / MIME messages (EML), mbox mailboxes, MHTML web archives and
//! Apple Mail EMLX files, parsed with `mail-parser`.

use std::collections::BTreeMap;

use mail_parser::{Address, Message, MessageParser, MimeHeaders, PartType};
use serde_json::json;

use super::Mail;
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, parse_date,
    truncate_chars,
};

/// Extractor for MIME messages and mailboxes.
pub struct Mime;

static META: ExtractorMeta = ExtractorMeta {
    id: "email.mime",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "eml",
            name: "Email message",
            family: "email",
            mimes: &["message/rfc822"],
            extensions: &["eml", "mail"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "mbox",
            name: "Mailbox (mbox)",
            family: "email",
            mimes: &["application/mbox"],
            extensions: &["mbox", "mbx"],
            // `From ` starts too many texts (git patches, quoted mail): the sniffer decides.
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "mhtml",
            name: "MHTML web archive",
            family: "email",
            mimes: &["multipart/related", "application/x-mimearchive"],
            extensions: &["mht", "mhtml"],
            magic: &[],
            parent: Some("text"),
        },
        FormatSpec {
            id: "emlx",
            name: "Apple Mail message",
            family: "email",
            mimes: &["message/x-emlx"],
            extensions: &["emlx"],
            magic: &[],
            parent: Some("text"),
        },
    ],
};

const HEADERS: &[&str] = &[
    "received:",
    "return-path:",
    "from:",
    "to:",
    "subject:",
    "date:",
    "message-id:",
    "mime-version:",
    "delivered-to:",
    "content-type:",
    "x-mailer:",
    "reply-to:",
    "cc:",
    "dkim-signature:",
    "authentication-results:",
    "x-originating-ip:",
    "user-agent:",
    "references:",
    "in-reply-to:",
    "sender:",
    "arc-seal:",
    "x-received:",
];

/// How many known header names start the lines of `head`'s first block.
fn header_score(head: &[u8]) -> usize {
    let text = String::from_utf8_lossy(&head[..head.len().min(8192)]);
    let mut n = 0;
    for line in text.lines().take(80) {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if HEADERS.iter().any(|h| lower.starts_with(h)) {
            n += 1;
        }
    }
    n
}

impl Extractor for Mime {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let head = probe.head;
        if head.starts_with(b"From ") {
            let first = head.iter().position(|&b| b == b'\n').map_or(head, |i| &head[..i]);
            // `git format-patch` output: an mbox of one, but a patch first.
            if first.ends_with(b"Mon Sep 17 00:00:00 2001") || first.ends_with(b"Mon Sep 17 00:00:00 2001\r") {
                return None;
            }
            let second = head.iter().position(|&b| b == b'\n').map_or(&head[..0], |i| &head[i + 1..]);
            return (header_score(second) >= 2).then_some(Sniff { format: "mbox", confidence: 0.9 });
        }
        // EMLX: a byte count on the first line, then the message.
        if let Some(nl) = head.iter().take(12).position(|&b| b == b'\n')
            && nl > 0
            && head[..nl].iter().all(|b| b.is_ascii_digit() || *b == b' ' || *b == b'\r')
            && header_score(&head[nl + 1..]) >= 2
        {
            return Some(Sniff { format: "emlx", confidence: 0.9 });
        }
        let score = header_score(head);
        if score < 2 {
            return None;
        }
        let lower = String::from_utf8_lossy(&head[..head.len().min(8192)]).to_ascii_lowercase();
        if lower.contains("snapshot-content-location:")
            || (lower.contains("multipart/related") && !lower.contains("\nfrom:") && !lower.starts_with("from:"))
        {
            return Some(Sniff { format: "mhtml", confidence: 0.85 });
        }
        Some(Sniff { format: "eml", confidence: if score >= 4 { 0.92 } else { 0.75 } })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, _) = cx.read_bytes(src)?;
        match cx.format_id() {
            "mbox" => mbox(&bytes, cx),
            "emlx" => emlx(&bytes, cx),
            "mhtml" => {
                let msg = MessageParser::default()
                    .parse(&bytes)
                    .ok_or_else(|| ExtractError::malformed("not a MIME message"))?;
                let mut mail = to_mail(&msg, false);
                if let Some(url) =
                    msg.header_raw("Snapshot-Content-Location").or_else(|| msg.root_part().content_location())
                {
                    mail.format.insert("url".into(), json!(truncate_chars(url.trim(), 500)));
                }
                let resources = msg.parts.len().saturating_sub(2);
                mail.format.insert("resources".into(), json!(resources));
                // Web archive parts are page resources, not attachments.
                mail.attachments.clear();
                mail.write(cx);
                Ok(())
            }
            _ => {
                let msg = MessageParser::default()
                    .parse(&bytes)
                    .ok_or_else(|| ExtractError::malformed("not a MIME message"))?;
                to_mail(&msg, true).write(cx);
                Ok(())
            }
        }
    }
}

crate::register_extractor!(Mime);

type Named = (Option<String>, Option<String>);

fn addrs(a: Option<&Address<'_>>) -> Vec<Named> {
    a.map(|a| a.iter().take(10_000).map(|x| (x.name().map(str::to_string), x.address().map(str::to_string))).collect())
        .unwrap_or_default()
}

fn rfc3339(d: &mail_parser::DateTime) -> Option<(String, bool)> {
    parse_date(&d.to_rfc3339())
}

/// The fields of a parsed message; `attachments` keeps attachment data.
#[allow(clippy::too_many_lines)] // one field after another
pub(crate) fn to_mail(m: &Message<'_>, attachments: bool) -> Mail {
    let mut mail = Mail {
        subject: m.subject().map(|s| truncate_chars(s.trim(), 1000)).filter(|s| !s.is_empty()),
        from: addrs(m.from()).into_iter().next(),
        sender: addrs(m.sender()).into_iter().next(),
        reply_to: addrs(m.reply_to()),
        return_path: m
            .return_path()
            .as_text()
            .map(|r| r.trim().trim_matches(['<', '>']).to_string())
            .filter(|r| r.contains('@')),
        to: addrs(m.to()),
        cc: addrs(m.cc()),
        bcc: addrs(m.bcc()),
        date: m.date().and_then(rfc3339),
        message_id: m.message_id().map(str::to_string),
        parts: m.parts.len(),
        ..Mail::default()
    };
    mail.received = m
        .received_all()
        .take(100)
        .map(|r| (r.date.as_ref().and_then(rfc3339).map(|d| d.0), r.by.as_ref().map(ToString::to_string)))
        .collect();
    mail.in_reply_to = m
        .in_reply_to()
        .as_text_list()
        .and_then(|l| l.first())
        .map(ToString::to_string)
        .or_else(|| m.in_reply_to().as_text().map(str::to_string));
    mail.references =
        m.references().as_text_list().map_or_else(|| usize::from(m.references().as_text().is_some()), <[_]>::len);
    let raw = |name: &str| m.header_raw(name).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    mail.client = raw("X-Mailer").or_else(|| raw("User-Agent"));
    mail.list_id = m.list_id().as_text().map(str::to_string);
    mail.bulk = raw("List-Unsubscribe").is_some()
        || raw("Precedence").is_some_and(|p| matches!(p.to_ascii_lowercase().as_str(), "bulk" | "list" | "junk"));
    mail.spam = raw("X-Spam-Status").or_else(|| raw("X-Spam-Flag"));
    mail.priority = raw("X-Priority").or_else(|| raw("Importance")).or_else(|| raw("Priority"));
    mail.language = raw("Content-Language");
    for (name, value) in m.headers_raw() {
        if name.eq_ignore_ascii_case("Authentication-Results")
            || name.eq_ignore_ascii_case("ARC-Authentication-Results")
        {
            auth_results(value, &mut mail.auth);
        } else if name.eq_ignore_ascii_case("DKIM-Signature")
            && let Some(d) = tag(value, "d")
            && mail.dkim_domains.len() < 10
            && !mail.dkim_domains.contains(&d)
        {
            mail.dkim_domains.push(d);
        } else if name.eq_ignore_ascii_case("Received-SPF")
            && let Some(word) = value.split_whitespace().next()
        {
            mail.auth.entry("spf".into()).or_insert_with(|| word.to_ascii_lowercase());
        }
    }
    mail.text = m
        .text_bodies()
        .find(|p| matches!(p.body, PartType::Text(_)))
        .and_then(|p| p.text_contents())
        .map(str::to_string);
    mail.html = m
        .html_bodies()
        .find(|p| matches!(p.body, PartType::Html(_)))
        .and_then(|p| p.text_contents())
        .map(str::to_string);
    // Signatures and encryption from the MIME structure.
    for p in &m.parts {
        let Some(ct) = p.content_type() else { continue };
        let full = format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("")).to_ascii_lowercase();
        match full.as_str() {
            "multipart/signed" => {
                let proto = ct.attribute("protocol").unwrap_or("").to_ascii_lowercase();
                mail.signed = Some(if proto.contains("pgp") { "pgp".into() } else { "smime".into() });
            }
            "application/pkcs7-mime" | "application/x-pkcs7-mime" => {
                if ct.attribute("smime-type").is_some_and(|t| t.eq_ignore_ascii_case("signed-data")) {
                    mail.signed = Some("smime".into());
                } else {
                    mail.encrypted = Some("smime".into());
                }
            }
            "multipart/encrypted" => mail.encrypted = Some("pgp".into()),
            _ => {}
        }
    }
    for (i, p) in m.attachments().enumerate() {
        if mail.attachments.len() >= 1000 {
            break;
        }
        let ctype = p
            .content_type()
            .map_or_else(String::new, |c| format!("{}/{}", c.ctype(), c.subtype().unwrap_or("")).to_ascii_lowercase());
        let data: Vec<u8> = match &p.body {
            PartType::Message(inner) => inner.raw_message().to_vec(),
            _ => p.contents().to_vec(),
        };
        let name = p.attachment_name().map_or_else(
            || {
                let ext = match ctype.as_str() {
                    "message/rfc822" => "eml",
                    "application/pdf" => "pdf",
                    "text/calendar" => "ics",
                    "text/vcard" | "text/x-vcard" => "vcf",
                    _ => "bin",
                };
                format!("attachment-{}.{ext}", i + 1)
            },
            str::to_string,
        );
        let size = data.len();
        // Signature parts are not attachments a reader opens.
        if matches!(
            ctype.as_str(),
            "application/pkcs7-signature" | "application/x-pkcs7-signature" | "application/pgp-signature"
        ) {
            continue;
        }
        mail.attachments.push((name, ctype, size, if attachments { data } else { Vec::new() }));
    }
    mail
}

/// `spf=pass`, `dkim=fail`, `dmarc=none` … from an Authentication-Results value.
fn auth_results(value: &str, out: &mut BTreeMap<String, String>) {
    for token in value.split([';', ' ', '\t', '\n', '\r']) {
        if let Some((k, v)) = token.split_once('=') {
            let k = k.trim().to_ascii_lowercase();
            if matches!(k.as_str(), "spf" | "dkim" | "dmarc" | "arc" | "bimi" | "auth" | "iprev") {
                let v: String =
                    v.trim().chars().take_while(char::is_ascii_alphabetic).collect::<String>().to_ascii_lowercase();
                if !v.is_empty() {
                    // The first verdict per method wins (the newest header comes first).
                    out.entry(k).or_insert(v);
                }
            }
        }
    }
}

/// A `tag=value` from a DKIM-Signature.
fn tag(value: &str, name: &str) -> Option<String> {
    value.split(';').find_map(|t| {
        let (k, v) = t.split_once('=')?;
        (k.trim() == name).then(|| v.trim().to_ascii_lowercase())
    })
}

/// Apple Mail `.emlx`: byte count, message, XML plist trailer with flags.
fn emlx(bytes: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let nl = bytes.iter().position(|&b| b == b'\n').ok_or_else(|| ExtractError::malformed("emlx byte count"))?;
    let count: usize = std::str::from_utf8(&bytes[..nl])
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| ExtractError::malformed("emlx byte count"))?;
    let end = (nl + 1 + count).min(bytes.len());
    let msg = MessageParser::default()
        .parse(&bytes[nl + 1..end])
        .ok_or_else(|| ExtractError::malformed("not a MIME message"))?;
    let mut mail = to_mail(&msg, true);
    let trailer = String::from_utf8_lossy(&bytes[end..]);
    if let Some(flags) = plist_value(&trailer, "flags").and_then(|v| v.parse::<u64>().ok()) {
        let names: Vec<&str> = [
            (0, "read"),
            (1, "deleted"),
            (2, "answered"),
            (3, "encrypted"),
            (4, "flagged"),
            (5, "recent"),
            (6, "draft"),
            (8, "forwarded"),
            (9, "redirected"),
        ]
        .iter()
        .filter(|(bit, _)| flags & (1 << bit) != 0)
        .map(|(_, n)| *n)
        .collect();
        mail.format.insert("mail_flags".into(), json!(names));
    }
    if let Some(d) = plist_value(&trailer, "date-received").and_then(|v| v.parse::<f64>().ok()) {
        // Seconds since 1970 in Apple Mail's trailer.
        #[allow(clippy::cast_possible_truncation)] // whole seconds
        let ts = d as i64;
        mail.format.insert("date_received_unix".into(), json!(ts));
    }
    mail.write(cx);
    Ok(())
}

/// The value after `<key>name</key>` in a plist.
fn plist_value(xml: &str, key: &str) -> Option<String> {
    let at = xml.find(&format!("<key>{key}</key>"))? + key.len() + 11;
    let rest = &xml[at..];
    let open = rest.find('>')? + 1;
    let close = rest[open..].find('<')? + open;
    Some(rest[open..close].trim().to_string())
}

/// A `From ` separated mailbox: totals, date range and senders, plus each
/// message as a child.
fn mbox(bytes: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut starts = vec![0usize];
    let mut i = 0;
    while let Some(p) = bytes[i..].windows(6).position(|w| w == b"\nFrom ") {
        let at = i + p + 1;
        // A separator follows a blank line (or a line end, in sloppy files).
        starts.push(at);
        i = at + 5;
        if starts.len() >= 1_000_000 {
            break;
        }
    }
    let parser = MessageParser::default();
    let recurse = cx.options().limits.max_depth > 0;
    let mut dates: Vec<String> = Vec::new();
    let mut senders = std::collections::BTreeSet::new();
    let mut subjects = String::new();
    let mut attachments = 0usize;
    let mut children = true;
    for (n, &s) in starts.iter().enumerate() {
        if n.is_multiple_of(64) {
            cx.checkpoint()?;
        }
        let e = starts.get(n + 1).copied().unwrap_or(bytes.len());
        let chunk = &bytes[s..e];
        let body = chunk.iter().position(|&b| b == b'\n').map_or(chunk, |nl| &chunk[nl + 1..]);
        let Some(msg) = parser.parse(body) else { continue };
        if let Some(d) = msg.date().and_then(rfc3339) {
            dates.push(d.0);
        }
        if let Some(d) = msg.from().and_then(Address::first).and_then(|a| a.address()).and_then(super::domain)
            && senders.len() < 100_000
        {
            senders.insert(d);
        }
        if let Some(s) = msg.subject()
            && subjects.len() < 256 * 1024
        {
            subjects.push_str(s.trim());
            subjects.push('\n');
        }
        attachments += msg.attachment_count();
        if recurse && children && cx.emit_child(&format!("message-{:05}.eml", n + 1), body.to_vec()).is_err() {
            children = false;
        }
    }
    dates.sort();
    cx.physical().entries(starts.len() as u64);
    cx.format_set("messages", starts.len());
    if let (Some(first), Some(last)) = (dates.first(), dates.last()) {
        cx.format_set("date_range", json!([first, last]));
    }
    cx.format_set("sender_domains", senders.len());
    if attachments > 0 {
        cx.format_set("attachments", attachments);
    }
    if !subjects.is_empty() {
        cx.emit_text(TextRole::Body, &subjects);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(name: &str, raw: &str) -> crate::plugin::Report {
        crate::plugin::testing::report_for(name, raw.replace('\n', "\r\n").as_bytes())
    }

    #[test]
    fn reads_a_plain_message() {
        let r = report(
            "notice.eml",
            "Received: from mx.saltmere.example by mail.example.org; Wed, 1 May 2024 08:31:00 +0200
From: Harbour Office <office@saltmere.example>
To: Mira Castell <mira@example.org>, ben@example.org
Subject: Berth 5 is free on Friday
Date: Wed, 1 May 2024 08:30:00 +0200
Message-ID: <berth5@saltmere.example>
Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=saltmere.example; dkim=pass header.d=saltmere.example
DKIM-Signature: v=1; a=rsa-sha256; d=saltmere.example; s=mail; h=from:to; b=abc
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Berth 5 is free from Friday noon.
",
        );
        assert_eq!(r.identification.format, "eml");
        assert_eq!(r.content.title.as_deref(), Some("Berth 5 is free on Friday"));
        let f = &r.format["eml"];
        // Strict privacy: domains only.
        assert_eq!(f["from"]["domain"], "saltmere.example");
        assert!(f["from"].get("address").is_none());
        assert_eq!(f["to_count"], 2);
        assert_eq!(f["authentication"]["spf"], "pass");
        assert_eq!(f["dkim_domains"][0], "saltmere.example");
        assert!(r.security.risks.is_empty(), "{:?}", r.security.risks);
        assert!(
            r.temporal
                .content
                .iter()
                .any(|d| d.field == crate::plugin::DateField::Sent && d.value == "2024-05-01T08:30:00+02:00")
        );
    }

    #[test]
    fn flags_phishing_signals() {
        let r = report(
            "fees.eml",
            "From: \"fees@saltmere.example\" <billing@other.example>
Reply-To: payments@third.example
To: mira@example.org
Subject: Mooring fee reminder
Date: Wed, 1 May 2024 08:30:00 +0000
Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=other.example; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=b1

--b1
Content-Type: text/html; charset=utf-8

<p>Your mooring fee is due. <a href=\"https://other.example/pay\">https://saltmere.example/fees</a></p>
--b1
Content-Type: application/octet-stream; name=\"invoice.pdf.exe\"
Content-Disposition: attachment; filename=\"invoice.pdf.exe\"
Content-Transfer-Encoding: base64

aGVsbG8=
--b1--
",
        );
        let kinds: Vec<&str> = r.security.risks.iter().map(|x| x.kind.as_str()).collect();
        for k in [
            "reply_to_mismatch",
            "display_name_spoof",
            "authentication_failure",
            "link_text_mismatch",
            "double_extension",
        ] {
            assert!(kinds.contains(&k), "{k} missing from {kinds:?}");
        }
        assert_eq!(r.format["eml"]["attachments"][0]["name"], "invoice.pdf.exe");
        assert_eq!(r.embedded.len(), 1);
    }

    #[test]
    fn counts_an_mbox() {
        let mbox = "From office@saltmere.example Wed May  1 08:30:00 2024
From: office@saltmere.example
Subject: Tides this week
Date: Wed, 1 May 2024 08:30:00 +0000

Spring tides.

From ben@example.org Thu May  2 09:00:00 2024
From: ben@example.org
Subject: Re: Tides this week
Date: Thu, 2 May 2024 09:00:00 +0000

Thanks.
";
        let r = crate::plugin::testing::report_for("harbour.mbox", mbox.as_bytes());
        assert_eq!(r.identification.format, "mbox");
        assert_eq!(r.format["mbox"]["messages"], 2);
        assert_eq!(r.format["mbox"]["sender_domains"], 2);
        assert_eq!(r.embedded.len(), 2);
    }

    crate::fixture_tests!("eml", "mbox", "mhtml", "emlx");

    #[test]
    fn auth_tokens() {
        let mut m = BTreeMap::new();
        auth_results("mx.example.org; spf=softfail (sender) smtp.mailfrom=x; dkim=none; dmarc=pass (p=none)", &mut m);
        assert_eq!(m["spf"], "softfail");
        assert_eq!(m["dmarc"], "pass");
        assert_eq!(tag("v=1; d=Example.ORG; s=k", "d").as_deref(), Some("example.org"));
    }
}
