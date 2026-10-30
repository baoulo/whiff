//! Packet captures: pcap (micro- and nanosecond, either byte order),
//! pcapng (section: OS, hardware, application; interfaces: link type,
//! name, description, snap length; block counts, name resolution and
//! decryption-secret blocks) and Bluetooth btsnoop. Each gives the packet
//! count, captured and original bytes, truncated packets and the time
//! range; with the `full` profile also a protocol histogram from the
//! Ethernet / IP / TCP / UDP headers and well-known ports. Addresses and
//! payloads are never reported.
//!
//! Specifications: pcap (draft-ietf-opsawg-pcap), pcapng
//! (draft-ietf-opsawg-pcapng), tcpdump.org link-layer types; btsnoop
//! (RFC 1761 style, as written by Android and `BlueZ`).

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::{Window, unix_time};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Profile, Source, truncate_chars,
};

/// Extractor for packet captures.
pub struct Capture;

static META: ExtractorMeta = ExtractorMeta {
    id: "forensic.capture",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "pcap",
            name: "pcap packet capture",
            family: "forensic",
            mimes: &["application/vnd.tcpdump.pcap"],
            extensions: &["pcap", "cap", "dmp"],
            magic: &[
                Magic::prefix(b"\xd4\xc3\xb2\xa1"),
                Magic::prefix(b"\xa1\xb2\xc3\xd4"),
                Magic::prefix(b"\x4d\x3c\xb2\xa1"),
                Magic::prefix(b"\xa1\xb2\x3c\x4d"),
            ],
            parent: None,
        },
        FormatSpec {
            id: "pcapng",
            name: "pcapng packet capture",
            family: "forensic",
            mimes: &["application/x-pcapng"],
            extensions: &["pcapng", "ntar"],
            magic: &[Magic::prefix(b"\x0a\x0d\x0d\x0a")],
            parent: None,
        },
        FormatSpec {
            id: "btsnoop",
            name: "Bluetooth btsnoop log",
            family: "forensic",
            mimes: &[],
            extensions: &["btsnoop", "log", "cfa"],
            magic: &[Magic::prefix(b"btsnoop\0")],
            parent: None,
        },
    ],
};

/// Packets walked.
const MAX_PACKETS: u64 = 50_000_000;

fn link_type(t: u32) -> String {
    match t & 0x0fff_ffff {
        0 => "null".into(),
        1 => "ethernet".into(),
        6 => "ieee802_5".into(),
        9 => "ppp".into(),
        12 | 14 | 101 => "raw_ip".into(),
        104 => "cisco_hdlc".into(),
        105 => "ieee802_11".into(),
        113 => "linux_sll".into(),
        119 => "prism".into(),
        127 => "ieee802_11_radiotap".into(),
        147..=162 => "user".into(),
        187 => "bluetooth_hci_h4".into(),
        189 => "usb_linux".into(),
        195 => "ieee802_15_4".into(),
        201 => "bluetooth_hci_h4_with_phdr".into(),
        220 => "usb_linux_mmapped".into(),
        228 => "ipv4".into(),
        229 => "ipv6".into(),
        249 => "usbpcap".into(),
        253 => "netlink".into(),
        276 => "linux_sll2".into(),
        n => format!("linktype_{n}"),
    }
}

/// What the packets add up to.
#[derive(Default)]
struct Stats {
    packets: u64,
    captured: u64,
    original: u64,
    truncated: u64,
    first: Option<f64>,
    last: Option<f64>,
    protocols: Option<BTreeMap<&'static str, u64>>,
}

impl Stats {
    fn packet(&mut self, ts: f64, cap: u64, orig: u64) {
        self.packets += 1;
        self.captured += cap;
        self.original += orig;
        if cap < orig {
            self.truncated += 1;
        }
        if ts > 0.0 {
            self.first = Some(self.first.map_or(ts, |f| f.min(ts)));
            self.last = Some(self.last.map_or(ts, |l| l.max(ts)));
        }
    }

    fn classify(&mut self, link: u32, data: &[u8]) {
        let Some(h) = self.protocols.as_mut() else { return };
        for p in protocols(link, data) {
            *h.entry(p).or_default() += 1;
        }
    }

    fn report(self, cx: &mut Context<'_>) {
        cx.format_set("packets", self.packets);
        cx.format_set("captured_bytes", self.captured);
        cx.format_set("original_bytes", self.original);
        if self.truncated > 0 {
            cx.format_set("truncated_packets", self.truncated);
        }
        #[allow(clippy::cast_possible_truncation)] // capture times are recent seconds
        let t = |v: f64| unix_time(v.floor() as i64);
        if let (Some(a), Some(b)) = (self.first.and_then(t), self.last.and_then(t)) {
            cx.format_set("first_packet", a.clone());
            cx.format_set("last_packet", b.clone());
            let mut tw = cx.temporal();
            tw.source("forensic.capture");
            tw.content_date(crate::plugin::DateField::Created, a, true);
        }
        if let (Some(a), Some(b)) = (self.first, self.last) {
            cx.format_set("duration_s", ((b - a) * 1000.0).round() / 1000.0);
        }
        if let Some(h) = self.protocols {
            let mut v: Vec<(&str, u64)> = h.into_iter().collect();
            v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            let m: Map<String, Value> = v.into_iter().map(|(k, n)| (k.to_string(), n.into())).collect();
            cx.format_set("protocols", Value::Object(m));
        }
    }
}

fn port_name(p: u16) -> Option<&'static str> {
    Some(match p {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 | 465 => "smtp",
        53 => "dns",
        67 | 68 => "dhcp",
        80 | 8080 => "http",
        110 => "pop3",
        123 => "ntp",
        137..=139 => "netbios",
        143 | 993 => "imap",
        161 | 162 => "snmp",
        389 | 636 => "ldap",
        443 | 8443 => "tls",
        445 => "smb",
        514 => "syslog",
        1900 => "ssdp",
        3389 => "rdp",
        5353 => "mdns",
        5355 => "llmnr",
        _ => return None,
    })
}

/// The protocols a frame carries, outermost first.
fn protocols(link: u32, d: &[u8]) -> Vec<&'static str> {
    let mut out = Vec::new();
    let (ethertype, ip) = match link & 0x0fff_ffff {
        1 => {
            out.push("ethernet");
            let mut at = 12;
            let mut t = super::be(d.get(12..14).unwrap_or_default());
            // 802.1Q tags.
            while t == 0x8100 || t == 0x88a8 {
                out.push("vlan");
                at += 4;
                t = super::be(d.get(at..at + 2).unwrap_or_default());
            }
            (t, d.get(at + 2..))
        }
        113 => (super::be(d.get(14..16).unwrap_or_default()), d.get(16..)),
        12 | 14 | 101 | 228 | 229 => (if d.first().is_some_and(|b| b >> 4 == 6) { 0x86dd } else { 0x0800 }, Some(d)),
        _ => return out,
    };
    let Some(ip) = ip else { return out };
    let (proto, l4) = match ethertype {
        0x0800 if ip.first().is_some_and(|b| b >> 4 == 4) => {
            out.push("ipv4");
            let ihl = usize::from(ip[0] & 0x0f) * 4;
            (ip.get(9).copied(), ip.get(ihl..))
        }
        0x86dd => {
            out.push("ipv6");
            (ip.get(6).copied(), ip.get(40..))
        }
        0x0806 => {
            out.push("arp");
            return out;
        }
        0x88cc => {
            out.push("lldp");
            return out;
        }
        _ => {
            out.push("other_l3");
            return out;
        }
    };
    let name = match proto {
        Some(6) => "tcp",
        Some(17) => "udp",
        Some(1) => "icmp",
        Some(58) => "icmpv6",
        Some(2) => "igmp",
        Some(47) => "gre",
        Some(50) => "esp",
        _ => "other_l4",
    };
    out.push(name);
    if (name == "tcp" || name == "udp")
        && let Some(l4) = l4
    {
        let port = |at: usize| l4.get(at..at + 2).map(|p| u16::from_be_bytes([p[0], p[1]]));
        if let (Some(s), Some(d)) = (port(0), port(2))
            && let Some(app) = port_name(s.min(d)).or_else(|| port_name(s)).or_else(|| port_name(d))
        {
            out.push(if app == "tls" && name == "udp" { "quic" } else { app });
        }
    }
    out
}

impl Extractor for Capture {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut st = Stats::default();
        if cx.options().profile == Profile::Full {
            st.protocols = Some(BTreeMap::new());
        }
        let mut w = Window::new(src);
        match cx.format_id() {
            "pcapng" => pcapng(&mut w, &mut st, cx)?,
            "btsnoop" => btsnoop(&mut w, &mut st, cx)?,
            _ => pcap(&mut w, &mut st, cx)?,
        }
        st.report(cx);
        Ok(())
    }
}

fn pcap(w: &mut Window<'_>, st: &mut Stats, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = w.get(0, 24).ok_or_else(|| ExtractError::malformed("pcap header"))?.to_vec();
    let (big, nanos) = match &h[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
        _ => (true, true),
    };
    let n = |b: &[u8]| if big { super::be(b) } else { super::le(b) };
    cx.format_set("version", format!("{}.{}", n(&h[4..6]), n(&h[6..8])));
    cx.format_set("byte_order", if big { "big_endian" } else { "little_endian" });
    cx.format_set("timestamp_resolution", if nanos { "nanosecond" } else { "microsecond" });
    cx.format_set("snap_length", n(&h[16..20]));
    let link = u32::try_from(n(&h[20..24])).unwrap_or(0);
    cx.format_set("link_type", link_type(link));
    let scale = if nanos { 1e-9 } else { 1e-6 };
    let mut at = 24u64;
    while st.packets < MAX_PACKETS {
        let Some(r) = w.get(at, 16) else { break };
        let (sec, frac, cap, orig) = (n(&r[..4]), n(&r[4..8]), n(&r[8..12]), n(&r[12..16]));
        if cap > 0x0400_0000 {
            cx.warn(format!("packet record at offset {at} is malformed"));
            break;
        }
        #[allow(clippy::cast_precision_loss)]
        st.packet(sec as f64 + frac as f64 * scale, cap, orig);
        if st.protocols.is_some()
            && let Some(d) = w.get(at + 16, usize::try_from(cap.min(128)).unwrap_or(0))
        {
            let d = d.to_vec();
            st.classify(link, &d);
        }
        at += 16 + cap;
        if st.packets.is_multiple_of(65_536) {
            cx.checkpoint()?;
        }
    }
    if at < w.len() && at + 16 > w.len() {
        cx.warn("the capture ends in the middle of a packet");
    }
    Ok(())
}

/// The value of a pcapng option list's `code`, as text.
fn options(b: &[u8], big: bool) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= b.len() {
        let n = |v: &[u8]| if big { super::be(v) } else { super::le(v) };
        let code = u16::try_from(n(&b[at..at + 2])).unwrap_or(0);
        let len = usize::try_from(n(&b[at + 2..at + 4])).unwrap_or(0);
        if code == 0 {
            break;
        }
        let Some(v) = b.get(at + 4..at + 4 + len) else { break };
        out.push((code, v.to_vec()));
        at += 4 + len.div_ceil(4) * 4;
    }
    out
}

fn text(v: &[u8]) -> String {
    truncate_chars(String::from_utf8_lossy(v).trim_end_matches('\0'), 200)
}

#[allow(clippy::too_many_lines)] // one arm per block type
fn pcapng(w: &mut Window<'_>, st: &mut Stats, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut at = 0u64;
    let mut big = false;
    let mut sections = 0u64;
    let mut ifaces: Vec<(u32, f64)> = Vec::new();
    let mut iface_list = Vec::new();
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut comments = 0u64;
    let mut blocks = 0u64;
    while blocks < MAX_PACKETS {
        let Some(h) = w.get(at, 12) else { break };
        let h = h.to_vec();
        let kind = u32::try_from(super::le(&h[..4])).unwrap_or(0);
        if kind == 0x0a0d_0d0a {
            big = h[8..12] == [0x1a, 0x2b, 0x3c, 0x4d];
            sections += 1;
            ifaces.clear();
        }
        let n = |b: &[u8]| if big { super::be(b) } else { super::le(b) };
        let len = n(&h[4..8]);
        if len < 12 || !len.is_multiple_of(4) || at + len > w.len() {
            if at == 0 {
                return Err(ExtractError::malformed("pcapng section header"));
            }
            cx.warn(format!("block at offset {at} is malformed or cut short"));
            break;
        }
        let body_len = usize::try_from(len - 12).unwrap_or(0);
        let kind = u32::try_from(n(&h[..4])).unwrap_or(0);
        // Packet blocks: only their fixed part is read (and 128 bytes of data
        // for the protocol histogram).
        let want = if matches!(kind, 2 | 3 | 6) { body_len.min(20 + 128) } else { body_len.min(1 << 20) };
        let body = w.get(at + 8, want).map(<[u8]>::to_vec).unwrap_or_default();
        blocks += 1;
        let name = match kind {
            0x0a0d_0d0a => {
                if sections == 1 {
                    cx.format_set("version", format!("{}.{}", n(&body[4..6]), n(&body[6..8])));
                    cx.format_set("byte_order", if big { "big_endian" } else { "little_endian" });
                    for (code, v) in options(&body[16..], big) {
                        match code {
                            1 => comments += 1,
                            2 => cx.format_set("hardware", text(&v)),
                            3 => cx.format_set("os", text(&v)),
                            4 => cx.format_set("application", text(&v)),
                            _ => {}
                        }
                    }
                }
                "section_header"
            }
            1 => {
                let link = u32::try_from(n(&body[..2])).unwrap_or(0);
                let mut m = Map::new();
                m.insert("link_type".into(), link_type(link).into());
                m.insert("snap_length".into(), n(&body[4..8]).into());
                let mut res = 1e-6;
                for (code, v) in options(&body[8..], big) {
                    match code {
                        1 => comments += 1,
                        2 => {
                            m.insert("name".into(), text(&v).into());
                        }
                        3 => {
                            m.insert("description".into(), text(&v).into());
                        }
                        9 => {
                            if let Some(&r) = v.first() {
                                let e = i32::from(r & 0x7f);
                                res = if r & 0x80 == 0 { 10f64.powi(-e) } else { 2f64.powi(-e) };
                            }
                        }
                        11 => {
                            m.insert("filter".into(), text(v.get(1..).unwrap_or_default()).into());
                        }
                        12 => {
                            m.insert("os".into(), text(&v).into());
                        }
                        _ => {}
                    }
                }
                ifaces.push((link, res));
                if iface_list.len() < 64 {
                    iface_list.push(Value::Object(m));
                }
                "interface_description"
            }
            6 | 2 => {
                let (iface, ts_at, cap_at) = if kind == 6 { (n(&body[..4]), 4, 12) } else { (n(&body[..2]), 4, 12) };
                let (link, res) =
                    ifaces.get(usize::try_from(iface).unwrap_or(usize::MAX)).copied().unwrap_or((1, 1e-6));
                let ts = (n(&body[ts_at..ts_at + 4]) << 32) | n(&body[ts_at + 4..ts_at + 8]);
                #[allow(clippy::cast_precision_loss)]
                st.packet(ts as f64 * res, n(&body[cap_at..cap_at + 4]), n(&body[cap_at + 4..cap_at + 8]));
                if st.protocols.is_some() {
                    st.classify(link, body.get(20..).unwrap_or_default());
                }
                if kind == 6 { "enhanced_packet" } else { "packet" }
            }
            3 => {
                let orig = n(&body[..4]);
                let cap = (body_len as u64 - 4).min(orig);
                st.packet(0.0, cap, orig);
                let link = ifaces.first().map_or(1, |i| i.0);
                if st.protocols.is_some() {
                    st.classify(link, body.get(4..).unwrap_or_default());
                }
                "simple_packet"
            }
            4 => "name_resolution",
            5 => "interface_statistics",
            0x0a => "decryption_secrets",
            0x0bad | 0x4000_0bad => "custom",
            0x0204 | 0x0201 | 0x0202 => "systemd_journal_export",
            _ => "other",
        };
        *counts.entry(name).or_default() += 1;
        at += len;
        if blocks.is_multiple_of(65_536) {
            cx.checkpoint()?;
        }
    }
    cx.format_set("sections", sections);
    cx.format_set("interfaces", iface_list);
    cx.format_set("blocks", Value::Object(counts.iter().map(|(k, v)| ((*k).to_string(), json!(v))).collect()));
    if comments > 0 {
        cx.format_set("comments", comments);
    }
    // Name resolution holds addresses with host names: only counted.
    if counts.contains_key("decryption_secrets") {
        cx.security().risk("embedded_secret", Some("pcapng decryption secrets".into()));
    }
    Ok(())
}

/// Seconds between year 0 (btsnoop's epoch, in microseconds) and 1970.
const BTSNOOP_EPOCH_US: i64 = 0x00dc_ddb3_0f2f_8000;

fn btsnoop(w: &mut Window<'_>, st: &mut Stats, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = w.get(0, 16).ok_or_else(|| ExtractError::malformed("btsnoop header"))?.to_vec();
    cx.format_set("version", super::be(&h[8..12]));
    let link = super::be(&h[12..16]);
    cx.format_set(
        "datalink",
        match link {
            1001 => "hci_h1",
            1002 => "hci_uart",
            1003 => "hci_bscp",
            1004 => "hci_serial",
            2001 => "linux_monitor",
            _ => "unknown",
        },
    );
    let mut at = 16u64;
    while st.packets < MAX_PACKETS {
        let Some(r) = w.get(at, 24) else { break };
        let (orig, cap) = (super::be(&r[..4]), super::be(&r[4..8]));
        let ts = i64::from_be_bytes(r[16..24].try_into().unwrap_or_default());
        #[allow(clippy::cast_precision_loss)]
        st.packet((ts - BTSNOOP_EPOCH_US) as f64 / 1e6, cap, orig);
        at += 24 + cap;
        if st.packets.is_multiple_of(65_536) {
            cx.checkpoint()?;
        }
    }
    Ok(())
}

crate::register_extractor!(Capture);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::testing::report_for;

    #[test]
    fn protocol_layers() {
        let mut f = vec![0u8; 12];
        f.extend([0x08, 0x00, 0x45, 0, 0, 40, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
        f.extend([0xd4, 0x31, 0x00, 0x35]);
        assert_eq!(protocols(1, &f), ["ethernet", "ipv4", "udp", "dns"]);
    }

    #[test]
    fn decryption_secrets_are_flagged() {
        let mut b = Vec::new();
        let block = |b: &mut Vec<u8>, kind: u32, body: &[u8]| {
            let len = u32::try_from(12 + body.len()).unwrap();
            b.extend(kind.to_le_bytes());
            b.extend(len.to_le_bytes());
            b.extend_from_slice(body);
            b.extend(len.to_le_bytes());
        };
        block(
            &mut b,
            0x0a0d_0d0a,
            &[0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        );
        block(&mut b, 0x0a, &[0x4b, 0x53, 0x4c, 0x54, 4, 0, 0, 0, b'x', b'x', b'x', b'x']);
        let r = report_for("s.pcapng", &b);
        assert_eq!(r.format["pcapng"]["blocks"]["decryption_secrets"], 1);
        assert!(r.security.risks.iter().any(|x| x.kind == "embedded_secret"));
    }

    crate::fixture_tests!("pcap", "pcapng", "btsnoop");
}
