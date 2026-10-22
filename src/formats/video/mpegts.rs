//! MPEG transport streams (broadcast `.ts`, HLS segments, Blu-ray / AVCHD
//! `.m2ts`): packet size, programs (PAT / PMT), DVB service and provider
//! names (SDT), each elementary stream (stream type, language, and its
//! codec details from the first PES payloads), scrambling, and the
//! duration from the first and last presentation time stamps.
//!
//! The first 8 MiB and the last 4 MiB are read; the rest of the media is
//! skipped.
//!
//! Specifications: ISO/IEC 13818-1 §2.4 (packets, PSI, descriptors), ETSI
//! EN 300 468 (SDT, DVB descriptors), ATSC A/53 and A/52 Annex A, the
//! Blu-ray BDAV transport stream (192-byte source packets).

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::pes::{self, Kind, Probed, Span};
use super::{Video, audio_map, finish, labels, other_map};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source};

/// Extractor for MPEG transport streams.
pub struct MpegTs;

static META: ExtractorMeta = ExtractorMeta {
    id: "video.mpegts",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "ts",
            name: "MPEG transport stream",
            family: "video",
            mimes: &["video/mp2t"],
            extensions: &["ts", "tsa", "mpegts", "trp"],
            // A first packet starting a table (PAT, SDT…) on a low PID; others
            // are found by the sniffer.
            magic: &[Magic::masked(0, b"\x47\x40\x00\x10", b"\xff\x5f\x00\x10")],
            parent: None,
        },
        FormatSpec {
            id: "m2ts",
            name: "BDAV MPEG-2 transport stream",
            family: "video",
            mimes: &["video/mp2t"],
            extensions: &["m2ts", "mts", "m2t"],
            magic: &[Magic::masked(4, b"\x47\x40\x00\x10", b"\xff\x5f\x00\x10")],
            parent: None,
        },
    ],
};

/// Bytes read from the start for the tables and the codec headers.
const HEAD_SCAN: u64 = 8 << 20;
/// Bytes read from the end for the last time stamps.
const TAIL_SCAN: u64 = 4 << 20;
/// Bytes kept per stream for codec probing.
const MAX_PROBE: usize = 512 << 10;
/// Elementary streams tracked.
const MAX_STREAMS: usize = 64;
const CHUNK: usize = 1 << 20;

/// Packet size and the offset of the sync byte in it.
fn layout(head: &[u8], len: u64) -> Option<(usize, usize)> {
    for (size, off) in [(188, 0), (192, 4), (204, 0)] {
        let n = head.len().saturating_sub(off) / size;
        let needed = if len <= (size * 4) as u64 { 1 } else { 4 };
        if n >= needed && (0..n.min(16)).all(|i| head[off + i * size] == 0x47) {
            return Some((size, off));
        }
    }
    None
}

impl Extractor for MpegTs {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let (size, _) = layout(probe.head, probe.len)?;
        Some(Sniff { format: if size == 192 { "m2ts" } else { "ts" }, confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (size, off) = layout(src.head(), src.len()).ok_or_else(|| ExtractError::malformed("no sync bytes"))?;
        let mut st = State { bdav: size == 192, ..State::default() };
        let len = src.len();
        let packets_per_chunk = CHUNK / size;
        let mut pos = 0u64;
        let head_end = len.min(HEAD_SCAN);
        while pos + size as u64 <= head_end {
            cx.checkpoint()?;
            let n = usize::try_from((head_end - pos) / size as u64).unwrap_or(0).min(packets_per_chunk);
            let buf = src.read_vec(pos, n * size)?;
            for p in buf.chunks_exact(size) {
                if let Some(pkt) = p.get(off..off + 188).filter(|p| p[0] == 0x47) {
                    st.packet(pkt, false);
                }
            }
            pos += (n * size) as u64;
            if st.complete() && pos >= 1 << 20 {
                break;
            }
        }
        let tail_start = pos.max(len.saturating_sub(TAIL_SCAN)) / size as u64 * size as u64;
        let mut t = tail_start;
        while t + size as u64 <= len {
            cx.checkpoint()?;
            let n = usize::try_from((len - t) / size as u64).unwrap_or(0).min(packets_per_chunk);
            let buf = src.read_vec(t, n * size)?;
            for p in buf.chunks_exact(size) {
                if let Some(pkt) = p.get(off..off + 188).filter(|p| p[0] == 0x47) {
                    st.packet(pkt, true);
                }
            }
            t += (n * size) as u64;
        }
        st.report(cx, size, len);
        Ok(())
    }
}

crate::register_extractor!(MpegTs);

#[derive(Default)]
struct Program {
    number: u16,
    pmt_pid: u16,
    pcr_pid: Option<u16>,
    parsed: bool,
    provider: Option<String>,
    service: Option<String>,
    service_type: Option<u8>,
}

struct Es {
    pid: u16,
    program: u16,
    stream_type: u8,
    kind: Option<Kind>,
    /// `video`, `audio`, `subtitle` or `data`, and the codec, for streams
    /// that are not probed.
    class: &'static str,
    codec: &'static str,
    language: Option<String>,
    buf: Vec<u8>,
    probed: Option<Probed>,
    span: Span,
    packets: u64,
    scrambled: bool,
}

#[derive(Default)]
struct State {
    bdav: bool,
    programs: Vec<Program>,
    streams: BTreeMap<u16, Es>,
    sections: BTreeMap<u16, Vec<u8>>,
    packets: u64,
    scrambled: u64,
    sdt: bool,
    transport_stream_id: Option<u16>,
}

impl State {
    /// Whether the head scan has what it needs.
    fn complete(&self) -> bool {
        !self.programs.is_empty()
            && self.programs.iter().all(|p| p.parsed)
            && self.streams.values().all(|e| (e.kind.is_none() || e.probed.is_some()) && e.span.first.is_some())
    }

    fn packet(&mut self, p: &[u8], tail: bool) {
        self.packets += 1;
        let pid = (u16::from(p[1] & 0x1f) << 8) | u16::from(p[2]);
        let pusi = p[1] & 0x40 != 0;
        let scrambling = p[3] >> 6;
        let afc = (p[3] >> 4) & 3;
        if afc & 1 == 0 {
            return;
        }
        let start = if afc & 2 != 0 { 5 + usize::from(p[4]) } else { 4 };
        let Some(payload) = p.get(start..) else { return };
        if let Some(e) = self.streams.get_mut(&pid) {
            e.packets += 1;
            if scrambling != 0 {
                e.scrambled = true;
                self.scrambled += 1;
                return;
            }
            if pusi {
                let Some(h) = pes::header(payload) else { return };
                if let Some(pts) = h.pts {
                    if !tail {
                        e.span.first(pts);
                    }
                    e.span.last(pts);
                }
                if tail || e.probed.is_some() || e.kind.is_none() {
                    return;
                }
                if e.buf.is_empty() {
                    e.buf.extend_from_slice(payload.get(h.payload..).unwrap_or_default());
                } else {
                    // A new packet: probe what the previous ones gathered.
                    e.try_probe(true);
                    if e.probed.is_none() && e.buf.len() < MAX_PROBE {
                        e.buf.extend_from_slice(payload.get(h.payload..).unwrap_or_default());
                    }
                }
            } else if !tail && e.probed.is_none() && e.kind.is_some() && !e.buf.is_empty() && e.buf.len() < MAX_PROBE {
                e.buf.extend_from_slice(payload);
                e.try_probe(false);
            }
            return;
        }
        if tail {
            return;
        }
        let is_pmt = self.programs.iter().any(|g| g.pmt_pid == pid && !g.parsed);
        if pid != 0 && pid != 0x11 && !is_pmt {
            return;
        }
        let Some(section) = self.section(pid, payload, pusi) else { return };
        match (pid, section[0]) {
            (0, 0) => self.pat(&section),
            (0x11, 0x42) if !self.sdt => self.sdt(&section),
            (_, 2) if is_pmt => self.pmt(&section),
            _ => {}
        }
    }

    /// Gather a PSI section across packets; the complete section when done.
    fn section(&mut self, pid: u16, payload: &[u8], pusi: bool) -> Option<Vec<u8>> {
        let buf = if pusi {
            let pointer = usize::from(*payload.first()?);
            let b = self.sections.entry(pid).or_default();
            *b = payload.get(1 + pointer..)?.to_vec();
            b
        } else {
            let b = self.sections.get_mut(&pid)?;
            b.extend_from_slice(payload);
            b
        };
        if buf.len() > 4096 + 188 {
            self.sections.remove(&pid);
            return None;
        }
        if buf.len() < 3 || buf[0] == 0xff {
            return None;
        }
        let need = 3 + ((usize::from(buf[1] & 0x0f) << 8) | usize::from(buf[2]));
        if buf.len() < need {
            return None;
        }
        let mut s = self.sections.remove(&pid)?;
        s.truncate(need);
        (need >= 12).then_some(s)
    }

    fn pat(&mut self, s: &[u8]) {
        if !self.programs.is_empty() {
            return;
        }
        self.transport_stream_id = Some(u16::from_be_bytes([s[3], s[4]]));
        for e in s[8..s.len() - 4].as_chunks::<4>().0.iter().take(64) {
            let number = u16::from_be_bytes([e[0], e[1]]);
            let pid = (u16::from(e[2] & 0x1f) << 8) | u16::from(e[3]);
            if number != 0 {
                self.programs.push(Program { number, pmt_pid: pid, ..Program::default() });
            }
        }
    }

    fn pmt(&mut self, s: &[u8]) {
        let number = u16::from_be_bytes([s[3], s[4]]);
        let pcr = (u16::from(s[8] & 0x1f) << 8) | u16::from(s[9]);
        let info = (usize::from(s[10] & 0x0f) << 8) | usize::from(s[11]);
        let end = s.len() - 4;
        let program_desc = s.get(12..12 + info).unwrap_or_default();
        let hdmv = self.bdav || registration(program_desc).as_deref() == Some("HDMV");
        let mut at = 12 + info;
        while at + 5 <= end && self.streams.len() < MAX_STREAMS {
            let stream_type = s[at];
            let pid = (u16::from(s[at + 1] & 0x1f) << 8) | u16::from(s[at + 2]);
            let n = (usize::from(s[at + 3] & 0x0f) << 8) | usize::from(s[at + 4]);
            let desc = s.get(at + 5..at + 5 + n).unwrap_or_default();
            at += 5 + n;
            let (kind, class, codec) = classify(stream_type, desc, hdmv);
            self.streams.entry(pid).or_insert(Es {
                pid,
                program: number,
                stream_type,
                kind,
                class,
                codec,
                language: language(desc),
                buf: Vec::new(),
                probed: None,
                span: Span::default(),
                packets: 0,
                scrambled: false,
            });
        }
        for p in self.programs.iter_mut().filter(|p| p.number == number) {
            p.parsed = true;
            p.pcr_pid = Some(pcr).filter(|p| *p != 0x1fff);
        }
    }

    fn sdt(&mut self, s: &[u8]) {
        self.sdt = true;
        let end = s.len() - 4;
        let mut at = 11;
        while at + 5 <= end {
            let id = u16::from_be_bytes([s[at], s[at + 1]]);
            let n = (usize::from(s[at + 3] & 0x0f) << 8) | usize::from(s[at + 4]);
            let desc = s.get(at + 5..at + 5 + n).unwrap_or_default();
            at += 5 + n;
            for (tag, d) in descriptors(desc) {
                if tag != 0x48 || d.len() < 2 {
                    continue;
                }
                let pl = usize::from(d[1]);
                let provider = d.get(2..2 + pl).map(dvb_text);
                let name = d.get(2 + pl).and_then(|&n| d.get(3 + pl..3 + pl + usize::from(n))).map(dvb_text);
                if let Some(p) = self.programs.iter_mut().find(|p| p.number == id) {
                    p.service_type = Some(d[0]);
                    p.provider = provider.filter(|t| !t.is_empty());
                    p.service = name.filter(|t| !t.is_empty());
                }
            }
        }
    }

    fn report(mut self, cx: &mut Context<'_>, size: usize, len: u64) {
        for e in self.streams.values_mut().filter(|e| e.probed.is_none() && !e.buf.is_empty()) {
            e.try_probe(true);
        }
        cx.format_set("packet_size", size);
        if let Some(id) = self.transport_stream_id {
            cx.format_set("transport_stream_id", id);
        }
        let programs: Vec<Value> = self
            .programs
            .iter()
            .map(|p| {
                let mut m = Map::new();
                m.insert("number".into(), json!(p.number));
                m.insert("pmt_pid".into(), json!(p.pmt_pid));
                if let Some(pcr) = p.pcr_pid {
                    m.insert("pcr_pid".into(), json!(pcr));
                }
                if let Some(s) = &p.service {
                    m.insert("service_name".into(), json!(s));
                }
                if let Some(s) = &p.provider {
                    m.insert("provider_name".into(), json!(s));
                }
                if let Some(t) = p.service_type {
                    m.insert("service_type".into(), json!(t));
                }
                let pids: Vec<u16> = self.streams.values().filter(|e| e.program == p.number).map(|e| e.pid).collect();
                m.insert("pids".into(), json!(pids));
                Value::Object(m)
            })
            .collect();
        cx.format_set("programs", Value::Array(programs));
        if self.scrambled > 0 {
            cx.format_set("scrambled_packets", self.scrambled);
            cx.security().encrypted(true);
        }
        if self.programs.is_empty() {
            cx.warn("no program association table");
        }
        let mut spans = Vec::new();
        let mut maps = Vec::new();
        for e in self.streams.values() {
            let mut frame = 0.0;
            let mut m = match &e.probed {
                Some(Probed::Video(v)) => {
                    frame = v.fps.filter(|f| *f > 0.0).map_or(0.0, |f| 1.0 / f);
                    let mut v = v.clone();
                    v.language.clone_from(&e.language);
                    v.encrypted = e.scrambled;
                    v.to_map()
                }
                Some(Probed::Audio(s, d)) => {
                    frame = *d;
                    let mut m = audio_map(s);
                    labels(&mut m, e.language.as_deref(), None, None, None);
                    m
                }
                None if e.class == "video" => {
                    let mut v = Video::new(e.codec);
                    v.language.clone_from(&e.language);
                    v.to_map()
                }
                None => {
                    let mut m = other_map(e.class, e.codec);
                    labels(&mut m, e.language.as_deref(), None, None, None);
                    m
                }
            };
            m.insert("pid".into(), json!(e.pid));
            m.insert("stream_type".into(), json!(format!("0x{:02x}", e.stream_type)));
            if matches!(e.class, "video" | "audio") {
                spans.push((e.span, frame));
            }
            maps.push(m);
        }
        let duration = pes::duration(&spans);
        finish(cx, maps, duration, len);
    }
}

impl Es {
    fn try_probe(&mut self, force: bool) {
        let Some(kind) = self.kind else { return };
        if !force && self.buf.len() % 4096 > 184 {
            return;
        }
        self.probed = pes::probe(kind, &self.buf);
        if self.probed.is_some() {
            self.buf = Vec::new();
        }
    }
}

fn descriptors(d: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut at = 0;
    std::iter::from_fn(move || {
        let tag = *d.get(at)?;
        let n = usize::from(*d.get(at + 1)?);
        let body = d.get(at + 2..at + 2 + n)?;
        at += 2 + n;
        Some((tag, body))
    })
}

fn registration(d: &[u8]) -> Option<String> {
    descriptors(d).find(|(t, b)| *t == 5 && b.len() >= 4).map(|(_, b)| String::from_utf8_lossy(&b[..4]).into_owned())
}

fn language(d: &[u8]) -> Option<String> {
    descriptors(d)
        .find(|(t, b)| *t == 0x0a && b.len() >= 3)
        .map(|(_, b)| String::from_utf8_lossy(&b[..3]).to_ascii_lowercase())
        .filter(|l| l.chars().all(|c| c.is_ascii_lowercase()))
}

/// A DVB string: an optional character-table prefix, then the text.
fn dvb_text(b: &[u8]) -> String {
    let b = match b.first() {
        Some(0x10) => b.get(3..).unwrap_or_default(),
        Some(&c) if c < 0x20 => &b[1..],
        _ => b,
    };
    let text = crate::plugin::latin1_or_utf8(b);
    text.chars().filter(|c| !c.is_control()).collect::<String>().trim().to_string()
}

/// The kind (when probed), class and codec of a stream type.
fn classify(stream_type: u8, desc: &[u8], hdmv: bool) -> (Option<Kind>, &'static str, &'static str) {
    let k = |kind: Kind| (Some(kind), if kind.is_video() { "video" } else { "audio" }, kind.codec());
    match stream_type {
        0x01 | 0x02 => k(Kind::MpegVideo),
        0x03 | 0x04 => k(Kind::MpegAudio),
        0x0f => k(Kind::Adts),
        0x11 => k(Kind::Latm),
        0x10 => k(Kind::Mpeg4Video),
        0x1b => k(Kind::H264),
        0x24 => k(Kind::Hevc),
        0x33 => k(Kind::Vvc),
        0x42 => k(Kind::Cavs),
        0xea => k(Kind::Vc1),
        0x81 => k(Kind::Ac3),
        0x87 => k(Kind::Eac3),
        0x80 if hdmv => k(Kind::BdLpcm),
        0x82 | 0x85 | 0x86 | 0xa2 if hdmv => k(Kind::Dts),
        0x83 if hdmv => k(Kind::TrueHd),
        0x84 | 0xa1 if hdmv => k(Kind::Eac3),
        0x90 if hdmv => (None, "subtitle", "hdmv_pgs_subtitle"),
        0x91 if hdmv => (None, "data", "hdmv_igs"),
        0x92 if hdmv => (None, "subtitle", "hdmv_text_subtitle"),
        0x86 => (None, "data", "scte_35"),
        0x15 => (None, "data", "timed_id3"),
        0x2d | 0x2e => (None, "audio", "mpegh_3d_audio"),
        0x05 | 0x0b..=0x0d => (None, "data", "private_sections"),
        0x06 => {
            for (tag, b) in descriptors(desc) {
                match tag {
                    0x6a => return k(Kind::Ac3),
                    0x7a => return k(Kind::Eac3),
                    0x7b => return k(Kind::Dts),
                    0x59 => return (None, "subtitle", "dvb_subtitle"),
                    0x56 | 0x46 => return (None, "subtitle", "dvb_teletext"),
                    0x05 if b.len() >= 4 => match &b[..4] {
                        b"AC-3" => return k(Kind::Ac3),
                        b"EAC3" => return k(Kind::Eac3),
                        b"DTS1" | b"DTS2" | b"DTS3" => return k(Kind::Dts),
                        b"Opus" => return k(Kind::Opus),
                        b"HEVC" => return k(Kind::Hevc),
                        b"KLVA" => return (None, "data", "klv"),
                        b"ID3 " => return (None, "data", "timed_id3"),
                        b"BSSD" => return (None, "audio", "s302m"),
                        _ => {}
                    },
                    _ => {}
                }
            }
            (None, "data", "private")
        }
        _ => (None, "data", "unknown"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("ts", "m2ts");

    #[test]
    fn layouts_and_descriptors() {
        let mut ts = vec![0u8; 188 * 5];
        for i in 0..5 {
            ts[i * 188] = 0x47;
        }
        assert_eq!(layout(&ts, ts.len() as u64), Some((188, 0)));
        assert_eq!(layout(&ts[1..], 939), None);
        let desc = [0x0a, 4, b'D', b'E', b'U', 0, 0x05, 4, b'A', b'C', b'-', b'3'];
        assert_eq!(language(&desc).as_deref(), Some("deu"));
        assert_eq!(classify(0x06, &desc, false).2, "ac3");
        assert_eq!(classify(0x90, &[], true).1, "subtitle");
        assert_eq!(dvb_text(b"\x15Saltmere One"), "Saltmere One");
    }
}
