//! Direct Stream Digital: Sony DSF (format chunk, sample count, the ID3v2
//! tag the metadata pointer leads to) and Philips DSDIFF / DFF (sample rate,
//! channels, compression — plain DSD or DST — sound data size, edited
//! master title / artist, comments, and an `ID3 ` chunk).
//!
//! Specifications: Sony DSF File Format Specification 1.01; Philips
//! DSDIFF 1.5.

use serde_json::json;

use super::{Stream, Tags, id3};
use crate::plugin::{ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for DSF and DSDIFF.
pub struct Dsd;

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.dsd",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "dsf",
            name: "DSD Stream File",
            family: "audio",
            mimes: &["audio/dsf", "audio/x-dsf"],
            extensions: &["dsf"],
            magic: &[Magic::prefix(b"DSD \x1c\0\0\0\0\0\0\0")],
            parent: None,
        },
        FormatSpec {
            id: "dff",
            name: "DSDIFF audio",
            family: "audio",
            mimes: &["audio/dff", "audio/x-dff"],
            extensions: &["dff"],
            magic: &[Magic::masked(
                0,
                b"FRM8\0\0\0\0\0\0\0\0DSD ",
                b"\xff\xff\xff\xff\0\0\0\0\0\0\0\0\xff\xff\xff\xff",
            )],
            parent: None,
        },
    ],
};

/// DSDIFF chunks walked (top level and inside `PROP` / `DIIN`).
const MAX_CHUNKS: usize = 4096;
/// Largest metadata chunk read.
const MAX_META: u64 = 16 << 20;

impl Extractor for Dsd {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut tags = Tags::default();
        if src.head().starts_with(b"DSD ") {
            dsf(src, cx, &mut tags)?;
        } else {
            dff(src, cx, &mut tags)?;
        }
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Dsd);

fn channel_layout(kind: u32) -> Option<&'static str> {
    Some(match kind {
        1 => "mono",
        2 => "stereo",
        3 => "3.0",
        4 => "quad",
        5 => "4.0",
        6 => "5.0",
        7 => "5.1",
        _ => return None,
    })
}

fn dsf(src: &mut dyn Source, cx: &mut Context<'_>, tags: &mut Tags) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 28 + 52)?;
    let mut r = ByteReader::new(&h);
    r.advance(4)?;
    let (_chunk, _total, metadata) = (r.le_u64()?, r.le_u64()?, r.le_u64()?);
    r.tag(b"fmt ")?;
    let (_size, version, format, kind, channels, rate, bits, samples, block) = (
        r.le_u64()?,
        r.le_u32()?,
        r.le_u32()?,
        r.le_u32()?,
        r.le_u32()?,
        r.le_u32()?,
        r.le_u32()?,
        r.le_u64()?,
        r.le_u32()?,
    );
    let mut s = Stream::new(if format == 0 { "dsd" } else { "dsd_other" });
    s.sample_rate_hz = Some(rate);
    s.channels = u16::try_from(channels).ok();
    s.channel_layout = channel_layout(kind).map(str::to_string);
    s.bits_per_sample = u16::try_from(bits).ok();
    s.samples = Some(samples);
    s.bitrate_bps = Some(u64::from(rate) * u64::from(channels));
    cx.format_set("format_version", version);
    cx.format_set("block_bytes_per_channel", block);
    cx.format_set("dsd_rate", dsd_rate(rate));
    if metadata > 0 && metadata < src.len() {
        id3::read_v2(src, metadata, cx, tags)?;
    }
    s.report(cx, None, src.len());
    Ok(())
}

/// DSD64, DSD128… from the sample rate (multiples of 44.1 kHz × 64).
fn dsd_rate(rate: u32) -> String {
    let base = if rate.is_multiple_of(44_100) { 44_100 } else { 48_000 };
    format!("DSD{}", rate / base)
}

fn dff(src: &mut dyn Source, cx: &mut Context<'_>, tags: &mut Tags) -> Result<(), ExtractError> {
    let mut s = Stream::new("dsd");
    let mut pos = 16u64;
    let mut sound_bytes = None;
    let mut dst_frames = None;
    let mut chunks = Vec::new();
    for _ in 0..MAX_CHUNKS {
        let Ok(h) = src.read_vec(pos, 12) else { break };
        let id = String::from_utf8_lossy(&h[..4]).into_owned();
        let size = u64::from_be_bytes(h[4..12].try_into().unwrap_or_default());
        let body = pos + 12;
        if chunks.len() < 64 {
            chunks.push(id.clone());
        }
        if size > src.len().saturating_sub(body) {
            if id == "DSD " {
                sound_bytes = Some(src.len().saturating_sub(body));
            }
            break;
        }
        let small = size <= MAX_META;
        match id.as_str() {
            "FVER" if size >= 4 => {
                let v = src.read_vec(body, 4)?;
                cx.format_set("format_version", format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3]));
            }
            "PROP" if small => {
                let d = src.read_vec(body, usize::try_from(size).unwrap_or(0))?;
                prop(&d, &mut s, cx);
            }
            "DSD " => sound_bytes = Some(size),
            "DST " if small => {
                // The DST frame information chunk comes first.
                let d = src.read_vec(body, usize::try_from(size.min(64)).unwrap_or(0))?;
                if d.starts_with(b"FRTE") && d.len() >= 18 {
                    let frames = u32::from_be_bytes([d[12], d[13], d[14], d[15]]);
                    let rate = u16::from_be_bytes([d[16], d[17]]);
                    dst_frames = Some((frames, rate));
                }
                s.codec = "dst".into();
            }
            "DST " => s.codec = "dst".into(),
            "DIIN" if small => {
                let d = src.read_vec(body, usize::try_from(size).unwrap_or(0))?;
                diin(&d, cx, tags);
            }
            "COMT" if small => {
                let d = src.read_vec(body, usize::try_from(size).unwrap_or(0))?;
                comments(&d, tags);
            }
            "ID3 " if small => {
                let d = src.read_vec(body, usize::try_from(size).unwrap_or(0))?;
                id3::parse_bytes(&d, cx, tags);
            }
            _ => {}
        }
        pos = body + size + size % 2;
        if pos >= src.len() {
            break;
        }
    }
    cx.format_set("chunks", json!(chunks));
    let channels = u64::from(s.channels.unwrap_or(0));
    if let (Some(b), true, "dsd") = (sound_bytes, channels > 0, s.codec.as_str()) {
        s.samples = Some(b * 8 / channels);
    }
    let duration = dst_frames.filter(|(_, r)| *r > 0).map(|(f, r)| f64::from(f) / f64::from(r));
    if let Some(rate) = s.sample_rate_hz {
        s.bitrate_bps = Some(u64::from(rate) * channels);
        cx.format_set("dsd_rate", dsd_rate(rate));
    }
    s.report(cx, duration, src.len());
    Ok(())
}

fn sub_chunks(d: &[u8]) -> impl Iterator<Item = ([u8; 4], &[u8])> {
    let mut r = ByteReader::new(d);
    std::iter::from_fn(move || {
        let id = r.array::<4>().ok()?;
        let size = usize::try_from(r.be_u64().ok()?).ok()?;
        let body = r.bytes(size).ok()?;
        if size % 2 == 1 {
            let _ = r.advance(1);
        }
        Some((id, body))
    })
    .take(MAX_CHUNKS)
}

fn prop(d: &[u8], s: &mut Stream, cx: &mut Context<'_>) {
    if !d.starts_with(b"SND ") {
        return;
    }
    for (id, body) in sub_chunks(&d[4..]) {
        match &id {
            b"FS  " if body.len() >= 4 => {
                s.sample_rate_hz = Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
            }
            b"CHNL" if body.len() >= 2 => {
                let n = u16::from_be_bytes([body[0], body[1]]);
                s.channels = Some(n);
                let ids: Vec<String> = body[2..]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .take(usize::from(n))
                    .map(|c| String::from_utf8_lossy(c).trim().to_string())
                    .collect();
                cx.format_set("channel_ids", json!(ids));
            }
            b"CMPR" if body.len() >= 4 => {
                let kind = &body[..4];
                s.codec = if kind == b"DST " { "dst".into() } else { "dsd".into() };
                if let Some(&n) = body.get(4) {
                    let name = body.get(5..5 + usize::from(n)).map(super::text).unwrap_or_default();
                    if !name.is_empty() {
                        cx.format_set("compression_name", name);
                    }
                }
            }
            b"LSCO" if body.len() >= 2 => cx.format_set("loudspeaker_config", u16::from_be_bytes([body[0], body[1]])),
            _ => {}
        }
    }
}

/// Edited master information: title (`DITI`) and artist (`DIAR`).
fn diin(d: &[u8], cx: &mut Context<'_>, tags: &mut Tags) {
    for (id, body) in sub_chunks(d) {
        let key = match &id {
            b"DITI" => "title",
            b"DIAR" => "artist",
            b"EMID" => {
                cx.format_set("edited_master_id", super::text(body));
                continue;
            }
            _ => continue,
        };
        let mut r = ByteReader::new(body);
        let Ok(n) = r.be_u32() else { continue };
        let Ok(text) = r.bytes(n as usize) else { continue };
        let text = super::text(text);
        tags.system("dsdiff");
        tags.set(key, &text, "dsdiff");
        cx.metadata_set("dsdiff", &String::from_utf8_lossy(&id), text);
    }
}

fn comments(d: &[u8], tags: &mut Tags) {
    let mut r = ByteReader::new(d);
    let Ok(n) = r.be_u16() else { return };
    for _ in 0..n.min(256) {
        // time stamp (6 bytes), type, reference, length, text
        if r.advance(6).is_err() {
            break;
        }
        let (Ok(_kind), Ok(_reference), Ok(len)) = (r.be_u16(), r.be_u16(), r.be_u32()) else { break };
        let Ok(text) = r.bytes(len as usize) else { break };
        if len % 2 == 1 {
            let _ = r.advance(1);
        }
        tags.set("comment", &super::text(text), "dsdiff");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("dsf", "dff");

    #[test]
    fn rates() {
        assert_eq!(dsd_rate(2_822_400), "DSD64");
        assert_eq!(dsd_rate(5_644_800), "DSD128");
        assert_eq!(dsd_rate(3_072_000), "DSD64");
    }
}
