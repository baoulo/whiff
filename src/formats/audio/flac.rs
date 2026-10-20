//! FLAC: STREAMINFO (sample rate, channels, bit depth, total samples, MD5 of
//! the audio), Vorbis comments, pictures, the cue sheet, seek table,
//! application blocks and padding. A leading ID3v2 tag is read too.
//!
//! Specification: RFC 9639 (Free Lossless Audio Codec).

use serde_json::{Value, json};

use super::{Stream, Tags, id3, round_s, vorbis};
use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
};

/// Extractor for FLAC.
pub struct Flac;

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.flac",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "flac",
        name: "FLAC audio",
        family: "audio",
        mimes: &["audio/flac", "audio/x-flac"],
        extensions: &["flac"],
        magic: &[Magic::prefix(b"fLaC")],
        parent: None,
    }],
};

/// Metadata blocks read.
const MAX_BLOCKS: usize = 1024;
/// Largest block read (pictures).
const MAX_BLOCK: u32 = 16 << 20;

impl Extractor for Flac {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let len = usize::try_from(id3::v2_len(probe.head)?).ok()?;
        (probe.head.get(len..len + 4)? == b"fLaC").then_some(Sniff { format: "flac", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut tags = Tags::default();
        let mut pos = match id3::read_v2(src, 0, cx, &mut tags)? {
            Some(info) => info.len,
            None => 0,
        };
        if src.read_vec(pos, 4).ok().as_deref() != Some(b"fLaC") {
            return Err(ExtractError::malformed("no fLaC marker"));
        }
        pos += 4;
        let mut stream = None;
        let mut blocks = Vec::new();
        let (mut padding, mut seek_points) = (0u64, 0u64);
        let mut applications = Vec::new();
        for _ in 0..MAX_BLOCKS {
            let Ok(h) = src.read_vec(pos, 4) else { break };
            let last = h[0] & 0x80 != 0;
            let kind = h[0] & 0x7f;
            let size = u32::from_be_bytes([0, h[1], h[2], h[3]]);
            let body_at = pos + 4;
            pos = body_at + u64::from(size);
            if pos > src.len() {
                cx.warn("metadata block runs past the end");
                break;
            }
            blocks.push(block_name(kind));
            match kind {
                0 => {
                    let d = src.read_vec(body_at, size.min(34) as usize)?;
                    if let Some((s, extra)) = streaminfo(&d) {
                        cx.format_set("streaminfo", extra);
                        stream = Some(s);
                    }
                }
                1 => padding += u64::from(size),
                2 => {
                    if let Ok(d) = src.read_vec(body_at, size.min(4) as usize) {
                        applications.push(String::from_utf8_lossy(&d).into_owned());
                    }
                }
                3 => seek_points += u64::from(size / 18),
                4..=6 if size <= MAX_BLOCK => {
                    let d = src.read_vec(body_at, size as usize)?;
                    match kind {
                        4 => vorbis::comments(&d, cx, &mut tags),
                        5 => cuesheet(&d, stream.as_ref().and_then(|s| s.sample_rate_hz), cx),
                        _ => {
                            if let Some(p) = vorbis::picture(&d) {
                                tags.pictures.push(p);
                            }
                        }
                    }
                }
                _ => {}
            }
            if last {
                break;
            }
        }
        cx.format_set("metadata_blocks", json!(blocks));
        if padding > 0 {
            cx.format_set("padding_bytes", padding);
        }
        if seek_points > 0 {
            cx.format_set("seek_points", seek_points);
        }
        if !applications.is_empty() {
            cx.format_set("applications", json!(applications));
        }
        let stream = stream.ok_or_else(|| ExtractError::malformed("no STREAMINFO block"))?;
        let mut stream = stream;
        if let Some(d) = stream.duration_s().filter(|d| *d > 0.0) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
            let audio = ((src.len().saturating_sub(pos)) as f64 * 8.0 / d).round() as u64;
            stream.bitrate_bps = Some(audio);
        }
        stream.report(cx, None, src.len());
        cx.format_set("audio_offset_bytes", pos);
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Flac);

fn block_name(kind: u8) -> &'static str {
    match kind {
        0 => "streaminfo",
        1 => "padding",
        2 => "application",
        3 => "seektable",
        4 => "vorbis_comment",
        5 => "cuesheet",
        6 => "picture",
        _ => "reserved",
    }
}

/// A STREAMINFO block: the stream and its block / frame sizes and MD5.
pub(crate) fn streaminfo(d: &[u8]) -> Option<(Stream, Value)> {
    let d = d.get(..34)?;
    let min_block = u16::from_be_bytes([d[0], d[1]]);
    let max_block = u16::from_be_bytes([d[2], d[3]]);
    let min_frame = u32::from_be_bytes([0, d[4], d[5], d[6]]);
    let max_frame = u32::from_be_bytes([0, d[7], d[8], d[9]]);
    let x = u64::from_be_bytes([d[10], d[11], d[12], d[13], d[14], d[15], d[16], d[17]]);
    let rate = u32::try_from(x >> 44).unwrap_or(0);
    let channels = u16::try_from(((x >> 41) & 7) + 1).unwrap_or(0);
    let bits = u16::try_from(((x >> 36) & 0x1f) + 1).unwrap_or(0);
    let samples = x & 0x000f_ffff_ffff;
    let md5 = super::hex(&d[18..34]);
    let mut s = Stream::new("flac");
    s.sample_rate_hz = Some(rate);
    s.channels = Some(channels);
    s.bits_per_sample = Some(bits);
    if samples > 0 {
        s.samples = Some(samples);
    }
    let extra = json!({
        "min_block_samples": min_block,
        "max_block_samples": max_block,
        "min_frame_bytes": min_frame,
        "max_frame_bytes": max_frame,
        "audio_md5": if md5.bytes().all(|b| b == b'0') { Value::Null } else { json!(md5) },
    });
    Some((s, extra))
}

/// A CUESHEET block: catalogue number and track start times.
fn cuesheet(d: &[u8], rate: Option<u32>, cx: &mut Context<'_>) {
    let mut r = ByteReader::new(d);
    let Ok(catalog) = r.bytes(128) else { return };
    let Ok(lead_in) = r.be_u64() else { return };
    let Ok(cd) = r.u8() else { return };
    if r.advance(258).is_err() {
        return;
    }
    let Ok(n) = r.u8() else { return };
    let mut tracks = Vec::new();
    for _ in 0..n {
        let (Ok(offset), Ok(number), Ok(isrc), Ok(flags)) = (r.be_u64(), r.u8(), r.bytes(12), r.u8()) else { break };
        if r.advance(13).is_err() {
            break;
        }
        let Ok(indices) = r.u8() else { break };
        if r.advance(usize::from(indices) * 12).is_err() {
            break;
        }
        if number == 170 || number == 255 {
            continue; // lead-out
        }
        let mut t = serde_json::Map::new();
        t.insert("number".into(), json!(number));
        if let Some(rate) = rate.filter(|r| *r > 0) {
            t.insert("start_s".into(), json!(round_s(offset as f64 / f64::from(rate))));
        }
        let isrc = String::from_utf8_lossy(isrc).trim_end_matches('\0').trim().to_string();
        if !isrc.is_empty() {
            t.insert("isrc".into(), json!(isrc));
        }
        t.insert("audio".into(), json!(flags & 0x80 == 0));
        tracks.push(Value::Object(t));
    }
    let catalog = String::from_utf8_lossy(catalog).trim_end_matches('\0').trim().to_string();
    cx.format_set(
        "cuesheet",
        json!({
            "catalog_number": if catalog.is_empty() { Value::Null } else { json!(catalog) },
            "compact_disc": cd & 0x80 != 0,
            "lead_in_samples": lead_in,
            "tracks": tracks,
        }),
    );
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("flac");
}
