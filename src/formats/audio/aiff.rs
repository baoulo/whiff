//! AIFF and AIFF-C: the `COMM` chunk (channels, sample frames, bit depth,
//! 80-bit sample rate, compression type), the sound data size, the text
//! chunks (`NAME`, `AUTH`, `(c) `, `ANNO`, `COMT`), markers, an `ID3 `
//! chunk and XMP (`APPL` / `XMP `).
//!
//! Specifications: Apple Audio Interchange File Format 1.3 and AIFF-C
//! (draft of 1991-08-26).

use serde_json::json;

use super::{Stream, Tags, extended, id3};
use crate::plugin::{
    BlockKind, ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source,
};

/// Extractor for AIFF and AIFF-C.
pub struct Aiff;

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.aiff",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "aiff",
        name: "AIFF audio",
        family: "audio",
        mimes: &["audio/aiff", "audio/x-aiff"],
        extensions: &["aif", "aiff", "aifc", "aiffc"],
        magic: &[
            Magic::masked(0, b"FORM\0\0\0\0AIFF", b"\xff\xff\xff\xff\0\0\0\0\xff\xff\xff\xff"),
            Magic::masked(0, b"FORM\0\0\0\0AIFC", b"\xff\xff\xff\xff\0\0\0\0\xff\xff\xff\xff"),
        ],
        parent: None,
    }],
};

/// Chunks walked.
const MAX_CHUNKS: usize = 10_000;
/// Largest metadata chunk read.
const MAX_META: u32 = 16 << 20;

impl Extractor for Aiff {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // one arm per chunk type
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.read_vec(0, 12)?;
        let aifc = &head[8..12] == b"AIFC";
        cx.format_set("variant", if aifc { "aifc" } else { "aiff" });
        let mut pos = 12u64;
        let mut tags = Tags::default();
        let mut stream = None;
        let mut chunks = Vec::new();
        let (mut sound_bytes, mut markers) = (None, 0u16);
        for n in 0..MAX_CHUNKS {
            if n % 256 == 0 {
                cx.checkpoint()?;
            }
            let Ok(h) = src.read_vec(pos, 8) else { break };
            let id = String::from_utf8_lossy(&h[..4]).into_owned();
            let size = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
            let body = pos + 8;
            if chunks.len() < 64 {
                chunks.push(id.clone());
            }
            let avail = src.len().saturating_sub(body);
            if u64::from(size) > avail {
                if id == "SSND" {
                    sound_bytes = Some(avail.saturating_sub(8));
                }
                cx.warn(format!("{id} chunk runs past the end"));
                break;
            }
            let read = |src: &mut dyn Source| -> Result<Option<Vec<u8>>, ExtractError> {
                if size > MAX_META {
                    return Ok(None);
                }
                Ok(Some(src.read_vec(body, size as usize)?))
            };
            match id.as_str() {
                "COMM" => {
                    if let Some(d) = read(src)? {
                        stream = comm(&d, aifc, cx);
                    }
                }
                "SSND" => sound_bytes = Some(u64::from(size).saturating_sub(8)),
                "NAME" | "AUTH" | "(c) " | "ANNO" => {
                    if let Some(d) = read(src)? {
                        let text = super::text(&d);
                        let key = match id.as_str() {
                            "NAME" => "title",
                            "AUTH" => "artist",
                            "(c) " => "copyright",
                            _ => "comment",
                        };
                        tags.system("aiff_text");
                        tags.set(key, &text, "aiff");
                        cx.metadata_set("aiff", id.trim(), text);
                    }
                }
                "COMT" => {
                    if let Some(d) = read(src)? {
                        comments(&d, cx, &mut tags);
                    }
                }
                "MARK" => {
                    if let Some(d) = read(src)?
                        && d.len() >= 2
                    {
                        markers = u16::from_be_bytes([d[0], d[1]]);
                    }
                }
                "ID3 " | "id3 " => {
                    if let Some(d) = read(src)? {
                        id3::parse_bytes(&d, cx, &mut tags);
                    }
                }
                "APPL" => {
                    if let Some(d) = read(src)?
                        && d.starts_with(b"XMP ")
                    {
                        cx.emit_block(BlockKind::XMP, d[4..].to_vec());
                    }
                }
                "XMP " => {
                    if let Some(d) = read(src)? {
                        cx.emit_block(BlockKind::XMP, d);
                    }
                }
                _ => {}
            }
            pos = body + u64::from(size) + u64::from(size % 2);
            if pos >= src.len() {
                break;
            }
        }
        cx.format_set("chunks", json!(chunks));
        if markers > 0 {
            cx.format_set("markers", markers);
        }
        let mut stream = stream.ok_or_else(|| ExtractError::malformed("no COMM chunk"))?;
        if let (Some(b), Some(d)) = (sound_bytes, stream.duration_s().filter(|d| *d > 0.0)) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
            let rate = (b as f64 * 8.0 / d).round() as u64;
            stream.bitrate_bps = Some(rate);
            cx.format_set("sound_bytes", b);
        }
        stream.report(cx, None, src.len());
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Aiff);

fn comm(d: &[u8], aifc: bool, cx: &mut Context<'_>) -> Option<Stream> {
    let mut r = ByteReader::new(d);
    let channels = r.be_u16().ok()?;
    let frames = r.be_u32().ok()?;
    let bits = r.be_u16().ok()?;
    let rate = extended(&r.array::<10>().ok()?);
    let (codec, name) = if aifc {
        let kind = r.array::<4>().ok()?;
        let name = r.u8().ok().and_then(|n| r.bytes(usize::from(n)).ok()).map(super::text).unwrap_or_default();
        (compression(kind), name)
    } else {
        ("pcm".to_string(), String::new())
    };
    if !name.is_empty() {
        cx.format_set("compression_name", name);
    }
    let mut s = Stream::new(codec);
    s.channels = Some(channels);
    s.bits_per_sample = Some(bits);
    s.sample_rate_hz = super::whole_u32(rate);
    s.samples = Some(u64::from(frames));
    // Compressed AIFF-C counts sample frames of the decoded audio; ima4
    // packets hold 64 frames each.
    if s.codec == "ima_adpcm" {
        s.samples = Some(u64::from(frames) * 64);
        s.bits_per_sample = None;
    }
    Some(s)
}

fn compression(kind: [u8; 4]) -> String {
    match &kind {
        b"NONE" | b"twos" => "pcm",
        b"sowt" => "pcm_le",
        b"fl32" | b"FL32" | b"fl64" | b"FL64" => "pcm_float",
        b"ulaw" | b"ULAW" => "mulaw",
        b"alaw" | b"ALAW" => "alaw",
        b"ima4" => "ima_adpcm",
        b"MAC3" => "mace3",
        b"MAC6" => "mace6",
        b"GSM " | b"agsm" => "gsm",
        b"QDM2" => "qdesign2",
        b"QDMC" => "qdesign",
        b"Qclp" => "qcelp",
        _ => return format!("aifc_{}", String::from_utf8_lossy(&kind).trim()),
    }
    .to_string()
}

/// `COMT`: timestamped comments.
fn comments(d: &[u8], cx: &mut Context<'_>, tags: &mut Tags) {
    let mut r = ByteReader::new(d);
    let Ok(n) = r.be_u16() else { return };
    let mut list = Vec::new();
    for _ in 0..n.min(256) {
        let (Ok(_time), Ok(_marker), Ok(len)) = (r.be_u32(), r.be_u16(), r.be_u16()) else { break };
        let Ok(text) = r.bytes(usize::from(len)) else { break };
        if len % 2 == 1 {
            let _ = r.advance(1);
        }
        let text = super::text(text);
        tags.set("comment", &text, "aiff");
        list.push(text);
    }
    if !list.is_empty() {
        cx.metadata_set("aiff", "COMT", json!(list));
    }
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("aiff");
}
