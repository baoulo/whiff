//! Apple Core Audio Format (CAF): the audio description (`desc`), the
//! packet table (`pakt`: valid frames, priming and remainder), the data
//! size, the channel layout (`chan`), `info` strings and markers.
//!
//! Specification: Apple Core Audio Format Specification 1.0.

use serde_json::json;

use super::{Stream, Tags, mask_layout, whole_u32};
use crate::plugin::{ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for CAF.
pub struct Caf;

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.caf",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "caf",
        name: "Core Audio Format",
        family: "audio",
        mimes: &["audio/x-caf"],
        extensions: &["caf", "caff"],
        magic: &[Magic::prefix(b"caff\0\x01")],
        parent: None,
    }],
};

/// Chunks walked.
const MAX_CHUNKS: usize = 10_000;
/// Largest metadata chunk read.
const MAX_META: u64 = 16 << 20;

impl Extractor for Caf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let mut pos = 8u64;
        let mut tags = Tags::default();
        let mut desc = None;
        let (mut data_bytes, mut valid_frames, mut packets) = (None, None, None);
        let mut chunks = Vec::new();
        for n in 0..MAX_CHUNKS {
            if n % 256 == 0 {
                cx.checkpoint()?;
            }
            let Ok(h) = src.read_vec(pos, 12) else { break };
            let id = String::from_utf8_lossy(&h[..4]).into_owned();
            let size = i64::from_be_bytes(h[4..12].try_into().unwrap_or_default());
            let body = pos + 12;
            let avail = len.saturating_sub(body);
            // Size -1: the data chunk runs to the end of the file.
            let size = if size == -1 && id == "data" { avail } else { u64::try_from(size).unwrap_or(u64::MAX) };
            if chunks.len() < 64 {
                chunks.push(id.clone());
            }
            if size > avail {
                cx.warn(format!("{id} chunk runs past the end"));
                if id == "data" {
                    data_bytes = Some(avail.saturating_sub(4));
                }
                break;
            }
            let small = size <= MAX_META;
            match id.as_str() {
                "desc" if small => desc = Some(src.read_vec(body, usize::try_from(size).unwrap_or(0))?),
                "data" => data_bytes = Some(size.saturating_sub(4)),
                "pakt" if size >= 24 => {
                    let d = src.read_vec(body, 24)?;
                    let mut r = ByteReader::new(&d);
                    let (np, nv) = (r.be_u64().unwrap_or(0), r.be_u64().unwrap_or(0));
                    let (priming, remainder) = (r.be_i32().unwrap_or(0), r.be_i32().unwrap_or(0));
                    packets = Some(np);
                    valid_frames = Some(nv);
                    cx.format_set(
                        "packet_table",
                        json!({ "packets": np, "valid_frames": nv, "priming_frames": priming, "remainder_frames": remainder }),
                    );
                }
                "info" if small => {
                    let d = src.read_vec(body, usize::try_from(size).unwrap_or(0))?;
                    info(&d, cx, &mut tags);
                }
                "chan" if size >= 12 => {
                    let d = src.read_vec(body, 12)?;
                    let tag = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
                    let bitmap = u32::from_be_bytes([d[4], d[5], d[6], d[7]]);
                    cx.format_set("channel_layout_tag", tag);
                    if tag == 0x0001_0000
                        && let Some(l) = mask_layout(bitmap)
                    {
                        cx.format_set("channel_layout", l);
                    }
                }
                _ => {}
            }
            pos = body.saturating_add(size);
            if pos >= len {
                break;
            }
        }
        cx.format_set("chunks", json!(chunks));
        let d = desc.ok_or_else(|| ExtractError::malformed("no desc chunk"))?;
        let mut r = ByteReader::new(&d);
        let rate = f64::from_bits(r.be_u64()?);
        let format = r.array::<4>()?;
        let (flags, bytes_per_packet, frames_per_packet, channels, bits) =
            (r.be_u32()?, r.be_u32()?, r.be_u32()?, r.be_u32()?, r.be_u32()?);
        let mut s = Stream::new(codec(format, flags));
        s.sample_rate_hz = whole_u32(rate);
        s.channels = u16::try_from(channels).ok();
        s.bits_per_sample = u16::try_from(bits).ok().filter(|b| *b > 0);
        cx.format_set("format_id", String::from_utf8_lossy(&format).trim().to_string());
        cx.format_set("bytes_per_packet", bytes_per_packet);
        cx.format_set("frames_per_packet", frames_per_packet);
        s.samples = valid_frames.or_else(|| {
            let total = match (bytes_per_packet, packets, data_bytes) {
                (_, Some(p), _) => p,
                (b, None, Some(d)) if b > 0 => d / u64::from(b),
                _ => return None,
            };
            Some(total * u64::from(frames_per_packet.max(1)))
        });
        if let (Some(b), Some(dur)) = (data_bytes, s.duration_s().filter(|d| *d > 0.0)) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
            let br = (b as f64 * 8.0 / dur).round() as u64;
            s.bitrate_bps = Some(br);
        }
        s.report(cx, None, len);
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Caf);

fn codec(format: [u8; 4], flags: u32) -> String {
    match &format {
        b"lpcm" => {
            if flags & 1 != 0 {
                "pcm_float"
            } else {
                "pcm"
            }
        }
        b"aac " => "aac",
        b"aach" => "he_aac",
        b"aacp" => "he_aac_v2",
        b"aacl" => "aac_ld",
        b"aace" => "aac_eld",
        b"alac" => "alac",
        b"flac" => "flac",
        b"opus" => "opus",
        b".mp3" => "mp3",
        b".mp2" => "mp2",
        b".mp1" => "mp1",
        b"ima4" => "ima_adpcm",
        b"ulaw" => "mulaw",
        b"alaw" => "alaw",
        b"ac-3" => "ac3",
        b"ec-3" => "eac3",
        b"samr" => "amr_nb",
        b"sawb" => "amr_wb",
        b"ilbc" => "ilbc",
        b"MAC3" => "mace3",
        b"MAC6" => "mace6",
        b"QDM2" => "qdesign2",
        b"apac" => "apac",
        _ => return format!("caf_{}", String::from_utf8_lossy(&format).trim()),
    }
    .to_string()
}

/// `info`: a count, then key / value C strings.
fn info(d: &[u8], cx: &mut Context<'_>, tags: &mut Tags) {
    let mut r = ByteReader::new(d);
    let Ok(n) = r.be_u32() else { return };
    tags.system("caf_info");
    for _ in 0..n.min(1000) {
        let (Ok(k), Ok(v)) = (r.cstr(), r.cstr()) else { break };
        let (k, v) = (String::from_utf8_lossy(k).into_owned(), String::from_utf8_lossy(v).into_owned());
        let key = match k.to_ascii_lowercase().as_str() {
            "title" => Some("title"),
            "artist" => Some("artist"),
            "album" => Some("album"),
            "track number" => Some("track"),
            "year" | "recorded date" => Some("date"),
            "genre" => Some("genre"),
            "composer" => Some("composer"),
            "lyricist" => Some("lyricist"),
            "comments" => Some("comment"),
            "copyright" => Some("copyright"),
            "encoding application" => Some("encoder"),
            "tempo" => Some("bpm"),
            "key signature" => Some("key"),
            // ffmpeg writes its own lower-case keys (date, track, comment…).
            other => super::freeform_key(other),
        };
        if let Some(key) = key {
            tags.set(key, &v, "caf");
        }
        cx.metadata_set("caf_info", &k, v);
    }
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("caf");
}
