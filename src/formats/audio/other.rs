//! Smaller audio formats with simple headers: ADTS AAC (frames walked for
//! the duration), Sun / `NeXT` AU, AMR-NB / AMR-WB (frames counted), Creative
//! Voice (VOC blocks) and True Audio (TTA), with their ID3 / APE tags.
//!
//! Specifications: ISO/IEC 14496-3 §1.A.2 (ADTS); the Sun / `NeXT` audio file
//! header; RFC 4867 §5 (AMR storage format); the Creative Voice File format;
//! the TTA1 format description (tausoft.org).

use super::{Stream, Tags, apetag, id3};
use crate::plugin::mp4::aac_profile;
use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
};

/// Extractor for ADTS, AU, AMR, VOC and TTA.
pub struct OtherAudio;

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.other",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "aac",
            name: "AAC audio (ADTS)",
            family: "audio",
            mimes: &["audio/aac", "audio/aacp"],
            extensions: &["aac", "adts"],
            magic: &[Magic::masked(0, b"\xff\xf0", b"\xff\xf6")],
            parent: None,
        },
        FormatSpec {
            id: "au",
            name: "Sun / NeXT audio",
            family: "audio",
            mimes: &["audio/basic"],
            extensions: &["au", "snd"],
            magic: &[Magic::prefix(b".snd")],
            parent: None,
        },
        FormatSpec {
            id: "amr",
            name: "AMR audio",
            family: "audio",
            mimes: &["audio/amr", "audio/amr-wb"],
            extensions: &["amr", "awb"],
            magic: &[Magic::prefix(b"#!AMR")],
            parent: None,
        },
        FormatSpec {
            id: "voc",
            name: "Creative Voice audio",
            family: "audio",
            mimes: &["audio/x-voc"],
            extensions: &["voc"],
            magic: &[Magic::prefix(b"Creative Voice File\x1a")],
            parent: None,
        },
        FormatSpec {
            id: "tta",
            name: "True Audio",
            family: "audio",
            mimes: &["audio/x-tta"],
            extensions: &["tta"],
            magic: &[Magic::prefix(b"TTA1")],
            parent: None,
        },
    ],
};

/// Bytes walked frame by frame (ADTS, AMR); the rest is estimated.
const MAX_SCAN: u64 = 64 << 20;
/// VOC blocks walked.
const MAX_BLOCKS: usize = 100_000;

impl Extractor for OtherAudio {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // ADTS or TTA after an ID3v2 tag.
        let len = usize::try_from(id3::v2_len(probe.head)?).ok()?;
        let after = probe.head.get(len..len + 4)?;
        if after[0] == 0xff && after[1] & 0xf6 == 0xf0 {
            Some(Sniff { format: "aac", confidence: 0.95 })
        } else if after == b"TTA1" {
            Some(Sniff { format: "tta", confidence: 0.95 })
        } else {
            None
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut tags = Tags::default();
        match cx.format_id() {
            "aac" => adts(src, cx, &mut tags)?,
            "au" => au(src, cx, &mut tags)?,
            "amr" => amr(src, cx)?,
            "voc" => voc(src, cx)?,
            _ => tta(src, cx, &mut tags)?,
        }
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(OtherAudio);

/// Tags at both ends: a leading ID3v2, a trailing ID3v1 and APE tag.
/// Returns (audio start, audio end).
fn edge_tags(src: &mut dyn Source, cx: &mut Context<'_>, tags: &mut Tags) -> Result<(u64, u64), ExtractError> {
    let start = id3::read_v2(src, 0, cx, tags)?.map_or(0, |i| i.len);
    let tail = src.tail().to_vec();
    let v1 = id3::read_v1(&tail, cx, tags);
    let ape = apetag::read(src, v1, cx, tags)?;
    Ok((start, src.len() - v1 - ape))
}

const ADTS_RATES: [u32; 13] = [96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350];

fn adts(src: &mut dyn Source, cx: &mut Context<'_>, tags: &mut Tags) -> Result<(), ExtractError> {
    let (start, end) = edge_tags(src, cx, tags)?;
    let h = src.read_vec(start, 7)?;
    if h[0] != 0xff || h[1] & 0xf6 != 0xf0 {
        return Err(ExtractError::malformed("no ADTS frame"));
    }
    let object = (h[2] >> 6) + 1;
    let rate = ADTS_RATES.get(usize::from((h[2] >> 2) & 0xf)).copied();
    let channels = u16::from(((h[2] & 1) << 2) | (h[3] >> 6));
    let mpeg2 = h[1] & 8 != 0;
    // Walk the frames: 13-bit length, raw data blocks per frame.
    let (mut frames, mut blocks, mut pos) = (0u64, 0u64, start);
    let limit = end.min(start.saturating_add(MAX_SCAN));
    let mut buf = Vec::new();
    let mut buf_at = start;
    while pos + 7 <= limit {
        if pos + 7 > buf_at + buf.len() as u64 {
            cx.checkpoint()?;
            buf_at = pos;
            buf = src.read_vec(pos, usize::try_from((end - pos).min(1 << 20)).unwrap_or(0))?;
        }
        let o = usize::try_from(pos - buf_at).unwrap_or(0);
        let f = &buf[o..o + 7];
        if f[0] != 0xff || f[1] & 0xf6 != 0xf0 {
            break;
        }
        let len = (u64::from(f[3] & 3) << 11) | (u64::from(f[4]) << 3) | u64::from(f[5] >> 5);
        if len < 7 {
            break;
        }
        frames += 1;
        blocks += u64::from(f[6] & 3) + 1;
        pos += len;
    }
    if limit < end && pos > start {
        // Estimate the rest from the average frame size.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
        let estimate = (blocks as f64 * (end - start) as f64 / (pos - start) as f64).round() as u64;
        blocks = estimate;
        cx.warn("frame count estimated beyond the scanned part");
    }
    let mut s = Stream::new("aac");
    s.profile = Some(aac_profile(object).to_string());
    s.sample_rate_hz = rate;
    s.channels = Some(channels).filter(|c| *c > 0);
    s.samples = Some(blocks * 1024);
    if let Some(d) = s.duration_s().filter(|d| *d > 0.0) {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
        let br = ((end - start) as f64 * 8.0 / d).round() as u64;
        s.bitrate_bps = Some(br);
    }
    cx.format_set("mpeg_version", if mpeg2 { 2 } else { 4 });
    cx.format_set("frames", frames);
    cx.format_set("crc_protected", h[1] & 1 == 0);
    s.report(cx, None, src.len());
    Ok(())
}

fn au(src: &mut dyn Source, cx: &mut Context<'_>, tags: &mut Tags) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 24)?;
    let mut r = ByteReader::new(&h[4..]);
    let (offset, size, encoding, rate, channels) = (r.be_u32()?, r.be_u32()?, r.be_u32()?, r.be_u32()?, r.be_u32()?);
    let (codec, bits): (&str, u16) = match encoding {
        1 => ("mulaw", 8),
        2 => ("pcm", 8),
        3 => ("pcm", 16),
        4 => ("pcm", 24),
        5 => ("pcm", 32),
        6 => ("pcm_float", 32),
        7 => ("pcm_float", 64),
        23 => ("g721", 4),
        25 => ("g723_3", 3),
        26 => ("g723_5", 5),
        27 => ("alaw", 8),
        _ => ("unknown", 0),
    };
    let data = if size == u32::MAX { src.len().saturating_sub(u64::from(offset)) } else { u64::from(size) };
    let mut s = Stream::new(codec);
    s.sample_rate_hz = Some(rate);
    s.channels = u16::try_from(channels).ok();
    s.bits_per_sample = Some(bits).filter(|b| *b > 0);
    if bits > 0 && channels > 0 {
        s.samples = Some(data * 8 / (u64::from(bits) * u64::from(channels)));
        s.bitrate_bps = Some(u64::from(rate) * u64::from(bits) * u64::from(channels));
    }
    cx.format_set("encoding", encoding);
    cx.format_set("data_offset_bytes", offset);
    // The annotation between the header and the data (often "key=value").
    if offset > 24
        && offset <= 4096
        && let Ok(a) = src.read_vec(24, usize::try_from(offset - 24).unwrap_or(0))
    {
        let text = super::text(&a[..a.iter().position(|&b| b == 0).unwrap_or(a.len())]);
        if !text.is_empty() {
            tags.system("au_annotation");
            for line in text.lines() {
                if let Some((k, v)) = line.split_once('=')
                    && let Some(key) = super::comment_key(&k.trim().to_ascii_uppercase())
                {
                    tags.set(key, v, "au");
                }
            }
            cx.metadata_set("au", "annotation", text);
        }
    }
    s.report(cx, None, src.len());
    Ok(())
}

/// Frame sizes (speech bits plus the header byte) by frame type.
const AMR_NB: [u8; 16] = [13, 14, 16, 18, 20, 21, 27, 32, 6, 0, 0, 0, 0, 0, 0, 1];
const AMR_WB: [u8; 16] = [18, 24, 33, 37, 41, 47, 51, 59, 61, 6, 0, 0, 0, 0, 1, 1];

fn amr(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let head = src.read_vec(0, 12.min(usize::try_from(src.len()).unwrap_or(0)))?;
    let (wb, at) = if head.starts_with(b"#!AMR-WB\n") {
        (true, 9u64)
    } else if head.starts_with(b"#!AMR\n") {
        (false, 6)
    } else {
        return Err(ExtractError::malformed("multichannel AMR is not read"));
    };
    let sizes = if wb { &AMR_WB } else { &AMR_NB };
    let limit = src.len().min(at.saturating_add(MAX_SCAN));
    let data = src.read_vec(at, usize::try_from(limit - at).unwrap_or(0))?;
    cx.checkpoint()?;
    let (mut frames, mut i) = (0u64, 0usize);
    let mut modes = [0u64; 16];
    while i < data.len() {
        let ft = usize::from((data[i] >> 3) & 0xf);
        let n = usize::from(sizes[ft]);
        if n == 0 {
            break;
        }
        modes[ft] += 1;
        frames += 1;
        i += n;
    }
    let rate = if wb { 16_000 } else { 8_000 };
    let mut s = Stream::new(if wb { "amr_wb" } else { "amr_nb" });
    s.sample_rate_hz = Some(rate);
    s.channels = Some(1);
    s.samples = Some(frames * u64::from(rate / 50)); // 20 ms frames
    let used = modes.iter().take(9).filter(|n| **n > 0).count();
    s.vbr = Some(used > 1);
    if let Some(d) = s.duration_s().filter(|d| *d > 0.0) {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
        let br = ((src.len() - at) as f64 * 8.0 / d).round() as u64;
        s.bitrate_bps = Some(br);
    }
    cx.format_set("frames", frames);
    s.report(cx, None, src.len());
    Ok(())
}

fn voc(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.read_vec(0, 26)?;
    let header = u64::from(u16::from_le_bytes([h[20], h[21]]));
    let version = u16::from_le_bytes([h[22], h[23]]);
    cx.format_set("version", format!("{}.{:02}", version >> 8, version & 0xff));
    let mut pos = header;
    let (mut samples, mut stream) = (0u64, None::<Stream>);
    let (mut rate, mut channels, mut bits) = (0u32, 1u16, 8u16);
    let mut pending_ext: Option<(u32, u16)> = None;
    for n in 0..MAX_BLOCKS {
        if n % 1024 == 0 {
            cx.checkpoint()?;
        }
        let Ok(b) = src.read_vec(pos, 4) else { break };
        let kind = b[0];
        if kind == 0 {
            break; // terminator
        }
        let size = u64::from(u32::from_le_bytes([b[1], b[2], b[3], 0]));
        let body = pos + 4;
        match kind {
            1 if size >= 2 => {
                let d = src.read_vec(body, 2)?;
                let (r, ch) = pending_ext.take().unwrap_or_else(|| (1_000_000 / (256 - u32::from(d[0])), 1));
                (rate, channels, bits) = (r, ch, 8);
                let codec = match d[1] {
                    0 => "pcm_u8",
                    1 => "creative_adpcm_4",
                    2 => "creative_adpcm_3",
                    3 => "creative_adpcm_2",
                    _ => "unknown",
                };
                stream.get_or_insert_with(|| Stream::new(codec));
                if d[1] == 0 {
                    samples += (size - 2) / u64::from(channels);
                }
            }
            2 => samples += size / (u64::from(bits / 8).max(1) * u64::from(channels)),
            3 if size >= 3 => {
                let d = src.read_vec(body, 3)?;
                samples += u64::from(u16::from_le_bytes([d[0], d[1]])) + 1;
            }
            8 if size >= 4 => {
                // Extended block: time constant for the next sound block.
                let d = src.read_vec(body, 4)?;
                let tc = u32::from(u16::from_le_bytes([d[0], d[1]]));
                let ch = u16::from(d[3]) + 1;
                pending_ext = Some((256_000_000 / ((65536 - tc.min(65535)) * u32::from(ch)), ch));
            }
            9 if size >= 12 => {
                let d = src.read_vec(body, 12)?;
                rate = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
                bits = u16::from(d[4]);
                channels = u16::from(d[5]).max(1);
                let codec = match u16::from_le_bytes([d[6], d[7]]) {
                    0 => "pcm_u8",
                    4 => "pcm",
                    6 => "alaw",
                    7 => "mulaw",
                    0x200 => "creative_adpcm_4",
                    _ => "unknown",
                };
                stream.get_or_insert_with(|| Stream::new(codec));
                samples += (size - 12) * 8 / (u64::from(bits.max(1)) * u64::from(channels));
            }
            _ => {}
        }
        pos = body + size;
        if pos >= src.len() {
            break;
        }
    }
    let mut s = stream.ok_or_else(|| ExtractError::malformed("no VOC sound block"))?;
    s.sample_rate_hz = Some(rate);
    s.channels = Some(channels);
    s.bits_per_sample = Some(bits);
    s.samples = Some(samples);
    s.report(cx, None, src.len());
    Ok(())
}

fn tta(src: &mut dyn Source, cx: &mut Context<'_>, tags: &mut Tags) -> Result<(), ExtractError> {
    let (start, end) = edge_tags(src, cx, tags)?;
    let h = src.read_vec(start, 22)?;
    let mut r = ByteReader::new(&h);
    r.tag(b"TTA1")?;
    let (format, channels, bits, rate, samples) = (r.le_u16()?, r.le_u16()?, r.le_u16()?, r.le_u32()?, r.le_u32()?);
    let mut s = Stream::new("tta");
    s.sample_rate_hz = Some(rate);
    s.channels = Some(channels);
    s.bits_per_sample = Some(bits);
    s.samples = Some(u64::from(samples));
    if let Some(d) = s.duration_s().filter(|d| *d > 0.0) {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // positive, small
        let br = ((end - start) as f64 * 8.0 / d).round() as u64;
        s.bitrate_bps = Some(br);
    }
    if format == 2 {
        cx.security().encrypted(true);
    }
    cx.format_set(
        "format",
        match format {
            1 => "pcm",
            2 => "encrypted",
            3 => "float",
            _ => "unknown",
        },
    );
    s.report(cx, None, src.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::plugin::testing::report_for;

    crate::fixture_tests!("aac", "au", "amr", "voc", "tta");

    #[test]
    fn au_annotation_and_voc_blocks() {
        let mut au = b".snd".to_vec();
        for v in [40u32, 8000, 3, 8000, 1] {
            au.extend_from_slice(&v.to_be_bytes());
        }
        au.extend_from_slice(b"title=Fog horn\0\0");
        au.resize(40 + 8000, 0);
        let r = report_for("horn.au", &au);
        assert_eq!(r.format["au"]["tags"]["title"], "Fog horn");
        assert_eq!(r.physical.media.as_ref().unwrap().duration_s, Some(0.5));

        // VOC 1.20: a type-9 block (16-bit stereo, 22.05 kHz, 0.1 s), then the terminator.
        let mut voc = b"Creative Voice File\x1a\x1a\x00\x14\x01\x1f\x11".to_vec();
        let data = 22050 / 10 * 4;
        let size = 12 + data;
        voc.push(9);
        voc.extend_from_slice(&u32::try_from(size).unwrap().to_le_bytes()[..3]);
        voc.extend_from_slice(&22050u32.to_le_bytes());
        voc.extend_from_slice(&[16, 2, 4, 0, 0, 0, 0, 0]);
        voc.resize(voc.len() + data, 0);
        voc.push(0);
        let r = report_for("bell.voc", &voc);
        let s = &r.physical.media.as_ref().unwrap().streams[0];
        assert_eq!(
            (&s["codec"], &s["channels"], &s["bits_per_sample"]),
            (&serde_json::json!("pcm"), &serde_json::json!(2), &serde_json::json!(16))
        );
        assert_eq!(r.physical.media.as_ref().unwrap().duration_s, Some(0.1));
    }
}
