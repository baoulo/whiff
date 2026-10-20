//! RealMedia (RM, RMVB): the file properties (bitrates, packet count,
//! duration, flags), each media property header (stream name, MIME type,
//! bitrates; RealVideo FourCC, size and frame rate; RealAudio version 4 / 5
//! codec, sample rate and channels), and the content description (title,
//! author, copyright, comment).
//!
//! Specification: the RealMedia file format (Helix DNA documentation).

use serde_json::json;

use super::super::audio::{Stream, Tags};
use super::{Video, audio_map, finish, labels, other_map};
use crate::plugin::{ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for RealMedia.
pub struct RealMedia;

static META: ExtractorMeta = ExtractorMeta {
    id: "video.realmedia",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "rm",
        name: "RealMedia",
        family: "video",
        mimes: &["application/vnd.rn-realmedia", "application/vnd.rn-realmedia-vbr"],
        extensions: &["rm", "rmvb", "rv"],
        magic: &[Magic::prefix(b".RMF")],
        parent: None,
    }],
};

const MAX_CHUNK: u32 = 1 << 20;
const MAX_CHUNKS: usize = 256;

impl Extractor for RealMedia {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let len = src.len();
        let mut pos = 0u64;
        let mut duration = None;
        let mut maps = Vec::new();
        let mut tags = Tags::default();
        for _ in 0..MAX_CHUNKS {
            if pos + 10 > len {
                break;
            }
            let h = src.read_vec(pos, 10)?;
            let id = [h[0], h[1], h[2], h[3]];
            let size = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
            if size < 10 {
                break;
            }
            if &id == b"DATA" || &id == b"INDX" {
                break;
            }
            if size <= MAX_CHUNK {
                let d = src.read_vec(pos + 10, (size - 10) as usize)?;
                match &id {
                    b".RMF" => {
                        if d.len() >= 4 {
                            cx.format_set("file_version", u32::from_be_bytes([d[0], d[1], d[2], d[3]]));
                        }
                    }
                    b"PROP" => {
                        let mut r = ByteReader::new(&d);
                        if let (Ok(max), Ok(avg), Ok(_mp), Ok(_ap), Ok(packets), Ok(ms), Ok(preroll)) =
                            (r.be_u32(), r.be_u32(), r.be_u32(), r.be_u32(), r.be_u32(), r.be_u32(), r.be_u32())
                        {
                            duration = Some(f64::from(ms) / 1000.0).filter(|d| *d > 0.0);
                            cx.format_set("max_bitrate_bps", max);
                            cx.format_set("avg_bitrate_bps", avg);
                            cx.format_set("packets", packets);
                            cx.format_set("preroll_ms", preroll);
                        }
                        if r.advance(8).is_ok()
                            && let (Ok(_streams), Ok(flags)) = (r.be_u16(), r.be_u16())
                        {
                            cx.format_set("flags", json!({ "save_enabled": flags & 1 != 0, "perfect_play": flags & 2 != 0, "live": flags & 4 != 0 }));
                        }
                    }
                    b"MDPR" => {
                        if let Some(m) = media(&d) {
                            maps.push(m);
                        }
                    }
                    b"CONT" => {
                        let mut r = ByteReader::new(&d);
                        tags.system("realmedia");
                        for key in ["title", "artist", "copyright", "comment"] {
                            let Ok(n) = r.be_u16() else { break };
                            let Ok(t) = r.bytes(usize::from(n)) else { break };
                            let text = crate::plugin::latin1_or_utf8(t).trim_matches('\0').trim().to_string();
                            if !text.is_empty() {
                                tags.set(key, &text, "realmedia");
                                cx.metadata_set("realmedia", key, text);
                            }
                        }
                    }
                    _ => {}
                }
            }
            pos += u64::from(size);
        }
        finish(cx, maps, duration, len);
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(RealMedia);

fn pascal<'a>(r: &mut ByteReader<'a>) -> Option<&'a [u8]> {
    let n = r.u8().ok()?;
    r.bytes(usize::from(n)).ok()
}

/// A media properties header.
fn media(d: &[u8]) -> Option<serde_json::Map<String, serde_json::Value>> {
    let mut r = ByteReader::new(d);
    let (number, _max, avg) = (r.be_u16().ok()?, r.be_u32().ok()?, r.be_u32().ok()?);
    r.advance(4 * 4).ok()?; // packet sizes, start time, preroll
    let ms = r.be_u32().ok()?;
    let name = String::from_utf8_lossy(pascal(&mut r)?).into_owned();
    let mime = String::from_utf8_lossy(pascal(&mut r)?).into_owned();
    let n = r.be_u32().ok()? as usize;
    let t = r.bytes(n).ok()?;
    let seconds = Some(f64::from(ms) / 1000.0).filter(|s| *s > 0.0);
    let mut m = if t.get(4..8) == Some(b"VIDO") && t.len() >= 26 {
        let fourcc = String::from_utf8_lossy(&t[8..12]).into_owned();
        let mut v = Video::new(match fourcc.as_str() {
            "RV10" => "rv10",
            "RV20" => "rv20",
            "RV30" => "rv30",
            "RV40" => "rv40",
            "RV60" => "rv60",
            other => return Some(other_map("video", &other.to_ascii_lowercase())),
        });
        v.codec_tag = Some(fourcc);
        v.width = Some(u32::from(u16::from_be_bytes([t[12], t[13]])));
        v.height = Some(u32::from(u16::from_be_bytes([t[14], t[15]])));
        let fps = u32::from_be_bytes([t[22], t[23], t[24], t[25]]);
        v.fps = Some(f64::from(fps) / 65536.0).filter(|f| *f > 0.0);
        v.bitrate_bps = Some(u64::from(avg)).filter(|b| *b > 0);
        v.duration_s = seconds;
        v.to_map()
    } else if t.starts_with(b".ra\xfd") {
        let mut s = real_audio(t).unwrap_or_else(|| Stream::new("real_audio"));
        s.bitrate_bps = s.bitrate_bps.or(Some(u64::from(avg)).filter(|b| *b > 0));
        audio_map(&s)
    } else if mime.starts_with("audio/") {
        other_map("audio", &mime)
    } else {
        other_map("data", if mime.is_empty() { "unknown" } else { &mime })
    };
    labels(&mut m, None, Some(&name), None, None);
    m.insert("stream_number".into(), json!(number));
    if !mime.is_empty() {
        m.insert("mime".into(), json!(mime));
    }
    Some(m)
}

/// A RealAudio version 4 or 5 header.
fn real_audio(t: &[u8]) -> Option<Stream> {
    let mut r = ByteReader::new(t.get(4..)?);
    let version = r.be_u16().ok()?;
    if version != 4 && version != 5 {
        return None;
    }
    // Revision, ".ra4" / ".ra5", data size, version, header size, flavour,
    // coded frame size, then three words and the interleave sizes.
    r.advance(2 + 4 + 4 + 2 + 4 + 2 + 4 + 4).ok()?;
    let bytes_per_minute = r.be_u32().ok()?;
    r.advance(4 + 2 + 2 + 2 + 2).ok()?;
    if version == 5 {
        r.advance(6).ok()?;
    }
    let rate = r.be_u16().ok()?;
    r.advance(4).ok()?;
    let channels = r.be_u16().ok()?;
    let fourcc = if version == 5 {
        r.advance(4).ok()?;
        r.bytes(4).ok()?
    } else {
        pascal(&mut r)?;
        pascal(&mut r)?
    };
    let codec = match fourcc {
        b"cook" => "cook",
        b"atrc" => "atrac3",
        b"sipr" => "sipr",
        b"raac" | b"racp" => "aac",
        b"28_8" => "ra_288",
        b"dnet" => "ac3",
        b"lpcJ" => "ra_144",
        b"ralf" => "ralf",
        other => return Some(Stream::new(String::from_utf8_lossy(other).to_ascii_lowercase())),
    };
    let mut s = Stream::new(codec);
    s.sample_rate_hz = Some(u32::from(rate)).filter(|r| *r > 0);
    s.channels = Some(channels).filter(|c| *c > 0);
    if version == 4 {
        s.bitrate_bps = Some(u64::from(bytes_per_minute) * 8 / 60).filter(|b| *b > 0);
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("rm");
}
