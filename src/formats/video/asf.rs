//! Windows Media Video and other ASF files with video: the WMA extractor's
//! header, DRM and tag handling, plus each video stream (codec from its
//! FourCC, size, frame rate from the extended stream properties, bitrate,
//! language, name; the VC-1 / WMV3 profile from the codec data).
//!
//! The header objects are read by `plugin::asf`.

use super::super::audio::{self, round_s};
use super::avi::vfw_codec;
use super::{Video, audio_map, finish, labels, other_map};
use crate::plugin::asf::{self, HEADER, VIDEO_MEDIA};
use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source};

/// Extractor for WMV.
pub struct Wmv;

static META: ExtractorMeta = ExtractorMeta {
    id: "video.asf",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "wmv",
        name: "Windows Media Video",
        family: "video",
        mimes: &["video/x-ms-wmv", "video/x-ms-asf"],
        extensions: &["wmv", "asf", "wm", "dvr-ms"],
        magic: &[],
        parent: Some("wma"),
    }],
};

impl Extractor for Wmv {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // A header object whose stream properties name a video stream.
        if probe.head.get(..16)? != HEADER || !probe.head.windows(16).any(|w| w == VIDEO_MEDIA) {
            return None;
        }
        Some(Sniff { format: "wmv", confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let a = asf::read(src)?;
        let duration = audio::asf::header(&a, cx);
        let mut maps = Vec::new();
        for s in &a.streams {
            let mut m = match s.kind {
                "video" => {
                    let Some((w, h, fourcc, bits)) = &s.video else { continue };
                    let mut v = Video::new(vfw_codec(fourcc));
                    v.codec_tag = Some(fourcc.clone());
                    (v.width, v.height) = (Some(*w).filter(|w| *w > 0), Some(*h).filter(|h| *h > 0));
                    v.fps = s.frame_time.map(|t| 1e7 / t as f64);
                    v.bitrate_bps = s.bitrate.map(u64::from);
                    v.profile = wmv_profile(&v.codec, &s.extra).map(Into::into);
                    v.language.clone_from(&s.language);
                    v.title.clone_from(&s.name);
                    v.encrypted = s.encrypted;
                    let _ = bits;
                    v.to_map()
                }
                "audio" => {
                    let Some(st) = audio::asf::stream(s) else { continue };
                    let mut m = audio_map(&st);
                    labels(&mut m, None, s.name.as_deref(), None, None);
                    m
                }
                other => other_map("data", other),
            };
            m.insert("stream_number".into(), serde_json::json!(s.number));
            maps.push(m);
        }
        finish(cx, maps, duration.map(round_s), src.len());
        audio::asf::tags(&a, cx);
        Ok(())
    }
}

crate::register_extractor!(Wmv);

/// The WMV3 (VC-1 simple / main) or WVC1 (advanced) profile from the codec data.
fn wmv_profile(codec: &str, extra: &[u8]) -> Option<&'static str> {
    match codec {
        "wmv3" => match extra.first()? >> 6 {
            0 => Some("simple"),
            1 => Some("main"),
            3 => Some("advanced"),
            _ => None,
        },
        "vc1" => Some("advanced"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("wmv");

    #[test]
    fn profiles() {
        assert_eq!(wmv_profile("wmv3", &[0x4e]), Some("main"));
        assert_eq!(wmv_profile("wmv2", &[0]), None);
    }
}
