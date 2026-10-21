//! Adaptive streaming manifests: MPEG-DASH MPD (type, profiles, duration,
//! periods, adaptation sets with content type, codecs, languages, roles and
//! representations, segment addressing, DRM systems, program information)
//! and Smooth Streaming client manifests (duration, live, stream indexes
//! with quality levels, DRM).
//!
//! Specifications: ISO/IEC 23009-1; the IIS Smooth Streaming Transport
//! Protocol (MS-SSTR) §2.2.2.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use super::super::text::{XmlNode, XmlTree, decode_xml, url_host, xml_root};
use super::{Entry, Playlist, drm_system, iso_duration};
use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, parse_date, truncate_chars,
};

/// Extractor for DASH and Smooth Streaming manifests.
pub struct Manifest;

static META: ExtractorMeta = ExtractorMeta {
    id: "playlist.manifest",
    version: 1,
    cost: Cost::Scan,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "mpd",
            name: "MPEG-DASH manifest",
            family: "audio.playlist",
            mimes: &["application/dash+xml"],
            extensions: &["mpd"],
            magic: &[],
            parent: Some("xml"),
        },
        FormatSpec {
            id: "ismc",
            name: "Smooth Streaming manifest",
            family: "audio.playlist",
            mimes: &["application/vnd.ms-sstr+xml"],
            extensions: &["ismc", "ism"],
            magic: &[],
            parent: Some("xml"),
        },
    ],
};

/// Adaptation sets and stream indexes listed.
const MAX_LISTED: usize = 32;

impl Extractor for Manifest {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let found = |format| Some(Sniff { format, confidence: 0.95 });
        match xml_root(probe.head)?.rsplit(':').next()? {
            "MPD" => found("mpd"),
            "SmoothStreamingMedia" => found("ismc"),
            _ => None,
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let (bytes, _) = cx.read_bytes(src)?;
        let text = decode_xml(&bytes);
        let tree = XmlTree::parse(&text).map_err(ExtractError::malformed)?;
        cx.checkpoint()?;
        let p = if cx.format_id() == "ismc" { smooth(&tree) } else { mpd(&tree) };
        p.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Manifest);

fn num<T: std::str::FromStr>(n: &XmlNode, k: &str) -> Option<T> {
    n.attr(k).and_then(|v| v.trim().parse().ok())
}

/// `30000/1001` or `25` as frames per second.
fn rate(v: &str) -> Option<f64> {
    let r = match v.split_once('/') {
        Some((a, b)) => a.trim().parse::<f64>().ok()? / b.trim().parse::<f64>().ok()?,
        None => v.trim().parse().ok()?,
    };
    (r.is_finite() && r > 0.0).then(|| (r * 1000.0).round() / 1000.0)
}

/// Note `ContentProtection` children: DRM system names, or `cenc` for the
/// generic MP4 protection scheme.
fn protection(tree: &XmlTree, n: &XmlNode, drm: &mut BTreeSet<String>) {
    for c in tree.children(n, "ContentProtection") {
        let scheme = c.attr("schemeIdUri").unwrap_or("");
        if let Some(d) = drm_system(scheme) {
            drm.insert(d.into());
        } else if scheme.eq_ignore_ascii_case("urn:mpeg:dash:mp4protection:2011") {
            drm.insert(c.attr("value").unwrap_or("cenc").to_ascii_lowercase());
        }
    }
}

#[allow(clippy::too_many_lines)] // periods, adaptation sets, representations
fn mpd(tree: &XmlTree) -> Playlist {
    let root = tree.root();
    let mut p = Playlist { unlisted: true, ..Playlist::default() };
    let kind = root.attr("type").unwrap_or("static").to_ascii_lowercase();
    p.set("type", kind.clone());
    p.set("profiles", root.attr("profiles").map(|v| v.split(',').map(str::trim).collect::<Vec<_>>()));
    p.duration = root.attr("mediaPresentationDuration").and_then(iso_duration);
    p.set("min_buffer_time_s", root.attr("minBufferTime").and_then(iso_duration));
    p.set("max_segment_duration_s", root.attr("maxSegmentDuration").and_then(iso_duration));
    if kind == "dynamic" {
        p.set("live", true);
        p.set("time_shift_buffer_s", root.attr("timeShiftBufferDepth").and_then(iso_duration));
        p.set("availability_start", root.attr("availabilityStartTime").and_then(parse_date).map(|d| d.0));
    }
    if let Some(info) = tree.child(root, "ProgramInformation") {
        p.title = tree.text(info, "Title").map(str::to_string);
        p.set("source", tree.text(info, "Source"));
        p.copyright = tree.text(info, "Copyright").map(str::to_string);
        p.set("language", info.attr("lang"));
    }
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    let mut base = |n: &XmlNode| {
        for b in tree.children(n, "BaseURL") {
            if let Some(h) = url_host(b.text.trim()) {
                hosts.insert(h);
            }
        }
    };
    base(root);
    let mut drm: BTreeSet<String> = BTreeSet::new();
    protection(tree, root, &mut drm);
    let mut sets = Vec::new();
    let mut addressing: BTreeSet<&'static str> = BTreeSet::new();
    let (mut periods, mut events, mut representations) = (0u64, 0u64, 0u64);
    let mut languages: BTreeSet<String> = BTreeSet::new();
    for period in tree.children(root, "Period") {
        periods += 1;
        base(period);
        events += tree.children(period, "EventStream").count() as u64;
        for set in tree.children(period, "AdaptationSet") {
            base(set);
            protection(tree, set, &mut drm);
            let reps: Vec<&XmlNode> = tree.children(set, "Representation").collect();
            representations += reps.len() as u64;
            let mut codecs: BTreeSet<String> = set.attr("codecs").map(str::to_string).into_iter().collect();
            let mut mimes: BTreeSet<String> = set.attr("mimeType").map(str::to_string).into_iter().collect();
            let (mut min_bw, mut max_bw, mut max_px) = (u64::MAX, 0u64, None::<(u64, u64)>);
            let mut rates: BTreeSet<String> = BTreeSet::new();
            let mut sampling = None;
            let mut channels = None;
            for scope in std::iter::once(set).chain(reps.iter().copied()) {
                for (k, v) in [("SegmentTemplate", "template"), ("SegmentList", "list"), ("SegmentBase", "base")] {
                    if tree.child(scope, k).is_some() {
                        addressing.insert(v);
                    }
                }
                if let Some(c) = tree.child(scope, "AudioChannelConfiguration").and_then(|c| c.attr("value")) {
                    channels.get_or_insert_with(|| c.to_string());
                }
            }
            for r in &reps {
                protection(tree, r, &mut drm);
                base(r);
                if let Some(c) = r.attr("codecs") {
                    codecs.insert(c.to_string());
                }
                if let Some(m) = r.attr("mimeType") {
                    mimes.insert(m.to_string());
                }
                if let Some(bw) = num::<u64>(r, "bandwidth") {
                    min_bw = min_bw.min(bw);
                    max_bw = max_bw.max(bw);
                }
                if let (Some(w), Some(h)) = (num::<u64>(r, "width"), num::<u64>(r, "height"))
                    && max_px.is_none_or(|(a, b)| w * h > a * b)
                {
                    max_px = Some((w, h));
                }
                if let Some(f) = r.attr("frameRate").or_else(|| set.attr("frameRate")).and_then(rate) {
                    rates.insert(f.to_string());
                }
                if sampling.is_none() {
                    sampling = num::<u64>(r, "audioSamplingRate");
                }
                p.push(Entry { location: tree.text(r, "BaseURL").map(str::to_string), ..Entry::default() });
            }
            let content = set
                .attr("contentType")
                .map(str::to_string)
                .or_else(|| mimes.iter().next().map(|m| m.split('/').next().unwrap_or(m).to_string()));
            let lang = set.attr("lang").map(str::to_string);
            if let Some(l) = &lang {
                languages.insert(l.clone());
            }
            if sets.len() < MAX_LISTED {
                let mut m = Map::new();
                let mut put = |k: &str, v: Value| {
                    if !v.is_null() && v != json!([]) {
                        m.insert(k.into(), v);
                    }
                };
                put("content_type", json!(content));
                put("mime_types", json!(mimes));
                put("codecs", json!(codecs.into_iter().take(16).collect::<Vec<_>>()));
                put("language", json!(lang));
                put("role", json!(tree.child(set, "Role").and_then(|r| r.attr("value"))));
                put("label", json!(tree.text(set, "Label").map(|l| truncate_chars(l, 100))));
                put("representations", json!(reps.len()));
                if max_bw > 0 {
                    put("bandwidth_bps", json!([min_bw, max_bw]));
                }
                put("max_resolution", json!(max_px.map(|(w, h)| format!("{w}x{h}"))));
                put("frame_rates", json!(rates.into_iter().filter_map(|r| r.parse::<f64>().ok()).collect::<Vec<_>>()));
                put("sampling_rate", json!(sampling));
                put("channels", json!(channels));
                sets.push(Value::Object(m));
            }
        }
    }
    // A single period without a presentation duration: its own duration.
    if p.duration.is_none()
        && periods == 1
        && let Some(per) = tree.child(root, "Period")
    {
        p.duration = per.attr("duration").and_then(iso_duration);
    }
    p.set("periods", periods);
    p.set("adaptation_sets", sets.len());
    p.set("representations", representations);
    p.set("adaptation_set_list", Value::Array(sets));
    p.set("segment_addressing", addressing.into_iter().collect::<Vec<_>>());
    p.set("languages", languages.into_iter().collect::<Vec<_>>());
    if events > 0 {
        p.set("event_streams", events);
    }
    p.set("base_url_hosts", hosts.into_iter().take(10).collect::<Vec<_>>());
    if !drm.is_empty() {
        p.encrypted = true;
        p.set("drm", drm.into_iter().collect::<Vec<_>>());
    }
    if tree.child(root, "UTCTiming").is_some() {
        p.set("utc_timing", true);
    }
    p
}

fn smooth(tree: &XmlTree) -> Playlist {
    let root = tree.root();
    let mut p = Playlist { unlisted: true, ..Playlist::default() };
    let scale = num::<f64>(root, "TimeScale").filter(|s| *s > 0.0).unwrap_or(10_000_000.0);
    p.duration = num::<f64>(root, "Duration").map(|d| d / scale);
    p.set(
        "version",
        match (root.attr("MajorVersion"), root.attr("MinorVersion")) {
            (Some(a), Some(b)) => Some(format!("{a}.{b}")),
            _ => None,
        },
    );
    if root.attr("IsLive").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        p.set("live", true);
        p.set("dvr_window_s", num::<f64>(root, "DVRWindowLength").map(|d| d / scale));
    }
    let mut drm: BTreeSet<String> = BTreeSet::new();
    for prot in tree.children(root, "Protection") {
        for h in tree.children(prot, "ProtectionHeader") {
            if let Some(d) = h.attr("SystemID").and_then(drm_system) {
                drm.insert(d.into());
            } else {
                drm.insert("unknown".into());
            }
        }
    }
    let mut streams = Vec::new();
    let mut languages: BTreeSet<String> = BTreeSet::new();
    for s in tree.children(root, "StreamIndex") {
        let levels: Vec<&XmlNode> = tree.children(s, "QualityLevel").collect();
        let lang = s.attr("Language").map(str::to_string);
        if let Some(l) = &lang {
            languages.insert(l.clone());
        }
        for _ in &levels {
            p.push(Entry::default());
        }
        if streams.len() < MAX_LISTED {
            let bitrates: Vec<u64> = levels.iter().filter_map(|q| num::<u64>(q, "Bitrate")).collect();
            let fourcc: BTreeSet<&str> = levels.iter().filter_map(|q| q.attr("FourCC")).collect();
            let mut m = Map::new();
            let mut put = |k: &str, v: Value| {
                if !v.is_null() && v != json!([]) {
                    m.insert(k.into(), v);
                }
            };
            put("type", json!(s.attr("Type").map(str::to_ascii_lowercase)));
            put("subtype", json!(s.attr("Subtype")));
            put("name", json!(s.attr("Name")));
            put("language", json!(lang));
            put("quality_levels", json!(levels.len()));
            put("bitrates_bps", json!(bitrates));
            put("fourcc", json!(fourcc));
            put("chunks", json!(num::<u64>(s, "Chunks").or(Some(tree.children(s, "c").count() as u64))));
            let w = levels.iter().filter_map(|q| num::<u64>(q, "MaxWidth")).max();
            let h = levels.iter().filter_map(|q| num::<u64>(q, "MaxHeight")).max();
            if let (Some(w), Some(h)) = (w, h) {
                put("max_resolution", json!(format!("{w}x{h}")));
            }
            put("sampling_rate", json!(levels.iter().find_map(|q| num::<u64>(q, "SamplingRate"))));
            put("channels", json!(levels.iter().find_map(|q| num::<u64>(q, "Channels"))));
            streams.push(Value::Object(m));
        }
    }
    p.set("stream_indexes", streams.len());
    p.set("stream_list", Value::Array(streams));
    p.set("languages", languages.into_iter().collect::<Vec<_>>());
    if !drm.is_empty() {
        p.encrypted = true;
        p.set("drm", drm.into_iter().collect::<Vec<_>>());
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::fixture_tests!("mpd", "ismc");

    #[test]
    fn manifests() {
        let t = XmlTree::parse(
            "<MPD type=\"static\" profiles=\"urn:mpeg:dash:profile:isoff-live:2011\" mediaPresentationDuration=\"PT1M0.5S\">\
             <Period><AdaptationSet contentType=\"video\" lang=\"en\"><ContentProtection schemeIdUri=\"urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed\"/>\
             <SegmentTemplate media=\"$Number$.m4s\"/><Representation id=\"v1\" bandwidth=\"500000\" width=\"640\" height=\"360\" codecs=\"avc1.64001e\" frameRate=\"30000/1001\"/>\
             <Representation id=\"v2\" bandwidth=\"900000\" width=\"1280\" height=\"720\" codecs=\"avc1.64001f\"/></AdaptationSet></Period></MPD>",
        )
        .unwrap();
        let p = mpd(&t);
        assert_eq!(p.duration, Some(60.5));
        assert_eq!(p.entries.len(), 2);
        assert!(p.encrypted);
        let set = &p.format["adaptation_set_list"][0];
        assert_eq!(set["max_resolution"], "1280x720");
        assert_eq!(set["bandwidth_bps"], json!([500_000, 900_000]));
        assert_eq!(set["frame_rates"], json!([29.97]));
        assert_eq!(p.format["segment_addressing"], json!(["template"]));
        let t = XmlTree::parse(
            "<SmoothStreamingMedia MajorVersion=\"2\" MinorVersion=\"2\" Duration=\"50000000\"><StreamIndex Type=\"audio\" Language=\"eng\" Chunks=\"3\"><QualityLevel Bitrate=\"128000\" FourCC=\"AACL\" SamplingRate=\"48000\" Channels=\"2\"/></StreamIndex></SmoothStreamingMedia>",
        )
        .unwrap();
        let p = smooth(&t);
        assert_eq!(p.duration, Some(5.0));
        assert_eq!(p.format["stream_list"][0]["channels"], 2);
        assert_eq!(rate("25"), Some(25.0));
        assert_eq!(rate("1/0"), None);
    }
}
