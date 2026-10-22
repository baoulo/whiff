//! WAVE audio in RIFF, RF64 / BW64 and Sony Wave64: the `fmt ` chunk
//! (codec, channels and speaker mask, rate, bit depth), `fact`, the data
//! size and duration, `LIST INFO` tags, Broadcast Wave `bext` (description,
//! originator, origination date, time reference, loudness, coding history),
//! iXML production metadata, `id3 ` tags, cue points and XMP (`_PMX`).
//!
//! Specifications: Microsoft RIFF / WAVEFORMATEX(TENSIBLE); EBU Tech 3285
//! (BWF), 3306 (RF64) and ITU-R BS.2088 (BW64); the iXML specification;
//! Sony Wave64.

use serde_json::{Map, Value, json};

use super::{Stream, Tags, id3, mask_layout};
use crate::plugin::{
    BlockKind, ByteReader, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source,
};

/// Extractor for WAVE files.
pub struct Wave;

/// The Wave64 `riff` GUID.
const W64_RIFF: &[u8; 16] = b"riff\x2e\x91\xcf\x11\xa5\xd6\x28\xdb\x04\xc1\x00\x00";
/// The tail every Wave64 chunk GUID but `riff` / `list` shares.
const W64_TAIL: &[u8; 12] = b"\xf3\xac\xd3\x11\x8c\xd1\x00\xc0\x4f\x8e\xdb\x8a";

static META: ExtractorMeta = ExtractorMeta {
    id: "audio.wave",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "wav",
            name: "WAVE audio",
            family: "audio",
            mimes: &["audio/wav", "audio/x-wav", "audio/vnd.wave"],
            extensions: &["wav", "wave", "bwf"],
            magic: &[Magic::masked(0, b"RIFF\0\0\0\0WAVE", b"\xff\xff\xff\xff\0\0\0\0\xff\xff\xff\xff")],
            parent: None,
        },
        FormatSpec {
            id: "rf64",
            name: "RF64 / BW64 audio",
            family: "audio",
            mimes: &["audio/x-rf64"],
            extensions: &["rf64", "bw64", "wav"],
            magic: &[
                Magic::masked(0, b"RF64\0\0\0\0WAVE", b"\xff\xff\xff\xff\0\0\0\0\xff\xff\xff\xff"),
                Magic::masked(0, b"BW64\0\0\0\0WAVE", b"\xff\xff\xff\xff\0\0\0\0\xff\xff\xff\xff"),
            ],
            parent: None,
        },
        FormatSpec {
            id: "w64",
            name: "Sony Wave64 audio",
            family: "audio",
            mimes: &["audio/x-w64"],
            extensions: &["w64"],
            magic: &[Magic::prefix(W64_RIFF)],
            parent: None,
        },
    ],
};

/// Chunks walked.
const MAX_CHUNKS: usize = 10_000;
/// Largest metadata chunk read.
const MAX_META: u64 = 16 << 20;

#[derive(Default)]
struct Fmt {
    tag: u16,
    channels: u16,
    rate: u32,
    byte_rate: u32,
    block_align: u16,
    bits: u16,
    valid_bits: Option<u16>,
    mask: Option<u32>,
}

impl Extractor for Wave {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    #[allow(clippy::too_many_lines)] // one arm per chunk type
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.read_vec(0, 16.min(usize::try_from(src.len()).unwrap_or(0)))?;
        let w64 = head.starts_with(W64_RIFF);
        let rf64 = head.starts_with(b"RF64") || head.starts_with(b"BW64");
        let (mut pos, header) = if w64 { (40u64, 24u64) } else { (12, 8) };
        let mut fmt = None;
        let (mut data_len, mut fact) = (None, None);
        let mut ds64_data = None;
        let mut tags = Tags::default();
        let mut chunks = Vec::new();
        let mut cues = 0u32;
        for n in 0..MAX_CHUNKS {
            if n % 256 == 0 {
                cx.checkpoint()?;
            }
            let Ok(h) = src.read_vec(pos, usize::try_from(header).unwrap_or(8)) else { break };
            let (id, mut size) = if w64 {
                let id = if &h[4..16] == W64_TAIL { fourcc(&h[..4]) } else { guid_name(&h[..16]) };
                let size = u64::from_le_bytes(h[16..24].try_into().unwrap_or_default());
                (id, size.saturating_sub(24))
            } else {
                (fourcc(&h[..4]), u64::from(u32::from_le_bytes([h[4], h[5], h[6], h[7]])))
            };
            let body = pos + header;
            if id == "data" && rf64 && size == 0xffff_ffff {
                size = ds64_data.unwrap_or(src.len().saturating_sub(body));
            }
            if chunks.len() < 64 {
                chunks.push(id.clone());
            }
            let avail = src.len().saturating_sub(body);
            if size > avail {
                if id == "data" {
                    cx.warn("data chunk runs past the end (truncated or still being written)");
                    data_len = Some(avail);
                } else {
                    cx.warn(format!("{id} chunk runs past the end"));
                }
                break;
            }
            let read = |src: &mut dyn Source| -> Result<Option<Vec<u8>>, ExtractError> {
                if size > MAX_META {
                    return Ok(None);
                }
                Ok(Some(src.read_vec(body, usize::try_from(size).unwrap_or(0))?))
            };
            match id.as_str() {
                "fmt " => fmt = read(src)?.and_then(|d| parse_fmt(&d)),
                "ds64" => {
                    if let Some(d) = read(src)?
                        && d.len() >= 24
                    {
                        ds64_data = Some(u64::from_le_bytes(d[8..16].try_into().unwrap_or_default()));
                        let samples = u64::from_le_bytes(d[16..24].try_into().unwrap_or_default());
                        if samples > 0 {
                            fact = Some(samples);
                        }
                    }
                }
                "fact" => {
                    if let Some(d) = read(src)?
                        && d.len() >= 4
                        && fact.is_none()
                    {
                        fact = Some(u64::from(u32::from_le_bytes([d[0], d[1], d[2], d[3]])));
                    }
                }
                "data" => data_len = Some(size),
                "LIST" | "list" => {
                    if let Some(d) = read(src)? {
                        list(&d, cx, &mut tags);
                    }
                }
                "bext" => {
                    if let Some(d) = read(src)? {
                        bext(&d, cx, &mut tags);
                    }
                }
                "iXML" => {
                    if let Some(d) = read(src)? {
                        ixml(&String::from_utf8_lossy(&d), cx);
                    }
                }
                "id3 " | "ID3 " => {
                    if let Some(d) = read(src)? {
                        id3::parse_bytes(&d, cx, &mut tags);
                    }
                }
                "_PMX" => {
                    if let Some(d) = read(src)? {
                        cx.emit_block(BlockKind::XMP, d);
                    }
                }
                "cue " => {
                    if let Some(d) = read(src)?
                        && d.len() >= 4
                    {
                        cues = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
                    }
                }
                _ => {}
            }
            let align = if w64 { 8 } else { 2 };
            let padded = size.div_ceil(align) * align;
            pos = body + padded;
            if pos >= src.len() {
                break;
            }
        }
        cx.format_set("chunks", json!(chunks));
        if cues > 0 {
            cx.format_set("cue_points", cues);
        }
        let fmt = fmt.ok_or_else(|| ExtractError::malformed("no fmt chunk"))?;
        let mut stream = Stream::new(codec(fmt.tag));
        stream.sample_rate_hz = Some(fmt.rate);
        stream.channels = Some(fmt.channels);
        stream.bits_per_sample = fmt.valid_bits.filter(|v| *v > 0).or(Some(fmt.bits));
        stream.channel_layout = fmt.mask.filter(|m| *m != 0).and_then(mask_layout);
        stream.bitrate_bps = Some(u64::from(fmt.byte_rate) * 8);
        let pcm = matches!(fmt.tag, 1 | 3 | 6 | 7);
        let samples = match (fact, data_len) {
            (Some(n), _) if !pcm || n > 0 => Some(n),
            (_, Some(d)) if pcm && fmt.block_align > 0 => Some(d / u64::from(fmt.block_align)),
            _ => None,
        };
        // Without a sample count, from the data size and byte rate.
        let duration = match (samples, data_len) {
            (None, Some(d)) if fmt.byte_rate > 0 => Some(d as f64 / f64::from(fmt.byte_rate)),
            _ => None,
        };
        stream.samples = samples;
        cx.format_set("format_tag", format!("0x{:04x}", fmt.tag));
        cx.format_set("block_align_bytes", fmt.block_align);
        if let Some(d) = data_len {
            cx.format_set("data_bytes", d);
        }
        stream.report(cx, duration, src.len());
        tags.report(cx);
        Ok(())
    }
}

crate::register_extractor!(Wave);

fn fourcc(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Names of the Wave64 GUIDs that are not four-character codes.
fn guid_name(g: &[u8]) -> String {
    if g == W64_RIFF {
        "riff".into()
    } else if g == b"list\x2f\x91\xcf\x11\xa5\xd6\x28\xdb\x04\xc1\x00\x00" {
        "list".into()
    } else {
        super::hex(g)
    }
}

fn parse_fmt(d: &[u8]) -> Option<Fmt> {
    let mut r = ByteReader::new(d);
    let mut f = Fmt {
        tag: r.le_u16().ok()?,
        channels: r.le_u16().ok()?,
        rate: r.le_u32().ok()?,
        byte_rate: r.le_u32().ok()?,
        block_align: r.le_u16().ok()?,
        bits: r.le_u16().unwrap_or(0),
        ..Fmt::default()
    };
    if f.tag == 0xfffe && r.le_u16().ok()? >= 22 {
        f.valid_bits = r.le_u16().ok();
        f.mask = r.le_u32().ok();
        // The sub-format GUID starts with the real format tag.
        if let Ok(g) = r.bytes(16) {
            f.tag = u16::from_le_bytes([g[0], g[1]]);
        }
    }
    Some(f)
}

/// The codec of a WAVE format tag.
pub(crate) fn codec(tag: u16) -> String {
    match tag {
        0x0001 => "pcm",
        0x0002 => "ms_adpcm",
        0x0003 => "pcm_float",
        0x0006 => "alaw",
        0x0007 => "mulaw",
        0x0011 => "ima_adpcm",
        0x0022 => "truespeech",
        0x0031 => "gsm610",
        0x0040 => "g721",
        0x0050 => "mp2",
        0x0055 => "mp3",
        0x0092 | 0x2000 => "ac3",
        0x00ff | 0x1600 | 0x1601 | 0x1602 | 0x1610 => "aac",
        0x0160 => "wmav1",
        0x0161 => "wmav2",
        0x0162 => "wma_pro",
        0x0163 => "wma_lossless",
        0x0270 => "atrac3",
        0x2001 => "dts",
        0x674f => "vorbis",
        0x704f => "opus",
        0xf1ac => "flac",
        _ => return format!("wave_0x{tag:04x}"),
    }
    .to_string()
}

/// A `LIST` chunk: `INFO` tags (other list types are noted only).
pub(crate) fn list(d: &[u8], cx: &mut Context<'_>, tags: &mut Tags) {
    let Some(kind) = d.get(..4) else { return };
    if kind != b"INFO" {
        if kind == b"adtl" {
            cx.format_set("associated_data_list", true);
        }
        return;
    }
    tags.system("riff_info");
    let mut r = ByteReader::new(&d[4..]);
    for _ in 0..1000 {
        let (Ok(id), Ok(n)) = (r.array::<4>(), r.le_u32()) else { break };
        let Ok(v) = r.bytes(n as usize) else { break };
        if n % 2 == 1 {
            let _ = r.advance(1);
        }
        let id = String::from_utf8_lossy(&id).into_owned();
        let value = super::text(v);
        if value.is_empty() {
            continue;
        }
        if let Some(key) = info_key(&id) {
            tags.set(key, &value, "riff_info");
        }
        cx.metadata_set("riff_info", &id, value);
    }
}

fn info_key(id: &str) -> Option<&'static str> {
    Some(match id {
        "INAM" => "title",
        "IART" => "artist",
        "IPRD" | "IALB" => "album",
        "ICRD" => "date",
        "IGNR" => "genre",
        "ICMT" => "comment",
        "ICOP" => "copyright",
        "ISFT" => "encoder",
        "ITRK" | "IPRT" | "TRCK" => "track",
        "ISBJ" => "description",
        "IMUS" => "composer",
        "IWRI" => "lyricist",
        "IPUB" => "label",
        "ILNG" => "language",
        "IENC" => "encoded_by",
        _ => return None,
    })
}

/// A Broadcast Wave `bext` chunk.
fn bext(d: &[u8], cx: &mut Context<'_>, tags: &mut Tags) {
    if d.len() < 346 {
        return;
    }
    let field = |a: usize, b: usize| super::text(&d[a..b]);
    let (description, originator, reference) = (field(0, 256), field(256, 288), field(288, 320));
    let (date, time) = (field(320, 330), field(330, 338));
    let time_ref = u64::from_le_bytes(d[338..346].try_into().unwrap_or_default());
    let version = u16::from_le_bytes([d[346], *d.get(347).unwrap_or(&0)]);
    tags.system("bext");
    let mut m = Map::new();
    let mut put = |k: &str, v: &str| {
        if !v.is_empty() {
            m.insert(k.into(), json!(v));
        }
    };
    put("description", &description);
    put("originator", &originator);
    put("originator_reference", &reference);
    put("origination_date", &date);
    put("origination_time", &time);
    m.insert("time_reference_samples".into(), json!(time_ref));
    m.insert("version".into(), json!(version));
    if let Some(umid) = d.get(348..412)
        && umid.iter().any(|&b| b != 0)
    {
        m.insert("umid".into(), json!(super::hex(umid)));
    }
    if version >= 2
        && let Some(l) = d.get(412..422)
    {
        let v = |i: usize| f64::from(i16::from_le_bytes([l[i], l[i + 1]])) / 100.0;
        m.insert(
            "loudness".into(),
            json!({
                "integrated_lufs": v(0),
                "range_lu": v(2),
                "max_true_peak_dbtp": v(4),
                "max_momentary_lufs": v(6),
                "max_short_term_lufs": v(8),
            }),
        );
    }
    if let Some(h) = d.get(602..) {
        let history = super::text(h);
        if !history.is_empty() {
            m.insert("coding_history".into(), json!(history.lines().map(str::trim).collect::<Vec<_>>()));
        }
    }
    if !description.is_empty() {
        tags.set("description", &description, "bext");
    }
    if date.len() == 10 {
        let when = if time.len() == 8 {
            format!("{}T{}", date.replace([':', '/', '.'], "-"), time.replace(['-', '.', '/'], ":"))
        } else {
            date.replace([':', '/', '.'], "-")
        };
        if let Some((v, tz)) = crate::plugin::parse_date(&when) {
            cx.temporal().source("bext.origination").content_date(DateField::Created, v, tz);
        }
    }
    cx.format_set("bext", Value::Object(m));
}

/// iXML: the production fields and track names.
fn ixml(text: &str, cx: &mut Context<'_>) {
    use quick_xml::events::Event;
    const FIELDS: &[(&str, &str)] = &[
        ("BWFXML/IXML_VERSION", "version"),
        ("BWFXML/PROJECT", "project"),
        ("BWFXML/SCENE", "scene"),
        ("BWFXML/TAKE", "take"),
        ("BWFXML/TAPE", "tape"),
        ("BWFXML/NOTE", "note"),
        ("BWFXML/CIRCLED", "circled"),
        ("BWFXML/FILE_UID", "file_uid"),
        ("BWFXML/UBITS", "user_bits"),
        ("BWFXML/SPEED/TIMECODE_RATE", "timecode_rate"),
        ("BWFXML/SPEED/TIMECODE_FLAG", "timecode_flag"),
        ("BWFXML/SPEED/MASTER_SPEED", "master_speed"),
        ("BWFXML/TRACK_LIST/TRACK_COUNT", "track_count"),
    ];
    let mut reader = quick_xml::Reader::from_str(text);
    reader.config_mut().check_end_names = false;
    let mut path: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut m = Map::new();
    let mut tracks = Vec::new();
    for _ in 0..100_000 {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                if path.len() < 16 {
                    path.push(e.local_name().as_ref().to_string());
                }
                buf.clear();
            }
            Ok(Event::Text(t)) => buf.push_str(&t.xml10_content()),
            Ok(Event::End(_)) => {
                let p = path.join("/");
                let v = buf.trim();
                if let Some((_, key)) = FIELDS.iter().find(|(f, _)| *f == p)
                    && !v.is_empty()
                {
                    m.insert((*key).to_string(), json!(v));
                } else if p == "BWFXML/TRACK_LIST/TRACK/NAME" && !v.is_empty() && tracks.len() < 256 {
                    tracks.push(v.to_string());
                }
                path.pop();
                buf.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    if !tracks.is_empty() {
        m.insert("track_names".into(), json!(tracks));
    }
    if !m.is_empty() {
        cx.format_set("ixml", Value::Object(m));
    }
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("wav", "rf64", "w64");
}
