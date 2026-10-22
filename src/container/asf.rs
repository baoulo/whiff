//! Advanced Systems Format (WMA, WMV, ASF): the header objects — file
//! properties (duration, preroll, creation date, flags), stream properties
//! (audio wave format, video dimensions and codec), extended stream
//! properties (bitrate, frame time, language, name), content description,
//! extended content description and metadata (library) attributes, the
//! codec list, and content encryption (DRM).
//!
//! Only the header object is read.
//!
//! Specification: Microsoft Advanced Systems Format (ASF) Specification,
//! revision 01.20.05.

use crate::io::{ByteReader, Source};
use crate::plugin::ExtractError;

/// The header object GUID, as stored.
pub const HEADER: [u8; 16] = guid(0x75B2_2630, 0x668E, 0x11CF, [0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C]);
const FILE_PROPERTIES: [u8; 16] = guid(0x8CAB_DCA1, 0xA947, 0x11CF, [0x8E, 0xE4, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65]);
const STREAM_PROPERTIES: [u8; 16] = guid(0xB7DC_0791, 0xA9B7, 0x11CF, [0x8E, 0xE6, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65]);
const CONTENT_DESCRIPTION: [u8; 16] =
    guid(0x75B2_2633, 0x668E, 0x11CF, [0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C]);
const EXTENDED_CONTENT: [u8; 16] = guid(0xD2D0_A440, 0xE307, 0x11D2, [0x97, 0xF0, 0x00, 0xA0, 0xC9, 0x5E, 0xA8, 0x50]);
const HEADER_EXTENSION: [u8; 16] = guid(0x5FBF_03B5, 0xA92E, 0x11CF, [0x8E, 0xE3, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65]);
const METADATA: [u8; 16] = guid(0xC5F8_CBEA, 0x5BAF, 0x4877, [0x84, 0x67, 0xAA, 0x8C, 0x44, 0xFA, 0x4C, 0xCA]);
const METADATA_LIBRARY: [u8; 16] = guid(0x4423_1C94, 0x9498, 0x49D1, [0xA1, 0x41, 0x1D, 0x13, 0x4E, 0x45, 0x70, 0x54]);
const CODEC_LIST: [u8; 16] = guid(0x86D1_5240, 0x311D, 0x11D0, [0xA3, 0xA4, 0x00, 0xA0, 0xC9, 0x03, 0x48, 0xF6]);
const CONTENT_ENCRYPTION: [u8; 16] =
    guid(0x2211_B3FB, 0xBD23, 0x11D2, [0xB4, 0xB7, 0x00, 0xA0, 0xC9, 0x55, 0xFC, 0x6E]);
const EXTENDED_ENCRYPTION: [u8; 16] =
    guid(0x298A_E614, 0x2622, 0x4C17, [0xB9, 0x35, 0xDA, 0xE0, 0x7E, 0xE9, 0x28, 0x9C]);
const AUDIO_MEDIA: [u8; 16] = guid(0xF869_9E40, 0x5B4D, 0x11CF, [0xA8, 0xFD, 0x00, 0x80, 0x5F, 0x5C, 0x44, 0x2B]);
/// The video stream type GUID, as stored.
pub const VIDEO_MEDIA: [u8; 16] = guid(0xBC19_EFC0, 0x5B4D, 0x11CF, [0xA8, 0xFD, 0x00, 0x80, 0x5F, 0x5C, 0x44, 0x2B]);
const EXTENDED_STREAM: [u8; 16] = guid(0x14E6_A5CB, 0xC672, 0x4332, [0x83, 0x99, 0xA9, 0x69, 0x52, 0x06, 0x5B, 0x5A]);
const LANGUAGE_LIST: [u8; 16] = guid(0x7C43_46A9, 0xEFE0, 0x4BFC, [0xB2, 0x29, 0x39, 0x3E, 0xDE, 0x41, 0x5C, 0x85]);
const COMMAND_MEDIA: [u8; 16] = guid(0x59DA_CFC0, 0x59E6, 0x11D0, [0xA3, 0xAC, 0x00, 0xA0, 0xC9, 0x03, 0x48, 0xF6]);

/// Largest header object read.
const MAX_HEADER: u64 = 16 << 20;
/// Objects and attributes read.
const MAX_ITEMS: usize = 4096;

/// A GUID in its stored (mixed-endian) byte order.
const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> [u8; 16] {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let c = c.to_le_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]
}

/// An attribute value.
#[derive(Debug, Clone, PartialEq)]
pub enum Attr {
    /// UTF-16 text.
    Text(String),
    /// Raw bytes (`WM/Picture`, binary attributes).
    Bytes(Vec<u8>),
    /// A boolean.
    Bool(bool),
    /// A number (WORD, DWORD or QWORD).
    Int(u64),
    /// A GUID, as text.
    Guid(String),
}

/// An audio stream's wave format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WaveFormat {
    /// Format tag (`0x0161` = WMA 2).
    pub tag: u16,
    /// Channels.
    pub channels: u16,
    /// Samples per second.
    pub rate: u32,
    /// Average bytes per second.
    pub byte_rate: u32,
    /// Block alignment.
    pub block_align: u16,
    /// Bits per sample.
    pub bits: u16,
}

/// A stream.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Stream {
    /// Stream number (1–127).
    pub number: u16,
    /// `audio`, `video`, `command` or `other`.
    pub kind: &'static str,
    /// Whether the stream's content is encrypted.
    pub encrypted: bool,
    /// Audio wave format.
    pub audio: Option<WaveFormat>,
    /// Video: width, height, compression four-character code, bit count.
    pub video: Option<(u32, u32, String, u16)>,
    /// Codec-specific data after the wave format or bitmap header.
    pub extra: Vec<u8>,
    /// Data bitrate (extended stream properties).
    pub bitrate: Option<u32>,
    /// Average time per frame, in 100 ns units (extended stream properties).
    pub frame_time: Option<u64>,
    /// Language tag (extended stream properties and the language list).
    pub language: Option<String>,
    /// Stream name (extended stream properties).
    pub name: Option<String>,
}

/// File properties.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileProperties {
    /// File size as declared.
    pub size: u64,
    /// Creation time (100 ns units since 1601-01-01; 0 when unset).
    pub created: u64,
    /// Data packets.
    pub packets: u64,
    /// Play duration (100 ns units, preroll included).
    pub play_duration: u64,
    /// Preroll (milliseconds).
    pub preroll_ms: u64,
    /// Broadcast (live) flag.
    pub broadcast: bool,
    /// Seekable flag.
    pub seekable: bool,
    /// Maximum bitrate (bits per second).
    pub max_bitrate: u32,
}

impl FileProperties {
    /// Duration in seconds (play duration less preroll).
    pub fn duration_s(&self) -> Option<f64> {
        let d = self.play_duration as f64 / 1e7 - self.preroll_ms as f64 / 1000.0;
        (!self.broadcast && d > 0.0).then_some(d)
    }
}

/// A parsed ASF header.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Asf {
    /// File properties.
    pub file: Option<FileProperties>,
    /// Streams.
    pub streams: Vec<Stream>,
    /// Content description: (`Title` | `Author` | `Copyright` | `Description` | `Rating`, text).
    pub content: Vec<(&'static str, String)>,
    /// Extended content, metadata and metadata library attributes.
    pub attributes: Vec<(String, Attr)>,
    /// Codec list: (type 1 video / 2 audio, name, description).
    pub codecs: Vec<(u16, String, String)>,
    /// Content encryption objects present (DRM).
    pub encrypted: bool,
    /// Header object names, in order.
    pub objects: Vec<&'static str>,
    /// Language list (RFC 1766 tags), indexed by the stream properties.
    pub languages: Vec<String>,
    /// Extended stream properties: stream number, bitrate, frame time,
    /// language index, name.
    extended: Vec<(u16, u32, u64, u16, Option<String>)>,
}

/// Read the header object at the start of `src`.
pub fn read(src: &mut dyn Source) -> Result<Asf, ExtractError> {
    let h = src.read_vec(0, 30)?;
    if h[..16] != HEADER {
        return Err(ExtractError::malformed("not an ASF header object"));
    }
    let size = u64::from_le_bytes(h[16..24].try_into().unwrap_or_default());
    if size < 30 || size > MAX_HEADER.min(src.len()) {
        return Err(ExtractError::malformed("ASF header size out of range"));
    }
    let body = src.read_vec(30, usize::try_from(size - 30).unwrap_or(0))?;
    let mut asf = Asf::default();
    objects(&body, &mut asf, true);
    for (number, bitrate, frame_time, lang, name) in std::mem::take(&mut asf.extended) {
        let language = asf.languages.get(usize::from(lang)).cloned();
        for s in asf.streams.iter_mut().filter(|s| s.number == number) {
            s.bitrate = Some(bitrate).filter(|b| *b > 0);
            s.frame_time = Some(frame_time).filter(|t| *t > 0);
            s.language.clone_from(&language);
            s.name.clone_from(&name);
        }
    }
    Ok(asf)
}

fn objects(mut d: &[u8], asf: &mut Asf, top: bool) {
    while d.len() >= 24 && asf.objects.len() < MAX_ITEMS {
        let id: [u8; 16] = d[..16].try_into().unwrap_or_default();
        let size = usize::try_from(u64::from_le_bytes(d[16..24].try_into().unwrap_or_default())).unwrap_or(usize::MAX);
        if size < 24 || size > d.len() {
            break;
        }
        let body = &d[24..size];
        d = &d[size..];
        let name = match id {
            FILE_PROPERTIES => {
                file_properties(body, asf);
                "file_properties"
            }
            STREAM_PROPERTIES => {
                stream_properties(body, asf);
                "stream_properties"
            }
            CONTENT_DESCRIPTION => {
                content_description(body, asf);
                "content_description"
            }
            EXTENDED_CONTENT => {
                extended_content(body, asf);
                "extended_content_description"
            }
            HEADER_EXTENSION if top => {
                // Reserved GUID and WORD, data size, then nested objects.
                if let Some(nested) = body.get(22..) {
                    objects(nested, asf, false);
                }
                "header_extension"
            }
            METADATA | METADATA_LIBRARY => {
                metadata(body, asf);
                if id == METADATA { "metadata" } else { "metadata_library" }
            }
            CODEC_LIST => {
                codec_list(body, asf);
                "codec_list"
            }
            EXTENDED_STREAM => {
                extended_stream(body, asf);
                "extended_stream_properties"
            }
            LANGUAGE_LIST => {
                let mut r = ByteReader::new(body);
                if let Ok(n) = r.le_u16() {
                    for _ in 0..n.min(128) {
                        let Ok(len) = r.u8() else { break };
                        let Ok(b) = r.bytes(usize::from(len)) else { break };
                        asf.languages.push(utf16(b));
                    }
                }
                "language_list"
            }
            CONTENT_ENCRYPTION | EXTENDED_ENCRYPTION => {
                asf.encrypted = true;
                if id == CONTENT_ENCRYPTION { "content_encryption" } else { "extended_content_encryption" }
            }
            _ => "other",
        };
        asf.objects.push(name);
    }
}

fn file_properties(d: &[u8], asf: &mut Asf) {
    let mut r = ByteReader::new(d);
    if r.advance(16).is_err() {
        return;
    }
    let (Ok(size), Ok(created), Ok(packets), Ok(play), Ok(_send), Ok(preroll), Ok(flags), Ok(_min), Ok(_max), Ok(br)) = (
        r.le_u64(),
        r.le_u64(),
        r.le_u64(),
        r.le_u64(),
        r.le_u64(),
        r.le_u64(),
        r.le_u32(),
        r.le_u32(),
        r.le_u32(),
        r.le_u32(),
    ) else {
        return;
    };
    asf.file = Some(FileProperties {
        size,
        created,
        packets,
        play_duration: play,
        preroll_ms: preroll,
        broadcast: flags & 1 != 0,
        seekable: flags & 2 != 0,
        max_bitrate: br,
    });
}

fn stream_properties(d: &[u8], asf: &mut Asf) {
    let mut r = ByteReader::new(d);
    let (Ok(kind), Ok(_ecc), Ok(_offset), Ok(type_len), Ok(_ecc_len), Ok(flags), Ok(_res)) =
        (r.array::<16>(), r.array::<16>(), r.le_u64(), r.le_u32(), r.le_u32(), r.le_u16(), r.le_u32())
    else {
        return;
    };
    let Ok(t) = r.bytes(type_len as usize) else { return };
    let mut s = Stream {
        number: flags & 0x7f,
        kind: match kind {
            AUDIO_MEDIA => "audio",
            VIDEO_MEDIA => "video",
            COMMAND_MEDIA => "command",
            _ => "other",
        },
        encrypted: flags & 0x8000 != 0,
        ..Stream::default()
    };
    let mut r = ByteReader::new(t);
    match s.kind {
        "audio" => {
            if let (Ok(tag), Ok(channels), Ok(rate), Ok(byte_rate), Ok(block_align), Ok(bits)) =
                (r.le_u16(), r.le_u16(), r.le_u32(), r.le_u32(), r.le_u16(), r.le_u16())
            {
                s.audio = Some(WaveFormat { tag, channels, rate, byte_rate, block_align, bits });
                s.extra = t.get(18..).unwrap_or_default().to_vec();
            }
        }
        "video" => {
            // Encoded width / height, flags, format data size, BITMAPINFOHEADER.
            if let (Ok(w), Ok(h), Ok(_f), Ok(_n), Ok(_bisize), Ok(_bw), Ok(_bh), Ok(_planes), Ok(bits), Ok(fourcc)) = (
                r.le_u32(),
                r.le_u32(),
                r.u8(),
                r.le_u16(),
                r.le_u32(),
                r.le_i32(),
                r.le_i32(),
                r.le_u16(),
                r.le_u16(),
                r.array::<4>(),
            ) {
                let code = String::from_utf8_lossy(&fourcc).trim_end_matches(['\0', ' ']).to_string();
                s.video = Some((w, h, code, bits));
                // The bitmap header is 40 bytes from offset 11; codec data follows.
                s.extra = t.get(51..).unwrap_or_default().iter().take(4096).copied().collect();
            }
        }
        _ => {}
    }
    if asf.streams.len() < 128 {
        asf.streams.push(s);
    }
}

fn extended_stream(d: &[u8], asf: &mut Asf) {
    let mut r = ByteReader::new(d);
    // Start and end time, then the leaky-bucket parameters.
    if r.advance(16).is_err() {
        return;
    }
    let Ok(bitrate) = r.le_u32() else { return };
    if r.advance(4 * 5 + 4 + 4).is_err() {
        return;
    }
    let (Ok(number), Ok(lang), Ok(frame_time), Ok(names), Ok(_systems)) =
        (r.le_u16(), r.le_u16(), r.le_u64(), r.le_u16(), r.le_u16())
    else {
        return;
    };
    let mut name = None;
    if names > 0
        && let (Ok(_lang), Ok(len)) = (r.le_u16(), r.le_u16())
        && let Ok(b) = r.bytes(usize::from(len))
    {
        name = Some(utf16(b)).filter(|n| !n.is_empty());
    }
    if asf.extended.len() < 128 {
        asf.extended.push((number, bitrate, frame_time, lang, name));
    }
}

fn utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    String::from_utf16_lossy(&units).trim_end_matches('\0').to_string()
}

fn content_description(d: &[u8], asf: &mut Asf) {
    let mut r = ByteReader::new(d);
    let mut lens = [0u16; 5];
    for l in &mut lens {
        let Ok(n) = r.le_u16() else { return };
        *l = n;
    }
    for (name, len) in ["Title", "Author", "Copyright", "Description", "Rating"].into_iter().zip(lens) {
        let Ok(b) = r.bytes(usize::from(len)) else { return };
        let text = utf16(b);
        if !text.trim().is_empty() {
            asf.content.push((name, text));
        }
    }
}

fn value(kind: u16, b: &[u8]) -> Attr {
    let int = |b: &[u8]| b.iter().rev().fold(0u64, |n, &x| (n << 8) | u64::from(x));
    match kind {
        0 => Attr::Text(utf16(b)),
        2 => Attr::Bool(int(b) != 0),
        3..=5 => Attr::Int(int(b)),
        6 => {
            <&[u8; 16]>::try_from(b).ok().and_then(super::cfb::guid).map_or_else(|| Attr::Bytes(b.to_vec()), Attr::Guid)
        }
        _ => Attr::Bytes(b.to_vec()),
    }
}

fn extended_content(d: &[u8], asf: &mut Asf) {
    let mut r = ByteReader::new(d);
    let Ok(n) = r.le_u16() else { return };
    for _ in 0..n {
        let Ok(name_len) = r.le_u16() else { break };
        let Ok(name) = r.bytes(usize::from(name_len)) else { break };
        let (Ok(kind), Ok(len)) = (r.le_u16(), r.le_u16()) else { break };
        let Ok(v) = r.bytes(usize::from(len)) else { break };
        // Extended content stores BOOL as 4 bytes, the rest as in metadata objects.
        if asf.attributes.len() < MAX_ITEMS {
            asf.attributes.push((utf16(name), value(kind, v)));
        }
    }
}

fn metadata(d: &[u8], asf: &mut Asf) {
    let mut r = ByteReader::new(d);
    let Ok(n) = r.le_u16() else { return };
    for _ in 0..n {
        let (Ok(_lang), Ok(_stream), Ok(name_len), Ok(kind), Ok(len)) =
            (r.le_u16(), r.le_u16(), r.le_u16(), r.le_u16(), r.le_u32())
        else {
            break;
        };
        let Ok(name) = r.bytes(usize::from(name_len)) else { break };
        let Ok(v) = r.bytes(len as usize) else { break };
        if asf.attributes.len() < MAX_ITEMS {
            asf.attributes.push((utf16(name), value(kind, v)));
        }
    }
}

fn codec_list(d: &[u8], asf: &mut Asf) {
    let mut r = ByteReader::new(d);
    if r.advance(16).is_err() {
        return;
    }
    let Ok(n) = r.le_u32() else { return };
    for _ in 0..n.min(64) {
        let Ok(kind) = r.le_u16() else { break };
        let Ok(nl) = r.le_u16() else { break };
        let Ok(name) = r.bytes(usize::from(nl) * 2) else { break };
        let Ok(dl) = r.le_u16() else { break };
        let Ok(desc) = r.bytes(usize::from(dl) * 2) else { break };
        let Ok(il) = r.le_u16() else { break };
        if r.advance(usize::from(il)).is_err() {
            break;
        }
        asf.codecs.push((kind, utf16(name).trim().to_string(), utf16(desc).trim().to_string()));
    }
}

/// A `WM/Picture` attribute: picture type, MIME type, description, image.
pub fn picture(b: &[u8]) -> Option<(u8, String, String, &[u8])> {
    let mut r = ByteReader::new(b);
    let kind = r.u8().ok()?;
    let len = r.le_u32().ok()? as usize;
    let rest = r.rest();
    let (mime, rest) = utf16z(rest)?;
    let (desc, rest) = utf16z(rest)?;
    Some((kind, mime, desc, rest.get(..len)?))
}

/// A NUL-terminated UTF-16LE string and what follows it.
fn utf16z(b: &[u8]) -> Option<(String, &[u8])> {
    let end = b.as_chunks::<2>().0.iter().position(|c| *c == [0, 0])? * 2;
    Some((utf16(&b[..end]), &b[end + 2..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_and_pictures() {
        assert_eq!(&HEADER[..4], &[0x30, 0x26, 0xb2, 0x75]);
        let mut pic = vec![3u8, 4, 0, 0, 0];
        pic.extend_from_slice(&[b'a', 0, 0, 0, b'd', 0, 0, 0]);
        pic.extend_from_slice(b"\x89PNG");
        let (kind, mime, desc, data) = picture(&pic).unwrap();
        assert_eq!((kind, mime.as_str(), desc.as_str(), data), (3, "a", "d", &b"\x89PNG"[..]));
        assert_eq!(value(3, &[1, 2, 0, 0]), Attr::Int(0x201));
        assert_eq!(value(0, &[b'h', 0, b'i', 0, 0, 0]), Attr::Text("hi".into()));
    }
}
