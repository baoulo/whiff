//! `image` extractors (feature `common`): raster formats, camera raw,
//! layered documents, vector images and GPU textures.
//!
//! Extractors read headers and structure only (no pixel decoding) and hand
//! embedded EXIF / XMP / IPTC / ICC / Photoshop blocks to `whiff::meta`.

// Header parsers follow their specifications' field names (`w`, `h`, `x0`,
// `y1`) and keep a reader `r` and layout `l` in scope: short names are clearer here.
#![allow(clippy::many_single_char_names, clippy::similar_names)]

pub(crate) mod bmp;
pub(crate) mod dds;
pub(crate) mod emf;
pub(crate) mod exr;
pub(crate) mod gif;
pub(crate) mod hdr;
pub(crate) mod heif;
pub(crate) mod ico;
pub(crate) mod jp2;
pub(crate) mod jpeg;
pub(crate) mod jxl;
pub(crate) mod ktx;
pub(crate) mod pcx;
pub(crate) mod png;
pub(crate) mod pnm;
pub(crate) mod psd;
pub(crate) mod qoi;
pub(crate) mod raw;
pub(crate) mod svg;
pub(crate) mod tga;
pub(crate) mod tiff;
pub(crate) mod webp;
pub(crate) mod xcf;

/// Boxes in an ISO base media file (`size`, `type`, body): 32- and 64-bit
/// sizes, size 0 = to the end. Stops at the first box that does not fit.
pub(crate) fn boxes(data: &[u8]) -> impl Iterator<Item = ([u8; 4], &[u8])> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        let head = data.get(pos..pos + 8)?;
        let size32 = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        let kind = [head[4], head[5], head[6], head[7]];
        let (header, size) = match size32 {
            0 => (8, data.len() - pos),
            1 => {
                let ext = data.get(pos + 8..pos + 16)?;
                (16, usize::try_from(u64::from_be_bytes(ext.try_into().ok()?)).ok()?)
            }
            n => (8, n as usize),
        };
        if size < header {
            return None;
        }
        let body = data.get(pos + header..pos.checked_add(size)?)?;
        pos += size;
        Some((kind, body))
    })
}

/// A top-level box of a file: type, body offset, body length.
pub(crate) struct TopBox {
    pub(crate) kind: [u8; 4],
    pub(crate) at: u64,
    pub(crate) len: u64,
}

/// Top-level boxes of an ISO BMFF file, reading only their headers (media
/// data is never read). At most `max` boxes.
pub(crate) fn top_boxes(
    src: &mut dyn crate::plugin::Source,
    max: usize,
) -> Result<Vec<TopBox>, crate::plugin::ExtractError> {
    let mut out = Vec::new();
    let mut pos = 0u64;
    while pos + 8 <= src.len() && out.len() < max {
        let h = src.read_vec(pos, 8)?;
        let size32 = u64::from(u32::from_be_bytes([h[0], h[1], h[2], h[3]]));
        let kind = [h[4], h[5], h[6], h[7]];
        let (header, size) = match size32 {
            0 => (8, src.len() - pos),
            1 => (16, u64::from_be_bytes(src.read_vec(pos + 8, 8)?.try_into().unwrap_or_default())),
            n => (8, n),
        };
        if size < header || pos.saturating_add(size) > src.len() {
            break;
        }
        out.push(TopBox { kind, at: pos + header, len: size - header });
        pos += size;
    }
    Ok(out)
}

/// The body of a top-level box, if it is at most `max` bytes.
pub(crate) fn read_box(src: &mut dyn crate::plugin::Source, b: &TopBox, max: u64) -> Option<Vec<u8>> {
    (b.len <= max).then(|| src.read_vec(b.at, usize::try_from(b.len).ok()?).ok()).flatten()
}

/// The first box of `kind` among `data`'s boxes.
pub(crate) fn find_box(data: &[u8], kind: [u8; 4]) -> Option<&[u8]> {
    boxes(data).find(|(k, _)| *k == kind).map(|(_, b)| b)
}

/// A computed size in pixels (from millimetres, inches, user units…):
/// rounded, with negative and non-finite values as 0.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // clamped to the u32 range first
pub(crate) fn px(v: f64) -> u32 {
    if v.is_finite() { v.round().clamp(0.0, f64::from(u32::MAX)) as u32 } else { 0 }
}

/// A four-character code as text.
pub(crate) fn fourcc(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim_end_matches(['\0', ' ']).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterates_boxes() {
        let mut d = Vec::new();
        d.extend_from_slice(&12u32.to_be_bytes());
        d.extend_from_slice(b"ftypabcd");
        d.extend_from_slice(&9u32.to_be_bytes());
        d.extend_from_slice(b"free!");
        d.extend_from_slice(&100u32.to_be_bytes()); // does not fit
        d.extend_from_slice(b"mdat");
        let found: Vec<[u8; 4]> = boxes(&d).map(|(k, _)| k).collect();
        assert_eq!(found, [*b"ftyp", *b"free"]);
        assert_eq!(find_box(&d, *b"ftyp"), Some(&b"abcd"[..]));
        assert_eq!(boxes(&[0u8, 0, 0, 1]).count(), 0);
    }
}
