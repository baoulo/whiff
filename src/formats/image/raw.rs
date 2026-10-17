//! Camera raw files: DNG, Canon CR2 / CR3, Nikon NEF, Sony ARW, Olympus
//! ORF, Panasonic RW2, Pentax PEF, Fujifilm RAF and Samsung SRW.
//!
//! Reports the make and model, the sensor (largest) image size, CFA
//! layout, the embedded previews, DNG versions, and sends the EXIF / XMP /
//! IPTC metadata to the decoders. Raw sensor data is never read.
//!
//! Most raw formats are TIFF structures. Those with their own signature
//! (ORF, RW2, RAF, CR3) are found by magic; the others by sniffing a TIFF
//! header together with a raw extension or a vendor marker (the CR2
//! signature, the `DNGVersion` tag), so ordinary TIFFs are unaffected.
//!
//! Specifications: Adobe DNG 1.7; vendor layouts as documented by
//! ExifTool, LibRaw and the CR3 analysis (`lclevy/canon_cr3`).

use std::collections::HashSet;

use serde_json::json;

use super::tiff::{Entry, Layout, emit_metadata, find, layout, mini_exif, read_ifd};
use super::{boxes, read_box, top_boxes};
use crate::plugin::{
    BlockKind, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff, Source,
};

/// Extractor for camera raw files.
pub struct Raw;

const fn raw(
    id: &'static str,
    name: &'static str,
    ext: &'static [&'static str],
    magic: &'static [Magic],
) -> FormatSpec {
    FormatSpec { id, name, family: "image.raw", mimes: &[], extensions: ext, magic, parent: Some("tiff") }
}

static META: ExtractorMeta = ExtractorMeta {
    id: "image.raw",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec { mimes: &["image/x-adobe-dng"], ..raw("dng", "Adobe DNG raw image", &["dng"], &[]) },
        FormatSpec { mimes: &["image/x-canon-cr2"], ..raw("cr2", "Canon CR2 raw image", &["cr2"], &[]) },
        FormatSpec {
            mimes: &["image/x-canon-cr3"],
            parent: None,
            ..raw("cr3", "Canon CR3 raw image", &["cr3"], &[Magic::at(4, b"ftypcrx ")])
        },
        FormatSpec { mimes: &["image/x-nikon-nef"], ..raw("nef", "Nikon NEF raw image", &["nef", "nrw"], &[]) },
        FormatSpec { mimes: &["image/x-sony-arw"], ..raw("arw", "Sony ARW raw image", &["arw", "srf", "sr2"], &[]) },
        FormatSpec {
            mimes: &["image/x-olympus-orf"],
            ..raw(
                "orf",
                "Olympus ORF raw image",
                &["orf", "ori"],
                &[Magic::prefix(b"IIRO"), Magic::prefix(b"IIRS"), Magic::prefix(b"MMOR")],
            )
        },
        FormatSpec {
            mimes: &["image/x-panasonic-rw2"],
            ..raw("rw2", "Panasonic RW2 raw image", &["rw2", "rwl", "raw"], &[Magic::prefix(b"IIU\0\x08\0\0\0")])
        },
        FormatSpec { mimes: &["image/x-pentax-pef"], ..raw("pef", "Pentax PEF raw image", &["pef"], &[]) },
        FormatSpec {
            mimes: &["image/x-fuji-raf"],
            parent: None,
            ..raw("raf", "Fujifilm RAF raw image", &["raf"], &[Magic::prefix(b"FUJIFILMCCD-RAW ")])
        },
        FormatSpec { mimes: &["image/x-samsung-srw"], ..raw("srw", "Samsung SRW raw image", &["srw"], &[]) },
    ],
};

/// TIFF-based raw formats recognised by extension.
const BY_EXTENSION: &[(&str, &str)] = &[
    ("dng", "dng"),
    ("cr2", "cr2"),
    ("nef", "nef"),
    ("nrw", "nef"),
    ("arw", "arw"),
    ("srf", "arw"),
    ("sr2", "arw"),
    ("pef", "pef"),
    ("srw", "srw"),
];

const MAX_IFDS: usize = 64;
/// CR3 `moov` / RAF JPEG bytes read for metadata.
const MAX_META: u64 = 16 << 20;
const CANON_UUID: [u8; 16] =
    [0x85, 0xc0, 0xb6, 0x87, 0x82, 0x0f, 0x11, 0xe0, 0x81, 0x11, 0xf4, 0xce, 0x46, 0x2b, 0x6a, 0x48];

impl Extractor for Raw {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let l = layout(h).filter(|l| !l.big && h.get(2..4).is_some_and(|m| m == b"*\0" || m == b"\0*"))?;
        if h.get(8..11) == Some(b"CR\x02") {
            return Some(Sniff { format: "cr2", confidence: 0.95 });
        }
        if head_has_tag(h, &l, 50706) {
            return Some(Sniff { format: "dng", confidence: 0.95 });
        }
        let ext = probe.extension?;
        BY_EXTENSION.iter().find(|(e, _)| *e == ext).map(|(_, f)| Sniff { format: f, confidence: 0.95 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        match cx.format_id() {
            "raf" => raf(src, cx),
            "cr3" => cr3(src, cx),
            _ => tiff_raw(src, cx),
        }
    }
}

crate::register_extractor!(Raw);

/// Whether IFD0, read from the head window, has `tag`.
fn head_has_tag(h: &[u8], l: &Layout, tag: u16) -> bool {
    let u16_at = |o: usize| {
        h.get(o..o + 2).map(|b| if l.le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) })
    };
    let Ok(at) = usize::try_from(l.first) else { return false };
    let Some(n) = u16_at(at) else { return false };
    (0..usize::from(n.min(1024))).any(|i| u16_at(at + 2 + 12 * i) == Some(tag))
}

struct Ifd {
    entries: Vec<Entry>,
    /// Where it was found: `ifd0`, `ifd1`, `subifd0`, …
    place: String,
}

/// IFD0's chain plus every `SubIFD` (one level, and their own `SubIFDs`).
fn all_ifds(src: &mut dyn Source, l: &Layout, cx: &mut Context<'_>) -> Result<Vec<Ifd>, ExtractError> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut queue = vec![(l.first, "ifd".to_string(), true)];
    let mut chain_index = 0;
    while let Some((offset, prefix, chain)) = queue.pop() {
        if offset == 0 || !seen.insert(offset) || out.len() >= MAX_IFDS {
            continue;
        }
        cx.checkpoint()?;
        let Ok((entries, next)) = read_ifd(src, l, offset) else { continue };
        let place = if chain {
            let p = format!("{prefix}{chain_index}");
            chain_index += 1;
            queue.push((next, prefix, true));
            p
        } else {
            prefix
        };
        if let Some(subs) = find(&entries, 330) {
            for (i, o) in subs.uints(l.le).into_iter().enumerate().take(16) {
                queue.push((o, format!("{place}.sub{i}"), false));
            }
        }
        out.push(Ifd { entries, place });
    }
    Ok(out)
}

fn tiff_raw(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let l = layout(src.head()).ok_or_else(|| ExtractError::malformed("no TIFF header"))?;
    let ifds = all_ifds(src, &l, cx)?;
    let ifd0 = ifds.first().map(|i| i.entries.clone()).ok_or_else(|| ExtractError::malformed("no IFD"))?;
    let u = |e: &[Entry], t: u16| find(e, t).and_then(|x| x.uint(l.le));
    let s = |e: &[Entry], t: u16| find(e, t).map(Entry::string).filter(|s| !s.is_empty());

    // Panasonic RW2 keeps the sensor size in its own tags.
    // Panasonic RW2: sensor size in tags 2 / 3, the image area within it
    // in the borders (top 4, left 5, bottom 6, right 7).
    let mut sensor = if cx.format_id() == "rw2" {
        let borders = (u(&ifd0, 4), u(&ifd0, 5), u(&ifd0, 6), u(&ifd0, 7));
        match (borders, u(&ifd0, 2), u(&ifd0, 3)) {
            ((Some(t), Some(l), Some(b), Some(r)), ..) if b > t && r > l => Some((r - l, b - t, u(&ifd0, 10))),
            (_, Some(w), Some(h)) => Some((w, h, u(&ifd0, 10))),
            _ => None,
        }
    } else {
        None
    };
    let mut previews = Vec::new();
    let mut cfa = None;
    for ifd in &ifds {
        let e = &ifd.entries;
        let (w, h) = (u(e, 256).unwrap_or(0), u(e, 257).unwrap_or(0));
        let subfile = u(e, 254).unwrap_or(0);
        let compression = u(e, 259);
        let photometric = u(e, 262);
        let jpeg = matches!(compression, Some(6 | 7));
        let jpeg_len = u(e, 514).or_else(|| find(e, 279).map(|b| b.uints(l.le).iter().sum()));
        let is_raw = subfile == 0 && matches!(photometric, Some(32803 | 34892) | None) && compression != Some(6);
        if photometric == Some(32803) {
            cfa = find(e, 33422).map(|p| p.data.clone()).or(cfa);
        }
        if is_raw && w * h > sensor.map_or(0, |(sw, sh, _)| sw * sh) {
            sensor = Some((w, h, u(e, 258)));
        } else if w > 0 && h > 0 && (subfile & 1 == 1 || jpeg) {
            previews.push(json!({ "ifd": ifd.place, "width": w, "height": h, "bytes": jpeg_len }));
        } else if jpeg_len.is_some() && w == 0 {
            previews.push(json!({ "ifd": ifd.place, "bytes": jpeg_len }));
        }
    }
    if let Some((w, h, bits)) = sensor
        && let (Ok(w), Ok(h)) = (u32::try_from(w), u32::try_from(h))
    {
        let mut img = cx.physical().image(w, h);
        if let Some(b) = bits.and_then(|b| u8::try_from(b).ok()) {
            img.bit_depth(b);
        }
        img.color_space("raw");
    }
    let make = s(&ifd0, 271);
    let model = s(&ifd0, 272);
    let mut raw = json!({ "make": make, "model": model, "previews": previews, "ifds": ifds.len() });
    if let Some(p) = cfa.filter(|p| p.len() == 4) {
        let c = |b: u8| ["R", "G", "B", "C", "M", "Y", "W"].get(usize::from(b)).copied().unwrap_or("?");
        raw["cfa_pattern"] = json!(p.iter().map(|b| c(*b)).collect::<String>());
    }
    if let Some(v) = find(&ifd0, 50706).filter(|e| e.data.len() == 4) {
        raw["dng_version"] = json!(v.data.iter().map(u8::to_string).collect::<Vec<_>>().join("."));
        if let Some(b) = find(&ifd0, 50707).filter(|e| e.data.len() == 4) {
            raw["dng_backward_version"] = json!(b.data.iter().map(u8::to_string).collect::<Vec<_>>().join("."));
        }
        if let Some(m) = s(&ifd0, 50708) {
            raw["unique_camera_model"] = json!(m);
        }
        if let Some(m) = s(&ifd0, 50827) {
            raw["original_raw_file_name"] = json!(m);
        }
    }
    if let Some(sw) = s(&ifd0, 305) {
        raw["software"] = json!(sw);
    }
    cx.format_set("byte_order", if l.le { "little-endian" } else { "big-endian" });
    cx.format_set("raw", raw);

    emit_metadata(src, &l, &ifd0, cx);
    // RW2 keeps the full EXIF in an embedded JPEG (tag 0x2E) instead.
    if find(&ifd0, 34665).is_none()
        && let Some(jpg) = find(&ifd0, 0x2e).filter(|e| !e.data.is_empty())
        && let Some(exif) = jpeg_exif(&jpg.data)
    {
        cx.emit_block(BlockKind::EXIF, exif);
    }
    Ok(())
}

/// The EXIF TIFF data of a JPEG's APP1 segment.
fn jpeg_exif(jpg: &[u8]) -> Option<Vec<u8>> {
    if !jpg.starts_with(&[0xff, 0xd8]) {
        return None;
    }
    let mut pos = 2;
    while pos + 4 <= jpg.len() && jpg[pos] == 0xff {
        let marker = jpg[pos + 1];
        let len = usize::from(u16::from_be_bytes([jpg[pos + 2], jpg[pos + 3]]));
        if marker == 0xda || len < 2 {
            return None;
        }
        let body = jpg.get(pos + 4..pos + 2 + len)?;
        if marker == 0xe1 && body.starts_with(b"Exif\0\0") {
            return Some(body[6..].to_vec());
        }
        pos += 2 + len;
    }
    None
}

/// Fujifilm RAF: header, then an embedded JPEG that holds the EXIF.
fn raf(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let h = src.head().to_vec();
    let text = |r: std::ops::Range<usize>| {
        h.get(r).map(|b| String::from_utf8_lossy(b).trim_end_matches('\0').trim().to_string())
    };
    let be = |o: usize| h.get(o..o + 4).map(|b| u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])));
    let model = text(28..60);
    cx.format_set("raw", json!({ "make": "FUJIFILM", "model": model, "format_version": text(60..64) }));
    // The CFA header: `count`, then `tag u16, size u16, data` records;
    // 0x100 is the raw image size (height, width).
    if let (Some(off), Some(len)) = (be(92), be(96))
        && len <= 64 * 1024
        && off + len <= src.len()
    {
        let meta = src.read_vec(off, usize::try_from(len).unwrap_or(0))?;
        if let Some((w, h)) = raf_size(&meta) {
            cx.physical().image(w, h).color_space("raw");
        }
    }
    if let (Some(off), Some(len)) = (be(84), be(88))
        && len <= MAX_META
        && off + len <= src.len()
    {
        let jpg = src.read_vec(off, usize::try_from(len).unwrap_or(usize::MAX))?;
        cx.format_set("preview_bytes", len);
        match jpeg_exif(&jpg) {
            Some(exif) => cx.emit_block(BlockKind::EXIF, exif),
            None => cx.warn("no EXIF in the embedded JPEG"),
        }
    }
    Ok(())
}

fn raf_size(meta: &[u8]) -> Option<(u32, u32)> {
    let count = u32::from_be_bytes(meta.get(..4)?.try_into().ok()?);
    let mut pos = 4;
    for _ in 0..count.min(256) {
        let tag = u16::from_be_bytes(meta.get(pos..pos + 2)?.try_into().ok()?);
        let size = usize::from(u16::from_be_bytes(meta.get(pos + 2..pos + 4)?.try_into().ok()?));
        let data = meta.get(pos + 4..pos + 4 + size)?;
        if tag == 0x100 && size == 4 {
            let h = u16::from_be_bytes([data[0], data[1]]);
            let w = u16::from_be_bytes([data[2], data[3]]);
            return Some((u32::from(w), u32::from(h)));
        }
        pos += 4 + size;
    }
    None
}

/// Canon CR3: ISO BMFF; the metadata lives in `moov/uuid(Canon)/CMT1…CMT4`,
/// each a TIFF structure (IFD0, Exif IFD, `MakerNote`, GPS IFD).
fn cr3(src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let tops = top_boxes(src, 64)?;
    let moov = tops.iter().find(|b| &b.kind == b"moov").ok_or_else(|| ExtractError::malformed("no moov box"))?;
    let at = moov.at;
    let body = read_box(src, moov, MAX_META).ok_or_else(|| ExtractError::malformed("moov too large"))?;
    // File offsets of the CMT boxes. Box bodies are sub-slices of `body`,
    // so their pointer offset within it gives their position in the file.
    let offset_in = |outer: &[u8], inner: &[u8]| (inner.as_ptr() as usize - outer.as_ptr() as usize) as u64;
    let mut cmt: [Option<(u64, u64)>; 4] = [None; 4];
    let mut thumb = None;
    for (kind, b) in boxes(&body) {
        if &kind == b"uuid" && b.starts_with(&CANON_UUID) {
            for (k, c) in boxes(&b[16..]) {
                let pos = at + offset_in(&body, c);
                match &k {
                    b"CMT1" => cmt[0] = Some((pos, c.len() as u64)),
                    b"CMT2" => cmt[1] = Some((pos, c.len() as u64)),
                    b"CMT3" => cmt[2] = Some((pos, c.len() as u64)),
                    b"CMT4" => cmt[3] = Some((pos, c.len() as u64)),
                    b"THMB" if c.len() >= 8 => {
                        thumb = Some((u16::from_be_bytes([c[4], c[5]]), u16::from_be_bytes([c[6], c[7]])));
                    }
                    _ => {}
                }
            }
        }
    }
    let mut ifd = |i: usize| -> Option<(Layout, Vec<Entry>)> {
        let (pos, len) = cmt[i]?;
        let mut sub = src.slice(pos, len).ok()?;
        let l = layout(sub.head())?;
        let e = read_ifd(&mut sub, &l, l.first).ok()?.0;
        Some((l, e))
    };
    let (ifd0, exif, gps) = (ifd(0), ifd(1), ifd(3));
    let le = ifd0.as_ref().is_none_or(|(l, _)| l.le);
    let get = |x: &Option<(Layout, Vec<Entry>)>| x.as_ref().map(|(_, e)| e.clone()).unwrap_or_default();
    let (ifd0e, exife, gpse) = (get(&ifd0), get(&exif), get(&gps));
    // Each CMT holds its own byte order; the rebuilt block needs one.
    if [&ifd0, &exif, &gps].iter().all(|x| x.as_ref().is_none_or(|(l, _)| l.le == le)) {
        let block = mini_exif(le, &ifd0e, &exife, &gpse);
        if !block.is_empty() {
            cx.emit_block(BlockKind::EXIF, block);
        }
    } else {
        cx.warn("CR3 metadata blocks use different byte orders");
    }
    let s = |t: u16| find(&ifd0e, t).map(Entry::string).filter(|s| !s.is_empty());
    let mut raw = json!({ "make": s(271), "model": s(272), "boxes": tops.iter().map(|b| super::fourcc(&b.kind)).collect::<Vec<_>>() });
    if let Some((w, h)) = thumb {
        raw["thumbnail"] = json!({ "width": w, "height": h });
    }
    let dims = |t: u16| find(&exife, t).and_then(|e| e.uint(le)).and_then(|v| u32::try_from(v).ok());
    if let (Some(w), Some(h)) = (dims(0xa002), dims(0xa003)) {
        cx.physical().image(w, h).color_space("raw");
    }
    cx.format_set("raw", raw);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exif_from_embedded_jpeg() {
        let mut j = vec![0xff, 0xd8, 0xff, 0xe1, 0x00, 0x10];
        j.extend_from_slice(b"Exif\0\0II*\0\x08\0\0\0");
        assert_eq!(jpeg_exif(&j).unwrap(), b"II*\0\x08\0\0\0");
        assert!(jpeg_exif(b"nope").is_none());
    }

    crate::fixture_tests!("dng", "cr2", "nef", "arw", "orf", "rw2", "pef", "raf", "srw", "cr3");
}
