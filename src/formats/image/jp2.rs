//! JPEG 2000: JP2 / JPX / JPM / MJ2 files (boxes) and bare codestreams.
//! Size, components and bit depth (`ihdr` / `SIZ`), colour specification
//! (enumerated or an ICC profile), capture and display resolution, XMP and
//! EXIF UUID boxes, XML boxes, GeoJP2 / GML markers, tiles and
//! decomposition levels. IPTC-IIM in its UUID box.
//!
//! Specification: ISO/IEC 15444-1 (JP2, codestream), 15444-2 (JPX).

use serde_json::json;

use super::{boxes, find_box, fourcc, read_box, top_boxes};
use crate::plugin::{
    BlockKind, ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source,
};

/// Extractor for JPEG 2000.
pub struct Jp2;

const SIGNATURE: &[u8] = b"\0\0\0\x0cjP  \r\n\x87\n";
const XMP_UUID: [u8; 16] =
    [0xbe, 0x7a, 0xcf, 0xcb, 0x97, 0xa9, 0x42, 0xe8, 0x9c, 0x71, 0x99, 0x94, 0x91, 0xe3, 0xaf, 0xac];
const IPTC_UUID: [u8; 16] =
    [0x33, 0xc7, 0xa4, 0xd2, 0xb8, 0x1d, 0x47, 0x23, 0xa0, 0xba, 0xf1, 0xa3, 0xe0, 0x97, 0xad, 0x38];
const GEOJP2_UUID: [u8; 16] =
    [0xb1, 0x4b, 0xf8, 0xbd, 0x08, 0x3d, 0x4b, 0x43, 0xa5, 0xae, 0x8c, 0xd7, 0xd5, 0xa6, 0xce, 0x03];

static META: ExtractorMeta = ExtractorMeta {
    id: "image.jp2",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "jp2",
            name: "JPEG 2000 image",
            family: "image.raster",
            mimes: &["image/jp2"],
            extensions: &["jp2", "jpf", "jpx", "jpm", "mj2"],
            magic: &[Magic::prefix(SIGNATURE)],
            parent: None,
        },
        FormatSpec {
            id: "j2k",
            name: "JPEG 2000 codestream",
            family: "image.raster",
            mimes: &["image/x-jp2-codestream"],
            extensions: &["j2k", "j2c", "jpc", "jhc"],
            magic: &[Magic::prefix(b"\xff\x4f\xff\x51")],
            parent: None,
        },
    ],
};

/// Boxes larger than this (other than the codestream) are not read.
const MAX_BOX: u64 = 16 << 20;

impl Extractor for Jp2 {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        if cx.format_id() == "j2k" {
            let head = src.head().to_vec();
            return codestream(&head, cx);
        }
        let mut list = Vec::new();
        let mut have_size = false;
        for b in top_boxes(src, 4096)? {
            list.push(fourcc(&b.kind));
            // The codestream only needs its main header.
            let body = if &b.kind == b"jp2c" {
                src.read_vec(b.at, usize::try_from(b.len.min(64 * 1024)).unwrap_or(0))?
            } else {
                match read_box(src, &b, MAX_BOX) {
                    Some(body) => body,
                    None => continue,
                }
            };
            let (kind, body) = (b.kind, body.as_slice());
            match &kind {
                b"ftyp" => {
                    cx.format_set("brand", fourcc(body.get(..4).unwrap_or_default()));
                    let compat: Vec<String> =
                        body.get(8..).unwrap_or_default().as_chunks::<4>().0.iter().map(|b| fourcc(b)).collect();
                    cx.format_set("compatible_brands", json!(compat));
                }
                b"jp2h" => have_size |= header(body, cx),
                b"jp2c" => {
                    if have_size {
                        tiles(body, cx);
                    } else {
                        codestream(body, cx)?;
                    }
                }
                b"xml " => {
                    let t = String::from_utf8_lossy(body);
                    if t.contains("x:xmpmeta") || t.contains("rdf:RDF") {
                        cx.emit_block(BlockKind::XMP, body.to_vec());
                    } else if t.contains("gml") {
                        cx.format_set("gml", true);
                    }
                }
                b"uuid" if body.len() > 16 => {
                    let (id, payload) = body.split_at(16);
                    if id == XMP_UUID {
                        cx.emit_block(BlockKind::XMP, payload.to_vec());
                    } else if id == IPTC_UUID {
                        cx.emit_block(BlockKind::IPTC_IIM, payload.to_vec());
                    } else if id == GEOJP2_UUID {
                        cx.format_set("geojp2", true);
                    } else if payload.starts_with(b"II*\0")
                        || payload.starts_with(b"MM\0*")
                        || id.starts_with(b"JpgTiffExif->JP2")
                    {
                        cx.emit_block(BlockKind::EXIF, payload.to_vec());
                    }
                }
                _ => {}
            }
        }
        cx.format_set("boxes", json!(list));
        Ok(())
    }
}

crate::register_extractor!(Jp2);

/// The JP2 header box: `ihdr`, `colr`, `res `. True if it gave the size.
fn header(b: &[u8], cx: &mut Context<'_>) -> bool {
    let mut sized = false;
    if let Some(ihdr) = find_box(b, *b"ihdr").filter(|i| i.len() >= 14) {
        let h = u32::from_be_bytes([ihdr[0], ihdr[1], ihdr[2], ihdr[3]]);
        let w = u32::from_be_bytes([ihdr[4], ihdr[5], ihdr[6], ihdr[7]]);
        let nc = u16::from_be_bytes([ihdr[8], ihdr[9]]);
        let bpc = ihdr[10];
        let mut img = cx.physical().image(w, h);
        img.channels(u8::try_from(nc).unwrap_or(u8::MAX));
        if bpc != 0xff {
            img.bit_depth((bpc & 0x7f) + 1);
        }
        sized = true;
    }
    if let Some(colr) = find_box(b, *b"colr").filter(|c| c.len() >= 3) {
        match colr[0] {
            1 if colr.len() >= 7 => {
                let cs = u32::from_be_bytes([colr[3], colr[4], colr[5], colr[6]]);
                let name = match cs {
                    16 => "sRGB",
                    17 => "Gray",
                    18 => "sYCC",
                    12 => "CMYK",
                    14 => "CIELab",
                    _ => "other",
                };
                if let Some(mut img) = cx.physical().existing_image() {
                    img.color_space(name);
                }
            }
            2 => cx.emit_block(BlockKind::ICC, colr[3..].to_vec()),
            _ => {}
        }
    }
    if let Some(res) = find_box(b, *b"res ") {
        for (kind, r) in boxes(res) {
            if r.len() < 10 {
                continue;
            }
            let v = |o: usize| f64::from(u16::from_be_bytes([r[o], r[o + 1]]));
            let e = |o: usize| i32::from(r[o].cast_signed());
            let vert = v(0) / v(2).max(1.0) * 10f64.powi(e(8));
            let horz = v(4) / v(6).max(1.0) * 10f64.powi(e(9));
            let dpi = |ppm: f64| (ppm * 0.0254 * 100.0).round() / 100.0;
            match &kind {
                b"resd" | b"resc" => {
                    if let Some(mut img) = cx.physical().existing_image() {
                        img.dpi(dpi(horz), dpi(vert));
                    }
                }
                _ => {}
            }
        }
    }
    sized
}

/// A bare codestream: the `SIZ` marker segment.
fn codestream(b: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(b);
    r.tag(b"\xff\x4f\xff\x51")?;
    r.advance(2)?; // Lsiz
    let _rsiz = r.be_u16()?;
    let (xsiz, ysiz, xo, yo) = (r.be_u32()?, r.be_u32()?, r.be_u32()?, r.be_u32()?);
    let (xt, yt, _xto, _yto) = (r.be_u32()?, r.be_u32()?, r.be_u32()?, r.be_u32()?);
    let comps = r.be_u16()?;
    let depth = r.u8()?;
    let mut img = cx.physical().image(xsiz.saturating_sub(xo), ysiz.saturating_sub(yo));
    img.channels(u8::try_from(comps).unwrap_or(u8::MAX)).bit_depth((depth & 0x7f) + 1);
    let tiles_x = xsiz.saturating_sub(xo).div_ceil(xt.max(1));
    let tiles_y = ysiz.saturating_sub(yo).div_ceil(yt.max(1));
    cx.format_set("tiles", u64::from(tiles_x) * u64::from(tiles_y));
    tiles(b, cx);
    Ok(())
}

/// Decomposition levels and progression order from the `COD` marker.
fn tiles(b: &[u8], cx: &mut Context<'_>) {
    let Some(at) = b.windows(2).take(64 * 1024).position(|w| w == [0xff, 0x52]) else { return };
    let cod = &b[at + 2..];
    if cod.len() >= 8 {
        let order = match cod[3] {
            0 => "LRCP",
            1 => "RLCP",
            2 => "RPCL",
            3 => "PCRL",
            4 => "CPRL",
            _ => "unknown",
        };
        cx.format_set("progression_order", order);
        cx.format_set("quality_layers", u16::from_be_bytes([cod[4], cod[5]]));
        cx.format_set("decomposition_levels", cod[7]);
        cx.format_set("reversible", cod.get(11).is_some_and(|t| *t == 1));
    }
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("jp2", "j2k");
}
