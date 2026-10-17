//! Adobe Photoshop (PSD / PSB): size, channels, depth, colour mode, the
//! image resources (sent to the Photoshop IRB decoder, which handles the
//! embedded IPTC, XMP, EXIF, ICC and thumbnail), and the layer tree: names,
//! groups, text and adjustment layers, visibility and blend modes.
//!
//! Specification: Adobe Photoshop File Formats Specification.

use serde_json::{Value, json};

use crate::plugin::{
    BlockKind, ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source, TextRole,
};

/// Extractor for PSD and PSB.
pub struct Psd;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.psd",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "psd",
            name: "Photoshop document",
            family: "image.layered",
            mimes: &["image/vnd.adobe.photoshop"],
            extensions: &["psd"],
            magic: &[Magic::prefix(b"8BPS\0\x01")],
            parent: None,
        },
        FormatSpec {
            id: "psb",
            name: "Photoshop large document",
            family: "image.layered",
            mimes: &["image/vnd.adobe.photoshop"],
            extensions: &["psb"],
            magic: &[Magic::prefix(b"8BPS\0\x02")],
            parent: None,
        },
    ],
};

/// Image resources and layer records read, at most.
const MAX_RESOURCES: u64 = 32 << 20;
const MAX_LAYER_INFO: u64 = 64 << 20;
const MAX_LAYERS: usize = 10_000;

impl Extractor for Psd {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head().to_vec();
        let mut r = ByteReader::new(&head).skip(4)?;
        let version = r.be_u16()?;
        let psb = version == 2;
        r.advance(6)?;
        let channels = r.be_u16()?;
        let (h, w) = (r.be_u32()?, r.be_u32()?);
        let depth = r.be_u16()?;
        let mode = r.be_u16()?;
        let mode_name = match mode {
            0 => "Bitmap",
            1 => "Grayscale",
            2 => "Indexed",
            3 => "RGB",
            4 => "CMYK",
            7 => "Multichannel",
            8 => "Duotone",
            9 => "Lab",
            _ => "unknown",
        };
        cx.physical()
            .image(w, h)
            .channels(u8::try_from(channels).unwrap_or(u8::MAX))
            .bit_depth(u8::try_from(depth).unwrap_or(u8::MAX))
            .color_space(mode_name);
        cx.format_set("version", version);
        cx.format_set("color_mode", mode_name);
        cx.format_set("channels", channels);

        // Colour mode data, then image resources.
        let mut pos = 26u64;
        let cm_len = be32(src, pos)?;
        pos += 4 + cm_len;
        let res_len = be32(src, pos)?;
        pos += 4;
        if res_len > 0 && res_len <= MAX_RESOURCES && pos + res_len <= src.len() {
            let res = src.read_vec(pos, usize::try_from(res_len).unwrap_or(usize::MAX))?;
            cx.emit_block(BlockKind::PHOTOSHOP_IRB, res);
        } else if res_len > MAX_RESOURCES {
            cx.warn(format!("image resources of {res_len} bytes not read"));
        }
        pos += res_len;

        // Layer and mask information.
        let lm_len = if psb { be64(src, pos)? } else { be32(src, pos)? };
        pos += if psb { 8 } else { 4 };
        if lm_len == 0 {
            cx.format_set("layers", 0);
            return Ok(());
        }
        let li_len = if psb { be64(src, pos)? } else { be32(src, pos)? };
        let li_at = pos + if psb { 8 } else { 4 };
        if li_len == 0 || li_len > MAX_LAYER_INFO || li_at + li_len > src.len() {
            if li_len > MAX_LAYER_INFO {
                cx.warn(format!("layer info of {li_len} bytes not read"));
            }
            return Ok(());
        }
        // Only the layer records are needed, not the channel image data,
        // but the records' total size is not stored: read the section.
        let info = src.read_vec(li_at, usize::try_from(li_len).unwrap_or(usize::MAX))?;
        match layers(&info, psb, cx) {
            Ok(()) => {}
            Err(e) => cx.warn(format!("layer records: {e}")),
        }
        Ok(())
    }
}

crate::register_extractor!(Psd);

fn be32(src: &mut dyn Source, at: u64) -> Result<u64, ExtractError> {
    let b = src.read_vec(at, 4)?;
    Ok(u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
}

fn be64(src: &mut dyn Source, at: u64) -> Result<u64, ExtractError> {
    let b = src.read_vec(at, 8)?;
    Ok(u64::from_be_bytes(b.try_into().unwrap_or_default()))
}

const BLEND: &[(&[u8; 4], &str)] = &[
    (b"pass", "pass through"),
    (b"norm", "normal"),
    (b"diss", "dissolve"),
    (b"dark", "darken"),
    (b"mul ", "multiply"),
    (b"idiv", "color burn"),
    (b"lbrn", "linear burn"),
    (b"lite", "lighten"),
    (b"scrn", "screen"),
    (b"div ", "color dodge"),
    (b"lddg", "linear dodge"),
    (b"over", "overlay"),
    (b"sLit", "soft light"),
    (b"hLit", "hard light"),
    (b"diff", "difference"),
    (b"smud", "exclusion"),
    (b"hue ", "hue"),
    (b"sat ", "saturation"),
    (b"colr", "color"),
    (b"lum ", "luminosity"),
];

/// Additional-layer-information keys that make a layer an adjustment.
const ADJUSTMENTS: &[&[u8; 4]] = &[
    b"levl", b"curv", b"brit", b"blnc", b"hue2", b"hue ", b"selc", b"thrs", b"nvrt", b"post", b"mixr", b"grdm",
    b"phfl", b"expA", b"vibA", b"clrL", b"SoCo", b"GdFl", b"PtFl", b"blwh",
];

/// Keys whose length is 64-bit in a PSB.
const LONG_IN_PSB: &[&[u8; 4]] = &[
    b"LMsk", b"Lr16", b"Lr32", b"Layr", b"Mt16", b"Mt32", b"Mtrn", b"Alph", b"FMsk", b"lnk2", b"FEid", b"FXid", b"PxSD",
];

/// A layer record's additional layer information: its kind, and the
/// Unicode name (`luni`) when present.
fn tagged_blocks(e: &mut ByteReader<'_>, psb: bool, name: &mut String) -> Result<&'static str, ExtractError> {
    let mut kind = "pixel";
    while e.remaining() >= 12 {
        let sig = e.bytes(4)?;
        if sig != b"8BIM" && sig != b"8B64" {
            break;
        }
        let key: [u8; 4] = e.bytes(4)?.try_into().unwrap_or_default();
        let len = if psb && LONG_IN_PSB.contains(&&key) {
            usize::try_from(e.be_u64()?).unwrap_or(usize::MAX)
        } else {
            e.be_u32()? as usize
        };
        let data = e.bytes(len.min(e.remaining()))?;
        match &key {
            b"luni" if data.len() >= 4 => {
                let chars = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                let units: Vec<u16> =
                    data[4..].as_chunks::<2>().0.iter().take(chars).map(|c| u16::from_be_bytes(*c)).collect();
                *name = String::from_utf16_lossy(&units).trim_end_matches('\0').to_string();
            }
            b"lsct" | b"lsdk" if data.len() >= 4 => {
                kind = match u32::from_be_bytes([data[0], data[1], data[2], data[3]]) {
                    1 | 2 => "group",
                    3 => "group_end",
                    _ => kind,
                };
            }
            b"TySh" | b"tySh" => kind = "text",
            b"SoLd" | b"PlLd" | b"SoLE" => kind = "smart_object",
            k if ADJUSTMENTS.contains(&k) && kind == "pixel" => kind = "adjustment",
            _ => {}
        }
    }
    Ok(kind)
}

fn layers(b: &[u8], psb: bool, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(b);
    let count = r.be_u16()?.cast_signed();
    let n = usize::from(count.unsigned_abs());
    cx.format_set("merged_alpha", count < 0);
    let mut list = Vec::new();
    let (mut text_layers, mut groups, mut adjustments, mut smart, mut hidden) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut names = Vec::new();
    for _ in 0..n.min(MAX_LAYERS) {
        let (top, left, bottom, right) = (
            r.be_u32()?.cast_signed(),
            r.be_u32()?.cast_signed(),
            r.be_u32()?.cast_signed(),
            r.be_u32()?.cast_signed(),
        );
        let ch = r.be_u16()?;
        r.advance(usize::from(ch) * if psb { 10 } else { 6 })?;
        r.tag(b"8BIM")?;
        let blend: [u8; 4] = r.bytes(4)?.try_into().unwrap_or_default();
        let opacity = r.u8()?;
        let _clipping = r.u8()?;
        let flags = r.u8()?;
        r.advance(1)?;
        let extra = r.be_u32()? as usize;
        let mut e = ByteReader::new(r.bytes(extra)?);
        let mask = e.be_u32()? as usize;
        e.advance(mask)?;
        let ranges = e.be_u32()? as usize;
        e.advance(ranges)?;
        let name_len = usize::from(e.u8()?);
        let mut name = crate::plugin::latin1_or_utf8(e.bytes(name_len)?);
        e.advance((4 - (name_len + 1) % 4) % 4).ok();
        let kind = tagged_blocks(&mut e, psb, &mut name)?;
        match kind {
            "text" => text_layers += 1,
            "group" => groups += 1,
            "adjustment" => adjustments += 1,
            "smart_object" => smart += 1,
            _ => {}
        }
        let visible = flags & 2 == 0;
        if !visible {
            hidden += 1;
        }
        if kind == "group_end" {
            continue;
        }
        // A text layer is named after its text unless renamed: the closest
        // thing to the document's words without decoding the text engine data.
        if kind == "text" && !name.is_empty() && names.len() < 256 {
            names.push(name.clone());
        }
        if list.len() < 256 {
            list.push(json!({
                "name": name,
                "kind": kind,
                "visible": visible,
                "opacity": (f64::from(opacity) / 2.55).round(),
                "blend_mode": BLEND.iter().find(|(k, _)| **k == blend).map_or_else(|| String::from_utf8_lossy(&blend).into_owned(), |(_, n)| n.to_string()),
                "bounds": [left, top, right, bottom],
            }));
        }
    }
    cx.format_set("layers", list.len());
    cx.format_set("layer_kinds", json!({ "text": text_layers, "group": groups, "adjustment": adjustments, "smart_object": smart, "hidden": hidden }));
    cx.format_set("layer_list", Value::Array(list));
    if !names.is_empty() {
        cx.emit_text(TextRole::Body, &names.join("\n"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("psd", "psb");
}
