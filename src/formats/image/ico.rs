//! Windows icons and cursors (ICO / CUR): every entry's size, colour depth
//! and encoding (BMP or PNG), cursor hotspots; the largest entry gives the
//! image size.
//!
//! Specification: Microsoft ICONDIR / ICONDIRENTRY.

use serde_json::{Value, json};

use crate::plugin::{
    ByteReader, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source,
};

/// Extractor for ICO and CUR.
pub struct Ico;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.ico",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "ico",
            name: "Windows icon",
            family: "image.raster",
            mimes: &["image/vnd.microsoft.icon"],
            extensions: &["ico"],
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "cur",
            name: "Windows cursor",
            family: "image.raster",
            mimes: &["image/x-win-bitmap"],
            extensions: &["cur"],
            magic: &[],
            parent: None,
        },
    ],
};

const MAX_ENTRIES: u16 = 512;

impl Extractor for Ico {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // Reserved 0, type 1 (icon) or 2 (cursor), a plausible count, and a
        // first entry whose data lies inside the file.
        let h = probe.head;
        let (kind, count) =
            (u16::from_le_bytes([*h.get(2)?, *h.get(3)?]), u16::from_le_bytes([*h.get(4)?, *h.get(5)?]));
        if h.get(..2)? != [0, 0] || !(1..=MAX_ENTRIES).contains(&count) || h.get(9)? != &0 {
            return None;
        }
        let size = u64::from(u32::from_le_bytes(h.get(14..18)?.try_into().ok()?));
        let offset = u64::from(u32::from_le_bytes(h.get(18..22)?.try_into().ok()?));
        let fits = offset >= 6 + 16 * u64::from(count) && offset + size <= probe.len && size > 0;
        match kind {
            1 if fits => Some(Sniff { format: "ico", confidence: 0.8 }),
            2 if fits => Some(Sniff { format: "cur", confidence: 0.8 }),
            _ => None,
        }
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head().to_vec();
        let mut r = ByteReader::new(&head).skip(2)?;
        let kind = r.le_u16()?;
        let count = r.le_u16()?;
        if count == 0 || count > MAX_ENTRIES {
            return Err(ExtractError::malformed(format!("{count} entries")));
        }
        let mut entries = Vec::new();
        let (mut best, mut best_area) = ((0u32, 0u32, 0u16), 0u64);
        for _ in 0..count {
            let w = match r.u8()? {
                0 => 256,
                n => u32::from(n),
            };
            let h = match r.u8()? {
                0 => 256,
                n => u32::from(n),
            };
            let _colors = r.u8()?;
            r.advance(1)?;
            let (a, b) = (r.le_u16()?, r.le_u16()?);
            let size = r.le_u32()?;
            let offset = r.le_u32()?;
            let encoding = match src.read_vec(u64::from(offset), 8) {
                Ok(m) if m.starts_with(b"\x89PNG") => "png",
                Ok(_) => "bmp",
                Err(_) => "missing",
            };
            let mut e = json!({ "width": w, "height": h, "bytes": size, "encoding": encoding });
            if kind == 2 {
                e["hotspot"] = json!([a, b]);
            } else {
                e["bits_per_pixel"] = json!(b);
            }
            let area = u64::from(w) * u64::from(h);
            if area > best_area {
                best_area = area;
                best = (w, h, if kind == 2 { 0 } else { b });
            }
            if entries.len() < 64 {
                entries.push(e);
            }
        }
        let mut img = cx.physical().image(best.0, best.1);
        img.frames(u32::from(count));
        if best.2 > 0 {
            img.bit_depth(u8::try_from(best.2).unwrap_or(0));
        }
        cx.format_set("entries", Value::Array(entries));
        cx.format_set("count", count);
        Ok(())
    }
}

crate::register_extractor!(Ico);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("ico", "cur");
}
