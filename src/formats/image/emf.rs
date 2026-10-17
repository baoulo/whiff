//! Windows metafiles: EMF / EMF+ (header bounds, frame in millimetres,
//! device size, record count, description string with the creating
//! application, EMF+ presence) and WMF (placeable header bounds and
//! resolution, record count). Compressed `.emz` / `.wmz` are gzip.
//!
//! Specifications: [MS-EMF], [MS-EMFPLUS], [MS-WMF].

use crate::plugin::{
    ByteReader, Compression, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Probe, Sniff,
    Source,
};

/// Extractor for EMF and WMF.
pub struct Emf;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.emf",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[
        FormatSpec {
            id: "emf",
            name: "Enhanced Metafile",
            family: "image.vector",
            mimes: &["image/emf"],
            extensions: &["emf", "emz"],
            // EMR_HEADER (record type 1) with " EMF" at offset 40: both are
            // needed, so this is a sniff rather than a magic.
            magic: &[],
            parent: None,
        },
        FormatSpec {
            id: "wmf",
            name: "Windows Metafile",
            family: "image.vector",
            mimes: &["image/wmf"],
            extensions: &["wmf", "wmz"],
            magic: &[Magic::prefix(b"\xd7\xcd\xc6\x9a")],
            parent: None,
        },
    ],
};

const MAX_EMZ: usize = 64 << 20;

impl Extractor for Emf {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        if h.starts_with(&[1, 0, 0, 0]) && h.get(40..44) == Some(b" EMF") {
            return Some(Sniff { format: "emf", confidence: 0.95 });
        }
        if h.starts_with(&[0x1f, 0x8b]) {
            return match probe.extension {
                Some("emz") => Some(Sniff { format: "emf", confidence: 0.9 }),
                Some("wmz") => Some(Sniff { format: "wmf", confidence: 0.9 }),
                _ => None,
            };
        }
        // A WMF without a placeable header: type 1 or 2, header size 9 words.
        (h.len() >= 18 && matches!(h[..2], [1 | 2, 0]) && h[2..4] == [9, 0] && matches!(h[4..6], [0, 1 | 3]))
            .then_some(Sniff { format: "wmf", confidence: 0.7 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let mut head = src.head().to_vec();
        if head.starts_with(&[0x1f, 0x8b]) {
            let (all, _) = cx.read_bytes(src)?;
            head = cx.inflate(&all, Compression::Gzip, MAX_EMZ)?;
            cx.format_set("compressed", true);
        }
        if cx.format_id() == "wmf" {
            return wmf(&head, cx);
        }
        let mut r = ByteReader::new(&head).skip(8)?;
        let bounds = [
            r.le_u32()?.cast_signed(),
            r.le_u32()?.cast_signed(),
            r.le_u32()?.cast_signed(),
            r.le_u32()?.cast_signed(),
        ];
        let frame = [
            r.le_u32()?.cast_signed(),
            r.le_u32()?.cast_signed(),
            r.le_u32()?.cast_signed(),
            r.le_u32()?.cast_signed(),
        ];
        r.tag(b" EMF")?;
        let version = r.le_u32()?;
        let bytes = r.le_u32()?;
        let records = r.le_u32()?;
        let handles = r.le_u16()?;
        r.advance(2)?;
        let desc_len = r.le_u32()? as usize;
        let desc_off = r.le_u32()? as usize;
        let palette = r.le_u32()?;
        let device = [r.le_u32()?, r.le_u32()?];
        let mm = [r.le_u32()?, r.le_u32()?];
        // Frame is in 0.01 mm; the image size in device pixels.
        let (fw, fh) = (f64::from(frame[2] - frame[0]) / 100.0, f64::from(frame[3] - frame[1]) / 100.0);
        if mm[0] > 0 && mm[1] > 0 && fw > 0.0 && fh > 0.0 {
            let w = fw * f64::from(device[0]) / f64::from(mm[0]);
            let h = fh * f64::from(device[1]) / f64::from(mm[1]);
            let mut img = cx.physical().image(super::px(w), super::px(h));
            img.dpi(
                (f64::from(device[0]) / f64::from(mm[0]) * 25.4 * 100.0).round() / 100.0,
                (f64::from(device[1]) / f64::from(mm[1]) * 25.4 * 100.0).round() / 100.0,
            );
        }
        cx.format_set("bounds", serde_json::json!(bounds));
        cx.format_set("frame_mm", serde_json::json!([fw, fh]));
        cx.format_set("version", format!("{}.{}", version >> 16, version & 0xffff));
        cx.format_set("declared_size", bytes);
        cx.format_set("records", records);
        cx.format_set("handles", handles);
        cx.format_set("palette_entries", palette);
        if desc_len > 0
            && let Some(d) = head.get(desc_off..desc_off + desc_len * 2)
        {
            let units: Vec<u16> = d.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            let parts: Vec<String> = String::from_utf16_lossy(&units)
                .split('\0')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            if let Some(app) = parts.first() {
                cx.format_set("software", app.clone());
            }
            if let Some(title) = parts.get(1) {
                cx.content().source("emf.description").title(title.clone());
            }
        }
        // EMF+ lives in the first EMR_COMMENT after the header ("EMF+").
        let header_size =
            u32::from_le_bytes(head.get(4..8).and_then(|b| b.try_into().ok()).unwrap_or_default()) as usize;
        if head.get(header_size..header_size + 4) == Some(&[0x46, 0, 0, 0])
            && head.get(header_size + 12..header_size + 16) == Some(b"EMF+")
        {
            cx.format_set("emf_plus", true);
        }
        Ok(())
    }
}

crate::register_extractor!(Emf);

fn wmf(h: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let mut r = ByteReader::new(h);
    if h.starts_with(b"\xd7\xcd\xc6\x9a") {
        r.advance(6)?;
        let b = [
            r.le_u16()?.cast_signed(),
            r.le_u16()?.cast_signed(),
            r.le_u16()?.cast_signed(),
            r.le_u16()?.cast_signed(),
        ];
        let inch = r.le_u16()?;
        r.advance(6)?;
        if inch > 0 {
            let w = (f64::from(b[2]) - f64::from(b[0])).abs() / f64::from(inch) * 96.0;
            let h = (f64::from(b[3]) - f64::from(b[1])).abs() / f64::from(inch) * 96.0;
            cx.physical().image(super::px(w), super::px(h));
            cx.format_set("units_per_inch", inch);
        }
        cx.format_set("bounds", serde_json::json!(b));
        cx.format_set("placeable", true);
    }
    let kind = r.le_u16()?;
    r.advance(2)?;
    let version = r.le_u16()?;
    let size_words = r.le_u32()?;
    let objects = r.le_u16()?;
    cx.format_set("storage", if kind == 2 { "disk" } else { "memory" });
    cx.format_set("version", format!("{}.{}", version >> 8, version & 0xff));
    cx.format_set("declared_size", u64::from(size_words) * 2);
    cx.format_set("objects", objects);
    Ok(())
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("emf", "wmf");
}
