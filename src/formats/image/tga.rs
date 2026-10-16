//! Truevision TGA: image type, size, bit depth, origin, image ID, and the
//! TGA 2.0 extension area (author, comments, date, software).
//!
//! Specification: Truevision TGA File Format Specification 2.0.

use crate::plugin::{
    ByteReader, Context, Cost, DateField, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source,
    TextRole,
};

/// Extractor for TGA.
pub struct Tga;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.tga",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "tga",
        name: "TGA image",
        family: "image.raster",
        mimes: &["image/x-tga"],
        extensions: &["tga", "tpic", "icb", "vda", "vst"],
        magic: &[],
        parent: None,
    }],
};

const FOOTER: &[u8] = b"TRUEVISION-XFILE.\0";

impl Extractor for Tga {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        // TGA has no leading magic; version 2 files end with a signature.
        probe.tail.ends_with(FOOTER).then_some(Sniff { format: "tga", confidence: 0.9 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head().to_vec();
        let mut r = ByteReader::new(&head);
        let id_len = usize::from(r.u8()?);
        let map_type = r.u8()?;
        let kind = r.u8()?;
        if map_type > 1 || !matches!(kind, 1 | 2 | 3 | 9 | 10 | 11 | 32 | 33) {
            return Err(ExtractError::malformed(format!("image type {kind}, colour map type {map_type}")));
        }
        r.advance(5)?; // colour map specification
        r.advance(4)?; // origin
        let (w, h) = (r.le_u16()?, r.le_u16()?);
        let bpp = r.u8()?;
        let descriptor = r.u8()?;
        let id = r.bytes(id_len)?;
        let (channels, space) = match kind & !8 {
            1 => (3, "palette"),
            3 => (1, "Gray"),
            _ => (if descriptor & 0x0f > 0 { 4 } else { 3 }, "RGB"),
        };
        cx.physical().image(u32::from(w), u32::from(h)).bit_depth(bpp).channels(channels).color_space(space);
        cx.format_set("rle", kind & 8 != 0);
        cx.format_set("origin", if descriptor & 0x20 != 0 { "top-left" } else { "bottom-left" });
        if !id.is_empty() {
            let s = crate::plugin::latin1_or_utf8(id);
            let s = s.trim_matches(char::from(0)).trim();
            if !s.is_empty() {
                cx.format_set("image_id", s.to_string());
            }
        }
        // Version 2: footer → extension area.
        let tail = src.tail().to_vec();
        if tail.len() >= 26 && tail.ends_with(FOOTER) {
            cx.format_set("version", 2);
            let ext = u32::from_le_bytes(tail[tail.len() - 26..tail.len() - 22].try_into().unwrap_or_default());
            if ext > 0 {
                extension(src, u64::from(ext), cx)?;
            }
        } else {
            cx.format_set("version", 1);
        }
        Ok(())
    }
}

crate::register_extractor!(Tga);

fn field(b: &[u8]) -> String {
    crate::plugin::latin1_or_utf8(b).trim_matches(|c: char| c == '\0' || c.is_whitespace()).to_string()
}

/// The 495-byte extension area.
fn extension(src: &mut dyn Source, at: u64, cx: &mut Context<'_>) -> Result<(), ExtractError> {
    let e = src.read_vec(at, 495)?;
    if u16::from_le_bytes([e[0], e[1]]) != 495 {
        return Ok(());
    }
    let author = field(&e[2..43]);
    if !author.is_empty() {
        cx.content().source("tga.author").author(author.clone());
        cx.rights().source("tga.author").creator(author);
    }
    let comments: Vec<String> = e[43..367].chunks(81).map(field).filter(|c| !c.is_empty()).collect();
    if !comments.is_empty() {
        let c = comments.join("\n");
        cx.emit_text(TextRole::Comment, &c);
        cx.format_set("comments", c);
    }
    let n = |o: usize| u16::from_le_bytes([e[o], e[o + 1]]);
    if n(371) > 0 {
        let d = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}", n(371), n(367), n(369), n(373), n(375), n(377));
        if let Some((v, tz)) = crate::plugin::parse_date(&d) {
            cx.temporal().source("tga.date").content_date(DateField::Created, v, tz);
        }
    }
    let job = field(&e[379..420]);
    if !job.is_empty() {
        cx.format_set("job", job);
    }
    let software = field(&e[426..467]);
    if !software.is_empty() {
        cx.format_set("software", software);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    crate::fixture_tests!("tga");
}
