//! Radiance HDR (RGBE): header variables (format, exposure, gamma,
//! primaries, software, view) and the resolution line.
//!
//! Specification: Radiance File Formats (Greg Ward).

use serde_json::{Map, Value, json};

use crate::plugin::{Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Source};

/// Extractor for Radiance HDR.
pub struct Hdr;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.hdr",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "hdr",
        name: "Radiance HDR image",
        family: "image.raster",
        mimes: &["image/vnd.radiance"],
        extensions: &["hdr", "pic", "rgbe"],
        magic: &[Magic::prefix(b"#?RADIANCE"), Magic::prefix(b"#?RGBE")],
        parent: None,
    }],
};

impl Extractor for Hdr {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head().to_vec();
        let text = String::from_utf8_lossy(&head[..head.len().min(16 * 1024)]).into_owned();
        let mut vars = Map::new();
        let mut lines = text.lines().skip(1);
        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once('=') {
                vars.insert(k.trim().to_ascii_lowercase(), json!(v.trim()));
            }
        }
        // `-Y 512 +X 768`
        let res = lines.next().unwrap_or("");
        let p: Vec<&str> = res.split_whitespace().collect();
        if p.len() == 4 {
            let (a, b) = (p[1].parse::<u32>().ok(), p[3].parse::<u32>().ok());
            if let (Some(a), Some(b)) = (a, b) {
                let (w, h) = if p[0].ends_with('Y') { (b, a) } else { (a, b) };
                cx.physical().image(w, h).channels(3).bit_depth(32).color_space("linear RGB");
                cx.format_set("orientation", res.trim());
            }
        }
        if let Some(Value::String(s)) = vars.get("software") {
            cx.format_set("software", s.clone());
        }
        cx.format_set("header", Value::Object(vars));
        Ok(())
    }
}

crate::register_extractor!(Hdr);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("hdr");
}
