//! Netpbm (PBM, PGM, PPM, PAM) and PFM: variant, size, maximum value,
//! channels, tuple type and header comments.
//!
//! Specification: netpbm.sourceforge.net (pbm, pgm, ppm, pam, pfm).

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole,
};

/// Extractor for Netpbm images.
pub struct Pnm;

static META: ExtractorMeta = ExtractorMeta {
    id: "image.pnm",
    version: 1,
    cost: Cost::Header,
    priority: 0,
    formats: &[FormatSpec {
        id: "pnm",
        name: "Netpbm image",
        family: "image.raster",
        mimes: &["image/x-portable-anymap"],
        extensions: &["pbm", "pgm", "ppm", "pnm", "pam", "pfm"],
        magic: &[],
        parent: None,
    }],
};

impl Extractor for Pnm {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        let h = probe.head;
        let ok = h.len() > 3
            && h[0] == b'P'
            && matches!(h[1], b'1'..=b'7' | b'F' | b'f')
            && h[2].is_ascii_whitespace()
            && (h[1] == b'7'
                || h[3..]
                    .iter()
                    .take(32)
                    .find(|c| !c.is_ascii_whitespace())
                    .is_some_and(|c| c.is_ascii_digit() || *c == b'#'));
        ok.then_some(Sniff { format: "pnm", confidence: 0.75 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let head = src.head().to_vec();
        let text = String::from_utf8_lossy(&head[..head.len().min(8192)]).into_owned();
        // `P` and one ASCII variant byte; anything else is not Netpbm (and
        // would not be safe to slice by byte below).
        let magic = text
            .get(..2)
            .filter(|m| m.starts_with('P') && m.as_bytes()[1].is_ascii_alphanumeric())
            .ok_or_else(|| ExtractError::malformed("no P1–P7 / PF magic"))?;
        let mut comments = Vec::new();
        let (w, h, channels, maxval, tuple) = if magic == "P7" {
            let (mut w, mut h, mut depth, mut maxval, mut tuple) = (0, 0, 0, 0u64, String::new());
            for line in text.lines().skip(1) {
                let mut p = line.split_whitespace();
                match p.next() {
                    Some("WIDTH") => w = p.next().and_then(|v| v.parse().ok()).unwrap_or(0),
                    Some("HEIGHT") => h = p.next().and_then(|v| v.parse().ok()).unwrap_or(0),
                    Some("DEPTH") => depth = p.next().and_then(|v| v.parse().ok()).unwrap_or(0),
                    Some("MAXVAL") => maxval = p.next().and_then(|v| v.parse().ok()).unwrap_or(0),
                    Some("TUPLTYPE") => tuple = p.collect::<Vec<_>>().join(" "),
                    Some("ENDHDR") => break,
                    Some(c) if c.starts_with('#') => comments.push(line.trim_start_matches('#').trim().to_string()),
                    _ => {}
                }
            }
            (w, h, depth, maxval, Some(tuple))
        } else {
            // Tokens, with `#` comments to end of line.
            let mut tokens = Vec::new();
            for line in text[2..].lines() {
                let (data, comment) = line.split_once('#').map_or((line, None), |(d, c)| (d, Some(c)));
                if let Some(c) = comment {
                    comments.push(c.trim().to_string());
                }
                tokens.extend(data.split_whitespace().map(str::to_string));
                if tokens.len() >= 3 {
                    break;
                }
            }
            // Width, height and maxval are integers (a PFM's third token is a float scale).
            let num = |i: usize| tokens.get(i).and_then(|t| t.parse::<u64>().ok());
            let dim = |i: usize| num(i).and_then(|v| u32::try_from(v).ok()).unwrap_or(0);
            let (w, h) = (dim(0), dim(1));
            let (channels, maxval) = match &magic[1..] {
                "1" | "4" => (1, 1),
                "2" | "5" => (1, num(2).unwrap_or(0)),
                "3" | "6" => (3, num(2).unwrap_or(0)),
                "F" => (3, 0),
                _ => (1, 0),
            };
            (w, h, channels, maxval, None)
        };
        if w == 0 || h == 0 {
            return Err(ExtractError::malformed("no size in header"));
        }
        let bits = match maxval {
            0 if magic.eq_ignore_ascii_case("pf") => 32,
            0 => 8,
            m => u8::try_from(64 - m.leading_zeros()).unwrap_or(16),
        };
        cx.physical().image(w, h).channels(u8::try_from(channels).unwrap_or(1)).bit_depth(bits);
        let variant = match magic {
            "P1" => "PBM (ASCII)",
            "P2" => "PGM (ASCII)",
            "P3" => "PPM (ASCII)",
            "P4" => "PBM",
            "P5" => "PGM",
            "P6" => "PPM",
            "P7" => "PAM",
            "PF" => "PFM (colour)",
            "Pf" => "PFM (grey)",
            _ => "unknown",
        };
        cx.format_set("variant", variant);
        if maxval > 0 {
            cx.format_set("maxval", maxval);
        }
        if let Some(t) = tuple.filter(|t| !t.is_empty()) {
            cx.format_set("tuple_type", t);
        }
        let comments: Vec<String> = comments.into_iter().filter(|c| !c.is_empty()).take(16).collect();
        if !comments.is_empty() {
            cx.emit_text(TextRole::Comment, &comments.join("\n"));
            cx.format_set("comments", serde_json::json!(comments));
        }
        Ok(())
    }
}

crate::register_extractor!(Pnm);

#[cfg(test)]
mod tests {
    crate::fixture_tests!("pnm");
}
