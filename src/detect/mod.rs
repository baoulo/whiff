//! Format detection.
//!
//! Signatures come from the [`FormatSpec`]s of every registered extractor, so
//! a new format brings its own magic and nothing central needs editing. The
//! steps are:
//!
//! 1. magic signatures (longer signatures score higher);
//! 2. extractor sniffers ([`Extractor::sniff`](crate::plugin::Extractor::sniff));
//! 3. extension: a small boost for a candidate it agrees with, or a weak
//!    candidate for magic-less formats such as CSV;
//! 4. built-in fallbacks: `empty`, `text` (with encoding), `binary`.
//!
//! Stage 1 adds the `file-format` fallback database and container refinement.

use crate::plugin::{FormatSpec, Probe, Registry};
use crate::report::{Candidate, DetectedBy, Identification};

/// Detection result before it is written into the report.
#[derive(Debug, Clone)]
pub struct Detection {
    /// The chosen format; `None` means a built-in fallback (`empty`/`text`/`binary`).
    pub spec: Option<&'static FormatSpec>,
    /// Identification to write into the report.
    pub identification: Identification,
}

struct Scored {
    spec: &'static FormatSpec,
    confidence: f64,
    by: DetectedBy,
}

/// Detect the format of the input described by `probe`.
pub fn detect(registry: &Registry, probe: &Probe<'_>, forced: Option<&str>) -> Detection {
    let ext = probe.extension;
    let mut scored: Vec<Scored> = Vec::new();

    if let Some(id) = forced
        && let Some((spec, _)) = registry.formats().find(|(f, _)| f.id == id)
    {
        scored.push(Scored { spec, confidence: 1.0, by: DetectedBy::Forced });
    }

    if scored.is_empty() {
        for (spec, _) in registry.formats() {
            let best = spec.magic.iter().filter(|m| m.matches(probe.head)).map(|m| m.bytes.len()).max();
            if let Some(len) = best {
                let confidence = 0.6 + 0.04 * len.min(8) as f64;
                upsert(&mut scored, spec, confidence, DetectedBy::Magic);
            }
        }
        for e in registry.extractors() {
            if let Some(sniff) = e.sniff(probe)
                && let Some(spec) = e.meta().formats.iter().find(|f| f.id == sniff.format)
            {
                upsert(&mut scored, spec, sniff.confidence.clamp(0.0, 1.0), DetectedBy::Sniff);
            }
        }
        if let Some(ext) = ext {
            for (spec, _) in registry.formats() {
                if !spec.extensions.iter().any(|e| e.eq_ignore_ascii_case(ext)) {
                    continue;
                }
                if let Some(s) = scored.iter_mut().find(|s| s.spec.id == spec.id) {
                    s.confidence = (s.confidence + 0.05).min(0.99);
                } else if spec.magic.is_empty() {
                    scored.push(Scored { spec, confidence: 0.35, by: DetectedBy::Extension });
                }
            }
        }
    }

    scored.sort_by(|a, b| b.confidence.total_cmp(&a.confidence).then_with(|| a.spec.id.cmp(b.spec.id)));
    let candidates: Vec<Candidate> = scored
        .iter()
        .take(5)
        .map(|s| Candidate { format: s.spec.id.to_string(), confidence: round3(s.confidence) })
        .collect();

    let fallback = fallback(probe);
    if let Some(top) = scored.first().filter(|s| s.confidence > fallback.confidence) {
        let spec = top.spec;
        let extension_matches =
            ext.map(|e| spec.extensions.is_empty() || spec.extensions.iter().any(|x| x.eq_ignore_ascii_case(e)));
        return Detection {
            spec: Some(spec),
            identification: Identification {
                format: spec.id.to_string(),
                name: spec.name.to_string(),
                mime: spec.mimes.first().copied().unwrap_or("application/octet-stream").to_string(),
                family: Some(spec.family.to_string()),
                confidence: round3(top.confidence),
                detected_by: top.by,
                extension_matches,
                candidates: if candidates.len() > 1 { candidates } else { Vec::new() },
                encoding: fallback.encoding,
                extractor: None,
                available_with_feature: None,
            },
        };
    }
    Detection { spec: None, identification: Identification { candidates, ..fallback } }
}

fn upsert(scored: &mut Vec<Scored>, spec: &'static FormatSpec, confidence: f64, by: DetectedBy) {
    match scored.iter_mut().find(|s| s.spec.id == spec.id) {
        Some(s) if confidence > s.confidence => {
            s.confidence = confidence;
            s.by = by;
        }
        Some(_) => {}
        None => scored.push(Scored { spec, confidence, by }),
    }
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// Identification for filesystem objects that are not regular files.
pub fn special(format: &str, name: &str, mime: &str) -> Identification {
    Identification {
        format: format.to_string(),
        name: name.to_string(),
        mime: mime.to_string(),
        confidence: 1.0,
        detected_by: DetectedBy::None,
        ..Identification::default()
    }
}

/// Built-in fallback: `empty`, `text` or `binary`.
fn fallback(probe: &Probe<'_>) -> Identification {
    if probe.len == 0 {
        return Identification {
            format: "empty".into(),
            name: "Empty file".into(),
            mime: "inode/x-empty".into(),
            confidence: 1.0,
            detected_by: DetectedBy::Heuristic,
            ..Identification::default()
        };
    }
    match text_encoding(probe.head, probe.len == probe.head.len() as u64) {
        Some(encoding) => Identification {
            format: "text".into(),
            name: "Text".into(),
            mime: "text/plain".into(),
            family: Some("text.plain".into()),
            confidence: 0.3,
            detected_by: DetectedBy::Heuristic,
            encoding: Some(encoding.into()),
            ..Identification::default()
        },
        None => Identification {
            format: "binary".into(),
            name: "Binary data".into(),
            mime: "application/octet-stream".into(),
            family: Some("binary.unknown".into()),
            confidence: 0.1,
            detected_by: DetectedBy::Heuristic,
            ..Identification::default()
        },
    }
}

/// Guess whether `head` is text, and in which encoding. `complete` says whether
/// `head` is the whole input (otherwise a multi-byte character may be cut).
pub fn text_encoding(head: &[u8], complete: bool) -> Option<&'static str> {
    if head.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Some("utf-8");
    }
    if head.starts_with(&[0xFF, 0xFE]) {
        return Some("utf-16le");
    }
    if head.starts_with(&[0xFE, 0xFF]) {
        return Some("utf-16be");
    }
    if head.contains(&0) {
        return None;
    }
    let control = head.iter().filter(|&&b| b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0c | 0x1b)).count();
    if control * 100 > head.len() {
        return None;
    }
    let utf8_ok = match std::str::from_utf8(head) {
        Ok(_) => true,
        // A character cut at the end of a partial head is fine.
        Err(e) => !complete && e.error_len().is_none() && head.len() - e.valid_up_to() < 4,
    };
    if utf8_ok {
        return Some(if head.is_ascii() { "us-ascii" } else { "utf-8" });
    }
    // Legacy 8-bit text: mostly printable ASCII with some high bytes.
    let printable = head.iter().filter(|&&b| (0x20..0x7f).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r')).count();
    (printable * 100 >= head.len() * 90).then_some("unknown-8bit")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings() {
        assert_eq!(text_encoding(b"hello\n", true), Some("us-ascii"));
        assert_eq!(text_encoding("héllo".as_bytes(), true), Some("utf-8"));
        assert_eq!(text_encoding(&[0xFF, 0xFE, b'h', 0], true), Some("utf-16le"));
        assert_eq!(text_encoding(&[0x7f, b'E', b'L', b'F', 0, 1], true), None);
        // Cut multi-byte char at the end of a partial head is still text.
        assert_eq!(text_encoding(&"é".as_bytes()[..1], false), Some("utf-8"));
        assert_eq!(text_encoding(b"caf\xe9 au lait", true), Some("unknown-8bit"));
    }
}
