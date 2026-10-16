//! Shared decoders for metadata blocks embedded in other formats: EXIF,
//! XMP (including VRA Core), IPTC IIM, ICC profiles and Photoshop image
//! resources, plus the MWG analyzer that turns them into normalised title,
//! creators, rights, dates and location.
//!
//! Container extractors find the blocks (`cx.emit_block(BlockKind::EXIF, …)`);
//! the decoders here write each standard's raw fields to `metadata.<standard>`
//! with the standard's own names. Normalised sections are filled only by
//! [`mwg::Mwg`], following the Metadata Working Group precedence rules.

pub mod exif;
pub mod icc;
pub mod iptc;
pub mod irb;
pub mod mwg;
pub mod xmp;

use serde_json::{Value, json};

/// Strings longer than this are cut in `metadata`.
pub(crate) const MAX_STRING: usize = 8 * 1024;
/// Arrays longer than this are summarised in `metadata`.
pub(crate) const MAX_ARRAY: usize = 64;

/// A string value for `metadata`, trimmed of NULs and padding and capped.
pub(crate) fn text_value(s: &str) -> Value {
    let t = s.trim_matches(|c: char| c == '\0' || c.is_whitespace());
    json!(crate::text::truncate_chars(t, MAX_STRING))
}

/// Binary payloads are never inlined.
pub(crate) fn binary(n: usize) -> Value {
    json!({ "binary_bytes": n })
}

/// Decode bytes that are UTF-8 when valid, otherwise Windows-1252 (Latin-1):
/// the rule for legacy metadata text (PNG `tEXt`, IPTC, EXIF ASCII).
pub fn latin1_or_utf8(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => encoding_rs::WINDOWS_1252.decode_without_bom_handling(b).0.into_owned(),
    }
}
