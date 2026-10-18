//! The text toolkit: decoding, `wc` statistics, language, keywords, keyword
//! frequency, summaries, dates and sensitive-data patterns.
//!
//! The analyzers in this module run over the text extractors emit with
//! `cx.emit_text(..)`. Extractors reach the helpers through `crate::plugin`
//! (`decode_text`, `parse_date`, `is_secret_key`, …), never directly.

pub(crate) mod analyzers;
pub mod dates;
pub mod decode;
pub mod keywords;
pub mod lang;
pub mod latex;
pub mod license;
pub mod markup;
pub mod sensitive;
pub mod stats;
pub mod summary;
pub mod words;

pub use dates::parse_date;
pub use decode::{Decoded, decode};
pub use stats::WcCounter;

/// Collapse runs of whitespace into single spaces and trim.
pub fn squash_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for w in s.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(w);
    }
    out
}

/// The first `max` characters of `s`, cut at a word boundary in the second
/// half when there is one, with `…` appended when anything was cut.
pub fn truncate_chars(s: &str, max: usize) -> String {
    let Some((cut, _)) = s.char_indices().nth(max) else { return s.to_string() };
    let head = &s[..cut];
    let at = head.rfind(char::is_whitespace).filter(|&i| i > cut / 2).unwrap_or(cut);
    format!("{}…", head[..at].trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn squash_and_truncate() {
        assert_eq!(squash_whitespace("  a \n\t b  c "), "a b c");
        assert_eq!(truncate_chars("short", 10), "short");
        assert_eq!(truncate_chars("one two three four", 12), "one two…");
        assert_eq!(truncate_chars("ééééé", 3), "ééé…");
    }
}
