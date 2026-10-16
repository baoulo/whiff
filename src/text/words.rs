//! Words, stop words and stems for one language.

use std::borrow::Cow;
use std::collections::HashSet;

use rust_stemmers::{Algorithm, Stemmer};

/// Stop words and stemmer for one language.
pub struct Lexicon {
    stop: HashSet<&'static str>,
    stemmer: Option<Stemmer>,
}

impl Lexicon {
    /// The lexicon for an ISO 639-1 code; English when unknown.
    pub fn for_language(code: Option<&str>) -> Self {
        let code = code.unwrap_or("en");
        let words = stop_words::lookup(code).or_else(|| stop_words::lookup("en")).unwrap_or(&[]);
        Self { stop: words.iter().copied().collect(), stemmer: algorithm(code).map(Stemmer::create) }
    }

    /// Whether the lowercase word is a stop word.
    pub fn is_stop(&self, lower: &str) -> bool {
        self.stop.contains(lower)
    }

    /// The stem of a lowercase word (the word itself when there is no stemmer).
    pub fn stem<'a>(&self, lower: &'a str) -> Cow<'a, str> {
        match &self.stemmer {
            Some(s) => s.stem(lower),
            None => Cow::Borrowed(lower),
        }
    }
}

/// Whether a word can be a keyword: contains a letter, is at least two
/// characters long, and is not mostly digits.
pub fn is_content_word(w: &str) -> bool {
    let mut letters = 0usize;
    let mut digits = 0usize;
    let mut chars = 0usize;
    for c in w.chars() {
        chars += 1;
        if c.is_alphabetic() {
            letters += 1;
        } else if c.is_numeric() {
            digits += 1;
        }
    }
    chars >= 2 && letters > 0 && digits <= letters
}

fn algorithm(code: &str) -> Option<Algorithm> {
    Some(match code {
        "ar" => Algorithm::Arabic,
        "da" => Algorithm::Danish,
        "nl" => Algorithm::Dutch,
        "en" => Algorithm::English,
        "fi" => Algorithm::Finnish,
        "fr" => Algorithm::French,
        "de" => Algorithm::German,
        "el" => Algorithm::Greek,
        "hu" => Algorithm::Hungarian,
        "it" => Algorithm::Italian,
        "nb" | "no" => Algorithm::Norwegian,
        "pt" => Algorithm::Portuguese,
        "ro" => Algorithm::Romanian,
        "ru" => Algorithm::Russian,
        "es" => Algorithm::Spanish,
        "sv" => Algorithm::Swedish,
        "ta" => Algorithm::Tamil,
        "tr" => Algorithm::Turkish,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexicon() {
        let en = Lexicon::for_language(Some("en"));
        assert!(en.is_stop("the"));
        assert!(!en.is_stop("harbour"));
        assert_eq!(en.stem("boats"), "boat");
        let unknown = Lexicon::for_language(Some("xx"));
        assert!(unknown.is_stop("the"));
        assert!(is_content_word("rust"));
        assert!(is_content_word("utf8"));
        assert!(!is_content_word("2026"));
        assert!(!is_content_word("a"));
    }
}
