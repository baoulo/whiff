//! Natural-language identification (`whatlang`), reported as ISO 639-1
//! codes where one exists.

use whatlang::Lang;

/// A detected language.
#[derive(Debug, Clone, PartialEq)]
pub struct Detected {
    /// ISO 639-1 code (`en`), or ISO 639-3 (`cmn`) when there is no two-letter code.
    pub code: &'static str,
    /// Confidence in `0.0..=1.0`.
    pub confidence: f64,
}

/// Fewer letters than this give unreliable guesses.
const MIN_LETTERS: usize = 40;

/// Detect the language of `text`; `None` when unsure or too short.
pub fn detect(text: &str) -> Option<Detected> {
    let sample = sample(text, 16 * 1024);
    if sample.chars().filter(|c| c.is_alphabetic()).count() < MIN_LETTERS {
        return None;
    }
    let info = whatlang::detect(sample)?;
    let confidence = (info.confidence() * 1000.0).round() / 1000.0;
    (info.is_reliable() || confidence >= 0.5).then(|| Detected { code: iso639_1(info.lang()), confidence })
}

/// At most `max` bytes, cut on a char boundary.
fn sample(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// ISO 639-1 code for a `whatlang` language.
pub fn iso639_1(lang: Lang) -> &'static str {
    match lang {
        Lang::Epo => "eo",
        Lang::Eng => "en",
        Lang::Rus => "ru",
        Lang::Cmn => "zh",
        Lang::Spa => "es",
        Lang::Por => "pt",
        Lang::Ita => "it",
        Lang::Ben => "bn",
        Lang::Fra => "fr",
        Lang::Deu => "de",
        Lang::Ukr => "uk",
        Lang::Kat => "ka",
        Lang::Ara => "ar",
        Lang::Hin => "hi",
        Lang::Jpn => "ja",
        Lang::Heb => "he",
        Lang::Yid => "yi",
        Lang::Pol => "pl",
        Lang::Amh => "am",
        Lang::Jav => "jv",
        Lang::Kor => "ko",
        Lang::Nob => "nb",
        Lang::Dan => "da",
        Lang::Swe => "sv",
        Lang::Fin => "fi",
        Lang::Tur => "tr",
        Lang::Nld => "nl",
        Lang::Hun => "hu",
        Lang::Ces => "cs",
        Lang::Ell => "el",
        Lang::Bul => "bg",
        Lang::Bel => "be",
        Lang::Mar => "mr",
        Lang::Kan => "kn",
        Lang::Ron => "ro",
        Lang::Slv => "sl",
        Lang::Hrv => "hr",
        Lang::Srp => "sr",
        Lang::Mkd => "mk",
        Lang::Lit => "lt",
        Lang::Lav => "lv",
        Lang::Est => "et",
        Lang::Tam => "ta",
        Lang::Vie => "vi",
        Lang::Urd => "ur",
        Lang::Tha => "th",
        Lang::Guj => "gu",
        Lang::Uzb => "uz",
        Lang::Pan => "pa",
        Lang::Aze => "az",
        Lang::Ind => "id",
        Lang::Tel => "te",
        Lang::Pes => "fa",
        Lang::Mal => "ml",
        Lang::Ori => "or",
        Lang::Mya => "my",
        Lang::Nep => "ne",
        Lang::Sin => "si",
        Lang::Khm => "km",
        Lang::Tuk => "tk",
        Lang::Aka => "ak",
        Lang::Zul => "zu",
        Lang::Sna => "sn",
        Lang::Afr => "af",
        Lang::Lat => "la",
        Lang::Slk => "sk",
        Lang::Cat => "ca",
        Lang::Tgl => "tl",
        Lang::Hye => "hy",
        Lang::Cym => "cy",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_languages() {
        let en = "The quick brown fox jumps over the lazy dog while the farmer watches from the porch.";
        assert_eq!(detect(en).map(|d| d.code), Some("en"));
        let de = "Der schnelle braune Fuchs springt über den faulen Hund, während der Bauer zusieht.";
        assert_eq!(detect(de).map(|d| d.code), Some("de"));
        assert_eq!(detect("too short"), None);
        for lang in Lang::all() {
            assert_ne!(iso639_1(*lang), "");
        }
    }
}
