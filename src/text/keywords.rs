//! Keyword extraction (YAKE) and keyword frequency.
//!
//! YAKE (Campos et al., 2020) scores each term from five local statistics:
//! casing, position, normalised frequency, relatedness to context and spread
//! over sentences. Candidate phrases of one to three words that do not start
//! or end with a stop word are scored from their terms; lower is better.
//! No model or corpus is needed, so it works on a single document.

use std::collections::{HashMap, HashSet};

use unicode_segmentation::UnicodeSegmentation;

use super::words::{Lexicon, is_content_word};

/// Text beyond this is ignored by the keyword extractor.
const MAX_BYTES: usize = 256 * 1024;
const MAX_NGRAM: usize = 3;

#[derive(Default)]
struct Term {
    tf: f64,
    upper: f64,
    capital: f64,
    sentences: Vec<usize>,
    left: HashMap<usize, u32>,
    right: HashMap<usize, u32>,
    stop: bool,
    score: f64,
}

struct Candidate {
    terms: Vec<usize>,
    tf: f64,
    forms: HashMap<String, u32>,
}

/// The `n` best key phrases of `text`, best first.
pub fn extract(text: &str, lex: &Lexicon, n: usize) -> Vec<String> {
    let text = clip(text, MAX_BYTES);
    let mut ids: HashMap<String, usize> = HashMap::new();
    let mut terms: Vec<Term> = Vec::new();
    let mut candidates: HashMap<String, Candidate> = HashMap::new();
    let mut sentence_count = 0usize;

    for (si, sentence) in text.unicode_sentences().enumerate() {
        sentence_count = si + 1;
        let mut first_word = true;
        // Chunks are runs of words between punctuation; phrases never cross them.
        let mut chunk: Vec<(usize, &str)> = Vec::new();
        for token in sentence.split_word_bounds() {
            if token.chars().all(char::is_whitespace) {
                continue;
            }
            if !token.chars().any(char::is_alphanumeric) {
                add_chunk(&chunk, &terms, &mut candidates);
                chunk.clear();
                continue;
            }
            let lower = token.to_lowercase();
            let next = terms.len();
            let id = *ids.entry(lower.clone()).or_insert(next);
            if id == next {
                terms.push(Term { stop: lex.is_stop(&lower) || !is_content_word(&lower), ..Term::default() });
            }
            let t = &mut terms[id];
            t.tf += 1.0;
            let letters: Vec<char> = token.chars().filter(|c| c.is_alphabetic()).collect();
            if letters.len() > 1 && letters.iter().all(|c| c.is_uppercase()) {
                t.upper += 1.0;
            } else if !first_word && token.chars().next().is_some_and(char::is_uppercase) {
                t.capital += 1.0;
            }
            if t.sentences.last() != Some(&si) {
                t.sentences.push(si);
            }
            if let Some(&(prev, _)) = chunk.last() {
                *terms[id].left.entry(prev).or_default() += 1;
                *terms[prev].right.entry(id).or_default() += 1;
            }
            chunk.push((id, token));
            first_word = false;
        }
        add_chunk(&chunk, &terms, &mut candidates);
    }
    if sentence_count == 0 || terms.is_empty() {
        return Vec::new();
    }
    score_terms(&mut terms, sentence_count);

    let mut scored: Vec<(f64, &str, &Candidate)> = candidates
        .iter()
        .map(|(key, c)| {
            let (mut prod, mut sum) = (1.0, 0.0);
            for &t in c.terms.iter().filter(|&&t| !terms[t].stop) {
                prod *= terms[t].score;
                sum += terms[t].score;
            }
            (prod / (c.tf * (1.0 + sum)), key.as_str(), c)
        })
        .collect();
    scored.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(b.1)));

    let mut seen: HashSet<String> = HashSet::new();
    let mut phrases: Vec<Vec<String>> = Vec::new();
    let mut out = Vec::new();
    for (_, key, c) in scored {
        let stems: Vec<String> = key.split(' ').map(|w| lex.stem(w).into_owned()).collect();
        if !seen.insert(stems.join(" ")) {
            continue;
        }
        // Multi-word phrases inside (or around) a better one add nothing:
        // "fishing boats" after "fishing boats return".
        if stems.len() > 1 && phrases.iter().any(|p| contains(p, &stems) || contains(&stems, p)) {
            continue;
        }
        if stems.len() > 1 {
            phrases.push(stems);
        }
        out.push(surface(key, c));
        if out.len() == n {
            break;
        }
    }
    out
}

/// Whether `needle` occurs as a contiguous run in `hay`.
fn contains(hay: &[String], needle: &[String]) -> bool {
    needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
}

fn add_chunk(chunk: &[(usize, &str)], terms: &[Term], candidates: &mut HashMap<String, Candidate>) {
    for start in 0..chunk.len() {
        if terms[chunk[start].0].stop {
            continue;
        }
        for len in 1..=MAX_NGRAM.min(chunk.len() - start) {
            let window = &chunk[start..start + len];
            let last = window[len - 1].0;
            if terms[last].stop {
                continue;
            }
            if len == 1 && window[0].1.chars().count() < 3 {
                continue;
            }
            let key = window.iter().map(|(_, w)| w.to_lowercase()).collect::<Vec<_>>().join(" ");
            let form = window.iter().map(|(_, w)| *w).collect::<Vec<_>>().join(" ");
            let c = candidates.entry(key).or_insert_with(|| Candidate {
                terms: window.iter().map(|(t, _)| *t).collect(),
                tf: 0.0,
                forms: HashMap::new(),
            });
            c.tf += 1.0;
            *c.forms.entry(form).or_default() += 1;
        }
    }
}

fn score_terms(terms: &mut [Term], sentence_count: usize) {
    let tfs: Vec<f64> = terms.iter().filter(|t| !t.stop).map(|t| t.tf).collect();
    let (mean, std) = mean_std(&tfs);
    let max_tf = terms.iter().map(|t| t.tf).fold(1.0, f64::max);
    for t in terms.iter_mut() {
        let casing = t.upper.max(t.capital) / (1.0 + t.tf.ln());
        let median = median(&t.sentences);
        let position = (3.0 + median).ln().ln();
        let frequency = t.tf / (mean + std).max(1.0);
        let ratio = |m: &HashMap<usize, u32>| {
            let all: u32 = m.values().sum();
            if all == 0 { 0.0 } else { m.len() as f64 / f64::from(all) }
        };
        let relatedness = 1.0 + (ratio(&t.left) + ratio(&t.right)) * (t.tf / max_tf);
        let spread = t.sentences.len() as f64 / sentence_count as f64;
        t.score = (relatedness * position) / (casing + frequency / relatedness + spread / relatedness);
    }
}

fn mean_std(v: &[f64]) -> (f64, f64) {
    if v.is_empty() {
        return (0.0, 0.0);
    }
    let n = v.len() as f64;
    let mean = v.iter().sum::<f64>() / n;
    let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    (mean, var.sqrt())
}

fn median(v: &[usize]) -> f64 {
    match v.len() {
        0 => 0.0,
        n if n % 2 == 1 => v[n / 2] as f64,
        n => (v[n / 2 - 1] + v[n / 2]) as f64 / 2.0,
    }
}

/// The most frequent spelling, lowercased unless it is an acronym or proper
/// noun everywhere it occurs.
fn surface(key: &str, c: &Candidate) -> String {
    let mut forms: Vec<(&String, &u32)> = c.forms.iter().collect();
    forms.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let all_capitalised = c.forms.keys().all(|f| f.chars().next().is_some_and(char::is_uppercase));
    match forms.first() {
        Some((form, _)) if all_capitalised => (*form).clone(),
        _ => key.to_string(),
    }
}

/// The `n` most frequent content words (grouped by stem) with their counts.
pub fn frequency(text: &str, lex: &Lexicon, n: usize) -> Vec<(String, u64)> {
    let mut by_stem: HashMap<String, (u64, HashMap<String, u64>)> = HashMap::new();
    for w in clip(text, 4 * MAX_BYTES).unicode_words() {
        let lower = w.to_lowercase();
        if lower.chars().count() < 3 || !is_content_word(&lower) || lex.is_stop(&lower) {
            continue;
        }
        let stem = lex.stem(&lower).into_owned();
        let e = by_stem.entry(stem).or_default();
        e.0 += 1;
        *e.1.entry(lower).or_default() += 1;
    }
    let mut rows: Vec<(String, u64)> = by_stem
        .into_values()
        .filter(|(count, _)| *count > 1)
        .map(|(count, forms)| {
            let form = forms.into_iter().max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0))).map(|f| f.0);
            (form.unwrap_or_default(), count)
        })
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(n);
    rows
}

fn clip(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "Fishing boats return to the harbour at dusk. The harbour master counts the boats. \
        Fishing boats unload their catch while gulls circle above the harbour. \
        In the morning the fishing fleet leaves again, and the harbour is quiet. \
        Tourists photograph the boats; the harbour cafe serves fish soup.";

    #[test]
    fn yake_finds_the_topic() {
        let lex = Lexicon::for_language(Some("en"));
        let kw = extract(TEXT, &lex, 5);
        assert!(kw.iter().any(|k| k.contains("harbour")), "{kw:?}");
        assert!(kw.iter().any(|k| k.contains("boats")), "{kw:?}");
        assert!(kw.iter().all(|k| !k.starts_with("the ")), "{kw:?}");
        assert_eq!(extract("", &lex, 5), Vec::<String>::new());
    }

    #[test]
    fn frequency_groups_by_stem() {
        let lex = Lexicon::for_language(Some("en"));
        let f = frequency(TEXT, &lex, 3);
        assert_eq!(f[0], ("harbour".to_string(), 5));
        assert_eq!(f[1].0, "boats");
        assert_eq!(f[1].1, 4);
    }
}
