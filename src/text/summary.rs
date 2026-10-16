//! Extractive summary with `TextRank`: sentences are nodes, edges are TF-IDF
//! cosine similarities, and `PageRank` picks the most central sentences, which
//! are returned in document order.

use std::collections::HashMap;

use unicode_segmentation::UnicodeSegmentation;

use super::words::{Lexicon, is_content_word};

const MAX_SENTENCES: usize = 300;
const ITERATIONS: usize = 30;
const DAMPING: f64 = 0.85;

/// A summary of `text` of up to `max_sentences` sentences, or `None` when
/// the text is too short to need one.
pub fn summarize(text: &str, lex: &Lexicon, max_sentences: usize) -> Option<String> {
    let sample = sample(text);
    let sentences: Vec<&str> = sample
        .unicode_sentences()
        .map(str::trim)
        .filter(|s| (5..=80).contains(&s.unicode_words().count()))
        .take(MAX_SENTENCES)
        .collect();
    if sentences.len() <= max_sentences {
        return None;
    }
    let bags: Vec<HashMap<String, f64>> = sentences.iter().map(|s| bag(s, lex)).collect();
    let mut df: HashMap<&str, f64> = HashMap::new();
    for b in &bags {
        for w in b.keys() {
            *df.entry(w.as_str()).or_default() += 1.0;
        }
    }
    let n = bags.len() as f64;
    let vectors: Vec<HashMap<&str, f64>> = bags
        .iter()
        .map(|b| b.iter().map(|(w, tf)| (w.as_str(), tf * (1.0 + n / df[w.as_str()]).ln())).collect())
        .collect();
    let norms: Vec<f64> = vectors.iter().map(|v| v.values().map(|x| x * x).sum::<f64>().sqrt()).collect();

    let count = vectors.len();
    let mut weights = vec![vec![0.0; count]; count];
    for i in 0..count {
        for j in (i + 1)..count {
            if norms[i] == 0.0 || norms[j] == 0.0 {
                continue;
            }
            let dot: f64 = vectors[i].iter().filter_map(|(w, x)| vectors[j].get(w).map(|y| x * y)).sum();
            let sim = dot / (norms[i] * norms[j]);
            weights[i][j] = sim;
            weights[j][i] = sim;
        }
    }
    let out_sum: Vec<f64> = weights.iter().map(|row| row.iter().sum()).collect();
    let mut rank = vec![1.0 / count as f64; count];
    for _ in 0..ITERATIONS {
        let next: Vec<f64> = (0..count)
            .map(|i| {
                let incoming: f64 =
                    (0..count).filter(|&j| out_sum[j] > 0.0).map(|j| weights[j][i] / out_sum[j] * rank[j]).sum();
                (1.0 - DAMPING) / count as f64 + DAMPING * incoming
            })
            .collect();
        rank = next;
    }
    let mut order: Vec<usize> = (0..count).collect();
    order.sort_by(|&a, &b| rank[b].total_cmp(&rank[a]).then(a.cmp(&b)));
    let mut picked: Vec<usize> = order.into_iter().take(max_sentences).collect();
    picked.sort_unstable();
    let summary = picked.iter().map(|&i| super::squash_whitespace(sentences[i])).collect::<Vec<_>>().join(" ");
    Some(super::truncate_chars(&summary, 800))
}

fn bag(sentence: &str, lex: &Lexicon) -> HashMap<String, f64> {
    let mut b = HashMap::new();
    for w in sentence.unicode_words() {
        let lower = w.to_lowercase();
        if is_content_word(&lower) && !lex.is_stop(&lower) {
            *b.entry(lex.stem(&lower).into_owned()).or_default() += 1.0;
        }
    }
    b
}

/// The first 32 KiB plus four evenly spaced 8 KiB windows of longer texts.
fn sample(text: &str) -> String {
    const HEAD: usize = 32 * 1024;
    const WINDOW: usize = 8 * 1024;
    if text.len() <= HEAD + 4 * WINDOW {
        return text.to_string();
    }
    let floor = |mut i: usize| {
        while !text.is_char_boundary(i) {
            i -= 1;
        }
        i
    };
    let mut out = text[..floor(HEAD)].to_string();
    let step = (text.len() - HEAD) / 4;
    for k in 0..4 {
        let start = floor(HEAD + k * step);
        let end = floor((start + WINDOW).min(text.len()));
        // Start at the next sentence so windows do not begin mid-sentence.
        let window = &text[start..end];
        let skip = window.find(". ").map_or(0, |i| i + 2);
        out.push('\n');
        out.push_str(&window[skip..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_central_sentences_in_order() {
        let text = "Rust is a systems programming language focused on safety. \
            The weather in the valley was mild that spring morning. \
            Rust prevents memory safety bugs at compile time with ownership. \
            Ownership and borrowing make Rust programs memory safe without a garbage collector. \
            A small dog barked at the passing bicycle on the road. \
            Many companies adopt Rust for safety critical systems programming.";
        let lex = Lexicon::for_language(Some("en"));
        let s = summarize(text, &lex, 2).unwrap();
        assert!(s.contains("Rust"), "{s}");
        assert!(!s.contains("dog"), "{s}");
        assert!(summarize("One short sentence here.", &lex, 3).is_none());
    }
}
