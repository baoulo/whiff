//! The conformance suite: checks every registered extractor without the
//! contributor writing any test code. `tests/conformance.rs` runs it over
//! [`Registry::builtin`](super::Registry::builtin).
//!
//! For each extractor and each declared format:
//!
//! * **fixtures** — at least one sample in `tests/fixtures/<format>/`;
//! * **detection** — each fixture is detected as that format;
//! * **schema** — reports round-trip through the `whiff/1` model;
//! * **determinism** — two runs give identical (redacted) JSON;
//! * **field names** — keys in `format.<id>` are `snake_case`;
//! * **robustness** — empty, 1-byte, magic-only, random, truncated and
//!   bit-flipped inputs never panic;
//! * **budget** — a 4 KiB read budget never causes a panic;
//! * **magic** — the declared magic matches all own fixtures and at most 5 %
//!   of other formats' fixtures.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{Extractor, FormatSpec, Registry};
use crate::report::{Report, RunStatus};
use crate::{Engine, Limits, Options};

use super::testing::{fixture_files, redact};

/// One failed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// Extractor id.
    pub extractor: String,
    /// Format id.
    pub format: String,
    /// Check name.
    pub check: &'static str,
    /// What went wrong.
    pub detail: String,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {} / {}: {}", self.check, self.extractor, self.format, self.detail)
    }
}

/// Result of a conformance run.
#[derive(Debug, Default)]
pub struct Outcome {
    /// (extractor, format) pairs checked.
    pub checked: usize,
    /// Everything that failed.
    pub failures: Vec<Failure>,
}

/// Check every extractor in `registry`. `manifest_dir` holds `tests/fixtures/`.
pub fn check_registry(registry: &Registry, manifest_dir: &Path) -> Outcome {
    let all_fixtures: Vec<(&'static str, PathBuf)> = registry
        .formats()
        .flat_map(|(spec, _)| fixture_files(manifest_dir, spec.id).into_iter().map(move |p| (spec.id, p)))
        .collect();
    let mut out = Outcome::default();
    for extractor in registry.extractors() {
        for spec in extractor.meta().formats {
            out.checked += 1;
            out.failures.extend(check_format(registry, extractor, spec, manifest_dir, &all_fixtures));
        }
    }
    out
}

fn engine_for(registry: &Registry, extractor_id: &str, options: Options) -> Engine {
    let only_this = registry.clone().retain_extractors(|id| id == extractor_id);
    Engine::builder().registry(only_this).options(options).build()
}

fn test_limits() -> Limits {
    Limits::default().file_timeout(Some(Duration::from_secs(10))).extractor_timeout(Some(Duration::from_secs(5)))
}

fn check_format(
    registry: &Registry,
    extractor: &dyn Extractor,
    spec: &'static FormatSpec,
    manifest_dir: &Path,
    all_fixtures: &[(&'static str, PathBuf)],
) -> Vec<Failure> {
    let id = extractor.meta().id;
    let mut failures = Vec::new();
    let mut fail = |check: &'static str, detail: String| {
        failures.push(Failure { extractor: id.into(), format: spec.id.into(), check, detail });
    };

    let fixtures = fixture_files(manifest_dir, spec.id);
    if fixtures.is_empty() {
        fail("fixtures", format!("no files in tests/fixtures/{}/", spec.id));
    }

    let natural = engine_for(registry, id, Options { limits: test_limits(), ..Options::default() });
    let forced = engine_for(
        registry,
        id,
        Options { limits: test_limits(), format: Some(spec.id.to_string()), ..Options::default() },
    );

    let mut fixture_bytes = Vec::new();
    for path in &fixtures {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let (Ok(a), Ok(b)) = (natural.extract_path(path), natural.extract_path(path)) else {
            fail("fixtures", format!("{name}: unreadable"));
            continue;
        };
        if a.identification.format != spec.id {
            fail("detection", format!("{name}: detected as `{}`", a.identification.format));
        }
        if let Some(run) = panicked(&a) {
            fail("robustness", format!("{name}: {run}"));
        }
        if serde_json::to_value(&a).ok().and_then(|v| serde_json::from_value::<Report>(v).ok()).as_ref() != Some(&a) {
            fail("schema", format!("{name}: report does not round-trip through the whiff/1 model"));
        }
        let (mut ra, mut rb) = (a.clone(), b);
        redact(&mut ra);
        redact(&mut rb);
        if ra != rb {
            fail("determinism", format!("{name}: two runs differ"));
        }
        if let Some(serde_json::Value::Object(map)) = a.format.get(spec.id) {
            for key in map.keys().filter(|k| !is_snake_case(k)) {
                fail("field_names", format!("{name}: format.{}.{key} is not snake_case", spec.id));
            }
        }
        if !spec.magic.is_empty() {
            if let Ok(data) = std::fs::read(path) {
                if !spec.magic.iter().any(|m| m.matches(&data)) {
                    fail("magic", format!("{name}: declared magic does not match"));
                }
                fixture_bytes.push((name, data));
            }
        } else if let Ok(data) = std::fs::read(path) {
            fixture_bytes.push((name, data));
        }
    }

    robustness(&forced, spec, &fixture_bytes, &mut fail);

    // Budget honesty: a tiny read budget must end in an error, not a panic.
    let tight = engine_for(
        registry,
        id,
        Options { limits: test_limits().max_read_bytes(4096), format: Some(spec.id.to_string()), ..Options::default() },
    );
    for (name, data) in &fixture_bytes {
        if let Some(run) = panicked(&tight.extract_bytes(Some(name), data.clone())) {
            fail("budget", format!("{name} with 4 KiB budget: {run}"));
        }
    }

    // Magic sanity: not matching (almost) everything else.
    if !spec.magic.is_empty() {
        let others: Vec<&PathBuf> = all_fixtures.iter().filter(|(f, _)| *f != spec.id).map(|(_, p)| p).collect();
        let hits =
            others.iter().filter(|p| std::fs::read(p).is_ok_and(|d| spec.magic.iter().any(|m| m.matches(&d)))).count();
        if !others.is_empty() && hits * 20 > others.len() {
            fail("magic", format!("matches {hits} of {} other formats' fixtures", others.len()));
        }
    }
    failures
}

/// Hostile variants, with the format forced so the extractor runs.
fn robustness(
    forced: &Engine,
    spec: &'static FormatSpec,
    fixture_bytes: &[(String, Vec<u8>)],
    fail: &mut impl FnMut(&'static str, String),
) {
    let mut inputs: Vec<(String, Vec<u8>)> = vec![("empty".into(), Vec::new()), ("one byte".into(), vec![0])];
    if let Some(m) = spec.magic.first() {
        let mut v = vec![0u8; m.offset];
        v.extend_from_slice(m.bytes);
        inputs.push(("magic only".into(), v));
    }
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15 ^ spec.id.len() as u64);
    inputs.push(("random 256 KiB".into(), (0..256 * 1024).map(|_| rng.next_u8()).collect()));
    for (name, data) in fixture_bytes {
        for i in 1..=16usize {
            let cut = data.len() * i / 17;
            inputs.push((format!("{name} truncated at {cut}"), data[..cut].to_vec()));
        }
        for i in 0..16 {
            let mut v = data.clone();
            if !v.is_empty() {
                let pos = usize::try_from(rng.next() % v.len() as u64).unwrap_or(0);
                v[pos] ^= 1 << (i % 8);
            }
            inputs.push((format!("{name} bit-flip #{i}"), v));
        }
    }
    for (label, data) in inputs {
        let report = forced.extract_bytes(Some(&format!("input.{}", spec.extensions.first().unwrap_or(&"bin"))), data);
        if let Some(run) = panicked(&report) {
            fail("robustness", format!("{label}: {run}"));
        }
    }
}

fn panicked(report: &Report) -> Option<String> {
    report
        .diagnostics
        .extractors
        .iter()
        .find(|r| r.status == RunStatus::Internal)
        .map(|r| format!("{}: {}", r.id, r.error.as_deref().unwrap_or("internal error")))
        .or_else(|| report.embedded.iter().find_map(panicked))
}

fn is_snake_case(key: &str) -> bool {
    key.starts_with(|c: char| c.is_ascii_lowercase())
        && key.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Deterministic PRNG so failures reproduce.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_u8(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
}

#[cfg(test)]
mod tests {
    use super::is_snake_case;

    #[test]
    fn snake_case() {
        assert!(is_snake_case("quality_estimate"));
        assert!(is_snake_case("mpf_images2"));
        assert!(!is_snake_case("QualityEstimate"));
        assert!(!is_snake_case("_x"));
        assert!(!is_snake_case("has-dash"));
    }
}
