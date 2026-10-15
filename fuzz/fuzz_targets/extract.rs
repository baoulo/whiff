//! Generic fuzz target. With `WHIFF_FUZZ_EXTRACTOR=<id>` only that extractor
//! runs, with its format forced; otherwise the whole engine (detection
//! included) is fuzzed. Run via `whiff-dev fuzz [<id>]`.
#![no_main]

use std::sync::LazyLock;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use whiff::report::RunStatus;
use whiff::{Engine, Hashes, Limits, Registry};

static ENGINE: LazyLock<Engine> = LazyLock::new(|| {
    let limits = Limits::default()
        .max_read_bytes(16 << 20)
        .file_timeout(Some(Duration::from_secs(5)))
        .extractor_timeout(Some(Duration::from_secs(2)));
    let mut builder = Engine::builder().limits(limits).hashes(Hashes::NONE);
    if let Ok(id) = std::env::var("WHIFF_FUZZ_EXTRACTOR") {
        let registry = Registry::builtin().retain_extractors(|e| e == id);
        let format = registry
            .extractors()
            .next()
            .and_then(|e| e.meta().formats.first())
            .unwrap_or_else(|| panic!("no extractor `{id}` in this build"))
            .id;
        builder = builder.registry(registry).format(format);
    }
    builder.build()
});

fuzz_target!(|data: &[u8]| {
    let report = ENGINE.extract_bytes(Some("fuzz.bin"), data.to_vec());
    // The engine contains panics; turn them back into crashes for libFuzzer.
    for run in &report.diagnostics.extractors {
        assert!(run.status != RunStatus::Internal, "{}: {:?}", run.id, run.error);
    }
});
