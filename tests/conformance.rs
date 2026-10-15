//! Runs the conformance suite (see `whiff::plugin::conformance`) over every
//! extractor compiled into this build. Contributors write no test code for it.

use std::path::Path;

use whiff::plugin::{Registry, conformance};

#[test]
fn every_registered_extractor_conforms() {
    let registry = Registry::builtin();
    let outcome = conformance::check_registry(&registry, Path::new(env!("CARGO_MANIFEST_DIR")));
    let failures: Vec<String> = outcome.failures.iter().map(ToString::to_string).collect();
    assert!(
        failures.is_empty(),
        "{} conformance failure(s) across {} extractor/format pairs:\n{}",
        failures.len(),
        outcome.checked,
        failures.join("\n")
    );
    eprintln!("conformance: {} extractor/format pairs checked", outcome.checked);
}
