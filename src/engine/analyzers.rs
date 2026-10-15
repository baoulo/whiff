//! Analyzers that ship with the engine itself.

use crate::plugin::{Analyzer, AnalyzerStage, ExtractError, Options, Report, TextStore};

/// Fills `temporal.earliest` / `temporal.latest` from zone-aware content dates.
pub struct TemporalRange;

impl Analyzer for TemporalRange {
    fn id(&self) -> &'static str {
        "temporal.range"
    }

    fn stage(&self) -> AnalyzerStage {
        AnalyzerStage::Reconcile
    }

    fn run(&self, report: &mut Report, _text: &TextStore, _options: &Options) -> Result<(), ExtractError> {
        let mut stamps: Vec<jiff::Timestamp> =
            report.temporal.content.iter().filter(|d| d.tz_known).filter_map(|d| d.value.parse().ok()).collect();
        stamps.sort();
        report.temporal.earliest = stamps.first().map(ToString::to_string);
        report.temporal.latest = stamps.last().map(ToString::to_string);
        Ok(())
    }
}

crate::register_analyzer!(TemporalRange);
