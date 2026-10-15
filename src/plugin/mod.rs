//! The contributor API. Format modules import only `whiff::plugin::*`
//! (inside the crate: `crate::plugin::*`).
//!
//! An extractor is a unit struct implementing [`Extractor`] plus one
//! `crate::register_extractor!(Name);` line in its module under `src/formats/`.
//! `build.rs` turns those lines into the built-in registry. Shared decoders
//! for embedded metadata blocks implement [`BlockDecoder`]; whole-report
//! post-processing implements [`Analyzer`].
//!
//! Extractors defined in *other* crates are added explicitly:
//! `Engine::builder().registry(Registry::builtin().with(MyExtractor))`.

pub mod conformance;
pub(crate) mod context;
mod registry;
mod spec;
#[doc(hidden)]
pub mod testing;
mod text;

pub use context::{ContentWriter, Context, ImageWriter, PhysicalWriter, RightsWriter, SecurityWriter, TemporalWriter};
pub use registry::Registry;
pub use spec::{BlockKind, Cost, ExtractorMeta, FormatSpec, Magic, Probe, Sniff};
pub use text::{TextChunk, TextRole, TextStore};

pub use crate::engine::Options;
pub use crate::error::ExtractError;
pub use crate::io::{BoundedReader, ByteReader, Source, SourceError};
pub use crate::report::{DateField, Map, Report};

/// Extracts information from one or more formats.
///
/// Implementations must never panic on bad input (the engine contains panics,
/// but reports them as bugs), never print, and write output only through the
/// [`Context`].
pub trait Extractor: Send + Sync + 'static {
    /// Static description: id, version, formats, cost.
    fn meta(&self) -> &'static ExtractorMeta;

    /// Optional content check beyond magic, e.g. ZIP→DOCX by
    /// `[Content_Types].xml`, XML→SVG by root element, text→Python by shebang.
    /// Gets the head/tail windows only, so it must be cheap.
    fn sniff(&self, _probe: &Probe<'_>) -> Option<Sniff> {
        None
    }

    /// Do the work.
    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError>;
}

/// Decodes one kind of embedded metadata block (EXIF, XMP, IPTC, ICC, …),
/// wherever a container extractor found it.
pub trait BlockDecoder: Send + Sync + 'static {
    /// Block kind handled.
    fn kind(&self) -> BlockKind;
    /// Decoder id, e.g. `meta.exif`.
    fn id(&self) -> &'static str;
    /// Output version (bump when output changes).
    fn version(&self) -> u32 {
        1
    }
    /// Decode `data` into the report.
    fn decode(&self, data: &[u8], cx: &mut Context<'_>) -> Result<(), ExtractError>;
}

/// When an analyzer runs relative to the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnalyzerStage {
    /// Text statistics, language, keywords, outline, summary.
    Text,
    /// Merging values from different sources into the normalised sections.
    Reconcile,
    /// Redaction of secrets and personal data.
    Privacy,
    /// Final shaping (LLM view).
    Output,
}

/// Post-processes the whole report after all extractors and decoders ran.
pub trait Analyzer: Send + Sync + 'static {
    /// Analyzer id, e.g. `text.stats`.
    fn id(&self) -> &'static str;
    /// Output version.
    fn version(&self) -> u32 {
        1
    }
    /// Stage; analyzers run in stage order, then by id.
    fn stage(&self) -> AnalyzerStage;
    /// Run over the report and the text collected from extractors.
    fn run(&self, report: &mut Report, text: &TextStore, options: &Options) -> Result<(), ExtractError>;
}

/// Mark a unit struct as a built-in [`Extractor`]. `build.rs` collects these
/// lines (one per line, `crate::register_extractor!(Name);`) into
/// [`Registry::builtin`]; the macro itself only checks the trait is implemented.
#[doc(hidden)]
#[macro_export]
macro_rules! register_extractor {
    ($t:ident) => {
        const _: () = {
            const fn registered<T: $crate::plugin::Extractor>() {}
            registered::<$t>();
        };
    };
}

/// Mark a unit struct as a built-in [`BlockDecoder`] (see [`register_extractor!`]).
#[doc(hidden)]
#[macro_export]
macro_rules! register_block_decoder {
    ($t:ident) => {
        const _: () = {
            const fn registered<T: $crate::plugin::BlockDecoder>() {}
            registered::<$t>();
        };
    };
}

/// Mark a unit struct as a built-in [`Analyzer`] (see [`register_extractor!`]).
#[doc(hidden)]
#[macro_export]
macro_rules! register_analyzer {
    ($t:ident) => {
        const _: () = {
            const fn registered<T: $crate::plugin::Analyzer>() {}
            registered::<$t>();
        };
    };
}

pub use crate::{fixture_tests, register_analyzer, register_block_decoder, register_extractor};
