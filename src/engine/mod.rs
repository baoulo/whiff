//! The extraction engine: stat → detect → extractors → block decoders →
//! children → analyzers → report.

pub(crate) mod analyzers;
mod options;
mod pipeline;
mod universal;

use std::io::Read;
use std::path::Path;
use std::sync::Arc;

pub use options::{Hashes, Limits, Options, Profile};

use crate::Error;
use crate::plugin::Registry;
use crate::report::Report;

/// Runs extractions. Cheap to share across threads (`&Engine` is `Sync`).
#[derive(Debug, Clone)]
pub struct Engine {
    registry: Registry,
    options: Options,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    /// An engine with every registered extractor and the standard profile.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Configure an engine.
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }

    /// The registry in use.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// The options in use.
    pub fn options(&self) -> &Options {
        &self.options
    }

    /// Describe the file (or directory, link, device…) at `path`.
    ///
    /// Fails only when `path` cannot be inspected at all; every problem inside
    /// the file is recorded in `diagnostics` instead.
    pub fn extract_path(&self, path: impl AsRef<Path>) -> Result<Report, Error> {
        pipeline::extract_path(self, path.as_ref())
    }

    /// Describe in-memory bytes. `name` (a file name) helps detection.
    pub fn extract_bytes(&self, name: Option<&str>, bytes: impl Into<Arc<[u8]>>) -> Report {
        pipeline::extract_bytes(self, name, &bytes.into())
    }

    /// Read `reader` into memory (up to `max_read_bytes`) and describe it.
    pub fn extract_reader(&self, name: Option<&str>, reader: impl Read) -> std::io::Result<Report> {
        let mut buf = Vec::new();
        let limit = self.options.limits.max_read_bytes;
        reader.take(limit.saturating_add(1)).read_to_end(&mut buf)?;
        let truncated = buf.len() as u64 > limit;
        if truncated {
            buf.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        let mut report = self.extract_bytes(name, buf);
        if truncated {
            report.diagnostics.truncated = true;
            report.diagnostics.limits_hit.push("read_bytes".into());
        }
        Ok(report)
    }
}

/// Builder for [`Engine`].
#[derive(Debug, Default)]
pub struct EngineBuilder {
    registry: Option<Registry>,
    options: Options,
    limits_set: bool,
}

impl EngineBuilder {
    /// Profile (also resets limits to the profile's defaults unless set explicitly).
    #[must_use]
    pub fn profile(mut self, profile: Profile) -> Self {
        self.options.profile = profile;
        self
    }

    /// Limits.
    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.options.limits = limits;
        self.limits_set = true;
        self
    }

    /// Hashes to compute.
    #[must_use]
    pub fn hashes(mut self, hashes: Hashes) -> Self {
        self.options.hashes = hashes;
        self
    }

    /// Run only these extractors / groups.
    #[must_use]
    pub fn only(mut self, ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.options.only = ids.into_iter().map(Into::into).collect();
        self
    }

    /// Never run these extractors / groups.
    #[must_use]
    pub fn skip(mut self, ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.options.skip = ids.into_iter().map(Into::into).collect();
        self
    }

    /// Force a format id instead of detecting.
    #[must_use]
    pub fn format(mut self, id: impl Into<String>) -> Self {
        self.options.format = Some(id.into());
        self
    }

    /// Record which source set each normalised field.
    #[must_use]
    pub fn provenance(mut self, on: bool) -> Self {
        self.options.provenance = on;
        self
    }

    /// Use exactly this registry instead of [`Registry::builtin`].
    #[must_use]
    pub fn registry(mut self, registry: Registry) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Replace all options at once.
    #[must_use]
    pub fn options(mut self, options: Options) -> Self {
        self.options = options;
        self.limits_set = true;
        self
    }

    /// Build the engine.
    pub fn build(mut self) -> Engine {
        if !self.limits_set {
            self.options.limits = self.options.profile.limits();
        }
        Engine { registry: self.registry.unwrap_or_else(Registry::builtin), options: self.options }
    }
}
