//! Format extractors, one directory per family group and one file per format.
//!
//! Groups are gated by cargo features, matching the "Feature" column of
//! `docs/metadata-extracted.md`:
//!
//! | Feature | Groups |
//! |---|---|
//! | `common` (default) | text, data, code, doc, email, image, audio, video, archive, package, exec, crypto, db, font, web, apple, binary |
//! | `geo` | geo |
//! | `science` | science |
//! | `data` | columnar |
//! | `cad` | cad |
//! | `forensics` | forensics |
//! | `games` | games |
//!
//! Format modules import only `crate::plugin::*`. Add a format with
//! `cargo run --features dev --bin whiff-dev -- new-extractor …`, which also
//! adds the `mod` line here.

// whiff-dev: group modules below this line
#[cfg(feature = "common")]
pub(crate) mod audio;
#[cfg(feature = "common")]
pub(crate) mod binary;
#[cfg(feature = "common")]
pub(crate) mod code;
#[cfg(feature = "common")]
pub(crate) mod data;
#[cfg(feature = "common")]
pub(crate) mod doc;
#[cfg(feature = "common")]
pub(crate) mod email;
#[cfg(feature = "common")]
pub(crate) mod image;
#[cfg(feature = "common")]
pub(crate) mod text;
