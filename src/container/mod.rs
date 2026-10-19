//! Readers for the container formats documents are built on: ZIP (OOXML,
//! OpenDocument, EPUB, CBZ) and the OLE2 compound file (legacy Office,
//! Outlook `.msg`, MSI), plus the property sets (`\x05SummaryInformation`)
//! stored inside compound files.
//!
//! They read through a [`Source`](crate::io::Source), so every read is charged
//! to the budget, and decompress through
//! [`Context::inflate`](crate::plugin::Context::inflate), so ZIP entries count
//! against the decompression budget. Extractors reach them through
//! [`crate::plugin`].

pub mod cfb;
pub mod oleps;
pub mod zip;
