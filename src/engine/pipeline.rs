use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;

use super::Engine;
use super::universal::{file_kind, fill_from_metadata, integrity_for_bytes, integrity_for_file};
use crate::Error;
use crate::detect;
use crate::io::{Budget, BytesSource, FileSource, Source};
use crate::plugin::context::{PendingBlock, PendingChild};
use crate::plugin::{Context, Probe, TextStore};
use crate::report::{ExtractorRun, FileKind, Map, Report, RunStatus, SourceInfo};

/// Wall-clock stopwatch; reads 0 on `wasm32-unknown-unknown` (no clock).
struct Stopwatch(#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))] std::time::Instant);

impl Stopwatch {
    fn start() -> Self {
        Self(
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            std::time::Instant::now(),
        )
    }

    fn ms(&self) -> f64 {
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            (self.0.elapsed().as_secs_f64() * 1e6).round() / 1e3
        }
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            0.0
        }
    }
}

fn new_report(engine: &Engine, source: SourceInfo) -> Report {
    let mut report = Report::new(engine.options.profile);
    report.source = source;
    if engine.options.provenance {
        report.diagnostics.provenance = Some(Map::new());
    }
    report
}

fn budget_for(engine: &Engine) -> Budget {
    let l = &engine.options.limits;
    Budget::new(l.max_read_bytes, l.max_decompressed_bytes, l.file_timeout)
}

pub(super) fn extract_path(engine: &Engine, path: &Path) -> Result<Report, Error> {
    let clock = Stopwatch::start();
    let io_err = |source| Error::Io { path: path.to_path_buf(), source };
    let lmeta = std::fs::symlink_metadata(path).map_err(io_err)?;
    let name =
        path.file_name().map_or_else(|| path.to_string_lossy().into_owned(), |n| n.to_string_lossy().into_owned());
    let mut report = new_report(engine, SourceInfo::from_name(Some(path.to_string_lossy().into_owned()), &name));
    let budget = budget_for(engine);

    let mut meta = lmeta.clone();
    if lmeta.file_type().is_symlink() {
        report.system.kind = FileKind::Symlink;
        report.system.symlink_target = std::fs::read_link(path).ok().map(|t| t.to_string_lossy().into_owned());
        match std::fs::metadata(path) {
            Ok(m) => meta = m,
            Err(e) => {
                fill_from_metadata(&mut report, &lmeta, path);
                report.identification = detect::special("symlink", "Symbolic link (broken)", "inode/symlink");
                report.diagnostics.warnings.push(format!("broken symlink: {e}"));
                finish(&mut report, &budget, &TextStore::default(), &clock);
                return Ok(report);
            }
        }
    }
    fill_from_metadata(&mut report, &meta, path);

    let special = match file_kind(&meta) {
        FileKind::Regular => None,
        FileKind::Directory => Some(("directory", "Directory", "inode/directory")),
        FileKind::Fifo => Some(("fifo", "Named pipe", "inode/fifo")),
        FileKind::Socket => Some(("socket", "Socket", "inode/socket")),
        FileKind::BlockDevice => Some(("block_device", "Block device", "inode/blockdevice")),
        FileKind::CharDevice => Some(("char_device", "Character device", "inode/chardevice")),
        FileKind::Symlink | FileKind::Memory | FileKind::Other => {
            Some(("other", "Special file", "application/octet-stream"))
        }
    };
    if let Some((id, label, mime)) = special {
        // Never opened: reading a FIFO or device could block or be endless.
        report.identification = detect::special(id, label, mime);
        finish(&mut report, &budget, &TextStore::default(), &clock);
        return Ok(report);
    }

    let text = match FileSource::open(path, budget.clone()) {
        Ok(mut src) => {
            let text = extract_source(engine, &mut report, &mut src, 0);
            integrity_for_file(&mut report, path, meta.len(), src.head(), &engine.options);
            text
        }
        Err(e) => {
            report.identification = detect::special("unreadable", "Unreadable file", "application/octet-stream");
            report.integrity.skipped = Some("unreadable".into());
            report.diagnostics.warnings.push(format!("cannot open: {e}"));
            TextStore::default()
        }
    };
    run_analyzers(engine, &mut report, &text, &budget);
    finish(&mut report, &budget, &text, &clock);
    Ok(report)
}

pub(super) fn extract_bytes(engine: &Engine, name: Option<&str>, data: &Arc<[u8]>) -> Report {
    let clock = Stopwatch::start();
    let budget = budget_for(engine);
    let source = name.map_or_else(SourceInfo::default, |n| SourceInfo::from_name(None, n));
    let mut report = bytes_report(engine, source, data, 0, &budget);
    finish_clock(&mut report, &clock);
    report
}

/// Full pipeline over in-memory data (root bytes input or an embedded child).
fn bytes_report(engine: &Engine, source: SourceInfo, data: &Arc<[u8]>, depth: u32, budget: &Budget) -> Report {
    let clock = Stopwatch::start();
    let mut report = new_report(engine, source);
    report.system.kind = FileKind::Memory;
    report.system.size_bytes = Some(data.len() as u64);
    report.physical.size_bytes = Some(data.len() as u64);
    let mut src = BytesSource::new(report.source.name.clone(), Arc::clone(data), budget.clone());
    let text = extract_source(engine, &mut report, &mut src, depth);
    integrity_for_bytes(&mut report, data, &engine.options);
    run_analyzers(engine, &mut report, &text, budget);
    finish(&mut report, budget, &text, &clock);
    report
}

/// Detection, extractors, block decoders and children for one source.
fn extract_source(engine: &Engine, report: &mut Report, src: &mut dyn Source, depth: u32) -> TextStore {
    let options = &engine.options;
    let registry = &engine.registry;
    let mut text = TextStore::with_limit(options.limits.max_text_bytes);

    let name = src.name_hint().map(str::to_string);
    let extension =
        name.as_deref().and_then(|n| Path::new(n).extension()).map(|e| e.to_string_lossy().to_ascii_lowercase());
    let probe = Probe {
        head: src.head(),
        tail: src.tail(),
        len: src.len(),
        name: name.as_deref(),
        extension: extension.as_deref(),
    };
    let detection = detect::detect(registry, &probe, options.format.as_deref());
    report.identification = detection.identification;
    if let Some(forced) = options.format.as_deref()
        && detection.spec.is_none_or(|s| s.id != forced)
    {
        report.diagnostics.warnings.push(format!("--format {forced}: no extractor declares this format"));
    }
    let Some(spec) = detection.spec else { return text };
    let budget = src.budget().clone();

    let mut blocks: VecDeque<PendingBlock> = VecDeque::new();
    let mut children: Vec<PendingChild> = Vec::new();
    let max_cost = options.profile.max_cost();
    let mut skipped_by_profile = false;
    for extractor in registry.extractors_for(spec.id) {
        let meta = extractor.meta();
        if !options.allows(meta.id) {
            continue;
        }
        if meta.cost > max_cost {
            skipped_by_profile = true;
            continue;
        }
        report.identification.extractor.get_or_insert_with(|| meta.id.to_string());
        let mut pending = Vec::new();
        let run = run_stage(meta.id, meta.version, options.limits.extractor_timeout, &budget, || {
            let mut cx = Context {
                report: &mut *report,
                text: &mut text,
                blocks: &mut pending,
                children: &mut children,
                options,
                budget: &budget,
                format_id: spec.id,
                emitter: meta.id,
            };
            extractor.extract(&mut *src, &mut cx)
        });
        report.diagnostics.extractors.push(run);
        blocks.extend(pending);
    }
    if skipped_by_profile && report.identification.extractor.is_none() {
        report
            .diagnostics
            .warnings
            .push(format!("extractors for `{}` skipped by the {:?} profile", spec.id, options.profile));
    }

    decode_blocks(engine, report, &mut text, &mut blocks, &mut children, spec.id, &budget);
    extract_children(engine, report, children, depth, &budget);
    text
}

fn decode_blocks(
    engine: &Engine,
    report: &mut Report,
    text: &mut TextStore,
    blocks: &mut VecDeque<PendingBlock>,
    children: &mut Vec<PendingChild>,
    format_id: &str,
    budget: &Budget,
) {
    // Decoders may emit further blocks (e.g. Photoshop IRB → IPTC); cap the chain.
    let mut processed = 0;
    while let Some(block) = blocks.pop_front() {
        processed += 1;
        if processed > 256 {
            report.diagnostics.warnings.push("too many metadata blocks; rest ignored".into());
            break;
        }
        let decoder = engine.registry.block_decoder(block.kind).filter(|d| engine.options.allows(d.id()));
        let Some(decoder) = decoder else {
            let kind = block.kind.to_string();
            if !report.diagnostics.undecoded_blocks.contains(&kind) {
                report.diagnostics.undecoded_blocks.push(kind);
            }
            continue;
        };
        let mut pending = Vec::new();
        let run = run_stage(decoder.id(), decoder.version(), engine.options.limits.extractor_timeout, budget, || {
            let mut cx = Context {
                report: &mut *report,
                text: &mut *text,
                blocks: &mut pending,
                children: &mut *children,
                options: &engine.options,
                budget,
                format_id,
                emitter: decoder.id(),
            };
            decoder.decode(&block.data, &mut cx)
        });
        report.diagnostics.extractors.push(run);
        blocks.extend(pending);
    }
}

fn extract_children(engine: &Engine, report: &mut Report, children: Vec<PendingChild>, depth: u32, budget: &Budget) {
    for child in children {
        let source = SourceInfo::from_name(None, &child.name);
        if depth >= engine.options.limits.max_depth {
            budget.hit("max_depth");
            let mut r = new_report(engine, source);
            r.system.kind = FileKind::Memory;
            r.system.size_bytes = Some(child.data.len() as u64);
            r.diagnostics.warnings.push("not analysed: max_depth reached".into());
            report.embedded.push(r);
            continue;
        }
        report.embedded.push(bytes_report(engine, source, &child.data.into(), depth + 1, budget));
    }
}

fn run_analyzers(engine: &Engine, report: &mut Report, text: &TextStore, budget: &Budget) {
    for analyzer in engine.registry.analyzers() {
        // `only` selects extractors; analyzers are skipped only explicitly.
        if engine.options.skip.iter().any(|s| analyzer.id() == s || analyzer.id().starts_with(&format!("{s}."))) {
            continue;
        }
        let run = run_stage(analyzer.id(), analyzer.version(), engine.options.limits.extractor_timeout, budget, || {
            analyzer.run(report, text, &engine.options)
        });
        report.diagnostics.extractors.push(run);
    }
}

/// Run one extractor/decoder/analyzer with its own deadline, containing panics.
fn run_stage(
    id: &str,
    version: u32,
    timeout: Option<std::time::Duration>,
    budget: &Budget,
    f: impl FnOnce() -> Result<(), crate::ExtractError>,
) -> ExtractorRun {
    let clock = Stopwatch::start();
    budget.begin_stage(timeout);
    let result = catch_unwind(AssertUnwindSafe(f));
    budget.end_stage();
    let mut run = ExtractorRun { id: id.to_string(), version, ms: clock.ms(), ..ExtractorRun::default() };
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            run.status =
                if matches!(e, crate::ExtractError::Internal(_)) { RunStatus::Internal } else { RunStatus::Error };
            run.error_kind = Some(e.kind().to_string());
            run.error = Some(e.to_string());
        }
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic".to_string());
            run.status = RunStatus::Internal;
            run.error_kind = Some("internal".into());
            run.error = Some(format!("panicked: {msg}"));
        }
    }
    run
}

fn finish(report: &mut Report, budget: &Budget, text: &TextStore, clock: &Stopwatch) {
    for hit in budget.limits_hit() {
        if !report.diagnostics.limits_hit.iter().any(|h| h == hit) {
            report.diagnostics.limits_hit.push(hit.to_string());
        }
    }
    report.diagnostics.truncated |= text.truncated() || !report.diagnostics.limits_hit.is_empty();
    finish_clock(report, clock);
}

fn finish_clock(report: &mut Report, clock: &Stopwatch) {
    report.diagnostics.elapsed_ms = clock.ms();
}
