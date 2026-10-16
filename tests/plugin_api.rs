//! The contributor-facing API: byte readers, sources, budgets, writers,
//! registry, and the conformance harness itself.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use whiff::io::{Budget, ByteReader, BytesSource, FileSource, Source, SourceError};
use whiff::plugin::{
    BlockDecoder, BlockKind, Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Magic, Registry,
    TextRole, TextStore, conformance, testing,
};
use whiff::report::{DateField, RunStatus};
use whiff::{Engine, Limits};

#[test]
fn byte_reader_reads_and_never_panics() {
    let data = [b'H', b'D', 0x12, 0x34, 0x34, 0x12, 0, 0, 0, 1, 1, 0, 0, 0, b'a', b'b', 0, 0xff, 0xfe];
    let mut r = ByteReader::new(&data);
    r.tag(b"HD").unwrap();
    assert_eq!(r.be_u16().unwrap(), 0x1234);
    assert_eq!(r.le_u16().unwrap(), 0x1234);
    assert_eq!(r.be_u32().unwrap(), 1);
    assert_eq!(r.le_u32().unwrap(), 1);
    assert_eq!(r.peek(2), Some(&b"ab"[..]));
    assert_eq!(r.cstr().unwrap(), b"ab");
    assert_eq!(r.position(), 17);
    assert_eq!(r.remaining(), 2);
    assert_eq!(r.le_i16().unwrap(), -257);
    assert!(r.is_empty());
    assert!(matches!(r.u8(), Err(ExtractError::Truncated { offset: 19, needed: 1 })));
    assert!(r.be_u64().is_err() && r.le_u64().is_err() && r.be_i16().is_err());
    assert!(r.be_i32().is_err() && r.le_i32().is_err());
    assert!(r.peek(1).is_none());

    let mut r = ByteReader::new(&data);
    assert!(matches!(r.tag(b"XX"), Err(ExtractError::Malformed(_))));
    r.seek(14).unwrap();
    assert_eq!(r.array::<2>().unwrap(), *b"ab");
    assert!(r.seek(100).is_err());
    assert_eq!(r.rest(), &[0, 0xff, 0xfe]);
    assert!(ByteReader::new(b"no nul").cstr().is_err());
    assert!(ByteReader::new(b"ab").skip(3).is_err());
    let mut r = ByteReader::new(&[0; 8]);
    assert_eq!(r.be_u64().unwrap(), 0);
}

#[test]
fn file_and_byte_sources_share_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.bin");
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &data).unwrap();

    let mut file = FileSource::open(&path, Budget::unlimited()).unwrap();
    let mut bytes = BytesSource::new(Some("big.bin".into()), data.clone(), Budget::unlimited());
    for src in [&mut file as &mut dyn Source, &mut bytes as &mut dyn Source] {
        assert_eq!(src.len(), 200_000);
        assert!(!src.is_empty());
        assert_eq!(src.head().len(), 64 * 1024);
        assert_eq!(src.tail(), &data[data.len() - 64 * 1024..]);
        assert_eq!(src.name_hint(), Some("big.bin"));
        assert_eq!(src.read_vec(100, 4).unwrap(), &data[100..104]);
        assert_eq!(src.read_at(300_000, &mut [0; 4]).unwrap(), 0);
        assert!(matches!(src.read_vec(199_998, 4), Err(SourceError::OutOfBounds { .. })));

        let mut sub = src.slice(1_000, 70_000).unwrap();
        assert_eq!(sub.len(), 70_000);
        assert_eq!(sub.head()[0], data[1_000]);
        assert_eq!(sub.tail().len(), 64 * 1024);
        assert_eq!(sub.name_hint(), Some("big.bin"));
        let mut buf = [0u8; 3];
        assert_eq!(sub.read_at(69_999, &mut buf).unwrap(), 1);
        assert_eq!(sub.read_at(80_000, &mut buf).unwrap(), 0);
        assert!(sub.budget().bytes_read() > 0);
        assert!(src.slice(199_000, 2_000).is_err());

        let mut reader = src.reader();
        assert_eq!(reader.seek(SeekFrom::End(-2)).unwrap(), 199_998);
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, &data[199_998..]);
        assert_eq!(reader.seek(SeekFrom::Current(-10)).unwrap(), 199_990);
        assert_eq!(reader.seek(SeekFrom::Start(5)).unwrap(), 5);
        assert!(reader.seek(SeekFrom::Current(-6)).is_err());
    }

    // Small inputs: the tail window is the head.
    let small = BytesSource::new(None, b"abc".to_vec(), Budget::unlimited());
    assert_eq!(small.tail(), b"abc");
    assert_eq!(small.data().len(), 3);
    let p = dir.path().join("small");
    std::fs::write(&p, b"abc").unwrap();
    let f = FileSource::open(&p, Budget::unlimited()).unwrap();
    assert_eq!(f.tail(), b"abc");
    let mut empty = BytesSource::new(None, Vec::new(), Budget::unlimited());
    assert!(empty.is_empty());
    assert_eq!(empty.read_at(0, &mut [0; 1]).unwrap(), 0);
    let mut sub = (&mut empty as &mut dyn Source).slice(0, 0).unwrap();
    assert_eq!(sub.read_at(0, &mut [0; 1]).unwrap(), 0);
}

#[test]
fn budgets_and_error_conversions() {
    let budget = Budget::new(10, 5, None);
    let mut src = BytesSource::new(None, vec![0u8; 100], budget.clone());
    assert!(src.read_at(0, &mut [0; 8]).is_ok());
    assert_eq!(src.read_at(0, &mut [0; 8]), Err(SourceError::LimitExceeded("read_bytes")));
    assert!(budget.charge_decompressed(5).is_ok());
    assert_eq!(budget.charge_decompressed(1), Err(SourceError::LimitExceeded("decompressed_bytes")));
    assert_eq!(budget.limits_hit(), vec!["read_bytes", "decompressed_bytes"]);
    budget.hit("read_bytes");
    assert_eq!(budget.limits_hit().len(), 2, "hits are de-duplicated");

    // Budget errors survive a trip through std::io (BoundedReader → io::Error → ExtractError).
    let mut reader = (&mut src as &mut dyn Source).reader();
    let io_err = reader.read(&mut [0; 4]).unwrap_err();
    assert_eq!(ExtractError::from(io_err), ExtractError::LimitExceeded("read_bytes".into()));
    let eof = std::io::Error::from(std::io::ErrorKind::UnexpectedEof);
    assert!(matches!(ExtractError::from(eof), ExtractError::Truncated { .. }));
    assert!(matches!(ExtractError::from(std::io::Error::other("disk")), ExtractError::Io(_)));

    for (e, kind) in [
        (ExtractError::Unsupported("x".into()), "unsupported"),
        (ExtractError::malformed("bad"), "malformed"),
        (ExtractError::Truncated { offset: 1, needed: 2 }, "truncated"),
        (ExtractError::Encrypted, "encrypted"),
        (ExtractError::LimitExceeded("x".into()), "limit_exceeded"),
        (ExtractError::Timeout, "timeout"),
        (ExtractError::Io("x".into()), "io"),
        (ExtractError::Internal("x".into()), "internal"),
    ] {
        assert_eq!(e.kind(), kind);
        assert_ne!(e.to_string(), "");
    }
    assert_eq!(ExtractError::from(SourceError::Timeout), ExtractError::Timeout);
    assert_eq!(ExtractError::from(SourceError::Io("x".into())), ExtractError::Io("x".into()));
    assert!(matches!(
        ExtractError::from(SourceError::OutOfBounds { offset: 1, needed: 1 }),
        ExtractError::Truncated { .. }
    ));
    let err = whiff::Engine::new().extract_path("/definitely/not/here").unwrap_err();
    assert!(err.to_string().contains("/definitely/not/here"));
}

#[test]
fn magic_and_text_store() {
    let m = Magic::masked(1, b"\x10\x20", b"\xf0\xff");
    assert!(m.matches(b"\x00\x1f\x20"));
    assert!(!m.matches(b"\x00\x2f\x20"));
    assert!(!m.matches(b"\x00"));
    assert!(Magic::at(2, b"ok").matches(b"..ok"));
    assert_eq!(BlockKind::XMP.to_string(), "xmp");

    let mut t = TextStore::with_limit(5);
    assert!(t.is_empty());
    t.push(TextRole::Title, "héllo world"); // cut on a char boundary
    assert_eq!(t.chunks()[0].text, "héll");
    assert!(t.truncated());
    t.push(TextRole::Body, "more");
    assert_eq!(t.len(), 5);
    assert_eq!(t.by_role(TextRole::Title).collect::<Vec<_>>(), ["héll"]);
    assert!(!whiff::enabled_features().is_empty() || cfg!(not(feature = "common")));
}

/// Calls every writer once, then again to show first-write-wins.
struct Everything;
impl Extractor for Everything {
    fn meta(&self) -> &'static ExtractorMeta {
        static F: [FormatSpec; 1] = [FormatSpec {
            id: "everything",
            name: "Everything",
            family: "test",
            mimes: &["application/x-everything"],
            extensions: &["evr"],
            magic: &[Magic::prefix(b"EVRY")],
            parent: None,
        }];
        static M: ExtractorMeta =
            ExtractorMeta { id: "test.everything", version: 2, formats: &F, cost: Cost::Header, priority: 5 };
        &M
    }
    fn extract(&self, _: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        for pass in 0..2 {
            let v = |s: &str| format!("{s}{pass}");
            cx.content()
                .source("custom.source")
                .description(v("desc"))
                .tag(v("tag"))
                .summary(v("sum"))
                .location(1.5, 2.5, Some(3.0))
                .title("  ");
            cx.rights()
                .source("xmp.rights")
                .creator(v("c"))
                .credit(v("cr"))
                .usage_terms(v("u"))
                .marked(pass == 0)
                .embedding(v("e"));
            cx.security().encrypted(pass == 0).signed(pass == 1).external_references(2).active_content("js");
            let mut p = cx.physical();
            p.duration_s(12.5)
                .bitrate_bps(128)
                .pages(3)
                .words(9)
                .slides(1)
                .sheets(2)
                .entries(4)
                .uncompressed_bytes(40)
                .encrypted_entries(1);
            p.stream(whiff::report::Map::new());
            cx.physical().image(10, 20).orientation(6).orientation(9).dpi(72.0, 72.0).frames(1);
            cx.temporal().content_date(DateField::Captured, "2026-01-01T00:00:00", false).content_date(
                DateField::Other,
                " ",
                false,
            );
        }
        cx.metadata("std").insert("k".into(), 1.into());
        cx.format().insert("x".into(), serde_json::Value::Null);
        cx.report_format_replace_check();
        cx.warn("careful");
        assert_eq!(cx.format_id(), "everything");
        assert!(cx.options().limits.max_children > 0);
        cx.checkpoint()?;
        for i in 0..100 {
            if cx.emit_child(&format!("c{i}"), vec![]).is_err() {
                cx.format_set("children_accepted", i);
                break;
            }
        }
        Ok(())
    }
}

/// Helper trait so the test can poke at a non-object `format` entry.
trait ReplaceCheck {
    fn report_format_replace_check(&mut self);
}
impl ReplaceCheck for Context<'_> {
    fn report_format_replace_check(&mut self) {
        self.metadata_set("scalar", "v", 1);
        // `metadata("std")` again returns the same object.
        assert_eq!(self.metadata("std")["k"], 1);
    }
}

struct NullDecoder;
impl BlockDecoder for NullDecoder {
    fn kind(&self) -> BlockKind {
        BlockKind::ICC
    }
    fn id(&self) -> &'static str {
        "meta.null"
    }
    fn decode(&self, _: &[u8], _: &mut Context<'_>) -> Result<(), ExtractError> {
        Err(ExtractError::Encrypted)
    }
}

#[test]
fn every_writer_and_registry_accessor() {
    let registry = Registry::empty()
        .with(Everything)
        .with(Everything)
        .with_block_decoder(NullDecoder)
        .with_block_decoder(NullDecoder);
    assert_eq!(registry.extractors().count(), 1, "duplicates ignored");
    assert_eq!(registry.block_decoders().count(), 1);
    assert!(registry.block_decoder(BlockKind::ICC).is_some() && registry.block_decoder(BlockKind::EXIF).is_none());
    assert_eq!(registry.extractors_for("everything").count(), 1);
    assert!(format!("{registry:?}").contains("test.everything"));
    assert_eq!(registry.formats().count(), 1);
    assert_eq!(NullDecoder.version(), 1);

    let r = Engine::builder()
        .registry(registry)
        .limits(Limits::default().max_depth(0))
        .build()
        .extract_bytes(None, b"EVRY".to_vec());
    let c = &r.content;
    assert_eq!(
        (c.description.as_deref(), c.summary.as_deref(), c.title.as_deref()),
        (Some("desc0"), Some("sum0"), None)
    );
    assert_eq!(c.tags, ["tag0", "tag1"]);
    assert_eq!(c.location.as_ref().map(|l| l.source.as_str()), Some("custom.source"));
    assert_eq!(r.rights.creators, ["c0", "c1"]);
    assert_eq!((r.rights.marked, r.rights.embedding.as_deref()), (Some(true), Some("e0")));
    assert_eq!(
        (r.security.encrypted, r.security.signed, r.security.external_references),
        (Some(true), Some(true), Some(4))
    );
    let p = &r.physical;
    assert_eq!(p.media.as_ref().map(|m| (m.duration_s, m.streams.len())), Some((Some(12.5), 2)));
    assert_eq!(p.document.as_ref().map(|d| (d.pages, d.sheets)), Some((Some(3), Some(2))));
    assert_eq!(p.container.as_ref().and_then(|c| c.ratio), Some(10.0));
    assert_eq!(p.image.as_ref().map(|i| (i.orientation, i.frames)), Some((Some(6), Some(1))));
    assert_eq!(r.temporal.content.len(), 1, "blank dates ignored, repeats merged");
    assert!(r.temporal.earliest.is_none(), "zone-less dates are not ranged");
    assert_eq!(r.format["everything"]["children_accepted"], 50);
    assert_eq!(r.embedded.len(), 50);
    assert!(r.diagnostics.warnings.iter().any(|w| w == "test.everything: careful"));
    assert!(r.diagnostics.limits_hit.contains(&"max_children".to_string()));
}

// ---- conformance harness -------------------------------------------------

macro_rules! fixture_extractor {
    ($name:ident, $id:literal, $fmt:literal, $magic:literal, $body:expr) => {
        struct $name;
        impl Extractor for $name {
            fn meta(&self) -> &'static ExtractorMeta {
                static F: [FormatSpec; 1] = [FormatSpec {
                    id: $fmt,
                    name: "Fixture format",
                    family: "test",
                    mimes: &["application/x-fixture"],
                    extensions: &["fx"],
                    magic: &[Magic::prefix($magic)],
                    parent: None,
                }];
                static M: ExtractorMeta =
                    ExtractorMeta { id: $id, version: 1, formats: &F, cost: Cost::Header, priority: 0 };
                &M
            }
            fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
                #[allow(clippy::redundant_closure_call)]
                ($body)(src, cx)
            }
        }
    };
}

fixture_extractor!(Good, "test.good", "good", b"GOOD", |src: &mut dyn Source, cx: &mut Context<'_>| {
    let mut r = ByteReader::new(src.head()).skip(4)?;
    let n = r.u8()?;
    cx.format_set("count", n);
    Ok(())
});
fixture_extractor!(Fragile, "test.fragile", "fragile", b"FRAG", |src: &mut dyn Source, cx: &mut Context<'_>| {
    let n = src.head()[4]; // bug: panics on short input
    cx.format_set("BadKey", n);
    Ok(())
});
fixture_extractor!(Lonely, "test.lonely", "lonely", b"LONE", |_: &mut dyn Source, _: &mut Context<'_>| Ok(()));

fn write_fixture(root: &Path, format: &str, name: &str, data: &[u8]) {
    let dir = root.join("tests/fixtures").join(format);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), data).unwrap();
    std::fs::write(dir.join("SOURCE.md"), "not a fixture").unwrap();
}

#[test]
fn conformance_passes_a_good_extractor() {
    let root = tempfile::tempdir().unwrap();
    write_fixture(root.path(), "good", "one.fx", b"GOOD\x07rest");
    let outcome = conformance::check_registry(&Registry::empty().with(Good), root.path());
    assert_eq!(outcome.checked, 1);
    assert!(outcome.failures.is_empty(), "{:?}", outcome.failures);

    let reports = testing::fixture_reports(root.path().to_str().unwrap(), "good");
    assert_eq!(reports.len(), 1, "SOURCE.md is not a fixture");
    assert_eq!(reports[0].0, "one.fx");
    assert_eq!(reports[0].1.whiff.version, "[version]", "reports are redacted");
}

#[test]
fn conformance_catches_bugs() {
    let root = tempfile::tempdir().unwrap();
    write_fixture(root.path(), "fragile", "a.fx", b"FRAG\x01");
    write_fixture(root.path(), "good", "wrong-magic.fx", b"NOPE\x01");
    let registry = Registry::empty().with(Fragile).with(Good).with(Lonely);
    let outcome = conformance::check_registry(&registry, root.path());
    let checks: Vec<(&str, &str)> = outcome.failures.iter().map(|f| (f.format.as_str(), f.check)).collect();
    assert!(checks.contains(&("fragile", "robustness")), "{checks:?}");
    assert!(checks.contains(&("fragile", "field_names")), "{checks:?}");
    assert!(checks.contains(&("good", "magic")), "{checks:?}");
    assert!(checks.contains(&("good", "detection")), "{checks:?}");
    assert!(checks.contains(&("lonely", "fixtures")), "{checks:?}");
    let shown = outcome.failures[0].to_string();
    assert!(shown.starts_with('[') && shown.contains(" / "));
}

#[test]
fn conformance_flags_over_broad_magic() {
    let root = tempfile::tempdir().unwrap();
    // `Broad` matches everything starting with "G", including `good` fixtures.
    fixture_extractor!(Broad, "test.broad", "broad", b"G", |_: &mut dyn Source, _: &mut Context<'_>| Ok(()));
    write_fixture(root.path(), "broad", "b.fx", b"Gxx");
    write_fixture(root.path(), "good", "g.fx", b"GOOD\x01");
    let outcome = conformance::check_registry(&Registry::empty().with(Broad).with(Good), root.path());
    assert!(
        outcome.failures.iter().any(|f| f.format == "broad" && f.detail.contains("other formats")),
        "{:?}",
        outcome.failures
    );
}

#[test]
fn internal_errors_count_as_bugs() {
    fixture_extractor!(Liar, "test.liar", "liar", b"LIAR", |_: &mut dyn Source, _: &mut Context<'_>| Err(
        ExtractError::Internal("invariant".into())
    ));
    let r = Engine::builder().registry(Registry::empty().with(Liar)).build().extract_bytes(None, b"LIAR".to_vec());
    assert_eq!(r.diagnostics.extractors[0].status, RunStatus::Internal);
}
