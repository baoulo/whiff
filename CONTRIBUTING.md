# Contributing to whiff

The most useful contribution is an **extractor** for a format listed in [`docs/metadata-extracted.md`](docs/metadata-extracted.md). Adding one touches no shared code apart from a `mod` line, which the tooling writes for you.

## Add a format

1. **Scaffold** (pick the family from `data/families.tsv`; it decides the cargo feature):

   ```sh
   cargo run --features dev --bin whiff-dev -- new-extractor image.qoi \
       --family image.raster --name "QOI image" --ext qoi --mime image/qoi --magic 716f6966
   ```

   This creates `src/formats/image/qoi.rs`, adds `pub(crate) mod qoi;` (and the group's feature-gated `mod` line if needed), and creates `tests/fixtures/qoi/SOURCE.md`. `--magic` takes hex, optionally with an offset: `4:66747970`. Use `--dry-run` to preview.

2. **Implement `extract`.** Read with `src.head()` (first 64 KiB, pre-read), `src.read_vec(offset, len)?` or `src.reader()`, and parse with the bounds-checked `ByteReader`. Write only through the `Context`:
   * normalised fields: `cx.content().title(..)`, `cx.temporal().content_date(..)`, `cx.rights().copyright(..)`, `cx.security().risk(..)`, `cx.physical().image(w, h)`;
   * raw metadata in a standard's own names: `cx.metadata_set("id3", "TIT2", title)`;
   * technical details: `cx.format_set("quality_estimate", 92)`. Keys are `snake_case` with unit suffixes (`_bytes`, `_s`, `_px`, `_hz`);
   * embedded metadata goes to the shared decoders: `cx.emit_block(BlockKind::XMP, bytes)`. Don't parse EXIF/XMP/IPTC/ICC yourself;
   * text goes to the text analyzers: `cx.emit_text(TextRole::Body, text)`. Don't count words yourself;
   * embedded files: `cx.emit_child(name, bytes)?`.

   Scalar fields are first-write-wins. Never panic, print or allocate based on unchecked lengths from the file.

3. **Add 2–5 small sample files** to `tests/fixtures/<format>/` and list each in `SOURCE.md` with its origin and licence. Files must be ≤ 256 KiB and redistributable: self-made, CC0 or permissively licensed.

4. **Test:**

   ```sh
   INSTA_UPDATE=always cargo test --features full
   ```

   Review the new `tests/snapshots/<format>__*.snap` files: they are the extractor's output contract. The **conformance suite** (`tests/conformance.rs`) then checks your extractor automatically: detection, schema round-trip, determinism, `snake_case` keys, and that empty, truncated, bit-flipped and random inputs, plus a 4 KiB read budget, never cause a panic.

5. **Regenerate the catalogue** so the "Extractor" column shows your work:

   ```sh
   cargo run --features dev --bin whiff-dev -- catalogue
   ```

6. Optional but appreciated: `cargo run --features dev --bin whiff-dev -- fuzz image.qoi` (needs nightly and `cargo install cargo-fuzz`).

## Rules

* **Pure Rust.** No crates that bind C/C++ libraries. Check the "Library" column of the catalogue, and prefer mature crates (a release in the last 18 months or clearly finished). Otherwise write a header parser with `ByteReader`.
* **Plugin boundary.** Format modules import only `crate::plugin::*` (checked by `whiff-dev check-boundary`).
* **Dependency budget.** CI counts transitive dependencies (`whiff-dev check-deps`). Exceeding a budget needs a justification in the PR.
* **Privacy.** Never output secret material (keys, passwords, cookie values). Count personal data such as e-mail addresses or patient fields; don't list it.
* **`unsafe` is forbidden** crate-wide.

## Before opening a PR

```sh
cargo fmt
cargo clippy --all-targets --features dev
cargo test --features dev
cargo run --features dev --bin whiff-dev -- catalogue --check
```

## Extractors in other crates

A crate outside whiff can implement `whiff::plugin::Extractor` and add it explicitly:

```rust
let engine = whiff::Engine::builder()
    .registry(whiff::Registry::builtin().with(MyExtractor))
    .build();
```

## How built-in registration works

`build.rs` scans `src/formats/`, `src/meta/` and `src/engine/` for `register_extractor!(Name)`, `register_block_decoder!(Name)` and `register_analyzer!(Name)` lines. It generates the list behind `Registry::builtin()`, gated by each group's cargo feature. This is deterministic on every target, unlike linker-section registration.
