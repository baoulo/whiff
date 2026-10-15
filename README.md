# whiff

**whiff** (verb): to catch the scent of something. Point `whiff` at any file and it returns one JSON document describing it: what it is, where it came from, who owns it, when it was made, what rights apply, its physical properties, and a compact, LLM-ready view of its content. Pure Rust, safe on untrusted input.

> **Status: Stage 0 (foundations).** The engine, JSON contract, CLI, plugin API and test harness are in place. Format extractors arrive from Stage 1, so today every file gets the universal sections (identification, system, temporal, security, physical, integrity) and text/binary detection. [`docs/metadata-extracted.md`](docs/metadata-extracted.md) lists the 1004 formats planned and what will be extracted from each.

## Use

```sh
cargo install whiff                   # common formats
cargo install whiff --features full   # every format collection

whiff photo.jpg                       # one report, pretty-printed on a terminal
whiff ~/Downloads                     # walks directories, one JSON report per line
cat upload.bin | whiff -              # stdin
whiff --profile minimal --hash none big.iso
whiff schema                          # JSON Schema of the report (whiff/1)
whiff formats                         # formats this build can extract
```

As a library:

```rust
let engine = whiff::Engine::new();
let report = engine.extract_path("photo.jpg")?;
println!("{}", serde_json::to_string_pretty(&report)?);
```

```toml
# library only, default formats, plus GIS support
whiff = { version = "0.1", default-features = false, features = ["common", "geo"] }
```

## The report

Every report has the same top-level sections: `whiff`, `source`, `identification`, `system`, `temporal`, `security`, `rights`, `physical`, `integrity`, `content`, `metadata` (raw EXIF/XMP/IPTC/… per standard), `format` (technical details per format), `embedded` (children of containers) and `diagnostics`. Empty fields are omitted; sections are always present. The schema is in [`docs/schema/whiff-1.schema.json`](docs/schema/whiff-1.schema.json).

## Features

| Feature | Default | Adds |
|---|---|---|
| `common` | yes | text, web, data, code, images, documents, email, audio/video, archives, packages, executables, certificates, SQLite, fonts |
| `cli` | yes | the `whiff` binary |
| `geo`, `science`, `data`, `cad`, `forensics`, `games` | no | specialist format collections |
| `full` | no | all collections |

## Contributing

Adding a format is one file. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

MIT. See [LICENSE](LICENSE).
