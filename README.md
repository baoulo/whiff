# whiff

**whiff** (verb): to catch the scent of something. Point `whiff` at any file and it returns one JSON document describing it: what it is, where it came from, who owns it, when it was made, what rights apply, its physical properties, and a compact, LLM-ready view of its content. Pure Rust, safe on untrusted input.

> **Status: Stage 1.** Every file gets the universal sections (identification, system, temporal, security, physical, integrity), plus `wc` statistics for text, owner names, extended attributes (macOS quarantine and "Where from", Finder tags, Windows `Zone.Identifier`), and a language, keywords, keyword frequency, excerpt and (in `full` / `llm`) a summary for any prose. Extractors cover plain text, logs, diffs, Markdown, HTML, XML, feeds, JSON / NDJSON / JSON5, YAML, TOML, INI / properties / dotenv, CSV / TSV, SQL, ~40 programming languages, package manifests, Jupyter notebooks, Dockerfiles and Makefiles. Other formats are still identified by signature. [`docs/metadata-extracted.md`](docs/metadata-extracted.md) lists the 1004 formats planned, what is extracted from each, and which extractor handles it today.

## Use

```sh
cargo install whiff                   # common formats
cargo install whiff --features full   # every format collection

whiff photo.jpg                       # one report, pretty-printed on a terminal
whiff ~/Downloads                     # walks directories, one JSON report per line
cat upload.bin | whiff -              # stdin
whiff --profile minimal --hash none big.iso
whiff --profile llm README.md         # compact, token-budgeted view for language models
whiff schema                          # JSON Schema of the report (whiff/1)
whiff formats                         # formats this build can extract
```

As a library:

```rust
let engine = whiff::Engine::new();
let report = engine.extract_path("photo.jpg")?;
println!("{}", serde_json::to_string_pretty(&report)?);
let compact = report.llm_view(800); // ~800 tokens
```

```toml
# library only, default formats, plus GIS support
whiff = { version = "0.1", default-features = false, features = ["common", "geo"] }
```

## The report

Every report has the same top-level sections: `whiff`, `source`, `identification`, `system`, `temporal`, `security`, `rights`, `physical`, `integrity`, `content`, `metadata` (raw EXIF/XMP/IPTC/… per standard), `format` (technical details per format), `embedded` (children of containers) and `diagnostics`. Empty fields are omitted; sections are always present. The schema is in [`docs/schema/whiff-1.schema.json`](docs/schema/whiff-1.schema.json).

Secrets found in content (keys, tokens, credentials in URLs) are counted under `security.secrets` and redacted from the report; personal data (e-mail addresses, phone numbers, card numbers, IBANs) is counted under `security.personal_data` and never listed in derived text.

Untrusted input is bounded: reads, decompression and time are budgeted per file, panics in extractors are contained, deeply nested input is refused before recursive parsers see it, and an extractor that ignores its deadline is abandoned by a watchdog.

## Features

| Feature | Default | Adds |
|---|---|---|
| `common` | yes | text, web, data, code, images, documents, email, audio/video, archives, packages, executables, certificates, SQLite, fonts |
| `cli` | yes | the `whiff` binary |
| `geo`, `science`, `data`, `cad`, `forensics`, `games` | no | specialist format collections |
| `full` | no | all collections |

The minimum supported Rust version is 1.89.

## Contributing

Adding a format is one file. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

MIT. See [LICENSE](LICENSE).
