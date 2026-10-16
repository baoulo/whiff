# Changelog

All notable changes to whiff are recorded here. The report format is
versioned separately (`whiff.schema`, currently `whiff/1`); additive changes
keep the schema version.

## 0.1.0 — 2026-10-16

First release.

- **Report:** one JSON document per file (`whiff/1`) with fixed sections —
  identification, system, temporal, security, rights, physical, integrity,
  content, metadata, format, embedded, diagnostics — and a JSON Schema
  (`whiff schema`).
- **Every file:** detection (registered extractors, then a ~1000-signature
  database), filesystem identity and times, permissions with owner names,
  extended attributes (macOS quarantine, "Where from", Finder tags; Windows
  `Zone.Identifier`), SHA-256 and BLAKE3, entropy, and `wc`-compatible counts
  for text.
- **Extractors (79 formats):** plain text, logs, diffs, Markdown, HTML,
  XML, RSS / Atom / JSON Feed / OPML / sitemaps, JSON / NDJSON / JSON5, YAML,
  TOML, INI / properties / dotenv, CSV / TSV, SQL, 43 programming languages,
  package manifests (npm, Cargo, Python, Go, Maven), Jupyter notebooks,
  Dockerfiles, Makefiles and unknown binary data. About 20 well-known
  configuration schemas are recognised (OpenAPI, Kubernetes, GitHub Actions,
  Docker Compose, HAR, SARIF, …).
- **Content analysis:** language, keywords, keyword frequency, outline,
  excerpt and summary; `--profile llm` prints a compact, token-budgeted view.
- **Privacy:** secrets are counted and redacted; personal data is counted,
  never listed.
- **Safety:** pure Rust with `unsafe` forbidden; read, decompression and time
  budgets; contained panics; nesting limits before recursive parsers; a
  watchdog for extractors that ignore their deadline; fuzzed.
- **Library:** `whiff::Engine` with profiles and limits; a plugin API for
  adding formats in one file, with an automatic conformance suite.
