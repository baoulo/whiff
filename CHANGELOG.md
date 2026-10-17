# Changelog

All notable changes to whiff are recorded here. The report format is
versioned separately (`whiff.schema`, currently `whiff/1`); additive changes
keep the schema version.

## Unreleased (0.2.0)

Images and embedded metadata blocks.

- **Image extractors (41 formats):** JPEG (JFIF, EXIF, XMP and extended
  XMP, ICC, MPF, Photoshop IRB, Adobe, quality estimate, Ultra HDR, C2PA),
  PNG / APNG, GIF, WebP, BMP, ICO / CUR, TIFF / BigTIFF, HEIC / HEIF / AVIF,
  JPEG XL, JPEG 2000 (JP2 and codestreams), TGA, PCX, Netpbm, QOI, Radiance
  HDR, OpenEXR, DDS, KTX / KTX2, Photoshop PSD / PSB (layers), GIMP XCF, SVG
  / SVGZ, EMF / WMF, and camera raw: DNG, CR2, CR3, NEF, ARW, ORF, RW2, PEF,
  RAF, SRW. Headers and structure only; pixels are never decoded.
- **Metadata blocks:** EXIF, XMP, IPTC-IIM, ICC profiles and Photoshop
  image resources are decoded wherever they are embedded, into
  `metadata.exif`, `metadata.xmp`, `metadata.iptc`, `metadata.icc` and
  `metadata.photoshop`.
- **Normalisation (MWG):** title, description, creators, copyright,
  keywords, credit, licence, capture / digitisation / modification dates and
  GPS location are reconciled across XMP, IPTC and EXIF with the Metadata
  Working Group's precedence rules (including the IPTC digest check).
- **AI provenance:** Stable Diffusion, ComfyUI and InvokeAI generation
  parameters in PNGs, and the IPTC `DigitalSourceType` for generated media,
  are reported; the prompt becomes the description and `security.risks`
  flags the image as AI-generated. C2PA manifests set `security.signed`.
- **SVG risks:** scripts, event handlers, `foreignObject`, external
  references and entity declarations are flagged.
- **Developer tools:** `whiff-dev oracle images` compares the normalised
  fields with `exiftool -use MWG`; `scripts/fixtures/` regenerates the image
  fixtures and a 200-image oracle corpus.
- MSRV is now Rust 1.89.

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
