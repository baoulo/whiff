# Changelog

All notable changes to whiff are recorded here. The report format is
versioned separately (`whiff.schema`, currently `whiff/1`); additive changes
keep the schema version.

## Unreleased (0.3.0)

Documents, e-mail, calendars and contacts.

- **PDF** (in-house parser): cross-reference tables and streams, object
  streams, incremental updates, and a repair scan for damaged files; RC4 and
  AES (128 and 256) decryption with the empty user password, so files
  encrypted only to set permissions are read in full. Reports the Info
  dictionary, XMP, page count and sizes, outline (as headings), fonts,
  images, annotations, AcroForm / XFA fields, signatures, PDF/A, /UA and /X
  claims, permissions and per-page text. JavaScript, automatic actions,
  launch actions, form submission, remote go-to actions and executable
  attachments are `security.risks`; embedded files become children. FDF
  field names too.
- **Office Open XML** (Word, Excel, PowerPoint, Visio, with their
  templates, macro-enabled and show variants, and XLSB): core, app and
  custom properties, sensitivity labels, outline, comments, tracked changes,
  fields, hyperlinks, sheets, slides, notes and text. Macros (VBA source
  decompressed and scanned), auto-run procedures, DDE fields, external
  templates and OLE links, Excel 4.0 macro sheets and remote images are
  risks; embeddings become children.
- **OpenDocument** (text, spreadsheet, presentation, drawing, formula,
  database, chart, master document, templates and flat XML): `meta.xml`,
  outline, text, comments, tracked changes, StarBasic macros and the events
  that run them, encryption.
- **Legacy Office and other compound files** (in-house CFB and property-set
  readers): Word 97–2003 text through the piece table and its fields, Excel
  97–2003 sheets and shared strings, PowerPoint 97–2003 slide titles and
  text, Visio, Publisher, Project, Hangul HWP, Thumbs.db, VBA projects and
  encrypted OOXML containers; macros, embedded objects and Equation Editor
  objects are flagged.
- **RTF** (in-house): the `\info` group, fonts, styles and outline, text in
  every code page, comments, fields and links, pictures, tracked changes and
  protection; embedded OLE objects become children, and linked or
  auto-updating objects, DDE fields and remote includes are risks.
- **Ebooks:** EPUB 2 / 3 (OPF metadata, creators and roles, identifiers
  with ISBN checks, series, navigation document or NCX, cover, DRM and font
  obfuscation, reading-order text), Mobipocket / Kindle MOBI, AZW and AZW3
  (EXTH records, PalmDOC-compressed text), PalmDOC, FictionBook (FB2, FBZ)
  and comic book ZIPs with `ComicInfo.xml`.
- **E-mail:** EML, mbox, MHTML and Apple Mail EMLX (via `mail-parser`) and
  Outlook MSG (in-house, including compressed RTF bodies): addresses,
  dates, Received hops, SPF / DKIM / DMARC verdicts, lists, S/MIME and PGP,
  body text and attachments as children. Phishing signals are risks: a
  Reply-To on another domain, a display name naming a different address,
  link text naming another site, failed authentication, risky attachment
  names (executables, double extensions, macro documents) and password
  forms.
- **Calendars and contacts** (in-house RFC 5545 / 6350 parsers): iCalendar
  and vCalendar events, to-dos, recurrence, time zones, organizers and
  attendees, date range and alarms that run a procedure; vCard 2.1 / 3.0 /
  4.0 names, organisations, titles, e-mail domains, phone and address
  counts.
- **PostScript and EPS** (DSC comments, previews, XMP, shown text) and
  **BibTeX** (entries, types, years, DOIs). LaTeX sources now also report
  class options, packages, the abstract, included files, figure / table /
  citation counts and the body text.
- **Privacy:** `--privacy strict` (the default) keeps only the domain of an
  e-mail address and counts phone numbers and street addresses;
  `--privacy off` lists them.
- **Engine:** a container extractor can hand a file to the format it found
  inside (`detected_by: content`), so compound files are routed to Word,
  Excel, Outlook and the rest by their streams.
- **Report schema:** new `DateField` values `printed`, `sent` and
  `received`, and `DetectedBy::Content` (additive; still `whiff/1`).
- **Developer tools:** `scripts/fixtures/documents.sh` regenerates the
  document fixtures with textutil, Ghostscript, Core Graphics and poppler,
  plus standard-library generators for the formats no local tool writes.

## 0.2.0 — 2026-10-17

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

Fixes:

- Reports read from stdin no longer carry the source name `-`.
- The LLM view no longer lowercases date values (`T` and `Z` came out as
  `t` and `z`).

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
