# whiff

**whiff** (verb): to catch the scent of something. Point `whiff` at any file and it returns one JSON document describing it: what it is, where it came from, who owns it, when it was made, what rights apply, its physical properties, and a compact, LLM-ready view of its content. Pure Rust, safe on untrusted input.

> **Status: 0.4 (Stage 4).** Every file gets the universal sections (identification, system, temporal, security, physical, integrity), plus `wc` statistics for text, owner names, extended attributes (macOS quarantine and "Where from", Finder tags, Windows `Zone.Identifier`), and a language, keywords, keyword frequency, excerpt and (in `full` / `llm`) a summary for any prose. Extractors cover plain text, logs, diffs, Markdown, HTML, XML, feeds, JSON / NDJSON / JSON5, YAML, TOML, INI / properties / dotenv, CSV / TSV, SQL, ~40 programming languages, package manifests, Jupyter notebooks, Dockerfiles and Makefiles, 41 image formats: JPEG, PNG, GIF, WebP, TIFF, HEIC / AVIF, JPEG XL, JPEG 2000, PSD, SVG, camera raw (DNG, CR2, CR3, NEF, ARW, ORF, RW2, PEF, RAF, SRW) and more, with EXIF, XMP, IPTC, ICC and Photoshop metadata reconciled the way the Metadata Working Group specifies, and documents: PDF, Word / Excel / PowerPoint / Visio (current and 97–2003), OpenDocument, RTF, EPUB, Kindle, FictionBook, comics, PostScript, BibTeX, e-mail (EML, mbox, MHTML, Outlook MSG), iCalendar and vCard, with macros, scripts, risky links and phishing signals flagged, and 23 audio formats: MP3, AAC / M4A / M4B, FLAC, Ogg Vorbis, Opus, Speex, WAV / Broadcast Wave / RF64 / Wave64, AIFF, CAF, WMA, WavPack, Monkey's Audio, Musepack, DSD, AMR and more, with ID3, Vorbis, APE, iTunes and ASF tags normalised, cover art, chapters and BWF / iXML production data, and video: MP4 / MOV / 3GP (fragmented too), Matroska / WebM, AVI, MPEG transport and program streams (TS, M2TS, MPG, VOB), FLV, WMV, RealMedia, Ogg Theora and H.264 / HEVC / AV1 / VP9 / MPEG-2 / YUV4MPEG2 elementary streams, with every stream's codec, profile, level, size, aspect ratio, frame rate, bit depth, colour and HDR format, rotation, chapters, tags, camera make, model and location, and the text of subtitle tracks, and subtitles: SRT, WebVTT, ASS / SSA, TTML, SAMI, SCC, EBU STL, PGS, VobSub, LRC and more, with cues, languages, speakers and the transcript, and playlists: M3U, HLS, DASH, Smooth Streaming, PLS, XSPF, ASX, WPL and CUE sheets, and scores: MIDI (with the tempo-map duration), tracker modules, MusicXML, MEI, MuseScore, Guitar Pro, ABC and LilyPond. Other formats are still identified by signature. [`docs/metadata-extracted.md`](https://github.com/baoulo/whiff/blob/main/docs/metadata-extracted.md) lists the 1004 formats planned, what is extracted from each, and which extractor handles it today.

## Install

```sh
brew install baoulo/tap/whiff                                    # macOS, Linux
scoop bucket add baoulo https://github.com/baoulo/scoop-bucket   # Windows
scoop install whiff
asdf plugin add whiff https://github.com/baoulo/asdf-whiff.git && asdf install whiff latest
mise use -g github:baoulo/whiff
curl -fsSL https://raw.githubusercontent.com/baoulo/whiff/main/scripts/install.sh | bash
cargo install whiff                                              # from source (Rust 1.89+)
```

Release binaries (Linux static, macOS, Windows) include every format collection; `cargo install whiff --features full` does the same from source. In GitHub Actions: `uses: baoulo/whiff/.github/actions/setup-whiff@main`.

## Use

```sh
whiff notes.md                        # one report (pretty-printed on a terminal)
whiff ~/projects/app                  # walks a directory (honours .gitignore); one JSON report per line
curl -s https://example.org/ | whiff -    # stdin: detection works from the content alone
whiff --profile llm README.md         # compact, token-budgeted view for language models
whiff --profile minimal --hash none disk.iso   # fast: stat and detection only, no hashing
whiff --only code.manifest package.json        # run only some extractors
whiff formats                         # formats this build extracts
whiff schema                          # JSON Schema of the report (whiff/1)
```

`whiff --profile llm guide.md` on a Markdown file with YAML front matter prints (abridged):

```json
{
  "format": "Markdown (markdown)",
  "title": "A Guide to the Old Harbour",
  "description": "Walks, boats and food around the old harbour.",
  "authors": ["Ada Example", "Ben Sample"],
  "language": "en",
  "dates": ["published: 2026-09-14", "modified: 2026-10-01T09:30:00+02:00"],
  "physical": { "lines": 48, "words": 158 },
  "rights": { "license": "CC-BY-4.0", "creators": ["Ada Example", "Ben Sample"] },
  "keywords": ["harbour", "boats", "quay", "harbour cafe", "fishing boats", "lighthouse"],
  "summary": "The old harbour is where the fishing boats come home. This guide covers the walk along the quay, the boats you will see and where to eat. Fish soup at the harbour cafe is the local favourite.",
  "outline": ["The Old Harbour", "  Walking the quay", "    Things to bring", "  Boats", "  Food"],
  "details": { "links": { "internal": 1, "external": 1 }, "code_languages": { "python": 1 }, "tasks": { "total": 3, "done": 1 } }
}
```

Images get their embedded metadata decoded (`metadata.exif`, `.xmp`, `.iptc`, `.icc`, `.photoshop`) and reconciled into the normalised fields. `whiff --profile llm harbour.jpg` prints (abridged):

```json
{
  "format": "JPEG image (jpeg)",
  "title": "Old harbour",
  "description": "Fishing boats in the old harbour at dusk",
  "authors": ["Mira Castell"],
  "dates": ["captured: 2024-05-01T19:42:10+02:00", "digitized: 2024-05-01T19:42:10"],
  "physical": { "pixels": "96x64" },
  "rights": { "copyright": "(c) 2024 Mira Castell, CC BY 4.0", "license": "https://creativecommons.org/licenses/by/4.0/", "creators": ["Mira Castell"] },
  "keywords": ["harbour", "boats", "dusk"],
  "details": { "process": "baseline", "chroma_subsampling": "4:2:0", "quality_estimate": 85 }
}
```

The full report adds the GPS location (`content.location`), camera settings, the ICC profile and the raw blocks. AI-generated images are flagged in `security.risks` (Stable Diffusion, ComfyUI and InvokeAI parameters in PNGs, the IPTC digital source type); SVGs with scripts or external references are flagged too.

Documents report their properties, outline and text; PDFs, Office files, RTF and e-mail also report active content (macros, JavaScript, DDE, external templates, launch actions) and phishing signals in `security.risks`, and their attachments and embedded files appear under `embedded`. Each risk carries a `category` (`active_content`, `phishing`, `external_reference`, `exploit`, …) and a `severity` (`info` to `high`); `security.risk_level` is the highest severity in the file or anything embedded in it, and `security.embedded_risks` counts the embedded files' risks. [`docs/risks.md`](https://github.com/baoulo/whiff/blob/main/docs/risks.md) lists every kind. Addresses are reduced to their domain unless you pass `--privacy off`.

Formats without an extractor yet (archives, media, executables, …) are still identified by signature, with every file-level section filled in.

As a library:

```rust
let engine = whiff::Engine::new();
let report = engine.extract_path("Cargo.toml")?;
println!("{}", serde_json::to_string_pretty(&report)?);
let compact = report.llm_view(800); // ~800 tokens
```

```toml
# library only, without the CLI's dependencies
whiff = { version = "0.4", default-features = false, features = ["common"] }
```

## The report

Every report has the same top-level sections: `whiff`, `source`, `identification`, `system`, `temporal`, `security`, `rights`, `physical`, `integrity`, `content`, `metadata` (raw metadata per standard: front matter, HTML meta, OpenGraph, JSON-LD, EXIF, XMP, IPTC, ICC, Photoshop resources), `format` (technical details per format), `embedded` (children of containers) and `diagnostics`. Empty fields are omitted; sections are always present. The schema is in [`docs/schema/whiff-1.schema.json`](https://github.com/baoulo/whiff/blob/main/docs/schema/whiff-1.schema.json).

Secrets found in content (keys, tokens, credentials in URLs) are counted under `security.secrets` and redacted from the report; personal data (e-mail addresses, phone numbers, card numbers, IBANs) is counted under `security.personal_data` and never listed in derived text.

Untrusted input is bounded: reads, decompression and time are budgeted per file, panics in extractors are contained, deeply nested input is refused before recursive parsers see it, and an extractor that ignores its deadline is abandoned by a watchdog.

## Features

| Feature | Default | Adds |
|---|---|---|
| `common` | yes | text, logs, diffs, Markdown, HTML, XML, feeds, JSON, YAML, TOML, INI, CSV, SQL, source code, package manifests, notebooks, Dockerfiles, Makefiles, raster / vector / layered images, camera raw, GPU textures, documents (PDF, Office, OpenDocument, RTF, ebooks, PostScript, BibTeX), e-mail, calendars and contacts, audio, video, subtitles, playlists, scores; archives, executables and more in later releases |
| `cli` | yes | the `whiff` binary |
| `geo`, `science`, `data`, `cad`, `forensics`, `games` | no | specialist collections (GIS, scientific and medical, columnar data, CAD and 3D, forensics, games); reserved, empty in 0.4 |
| `full` | no | all collections |

The minimum supported Rust version is 1.89.

## Contributing

Adding a format is one file. See [CONTRIBUTING.md](https://github.com/baoulo/whiff/blob/main/CONTRIBUTING.md).

## Licence

MIT. See [LICENSE](https://github.com/baoulo/whiff/blob/main/LICENSE).
