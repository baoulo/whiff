# Changelog

All notable changes to whiff are recorded here. The report format is
versioned separately (`whiff.schema`, currently `whiff/1`); additive changes
keep the schema version.

## 0.5.0 — 2026-10-25

Archives and compressed files (packages and disk images to come).

- **Compressed files:** gzip (name, time, comment, operating system,
  level, extra subfields incl. BGZF and dictzip; several members), raw
  zlib, bzip2 (several streams), xz (check, filters, dictionary; streams,
  blocks and size from the index), `.lzma`, lzip, Zstandard (window,
  content size, dictionary id, checksum, skippable frames, seekable
  format), LZ4 (frame and legacy formats), Brotli, Unix `compress` (`.Z`)
  and the Snappy framing format are decompressed and the stream inside is
  analysed in turn, so `x.tar.gz` lists the tar's entries. The stream
  does not use up a recursion level (up to three nested layers). lzop and
  LZFSE headers are read. Declared and measured sizes, trailing data and
  decompression bombs are reported.
- **Archives:** ZIP (Zip64, extended-timestamp and NTFS times, Unix modes,
  ZipCrypto and WinZip AES, comment, the system that made it, a
  self-extractor or polyglot prefix; stored, deflate, bzip2, LZMA,
  Zstandard and xz entries handed on), tar (v7, ustar, pax with global
  and extended headers, GNU long names and sparse files; checksums
  verified), 7z (plain and packed headers, folders, coders, solid blocks,
  encrypted headers; copy, LZMA, LZMA2, deflate and bzip2 folders, with
  BCJ or delta filters, handed on), RAR 4 and 5 (volume, solid, recovery
  record, lock, encrypted headers, comment; stored entries handed on),
  Microsoft Cabinet (sets of cabinets, folders; uncompressed and MSZIP
  folders handed on), LHA (header levels 0–2), ARJ, cpio (newc, crc, odc,
  binary) and `ar` (GNU and BSD names, symbol tables). Every archive
  reports the same inventory: entry, file, folder and link counts, sizes
  and ratio, methods, encrypted entries, file types, top-level folders,
  the range of modification times and the first 50 entries. ZIP names
  without the UTF-8 flag are read as code page 437.
- **Risks:** `path_traversal`, `absolute_path`, `symlink_escape`,
  `decompression_bomb` and `overlapping_entries` (Fifield's overlapping
  zip bomb), plus `double_extension` for archive entries; `trailing_data`
  now also covers archives and compressed streams.
- **Engine and plugin API:** `plugin::codec` decodes every codec above
  into at most a given number of bytes, charged to the decompression
  budget, with memory bounded by the output (LZMA dictionaries are never
  larger than it); `Context::decompress`, `decompress_mszip`,
  `emit_inner` (the stream inside a compressed file), `emit_child_prefix`
  (the start of a larger entry) and `child_room`. The ZIP reader reads
  extra fields, more methods and entries' first bytes
  (`Zip::read_prefix`). New dependencies, all pure Rust: `ruzstd`,
  `lzma-rust2` and `brotli-decompressor` (132 of 185 for the library).
- **Tests:** `tests/bombs.rs` checks that a 1 GiB zip bomb, a 42.zip-style
  nest of them (256 GiB in all), an overlapping-entry bomb, archives whose
  paths leave the target folder and a deep gzip-in-gzip chain are all
  reported within the limits; the inputs are built in memory, not kept as
  fixtures.
- **Developer tools:** `scripts/fixtures/archives.sh` regenerates the
  archive and compression fixtures with bsdtar, Info-ZIP, 7-Zip, Python's
  zipfile and tarfile, gzip, bzip2, xz, zstd, lz4, brotli, compress and
  `compression_tool`; `craft_archives.py` writes RAR, CAB, LHA, ARJ, lzip,
  Snappy, lzop and BGZF files (checked with `7zz t`).
  `archive_corpus.sh` builds a larger corpus from system folders with
  every method each tool offers, and `archive_oracle.py` compares entry
  counts, paths, types and sizes with 7-Zip's listing and uncompressed
  sizes with the reference decompressors.

## 0.4.0 — 2026-10-22

Audio, video, subtitles, playlists and scores.

- **Audio** (in-house readers, no new dependencies): MP3 / MP2 / MP1
  (frame header, Xing / Info / VBRI and LAME tags, duration from the VBR
  header, the CBR size or a bounded frame walk), AAC (ADTS) and MPEG-4
  audio (M4A, M4B, M4P, M4R: AAC profile, ALAC, Opus, FLAC, AC-3, AMR),
  FLAC (STREAMINFO, cue sheet, seek table, pictures), Ogg Vorbis / Opus /
  Speex / FLAC (headers reassembled across pages, duration from the last
  granule), WAV, Broadcast Wave (`bext`, iXML), RF64 / BW64 and Wave64,
  AIFF / AIFF-C, CAF (packet table, `info`), WMA (ASF header objects, DRM),
  WavPack, Monkey's Audio, Musepack SV7 / SV8, TTA, DSF and DSDIFF, AMR,
  Sun AU and Creative VOC. Streams report codec, profile, sample rate,
  channels and layout, bit depth, bitrate and CBR / VBR. HE-AAC reports
  its output rate and channels from the AudioSpecificConfig (SBR / PS
  signalling included), not the sample entry's. Durations, sample rates
  and channel counts agree with `ffprobe` on every fixture and on 6 615
  audio files found on a Mac (system sounds, ringtones, voice prompts,
  GarageBand and application content). Durations are the presentation
  length: the encoder priming and padding an MP4 edit list or CAF packet
  table marks are left out, where ffprobe keeps them (497 of those files).
- **Video** (in-house readers, no new dependencies): MP4 / M4V / MOV / 3GP
  / F4V / CMAF (fragmented files' durations from `mehd` or the `moof`
  run tables), Matroska / WebM / MKA / MKS (EBML; seek head, chapters,
  tags, attachments; the duration from the last cluster when the header
  has none), AVI and OpenDML, MPEG transport streams (TS, BDAV M2TS:
  PAT / PMT / SDT, stream types and descriptors, scrambling) and program
  streams (MPEG-1, MPEG-2, DVD VOB with private-stream audio and
  subpictures), FLV (AMF0 `onMetaData`, enhanced-RTMP FourCCs), WMV,
  RealMedia, Ogg Theora, and elementary streams (H.264, HEVC, MPEG-1 / 2
  video, AV1 OBU, IVF, YUV4MPEG2). Each stream reports codec and tag,
  profile, level and tier, size, display size, sample and display aspect
  ratios, frame rate and CFR / VFR, frame count, bit depth, chroma
  subsampling, colour primaries / transfer / matrix / range, HDR format
  (HDR10, HLG, Dolby Vision), mastering display and content light level,
  scan type and field order, rotation, stereo mode, bitrate, language,
  title, and default / forced flags, read from the container and the
  codec configuration (H.264 / HEVC parameter sets with VUI, `avcC`,
  `hvcC`, `av1C` and the AV1 sequence header, `vpcC` and VP8 / VP9 key
  frames, MPEG-1 / 2 sequence headers and extensions, MPEG-4 Part 2
  profiles, `colr`, `pasp`, `mdcv`, `clli`, `dvcC`). TS and PS durations
  come from the first and last presentation time stamps. Camera make,
  model and software go to `format.device`, QuickTime / ISO 6709
  locations to `content.location`, the QuickTime creation date to the
  captured date, and MP4 XMP to the XMP decoder. Durations, sizes,
  frame rates and codecs agree with `ffprobe` on 2 052 video files that
  ship with macOS and installed applications (one duration differs: an
  edit list that ends a track after the movie header's length).
- **Subtitles** (in-house readers, no new dependencies): SubRip, WebVTT,
  ASS / SSA, TTML (TTML 1 / 2, DFXP, IMSC, SMPTE-TT, EBU-TT: clock, frame,
  tick and offset times, nested time containers, agents), SAMI (classes
  and their languages), YouTube SBV, srv1 / srv2 / srv3 and json3,
  SubViewer 1 and 2, Spruce STL, MicroDVD, MPL2, LRC (ID tags, offsets,
  word times), Scenarist SCC (a CEA-608 decoder for pop-on, roll-up and
  paint-on captions), EBU STL (GSI titles, language, dates and counts; ISO
  6937 and ISO 8859 text), Blu-ray PGS and the VobSub index. Each reports
  the cue count, the first cue and the end of the last, language, title
  and author, styles and fonts, speakers, the frame rate, the markup used,
  sound-description and music cues, overlapping and out-of-order cues, and
  the format's header fields, and hands the transcript to the text
  analyzers. Codecs, cue counts and end times agree with `ffprobe` on 51
  of 52 files (the fixtures, ffmpeg's own subtitle test samples and the
  Sintel subtitles; the miss is a trimmed VobSub sample whose index points
  past its picture data). Where ffmpeg reads a format differently (it
  drops SubViewer cues whose text starts with `[`, reads LRC millisecond
  fractions and Spruce STL frames as hundredths), whiff follows the format.
- **Playlists** (in-house readers): M3U and extended M3U (IPTV attributes
  and groups), HLS master playlists (variants with bandwidth, resolution,
  codecs, frame rate and video range; renditions; I-frame variants;
  session data) and media playlists (segments and total duration, target
  duration, VOD / live, fMP4 / TS / packed audio, byte ranges, gaps,
  encryption and key formats, program date-times, ad markers,
  low-latency parts), PLS, XSPF, ASX, WPL / ZPL, CUE sheets (catalogue
  number, REM fields, files, tracks with ISRCs and index times, disc
  images), MPEG-DASH (type, duration, periods, adaptation sets,
  representations, segment addressing, DRM systems) and Smooth Streaming
  client manifests. Entries report titles, artists, albums and durations;
  locations only by file name and host, since paths name folders and users
  and query strings can carry access tokens. Remote entries count as
  external references; HLS keys and DRM systems set `security.encrypted`.
- **Subtitle text in video files:** the text of SubRip, ASS / SSA and
  WebVTT tracks in Matroska and WebM (zlib and header-stripping
  compression included), and of 3GPP timed text, QuickTime text and
  WebVTT tracks in MP4 / MOV, is read into cues. Each subtitle stream
  reports its cue count and the end of its last cue, and the text of one
  track (the default one that is not forced) goes to the text analyzers.
  Matroska blocks of other tracks are skipped by their headers; the walk
  is skipped in the `minimal` profile and stops at its block, byte and
  time limits with a warning.
- **Scores** (in-house readers): Standard MIDI files (formats 0, 1 and 2),
  karaoke `.kar` and RIFF MIDI: division, tracks with names and
  instruments, the tempo map and the duration it gives, time and key
  signatures, General MIDI program names, percussion, note counts, GM /
  GM2 / GS / XG, markers (as chapters), cue points, copyright and lyrics.
  Tracker modules (MOD, XM, S3M, IT, MPTM): title, tracker, channels,
  orders, patterns, instrument and sample names, the IT song message, and
  the length of one pass, from a walk of the patterns for the commands
  that change timing. Notation: MusicXML (partwise and timewise) and
  compressed MXL, MEI, MuseScore (`.mscx`, `.mscz`), Guitar Pro 3 to 5,
  ABC (tune books too) and LilyPond: title, composer and other creators,
  rights, software, parts with instruments, staves, measures, notes and
  rests, key, time signature, tempo, repeats, length in quarter notes
  (seconds when a tempo is marked) and lyrics. MIDI durations agree with
  mido on every fixture and on 100 corpus scores rendered by music21; on
  music21's corpus (627 MusicXML / MXL scores, 1 146 ABC files) staves,
  measures and ABC tune counts agree on all, notes on 99.8 % and lengths
  in quarter notes on 97.1 %. `.abc` Alembic, `.mod` DTD and `.gpx` GPS
  files are not mistaken for scores.
- **Tags:** ID3v1 / v1.1 and ID3v2.2–2.4 (unsynchronisation, compressed
  and grouped frames, iTunes' non-syncsafe sizes, CHAP / CTOC chapters),
  Vorbis comments, APEv1 / v2, iTunes `ilst` (with free-form `----` items
  and QuickTime `keys`), RIFF `INFO`, ASF / `WM/` attributes, AIFF text
  chunks, CAF `info` and DSDIFF edited-master data are kept in their own
  names under `metadata.<standard>` and normalised into `format.tags`
  (title, artist, album, track / disc and totals, dates, genre, composer,
  label, ISRC, BPM, key, MusicBrainz ids, ReplayGain…), which fills
  `content`, `rights` and `temporal`. Cover art is described and handed
  on as an embedded file; chapters fill `format.chapters` and the outline;
  lyrics go to the text analyzers. A purchaser's Apple ID or name
  (`apID`, `ownr`) goes through the privacy setting.
- **Containers:** `plugin::mp4` (ISO base media: tracks, sample tables,
  `esds`, `ilst`, chapters, visual sample entries and their configuration
  boxes, protection schemes, movie fragments, subtitle text samples, XMP)
  and `plugin::asf` (ASF
  header objects, extended stream properties, language list) are shared
  by the audio and video extractors; the HEIF extractor uses
  `plugin::mp4`'s box iterator. A WMA file with a video stream is handed
  to the WMV extractor, and an Ogg file with a Theora stream is reported
  as Ogg video.
- **Developer tools:** `scripts/fixtures/scores.sh` regenerates the score
  fixtures with mido, music21, verovio and pyguitarpro;
  `craft_scores.py` writes the tracker modules, RIFF MIDI, ABC, LilyPond
  and MuseScore files; `score_oracle.py` compares whiff with music21 and
  mido. `whiff-dev oracle subtitles` compares subtitle
  codecs, cue counts and the end of the last cue with `ffprobe`'s packets
  (gate: 98 % of cue counts). `scripts/fixtures/subtitles.sh` regenerates
  the subtitle and playlist fixtures with ffmpeg, GStreamer, pysubs2,
  pycaption, the m3u8 library and metaflac; `craft_subtitles.py` writes
  the formats none of them does (SBV, SubViewer, Spruce STL, YouTube timed
  text, EBU STL, PGS, VobSub, hand-written playlists).
  `whiff-dev oracle media` compares durations,
  sample rates and channel counts, and the first video stream's codec,
  size and frame rate, with `ffprobe` (gate: 98 % of durations within
  0.1 s; mono HE-AAC, which ffmpeg decodes to stereo, counts as agreeing).
  `scripts/fixtures/video.sh` regenerates the video fixtures with ffmpeg,
  GStreamer's own muxers, the x264 / x265 encoders, VideoToolbox and
  `avconvert`. `scripts/fixtures/audio.sh` regenerates the audio
  fixtures with ffmpeg, LAME, flac / metaflac, speexenc, mpcenc and Core
  Audio's `afconvert`; `craft_audio.py` writes the iXML chunk and the
  Monkey's Audio, DSF and DSDIFF files no available tool writes.

## 0.3.0 — 2026-10-18

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
- **Risk categories and severities:** every `security.risks[]` entry now
  has a `category` (`active_content`, `phishing`, `external_reference`,
  `exploit`, `obfuscation`, `data_exposure`, `supply_chain`,
  `unsafe_operation`, `provenance`) and a `severity` (`info`, `low`,
  `medium`, `high`), both decided by the kind in one vocabulary
  (`src/report/risk.rs`, listed in the generated `docs/risks.md`).
  `security.risk_level` is the highest severity of a file and everything
  embedded in it; `security.embedded_risks` counts embedded files' risks by
  kind, at any depth. The LLM view shows the level and each risk's
  severity. Kinds outside the vocabulary (third-party extractors) are
  `other` / `medium`; the conformance suite fails on any in whiff.
- **Report schema:** new `DateField` values `printed`, `sent` and
  `received`, `DetectedBy::Content`, and the risk fields above (additive;
  still `whiff/1`).
- **Pure-Rust check:** `whiff-dev check-deps` fails on `-sys` crates and
  native build tools in the library's and CLI's dependency graph, and CI
  checks that the published crate holds no development tooling.
- **Developer tools:** `scripts/fixtures/documents.sh` regenerates the
  document fixtures with textutil, Ghostscript, Core Graphics and poppler,
  third-party writers (rust_xlsxwriter, simple_excel_writer, docx-rs and
  ppt-rs in `scripts/fixtures/office_gen`; Apache POI for BIFF8 workbooks,
  PowerPoint 97 slide shows and genuinely encrypted xls, ppt and OOXML),
  plus standard-library generators for the formats no local tool writes.
  Files from these independent writers showed and fixed: a false macro
  risk on every PowerPoint-saved `.ppt` (the VBA-info record is present
  without a project), slides lost after a record whose length overruns its
  container, master-slide placeholders read as slide text, packed string
  vectors in property sets (PowerPoint's `TitlesOfParts`), sheet names read
  from encrypted BIFF records, and encrypted OOXML whose directory is not
  contiguous left as a plain compound file. Excel cell notes and threaded
  comments are now counted, with their authors.
- **Release:** the release workflow now pushes the Homebrew formula and
  Scoop manifest to `baoulo/homebrew-tap` and `baoulo/scoop-bucket`, and
  publishes to crates.io only once that has succeeded.

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
