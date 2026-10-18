# whiff: metadata extracted per file format

This is the reference for **what whiff extracts from each file format, why it is useful to an LLM, and which pure-Rust library (or in-house parser) produces it**. Stages (S0–S8) refer to the implementation plan. whiff is a single crate. The **Feature** column gives the cargo feature that compiles each format's extractor: `common` (default) or one of the opt-in specialist features `geo`, `science`, `data`, `cad`, `forensics`, `games` (`full` = all).

*Researched 2026-10-15. Crate versions were checked against the crates.io API on that date.*

## 1. How this list was built

* **No authoritative "top 1000 file formats" ranking exists.** This list was curated from common usage and cross-checked against the freedesktop `shared-mime-info` database, the IANA media-type registry, The National Archives PRONOM registry, and Wikipedia's list of file formats. Formats are sorted into three popularity **tiers**, not given an exact rank.
* Some rows cover a *format family that shares one parser* (for example "Canon CR2 / CR3 / CRW"). One row = one thing a contributor would implement and test as a unit.
* Rows with the same family share an extractor. The per-format column lists only what that format adds on top of its family.
* **Pure Rust is a hard constraint.** Crates that wrap C libraries are listed only as rejected alternatives: `rusqlite` (bundled SQLite), `unrar`, `xmp_toolkit`, `netcdf`, `hdf5-metno`, `libheif-rs`, `tree-sitter`, `ffmpeg-next`, `lcms2`, `minimp3`, `opus` and `sequoia-openpgp` (Nettle backend). Where the only option was C, the format is marked **impl**: whiff writes the parser, usually header-only, which covers the metadata.

### Library verification against the reviewed article

The article [*Rust libraries for file formats* (2026-10-13)](https://thanos.github.io/articles/2026-10-13-rust-libraries-for-file-formats/) was the starting point. Each crate it names was looked up on crates.io:

| Article claim | Finding on crates.io (2026-10-15) | Decision |
|---|---|---|
| `file-format` is the main detection crate | 0.29.0, ~2M downloads, actively maintained | **Use** as the primary magic database |
| `filetype` uses PRONOM signatures | `filetype` 0.2.0 dates from 2015 and is an unrelated `std::fs::File` extension | Reject. `infer` (132M downloads) and `mimetype-detector` (~500 types) are the real alternatives |
| `xberg` does lightweight magic inference | Actually a document-intelligence (text extraction) library | Not used for detection |
| `oxiarc` handles ZIP, TAR, GZIP, XZ, CAB and LZH | No crate named `oxiarc`; published as `oxiarc-core` and `oxiarc-archive` 0.4.2 (low adoption) | Prefer `zip`, `tar`, `cab` and `delharc`; evaluate `oxiarc-archive` |
| `spoor` reads ELF, PE, Mach-O and WASM metadata plus DWARF | `spoor` 0.1.0 (12 downloads) only recovers the crate manifest from Rust binaries | Use `goblin` / `object` + `gimli`. `spoor` is an optional extra for Rust binaries |
| `turbo-parsepdf-core` speedups | 0.1.1, about 40 downloads | Not used. whiff reads PDF with an in-house parser |
| `doc_loader` gives unified extraction | 0.3.2, about 2k downloads | Not used. Per-format crates instead |
| `oxigdal` / `oxigeo` as a pure-Rust GDAL | 0.1.7 / 0.2.4, about 1k downloads each | Evaluate later (S7). Use mature single-format crates first |
| `bitframe` for bit-level headers | 0.1.1, 32 downloads | Not used. `binrw` + `zerocopy` instead |
| `symphonia` as the pure-Rust audio demuxer/decoder | 0.6.1, 17M downloads | **Use** for codec parameters and duration. Tags come from `lofty` |
| `image` + `png`, `zune-jpeg`, `image-webp`, `tiff`, `exr` | All mature | **Use** (decode is opt-in; probing uses `imagesize` + `img-parts`) |
| HEIC, AVIF and JPEG XL need FFI | `jxl-oxide`, `avif-parse` and `heic` 0.1.6 are pure Rust | Metadata comes from ISOBMFF boxes (`mp4-atom`), so no FFI is needed |
| `rusqlite` for embedded databases | Bundles C SQLite | Reject. Implement a read-only SQLite b-tree reader for the schema |
| `arrow`, `parquet`, `lance`, `vortex-ipc` | All current | `parquet` / `arrow` footer-only by default. `lance` and `vortex` are feature-gated (heavy) |
| `monstertruck-io` for STEP/IGES | 0.4.1, about 600 downloads, full B-rep | Feature-gated. The default is an in-house ISO-10303-21 header lexer |

Crates the article missed that whiff relies on: `lofty` (audio tags), `kamadak-exif`, `nom-exif`, `img-parts`, `imagesize`, `mail-parser`, `read-fonts` / `skrifa`, `x509-parser`, `pgp`, `goblin`, `object`, `gimli`, `mp4-atom`, `matroska`, `mpeg2ts-reader`, `hdf5-reader` (pure-Rust HDF5), `netcdf3`, `fitsrs`, `dicom-object`, `lava_torrent`, `tokei`, `whatlang`, `yake-rust`, `chardetng`, `feed-rs`, `ssh-key`, `midly`, `fitparser` and `serde-saphyr`.

## 2. Universal information (every file, every format)

These sections are filled for **every** file before format-specific extraction runs. They map directly onto the categories you asked for.

| Section | Fields | Source |
|---|---|---|
| **System identification** | path (as given + canonical), file name, stem, extension, detected format id + name + MIME + confidence + detector, extension/content mismatch flag, device id, inode, hard-link count, file kind (regular/dir/symlink/fifo/socket/device), symlink target, hidden flag, hostname (opt-in) | `std::fs::Metadata`, `std::os::unix::fs::MetadataExt`, `file-format` + `infer` + in-house sniffers |
| **Temporal data** | filesystem: modified, accessed, changed (ctime), created (birth time where available); content: every date the extractors found (EXIF DateTimeOriginal, PDF CreationDate, docProps created/modified, ID3 TDRC, archive entry mtime range...), normalised to RFC 3339 with `source` provenance and `tz_known` | `std::fs`, `jiff` for parsing and normalisation |
| **Security & rights** | Unix mode (octal + rwx string), owner uid/gid + names, setuid/setgid/sticky, ACL present, extended attributes (names; values for `com.apple.quarantine`, `com.apple.metadata:kMDItemWhereFroms`, `user.xdg.origin.url`), Windows Zone.Identifier ADS (when present); content: encrypted?, signed?, signature validity (where checkable offline), macros/scripts/active content present, external references, DRM present, copyright / licence / usage terms gathered from EXIF, IPTC, XMP (`xmpRights`, `cc`), ID3 TCOP, font fsType, package licences | `rustix`, `uzers`, `xattr` + per-format extractors |
| **Physical properties** | size in bytes, allocated blocks, sparse?; for text: `wc` (bytes, chars, words, lines, max line length), line endings, encoding, BOM; for binaries: Shannon entropy + per-block profile; dimensions / duration / page count / entry count / row count as applicable | streaming counters, `unicode-segmentation` |
| **Integrity** | SHA-256 and BLAKE3 (configurable, streaming), optional perceptual hash (images) and TLSH-style similarity hash | `sha2`, `blake3` |
| **Content (LLM view)** | title, authors, description, language (+ confidence), keywords (YAKE), keyword frequency (top N stemmed terms), headings outline, extractive summary (TextRank, N sentences), text excerpt (token-budgeted), tags (merged from metadata keywords + extracted keywords) | `whatlang`, `yake-rust`, `stop-words`, `rust-stemmers`; TextRank implemented in-house |
| **Embedded / children** | for containers (archives, emails, Office files, PDFs with attachments): each child gets its own (bounded, recursive) whiff record | engine recursion with depth, size and count limits |
| **Diagnostics** | extractors run + versions + timings, warnings, partial/truncated flags, limits hit | engine |

**Privacy defaults.** Whiff never outputs secret material, such as private-key bytes, passwords, `.env` values or cookie values. Personal data is **counted, not listed** by default: email addresses in vCards, DICOM patient fields, browser history URLs and IP addresses in logs. `--privacy=off` lifts the counted-not-listed rule for personal data. It never lifts the rule for secrets.


## 3. Parser families

Each format in §5 maps to one **family**. A family is one extractor implementation (or one reusable *block decoder*, marked `Block`) that serves every format in it. This is why ~1000 formats need ~60 extractors.

Status: **crate** means a pure-Rust crate does the heavy lifting. **mixed** means a crate parses the container and whiff maps it to the schema. **impl** means no suitable pure-Rust crate exists, so whiff implements the parser.

| Family | Category | Feature | Information extracted | Why it helps an LLM | Library / implementation | Status | Stage | # formats |
|---|---|---|---|---|---|---|---|---|
| `text.plain` | Text | `common` | encoding + BOM + confidence, line endings, bytes/chars/words/lines (wc), longest line, blank-line ratio, natural language, top keywords (YAKE), keyword frequency, extractive summary (TextRank), first-N-chars excerpt, detected secrets/PII counts (not values) | Language, summary and keywords let an LLM decide relevance without reading the file; wc numbers size the token budget | chardetng, encoding_rs, unicode-segmentation, whatlang, yake-rust, stop-words, rust-stemmers; TextRank summarizer = impl | mixed | S1 | 17 |
| `text.markdown` | Text | `common` | front matter (YAML/TOML/JSON) keys + title/date/tags, H1-H6 outline, link count (internal/external), image refs, code-block languages, tables, task-list done/total, + text.plain stats on rendered text | Outline + front matter is a near-perfect table of contents for retrieval | pulldown-cmark, gray_matter (or serde-saphyr + toml) | crate | S1 | 4 |
| `text.lightmarkup` | Text | `common` | document title, section outline, directives/roles used, links, + text.plain stats | Outline for docs written in non-Markdown markup | impl (line-oriented heading scanners per syntax) | impl | S8 | 11 |
| `text.html` | Web | `common` | &lt;title&gt;, lang, charset, meta (description, keywords, author, robots, generator, viewport, theme-color), OpenGraph + Twitter card, canonical/alternate/hreflang, feeds, favicon, JSON-LD/microdata/RDFa schema.org types, H1/H2/H3 (all H1-H6) outline, link counts internal/external + top hosts, images (+alt coverage), forms/inputs, scripts & stylesheets (inline/external hosts), iframes, visible text -&gt; text.plain | Title/description/OG + heading outline summarise a page; schema.org types say what the page *is* (Article, Product, Recipe) | html5ever + scraper (tl as fast path for huge files) | crate | S1 | 6 |
| `text.xml` | Data | `common` | XML decl (version/encoding/standalone), DOCTYPE, root element, namespaces, schemaLocation, element/attribute counts, max depth, top element names, processing instructions, vocabulary detection (XSD, XSLT, DocBook, TEI, JATS, XAML, Maven POM, MSBuild...), text content -&gt; text.plain | Root + namespaces identify the dialect; element histogram describes structure | quick-xml | crate | S1 | 32 |
| `text.feed` | Web | `common` | feed type/version, title, link, description, language, updated, generator, item count, newest/oldest item dates, latest N item titles + links, authors, categories | Directly answers 'what is this feed about and is it active' | feed-rs (RSS 0.x/1.0/2.0, Atom, JSON Feed); quick-xml for OPML/sitemaps | crate | S1 | 5 |
| `data.json` | Data | `common` | validity, top-level type, inferred schema (key paths -&gt; types, sample values, cardinality), depth, array lengths, record count (NDJSON), $schema/known-schema detection (package.json, tsconfig, OpenAPI, JSON Schema, GeoJSON, HAR, Jupyter...) | Inferred schema lets an LLM write correct code/queries against the file without seeing it all | serde_json, json5 (JSON5/JSONC) | crate | S1 | 32 |
| `data.yaml` | Data | `common` | documents count, inferred schema, anchors/aliases, known-schema detection (Kubernetes apiVersion/kind, OpenAPI, GitHub Actions, docker-compose, Ansible, Helm, CloudFormation) | kind/apiVersion style detection tells the LLM exactly what the config does | serde-saphyr (panic-free) / saphyr | crate | S1 | 15 |
| `data.toml` | Data | `common` | inferred schema, known-schema detection (Cargo.toml, pyproject.toml, netlify, rustfmt...), package name/version/deps when manifest | Same as JSON/YAML | toml | crate | S1 | 1 |
| `data.ini` | Data | `common` | sections, keys per section, value types; values that look like secrets are redacted (key name kept) | Config structure without leaking secrets | rust-ini, java-properties, dotenvy (parser only) | crate | S1 | 12 |
| `data.csv` | Data | `common` | dialect (delimiter, quote, escape, header present), column names, inferred column types, row count, null/empty ratio, distinct estimate, numeric min/max/mean, date ranges, 5 sample rows | Column schema + samples is exactly what an LLM needs to analyse a table | csv (+ impl dialect sniffer) | mixed | S1 | 13 |
| `data.sql` | Data | `common` | dialect guess, statement counts by kind, tables/views created + columns, inserts per table, referenced tables | Turns a dump/migration into a schema summary | sqlparser | crate | S1 | 4 |
| `data.binser` | Data | `common` | top-level type, inferred schema (as JSON), embedded schema where the format has one (Avro), record count, protobuf wire-format field numbers/types when no schema | Makes opaque binary serialisations inspectable | rmp-serde, ciborium, bson, plist, lava_torrent (bencode), apache-avro; protobuf wire walker = impl | mixed | S6 | 32 |
| `code.source` | Code | `common` | language (extension + shebang + modeline + content heuristics), LOC code/comment/blank, imports/includes, top-level symbols (functions, types, classes), doc comment of module, SPDX/licence header, TODO/FIXME counts, test file?, generated file?, minified? | Imports + symbols = a cheap 'map' of the codebase for an LLM | tokei (LOC), syn (Rust), oxc_parser (JS/TS), impl regex symbol scanners for the rest (tree-sitter is C) | mixed | S1/S6 | 117 |
| `code.manifest` | Code | `common` | ecosystem, package name, version, description, licence, authors, repository, dependencies (+dev) with versions & counts, scripts/entry points, lockfile: resolved package count | Dependency + licence picture of a project | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | impl | S1 | 33 |
| `code.notebook` | Code | `common` | kernel + language, nbformat, cell counts by type, markdown headings outline, imports, output types, error outputs, executed?, execution order | Outline + imports + errors summarise an analysis notebook | serde_json | impl | S1 | 4 |
| `code.infra` | Code | `common` | per dialect: base images/stages/ports/entrypoint (Dockerfile), targets (Makefile), providers/resources/modules (Terraform/HCL), server blocks (nginx), unit/exec (systemd), schedules (crontab) | What does this infra file deploy/run | hcl-rs + impl line scanners | mixed | S8 | 9 |
| `text.subtitle` | Media | `common` | cue count, first/last timestamp (duration covered), language tag, styles/speakers, frame rate (MicroDVD), full transcript text -&gt; text.plain | Transcript text is the content of the video for an LLM | impl (all formats are simple), ass_parser optional | impl | S4 | 11 |
| `text.calendar` | Personal | `common` | calendar name, prodid, event/todo counts, date range, recurring events, organizers/attendee counts, locations, timezones, event summaries (first N) | Schedules summarised | impl (RFC 5545 content lines, vCalendar 1.0) | impl | S3 | 3 |
| `text.contact` | Personal | `common` | contact count, versions, names, organisations, titles; emails/phones counted or redacted per privacy policy | Who is in the address book (privacy-aware) | impl (RFC 6350 content lines, vCard 2.1/3.0/4.0) | impl | S3 | 2 |
| `email` | Personal | `common` | From/To/Cc/Reply-To, Date, Subject, Message-ID, In-Reply-To/References (thread), mailer, Received hop count + first/last hop, SPF/DKIM/DMARC results, list headers, attachments (name, type, size), body text/plain (or html-&gt;text) -&gt; text.plain; mailbox: message count, date range, top senders | Who/when/what + thread linkage + attachment inventory | mail-parser (EML, mbox, MHTML, EMLX); impl MSG (MS-OXMSG over the in-house CFB reader, MS-OXRTFCP) | mixed | S3 | 11 |
| `doc.pdf` | Document | `common` | Info dict (Title, Author, Subject, Keywords, Creator, Producer, CreationDate, ModDate, Trapped), XMP (dc/xmp/pdf/pdfaid/pdfuaid), version, page count + page sizes, linearized, encrypted + permission bits, tagged, PDF/A/X/UA/E conformance, outline/bookmarks (-&gt; headings), fonts (embedded?), image count, AcroForm/XFA fields, annotations, JavaScript/OpenAction/Launch (security), embedded files, digital signatures, /Lang, per-page text -&gt; text.plain | Bookmarks + metadata + text summary; JS/embedded files flags matter for safety | impl (objects, xref tables/streams, object streams, repair, filters, RC4/AES decryption, content-stream text) + meta.xmp | impl | S3 | 5 |
| `doc.ooxml` | Document | `common` | docProps/core.xml (title, subject, creator, keywords, description, lastModifiedBy, revision, created, modified, category, contentStatus), app.xml (Application, AppVersion, Pages, Words, Characters, Lines, Paragraphs, TotalTime, Company, Manager, Template), custom.xml properties, headings outline (Heading styles), comments + authors, tracked changes count, hyperlinks, macros present (vbaProject.bin), external links, embedded objects, sensitivity labels (MSIP_*); XLSX: sheets + dimensions, defined names, formula count, charts/pivots; PPTX: slide count, slide titles, notes | Authoring history + outline + slide/sheet titles; macro & external-link flags for safety | impl (in-house ZIP reader + quick-xml mapping; BIFF12 workbook not read) | impl | S3 | 11 |
| `doc.odf` | Document | `common` | meta.xml (title, description, subject, keywords, initial-creator, creator, creation-date, date, editing-cycles, editing-duration, generator, document-statistic), headings outline, sheets/slides, macros present (Basic/), text -&gt; text.plain | Same as OOXML | impl (in-house ZIP reader + quick-xml) | impl | S3 | 8 |
| `doc.ole` | Document | `common` | SummaryInformation (title, subject, author, keywords, comments, template, last author, revision, app name, created/last-saved/last-printed, edit time, pages/words/chars, security flags) + DocumentSummaryInformation (company, manager, category, lines, paragraphs, slides, notes), stream/storage tree, VBA macros present, encrypted, embedded OLE objects; text where feasible | Legacy Office authoring metadata + macro flag | impl (MS-CFB reader, MS-OLEPS, MS-OVBA, BIFF8, PowerPoint records, Word piece table) | impl | S3 | 12 |
| `doc.rtf` | Document | `common` | \info group (title, subject, author, operator, keywords, doccomm, company, creatim, revtim, version, nofpages, nofwords), font table, embedded objects (\object, risky), text -&gt; text.plain | Metadata + text | impl (RTF 1.9.1 tokenizer) | impl | S3 | 2 |
| `doc.ebook` | Document | `common` | OPF/EXTH/title-info: title, creators + roles, language, identifiers (ISBN/ASIN/UUID), publisher, date, subjects, rights, description, series; TOC/chapter titles, spine length, cover image, DRM present, ComicInfo.xml for comics | Bibliographic record + chapter list | impl (OCF/OPF/NCX/nav on the in-house ZIP reader, PalmDB/MOBI/EXTH, FB2, ComicInfo) + quick-xml | impl | S3 | 8 |
| `doc.other` | Document | `common` | per format: DSC comments (%%Title %%Creator %%CreationDate %%Pages %%BoundingBox) for PS/EPS; \documentclass, packages, \title/\author, sectioning outline for LaTeX; entry count/types/keys/years for BibTeX; page count + metadata for DjVu/XPS; header metadata for others; text -&gt; text.plain | Outline/bibliography/title for long-tail document formats | impl (DSC scanner, BibTeX parser); LaTeX in code.source | impl | S3/S8 | 25 |
| `image.raster` | Image | `common` | width, height, color type, channels, bit depth, alpha, color space, ICC profile, DPI/physical size, orientation, progressive/interlaced, compression, animation (frames, loop count, total duration), palette size, embedded thumbnails, quality estimate (JPEG), perceptual hash (opt-in), dominant colours (opt-in, decodes), metadata blocks -&gt; meta.exif / meta.xmp / meta.iptc / meta.icc | Dimensions + capture metadata + rights; pHash enables duplicate detection | imagesize (probe), img-parts (block extraction), image / png / gif / tiff / image-webp / zune-jpeg / jxl-oxide / hayro-jpeg2000, avif-parse, mp4-atom (HEIF boxes) | crate | S2 | 49 |
| `image.raw` | Image | `common` | camera make/model/serial, lens, exposure/aperture/ISO/focal length, capture time, GPS, sensor dimensions, CFA pattern, white balance, embedded preview size, + full meta.exif/meta.xmp | Photographic provenance | rawler (rawloader fallback) + meta.exif | crate | S2 | 16 |
| `image.layered` | Image | `common` | canvas size, colour mode, bit depth, layer count + names + visibility, groups, text-layer strings, image resources (IPTC/XMP/EXIF/ICC/thumbnail), application version | Layer names and text layers describe a design file's content | psd; impl XCF/KRA/ORA (zip+xml) headers | mixed | S2 | 10 |
| `image.vector` | Image | `common` | SVG: width/height/viewBox, &lt;title&gt;/&lt;desc&gt;, &lt;metadata&gt; RDF (dc/cc), element histogram, text content, embedded rasters, fonts, external refs, scripts/event handlers (security), generator comment; WMF/EMF: bounds, record counts, embedded text | Title/desc/text tell the LLM what the drawing shows; script flag for safety | quick-xml (SVG, impl), impl EMF/WMF header | mixed | S2 | 12 |
| `image.texture` | Image | `common` | dimensions, pixel format, mip levels, array layers/faces (cube), compression (BCn/ASTC/ETC), colour space, embedded key/values (KTX2), EXR attributes (channels, compression, data window, owner, capture date) | Asset pipeline facts | ddsfile, ktx2, exr, ico, qoi; impl TGA/PCX/PNM/HDR/ICNS/SGI headers | mixed | S2 | 8 |
| `meta.exif` | Block | `common` | IFD0 (Make, Model, Software, DateTime, Artist, Copyright, Orientation, X/YResolution), Exif IFD (DateTimeOriginal + OffsetTime*, ExposureTime, FNumber, ISO, FocalLength(35mm), LensMake/Model, Flash, WhiteBalance, BodySerialNumber, ImageUniqueID), GPS IFD (lat/lon/alt decimal, timestamp, direction, speed), Interop, thumbnail presence; MakerNote ignored (size reported) | When/where/how a photo was taken; copyright/artist for rights | kamadak-exif (Reader::read_raw on blocks); nom-exif as alternative | crate | S2 | 1 |
| `meta.xmp` | Block | `common` | flattened per-namespace properties: dc (title, creator, description, subject, rights), xmp (CreateDate, ModifyDate, MetadataDate, CreatorTool, Rating, Label), xmpRights (Marked, Owner, UsageTerms, WebStatement), xmpMM (DocumentID, InstanceID, OriginalDocumentID, History), photoshop, Iptc4xmpCore/Ext, plus (licensing), cc (Creative Commons), exif/tiff mirrors, pdf, pdfaid, crs, VRA Core (vra:) -&gt; meta.vra; unknown namespaces kept raw | The richest cross-format rights + provenance record | impl on quick-xml (RDF/XML subset); evaluate xmpkit (pure, young); xmp_toolkit is FFI | impl | S2 | 1 |
| `meta.iptc` | Block | `common` | IIM Record 1 (CodedCharacterSet, envelope) + Record 2: ObjectName, Urgency, Category, SupplementalCategories, Keywords, SpecialInstructions, DateCreated/TimeCreated, By-line, By-lineTitle, City, Sub-location, Province-State, Country, OriginalTransmissionReference, Headline, Credit, Source, CopyrightNotice, Caption-Abstract, Writer-Editor | Newsroom-grade caption, keywords and credit | impl (Photoshop 8BIM resource 0x0404 + IIM dataset parser, ~300 LOC); `iptc` crate exists but is JPEG-only | impl | S2 | 0 |
| `meta.vra` | Block | `common` | VRA Core 4 elements for work/image/collection: agent (name, role, dates, culture), culturalContext, date (type, earliest/latest), description, inscription, location, material, measurements, relation, rights, source, stateEdition, stylePeriod, subject, technique, textref, title, worktype | Cultural-heritage cataloguing (museums, slide libraries) | impl: map XMP vra namespace + standalone VRA Core 4 XML records via quick-xml (no crate exists) | impl | S2 | 1 |
| `meta.icc` | Block | `common` | profile class, colour space, PCS, version, rendering intent, creator, device manufacturer/model, description (desc/mluc), copyright, creation date, white point | Colour-management context | impl (header + tag table); moxcms as fallback | impl | S2 | 1 |
| `audio` | Media | `common` | container, codec, duration, sample rate, channels + layout, bit depth, bitrate (avg, VBR?), encoder, tags (title, artist, album, album artist, track/disc n/total, date/year, genre, composer, conductor, lyricist, comment, lyrics, BPM, key, ISRC, label, MusicBrainz IDs, ReplayGain), cover art (mime, dimensions, size), chapters, loudness (opt-in decode) | Track identity and technical properties | lofty (tags, properties) + symphonia (probe/codec params/duration) | crate | S4 | 34 |
| `audio.score` | Media | `common` | MIDI: format, tracks, PPQ, tempo map, time signatures, key signatures, track/instrument names, lyrics/markers, note count, duration; trackers: title, channels, patterns, instrument/sample names; notation (MusicXML/MEI/ABC): title, composer, parts, measures, key/time | Musical structure for symbolic music | midly (MIDI); quick-xml (MusicXML); impl MOD/XM/IT/S3M/ABC | mixed | S4 | 4 |
| `audio.playlist` | Media | `common` | entry count, total declared duration, titles/artists, HLS: variants (bandwidth, resolution, codecs), segment count, target duration, encryption; CUE: performer, title, files, tracks + indexes | What a playlist contains | m3u8-rs (HLS), quick-xml (XSPF/ASX/MPD); impl M3U/PLS/CUE | mixed | S4 | 5 |
| `video` | Media | `common` | container + brand, duration, overall bitrate, creation time, encoder/handler, streams: video (codec, profile/level, WxH, SAR/DAR, fps, bit depth, chroma, HDR colour primaries/transfer/matrix, rotation), audio (codec, channels, rate, language), subtitle/data tracks (language, title), chapters, tags (title, artist, comment, ©xyz GPS, Apple QuickTime make/model/software), cover art, fragmented/faststart | Technical + descriptive summary of footage; GPS/make/model for provenance | mp4-atom (ISOBMFF/MOV/3GP), matroska / matroska-demuxer (MKV/WebM), riff (AVI), mpeg2ts-reader (TS), h264-parser (SPS details); impl FLV/ASF/MPEG-PS/OGM/RealMedia headers | mixed | S4 | 34 |
| `archive` | Archive | `common` | format + version, entry count, total compressed/uncompressed size, ratio, compression methods, encrypted entries, archive comment, multi-volume?, entries (path, size, mtime, mode) top N, file-type histogram, mtime range, risk flags (path traversal, absolute paths, symlinks out, bomb ratio), recursion into entries (bounded) | Inventory of what's inside without extracting; safety flags | zip, tar, sevenz-rust2, cab, delharc, oxiarc-archive; impl RAR4/5 header listing (unrar is FFI), ARJ, CPIO reader, ACE/ZOO/ARC headers | mixed | S5 | 34 |
| `compress` | Archive | `common` | algorithm, header fields (gzip FNAME/MTIME/OS/FCOMMENT, xz check + block count, zstd frame content size/dict id/checksum, lz4 frame descriptor, bzip2 block size), declared vs measured uncompressed size, then inner file -&gt; recursive extraction (bounded) | Transparent: the LLM cares about what's inside | flate2 (miniz_oxide), bzip2 (libbz2-rs-sys backend), lzma-rust2, ruzstd, lz4_flex, brotli, lzfse-rust; impl LZW (.Z), snappy framing | mixed | S5 | 13 |
| `package` | Package | `common` | ecosystem, name, version, release/arch, summary/description, licence, maintainer/author, homepage, dependencies, provides/conflicts, install scripts present (risk), file count, installed size, signatures/permissions (Android), min OS/SDK, bundle id, entitlements | What software this is and what it will do on install | rpm, apk-info + axmldecoder (APK), msi, backhand (snap/squashfs), zip, tar, ar; impl DEB control, wheel METADATA, gem, nuspec, xar (PKG), MSIX manifest mapping | mixed | S5 | 29 |
| `disk` | Disk | `forensics` | image type + version, virtual size, partition table (MBR/GPT: partitions, types, sizes, labels, GUIDs), filesystem superblocks (type, label, UUID, block size, used, created/mounted times), ISO PVD (volume id, publisher, preparer, application, dates, El Torito boot), backing file (qcow2), snapshots | What's on a disk image without mounting it | gpt, mbrman, fatfs, ext4-view, ntfs, backhand, apfs, vhd, vmdk; impl ISO9660/UDF PVD, qcow2/VDI/VHDX headers | mixed | S5 | 15 |
| `exec` | Executable | `common` | format, arch, bitness, endianness, kind (exe/dylib/object/core), entry point, sections (name, size, flags, entropy), segments, imports (libraries + symbol counts), exports, linked libraries/rpaths, interpreter, stripped?, debug info (DWARF, build-id, PDB path + GUID), hardening (PIE, NX, RELRO, stack canary, ASLR/DEP/CFG/SafeSEH), code signature (Authenticode signer, Apple team id + entitlements), PE version resources (CompanyName, ProductName, FileVersion, OriginalFilename), toolchain hints (rustc/Go buildinfo/.comment), packer/high-entropy flags | Identity, provenance and risk profile of a binary | goblin / object, gimli, pdb, wasmparser, apple-codesign (macOS sigs); impl Authenticode summary via cms | mixed | S6 | 22 |
| `bytecode` | Executable | `common` | target runtime + version (class major/minor, pyc magic -&gt; Python version, .NET metadata version), class/module name, superclass/interfaces, method & field counts, referenced assemblies/modules, source file attribute, timestamps | Identity of compiled artifacts | classfile-parser, dex, pyc (old) ; impl .NET CLI metadata reader, Lua/BEAM/Hermes headers | mixed | S6 | 12 |
| `crypto` | Security | `common` | X.509: subject, issuer, serial, validity, SANs, key algo/size, signature algo, extensions (BC, KU, EKU), self-signed, SHA-256 fingerprint; CSR/CRL fields; PEM bundle: object types + counts; private keys: type + size + encrypted? ONLY (never key material); SSH: type, bits, comment, fingerprint; OpenPGP: key ids, user ids, creation/expiry, algorithms, message encrypted/signed + recipients; PKCS#12/JKS: entry count/types; JWT: header + claims (signature NOT verified flag) | Answers 'what is this key/cert, who issued it, is it expired' safely | x509-parser, pem, der, cms, pgp (rpgp, pure), ssh-key, jsonwebtoken (decode only); impl JKS/BKS headers | mixed | S6 | 20 |
| `db` | Database | `common` | engine + file format version, page size, encoding, application_id/user_version (detects GeoPackage, MBTiles, browser history, Photos libraries...), schema: tables, columns + types, indexes, views, triggers, approximate row counts; DBF: record count, field descriptors, last update | Schema of an embedded database = what questions it can answer | impl SQLite b-tree reader for sqlite_schema (pure; rusqlite bundles C), impl DBF/MDB(Jet)/DuckDB/LMDB headers; evaluate sqlite-parser | impl | S6 | 21 |
| `forensic` | Forensics | `forensics` | PCAP/PCAPNG: link type, snaplen, interfaces, packet count, time span, top protocols/endpoints (opt-in); EVTX: channel, providers, event-id histogram, time range, record count; registry hive: root key, last written, key/value counts; LNK: target path, args, working dir, timestamps, volume serial, machine id; minidump: OS, CPU, exception, crashing thread, modules; MFT/prefetch: counts + time range; HAR: entries, hosts, methods, status histogram | Incident-response triage summaries | pcap-file / pcap-parser, evtx, notatin, lnk, minidump, mft; impl prefetch, utmp, HAR mapping | mixed | S6/S8 | 24 |
| `columnar` | Data | `data` | schema (columns, physical + logical types, nullability), row count, row groups/stripes/batches, compression codecs, created_by/writer, key-value metadata (pandas/arrow/geo schema), column statistics (min/max/null count), partition/table metadata (Delta/Iceberg: version, snapshots, partition spec) | Schema + stats lets an LLM write queries; footer-only read is cheap | parquet + arrow (default-features=false, footer/schema only), orc-rust, apache-avro, lance (heavy, feature-gated), vortex (feature-gated); serde_json for Delta/Iceberg logs | crate | S7 | 19 |
| `sci` | Scientific | `science` | groups/datasets/variables: names, shapes, dtypes, chunking, compression, attributes (CF conventions: title, institution, source, history, units, standard_name), dimensions, global attributes; FITS: HDUs + header cards (TELESCOP, INSTRUME, OBJECT, DATE-OBS, RA/DEC, EXPTIME, WCS); NPY: dtype, shape, order; GRIB: messages, parameters, levels, reference/forecast times, grid; stats files (SAV/DTA/SAS/RDS): variables + labels, row count, encoding | Variable inventory with units = what the dataset measures | hdf5-reader (pure, read-only), netcdf3, fitsrs, matfile, zarrs, grib / gribberish; impl NPY/NPZ, SAV, DTA, SAS7BDAT, RDS/RData headers | mixed | S7 | 27 |
| `medical` | Scientific | `science` | DICOM: SOP class, modality, manufacturer/model, study/series descriptions + UIDs, body part, acquisition dates, rows/cols/frames, pixel spacing, slice thickness, transfer syntax, patient fields REDACTED by default (PHI); NIfTI/Analyze: dims, voxel size, datatype, units, qform/sform codes, descrip, intent | Imaging study summary with PHI protection | dicom-object, nifti | crate | S7 | 6 |
| `geo` | Geospatial | `geo` | CRS (EPSG / WKT / PROJJSON), bbox (in source CRS + WGS84), feature/record count, geometry types histogram, attribute schema, layer names, time span (GPX/IGC/FIT), track distance + elevation range, creator/software, raster: size, bands, geotransform, nodata, GeoKeys, point clouds: point count, point format, bounds, scale/offset, VLRs | Where on Earth, what kind of features, how many | geojson, shapefile, gpx, kml, flatgeobuf, tiff (+ impl GeoKeys), las, laz, e57, osmpbf, fitparser (Garmin FIT); db (GeoPackage/MBTiles); evaluate oxigdal-* drivers (young) | mixed | S7 | 34 |
| `3d` | 3D | `cad` | asset generator/version/copyright, units + up axis, scenes/nodes/meshes/materials/textures/animations/skins counts, vertex & triangle counts, bbox, extensions used, external resources referenced, embedded textures, comments/header text | What a model contains and which tool made it | gltf, tobj, stl_io, ply-rs, fbxcel, blend, openusd, quick-xml (DAE/X3D/3MF); impl 3DS/VOX/PCD/OFF headers | mixed | S7 | 28 |
| `cad` | CAD | `cad` | STEP/IFC P21 HEADER: FILE_DESCRIPTION, FILE_NAME (name, time_stamp, author, organization, preprocessor, originating_system, authorization), FILE_SCHEMA (AP203/214/242, IFC2X3/IFC4/IFC4X3), entity-type histogram, IFC project/site/building/storey names; DXF: $ACADVER, $INSUNITS, $EXTMIN/$EXTMAX, layers, blocks, entity histogram, text strings; DWG: version (AC10xx) + summary info; IGES: global section (sender, author, org, units, dates); Gerber/Excellon: layer function, apertures, units | Engineering provenance (who/what tool/when) and model contents | dxf; impl ISO-10303-21 lexer (shared STEP/IFC), IGES, DWG header, Gerber; monstertruck-io (feature-gated B-rep) | mixed | S7 | 17 |
| `font` | Font | `common` | family, subfamily, full name, PostScript name, version, designer, manufacturer, vendor id, copyright, licence + licence URL, embedding permissions (OS/2 fsType -&gt; rights), glyph count, units per em, weight/width/italic/monospace, variable axes + named instances, unicode coverage -&gt; scripts, colour tables (COLR/CPAL/SVG/sbix/CBDT), OpenType feature tags, collection member count | Font identity and licensing (Security & Rights) | read-fonts / skrifa, allsorts (WOFF/WOFF2 decode); impl Type1/PFB, BDF/PCF headers | crate | S7 | 10 |
| `web.misc` | Web | `common` | per format: SWF (version, compressed, stage size, fps, frames, AS3); WARC (record count, types, target URIs, dates); torrent (name, files, total size, piece length, trackers, created by/date, private, infohash); shortcuts (.url/.webloc/.desktop target, icon); web manifest (name, start_url, icons); robots.txt / sitemap (rules, URL counts) | Where it points / what it packages | swf, lava_torrent, plist, serde_json; impl WARC, .url/.desktop | mixed | S8 | 16 |
| `apple` | Platform | `common` | plist: format (XML/binary), top-level keys, CFBundleIdentifier/Version/ExecutableName, minimum OS; .mobileprovision: team, app id, expiry, entitlements, device count; .DS_Store: file names listed; .strings: key count; Info.plist inside bundles | Apple platform artifact identity | plist, cms; impl DS_Store | mixed | S6 | 11 |
| `game` | Game | `games` | engine/format version, title/internal name, asset/lump/entry counts, ROM header (mapper, region, PRG/CHR sizes, game code, checksum), level/map names, NBT root tags | Identifies game assets and ROMs | impl headers (all simple); nbt via impl | impl | S8 | 17 |
| `binary.unknown` | Fallback | `common` | entropy (global + per-block profile), byte histogram class (text/binary/compressed/encrypted?), printable strings (top N, `strings`-like), embedded signature scan with offsets (binwalk-like), candidate format guesses with confidence | Something useful for any file, even unknown ones | aho-corasick + impl | impl | S1 | 8 |

## 4. Coverage summary

* **1004 formats** in total: tier 1 = 139, tier 2 = 120, tier 3 = 745.
* Formats with an extractor in this build: **225** of 1004.
* Formats by family status: crate = 246, mixed = 574, impl = 184.
* Formats by target stage: S1 = 168, S1/S6 = 97, S2 = 91, S3 = 32, S3/S8 = 1, S4 = 74, S5 = 85, S6 = 94, S6/S8 = 22, S7 = 135, S8 = 205.
* By feature: `common` = 817, `cad` = 45, `forensics` = 39, `geo` = 34, `science` = 33, `data` = 19, `games` = 17.
* By category: Code 163, Data 160, Image 95, Media 88, Document 71, Archive 47, Executable 34, Geospatial 34, Scientific 33, Text 32, Package 29, 3D 28, Web 27, Forensics 24, Database 21, Security 20, CAD 17, Game 17, Personal 16, Disk 15, Platform 11, Font 10, Fallback 8, Block 4.

## 5. Format table

`#` is the position after sorting by tier, then by stage and family. **Tier 1** is the ~140 formats a general-purpose tool meets every day. **Tier 2** is common in professional or specialist work. **Tier 3** is the long tail. Ordering inside a tier is by family, not a fine-grained popularity rank. "Stage" is the implementation stage (S0–S8) in the implementation plan. "Feature" is the cargo feature of the `whiff` crate that compiles the extractor: `common` is on by default; `geo`, `science`, `data`, `cad`, `forensics` and `games` are opt-in (`full` enables all). "Extractor" is the extractor that handles the format today (`—` = not implemented yet). Tier-3 formats are scheduled for S8, the long-tail stage, when they need an in-house parser (impl family, or the notes say "header" / "impl").

| # | Format | Extensions | MIME | Tier | Family | Feature | Extractor | Library | Stage | Format-specific extras |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Plain text | `txt` `text` | text/plain | 1 | `text.plain` | `common` | `text.plain` | chardetng, encoding_rs | S1 | — |
| 2 | Log file | `log` | text/plain | 1 | `text.plain` | `common` | `text.plain` | chardetng, encoding_rs | S1 | timestamp range, log-level histogram, top sources (impl detector for syslog/JSON-lines/Apache/CLF) |
| 3 | Web server access log (CLF / combined) | `log` `access.log` | text/plain | 1 | `text.plain` | `common` | `text.plain` | chardetng, encoding_rs | S1 | status histogram, methods, top paths, client count (IPs hashed), time range |
| 4 | Markdown | `md` `markdown` `mdown` `mkd` | text/markdown | 1 | `text.markdown` | `common` | `text.markdown` | pulldown-cmark, gray_matter | S1 | — |
| 5 | HTML | `html` `htm` | text/html | 1 | `text.html` | `common` | `text.html` | html5ever + scraper | S1 | — |
| 6 | XML | `xml` | application/xml | 1 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | — |
| 7 | JSON | `json` | application/json | 1 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | — |
| 8 | NDJSON / JSON Lines | `ndjson` `jsonl` `ldjson` | application/x-ndjson | 1 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | — |
| 9 | YAML | `yaml` `yml` | application/yaml | 1 | `data.yaml` | `common` | `data.yaml` | serde-saphyr | S1 | — |
| 10 | TOML | `toml` | application/toml | 1 | `data.toml` | `common` | `data.toml` | toml | S1 | — |
| 11 | INI | `ini` `cfg` `conf` | text/plain | 1 | `data.ini` | `common` | `data.ini` | rust-ini, java-properties | S1 | — |
| 12 | CSV | `csv` | text/csv | 1 | `data.csv` | `common` | `data.csv` | csv | S1 | — |
| 13 | TSV | `tsv` `tab` | text/tab-separated-values | 1 | `data.csv` | `common` | `data.csv` | csv | S1 | — |
| 14 | SQL script / dump | `sql` | application/sql | 1 | `data.sql` | `common` | `data.sql` | sqlparser | S1 | — |
| 15 | Python source | `py` `pyw` `pyi` | text/x-python | 1 | `code.source` | `common` | `code.source` | tokei | S1 | imports, defs/classes, docstring, __main__ guard |
| 16 | JavaScript source | `js` `mjs` `cjs` | text/javascript | 1 | `code.source` | `common` | `code.source` | tokei | S1 | oxc_parser: imports/exports, minified detection, source map ref |
| 17 | TypeScript source | `ts` `mts` `cts` | application/typescript | 1 | `code.source` | `common` | `code.source` | tokei | S1 | oxc_parser |
| 18 | Java source | `java` | text/x-java | 1 | `code.source` | `common` | `code.source` | tokei | S1 | package, imports, classes |
| 19 | C source | `c` | text/x-c | 1 | `code.source` | `common` | `code.source` | tokei | S1 | #includes, functions |
| 20 | C/C++ header | `h` `hh` `hpp` `hxx` `h++` | text/x-c-header | 1 | `code.source` | `common` | `code.source` | tokei | S1 | — |
| 21 | C++ source | `cpp` `cc` `cxx` `c++` `ipp` | text/x-c++ | 1 | `code.source` | `common` | `code.source` | tokei | S1 | — |
| 22 | C# source | `cs` | text/x-csharp | 1 | `code.source` | `common` | `code.source` | tokei | S1 | namespace, usings, types |
| 23 | Go source | `go` | text/x-go | 1 | `code.source` | `common` | `code.source` | tokei | S1 | package, imports, funcs, build tags |
| 24 | Rust source | `rs` | text/rust | 1 | `code.source` | `common` | `code.source` | tokei | S1 | syn: items, uses, attributes, unsafe count |
| 25 | PHP source | `php` `phtml` `php3` `php4` `php5` `phps` | application/x-httpd-php | 1 | `code.source` | `common` | `code.source` | tokei | S1 | — |
| 26 | Ruby source | `rb` `rbw` `rake` `gemspec` | text/x-ruby | 1 | `code.source` | `common` | `code.source` | tokei | S1 | — |
| 27 | Shell script | `sh` `bash` `zsh` `ksh` | application/x-sh | 1 | `code.source` | `common` | `code.source` | tokei | S1 | shebang, commands used, set -e |
| 28 | Swift source | `swift` | text/x-swift | 1 | `code.source` | `common` | `code.source` | tokei | S1 | — |
| 29 | Kotlin source | `kt` `kts` | text/x-kotlin | 1 | `code.source` | `common` | `code.source` | tokei | S1 | — |
| 30 | PowerShell | `ps1` `psm1` `psd1` | text/x-powershell | 1 | `code.source` | `common` | `code.source` | tokei | S1 | — |
| 31 | Windows batch | `bat` `cmd` | application/x-bat | 1 | `code.source` | `common` | `code.source` | tokei | S1 | — |
| 32 | SCSS / Sass | `scss` `sass` | text/x-scss | 1 | `code.source` | `common` | `code.source` | tokei | S1 | — |
| 33 | CSS | `css` | text/css | 1 | `code.source` | `common` | `code.source` | tokei | S1 | selectors, @imports, custom properties, @font-face, media queries |
| 34 | npm package.json | `package.json` | application/json | 1 | `code.manifest` | `common` | `code.manifest` | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S1 | — |
| 35 | Maven POM | `pom.xml` | — | 1 | `code.manifest` | `common` | `code.manifest` | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S1 | groupId/artifactId/version, deps |
| 36 | Jupyter notebook | `ipynb` | application/x-ipynb+json | 1 | `code.notebook` | `common` | `code.notebook` | serde_json | S1 | — |
| 37 | Unknown / generic binary | `bin` `dat` `(any)` | application/octet-stream | 1 | `binary.unknown` | `common` | `binary.unknown` | aho-corasick + impl | S1 | — |
| 38 | JPEG | `jpg` `jpeg` `jpe` `jfif` | image/jpeg | 1 | `image.raster` | `common` | `image.jpeg` | imagesize | S2 | APP0 JFIF / APP1 EXIF+XMP / APP2 ICC+MPF / APP13 IPTC / APP14 Adobe; quality from DQT |
| 39 | PNG | `png` | image/png | 1 | `image.raster` | `common` | `image.png` | imagesize | S2 | tEXt/iTXt/zTXt (incl. AI-generation 'parameters'), eXIf, iCCP, pHYs, tIME, APNG acTL |
| 40 | GIF | `gif` | image/gif | 1 | `image.raster` | `common` | `image.gif` | imagesize | S2 | frames, loop (NETSCAPE2.0), comments, XMP app ext |
| 41 | WebP | `webp` | image/webp | 1 | `image.raster` | `common` | `image.webp` | imagesize | S2 | VP8/VP8L/VP8X, EXIF/XMP/ICCP chunks, animation |
| 42 | HEIF / HEIC | `heic` `heif` `heics` `hif` | image/heic | 1 | `image.raster` | `common` | `image.heif` | imagesize | S2 | ISOBMFF meta box: ispe, colr, irot, Exif/XMP items, depth/alpha aux, burst/live photo |
| 43 | AVIF | `avif` `avifs` | image/avif | 1 | `image.raster` | `common` | `image.heif` | imagesize | S2 | avif-parse + mp4-atom |
| 44 | SVG | `svg` `svgz` | image/svg+xml | 1 | `image.raster` | `common` | — | imagesize | S2 | -&gt; image.vector |
| 45 | TIFF | `tif` `tiff` | image/tiff | 1 | `image.raster` | `common` | `image.tiff` | imagesize | S2 | all IFDs, pages, compression, GeoKeys -&gt; geo |
| 46 | BMP | `bmp` `dib` | image/bmp | 1 | `image.raster` | `common` | `image.bmp` | imagesize | S2 | header version, compression |
| 47 | ICO / CUR | `ico` `cur` | image/vnd.microsoft.icon | 1 | `image.raster` | `common` | `image.ico` | imagesize | S2 | sizes list |
| 48 | Animated PNG | `apng` | image/apng | 1 | `image.raster` | `common` | `image.png` | imagesize | S2 | — |
| 49 | Adobe DNG | `dng` | image/x-adobe-dng | 1 | `image.raw` | `common` | `image.raw` | rawler | S2 | — |
| 50 | Canon CR2 / CR3 / CRW | `cr2` `cr3` `crw` | image/x-canon-cr2 | 1 | `image.raw` | `common` | `image.raw` | rawler | S2 | CR3 = ISOBMFF CMT boxes |
| 51 | Nikon NEF / NRW | `nef` `nrw` | image/x-nikon-nef | 1 | `image.raw` | `common` | `image.raw` | rawler | S2 | — |
| 52 | Sony ARW / SRF / SR2 | `arw` `srf` `sr2` | image/x-sony-arw | 1 | `image.raw` | `common` | `image.raw` | rawler | S2 | — |
| 53 | Adobe Photoshop | `psd` `psb` | image/vnd.adobe.photoshop | 1 | `image.layered` | `common` | `image.psd` | psd | S2 | — |
| 54 | iCalendar | `ics` `ifb` `ical` | text/calendar | 1 | `text.calendar` | `common` | `text.calendar` | impl | S3 | — |
| 55 | vCard | `vcf` `vcard` | text/vcard | 1 | `text.contact` | `common` | `text.contact` | impl | S3 | — |
| 56 | Email message (RFC 5322 / MIME) | `eml` | message/rfc822 | 1 | `email` | `common` | `email.mime` | mail-parser | S3 | — |
| 57 | Mailbox | `mbox` `mbx` | application/mbox | 1 | `email` | `common` | `email.mime` | mail-parser | S3 | — |
| 58 | Outlook message | `msg` | application/vnd.ms-outlook | 1 | `email` | `common` | `email.msg` | mail-parser | S3 | — |
| 59 | PDF | `pdf` | application/pdf | 1 | `doc.pdf` | `common` | `doc.pdf` | impl | S3 | — |
| 60 | Word document (OOXML) | `docx` | application/vnd.openxmlformats-officedocument.wordprocessingml.document | 1 | `doc.ooxml` | `common` | `doc.ooxml` | impl | S3 | — |
| 61 | Excel workbook (OOXML) | `xlsx` | application/vnd.openxmlformats-officedocument.spreadsheetml.sheet | 1 | `doc.ooxml` | `common` | `doc.ooxml` | impl | S3 | — |
| 62 | PowerPoint presentation (OOXML) | `pptx` | application/vnd.openxmlformats-officedocument.presentationml.presentation | 1 | `doc.ooxml` | `common` | `doc.ooxml` | impl | S3 | — |
| 63 | Excel macro-enabled / template / add-in | `xlsm` `xltx` `xltm` `xlam` | application/vnd.ms-excel.sheet.macroEnabled.12 | 1 | `doc.ooxml` | `common` | `doc.ooxml` | impl | S3 | macros flag |
| 64 | OpenDocument Text | `odt` `ott` | application/vnd.oasis.opendocument.text | 1 | `doc.odf` | `common` | `doc.odf` | impl | S3 | — |
| 65 | Word 97-2003 | `doc` `dot` | application/msword | 1 | `doc.ole` | `common` | `doc.ole` | impl | S3 | — |
| 66 | Excel 97-2003 | `xls` `xlt` `xla` | application/vnd.ms-excel | 1 | `doc.ole` | `common` | `doc.ole` | impl | S3 | — |
| 67 | PowerPoint 97-2003 | `ppt` `pot` `pps` | application/vnd.ms-powerpoint | 1 | `doc.ole` | `common` | `doc.ole` | impl | S3 | — |
| 68 | Rich Text Format | `rtf` | application/rtf | 1 | `doc.rtf` | `common` | `doc.rtf` | impl | S3 | — |
| 69 | EPUB | `epub` | application/epub+zip | 1 | `doc.ebook` | `common` | `doc.ebook` | impl | S3 | — |
| 70 | PostScript | `ps` | application/postscript | 1 | `doc.other` | `common` | `doc.other` | impl | S3 | DSC comments |
| 71 | Encapsulated PostScript | `eps` `epsf` `epsi` | application/postscript | 1 | `doc.other` | `common` | `doc.other` | impl | S3 | DSC + embedded preview TIFF/WMF + XMP |
| 72 | LaTeX document | `tex` | application/x-tex | 1 | `doc.other` | `common` | — | impl | S3 | — |
| 73 | SubRip | `srt` | application/x-subrip | 1 | `text.subtitle` | `common` | — | impl | S4 | — |
| 74 | MP3 | `mp3` | audio/mpeg | 1 | `audio` | `common` | — | lofty | S4 | ID3v1/ID3v2.3/2.4, APE, Xing/Info/VBRI (VBR, frames), LAME tag |
| 75 | AAC / M4A | `m4a` `aac` `m4b` `m4p` | audio/mp4 | 1 | `audio` | `common` | — | lofty | S4 | iTunes ilst atoms, chapters (m4b), DRM (m4p) |
| 76 | WAV | `wav` `wave` | audio/wav | 1 | `audio` | `common` | — | lofty | S4 | fmt/fact/LIST INFO/bext (BWF)/iXML/ID3 chunks |
| 77 | FLAC | `flac` | audio/flac | 1 | `audio` | `common` | — | lofty | S4 | STREAMINFO, Vorbis comments, PICTURE, CUESHEET |
| 78 | Ogg Vorbis | `ogg` `oga` | audio/ogg | 1 | `audio` | `common` | — | lofty | S4 | — |
| 79 | Opus | `opus` | audio/opus | 1 | `audio` | `common` | — | lofty | S4 | OpusHead/OpusTags |
| 80 | AIFF / AIFF-C | `aif` `aiff` `aifc` | audio/aiff | 1 | `audio` | `common` | — | lofty | S4 | COMM, NAME/AUTH/ANNO, ID3 chunk |
| 81 | Windows Media Audio | `wma` | audio/x-ms-wma | 1 | `audio` | `common` | — | lofty | S4 | ASF header objects (impl) |
| 82 | MIDI | `mid` `midi` `kar` `rmi` | audio/midi | 1 | `audio.score` | `common` | — | midly | S4 | — |
| 83 | MP4 | `mp4` `m4v` | video/mp4 | 1 | `video` | `common` | — | mp4-atom | S4 | ftyp brands, moov/mvhd/tkhd/mdia, udta/meta/ilst, ©xyz GPS, Apple keys, sidx/moof (fragmented) |
| 84 | QuickTime MOV | `mov` `qt` | video/quicktime | 1 | `video` | `common` | — | mp4-atom | S4 | com.apple.quicktime.* keys (make, model, location, creationdate) |
| 85 | Matroska | `mkv` `mk3d` | video/x-matroska | 1 | `video` | `common` | — | mp4-atom | S4 | EBML DocType, Info, Tracks, Tags, Chapters, Attachments (fonts) |
| 86 | WebM | `webm` | video/webm | 1 | `video` | `common` | — | mp4-atom | S4 | — |
| 87 | AVI | `avi` | video/x-msvideo | 1 | `video` | `common` | — | mp4-atom | S4 | RIFF hdrl/strl/INFO, OpenDML |
| 88 | MPEG transport stream | `ts` `m2ts` `mts` `tsv` | video/mp2t | 1 | `video` | `common` | — | mp4-atom | S4 | PAT/PMT programs, stream types, PCR duration, AVCHD |
| 89 | Windows Media Video / ASF | `wmv` `asf` | video/x-ms-wmv | 1 | `video` | `common` | — | mp4-atom | S4 | ASF content description objects |
| 90 | 3GPP / 3GPP2 | `3gp` `3g2` | video/3gpp | 1 | `video` | `common` | — | mp4-atom | S4 | — |
| 91 | MPEG-1/2 program stream | `mpg` `mpeg` `m1v` `m2v` `vob` `mpe` | video/mpeg | 1 | `video` | `common` | — | mp4-atom | S4 | pack/system headers, sequence header |
| 92 | ZIP | `zip` `zipx` | application/zip | 1 | `archive` | `common` | — | zip, tar | S5 | central directory, extra fields (Unix/NTFS times, AES), comment, Zip64 |
| 93 | TAR | `tar` | application/x-tar | 1 | `archive` | `common` | — | zip, tar | S5 | ustar/pax/GNU headers, pax keywords |
| 94 | 7-Zip | `7z` | application/x-7z-compressed | 1 | `archive` | `common` | — | zip, tar | S5 | — |
| 95 | RAR | `rar` | application/vnd.rar | 1 | `archive` | `common` | — | zip, tar | S5 | RAR4/RAR5 block headers, encrypted headers flag, recovery record, solid |
| 96 | tar.gz / tgz | `tgz` `tar.gz` | application/gzip | 1 | `archive` | `common` | — | zip, tar | S5 | compress -&gt; archive chain |
| 97 | Microsoft Cabinet | `cab` | application/vnd.ms-cab-compressed | 1 | `archive` | `common` | — | zip, tar | S5 | — |
| 98 | gzip | `gz` `gzip` | application/gzip | 1 | `compress` | `common` | — | flate2 | S5 | — |
| 99 | bzip2 | `bz2` `bzip2` | application/x-bzip2 | 1 | `compress` | `common` | — | flate2 | S5 | — |
| 100 | xz | `xz` | application/x-xz | 1 | `compress` | `common` | — | flate2 | S5 | — |
| 101 | Zstandard | `zst` `zstd` | application/zstd | 1 | `compress` | `common` | — | flate2 | S5 | — |
| 102 | Debian package | `deb` `udeb` | application/vnd.debian.binary-package | 1 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | — |
| 103 | Android APK / AAB | `apk` `aab` `apks` `xapk` | application/vnd.android.package-archive | 1 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | manifest, permissions, signing scheme v1-v4, dex count, native ABIs |
| 104 | Java JAR / WAR / EAR | `jar` `war` `ear` | application/java-archive | 1 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | MANIFEST.MF, Maven pom.properties, signed (META-INF/*.SF) |
| 105 | Python wheel | `whl` | application/zip | 1 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | METADATA (core metadata), WHEEL tags, entry points |
| 106 | Windows Installer | `msi` `msp` `msm` | application/x-msi | 1 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | SummaryInformation + Property table (ProductName, Version, Manufacturer, UpgradeCode) |
| 107 | macOS disk image | `dmg` | application/x-apple-diskimage | 1 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | koly trailer, plist, partitions |
| 108 | ISO 9660 / UDF | `iso` `udf` | application/x-iso9660-image | 1 | `disk` | `forensics` | — | gpt, mbrman | S5 | — |
| 109 | Apple plist (XML) | `plist` | application/x-plist | 1 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | -&gt; apple |
| 110 | Apple plist (binary) | `plist` | application/x-bplist | 1 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | -&gt; apple |
| 111 | Windows PE executable / DLL | `exe` `dll` `sys` `scr` `ocx` `cpl` `efi` | application/vnd.microsoft.portable-executable | 1 | `exec` | `common` | — | goblin / object, gimli | S6 | — |
| 112 | ELF executable / shared object | `elf` `so` `(no` `ext)` `o` `ko` `axf` | application/x-elf | 1 | `exec` | `common` | — | goblin / object, gimli | S6 | — |
| 113 | Mach-O / universal binary | `(no` `ext)` `dylib` `bundle` `o` | application/x-mach-binary | 1 | `exec` | `common` | — | goblin / object, gimli | S6 | fat archs, load commands, LC_BUILD_VERSION, codesign |
| 114 | WebAssembly module | `wasm` | application/wasm | 1 | `exec` | `common` | — | goblin / object, gimli | S6 | imports/exports, custom sections (name, producers), target features |
| 115 | Java class | `class` | application/java-vm | 1 | `bytecode` | `common` | — | classfile-parser, dex | S6 | — |
| 116 | X.509 certificate | `crt` `cer` `der` `pem` | application/pkix-cert | 1 | `crypto` | `common` | — | x509-parser, pem | S6 | — |
| 117 | PEM bundle / chain | `pem` | application/x-pem-file | 1 | `crypto` | `common` | — | x509-parser, pem | S6 | — |
| 118 | SSH public / private key | `pub` `id_rsa` `id_ed25519` `ppk` | — | 1 | `crypto` | `common` | — | x509-parser, pem | S6 | OpenSSH + PuTTY PPK |
| 119 | SQLite database | `sqlite` `sqlite3` `db` `db3` `s3db` | application/vnd.sqlite3 | 1 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S6 | application_id routing (GeoPackage, MBTiles, Core Data...) |
| 120 | PCAP | `pcap` `cap` `dmp` | application/vnd.tcpdump.pcap | 1 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6 | — |
| 121 | Windows shortcut | `lnk` | application/x-ms-shortcut | 1 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6 | — |
| 122 | Apache Parquet | `parquet` `pq` | application/vnd.apache.parquet | 1 | `columnar` | `data` | — | parquet + arrow | S7 | — |
| 123 | HDF5 | `h5` `hdf5` `he5` | application/x-hdf5 | 1 | `sci` | `science` | — | hdf5-reader | S7 | — |
| 124 | MATLAB MAT | `mat` | application/x-matlab-data | 1 | `sci` | `science` | — | hdf5-reader | S7 | v5 header text, v7.3 -&gt; HDF5 |
| 125 | NumPy NPY / NPZ | `npy` `npz` | application/x-npy | 1 | `sci` | `science` | — | hdf5-reader | S7 | — |
| 126 | DICOM | `dcm` `dicom` `(no` `ext)` | application/dicom | 1 | `medical` | `science` | — | dicom-object, nifti | S7 | — |
| 127 | GeoJSON | `geojson` | application/geo+json | 1 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 128 | KML / KMZ | `kml` `kmz` | application/vnd.google-earth.kml+xml | 1 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 129 | GPX | `gpx` | application/gpx+xml | 1 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 130 | glTF / GLB | `gltf` `glb` | model/gltf+json | 1 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 131 | Wavefront OBJ / MTL | `obj` `mtl` | model/obj | 1 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 132 | STL | `stl` | model/stl | 1 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 133 | AutoCAD DXF | `dxf` | image/vnd.dxf | 1 | `cad` | `cad` | — | dxf | S7 | — |
| 134 | AutoCAD DWG | `dwg` | image/vnd.dwg | 1 | `cad` | `cad` | — | dxf | S7 | — |
| 135 | TrueType font | `ttf` | font/ttf | 1 | `font` | `common` | — | read-fonts / skrifa, allsorts | S7 | — |
| 136 | OpenType font | `otf` | font/otf | 1 | `font` | `common` | — | read-fonts / skrifa, allsorts | S7 | — |
| 137 | WOFF / WOFF2 | `woff` `woff2` | font/woff2 | 1 | `font` | `common` | — | read-fonts / skrifa, allsorts | S7 | — |
| 138 | Dockerfile / Containerfile | `Dockerfile` `Containerfile` `dockerfile` | — | 1 | `code.infra` | `common` | `code.infra` | hcl-rs + impl line scanners | S8 | — |
| 139 | Makefile | `Makefile` `makefile` `mk` `GNUmakefile` | — | 1 | `code.infra` | `common` | `code.infra` | hcl-rs + impl line scanners | S8 | — |
| 140 | NFO / DIZ info file | `nfo` `diz` | text/plain | 2 | `text.plain` | `common` | — | chardetng, encoding_rs | S1 | CP437 detection |
| 141 | README / LICENSE (extensionless) | `README` `LICENSE` `COPYING` `AUTHORS` `CHANGELOG` | — | 2 | `text.plain` | `common` | — | chardetng, encoding_rs | S1 | licence identification via SPDX text matching |
| 142 | Unix diff / patch | `diff` `patch` | text/x-diff | 2 | `text.plain` | `common` | `text.plain` | chardetng, encoding_rs | S1 | files changed, hunks, +/- lines |
| 143 | Subtitle-free transcript / meeting notes (VTT-less TXT) | `txt` | — | 2 | `text.plain` | `common` | `text.plain` | chardetng, encoding_rs | S1 | speaker turns, timestamps detected |
| 144 | MDX | `mdx` | text/mdx | 2 | `text.markdown` | `common` | `text.markdown` | pulldown-cmark, gray_matter | S1 | JSX component names |
| 145 | XHTML | `xhtml` `xht` | application/xhtml+xml | 2 | `text.html` | `common` | `text.html` | html5ever + scraper | S1 | — |
| 146 | MHTML web archive | `mht` `mhtml` | multipart/related | 2 | `text.html` | `common` | — | html5ever + scraper | S1 | MIME parts -&gt; email parser, then HTML |
| 147 | Internet shortcut HTML redirect | `shtml` | text/html | 2 | `text.html` | `common` | `text.html` | html5ever + scraper | S1 | — |
| 148 | XML Schema | `xsd` | application/xml | 2 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | target namespace, element/type counts |
| 149 | XSLT | `xsl` `xslt` | application/xslt+xml | 2 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | templates, output method |
| 150 | XAML | `xaml` | application/xaml+xml | 2 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | — |
| 151 | Android layout / resources XML | `xml` | — | 2 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | — |
| 152 | RSS | `rss` | application/rss+xml | 2 | `text.feed` | `common` | `text.feed` | feed-rs | S1 | — |
| 153 | Atom feed | `atom` | application/atom+xml | 2 | `text.feed` | `common` | `text.feed` | feed-rs | S1 | — |
| 154 | Sitemap XML | `xml` | application/xml | 2 | `text.feed` | `common` | — | feed-rs | S1 | URL count, lastmod range |
| 155 | JSON with comments | `jsonc` | application/json | 2 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | — |
| 156 | JSON Schema | `schema.json` | application/schema+json | 2 | `data.json` | `common` | — | serde_json, json5 | S1 | title, $id, properties |
| 157 | OpenAPI / Swagger (JSON) | `openapi.json` `swagger.json` | application/vnd.oai.openapi+json | 2 | `data.json` | `common` | — | serde_json, json5 | S1 | title, version, servers, paths/operations count |
| 158 | Kubernetes manifest | `yaml` | — | 2 | `data.yaml` | `common` | `data.yaml` | serde-saphyr | S1 | kinds, names, namespaces, images |
| 159 | Docker Compose | `compose.yaml` `docker-compose.yml` | — | 2 | `data.yaml` | `common` | — | serde-saphyr | S1 | services, images, ports, volumes |
| 160 | GitHub Actions workflow | `.github/workflows/*.yml` | — | 2 | `data.yaml` | `common` | — | serde-saphyr | S1 | triggers, jobs, actions used |
| 161 | Java properties | `properties` | text/x-java-properties | 2 | `data.ini` | `common` | `data.ini` | rust-ini, java-properties | S1 | — |
| 162 | dotenv | `env` `.env` | text/plain | 2 | `data.ini` | `common` | `data.ini` | rust-ini, java-properties | S1 | values redacted |
| 163 | JSX / TSX | `jsx` `tsx` | text/jsx | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | components exported |
| 164 | Objective-C / Objective-C++ | `m` `mm` | text/x-objective-c | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | disambiguate from MATLAB |
| 165 | Scala | `scala` `sc` | text/x-scala | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 166 | R script | `r` `R` | text/x-r | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | library() calls |
| 167 | Dart | `dart` | application/dart | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 168 | Lua | `lua` | text/x-lua | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 169 | Perl | `pl` `pm` `t` | text/x-perl | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 170 | Visual Basic / VB.NET | `vb` `bas` `cls` `frm` | text/x-vb | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 171 | VBScript | `vbs` `vbe` | text/vbscript | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 172 | Haskell | `hs` `lhs` | text/x-haskell | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 173 | Elixir | `ex` `exs` | text/x-elixir | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 174 | Erlang | `erl` `hrl` | text/x-erlang | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 175 | Clojure | `clj` `cljs` `cljc` `edn` | text/x-clojure | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 176 | F# | `fs` `fsi` `fsx` | text/x-fsharp | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 177 | OCaml | `ml` `mli` | text/x-ocaml | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 178 | Julia | `jl` | text/x-julia | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 179 | MATLAB / Octave script | `m` | text/x-matlab | 2 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 180 | Groovy / Gradle | `groovy` `gradle` `gvy` | text/x-groovy | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 181 | Assembly | `asm` `s` `S` `nasm` | text/x-asm | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 182 | Less / Stylus | `less` `styl` | — | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 183 | Vue single-file component | `vue` | — | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | template/script/style blocks |
| 184 | Svelte component | `svelte` | — | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 185 | Zig | `zig` | text/x-zig | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 186 | GraphQL | `graphql` `gql` | application/graphql | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | types, queries |
| 187 | CUDA | `cu` `cuh` | — | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | kernels |
| 188 | CMake | `cmake` `CMakeLists.txt` | — | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | project(), targets |
| 189 | Nix | `nix` | — | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 190 | LaTeX source | `tex` `ltx` `sty` `cls` | application/x-tex | 2 | `code.source` | `common` | `code.source` | tokei | S1/S6 | -&gt; doc.other |
| 191 | npm/yarn/pnpm lockfile | `package-lock.json` `yarn.lock` `pnpm-lock.yaml` | — | 2 | `code.manifest` | `common` | `code.manifest` | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S1 | — |
| 192 | Cargo manifest / lock | `Cargo.toml` `Cargo.lock` | — | 2 | `code.manifest` | `common` | `code.manifest` | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S1 | — |
| 193 | Python pyproject | `pyproject.toml` | — | 2 | `code.manifest` | `common` | `code.manifest` | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S1 | — |
| 194 | pip requirements | `requirements.txt` | — | 2 | `code.manifest` | `common` | `code.manifest` | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S1 | — |
| 195 | Go modules | `go.mod` `go.sum` | — | 2 | `code.manifest` | `common` | `code.manifest` | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S1 | — |
| 196 | Encrypted / random-looking blob | `enc` `bin` | — | 2 | `binary.unknown` | `common` | `binary.unknown` | aho-corasick + impl | S1 | high-entropy classification |
| 197 | JPEG XL | `jxl` | image/jxl | 2 | `image.raster` | `common` | `image.jxl` | imagesize | S2 | jxl-oxide; container boxes Exif/xml/jumb |
| 198 | JPEG 2000 | `jp2` `j2k` `jpf` `jpx` `jpm` `mj2` | image/jp2 | 2 | `image.raster` | `common` | `image.jp2` | imagesize | S2 | hayro-jpeg2000; boxes, XMP uuid box |
| 199 | TGA | `tga` `tpic` | image/x-tga | 2 | `image.raster` | `common` | `image.tga` | imagesize | S2 | — |
| 200 | PCX | `pcx` | image/vnd.zbrush.pcx | 2 | `image.raster` | `common` | `image.pcx` | imagesize | S2 | — |
| 201 | Netpbm PBM/PGM/PPM/PAM/PFM | `pbm` `pgm` `ppm` `pnm` `pam` `pfm` | image/x-portable-anymap | 2 | `image.raster` | `common` | `image.pnm` | imagesize | S2 | — |
| 202 | SVG / SVGZ | `svg` `svgz` | image/svg+xml | 2 | `image.vector` | `common` | `image.svg` | quick-xml | S2 | — |
| 203 | Windows Metafile / Enhanced Metafile | `wmf` `emf` `emz` `wmz` | image/emf | 2 | `image.vector` | `common` | `image.emf` | quick-xml | S2 | — |
| 204 | DirectDraw Surface | `dds` | image/vnd-ms.dds | 2 | `image.texture` | `common` | `image.dds` | ddsfile, ktx2 | S2 | — |
| 205 | OpenEXR | `exr` | image/x-exr | 2 | `image.texture` | `common` | `image.exr` | ddsfile, ktx2 | S2 | — |
| 206 | Word macro-enabled / template | `docm` `dotx` `dotm` | application/vnd.ms-word.document.macroEnabled.12 | 2 | `doc.ooxml` | `common` | `doc.ooxml` | impl | S3 | macros flag |
| 207 | Excel binary workbook | `xlsb` | application/vnd.ms-excel.sheet.binary.macroEnabled.12 | 2 | `doc.ooxml` | `common` | `doc.ooxml` | impl | S3 | calamine |
| 208 | PowerPoint macro-enabled / template / show | `pptm` `potx` `potm` `ppsx` `ppsm` | application/vnd.ms-powerpoint.presentation.macroEnabled.12 | 2 | `doc.ooxml` | `common` | `doc.ooxml` | impl | S3 | — |
| 209 | OpenDocument Spreadsheet | `ods` `ots` | application/vnd.oasis.opendocument.spreadsheet | 2 | `doc.odf` | `common` | `doc.odf` | impl | S3 | — |
| 210 | OpenDocument Presentation | `odp` `otp` | application/vnd.oasis.opendocument.presentation | 2 | `doc.odf` | `common` | `doc.odf` | impl | S3 | — |
| 211 | Kindle MOBI / AZW / AZW3 | `mobi` `azw` `azw3` `prc` | application/x-mobipocket-ebook | 2 | `doc.ebook` | `common` | `doc.ebook` | impl | S3 | EXTH records |
| 212 | Comic book archive | `cbz` `cbr` `cb7` `cbt` | application/vnd.comicbook+zip | 2 | `doc.ebook` | `common` | `doc.ebook` | impl | S3 | page count, ComicInfo.xml |
| 213 | BibTeX / BibLaTeX | `bib` | application/x-bibtex | 2 | `doc.other` | `common` | `doc.other` | impl | S3/S8 | — |
| 214 | WebVTT | `vtt` | text/vtt | 2 | `text.subtitle` | `common` | — | impl | S4 | — |
| 215 | Advanced SubStation / SSA | `ass` `ssa` | text/x-ssa | 2 | `text.subtitle` | `common` | — | impl | S4 | — |
| 216 | Apple Lossless | `m4a` `caf` | audio/mp4 | 2 | `audio` | `common` | — | lofty | S4 | — |
| 217 | Core Audio Format | `caf` | audio/x-caf | 2 | `audio` | `common` | — | lofty | S4 | — |
| 218 | WavPack | `wv` `wvc` | audio/wavpack | 2 | `audio` | `common` | — | lofty | S4 | — |
| 219 | Monkey's Audio | `ape` | audio/ape | 2 | `audio` | `common` | — | lofty | S4 | — |
| 220 | M3U / M3U8 (HLS) | `m3u` `m3u8` | application/vnd.apple.mpegurl | 2 | `audio.playlist` | `common` | — | m3u8-rs | S4 | — |
| 221 | Flash Video | `flv` `f4v` | video/x-flv | 2 | `video` | `common` | — | mp4-atom | S4 | onMetaData AMF0 (impl) |
| 222 | tar.bz2 / tar.xz / tar.zst | `tbz2` `txz` `tzst` `tar.bz2` `tar.xz` `tar.zst` | — | 2 | `archive` | `common` | — | zip, tar | S5 | — |
| 223 | RPM package | `rpm` | application/x-rpm | 2 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | — |
| 224 | iOS app archive | `ipa` | application/octet-stream | 2 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | Info.plist, provisioning, executable -&gt; exec |
| 225 | Python sdist / egg | `tar.gz` `egg` | application/gzip | 2 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | PKG-INFO |
| 226 | npm package tarball | `tgz` | application/gzip | 2 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | package/package.json |
| 227 | macOS installer package | `pkg` `mpkg` | application/vnd.apple.installer+xml | 2 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | xar TOC, Distribution, PackageInfo, signed |
| 228 | Windows MSIX / APPX | `msix` `appx` `msixbundle` `appxbundle` | application/msix | 2 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | AppxManifest.xml identity, capabilities |
| 229 | MessagePack | `msgpack` `mpk` | application/vnd.msgpack | 2 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 230 | CBOR | `cbor` | application/cbor | 2 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 231 | BSON | `bson` | application/bson | 2 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 232 | Protocol Buffers binary | `pb` `bin` `binpb` | application/x-protobuf | 2 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 233 | Protocol Buffers schema | `proto` | text/x-protobuf | 2 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | package, messages, services (impl or protobuf-parse) |
| 234 | Apache Avro container | `avro` | application/avro | 2 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | writer schema embedded |
| 235 | Static library / COFF object | `lib` `a` `obj` `o` | application/x-archive | 2 | `exec` | `common` | — | goblin / object, gimli | S6 | members, symbols |
| 236 | Android DEX | `dex` | application/vnd.android.dex | 2 | `bytecode` | `common` | — | classfile-parser, dex | S6 | — |
| 237 | Python bytecode | `pyc` `pyo` | application/x-python-code | 2 | `bytecode` | `common` | — | classfile-parser, dex | S6 | — |
| 238 | .NET assembly (CLI) | `exe` `dll` `winmd` | — | 2 | `bytecode` | `common` | — | classfile-parser, dex | S6 | CLR header, assembly name/version/culture, references, target framework attribute |
| 239 | Private key (PKCS#1/#8, SEC1) | `key` `pem` `p8` | application/pkcs8 | 2 | `crypto` | `common` | — | x509-parser, pem | S6 | type + bits + encrypted only |
| 240 | PKCS#12 / PFX | `p12` `pfx` | application/x-pkcs12 | 2 | `crypto` | `common` | — | x509-parser, pem | S6 | bag types (MAC/encrypted) |
| 241 | OpenPGP key / message / signature | `asc` `gpg` `pgp` `sig` `kbx` | application/pgp-keys | 2 | `crypto` | `common` | — | x509-parser, pem | S6 | — |
| 242 | PCAPNG | `pcapng` | application/x-pcapng | 2 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | — |
| 243 | macOS app bundle Info.plist | `plist` | — | 2 | `apple` | `common` | — | plist, cms | S6 | — |
| 244 | Apache Arrow IPC / Feather | `arrow` `feather` `ipc` `arrows` | application/vnd.apache.arrow.file | 2 | `columnar` | `data` | — | parquet + arrow | S7 | — |
| 245 | NetCDF (3 / 4) | `nc` `nc4` `cdf` | application/x-netcdf | 2 | `sci` | `science` | — | hdf5-reader | S7 | NetCDF4 = HDF5 + CF |
| 246 | ESRI Shapefile | `shp` `shx` `dbf` `prj` `cpg` | application/vnd.shp | 2 | `geo` | `geo` | — | geojson, shapefile | S7 | sidecar files grouped |
| 247 | GeoTIFF / COG | `tif` `tiff` | image/tiff; application=geotiff | 2 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 248 | GeoPackage | `gpkg` | application/geopackage+sqlite3 | 2 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 249 | FBX | `fbx` | application/vnd.autodesk.fbx | 2 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 250 | STEP | `step` `stp` `p21` | model/step | 2 | `cad` | `cad` | — | dxf | S7 | — |
| 251 | IFC (BIM) | `ifc` `ifczip` `ifcxml` | application/x-step | 2 | `cad` | `cad` | — | dxf | S7 | — |
| 252 | TrueType / OpenType collection | `ttc` `otc` | font/collection | 2 | `font` | `common` | — | read-fonts / skrifa, allsorts | S7 | — |
| 253 | reStructuredText | `rst` `rest` | text/x-rst | 2 | `text.lightmarkup` | `common` | — | impl | S8 | — |
| 254 | AsciiDoc | `adoc` `asciidoc` `asc` | text/asciidoc | 2 | `text.lightmarkup` | `common` | — | impl | S8 | document header attributes |
| 255 | Terraform / HCL | `tf` `tfvars` `hcl` | — | 2 | `code.infra` | `common` | — | hcl-rs + impl line scanners | S8 | — |
| 256 | .gitignore / .dockerignore | `gitignore` `dockerignore` `npmignore` | — | 2 | `code.infra` | `common` | — | hcl-rs + impl line scanners | S8 | — |
| 257 | Shockwave Flash | `swf` | application/x-shockwave-flash | 2 | `web.misc` | `common` | — | swf, lava_torrent | S8 | — |
| 258 | BitTorrent metainfo | `torrent` | application/x-bittorrent | 2 | `web.misc` | `common` | — | swf, lava_torrent | S8 | — |
| 259 | Internet shortcut / webloc | `url` `webloc` `website` | — | 2 | `web.misc` | `common` | — | swf, lava_torrent | S8 | — |
| 260 | Text with ANSI escapes | `ans` `asc` | text/plain | 3 | `text.plain` | `common` | — | chardetng, encoding_rs | S1 | strip ANSI before stats |
| 261 | Git commit message / mbox patch | `eml-patch` | — | 3 | `text.plain` | `common` | — | chardetng, encoding_rs | S1 | author, subject, files changed |
| 262 | Hosts file | `hosts` | — | 3 | `text.plain` | `common` | — | chardetng, encoding_rs | S1 | entries count, blocked domains |
| 263 | CODEOWNERS / MAINTAINERS | `CODEOWNERS` `MAINTAINERS` | — | 3 | `text.plain` | `common` | — | chardetng, encoding_rs | S1 | owners, paths |
| 264 | Chat export (WhatsApp / Signal text) | `txt` | — | 3 | `text.plain` | `common` | `text.plain` | chardetng, encoding_rs | S1 | participants count, message count, date range |
| 265 | Kindle clippings | `My` `Clippings.txt` | — | 3 | `text.plain` | `common` | — | chardetng, encoding_rs | S1 | books, highlight count |
| 266 | UTF-16 / UTF-32 text | `txt` | text/plain | 3 | `text.plain` | `common` | `text.plain` | chardetng, encoding_rs | S1 | BOM-driven decode |
| 267 | GNU info | `info` | application/x-info | 3 | `text.plain` | `common` | — | chardetng, encoding_rs | S1 | nodes |
| 268 | Fortune / quote databases | `dat` `fortune` | — | 3 | `text.plain` | `common` | — | chardetng, encoding_rs | S1 | — |
| 269 | Vim / Emacs swap & backup | `swp` `swo` `~` | — | 3 | `text.plain` | `common` | — | chardetng, encoding_rs | S8 | original filename, host, user (Vim swap header) |
| 270 | R Markdown | `rmd` | text/x-r-markdown | 3 | `text.markdown` | `common` | `text.markdown` | pulldown-cmark, gray_matter | S1 | code chunk languages |
| 271 | Quarto | `qmd` | text/x-quarto | 3 | `text.markdown` | `common` | `text.markdown` | pulldown-cmark, gray_matter | S1 | — |
| 272 | Server-side templates (PHP/ERB/JSP/ASP mixed HTML) | `jsp` `asp` `aspx` `erb` `ejs` `hbs` `mustache` `njk` `jinja` `j2` `twig` `liquid` | — | 3 | `text.html` | `common` | — | html5ever + scraper | S1 | template engine detection, HTML part analysed |
| 273 | Web archive (Safari) | `webarchive` | application/x-webarchive | 3 | `text.html` | `common` | — | html5ever + scraper | S1 | binary plist with WebMainResource |
| 274 | DTD | `dtd` | application/xml-dtd | 3 | `text.xml` | `common` | — | quick-xml | S1 | element declarations |
| 275 | RELAX NG | `rng` `rnc` | application/xml | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | — |
| 276 | DocBook | `dbk` `docbook` | application/docbook+xml | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | title, chapters |
| 277 | TEI XML | `tei` | application/tei+xml | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S8 | teiHeader fileDesc |
| 278 | JATS article XML | `nxml` | application/xml | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | article-meta: title, authors, DOI |
| 279 | WSDL | `wsdl` | application/wsdl+xml | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | services, operations |
| 280 | XLIFF translation | `xlf` `xliff` | application/xliff+xml | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | source/target languages, unit count |
| 281 | Android strings / .resx | `resx` | text/microsoft-resx | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | key count |
| 282 | Qt translation | `ts` | application/x-linguist | 3 | `text.xml` | `common` | — | quick-xml | S1 | — |
| 283 | SAML / XML-DSig | `saml` | application/samlmetadata+xml | 3 | `text.xml` | `common` | — | quick-xml | S1 | entity ids, certs |
| 284 | MathML | `mml` | application/mathml+xml | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | — |
| 285 | SMIL | `smil` `smi` | application/smil+xml | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | — |
| 286 | XBRL financial report | `xbrl` | application/xbrl+xml | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | entity, period, concept count |
| 287 | ONIX book metadata | `onix` | — | 3 | `text.xml` | `common` | — | quick-xml | S1 | — |
| 288 | METS / MODS / EAD library XML | `mets` `mods` `ead` | — | 3 | `text.xml` | `common` | — | quick-xml | S1 | — |
| 289 | Dublin Core XML / OAI-PMH | `dc` | — | 3 | `text.xml` | `common` | — | quick-xml | S1 | — |
| 290 | JUnit / xUnit test report | `xml` | — | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | suites, tests, failures, errors, time |
| 291 | Cobertura / JaCoCo / Clover coverage | `xml` | — | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | line/branch coverage % |
| 292 | Checkstyle / PMD / SpotBugs reports | `xml` | — | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | violations by severity |
| 293 | Apple Health export | `export.xml` | — | 3 | `text.xml` | `common` | — | quick-xml | S1 | record types histogram, date range, sources |
| 294 | Android manifest (text) | `AndroidManifest.xml` | — | 3 | `text.xml` | `common` | — | quick-xml | S1 | package, permissions, components |
| 295 | SVG sprite / icon sets | `svg` | — | 3 | `text.xml` | `common` | — | quick-xml | S1 | symbol count |
| 296 | Office custom XML / content types | `xml` | — | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | — |
| 297 | ClickOnce / app manifests | `application` `manifest` | — | 3 | `text.xml` | `common` | — | quick-xml | S1 | identity, dependencies |
| 298 | Nmap XML / Nessus reports | `xml` `nessus` | — | 3 | `text.xml` | `common` | `text.xml` | quick-xml | S1 | hosts, open ports, findings by severity |
| 299 | OpenSCENARIO / OpenDRIVE | `xosc` `xodr` | — | 3 | `text.xml` | `common` | — | quick-xml | S1 | roads, junctions |
| 300 | GPX-like Garmin TCX | `tcx` | — | 3 | `text.xml` | `common` | — | quick-xml | S1 | -&gt; geo |
| 301 | JSON Feed | `json` | application/feed+json | 3 | `text.feed` | `common` | — | feed-rs | S1 | — |
| 302 | OPML outline | `opml` | text/x-opml | 3 | `text.feed` | `common` | `text.feed` | feed-rs | S1 | outline titles, feed URLs |
| 303 | JSON5 | `json5` | application/json5 | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | — |
| 304 | JSON-LD | `jsonld` | application/ld+json | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | @context, @type |
| 305 | HAR archive | `har` | application/json | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | -&gt; forensic |
| 306 | Postman collection | `postman_collection.json` | application/json | 3 | `data.json` | `common` | — | serde_json, json5 | S1 | requests count, folders |
| 307 | VS Code workspace / settings | `code-workspace` | application/json | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | — |
| 308 | Chrome extension manifest | `manifest.json` | application/manifest+json | 3 | `data.json` | `common` | — | serde_json, json5 | S1 | name, version, permissions (risk) |
| 309 | Web app manifest | `webmanifest` | application/manifest+json | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | — |
| 310 | Lottie animation | `lottie` | application/json | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | fps, frames, size, layers |
| 311 | Excalidraw drawing | `excalidraw` | application/json | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | element counts, text |
| 312 | TopoJSON | `topojson` | application/json | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | -&gt; geo |
| 313 | Terraform state | `tfstate` `tfstate.backup` | application/json | 3 | `data.json` | `common` | — | serde_json, json5 | S1 | resources by type, providers, serial; all attribute values redacted |
| 314 | SARIF static-analysis log | `sarif` | application/sarif+json | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | tool, rules, result count by level |
| 315 | AWS CloudTrail / cloud audit logs | `json` `json.gz` | — | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | event names histogram, principals count, time range, regions |
| 316 | Grafana / Kibana dashboards | `json` `ndjson` | — | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | title, panels, datasources |
| 317 | Frictionless datapackage / CSVW | `datapackage.json` `csv-metadata.json` | — | 3 | `data.json` | `common` | — | serde_json, json5 | S1 | resources, schemas |
| 318 | dbt manifest / catalog | `manifest.json` `catalog.json` | — | 3 | `data.json` | `common` | — | serde_json, json5 | S1 | models, sources, tests count |
| 319 | ESLint / Prettier / Babel / tsconfig | `eslintrc` `prettierrc` `babelrc` `tsconfig.json` | — | 3 | `data.json` | `common` | — | serde_json, json5 | S1 | extends, plugins, compiler target |
| 320 | Social / takeout exports (Twitter, Facebook, Slack, Discord, Telegram, Spotify) | `json` `js` | — | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | export kind, record count, date range |
| 321 | Google Takeout location history | `Records.json` `Timeline.json` | — | 3 | `data.json` | `common` | — | serde_json, json5 | S1 | point count, date range, bbox -&gt; geo |
| 322 | Google Drive shortcuts | `gdoc` `gsheet` `gslides` `gdraw` | — | 3 | `data.json` | `common` | — | serde_json, json5 | S1 | doc id, URL |
| 323 | STIX 2 / MISP threat intel | `json` | — | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | object types, indicator count |
| 324 | CSAF / OpenVEX / OSV advisories | `json` | — | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | CVE ids, products, severity |
| 325 | Scratch project | `sb3` `sb2` | — | 3 | `data.json` | `common` | — | serde_json, json5 | S1 | sprites, block counts, extensions |
| 326 | Spine / DragonBones / Rive animations | `json` `skel` `riv` | — | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | skeleton, animations |
| 327 | OpenAI / Anthropic chat transcript exports | `json` `jsonl` | — | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | conversation count, message roles, date range |
| 328 | Jupyter-adjacent: VS Code .code-snippets / launch.json | `code-snippets` `launch.json` | — | 3 | `data.json` | `common` | — | serde_json, json5 | S1 | configurations |
| 329 | Composer / npm audit reports | `json` | — | 3 | `data.json` | `common` | `data.json` | serde_json, json5 | S1 | vulnerabilities by severity |
| 330 | OpenAPI (YAML) | `openapi.yaml` | — | 3 | `data.yaml` | `common` | — | serde-saphyr | S1 | — |
| 331 | Ansible playbook | `yml` | — | 3 | `data.yaml` | `common` | `data.yaml` | serde-saphyr | S1 | hosts, roles, modules |
| 332 | Helm chart | `Chart.yaml` | — | 3 | `data.yaml` | `common` | — | serde-saphyr | S1 | — |
| 333 | CloudFormation / SAM | `template.yaml` | — | 3 | `data.yaml` | `common` | — | serde-saphyr | S1 | resources by type |
| 334 | GitLab CI | `.gitlab-ci.yml` | — | 3 | `data.yaml` | `common` | — | serde-saphyr | S1 | stages, jobs |
| 335 | conda environment | `environment.yml` | — | 3 | `data.yaml` | `common` | — | serde-saphyr | S1 | channels, deps |
| 336 | Sigma detection rule | `yml` | — | 3 | `data.yaml` | `common` | `data.yaml` | serde-saphyr | S1 | title, logsource, level, tags (ATT&CK) |
| 337 | Kustomize / Argo / Tekton / Serverless | `kustomization.yaml` `serverless.yml` | — | 3 | `data.yaml` | `common` | — | serde-saphyr | S1 | resources, functions |
| 338 | Dependabot / Renovate / pre-commit configs | `dependabot.yml` `renovate.json` `.pre-commit-config.yaml` | — | 3 | `data.yaml` | `common` | — | serde-saphyr | S1 | ecosystems, hooks |
| 339 | winget / Scoop manifests | `yaml` `json` | — | 3 | `data.yaml` | `common` | `data.yaml` | serde-saphyr | S1 | package id, version, installer URL |
| 340 | OpenAPI 3.1 / AsyncAPI | `asyncapi.yaml` | — | 3 | `data.yaml` | `common` | — | serde-saphyr | S1 | channels, messages |
| 341 | Windows .reg export | `reg` | text/plain | 3 | `data.ini` | `common` | `data.ini` | rust-ini, java-properties | S1 | keys, value counts |
| 342 | Desktop entry | `desktop` | application/x-desktop | 3 | `data.ini` | `common` | `data.ini` | rust-ini, java-properties | S1 | Name, Exec, Categories |
| 343 | EditorConfig | `editorconfig` | — | 3 | `data.ini` | `common` | `data.ini` | rust-ini, java-properties | S1 | — |
| 344 | Git config | `gitconfig` `.gitmodules` | — | 3 | `data.ini` | `common` | `data.ini` | rust-ini, java-properties | S1 | remotes, submodules |
| 345 | systemd unit | `service` `socket` `timer` `mount` `target` | — | 3 | `data.ini` | `common` | `data.ini` | rust-ini, java-properties | S1 | -&gt; code.infra |
| 346 | Windows INF | `inf` | text/plain | 3 | `data.ini` | `common` | `data.ini` | rust-ini, java-properties | S1 | driver class, provider, hardware ids |
| 347 | WireGuard / OpenVPN config | `conf` `ovpn` | — | 3 | `data.ini` | `common` | `data.ini` | rust-ini, java-properties | S1 | peers/remotes count, keys redacted, embedded certs -&gt; crypto |
| 348 | Windows theme / desktop.ini | `theme` `desktop.ini` | — | 3 | `data.ini` | `common` | — | rust-ini, java-properties | S1 | — |
| 349 | Kerberos krb5.conf / Samba smb.conf | `conf` | — | 3 | `data.ini` | `common` | `data.ini` | rust-ini, java-properties | S1 | realms, shares |
| 350 | PSV / pipe separated | `psv` | — | 3 | `data.csv` | `common` | `data.csv` | csv | S1 | — |
| 351 | Fixed-width text table | `fwf` `prn` | — | 3 | `data.csv` | `common` | — | csv | S1 | column boundaries guess |
| 352 | vCalendar-like CSV exports (Outlook/Google contacts) | `csv` | — | 3 | `data.csv` | `common` | `data.csv` | csv | S1 | — |
| 353 | LCOV coverage | `info` `lcov` | — | 3 | `data.csv` | `common` | — | csv | S1 | files, line coverage |
| 354 | GTFS transit feed (zip of CSV) | `zip` | — | 3 | `data.csv` | `common` | — | csv | S1 | agency, routes, stops, service date range |
| 355 | Bank statements OFX / QFX / QIF / MT940 / CAMT | `ofx` `qfx` `qif` `sta` `940` `camt.053` | — | 3 | `data.csv` | `common` | — | csv | S1 | account (masked), transaction count, date range, currency |
| 356 | Ledger / Beancount / hledger journals | `ledger` `beancount` `journal` | — | 3 | `data.csv` | `common` | — | csv | S1 | accounts, transaction count, commodities |
| 357 | EDI X12 / EDIFACT | `edi` `x12` `edifact` | — | 3 | `data.csv` | `common` | — | csv | S1 | message types, sender/receiver ids |
| 358 | GEDCOM genealogy | `ged` `gedcom` | — | 3 | `data.csv` | `common` | — | csv | S1 | individuals, families, date range, source software |
| 359 | Prometheus / OpenMetrics exposition | `prom` `metrics` | — | 3 | `data.csv` | `common` | — | csv | S1 | metric names, types, label keys |
| 360 | TAP test output | `tap` | — | 3 | `data.csv` | `common` | — | csv | S1 | plan, pass/fail |
| 361 | PRQL | `prql` | — | 3 | `data.sql` | `common` | — | sqlparser | S1 | — |
| 362 | Cypher / GQL | `cypher` `cql` | — | 3 | `data.sql` | `common` | — | sqlparser | S1 | — |
| 363 | Database migration files (Flyway/Liquibase/Alembic) | `sql` `xml` `py` | — | 3 | `data.sql` | `common` | `data.sql` | sqlparser | S1 | version ordering, tables touched |
| 364 | Astro component | `astro` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 365 | Nim | `nim` `nims` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 366 | Crystal | `cr` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 367 | D | `d` `di` | text/x-d | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 368 | V / Vlang | `v` `vsh` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 369 | Odin | `odin` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 370 | Fortran | `f` `f77` `f90` `f95` `f03` `f08` `for` | text/x-fortran | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 371 | COBOL | `cob` `cbl` `cpy` | text/x-cobol | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 372 | Pascal / Delphi | `pas` `pp` `dpr` `lpr` | text/x-pascal | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 373 | Ada | `adb` `ads` | text/x-ada | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 374 | Common Lisp / Emacs Lisp | `lisp` `lsp` `el` `cl` | text/x-lisp | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 375 | Scheme / Racket | `scm` `ss` `rkt` | text/x-scheme | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 376 | Prolog | `pro` `P` | text/x-prolog | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 377 | Elm | `elm` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 378 | PureScript | `purs` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 379 | ReScript / ReasonML | `res` `resi` `re` `rei` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 380 | CoffeeScript | `coffee` `litcoffee` | text/coffeescript | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 381 | Haxe | `hx` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 382 | Tcl | `tcl` `tk` | text/x-tcl | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 383 | AWK / sed | `awk` `sed` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 384 | fish shell | `fish` | — | 3 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 385 | Solidity | `sol` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | contract names, pragma version |
| 386 | Move / Cairo / Vyper | `move` `cairo` `vy` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 387 | Verilog / SystemVerilog | `v` `sv` `svh` | text/x-verilog | 3 | `code.source` | `common` | — | tokei | S1/S6 | modules |
| 388 | VHDL | `vhd` `vhdl` | text/x-vhdl | 3 | `code.source` | `common` | — | tokei | S1/S6 | entities |
| 389 | OpenCL | `cl` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 390 | GLSL shader | `glsl` `vert` `frag` `geom` `comp` `tesc` `tese` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 391 | HLSL shader | `hlsl` `fx` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 392 | WGSL shader | `wgsl` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 393 | Metal shader | `metal` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 394 | SPIR-V binary | `spv` | — | 3 | `code.source` | `common` | — | tokei | S8 | -&gt; bytecode-like header |
| 395 | Apex / Salesforce | `cls` `trigger` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 396 | ABAP | `abap` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 397 | Smalltalk | `st` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 398 | Raku | `raku` `rakumod` `p6` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 399 | Hack | `hack` `hh` | — | 3 | `code.source` | `common` | `code.source` | tokei | S1/S6 | — |
| 400 | Starlark / Bazel | `bzl` `star` `BUILD` `WORKSPACE` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | rules, load() |
| 401 | Meson / Ninja | `meson.build` `ninja` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 402 | AutoHotkey / AutoIt | `ahk` `au3` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 403 | Jupyter-less IPython script | `ipy` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 404 | Gleam / Roc / Unison | `gleam` `roc` `u` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 405 | Mojo | `mojo` `🔥` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 406 | Q# / OpenQASM | `qs` `qasm` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 407 | Arduino sketch | `ino` `pde` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 408 | LLVM IR | `ll` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | target triple, functions |
| 409 | WebAssembly text | `wat` `wast` | text/wasm | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 410 | Regex / grammar files (ANTLR, PEG, Bison/Yacc, Lex) | `g4` `peg` `y` `yy` `l` `lex` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 411 | Puppet / Chef | `pp` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 412 | PL/SQL / T-SQL | `pls` `plsql` `pck` `tsql` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 413 | Template: Go/Handlebars/Pug | `tmpl` `gotmpl` `pug` `jade` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 414 | Vim script | `vim` `vimrc` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 415 | Shell rc / profile | `bashrc` `zshrc` `profile` `bash_profile` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | aliases, exports (values redacted) |
| 416 | Nushell / Elvish | `nu` `elv` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 417 | Rego (OPA) policy | `rego` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | package, rules |
| 418 | Bicep / ARM templates | `bicep` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | resources |
| 419 | Jenkinsfile / Earthfile / Tiltfile | `Jenkinsfile` `Earthfile` `Tiltfile` | — | 3 | `code.source` | `common` | `code.source` | tokei | S1/S6 | stages |
| 420 | Proof assistants (Lean, Coq, Agda, Idris, Isabelle) | `lean` `v` `agda` `idr` `thy` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | theorems/defs count |
| 421 | Formal specs (TLA+, Alloy) | `tla` `als` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 422 | Ballerina / Pony / Janet / Fennel / Hy | `bal` `pony` `janet` `fnl` `hy` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 423 | Forth / APL / J / K / Q | `fth` `4th` `apl` `ijs` `k` `q` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 424 | GDScript (Godot) | `gd` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | extends, signals, funcs |
| 425 | Unity ShaderLab | `shader` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 426 | PLC IEC 61131 Structured Text | `st` `scl` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | programs, function blocks |
| 427 | Max/MSP / Pure Data patches | `maxpat` `pd` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | object counts |
| 428 | YARA rules | `yar` `yara` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | rule names, tags, meta, strings count |
| 429 | Snort / Suricata rules | `rules` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | rule count, actions, protocols, sids, msg list, classtypes |
| 430 | Smithy / Avro IDL | `smithy` `avdl` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | services, shapes |
| 431 | AppleScript (text) / JXA | `applescript` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 432 | Kotlin Multiplatform / Compose scripts | `main.kts` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | — |
| 433 | SQL notebooks / dbt models | `sql` | — | 3 | `code.source` | `common` | — | tokei | S1/S6 | refs, sources (Jinja) |
| 434 | Pipfile / poetry.lock / uv.lock | `Pipfile` `Pipfile.lock` `poetry.lock` `uv.lock` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 435 | setup.py / setup.cfg | `setup.py` `setup.cfg` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 436 | Gradle build | `build.gradle` `build.gradle.kts` `settings.gradle` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 437 | Ruby Gemfile / lock | `Gemfile` `Gemfile.lock` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 438 | Composer | `composer.json` `composer.lock` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 439 | .NET project | `csproj` `fsproj` `vbproj` `sln` `props` `targets` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | target frameworks, PackageReferences |
| 440 | NuGet packages.config / Directory.Packages.props | `packages.config` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 441 | CocoaPods / SwiftPM | `Podfile` `Podfile.lock` `Package.swift` `Package.resolved` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 442 | Dart pubspec | `pubspec.yaml` `pubspec.lock` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 443 | Elixir mix / Hex | `mix.exs` `mix.lock` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 444 | Haskell cabal / stack | `cabal` `stack.yaml` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 445 | R DESCRIPTION | `DESCRIPTION` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 446 | Conan / vcpkg | `conanfile.txt` `conanfile.py` `vcpkg.json` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 447 | Deno config | `deno.json` `deno.jsonc` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 448 | Julia Project.toml / Manifest.toml | `Project.toml` `Manifest.toml` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 449 | CITATION.cff | `cff` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | title, authors, DOI |
| 450 | SBOM (SPDX / CycloneDX) | `spdx` `spdx.json` `cdx.json` `bom.xml` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | component count, licences |
| 451 | Homebrew formula / Brewfile | `rb` `Brewfile` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 452 | Arch PKGBUILD | `PKGBUILD` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | pkgname, pkgver, depends, source URLs |
| 453 | RPM spec | `spec` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | Name, Version, Release, License, Requires |
| 454 | Debian source control files | `control` `changelog` `copyright` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | Source, Maintainer, Build-Depends |
| 455 | Nix flake | `flake.nix` `flake.lock` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | inputs, outputs |
| 456 | Bazel MODULE / Terraform lock | `MODULE.bazel` `.terraform.lock.hcl` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 457 | Snapcraft / Flatpak manifests | `snapcraft.yaml` `flatpak.json` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 458 | opam / CPAN META / rebar.config | `opam` `META.json` `rebar.config` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 459 | elm.json / gleam.toml / build.zig.zon | `elm.json` `gleam.toml` `build.zig.zon` | — | 3 | `code.manifest` | `common` | — | reuses data.json/toml/yaml/xml parsers + impl per-ecosystem mapping | S8 | — |
| 460 | Zeppelin / Databricks notebook | `zpln` `dbc` | — | 3 | `code.notebook` | `common` | — | serde_json | S8 | — |
| 461 | Observable / Livebook | `livemd` | — | 3 | `code.notebook` | `common` | — | serde_json | S8 | — |
| 462 | Mathematica notebook | `nb` `cdf` | application/mathematica | 3 | `code.notebook` | `common` | — | serde_json | S8 | — |
| 463 | Memory / swap dumps | `mem` `raw` `vmem` `swap` | — | 3 | `binary.unknown` | `common` | — | aho-corasick + impl | S8 | strings + embedded signatures only |
| 464 | Firmware blob | `fw` `bin` `rom` | — | 3 | `binary.unknown` | `common` | `binary.unknown` | aho-corasick + impl | S8 | binwalk-style signature scan |
| 465 | Temporary / partial download | `part` `crdownload` `tmp` `download` | — | 3 | `binary.unknown` | `common` | — | aho-corasick + impl | S8 | underlying format re-detected |
| 466 | Backup copies | `bak` `old` `orig` `swp` | — | 3 | `binary.unknown` | `common` | — | aho-corasick + impl | S8 | detect underlying format; Vim swap -&gt; original filename |
| 467 | Sparse / zero-filled files | `*` | — | 3 | `binary.unknown` | `common` | — | aho-corasick + impl | S8 | hole detection (SEEK_DATA), zero ratio |
| 468 | Core Foundation / NSKeyedArchiver blobs | `plist` | — | 3 | `binary.unknown` | `common` | — | aho-corasick + impl | S8 | -&gt; apple |
| 469 | QOI | `qoi` | image/qoi | 3 | `image.raster` | `common` | `image.qoi` | imagesize | S2 | — |
| 470 | Farbfeld | `ff` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | — |
| 471 | JPEG-XR / HD Photo | `jxr` `wdp` `hdp` | image/jxr | 3 | `image.raster` | `common` | — | imagesize | S8 | TIFF-like IFD (impl) |
| 472 | JPEG-LS / Lossless JPEG | `jls` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | — |
| 473 | MPO (multi-picture) | `mpo` | image/mpo | 3 | `image.raster` | `common` | `image.jpeg` | imagesize | S2 | MPF index, stereo pairs |
| 474 | Radiance HDR | `hdr` `pic` | image/vnd.radiance | 3 | `image.raster` | `common` | `image.hdr` | imagesize | S2 | — |
| 475 | SGI / RGB | `sgi` `rgb` `rgba` `bw` | image/sgi | 3 | `image.raster` | `common` | — | imagesize | S2 | — |
| 476 | Sun Raster / XBM / XPM | `ras` `xbm` `xpm` | image/x-xpixmap | 3 | `image.raster` | `common` | — | imagesize | S2 | — |
| 477 | WBMP | `wbmp` | image/vnd.wap.wbmp | 3 | `image.raster` | `common` | — | imagesize | S2 | — |
| 478 | FLIF / BPG | `flif` `bpg` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | — |
| 479 | Apple ICNS | `icns` | image/icns | 3 | `image.raster` | `common` | — | imagesize | S2 | icon sizes |
| 480 | Windows animated cursor | `ani` | application/x-navi-animation | 3 | `image.raster` | `common` | — | imagesize | S2 | RIFF |
| 481 | PICT | `pict` `pct` | image/x-pict | 3 | `image.raster` | `common` | — | imagesize | S2 | — |
| 482 | Amiga IFF ILBM | `iff` `ilbm` `lbm` | image/x-ilbm | 3 | `image.raster` | `common` | — | imagesize | S2 | — |
| 483 | DCX / multi-page PCX | `dcx` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | — |
| 484 | FITS image | `fits` `fit` `fts` | image/fits | 3 | `image.raster` | `common` | — | imagesize | S2 | -&gt; sci |
| 485 | Cineon / DPX film scan | `cin` `dpx` | image/x-dpx | 3 | `image.raster` | `common` | — | imagesize | S8 | film/TV header: timecode, frame, creator |
| 486 | WebP2 / AVCI / HEJ2 (ISOBMFF variants) | `avci` `hej2` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | — |
| 487 | Google Ultra HDR / gain-map JPEG | `jpg` | — | 3 | `image.raster` | `common` | `image.jpeg` | imagesize | S2 | MPF + XMP hdrgm namespace |
| 488 | CompuServe RLE / Mac Paint | `rle` `mac` `pntg` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | — |
| 489 | OpenRaster | `ora` | image/openraster | 3 | `image.raster` | `common` | — | imagesize | S2 | -&gt; image.layered |
| 490 | Krita / Procreate | `kra` `procreate` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | -&gt; image.layered |
| 491 | DjVu single page | `djvu` | image/vnd.djvu | 3 | `image.raster` | `common` | — | imagesize | S2 | -&gt; doc.other |
| 492 | Windows Imaging Component (CR in WIC) | `wmp` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | — |
| 493 | BigTIFF | `tif` `tiff` `btf` | image/tiff | 3 | `image.raster` | `common` | `image.tiff` | imagesize | S2 | — |
| 494 | Kodak Photo CD / FlashPix | `pcd` `fpx` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | FPX = OLE property sets |
| 495 | XISF astronomy image | `xisf` | — | 3 | `image.raster` | `common` | — | imagesize | S8 | XML header: observation keywords |
| 496 | Thumbnails cache (Windows thumbcache) | `db` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | entry count -&gt; forensic |
| 497 | Colour LUTs | `cube` `3dl` `lut` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | size, title, domain |
| 498 | Photoshop assets (actions, brushes, swatches) | `atn` `abr` `aco` `ase` `grd` `pat` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | names list |
| 499 | Raw editor sidecars | `xmp` `pp3` `dop` `arp` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | -&gt; meta.xmp; develop settings |
| 500 | Whole-slide images | `svs` `ndpi` `scn` `mrxs` `vms` | — | 3 | `image.raster` | `common` | — | imagesize | S2 | scanner, magnification, levels -&gt; medical |
| 501 | HEIF image sequence / Live Photo HEIC | `heics` | — | 3 | `image.raster` | `common` | `image.heif` | imagesize | S2 | frame count |
| 502 | Fujifilm RAF | `raf` | image/x-fuji-raf | 3 | `image.raw` | `common` | `image.raw` | rawler | S2 | — |
| 503 | Olympus / OM ORF | `orf` | image/x-olympus-orf | 3 | `image.raw` | `common` | `image.raw` | rawler | S2 | — |
| 504 | Panasonic RW2 / RAW | `rw2` `raw` | image/x-panasonic-rw2 | 3 | `image.raw` | `common` | `image.raw` | rawler | S2 | — |
| 505 | Pentax PEF | `pef` | image/x-pentax-pef | 3 | `image.raw` | `common` | `image.raw` | rawler | S2 | — |
| 506 | Samsung SRW | `srw` | image/x-samsung-srw | 3 | `image.raw` | `common` | `image.raw` | rawler | S2 | — |
| 507 | Leica RWL / Hasselblad 3FR/FFF | `rwl` `3fr` `fff` | — | 3 | `image.raw` | `common` | `image.raw` | rawler | S2 | — |
| 508 | Phase One IIQ / Leaf MOS | `iiq` `mos` | — | 3 | `image.raw` | `common` | — | rawler | S2 | — |
| 509 | Mamiya MEF / Minolta MRW | `mef` `mrw` | — | 3 | `image.raw` | `common` | — | rawler | S2 | — |
| 510 | Sigma X3F | `x3f` | — | 3 | `image.raw` | `common` | — | rawler | S2 | — |
| 511 | Kodak DCR/KDC/K25 / Epson ERF | `dcr` `kdc` `k25` `erf` | — | 3 | `image.raw` | `common` | — | rawler | S2 | — |
| 512 | GoPro GPR | `gpr` | — | 3 | `image.raw` | `common` | — | rawler | S2 | — |
| 513 | Apple ProRAW (DNG) | `dng` | — | 3 | `image.raw` | `common` | `image.raw` | rawler | S2 | — |
| 514 | GIMP XCF | `xcf` | image/x-xcf | 3 | `image.layered` | `common` | `image.xcf` | psd | S2 | — |
| 515 | Krita | `kra` | application/x-krita | 3 | `image.layered` | `common` | — | psd | S2 | — |
| 516 | OpenRaster | `ora` | image/openraster | 3 | `image.layered` | `common` | — | psd | S2 | — |
| 517 | Procreate | `procreate` | — | 3 | `image.layered` | `common` | — | psd | S2 | — |
| 518 | Affinity Photo/Designer/Publisher | `afphoto` `afdesign` `afpub` | — | 3 | `image.layered` | `common` | — | psd | S8 | header, embedded thumbnail |
| 519 | Sketch | `sketch` | — | 3 | `image.layered` | `common` | — | psd | S2 | pages, artboards (zip+json) |
| 520 | Figma export | `fig` | — | 3 | `image.layered` | `common` | — | psd | S8 | header only |
| 521 | Paint.NET | `pdn` | — | 3 | `image.layered` | `common` | — | psd | S2 | — |
| 522 | Corel Painter / PaintShop Pro | `rif` `pspimage` | — | 3 | `image.layered` | `common` | — | psd | S2 | — |
| 523 | CorelDRAW | `cdr` `cdt` | application/vnd.corel-draw | 3 | `image.vector` | `common` | — | quick-xml | S2 | RIFF chunks, version |
| 524 | Adobe Illustrator legacy (PS-based) | `ai` | application/postscript | 3 | `image.vector` | `common` | — | quick-xml | S2 | -&gt; doc.other DSC |
| 525 | Xfig / Graphviz DOT | `fig` `dot` `gv` | text/vnd.graphviz | 3 | `image.vector` | `common` | — | quick-xml | S2 | graph name, node/edge count |
| 526 | Mermaid / PlantUML | `mmd` `mermaid` `puml` `plantuml` | — | 3 | `image.vector` | `common` | — | quick-xml | S2 | diagram type, nodes |
| 527 | draw.io / diagrams.net | `drawio` `dio` | — | 3 | `image.vector` | `common` | — | quick-xml | S2 | pages, labels |
| 528 | Visio stencil XML | `vdx` | — | 3 | `image.vector` | `common` | — | quick-xml | S2 | — |
| 529 | Inkscape / Sodipodi SVG | `svg` | — | 3 | `image.vector` | `common` | `image.svg` | quick-xml | S2 | inkscape:version, layers |
| 530 | Lottie / Bodymovin | `json` | — | 3 | `image.vector` | `common` | — | quick-xml | S2 | -&gt; data.json |
| 531 | Macromedia FreeHand | `fh` `fh11` | — | 3 | `image.vector` | `common` | — | quick-xml | S2 | — |
| 532 | CGM | `cgm` | image/cgm | 3 | `image.vector` | `common` | — | quick-xml | S2 | — |
| 533 | KTX / KTX2 | `ktx` `ktx2` | image/ktx2 | 3 | `image.texture` | `common` | `image.ktx` | ddsfile, ktx2 | S2 | — |
| 534 | Basis Universal | `basis` | — | 3 | `image.texture` | `common` | — | ddsfile, ktx2 | S2 | — |
| 535 | Valve VTF | `vtf` | — | 3 | `image.texture` | `common` | — | ddsfile, ktx2 | S2 | — |
| 536 | PVR texture | `pvr` | — | 3 | `image.texture` | `common` | — | ddsfile, ktx2 | S2 | — |
| 537 | ASTC | `astc` | — | 3 | `image.texture` | `common` | — | ddsfile, ktx2 | S2 | — |
| 538 | Unreal / Unity textures (raw headers) | `utx` `tex` | — | 3 | `image.texture` | `common` | — | ddsfile, ktx2 | S2 | — |
| 539 | EXIF raw dump | `exif` `exv` | — | 3 | `meta.exif` | `common` | — | kamadak-exif | S2 | exiv2 .exv container |
| 540 | XMP sidecar | `xmp` | application/rdf+xml | 3 | `meta.xmp` | `common` | — | impl on quick-xml | S8 | — |
| 541 | VRA Core 4 XML record | `xml` | — | 3 | `meta.vra` | `common` | — | impl: map XMP vra namespace + standalone VRA Core 4 XML records via quick-xml | S8 | — |
| 542 | ICC colour profile | `icc` `icm` | application/vnd.iccprofile | 3 | `meta.icc` | `common` | — | impl | S8 | — |
| 543 | vCalendar 1.0 | `vcs` | text/x-vcalendar | 3 | `text.calendar` | `common` | `text.calendar` | impl | S8 | — |
| 544 | JSCalendar | `json` | — | 3 | `text.calendar` | `common` | — | impl | S8 | — |
| 545 | JSContact / LDIF | `ldif` | text/directory | 3 | `text.contact` | `common` | — | impl | S8 | — |
| 546 | Outlook data file | `pst` `ost` | application/vnd.ms-outlook-pst | 3 | `email` | `common` | — | mail-parser | S3 | folder tree, item counts, date range |
| 547 | Maildir message | `(maildir` `file)` | — | 3 | `email` | `common` | — | mail-parser | S3 | — |
| 548 | Thunderbird / EMLX | `emlx` | — | 3 | `email` | `common` | `email.mime` | mail-parser | S3 | Apple Mail plist trailer |
| 549 | Usenet / NNTP article | `nws` | — | 3 | `email` | `common` | — | mail-parser | S3 | — |
| 550 | TNEF winmail.dat | `dat` | application/ms-tnef | 3 | `email` | `common` | — | mail-parser | S8 | attachments (impl) |
| 551 | Lotus Notes database | `nsf` | — | 3 | `email` | `common` | — | mail-parser | S8 | title, replica id (header) |
| 552 | Outlook for Mac archive / Outlook Express DBX | `olm` `dbx` | — | 3 | `email` | `common` | — | mail-parser | S3 | folders, message count |
| 553 | Mork address book / mail summary | `mab` `msf` | — | 3 | `email` | `common` | — | mail-parser | S3 | — |
| 554 | PDF/A, PDF/X, PDF/UA variants | `pdf` | application/pdf | 3 | `doc.pdf` | `common` | `doc.pdf` | impl | S8 | conformance from XMP pdfaid/pdfx/pdfuaid |
| 555 | Adobe Illustrator (PDF-based) | `ai` | application/illustrator | 3 | `doc.pdf` | `common` | — | impl | S8 | AI private data present, artboards |
| 556 | Forms Data Format | `fdf` `xfdf` | application/vnd.fdf | 3 | `doc.pdf` | `common` | `doc.pdf` | impl | S8 | field names/values |
| 557 | PDF portfolio / collection | `pdf` | — | 3 | `doc.pdf` | `common` | `doc.pdf` | impl | S8 | embedded file list |
| 558 | Visio drawing (OOXML) | `vsdx` `vsdm` `vstx` | application/vnd.ms-visio.drawing | 3 | `doc.ooxml` | `common` | `doc.ooxml` | impl | S8 | page names, shape text |
| 559 | Word XML 2003 / Flat OPC | `xml` `fodt` | — | 3 | `doc.ooxml` | `common` | — | impl | S8 | — |
| 560 | XPS / OpenXPS | `xps` `oxps` | application/oxps | 3 | `doc.ooxml` | `common` | — | impl | S8 | pages, fonts, docProps |
| 561 | 3D Manufacturing Format (OPC) | `3mf` | model/3mf | 3 | `doc.ooxml` | `common` | — | impl | S8 | -&gt; 3d |
| 562 | OpenDocument Drawing / Graphics | `odg` `otg` | application/vnd.oasis.opendocument.graphics | 3 | `doc.odf` | `common` | `doc.odf` | impl | S8 | — |
| 563 | OpenDocument Formula / Database / Chart | `odf` `odb` `odc` | — | 3 | `doc.odf` | `common` | `doc.odf` | impl | S8 | — |
| 564 | Flat OpenDocument XML | `fodt` `fods` `fodp` `fodg` | — | 3 | `doc.odf` | `common` | `doc.odf` | impl | S8 | — |
| 565 | Apple Pages / Numbers / Keynote | `pages` `numbers` `key` | application/vnd.apple.pages | 3 | `doc.odf` | `common` | — | impl | S8 | zip + IWA (snappy+protobuf); metadata from Metadata/Properties.plist + preview |
| 566 | Hancom HWPX | `hwpx` | — | 3 | `doc.odf` | `common` | — | impl | S8 | — |
| 567 | Visio legacy | `vsd` `vss` `vst` | application/vnd.visio | 3 | `doc.ole` | `common` | `doc.ole` | impl | S8 | — |
| 568 | Microsoft Publisher | `pub` | application/x-mspublisher | 3 | `doc.ole` | `common` | `doc.ole` | impl | S8 | — |
| 569 | Microsoft Project | `mpp` | application/vnd.ms-project | 3 | `doc.ole` | `common` | `doc.ole` | impl | S8 | — |
| 570 | Outlook template / item | `oft` | application/vnd.ms-outlook | 3 | `doc.ole` | `common` | — | impl | S8 | -&gt; email |
| 571 | Thumbs.db | `db` | — | 3 | `doc.ole` | `common` | `doc.ole` | impl | S8 | thumbnail count |
| 572 | Hangul HWP 5 | `hwp` | application/x-hwp | 3 | `doc.ole` | `common` | `doc.ole` | impl | S8 | — |
| 573 | Generic OLE2 Compound File | `cfb` `ole` | — | 3 | `doc.ole` | `common` | `doc.ole` | impl | S8 | storage tree |
| 574 | SolidWorks / Inventor (OLE-based) | `sldprt` `sldasm` `slddrw` `ipt` `iam` `idw` | — | 3 | `doc.ole` | `common` | — | impl | S8 | -&gt; cad, summary info |
| 575 | Microsoft Works / WordPerfect | `wps` `wks` `wpd` `wp` | application/vnd.wordperfect | 3 | `doc.ole` | `common` | — | impl | S8 | header + prefix packet |
| 576 | WordPad / RTFD bundle | `rtfd` | — | 3 | `doc.rtf` | `common` | — | impl | S8 | — |
| 577 | Kindle KFX | `kfx` | — | 3 | `doc.ebook` | `common` | — | impl | S8 | header only; DRM flag |
| 578 | FictionBook | `fb2` `fbz` | application/x-fictionbook+xml | 3 | `doc.ebook` | `common` | `doc.ebook` | impl | S8 | — |
| 579 | Apple iBooks | `ibooks` | — | 3 | `doc.ebook` | `common` | — | impl | S8 | — |
| 580 | Microsoft Reader / eReader | `lit` `pdb` | — | 3 | `doc.ebook` | `common` | `doc.ebook` | impl | S8 | — |
| 581 | DAISY / Open eBook | `opf` `ncx` | — | 3 | `doc.ebook` | `common` | — | impl | S8 | — |
| 582 | DjVu | `djvu` `djv` | image/vnd.djvu | 3 | `doc.other` | `common` | — | impl | S8 | — |
| 583 | Compiled HTML Help | `chm` | application/vnd.ms-htmlhelp | 3 | `doc.other` | `common` | — | impl | S8 | ITSF header, topics list (impl) |
| 584 | WinHelp | `hlp` | — | 3 | `doc.other` | `common` | — | impl | S8 | — |
| 585 | RIS / EndNote / CSL-JSON citations | `ris` `enw` `nbib` `csl` | — | 3 | `doc.other` | `common` | — | impl | S8 | entry count, titles, DOIs |
| 586 | Typst | `typ` | — | 3 | `doc.other` | `common` | — | impl | S8 | — |
| 587 | Groff/Scribus/LyX | `lyx` `sla` | — | 3 | `doc.other` | `common` | — | impl | S8 | — |
| 588 | Microsoft OneNote | `one` `onetoc2` | application/onenote | 3 | `doc.other` | `common` | — | impl | S8 | section/page titles (impl, revision store) |
| 589 | Evernote export | `enex` | application/enex+xml | 3 | `doc.other` | `common` | — | impl | S8 | note titles, tags, dates |
| 590 | Obsidian canvas | `canvas` | — | 3 | `doc.other` | `common` | — | impl | S8 | nodes, text |
| 591 | Scrivener / Final Draft / Fountain | `scriv` `fdx` `fountain` | — | 3 | `doc.other` | `common` | — | impl | S8 | title page, scene headings |
| 592 | Lotus 1-2-3 / Quattro | `wk1` `wk3` `wk4` `123` `qpw` | — | 3 | `doc.other` | `common` | — | impl | S8 | — |
| 593 | Apple ClarisWorks / AppleWorks | `cwk` | — | 3 | `doc.other` | `common` | — | impl | S8 | — |
| 594 | PDF-like: Adobe FrameMaker / InDesign | `fm` `mif` `indd` `idml` | — | 3 | `doc.other` | `common` | — | impl | S8 | IDML (zip+xml): stories text |
| 595 | XML Paper / StarOffice legacy | `sxw` `sxc` `sxi` `sdw` | — | 3 | `doc.other` | `common` | — | impl | S8 | -&gt; doc.odf mapping |
| 596 | Mailing labels / Mail merge data | `mdb-merge` | — | 3 | `doc.other` | `common` | — | impl | S8 | — |
| 597 | PCL / PJL print job | `pcl` `prn` `pjl` | application/vnd.hp-pcl | 3 | `doc.other` | `common` | — | impl | S8 | PJL JOB NAME, user, page count |
| 598 | Windows spool files | `spl` `shd` | — | 3 | `doc.other` | `common` | — | impl | S8 | document name, user, printer, submit time |
| 599 | AbiWord / Gnumeric / Calligra | `abw` `gnumeric` `kwd` | — | 3 | `doc.other` | `common` | — | impl | S8 | — |
| 600 | Microsoft Write / Ami Pro / Ichitaro | `wri` `sam` `jtd` | — | 3 | `doc.other` | `common` | — | impl | S8 | — |
| 601 | Marp / reveal.js slide markdown | `md` | — | 3 | `doc.other` | `common` | — | impl | S8 | slide count, titles |
| 602 | Notion / Confluence export bundles | `zip` | — | 3 | `doc.other` | `common` | — | impl | S8 | page tree, titles |
| 603 | TTML / DFXP | `ttml` `dfxp` `xml` | application/ttml+xml | 3 | `text.subtitle` | `common` | — | impl | S8 | — |
| 604 | MicroDVD / SubViewer | `sub` `sbv` | — | 3 | `text.subtitle` | `common` | — | impl | S8 | — |
| 605 | SAMI | `smi` `sami` | — | 3 | `text.subtitle` | `common` | — | impl | S8 | — |
| 606 | LRC lyrics | `lrc` | — | 3 | `text.subtitle` | `common` | — | impl | S8 | ti/ar/al tags |
| 607 | VobSub | `idx` `sub` | — | 3 | `text.subtitle` | `common` | — | impl | S8 | languages, cue count (vobsub) |
| 608 | PGS Blu-ray subtitles | `sup` | — | 3 | `text.subtitle` | `common` | — | impl | S8 | cue count, timings |
| 609 | Scenarist / SCC / STL captions | `scc` `stl` `cap` | — | 3 | `text.subtitle` | `common` | — | impl | S8 | — |
| 610 | YouTube timed text / JSON3 | `srv3` `json3` | — | 3 | `text.subtitle` | `common` | — | impl | S8 | — |
| 611 | Musepack | `mpc` `mp+` `mpp` | audio/musepack | 3 | `audio` | `common` | — | lofty | S4 | — |
| 612 | Speex / Ogg FLAC | `spx` | audio/ogg | 3 | `audio` | `common` | — | lofty | S4 | — |
| 613 | AMR / AMR-WB / 3GA | `amr` `awb` `3ga` | audio/amr | 3 | `audio` | `common` | — | lofty | S4 | — |
| 614 | AC-3 / E-AC-3 / DTS / TrueHD raw | `ac3` `ec3` `eac3` `dts` `thd` `mlp` | audio/ac3 | 3 | `audio` | `common` | — | lofty | S8 | sync frame header: channels, rate, bitrate |
| 615 | MPEG-1/2 Layer I/II | `mp1` `mp2` `mpa` | audio/mpeg | 3 | `audio` | `common` | — | lofty | S4 | — |
| 616 | ADTS AAC raw | `aac` `adts` | audio/aac | 3 | `audio` | `common` | — | lofty | S4 | — |
| 617 | DSD (DSF / DFF) | `dsf` `dff` | audio/dsd | 3 | `audio` | `common` | — | lofty | S4 | — |
| 618 | TTA / OptimFROG / TAK | `tta` `ofr` `tak` | — | 3 | `audio` | `common` | — | lofty | S4 | — |
| 619 | AU / SND | `au` `snd` | audio/basic | 3 | `audio` | `common` | — | lofty | S4 | — |
| 620 | RealAudio | `ra` `ram` | audio/vnd.rn-realaudio | 3 | `audio` | `common` | — | lofty | S4 | — |
| 621 | VOC / 8SVX / IFF audio | `voc` `8svx` | — | 3 | `audio` | `common` | — | lofty | S4 | — |
| 622 | Broadcast Wave / RF64 / W64 | `bwf` `rf64` `w64` | — | 3 | `audio` | `common` | — | lofty | S4 | bext originator, time reference |
| 623 | Matroska audio | `mka` | audio/x-matroska | 3 | `audio` | `common` | — | lofty | S4 | -&gt; video |
| 624 | WebM audio | `weba` | audio/webm | 3 | `audio` | `common` | — | lofty | S4 | — |
| 625 | Audible AA / AAX | `aa` `aax` | — | 3 | `audio` | `common` | — | lofty | S8 | chapters, title, narrator (header only, DRM flag) |
| 626 | GSM / VOX telephony | `gsm` `vox` | — | 3 | `audio` | `common` | — | lofty | S4 | — |
| 627 | SoundFont / DLS | `sf2` `sf3` `dls` | audio/x-soundfont | 3 | `audio` | `common` | — | lofty | S4 | bank name, presets, samples |
| 628 | Sampler / instrument (SFZ, EXS) | `sfz` `exs` | — | 3 | `audio` | `common` | — | lofty | S4 | — |
| 629 | Audio project: Audacity / Ableton / FL / Logic / Reaper | `aup3` `aup` `als` `flp` `logicx` `rpp` | — | 3 | `audio` | `common` | — | lofty | S4 | tracks, tempo, plugins (sqlite/xml/gzip-xml) |
| 630 | Qualcomm PureVoice / ATRAC / Shorten / VQF | `qcp` `oma` `aa3` `shn` `vqf` | — | 3 | `audio` | `common` | — | lofty | S4 | — |
| 631 | DAW sessions (Pro Tools, Cubase, GarageBand) | `ptx` `cpr` `band` | — | 3 | `audio` | `common` | — | lofty | S4 | tracks, tempo |
| 632 | Podcast RSS enclosure-tagged MP3 (chapters ID3 CHAP/CTOC) | `mp3` | — | 3 | `audio` | `common` | — | lofty | S4 | chapters with titles + URLs |
| 633 | MusicXML | `musicxml` `mxl` `xml` | application/vnd.recordare.musicxml+xml | 3 | `audio.score` | `common` | — | midly | S4 | — |
| 634 | MEI / ABC / LilyPond / Guitar Pro / MuseScore | `mei` `abc` `ly` `gp` `gp5` `gpx` `mscz` | — | 3 | `audio.score` | `common` | — | midly | S4 | — |
| 635 | Tracker modules MOD/XM/IT/S3M | `mod` `xm` `it` `s3m` `mptm` | audio/x-mod | 3 | `audio.score` | `common` | — | midly | S4 | — |
| 636 | PLS / XSPF / ASX / WPL | `pls` `xspf` `asx` `wpl` | audio/x-scpls | 3 | `audio.playlist` | `common` | — | m3u8-rs | S4 | — |
| 637 | CUE sheet | `cue` | application/x-cue | 3 | `audio.playlist` | `common` | — | m3u8-rs | S4 | — |
| 638 | DASH manifest | `mpd` | application/dash+xml | 3 | `audio.playlist` | `common` | — | m3u8-rs | S4 | periods, adaptation sets, codecs |
| 639 | Smooth Streaming manifest | `ism` `ismc` | — | 3 | `audio.playlist` | `common` | — | m3u8-rs | S4 | — |
| 640 | Ogg Theora / OGM | `ogv` `ogm` | video/ogg | 3 | `video` | `common` | — | mp4-atom | S4 | — |
| 641 | RealMedia | `rm` `rmvb` | application/vnd.rn-realmedia | 3 | `video` | `common` | — | mp4-atom | S4 | — |
| 642 | DV | `dv` `dif` | video/dv | 3 | `video` | `common` | — | mp4-atom | S4 | — |
| 643 | MXF broadcast | `mxf` | application/mxf | 3 | `video` | `common` | — | mp4-atom | S8 | partition pack, operational pattern, essence descriptors (impl KLV) |
| 644 | Apple ProRes / HEVC in MOV | `mov` | — | 3 | `video` | `common` | — | mp4-atom | S4 | codec profile from sample entry |
| 645 | H.264 / H.265 / AV1 / VVC elementary stream | `h264` `264` `h265` `265` `hevc` `obu` `ivf` `vvc` | video/h264 | 3 | `video` | `common` | — | mp4-atom | S8 | SPS/VPS/sequence header: profile, level, size, fps, bit depth |
| 646 | Motion JPEG / AVCHD / XAVC | `mjpg` `mjpeg` `mts` | — | 3 | `video` | `common` | — | mp4-atom | S4 | — |
| 647 | Blackmagic RAW / RED R3D / ARRIRAW | `braw` `r3d` `ari` | — | 3 | `video` | `common` | — | mp4-atom | S8 | camera, lens, timecode (header) |
| 648 | DivX / Xvid | `divx` `xvid` | — | 3 | `video` | `common` | — | mp4-atom | S4 | -&gt; AVI |
| 649 | Nullsoft NSV / Bink / Smacker | `nsv` `bik` `smk` | — | 3 | `video` | `common` | — | mp4-atom | S4 | — |
| 650 | AMV / MTV / FLIC | `amv` `mtv` `flc` `fli` | — | 3 | `video` | `common` | — | mp4-atom | S4 | — |
| 651 | Video project: Premiere / Final Cut / DaVinci / Kdenlive | `prproj` `fcpxml` `drp` `kdenlive` `mlt` | — | 3 | `video` | `common` | — | mp4-atom | S4 | clips, timeline length (gzip-xml/xml) |
| 652 | EDL / AAF / OTIO edit lists | `edl` `aaf` `otio` | — | 3 | `video` | `common` | — | mp4-atom | S4 | events, reel names, timecodes |
| 653 | Apple Live Photo / Motion Photo | `mov` `jpg` | — | 3 | `video` | `common` | — | mp4-atom | S4 | paired-asset XMP (GCamera/Container) |
| 654 | 360 / spatial video metadata | `mp4` `mov` | — | 3 | `video` | `common` | — | mp4-atom | S4 | sv3d/st3d boxes, Spherical XMP |
| 655 | Dashcam / drone telemetry tracks | `mp4` `mov` | — | 3 | `video` | `common` | — | mp4-atom | S4 | GPMF (GoPro), DJI SRT/klv -&gt; GPS track |
| 656 | Animated GIF video replacement (GIFV) | `gifv` | — | 3 | `video` | `common` | — | mp4-atom | S4 | -&gt; MP4 |
| 657 | Screen recording (asciinema) | `cast` | — | 3 | `video` | `common` | — | mp4-atom | S4 | width, height, duration, command |
| 658 | Video subtitles container | `mks` | — | 3 | `video` | `common` | — | mp4-atom | S4 | -&gt; video |
| 659 | Windows Media Center / TiVo recordings | `wtv` `dvr-ms` `tivo` | — | 3 | `video` | `common` | — | mp4-atom | S4 | program title, channel, air date |
| 660 | 360 camera native (INSV / OSV) | `insv` `osv` | — | 3 | `video` | `common` | — | mp4-atom | S4 | camera, GPS |
| 661 | Raw video Y4M / YUV | `y4m` `yuv` | — | 3 | `video` | `common` | — | mp4-atom | S8 | WxH, fps, colourspace (Y4M header) |
| 662 | CMAF / fragmented segments | `cmfv` `cmfa` `m4s` | — | 3 | `video` | `common` | — | mp4-atom | S4 | track ids, fragments |
| 663 | Video with embedded captions (CEA-608/708 in SEI) | `mp4` `ts` | — | 3 | `video` | `common` | — | mp4-atom | S4 | caption presence + language |
| 664 | LHA / LZH | `lzh` `lha` | application/x-lzh-compressed | 3 | `archive` | `common` | — | zip, tar | S5 | — |
| 665 | ARJ | `arj` | application/x-arj | 3 | `archive` | `common` | — | zip, tar | S5 | — |
| 666 | CPIO | `cpio` | application/x-cpio | 3 | `archive` | `common` | — | zip, tar | S5 | newc/odc/bin |
| 667 | Unix ar | `a` `ar` | application/x-archive | 3 | `archive` | `common` | — | zip, tar | S5 | -&gt; also static libraries (exec members) |
| 668 | ACE / ZOO / ARC / PAK (DOS) | `ace` `zoo` `arc` `pak` | — | 3 | `archive` | `common` | — | zip, tar | S8 | headers only |
| 669 | StuffIt | `sit` `sitx` | application/x-stuffit | 3 | `archive` | `common` | — | zip, tar | S8 | header only |
| 670 | WIM Windows imaging | `wim` `swm` `esd` | application/x-ms-wim | 3 | `archive` | `common` | — | zip, tar | S5 | images + XML metadata |
| 671 | XAR | `xar` `pkg` | application/x-xar | 3 | `archive` | `common` | — | zip, tar | S5 | TOC XML |
| 672 | Split / multipart archives | `001` `z01` `r00` `part1.rar` | — | 3 | `archive` | `common` | — | zip, tar | S5 | volume detection |
| 673 | Shell archive (shar) / makeself | `shar` `run` | — | 3 | `archive` | `common` | — | zip, tar | S5 | — |
| 674 | Java/Android archive (generic zip) | `jar` `war` `ear` `aar` | application/java-archive | 3 | `archive` | `common` | — | zip, tar | S5 | -&gt; package |
| 675 | Squashfs | `squashfs` `sqsh` `sfs` | application/vnd.squashfs | 3 | `archive` | `common` | — | zip, tar | S5 | -&gt; disk |
| 676 | PEA / ZPAQ / KGB | `pea` `zpaq` `kgb` | — | 3 | `archive` | `common` | — | zip, tar | S8 | headers only |
| 677 | Apple Archive / AAR | `aar` | — | 3 | `archive` | `common` | — | zip, tar | S5 | — |
| 678 | Bundle formats: .app/.framework zipped | `ipa` | — | 3 | `archive` | `common` | — | zip, tar | S5 | -&gt; package |
| 679 | Self-extracting archives (SFX) | `exe` | — | 3 | `archive` | `common` | — | zip, tar | S5 | embedded zip/rar/7z offset, then archive listing |
| 680 | Windows installers (NSIS / Inno Setup / InstallShield / WiX burn) | `exe` | — | 3 | `archive` | `common` | — | zip, tar | S8 | installer type, product name, version, files (NSIS/Inno headers) |
| 681 | Python zipapp / PEX | `pyz` `pex` | — | 3 | `archive` | `common` | — | zip, tar | S5 | __main__, PEX-INFO |
| 682 | Java JMOD / JIMAGE | `jmod` | — | 3 | `archive` | `common` | — | zip, tar | S5 | module-info |
| 683 | Android OBB | `obb` | — | 3 | `archive` | `common` | — | zip, tar | S5 | — |
| 684 | ALZip / EGG | `alz` `egg` | — | 3 | `archive` | `common` | — | zip, tar | S5 | — |
| 685 | Unix dump / restore | `dump` | — | 3 | `archive` | `common` | — | zip, tar | S5 | — |
| 686 | BinHex / MacBinary / AppleSingle / AppleDouble | `hqx` `bin` `as` `._*` | — | 3 | `archive` | `common` | — | zip, tar | S5 | finder info, resource fork types, xattrs |
| 687 | uuencode / base64 / yEnc wrappers | `uue` `b64` `yenc` | — | 3 | `archive` | `common` | — | zip, tar | S5 | decoded filename, recurse |
| 688 | Backup repositories (restic / borg / duplicity) | `config` `README` | — | 3 | `archive` | `common` | — | zip, tar | S5 | repo version, encryption |
| 689 | Android backup | `ab` | — | 3 | `archive` | `common` | — | zip, tar | S5 | version, compressed, encrypted |
| 690 | ZIP-based OCI / Docker save archive | `tar` | — | 3 | `archive` | `common` | — | zip, tar | S5 | -&gt; package |
| 691 | LZMA (alone) | `lzma` | application/x-lzma | 3 | `compress` | `common` | — | flate2 | S5 | — |
| 692 | LZ4 | `lz4` | application/x-lz4 | 3 | `compress` | `common` | — | flate2 | S5 | — |
| 693 | Brotli | `br` | application/x-brotli | 3 | `compress` | `common` | — | flate2 | S5 | — |
| 694 | Unix compress (.Z) | `Z` `taz` | application/x-compress | 3 | `compress` | `common` | — | flate2 | S5 | — |
| 695 | lzip / lzop | `lz` `lzo` | application/x-lzip | 3 | `compress` | `common` | — | flate2 | S5 | — |
| 696 | Snappy framed | `sz` `snappy` | — | 3 | `compress` | `common` | — | flate2 | S5 | — |
| 697 | LZFSE / Apple | `lzfse` | — | 3 | `compress` | `common` | — | flate2 | S5 | — |
| 698 | zlib raw stream | `zz` `zlib` | — | 3 | `compress` | `common` | — | flate2 | S5 | — |
| 699 | pack / compact / freeze (legacy) | `z` | — | 3 | `compress` | `common` | — | flate2 | S5 | — |
| 700 | NuGet package | `nupkg` `snupkg` | application/zip | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | .nuspec |
| 701 | Ruby gem | `gem` | application/x-tar | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | metadata.gz (YAML) |
| 702 | Rust crate | `crate` | application/gzip | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | Cargo.toml inside |
| 703 | Snap / Flatpak / AppImage | `snap` `flatpak` `flatpakref` `AppImage` | — | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | snap.yaml, flatpak metadata, ELF + squashfs desktop file |
| 704 | Arch / Alpine packages | `pkg.tar.zst` `apk` | application/x-tar | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | .PKGINFO |
| 705 | Conda package | `conda` `tar.bz2` | application/zip | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | info/index.json |
| 706 | Chrome / Firefox extension | `crx` `xpi` | application/x-chrome-extension | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | manifest.json permissions |
| 707 | VS Code extension / JetBrains plugin | `vsix` | application/zip | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | package.json / plugin.xml |
| 708 | Helm chart archive | `tgz` | — | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | Chart.yaml |
| 709 | Docker / OCI image tarball | `tar` | — | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | manifest.json, config: layers, env, entrypoint, labels |
| 710 | OCI layout / ORAS artifact | `oci-layout` | — | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | — |
| 711 | Windows CAB update / MSU | `msu` | — | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | — |
| 712 | Solaris / BSD / Slackware packages | `pkg` `txz` `tgz` | — | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | — |
| 713 | Haiku / Homebrew bottle | `hpkg` `bottle.tar.gz` | — | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | — |
| 714 | Unity package | `unitypackage` | — | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | asset paths |
| 715 | Office add-in / VBA add-in | `xla` `ppa` | — | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S5 | -&gt; doc.ole |
| 716 | Electron asar | `asar` | — | 3 | `package` | `common` | — | rpm, apk-info + axmldecoder | S8 | header JSON file list |
| 717 | Raw disk image | `img` `raw` `dd` `bin` | application/octet-stream | 3 | `disk` | `forensics` | — | gpt, mbrman | S5 | MBR/GPT |
| 718 | VirtualBox VDI | `vdi` | application/x-virtualbox-vdi | 3 | `disk` | `forensics` | — | gpt, mbrman | S5 | — |
| 719 | VMware VMDK | `vmdk` | application/x-vmdk | 3 | `disk` | `forensics` | — | gpt, mbrman | S5 | descriptor, extents |
| 720 | Hyper-V VHD / VHDX | `vhd` `vhdx` | application/x-vhd | 3 | `disk` | `forensics` | — | gpt, mbrman | S5 | — |
| 721 | QEMU QCOW2 / QED | `qcow` `qcow2` `qed` | application/x-qemu-disk | 3 | `disk` | `forensics` | — | gpt, mbrman | S5 | — |
| 722 | Apple sparsebundle / sparseimage | `sparseimage` `sparsebundle` | — | 3 | `disk` | `forensics` | — | gpt, mbrman | S5 | — |
| 723 | Expert Witness (E01) / AFF | `e01` `ex01` `aff` | — | 3 | `disk` | `forensics` | — | gpt, mbrman | S5 | case metadata, acquisition hashes |
| 724 | CD images BIN/CUE, NRG, MDF, CCD | `bin` `nrg` `mdf` `mds` `ccd` | — | 3 | `disk` | `forensics` | — | gpt, mbrman | S5 | tracks |
| 725 | Floppy images | `ima` `dsk` `adf` `d64` `st` | — | 3 | `disk` | `forensics` | — | gpt, mbrman | S5 | filesystem label |
| 726 | Filesystem images ext/FAT/NTFS/APFS/HFS+ | `ext4` `fat` `hfs` `apfs` | — | 3 | `disk` | `forensics` | — | gpt, mbrman | S5 | superblock |
| 727 | Android sparse / boot image | `simg` `boot.img` | — | 3 | `disk` | `forensics` | — | gpt, mbrman | S5 | kernel cmdline, os version |
| 728 | Firmware images (UEFI capsule, U-Boot uImage, FIT, Intel HEX, S-record) | `cap` `uimg` `itb` `hex` `srec` `s19` | — | 3 | `disk` | `forensics` | — | gpt, mbrman | S8 | header fields |
| 729 | OVA / OVF virtual appliance | `ova` `ovf` | — | 3 | `disk` | `forensics` | — | gpt, mbrman | S5 | product, vendor, disks |
| 730 | Apple sparse disk image (UDIF variants: UDZO/ULFO/UDRW) | `dmg` | — | 3 | `disk` | `forensics` | — | gpt, mbrman | S5 | compression type, partition names |
| 731 | Protobuf text format | `textproto` `pbtxt` `txtpb` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 732 | Avro schema | `avsc` | application/json | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 733 | Apache Thrift schema | `thrift` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 734 | Cap'n Proto schema | `capnp` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 735 | FlatBuffers schema / binary | `fbs` `bfbs` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 736 | Bencode | `bencode` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 737 | Python pickle | `pkl` `pickle` | application/x-python-pickle | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | opcode walk only (never unpickle!), referenced globals (risk) |
| 738 | Java serialized object | `ser` | application/x-java-serialized-object | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | class names (gadget risk flag) |
| 739 | PHP serialized | `phpser` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 740 | Ion (Amazon) | `ion` | application/ion | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 741 | Smile / UBJSON | `sml` `ubj` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 742 | RON | `ron` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 743 | KDL | `kdl` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 744 | HOCON | `conf` `hocon` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 745 | Dhall / Jsonnet / CUE | `dhall` `jsonnet` `libsonnet` `cue` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 746 | EDN | `edn` | application/edn | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 747 | S-expressions data | `sexp` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 748 | ASN.1 BER/DER blob | `der` `ber` | application/octet-stream | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | tag tree (asn1-rs) |
| 749 | XDR | `xdr` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 750 | NBT (Minecraft) | `nbt` `dat` | application/x-minecraft-nbt | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 751 | Godot resource | `tres` `res` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | — |
| 752 | Unity YAML asset | `unity` `prefab` `asset` `meta` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | GUIDs, component types |
| 753 | Java .properties-like binary: Android resources.arsc | `arsc` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | packages, string pool size |
| 754 | Android binary XML | `xml` `(binary)` | — | 3 | `data.binser` | `common` | — | rmp-serde, ciborium | S6 | decoded via axmldecoder -&gt; text.xml |
| 755 | ELF core dump | `core` | application/x-coredump | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | signal, process name, threads |
| 756 | Windows minidump | `dmp` `mdmp` | application/x-dmp | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | -&gt; forensic |
| 757 | MS-DOS / NE / LE executables | `com` `exe` | — | 3 | `exec` | `common` | — | goblin / object, gimli | S8 | header only |
| 758 | PDB debug database | `pdb` | application/x-ms-pdb | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | GUID, age, modules |
| 759 | DWARF split / dSYM | `dwo` `dwp` `dSYM` | — | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | compile units, producers |
| 760 | Linux kernel image / initramfs | `vmlinuz` `bzImage` `initrd` | — | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | version string |
| 761 | eBPF object | `bpf.o` | — | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | programs, maps |
| 762 | Android ART / OAT / ODEX | `oat` `odex` `vdex` `art` | — | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | — |
| 763 | Windows driver package / CAT | `cat` | — | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | signed catalog hashes count |
| 764 | Rust rlib / rmeta | `rlib` `rmeta` | — | 3 | `exec` | `common` | — | goblin / object, gimli | S8 | crate name, rustc version (rustc metadata header) |
| 765 | Go binary buildinfo | `(ELF/PE/Mach-O)` | — | 3 | `exec` | `common` | — | goblin / object, gimli | S8 | module path, deps, Go version (impl buildinfo parser) |
| 766 | PyInstaller / py2exe bundle | `exe` `(ELF)` | — | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | archive cookie, Python version, bundled modules |
| 767 | Windows script hosts (HTA, WSF, SCT, WSC) | `hta` `wsf` `sct` `wsc` | application/hta | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | script languages, external refs (risk) |
| 768 | AppleScript compiled | `scpt` `scptd` | — | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | — |
| 769 | AIX XCOFF | `xcoff` | — | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | — |
| 770 | Device tree blob / source | `dtb` `dtbo` `dts` | — | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | model, compatible, nodes |
| 771 | FPGA bitstream (Xilinx .bit) | `bit` `bin` | — | 3 | `exec` | `common` | — | goblin / object, gimli | S6 | design name, part, date, time |
| 772 | Lua bytecode / LuaJIT | `luac` | — | 3 | `bytecode` | `common` | — | classfile-parser, dex | S6 | — |
| 773 | Erlang BEAM | `beam` | — | 3 | `bytecode` | `common` | — | classfile-parser, dex | S6 | module, exports, attributes |
| 774 | Hermes / V8 snapshot / QuickJS | `hbc` `bin` | — | 3 | `bytecode` | `common` | — | classfile-parser, dex | S6 | — |
| 775 | Emacs / Guile compiled | `elc` `go` | — | 3 | `bytecode` | `common` | — | classfile-parser, dex | S6 | — |
| 776 | Ruby YARV / mruby | `mrb` | — | 3 | `bytecode` | `common` | — | classfile-parser, dex | S6 | — |
| 777 | OCaml / Haskell interface | `cmi` `cmo` `hi` | — | 3 | `bytecode` | `common` | — | classfile-parser, dex | S6 | — |
| 778 | Smalltalk image / Pharo | `image` `changes` | — | 3 | `bytecode` | `common` | — | classfile-parser, dex | S6 | — |
| 779 | Flash ActionScript ABC | `abc` | — | 3 | `bytecode` | `common` | — | classfile-parser, dex | S6 | -&gt; web.misc SWF |
| 780 | PKCS#7 / CMS signed data | `p7b` `p7c` `p7s` `p7m` | application/pkcs7-mime | 3 | `crypto` | `common` | — | x509-parser, pem | S6 | signers, certs |
| 781 | Certificate signing request | `csr` `req` | application/pkcs10 | 3 | `crypto` | `common` | — | x509-parser, pem | S6 | — |
| 782 | Certificate revocation list | `crl` | application/pkix-crl | 3 | `crypto` | `common` | — | x509-parser, pem | S6 | issuer, entries, next update |
| 783 | Java KeyStore / BKS | `jks` `bks` `keystore` | application/x-java-keystore | 3 | `crypto` | `common` | — | x509-parser, pem | S6 | aliases, entry types |
| 784 | JSON Web Key / JWT / JWS | `jwk` `jwks` `jwt` | — | 3 | `crypto` | `common` | — | x509-parser, pem | S8 | header + claims, sig unverified |
| 785 | age / minisign / signify | `age` `minisig` `sig` | — | 3 | `crypto` | `common` | — | x509-parser, pem | S6 | recipients/key ids |
| 786 | KeePass / password vault | `kdbx` `kdb` `1pif` | — | 3 | `crypto` | `common` | — | x509-parser, pem | S8 | header only: cipher, KDF (never decrypt) |
| 787 | TPM / FIDO / misc keys | `tss` | — | 3 | `crypto` | `common` | — | x509-parser, pem | S6 | — |
| 788 | Encrypted container (VeraCrypt/LUKS/BitLocker header) | `hc` `luks` `bek` | — | 3 | `crypto` | `common` | — | x509-parser, pem | S8 | header: cipher, version, UUID (LUKS) |
| 789 | S/MIME email | `p7m` | — | 3 | `crypto` | `common` | — | x509-parser, pem | S6 | -&gt; email |
| 790 | Apple signed artifacts (.mobileprovision) | `mobileprovision` `provisionprofile` | — | 3 | `crypto` | `common` | — | x509-parser, pem | S6 | -&gt; apple |
| 791 | Authenticode detached signature / catalog | `cat` | — | 3 | `crypto` | `common` | — | x509-parser, pem | S6 | — |
| 792 | Kerberos keytab | `keytab` | — | 3 | `crypto` | `common` | — | x509-parser, pem | S6 | principals, enctypes, kvno (no keys) |
| 793 | TLS key log | `keylog` `sslkeylog` | — | 3 | `crypto` | `common` | — | x509-parser, pem | S6 | line count only (secrets never output) |
| 794 | SQLite WAL / journal | `db-wal` `db-shm` `db-journal` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | frames, salts |
| 795 | Microsoft Access | `mdb` `accdb` | application/vnd.ms-access | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | Jet/ACE version, table names (impl) |
| 796 | dBase / FoxPro DBF | `dbf` | application/dbase | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | — |
| 797 | DuckDB database | `duckdb` `ddb` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | header version |
| 798 | LMDB / Berkeley DB | `mdb` `db` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | page size, entries |
| 799 | LevelDB / RocksDB SST & logs | `ldb` `sst` `log` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | table properties (RocksDB properties block) |
| 800 | Realm / Firebird / H2 / HSQLDB | `realm` `fdb` `gdb` `mv.db` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | header |
| 801 | Microsoft SQL Server backup / MDF | `bak` `mdf` `ldf` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | header: database name, version |
| 802 | PostgreSQL custom dump | `dump` `backup` | application/octet-stream | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | pg_dump header: db name, version, TOC entries |
| 803 | MySQL / MariaDB table files | `frm` `ibd` `myd` `myi` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | — |
| 804 | Browser profile databases (History, Cookies, Places) | `sqlite` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | known schema -&gt; summary (counts, date range; no URLs by default) |
| 805 | Apple Core Data / Photos library | `sqlite` `photoslibrary` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | — |
| 806 | Redis RDB / AOF | `rdb` `aof` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | version, key count estimate |
| 807 | MongoDB dump (BSON dir) | `bson` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | -&gt; data.binser |
| 808 | Mobile backups (iTunes Manifest.db / Android .ab) | `db` `ab` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | — |
| 809 | Adobe Lightroom catalog | `lrcat` `lrdata` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | image count, collections, keywords (SQLite) |
| 810 | Anki deck | `apkg` `colpkg` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | decks, note/card counts |
| 811 | Windows ESE database | `edb` `dat` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | tables (SRUM, WebCache, Windows Search) -&gt; forensic |
| 812 | Kafka log segment | `log` `index` `timeindex` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | base offset, record batches |
| 813 | Prometheus TSDB block | `meta.json` `chunks` | — | 3 | `db` | `common` | — | impl SQLite b-tree reader for sqlite_schema | S8 | time range, series count |
| 814 | Windows Event Log | `evtx` `evt` | application/x-ms-evtx | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | — |
| 815 | Windows Registry hive | `dat` `hiv` `NTUSER.DAT` `SYSTEM` `SOFTWARE` `SAM` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | — |
| 816 | Windows Prefetch | `pf` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | exe name, run count, last run times |
| 817 | NTFS $MFT / $UsnJrnl | `mft` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | — |
| 818 | Windows minidump | `dmp` `mdmp` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | — |
| 819 | Linux utmp/wtmp/btmp / journal | `wtmp` `btmp` `journal` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | — |
| 820 | macOS unified log / ASL | `tracev3` `asl` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | — |
| 821 | Jump lists / recycle bin ($I) | `automaticDestinations-ms` `customDestinations-ms` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | — |
| 822 | Zeek / Suricata / Whiff logs | `log` `json` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | — |
| 823 | NetFlow / IPFIX dumps | `nfcapd` `ipfix` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | — |
| 824 | Syslog / journal export | `log` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | -&gt; text.plain log detector |
| 825 | Crash reports (.ips, .crash, Breakpad) | `ips` `crash` `dmp` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | app, version, exception, frames |
| 826 | Snort unified2 alerts | `u2` `unified2` | application/octet-stream | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | alert count, sig ids, time range |
| 827 | Windows ETW trace | `etl` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | provider GUIDs, events count |
| 828 | macOS FSEvents | `fseventsd` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | records, path count |
| 829 | Memory image (LiME / crash dump / hiberfil) | `lime` `dmp` `hiberfil.sys` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | OS hints, size, profile |
| 830 | Browser cache entries | `data_0` `cache2` `f_000001` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | URLs count, content types |
| 831 | Windows Timeline / SRUM / Amcache | `db` `hve` `dat` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | -&gt; db / registry |
| 832 | Kubernetes / cloud audit logs | `jsonl` `log` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | verbs, resources, users count |
| 833 | Sysmon / auditd logs | `log` `evtx` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | event types histogram |
| 834 | Wireshark dissector-free: Bluetooth btsnoop / USB pcap | `btsnoop` `log` | — | 3 | `forensic` | `forensics` | — | pcap-file / pcap-parser, evtx | S6/S8 | packet count, time range |
| 835 | Apple .strings / .stringsdict / .xcstrings | `strings` `stringsdict` `xcstrings` | — | 3 | `apple` | `common` | — | plist, cms | S6 | — |
| 836 | .DS_Store | `DS_Store` | — | 3 | `apple` | `common` | — | plist, cms | S6 | — |
| 837 | Xcode project / workspace | `pbxproj` `xcworkspacedata` | — | 3 | `apple` | `common` | — | plist, cms | S6 | targets, build settings |
| 838 | Apple asset catalog compiled | `car` | — | 3 | `apple` | `common` | — | plist, cms | S6 | — |
| 839 | Apple Shortcuts / Automator | `shortcut` `workflow` | — | 3 | `apple` | `common` | — | plist, cms | S6 | actions |
| 840 | macOS alias / bookmark data | `alias` | — | 3 | `apple` | `common` | — | plist, cms | S6 | target path |
| 841 | Apple configuration profile | `mobileconfig` | — | 3 | `apple` | `common` | — | plist, cms | S6 | payload types (CMS-signed) |
| 842 | Apple Watch face / Siri / misc plists | `watchface` | — | 3 | `apple` | `common` | — | plist, cms | S6 | — |
| 843 | iOS backup Info.plist / Manifest.plist | `plist` | — | 3 | `apple` | `common` | — | plist, cms | S6 | device, iOS version |
| 844 | AppleDouble resource forks / xattr dumps | `._*` | — | 3 | `apple` | `common` | — | plist, cms | S6 | -&gt; archive |
| 845 | Apache ORC | `orc` | application/x-orc | 3 | `columnar` | `data` | — | parquet + arrow | S7 | — |
| 846 | Lance | `lance` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | feature-gated |
| 847 | Vortex | `vortex` `vtx` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | feature-gated |
| 848 | Delta Lake / Iceberg table metadata | `_delta_log/*.json` `metadata.json` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | — |
| 849 | GeoParquet | `parquet` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | geo metadata -&gt; geo |
| 850 | Apache Hudi / Kudu / CarbonData | `hoodie` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | — |
| 851 | Spark / Hadoop SequenceFile / RCFile | `seq` `rc` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | key/value classes, codec |
| 852 | Excel-like DataFrame pickles (pandas .pkl) | `pkl` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | -&gt; data.binser (never unpickle) |
| 853 | Feather v1 / R fst / qs | `fst` `qs` | — | 3 | `columnar` | `data` | — | parquet + arrow | S8 | header |
| 854 | TFRecord / RecordIO | `tfrecord` `tfrec` `rec` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | record count, feature keys (protobuf Example) |
| 855 | Safetensors | `safetensors` | — | 3 | `columnar` | `data` | — | parquet + arrow | S8 | tensor names, dtypes, shapes, __metadata__ (header JSON) |
| 856 | GGUF / GGML model | `gguf` `ggml` `bin` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | architecture, params, quantisation, context length, tokenizer, tensor count |
| 857 | ONNX model | `onnx` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | opset, producer, graph inputs/outputs, op histogram (protobuf) |
| 858 | PyTorch checkpoint | `pt` `pth` `ckpt` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | zip + pickle opcode walk (no unpickle), tensor list |
| 859 | Keras / TensorFlow SavedModel / TFLite | `keras` `h5` `pb` `tflite` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | -&gt; sci (HDF5) / protobuf / flatbuffer |
| 860 | Core ML / MLX / NumPy-weights | `mlmodel` `mlpackage` `npz` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | — |
| 861 | LanceDB / Chroma vector stores | `lance` `sqlite3` | — | 3 | `columnar` | `data` | — | parquet + arrow | S7 | collections, embedding dims |
| 862 | FITS | `fits` `fit` `fts` | application/fits | 3 | `sci` | `science` | — | hdf5-reader | S7 | — |
| 863 | Zarr | `zarr` `.zarray` `.zattrs` `zarr.json` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | — |
| 864 | GRIB 1/2 | `grb` `grib` `grb2` `grib2` | application/x-grib | 3 | `sci` | `science` | — | hdf5-reader | S7 | — |
| 865 | HDF4 / HDF-EOS | `hdf` `hdf4` `he4` | — | 3 | `sci` | `science` | — | hdf5-reader | S8 | header |
| 866 | SPSS data | `sav` `zsav` `por` | application/x-spss-sav | 3 | `sci` | `science` | — | hdf5-reader | S7 | — |
| 867 | Stata data | `dta` | application/x-stata-dta | 3 | `sci` | `science` | — | hdf5-reader | S7 | — |
| 868 | SAS dataset / transport | `sas7bdat` `xpt` | application/x-sas | 3 | `sci` | `science` | — | hdf5-reader | S7 | — |
| 869 | R data | `rds` `rdata` `rda` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | serialization version, object type |
| 870 | Excel-free stats: JMP / Minitab | `jmp` `mtw` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | — |
| 871 | ROOT (CERN) | `root` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | keys/trees |
| 872 | PDB / mmCIF / MOL / SDF chemistry | `pdb` `cif` `mmcif` `mol` `sdf` `mol2` `xyz` | chemical/x-pdb | 3 | `sci` | `science` | — | hdf5-reader | S7 | title, compound, atom counts, formula |
| 873 | FASTA / FASTQ / SAM / BAM / VCF / BED / GFF genomics | `fa` `fasta` `fq` `fastq` `sam` `bam` `cram` `vcf` `bcf` `bed` `gff` `gtf` | text/x-fasta | 3 | `sci` | `science` | — | hdf5-reader | S7 | sequence count, lengths, read count, reference, samples |
| 874 | mzML / mzXML mass spectrometry | `mzml` `mzxml` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | instrument, spectra count |
| 875 | EDF / BDF / BrainVision (EEG) | `edf` `bdf` `vhdr` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | channels, sampling rate, duration (patient REDACTED) |
| 876 | Gaussian / ORCA / CP2K outputs | `log` `out` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | — |
| 877 | SPICE / Touchstone / LTspice | `cir` `sp` `s2p` `asc` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | — |
| 878 | Origin / Igor / LabVIEW / TDMS | `opj` `ibw` `pxp` `tdms` `vi` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | — |
| 879 | ENVI / ERDAS / PCIDSK rasters | `hdr` `img` `pix` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | -&gt; geo |
| 880 | Wolfram / Maple / Mathcad files | `mx` `mw` `xmcd` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | — |
| 881 | Bruker / Varian NMR / microscopy (CZI, ND2, LIF, OME-TIFF) | `czi` `nd2` `lif` `ome.tif` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | instrument, channels, dims |
| 882 | VCD waveform | `vcd` `fst` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | timescale, signals, end time, scope tree |
| 883 | Sigrok session | `sr` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | channels, samplerate |
| 884 | IBIS / Liberty / LEF/DEF | `ibs` `lib` `lef` `def` | — | 3 | `sci` | `science` | — | hdf5-reader | S7 | component/cell names |
| 885 | NIfTI-1 / NIfTI-2 | `nii` `nii.gz` | application/x-nifti | 3 | `medical` | `science` | — | dicom-object, nifti | S7 | — |
| 886 | Analyze 7.5 | `hdr` `img` | — | 3 | `medical` | `science` | — | dicom-object, nifti | S7 | — |
| 887 | MINC / NRRD / MetaImage | `mnc` `nrrd` `nhdr` `mha` `mhd` | — | 3 | `medical` | `science` | — | dicom-object, nifti | S7 | — |
| 888 | HL7 v2 message / FHIR JSON | `hl7` `fhir.json` | — | 3 | `medical` | `science` | — | dicom-object, nifti | S7 | message type, segments (PHI REDACTED) |
| 889 | SCP-ECG / aECG | `scp` | — | 3 | `medical` | `science` | — | dicom-object, nifti | S7 | — |
| 890 | FlatGeobuf | `fgb` | application/vnd.flatgeobuf | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 891 | GeoParquet | `parquet` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 892 | LAS / LAZ point cloud | `las` `laz` | application/vnd.las | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 893 | E57 point cloud | `e57` | model/e57 | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 894 | OpenStreetMap PBF / XML | `osm.pbf` `osm` | application/x-osm+xml | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 895 | MBTiles / PMTiles | `mbtiles` `pmtiles` | application/vnd.mapbox-vector-tile | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | tileset name, bounds, zoom range, format |
| 896 | Mapbox Vector Tile | `mvt` `pbf` | application/vnd.mapbox-vector-tile | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | layers, feature counts |
| 897 | TopoJSON | `topojson` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 898 | WKT / WKB / EWKB | `wkt` `wkb` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | geometry type, SRID |
| 899 | GML / CityGML | `gml` | application/gml+xml | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 900 | MapInfo TAB / MIF | `tab` `mif` `mid` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 901 | Esri File Geodatabase / Personal GDB | `gdb` `mdb` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S8 | header / table list |
| 902 | DTED / SRTM HGT / ASC grid | `dt0` `dt1` `dt2` `hgt` `asc` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | tile extent, resolution |
| 903 | Garmin FIT | `fit` | application/vnd.ant.fit | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | sport, start time, distance, device (GPS track bbox) |
| 904 | TCX / IGC / NMEA logs | `tcx` `igc` `nmea` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 905 | GeoJSON-seq / NDGeoJSON | `geojsons` `geojsonl` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 906 | CSV with coordinates (WKT/lat-lon columns) | `csv` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | -&gt; data.csv + geo detection |
| 907 | ESRI ASCII / Grid / ArcInfo coverage | `adf` `e00` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 908 | QGIS / ArcGIS project | `qgs` `qgz` `aprx` `mxd` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | layers, CRS |
| 909 | COPC / EPT point cloud index | `copc.laz` `ept.json` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 910 | S-57 / S-101 nautical charts | `000` `s57` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 911 | NetCDF-CF / Zarr geodata | `nc` `zarr` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | -&gt; sci |
| 912 | OGC 3D Tiles / I3S | `b3dm` `i3dm` `pnts` `slpk` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 913 | CZML / world file / .prj | `czml` `tfw` `jgw` `pgw` `wld` `prj` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | CRS WKT, affine transform |
| 914 | MrSID / ECW rasters | `sid` `ecw` `jp2` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S8 | header: size, bands, CRS |
| 915 | OSM change / diff | `osc` `osc.gz` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | create/modify/delete counts |
| 916 | Map styles (Mapbox style JSON / SLD / lyrx) | `style.json` `sld` `lyrx` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | layers, sources |
| 917 | Geocaching LOC / GeoRSS | `loc` `georss` | — | 3 | `geo` | `geo` | — | geojson, shapefile | S7 | — |
| 918 | PLY | `ply` | model/ply | 3 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 919 | Collada DAE | `dae` | model/vnd.collada+xml | 3 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 920 | Blender | `blend` | application/x-blender | 3 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 921 | USD / USDZ / USDA / USDC | `usd` `usda` `usdc` `usdz` | model/vnd.usdz+zip | 3 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 922 | 3D Manufacturing Format | `3mf` | model/3mf | 3 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 923 | Autodesk 3DS / MAX | `3ds` `max` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | chunks; MAX = OLE summary |
| 924 | X3D / VRML | `x3d` `wrl` `vrml` | model/x3d+xml | 3 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 925 | Alembic | `abc` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 926 | MagicaVoxel / Qubicle | `vox` `qb` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 927 | Point cloud PCD / XYZ / PTS | `pcd` `xyz` `pts` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 928 | OFF / AMF / Stanford | `off` `amf` | application/x-amf | 3 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 929 | Maya / Cinema 4D / Houdini / Modo | `ma` `mb` `c4d` `hip` `lxo` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | ma (text): requires, scene info |
| 930 | SketchUp | `skp` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | version, thumbnail |
| 931 | Unreal / Unity scene & package | `umap` `uasset` `unity` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | -&gt; game |
| 932 | MikuMikuDance / Valve models | `pmx` `pmd` `mdl` `smd` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 933 | Gaussian splat | `splat` `ksplat` `spz` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | point count |
| 934 | 3D printing G-code | `gcode` `gco` `nc` | text/x-gcode | 3 | `3d` | `cad` | — | gltf, tobj | S7 | slicer, print time, filament, layer count |
| 935 | Draco compressed mesh | `drc` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | points, faces, attributes |
| 936 | OpenVDB volume | `vdb` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | grids, voxel counts, bbox |
| 937 | Houdini bgeo / Substance / MaterialX | `bgeo` `sbsar` `sbs` `mtlx` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | — |
| 938 | LDraw brick models | `ldr` `mpd` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | parts count, author |
| 939 | VRM avatar | `vrm` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | glTF + VRM meta: title, author, licence, allowed usage (rights) |
| 940 | Motion capture BVH / C3D | `bvh` `c3d` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | joints, frames, frame rate |
| 941 | IES photometric | `ies` `ldt` | — | 3 | `3d` | `cad` | — | gltf, tobj | S7 | manufacturer, luminaire, lumens |
| 942 | IGES | `igs` `iges` | model/iges | 3 | `cad` | `cad` | — | dxf | S7 | — |
| 943 | Parasolid / ACIS | `x_t` `x_b` `sat` `sab` | — | 3 | `cad` | `cad` | — | dxf | S8 | header |
| 944 | SolidWorks / Inventor / Creo / CATIA / NX | `sldprt` `sldasm` `ipt` `iam` `prt` `asm` `catpart` `catproduct` | — | 3 | `cad` | `cad` | — | dxf | S7 | OLE/zip summary info, version |
| 945 | Fusion 360 / Onshape exports | `f3d` `f3z` | — | 3 | `cad` | `cad` | — | dxf | S7 | — |
| 946 | Revit | `rvt` `rfa` | — | 3 | `cad` | `cad` | — | dxf | S7 | OLE BasicFileInfo stream: version, path |
| 947 | MicroStation DGN | `dgn` | — | 3 | `cad` | `cad` | — | dxf | S7 | — |
| 948 | Gerber / Excellon PCB | `gbr` `ger` `gtl` `gbl` `drl` `xln` | — | 3 | `cad` | `cad` | — | dxf | S7 | — |
| 949 | KiCad / Eagle / Altium | `kicad_pcb` `kicad_sch` `brd` `sch` `pcbdoc` `schdoc` | — | 3 | `cad` | `cad` | — | dxf | S7 | title block, nets, components count |
| 950 | OpenSCAD / FreeCAD | `scad` `fcstd` | — | 3 | `cad` | `cad` | — | dxf | S7 | — |
| 951 | JT / 3D PDF (PRC/U3D) | `jt` `prc` `u3d` | — | 3 | `cad` | `cad` | — | dxf | S7 | — |
| 952 | DWF / DWFx | `dwf` `dwfx` | — | 3 | `cad` | `cad` | — | dxf | S7 | — |
| 953 | CNC / ISO G-code | `nc` `tap` `ngc` | — | 3 | `cad` | `cad` | — | dxf | S7 | — |
| 954 | GDSII / OASIS chip layout | `gds` `gds2` `oas` | — | 3 | `cad` | `cad` | — | dxf | S7 | library name, structures, units, dates |
| 955 | PostScript Type 1 | `pfb` `pfa` `afm` `pfm` | application/x-font-type1 | 3 | `font` | `common` | — | read-fonts / skrifa, allsorts | S7 | — |
| 956 | Bitmap fonts BDF / PCF / FNT | `bdf` `pcf` `fon` `fnt` | — | 3 | `font` | `common` | — | read-fonts / skrifa, allsorts | S7 | — |
| 957 | EOT embedded OpenType | `eot` | application/vnd.ms-fontobject | 3 | `font` | `common` | — | read-fonts / skrifa, allsorts | S7 | — |
| 958 | Apple dfont / suitcase | `dfont` | — | 3 | `font` | `common` | — | read-fonts / skrifa, allsorts | S7 | — |
| 959 | Glyphs / UFO / FontForge sources | `glyphs` `ufo` `sfd` | — | 3 | `font` | `common` | — | read-fonts / skrifa, allsorts | S7 | family name, masters |
| 960 | PC Screen Font / Metafont | `psf` `mf` | — | 3 | `font` | `common` | — | read-fonts / skrifa, allsorts | S7 | — |
| 961 | Org-mode | `org` | text/org | 3 | `text.lightmarkup` | `common` | — | impl | S8 | #+TITLE/#+AUTHOR, TODO states |
| 962 | Textile | `textile` | text/x-textile | 3 | `text.lightmarkup` | `common` | — | impl | S8 | — |
| 963 | MediaWiki markup | `wiki` `mediawiki` | text/x-wiki | 3 | `text.lightmarkup` | `common` | — | impl | S8 | — |
| 964 | Perl POD | `pod` | text/x-pod | 3 | `text.lightmarkup` | `common` | — | impl | S8 | — |
| 965 | troff / man page | `1` `2` `3` `4` `5` `6` `7` `8` `man` `ms` `me` | text/troff | 3 | `text.lightmarkup` | `common` | — | impl | S8 | .TH name/section, NAME/SYNOPSIS |
| 966 | Texinfo | `texi` `texinfo` | application/x-texinfo | 3 | `text.lightmarkup` | `common` | — | impl | S8 | — |
| 967 | Creole / DokuWiki | `creole` `dokuwiki` | — | 3 | `text.lightmarkup` | `common` | — | impl | S8 | — |
| 968 | Djot | `dj` `djot` | — | 3 | `text.lightmarkup` | `common` | — | impl | S8 | — |
| 969 | Gemtext | `gmi` `gemini` | text/gemini | 3 | `text.lightmarkup` | `common` | — | impl | S8 | — |
| 970 | nginx / Apache config | `nginx.conf` `httpd.conf` `.htaccess` | — | 3 | `code.infra` | `common` | — | hcl-rs + impl line scanners | S8 | — |
| 971 | crontab | `crontab` `cron` | — | 3 | `code.infra` | `common` | — | hcl-rs + impl line scanners | S8 | — |
| 972 | Vagrantfile / Procfile / Justfile | `Vagrantfile` `Procfile` `justfile` `Taskfile.yml` | — | 3 | `code.infra` | `common` | — | hcl-rs + impl line scanners | S8 | — |
| 973 | SSH config / known_hosts | `ssh_config` `known_hosts` `authorized_keys` | — | 3 | `code.infra` | `common` | — | hcl-rs + impl line scanners | S8 | host count; keys -&gt; crypto |
| 974 | Caddyfile / HAProxy / Envoy | `Caddyfile` `haproxy.cfg` `envoy.yaml` | — | 3 | `code.infra` | `common` | — | hcl-rs + impl line scanners | S8 | — |
| 975 | WARC web archive | `warc` `warc.gz` | application/warc | 3 | `web.misc` | `common` | — | swf, lava_torrent | S8 | — |
| 976 | robots.txt / security.txt / humans.txt | `txt` | — | 3 | `web.misc` | `common` | — | swf, lava_torrent | S8 | — |
| 977 | Sitemap index / sitemap text | `xml` `txt` | — | 3 | `web.misc` | `common` | — | swf, lava_torrent | S8 | — |
| 978 | Magnet / metalink | `metalink` `meta4` | application/metalink4+xml | 3 | `web.misc` | `common` | — | swf, lava_torrent | S8 | — |
| 979 | Browser bookmarks HTML / JSON | `html` `json` | — | 3 | `web.misc` | `common` | — | swf, lava_torrent | S8 | folder tree, bookmark count, top domains |
| 980 | Cookie jar (Netscape) | `cookies.txt` | — | 3 | `web.misc` | `common` | — | swf, lava_torrent | S8 | domains count (values redacted) |
| 981 | HTTP Archive (HAR) | `har` | — | 3 | `web.misc` | `common` | — | swf, lava_torrent | S8 | -&gt; forensic |
| 982 | Wget / curl config, .netrc | `wgetrc` `curlrc` `netrc` | — | 3 | `web.misc` | `common` | — | swf, lava_torrent | S8 | credentials redacted |
| 983 | PAC proxy auto-config | `pac` | application/x-ns-proxy-autoconfig | 3 | `web.misc` | `common` | — | swf, lava_torrent | S8 | — |
| 984 | Web bundle / signed exchange | `wbn` `sxg` | — | 3 | `web.misc` | `common` | — | swf, lava_torrent | S8 | — |
| 985 | Google Earth / Maps link files | `kmz` `url` | — | 3 | `web.misc` | `common` | — | swf, lava_torrent | S8 | -&gt; geo |
| 986 | Shortcut-like: .desktop / .lnk / .website | `desktop` `website` | — | 3 | `web.misc` | `common` | — | swf, lava_torrent | S8 | target |
| 987 | Proxy lists / Adblock filter lists | `txt` | — | 3 | `web.misc` | `common` | — | swf, lava_torrent | S8 | rule count |
| 988 | NES / SNES / GB / GBA / N64 ROMs | `nes` `sfc` `smc` `gb` `gbc` `gba` `n64` `z64` | — | 3 | `game` | `games` | — | impl headers | S8 | header title, mapper, region |
| 989 | Sega / PlayStation / Switch images | `md` `gen` `iso` `nsp` `xci` `cia` | — | 3 | `game` | `games` | — | impl headers | S8 | header ids |
| 990 | Doom WAD / Quake PAK / BSP | `wad` `pak` `bsp` | — | 3 | `game` | `games` | — | impl headers | S8 | lump/entry counts, map names |
| 991 | Valve VPK / GCF | `vpk` | — | 3 | `game` | `games` | — | impl headers | S8 | file count |
| 992 | Unity asset bundle (UnityFS) | `unity3d` `assets` `bundle` | — | 3 | `game` | `games` | — | impl headers | S8 | engine version, asset count |
| 993 | Unreal package / pak | `uasset` `umap` `pak` | — | 3 | `game` | `games` | — | impl headers | S8 | engine version, package name |
| 994 | Godot packed scene / pck | `tscn` `pck` | — | 3 | `game` | `games` | — | impl headers | S8 | nodes count |
| 995 | Minecraft world / schematic | `mca` `schem` `schematic` `litematic` | — | 3 | `game` | `games` | — | impl headers | S8 | NBT root |
| 996 | RPG Maker / Ren'Py archives | `rgssad` `rpa` | — | 3 | `game` | `games` | — | impl headers | S8 | — |
| 997 | Save games / emulator states | `sav` `state` `srm` | — | 3 | `game` | `games` | — | impl headers | S8 | size + header only |
| 998 | Tiled map | `tmx` `tsx` `tmj` | — | 3 | `game` | `games` | — | impl headers | S8 | map size, layers, tilesets |
| 999 | Aseprite / Pyxel sprite | `aseprite` `ase` | — | 3 | `game` | `games` | — | impl headers | S8 | frames, layers, tags |
| 1000 | Godot / GameMaker projects | `godot` `yyp` | — | 3 | `game` | `games` | — | impl headers | S8 | — |
| 1001 | Steam app manifest / VDF | `acf` `vdf` | — | 3 | `game` | `games` | — | impl headers | S8 | appid, name |
| 1002 | Chip-tune / emulated music (NSF, SPC, VGM, SID) | `nsf` `spc` `vgm` `vgz` `sid` | audio/prs.sid | 3 | `game` | `games` | — | impl headers | S8 | title, author, copyright |
| 1003 | Game mod archives (Bethesda BSA/BA2, Paradox mod) | `bsa` `ba2` `mod` | — | 3 | `game` | `games` | — | impl headers | S8 | file count, version |
| 1004 | Twine / Ink interactive fiction | `twee` `ink` `z5` `z8` `ulx` | — | 3 | `game` | `games` | — | impl headers | S8 | title, passages / IFID |
