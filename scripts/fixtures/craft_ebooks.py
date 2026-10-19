#!/usr/bin/env python3
"""Write the ebook fixtures (EPUB 3, EPUB 2, FB2, FBZ, CBZ, MOBI, AZW3, PalmDOC)
with the standard library.

Usage: python3 scripts/fixtures/craft_ebooks.py [repo-root]

All names, places and texts are fictitious; the files are CC0-1.0.
"""

import base64
import struct
import sys
import zipfile
import zlib
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[2])
FIX = ROOT / "tests" / "fixtures"
STAMP = (2024, 5, 1, 8, 30, 0)


def png(width, height, rgb):
    """A small solid-colour PNG."""

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    row = b"\x00" + bytes(rgb) * width
    raw = row * height
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def write_zip(path, entries):
    """entries: (name, bytes); `mimetype` first and stored, the rest deflated."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries:
            info = zipfile.ZipInfo(name, STAMP)
            info.compress_type = zipfile.ZIP_STORED if name == "mimetype" else zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, data)
    print("wrote", path.relative_to(ROOT))


def chapter(title, paragraphs):
    body = "".join(f"<p>{p}</p>" for p in paragraphs)
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n<!DOCTYPE html>\n'
        '<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops" lang="en">'
        f"<head><title>{title}</title></head><body><section><h1>{title}</h1>{body}</section></body></html>"
    ).encode()


CONTAINER = b"""<?xml version="1.0" encoding="UTF-8"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles>
</container>"""


def epub3():
    opf = """<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0" unique-identifier="bookid" xml:lang="en">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:identifier id="bookid">urn:isbn:9780306406157</dc:identifier>
    <dc:title id="t1">Saltmere Tides</dc:title>
    <meta refines="#t1" property="title-type">main</meta>
    <dc:creator id="c1">Ana Lighthouse</dc:creator>
    <meta refines="#c1" property="role" scheme="marc:relators">aut</meta>
    <dc:creator id="c2">Ben Gull</dc:creator>
    <meta refines="#c2" property="role" scheme="marc:relators">ill</meta>
    <dc:language>en</dc:language>
    <dc:publisher>Saltmere Harbour Press</dc:publisher>
    <dc:date>2024-05-01</dc:date>
    <dc:subject>Tides</dc:subject>
    <dc:subject>Harbours</dc:subject>
    <dc:rights>CC0 1.0: no rights reserved</dc:rights>
    <dc:description>&lt;p&gt;A short guide to the tides of the fictitious port of Saltmere.&lt;/p&gt;</dc:description>
    <meta property="dcterms:modified">2024-05-02T10:00:00Z</meta>
    <meta property="belongs-to-collection" id="series">Harbour Guides</meta>
    <meta refines="#series" property="collection-type">series</meta>
    <meta refines="#series" property="group-position">2</meta>
  </metadata>
  <manifest>
    <item id="nav" href="nav.xhtml" media-type="application/xhtml+xml" properties="nav"/>
    <item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml"/>
    <item id="cover" href="images/cover.png" media-type="image/png" properties="cover-image"/>
    <item id="css" href="style.css" media-type="text/css"/>
    <item id="ch1" href="text/springs.xhtml" media-type="application/xhtml+xml"/>
    <item id="ch2" href="text/neaps.xhtml" media-type="application/xhtml+xml"/>
  </manifest>
  <spine toc="ncx"><itemref idref="ch1"/><itemref idref="ch2"/></spine>
</package>""".encode()
    nav = b"""<?xml version="1.0" encoding="utf-8"?>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops"><head><title>Contents</title></head>
<body><nav epub:type="toc"><h1>Contents</h1><ol>
<li><a href="text/springs.xhtml">Spring tides</a><ol><li><a href="text/springs.xhtml#mole">At the outer mole</a></li></ol></li>
<li><a href="text/neaps.xhtml">Neap tides</a></li></ol></nav>
<nav epub:type="landmarks" hidden=""><ol><li><a epub:type="bodymatter" href="text/springs.xhtml">Start</a></li></ol></nav></body></html>"""
    ncx = b"""<?xml version="1.0" encoding="UTF-8"?>
<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1"><head><meta name="dtb:uid" content="urn:isbn:9780306406157"/></head>
<docTitle><text>Saltmere Tides</text></docTitle><navMap>
<navPoint id="n1" playOrder="1"><navLabel><text>Spring tides</text></navLabel><content src="text/springs.xhtml"/></navPoint>
<navPoint id="n2" playOrder="2"><navLabel><text>Neap tides</text></navLabel><content src="text/neaps.xhtml"/></navPoint>
</navMap></ncx>"""
    write_zip(
        FIX / "epub" / "saltmere-tides.epub",
        [
            ("mimetype", b"application/epub+zip"),
            ("META-INF/container.xml", CONTAINER),
            ("OEBPS/content.opf", opf),
            ("OEBPS/nav.xhtml", nav),
            ("OEBPS/toc.ncx", ncx),
            ("OEBPS/style.css", b"body { font-family: serif; }\n"),
            ("OEBPS/images/cover.png", png(60, 90, (20, 60, 120))),
            (
                "OEBPS/text/springs.xhtml",
                chapter(
                    "Spring tides",
                    [
                        "Spring tides at Saltmere reach 5.2 metres, two days after the full and new moon.",
                        "High water at the outer mole comes about forty minutes after high water at the bar.",
                    ],
                ),
            ),
            (
                "OEBPS/text/neaps.xhtml",
                chapter("Neap tides", ["Neap tides rise to 3.9 metres; berth 3 still dries at low water."]),
            ),
        ],
    )


def epub2():
    opf = b"""<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="2.0" unique-identifier="uid">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:opf="http://www.idpf.org/2007/opf">
    <dc:title>Harbour Guide</dc:title>
    <dc:creator opf:role="aut" opf:file-as="Castell, Mira">Mira Castell</dc:creator>
    <dc:contributor opf:role="edt">Ana Lighthouse</dc:contributor>
    <dc:identifier id="uid" opf:scheme="UUID">urn:uuid:6f1c2a52-7d4e-4c55-9a43-2b1f0c9e8d11</dc:identifier>
    <dc:language>en-GB</dc:language>
    <dc:date opf:event="publication">2023-11-20</dc:date>
    <dc:subject>Travel</dc:subject>
    <meta name="cover" content="cover-img"/>
    <meta name="calibre:series" content="Harbour Guides"/>
    <meta name="calibre:series_index" content="1"/>
  </metadata>
  <manifest>
    <item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml"/>
    <item id="cover-img" href="cover.png" media-type="image/png"/>
    <item id="intro" href="intro.html" media-type="application/xhtml+xml"/>
  </manifest>
  <spine toc="ncx"><itemref idref="intro"/></spine>
  <guide><reference type="text" title="Introduction" href="intro.html"/></guide>
</package>"""
    ncx = b"""<?xml version="1.0" encoding="UTF-8"?>
<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1"><head/><docTitle><text>Harbour Guide</text></docTitle><navMap>
<navPoint id="p1" playOrder="1"><navLabel><text>Introduction</text></navLabel><content src="intro.html"/>
<navPoint id="p2" playOrder="2"><navLabel><text>Moorings</text></navLabel><content src="intro.html#moorings"/></navPoint></navPoint>
</navMap></ncx>"""
    intro = (
        b"<html><head><title>Introduction</title></head><body><h1>Introduction</h1>"
        b"<p>Saltmere harbour lies behind a stone mole&nbsp;&mdash; enter on the flood.</p>"
        b"<h2 id=\"moorings\">Moorings</h2><p>Visitors' moorings are the yellow buoys east of the ferry pier.</p></body></html>"
    )
    write_zip(
        FIX / "epub" / "harbour-guide-epub2.epub",
        [
            ("mimetype", b"application/epub+zip"),
            ("META-INF/container.xml", CONTAINER),
            ("OEBPS/content.opf", opf),
            ("OEBPS/toc.ncx", ncx),
            ("OEBPS/cover.png", png(40, 60, (200, 160, 40))),
            ("OEBPS/intro.html", intro),
        ],
    )


def fb2():
    cover = base64.b64encode(png(30, 45, (90, 30, 30))).decode()
    text = f"""<?xml version="1.0" encoding="UTF-8"?>
<FictionBook xmlns="http://www.gribuser.ru/xml/fictionbook/2.0" xmlns:l="http://www.w3.org/1999/xlink">
  <description>
    <title-info>
      <genre>sci_geo</genre>
      <author><first-name>Ana</first-name><last-name>Lighthouse</last-name></author>
      <book-title>Pilot Notes for Saltmere</book-title>
      <annotation><p>Notes for pilots entering the fictitious port of Saltmere.</p></annotation>
      <keywords>pilotage, harbour</keywords>
      <date value="2024-05-01">2024</date>
      <coverpage><image l:href="#cover.png"/></coverpage>
      <lang>en</lang>
      <sequence name="Harbour Guides" number="3"/>
    </title-info>
    <document-info>
      <author><nickname>whiff</nickname></author>
      <program-used>whiff fixtures</program-used>
      <date value="2024-05-01">1 May 2024</date>
      <id>0b6c4f1e-saltmere-pilot-notes</id>
      <version>1.0</version>
    </document-info>
    <publish-info><publisher>Saltmere Harbour Press</publisher><year>2024</year><isbn>978-0-306-40615-7</isbn></publish-info>
  </description>
  <body>
    <title><p>Pilot Notes for Saltmere</p></title>
    <section>
      <title><p>Approach</p></title>
      <p>Approach on a bearing of 040 degrees with the lighthouse fine on the starboard bow.</p>
      <section>
        <title><p>The bar</p></title>
        <p>The bar carries 2.1 metres at low water springs.</p>
      </section>
    </section>
    <section>
      <title><p>Berthing</p></title>
      <p>Berth 5 takes vessels of up to 4.5 metres draught.</p>
    </section>
  </body>
  <binary id="cover.png" content-type="image/png">{cover}</binary>
</FictionBook>
"""
    path = FIX / "fb2" / "pilot-notes.fb2"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print("wrote", path.relative_to(ROOT))


def cbz():
    info = b"""<?xml version="1.0" encoding="utf-8"?>
<ComicInfo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Title>The Lamp</Title>
  <Series>Saltmere Light</Series>
  <Number>3</Number>
  <Count>6</Count>
  <Summary>The keeper repairs the lamp before the winter storms.</Summary>
  <Year>2024</Year><Month>5</Month><Day>1</Day>
  <Writer>Ana Lighthouse</Writer>
  <Penciller>Ben Gull</Penciller>
  <Colorist>Mira Castell</Colorist>
  <Publisher>Saltmere Harbour Press</Publisher>
  <Genre>Adventure, Maritime</Genre>
  <PageCount>3</PageCount>
  <LanguageISO>en</LanguageISO>
  <Manga>No</Manga>
</ComicInfo>"""
    pages = [(f"lamp/{i:03}.png", png(48, 64, c)) for i, c in enumerate([(240, 220, 120), (40, 40, 80), (200, 80, 40)], 1)]
    write_zip(FIX / "cbz" / "lamp.cbz", [("ComicInfo.xml", info)] + pages)


def fbz():
    data = (FIX / "fb2" / "pilot-notes.fb2").read_bytes()
    write_zip(FIX / "fbz" / "pilot-notes.fbz", [("pilot-notes.fb2", data)])


def palmdoc_compress(data):
    """PalmDOC compression using literals and space+letter pairs only (valid, if not small)."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == 0x20 and i + 1 < len(data) and 0x40 <= data[i + 1] <= 0x7F:
            out.append(data[i + 1] ^ 0x80)
            i += 2
        elif 0x09 <= b <= 0x7F:
            out.append(b)
            i += 1
        else:
            run = data[i : i + 8]
            out.append(len(run))
            out += run
            i += len(run)
    return bytes(out)


def palm_database(name, type_creator, records, created=1714552200):
    """A Palm database: 78-byte header, record list, records."""
    head = name.encode()[:31].ljust(32, b"\0")
    head += struct.pack(">HHIIIIII", 0, 0, created, created, 0, 0, 0, 0) + type_creator + struct.pack(">II", 0, 0)
    head += struct.pack(">H", len(records))
    offset = len(head) + 8 * len(records) + 2
    table = b""
    for i, r in enumerate(records):
        table += struct.pack(">II", offset, i * 2)
        offset += len(r)
    return head + table + b"\0\0" + b"".join(records)


def text_records(html, compress):
    data = html.encode("utf-8")
    chunks = [data[i : i + 4096] for i in range(0, len(data), 4096)]
    return [palmdoc_compress(c) if compress else c for c in chunks], len(data)


def mobi_book(path, version, mobi_type, exth_records, title, html, compress=True):
    recs, length = text_records(html, compress)
    exth_body = b"".join(struct.pack(">II", k, len(v) + 8) + v for k, v in exth_records)
    exth = b"EXTH" + struct.pack(">II", len(exth_body) + 12, len(exth_records)) + exth_body
    exth += b"\0" * ((4 - len(exth) % 4) % 4)
    header_len = 0xE8
    r0 = bytearray(16 + header_len)
    struct.pack_into(">HHIHHHH", r0, 0, 2 if compress else 1, 0, length, len(recs), 4096, 0, 0)
    r0[16:20] = b"MOBI"
    struct.pack_into(">IIIII", r0, 20, header_len, mobi_type, 65001, 0x5A17, version)
    struct.pack_into(">I", r0, 0x5C, 0x0409)  # locale: en-US
    struct.pack_into(">I", r0, 0x68, version)  # minimum reader version
    struct.pack_into(">I", r0, 0x6C, 0xFFFFFFFF)  # first image record: none
    struct.pack_into(">I", r0, 0x80, 0x40)  # EXTH present
    struct.pack_into(">II", r0, 0xA8, 0xFFFFFFFF, 0)  # no DRM
    struct.pack_into(">H", r0, 0xF2, 0)  # no trailing entries
    r0 += exth
    title_offset = len(r0)
    r0 += title.encode("utf-8") + b"\0\0"
    struct.pack_into(">II", r0, 0x54, title_offset, len(title.encode("utf-8")))
    name = title.replace(" ", "_")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(palm_database(name, b"BOOKMOBI", [bytes(r0)] + recs + [b"\xe9\x8e\r\n"]))
    print("wrote", path.relative_to(ROOT))


BOOK_HTML = (
    "<html><head><guide></guide></head><body>"
    "<h1>Saltmere Tides</h1><p>Spring tides at Saltmere reach 5.2 metres, two days after the full and new moon.</p>"
    "<h2>Neap tides</h2><p>Neap tides rise to 3.9 metres; berth 3 still dries at low water.</p>"
    "<mbp:pagebreak/><h1>Moorings</h1><p>Visitors' moorings are the yellow buoys east of the ferry pier.</p>"
    "</body></html>"
)


def mobi():
    exth = [
        (100, b"Ana Lighthouse"),
        (101, b"Saltmere Harbour Press"),
        (103, b"A short guide to the tides of the fictitious port of Saltmere."),
        (104, b"9780306406157"),
        (105, b"Tides"),
        (106, b"2024-05-01"),
        (113, b"B0WHIFF001"),
        (501, b"EBOK"),
        (524, b"en"),
    ]
    mobi_book(FIX / "mobi" / "saltmere-tides.mobi", 6, 2, exth, "Saltmere Tides", BOOK_HTML)
    kf8 = [(100, b"Ana Lighthouse"), (101, b"Saltmere Harbour Press"), (504, b"B0WHIFF002"), (501, b"EBOK"), (524, b"en")]
    html = BOOK_HTML.replace("<mbp:pagebreak/>", "")
    mobi_book(FIX / "azw3" / "saltmere-tides.azw3", 8, 2, kf8, "Saltmere Tides (KF8)", html)


def palmdoc():
    text = (
        "Harbour Log\n\nMonday: wind north-west 4, ferry on time.\n"
        "Tuesday: fog until 10:00, fog signal sounded for two hours.\n"
        "Wednesday: spring tide, berth 3 dried at 14:20.\n"
    ).encode("latin-1")
    recs = [palmdoc_compress(text)]
    r0 = struct.pack(">HHIHHI", 2, 0, len(text), len(recs), 4096, 0)
    path = FIX / "palmdoc" / "harbour-log.pdb"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(palm_database("Harbour_Log", b"TEXtREAd", [r0] + recs))
    print("wrote", path.relative_to(ROOT))


if __name__ == "__main__":
    epub3()
    epub2()
    fb2()
    fbz()
    cbz()
    mobi()
    palmdoc()
