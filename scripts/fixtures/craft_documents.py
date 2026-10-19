#!/usr/bin/env python3
"""Craft the Office and OpenDocument fixtures under tests/fixtures/.

Packages are assembled part by part (OOXML and OpenDocument, plus the
template, macro-enabled, show and Visio variants and the plain compound
files of the less common OLE formats), so every structure whiff reads is
present and documented here. Standard library only; output is
deterministic.

    python3 scripts/fixtures/craft_documents.py tests/fixtures

The macros are ordinary office helpers (formatting, sums). Every name, address and company is fictitious;
domains are example.org / example.com / example.net.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from office import (  # noqa: E402
    FMTID_DOC_SUMMARY,
    FMTID_SUMMARY,
    FMTID_USER,
    VT_BOOL,
    VT_FILETIME,
    VT_I4,
    VT_LPSTR,
    cfb_bytes,
    filetime,
    guid_bytes,
    property_set,
    vba_project,
    zip_bytes,
)

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures")


def write(fmt, name, data):
    d = OUT / fmt
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))


# --------------------------------------------------------------------------
# OOXML

CT = "application/vnd.openxmlformats-officedocument"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def content_types(overrides, defaults=(("rels", "application/vnd.openxmlformats-package.relationships+xml"), ("xml", "application/xml"))):
    out = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    out += '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    for ext, ct in defaults:
        out += f'<Default Extension="{ext}" ContentType="{ct}"/>'
    for part, ct in overrides:
        out += f'<Override PartName="/{part}" ContentType="{ct}"/>'
    return out + "</Types>"


def rels(items):
    out = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    out += f'<Relationships xmlns="{PKG_REL}">'
    for i, (kind, target, *ext) in enumerate(items, 1):
        base = PKG_REL if kind in ("metadata/core-properties",) else REL
        uri = kind if kind.startswith("http") else f"{base}/{kind}"
        mode = ' TargetMode="External"' if ext else ""
        out += f'<Relationship Id="rId{i}" Type="{uri}" Target="{target}"{mode}/>'
    return out + "</Relationships>"


def core(title, creator, created, modified, **more):
    extra = "".join(f"<{k}>{v}</{k}>" for k, v in more.items())
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>{title}</dc:title><dc:creator>{creator}</dc:creator>{extra}"
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>'
        f'<dcterms:modified xsi:type="dcterms:W3CDTF">{modified}</dcterms:modified>'
        "</cp:coreProperties>"
    )


def app(application, **props):
    body = "".join(f"<{k}>{v}</{k}>" for k, v in props.items())
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
        'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
        f"<Application>{application}</Application>{body}</Properties>"
    )


def custom(props):
    out = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" '
        'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
    )
    for i, (name, vt, value) in enumerate(props, 2):
        out += f'<property fmtid="{{D5CDD505-2E9C-101B-9397-08002B2CF9AE}}" pid="{i}" name="{name}"><vt:{vt}>{value}</vt:{vt}></property>'
    return out + "</Properties>"


def para(text, style=None, extra=""):
    ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    return f"<w:p>{ppr}<w:r><w:t xml:space=\"preserve\">{text}</w:t></w:r>{extra}</w:p>"


def document(body):
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f'<w:document xmlns:w="{W}" xmlns:r="{REL}"><w:body>{body}<w:sectPr/></w:body></w:document>'
    )


STYLES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    f'<w:styles xmlns:w="{W}">'
    '<w:style w:type="paragraph" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
    '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/></w:style>'
    '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:pPr><w:outlineLvl w:val="0"/></w:pPr></w:style>'
    '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:pPr><w:outlineLvl w:val="1"/></w:pPr></w:style>'
    '<w:style w:type="paragraph" w:styleId="Kop3"><w:name w:val="heading 3"/></w:style>'
    "</w:styles>"
)


def xlsx_like(name, sheets_xml, main_ct, extra_parts=(), extra_ct=(), extra_rels=(), shared=None, workbook_extra=""):
    sheet_entries = "".join(
        f'<sheet name="{n}" sheetId="{i}" r:id="rId{i}"{f" state=" + chr(34) + st + chr(34) if st else ""}/>'
        for i, (n, st, _) in enumerate(sheets_xml, 1)
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="{REL}">'
        f"<sheets>{sheet_entries}</sheets>{workbook_extra}</workbook>"
    )
    wb_rels = [("worksheet", f"worksheets/sheet{i}.xml") for i in range(1, len(sheets_xml) + 1)]
    if shared is not None:
        wb_rels.append(("sharedStrings", "sharedStrings.xml"))
    wb_rels += list(extra_rels)
    parts = [("xl/workbook.xml", main_ct)]
    parts += [(f"xl/worksheets/sheet{i}.xml", f"{CT}.spreadsheetml.worksheet+xml") for i in range(1, len(sheets_xml) + 1)]
    if shared is not None:
        parts.append(("xl/sharedStrings.xml", f"{CT}.spreadsheetml.sharedStrings+xml"))
    entries = [
        ("[Content_Types].xml", content_types(parts + [
            ("docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml"),
            ("docProps/app.xml", f"{CT}.extended-properties+xml"),
        ] + list(extra_ct))),
        ("_rels/.rels", rels([("officeDocument", "xl/workbook.xml"), ("metadata/core-properties", "docProps/core.xml"), ("extended-properties", "docProps/app.xml")])),
        ("docProps/core.xml", core("Harbour fees 2024", "Tomas Lind", "2024-03-02T08:00:00Z", "2024-03-09T17:45:00Z", **{"cp:lastModifiedBy": "Ana Lima", "cp:keywords": "fees; harbour; 2024"})),
        ("docProps/app.xml", app("Microsoft Excel", AppVersion="16.0300", Company="Example Port Authority",
            TitlesOfParts='<vt:vector size="%d" baseType="lpstr">%s</vt:vector>' % (len(sheets_xml), "".join(f"<vt:lpstr>{n}</vt:lpstr>" for n, _, _ in sheets_xml)))),
        ("xl/workbook.xml", workbook),
        ("xl/_rels/workbook.xml.rels", rels(wb_rels)),
    ]
    for i, (_, _, body) in enumerate(sheets_xml, 1):
        if body is not None:
            entries.append((f"xl/worksheets/sheet{i}.xml", body))
    if shared is not None:
        items = "".join(f"<si><t>{s}</t></si>" for s in shared)
        entries.append(("xl/sharedStrings.xml", f'<?xml version="1.0" encoding="UTF-8"?>\n<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="{len(shared)}" uniqueCount="{len(shared)}">{items}</sst>'))
    entries += list(extra_parts)
    write(name.rsplit(".", 1)[1], name, zip_bytes(entries))


def sheet(rows, dim, extra=""):
    data = ""
    for r, cells in enumerate(rows, 1):
        data += f'<row r="{r}">'
        for c, (kind, v) in enumerate(cells):
            ref = f"{chr(65 + c)}{r}"
            if kind == "s":
                data += f'<c r="{ref}" t="s"><v>{v}</v></c>'
            elif kind == "f":
                data += f'<c r="{ref}"><f>{v}</f><v>0</v></c>'
            else:
                data += f'<c r="{ref}"><v>{v}</v></c>'
        data += "</row>"
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<dimension ref="{dim}"/><sheetData>{data}</sheetData>{extra}</worksheet>'
    )


MACRO_SOURCE = """Sub FormatTable()
    ActiveDocument.Tables(1).Style = "Table Grid"
End Sub

Function Helper(x As Integer) As Integer
    Helper = x * 2
End Function
"""

WORKBOOK_MACRO = """Sub SumFees()
    Range("B5").Value = Application.WorksheetFunction.Sum(Range("B2:B4"))
End Sub
"""


def ooxml():
    # A rich Word document: styles, outline, comments, tracked changes,
    # footnote, hyperlinks, a field, properties, a sensitivity label and
    # an embedded workbook.
    body = (
        para("Harbour Safety Review", "Title")
        + para("Introduction", "Heading1")
        + para("This review covers the night shift at the old harbour, the crane inspections and the new mooring rules.")
        + para("Findings", "Heading1")
        + para("Cranes", "Heading2")
        + "<w:p><w:r><w:t>Crane 3 needs a new brake. </w:t></w:r>"
        '<w:ins w:id="1" w:author="Ana Lima" w:date="2024-05-02T09:00:00Z"><w:r><w:t>Repairs are scheduled for June.</w:t></w:r></w:ins>'
        '<w:del w:id="2" w:author="Jonas Wren" w:date="2024-05-02T10:00:00Z"><w:r><w:delText>Old text.</w:delText></w:r></w:del>'
        '<w:commentRangeStart w:id="0"/><w:r><w:commentReference w:id="0"/></w:r>'
        '<w:r><w:footnoteReference w:id="1"/></w:r></w:p>'
        + para("Moorings", "Kop3")
        + '<w:p><w:hyperlink r:id="rId5"><w:r><w:t>Mooring rules</w:t></w:r></w:hyperlink><w:r><w:t> are published online.</w:t></w:r></w:p>'
        + '<w:p><w:fldSimple w:instr=" DATE \\@ &quot;d MMMM yyyy&quot; "><w:r><w:t>3 May 2024</w:t></w:r></w:fldSimple></w:p>'
        + '<w:tbl><w:tr><w:tc><w:p><w:r><w:t>Crane</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>Status</w:t></w:r></w:p></w:tc></w:tr></w:tbl>'
    )
    nested = zip_bytes([
        ("[Content_Types].xml", content_types([("xl/workbook.xml", f"{CT}.spreadsheetml.sheet.main+xml"), ("xl/worksheets/sheet1.xml", f"{CT}.spreadsheetml.worksheet+xml")])),
        ("_rels/.rels", rels([("officeDocument", "xl/workbook.xml")])),
        ("xl/workbook.xml", f'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="{REL}"><sheets><sheet name="Cranes" sheetId="1" r:id="rId1"/></sheets></workbook>'),
        ("xl/_rels/workbook.xml.rels", rels([("worksheet", "worksheets/sheet1.xml")])),
        ("xl/worksheets/sheet1.xml", sheet([[("n", 3)], [("n", 4)]], "A1:A2")),
    ])
    word_ct = [
        ("word/document.xml", f"{CT}.wordprocessingml.document.main+xml"),
        ("word/styles.xml", f"{CT}.wordprocessingml.styles+xml"),
        ("word/comments.xml", f"{CT}.wordprocessingml.comments+xml"),
        ("word/footnotes.xml", f"{CT}.wordprocessingml.footnotes+xml"),
        ("word/settings.xml", f"{CT}.wordprocessingml.settings+xml"),
        ("docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml"),
        ("docProps/app.xml", f"{CT}.extended-properties+xml"),
        ("docProps/custom.xml", f"{CT}.custom-properties+xml"),
    ]
    root_rels = rels([
        ("officeDocument", "word/document.xml"),
        ("metadata/core-properties", "docProps/core.xml"),
        ("extended-properties", "docProps/app.xml"),
        ("custom-properties", "docProps/custom.xml"),
    ])
    label = "3f2b1c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
    common = [
        ("_rels/.rels", root_rels),
        ("docProps/core.xml", core(
            "Harbour Safety Review", "Ana Lima; Jonas Wren", "2024-05-01T08:30:00Z", "2024-05-03T16:10:00Z",
            **{"dc:subject": "Night-shift safety at the old harbour", "cp:keywords": "harbour, safety, cranes",
               "cp:lastModifiedBy": "Jonas Wren", "cp:revision": "7", "cp:category": "Report",
               "cp:lastPrinted": "2024-05-03T15:00:00Z", "dc:language": "en-GB"})),
        ("docProps/app.xml", app("Microsoft Office Word", Template="Normal.dotm", TotalTime="95", Pages="3",
            Words="412", Characters="2350", Lines="40", Paragraphs="12", Company="Example Port Authority",
            AppVersion="16.0000", DocSecurity="0")),
        ("docProps/custom.xml", custom([
            ("Project", "lpwstr", "Harbour 2024"),
            ("Reviewed", "bool", "true"),
            (f"MSIP_Label_{label}_Enabled", "lpwstr", "true"),
            (f"MSIP_Label_{label}_Name", "lpwstr", "Internal"),
            (f"MSIP_Label_{label}_SiteId", "lpwstr", "11111111-2222-3333-4444-555555555555"),
            (f"MSIP_Label_{label}_Method", "lpwstr", "Standard"),
        ])),
        ("word/styles.xml", STYLES),
        ("word/comments.xml", f'<w:comments xmlns:w="{W}"><w:comment w:id="0" w:author="Ana Lima" w:date="2024-05-02T09:30:00Z"><w:p><w:r><w:t>Check the brake supplier.</w:t></w:r></w:p></w:comment></w:comments>'),
        ("word/footnotes.xml", f'<w:footnotes xmlns:w="{W}"><w:footnote w:type="separator" w:id="-1"/><w:footnote w:id="1"><w:p><w:r><w:t>Inspection of 2 May.</w:t></w:r></w:p></w:footnote></w:footnotes>'),
        ("word/settings.xml", f'<w:settings xmlns:w="{W}"><w:trackRevisions/></w:settings>'),
    ]
    doc_rels = [
        ("styles", "styles.xml"),
        ("comments", "comments.xml"),
        ("footnotes", "footnotes.xml"),
        ("settings", "settings.xml"),
        ("hyperlink", "https://www.example.org/harbour/moorings", True),
        ("package", "embeddings/Microsoft_Excel_Worksheet.xlsx"),
    ]
    write("docx", "review.docx", zip_bytes(
        [("[Content_Types].xml", content_types(word_ct + [("word/embeddings/Microsoft_Excel_Worksheet.xlsx", f"{CT}.spreadsheetml.sheet")]))]
        + common
        + [("word/document.xml", document(body)), ("word/_rels/document.xml.rels", rels(doc_rels)),
           ("word/embeddings/Microsoft_Excel_Worksheet.xlsx", nested)]))

    # A letter attached to a template on the company intranet.
    write("docx", "letter.docx", zip_bytes([
        ("[Content_Types].xml", content_types([w for w in word_ct if w[0] in ("word/document.xml", "word/settings.xml")])),
        ("_rels/.rels", rels([("officeDocument", "word/document.xml")])),
        ("word/document.xml", document(para("Dear harbour users,") + para("The north quay closes for maintenance in March."))),
        ("word/_rels/document.xml.rels", rels([("settings", "settings.xml")])),
        ("word/settings.xml", f'<w:settings xmlns:w="{W}" xmlns:r="{REL}"><w:attachedTemplate r:id="rId1"/></w:settings>'),
        ("word/_rels/settings.xml.rels", rels([("attachedTemplate", "https://intranet.example.org/templates/letterhead.dotx", True)])),
    ]))

    # A macro-enabled report with a table-formatting macro.
    vba = cfb_bytes(vba_project([("ThisDocument", "", True), ("Module1", MACRO_SOURCE, False)]))
    write("docm", "report.docm", zip_bytes([
        ("[Content_Types].xml", content_types([
            ("word/document.xml", "application/vnd.ms-word.document.macroEnabled.main+xml"),
            ("word/vbaProject.bin", "application/vnd.ms-office.vbaProject"),
            ("docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml"),
        ], defaults=(("rels", "application/vnd.openxmlformats-package.relationships+xml"), ("xml", "application/xml"), ("bin", "application/vnd.ms-office.vbaProject")))),
        ("_rels/.rels", rels([("officeDocument", "word/document.xml"), ("metadata/core-properties", "docProps/core.xml")])),
        ("docProps/core.xml", core("Berth report", "Harbour Office", "2024-06-10T07:00:00Z", "2024-06-10T07:05:00Z")),
        ("word/document.xml", document(para("Berth report") + para("Occupancy for June, by quay."))),
        ("word/_rels/document.xml.rels", rels([("http://schemas.microsoft.com/office/2006/relationships/vbaProject", "vbaProject.bin")])),
        ("word/vbaProject.bin", vba),
    ]))

    # Spreadsheet: shared strings, formulas, a hidden sheet, defined names, an external link.
    rows = [[("s", 0), ("s", 1)], [("s", 2), ("n", 120)], [("s", 3), ("n", 80)], [("s", 4), ("f", "SUM(B2:B3)")]]
    xlsx_like(
        "fees.xlsx",
        [("Fees", None, sheet(rows, "A1:B4")), ("Rates", "hidden", sheet([[("n", 1.5)]], "A1"))],
        f"{CT}.spreadsheetml.sheet.main+xml",
        shared=["Berth", "Fee (EUR)", "North quay", "South quay", "Total"],
        workbook_extra='<definedNames><definedName name="Total">Fees!$B$4</definedName></definedNames>',
        extra_rels=[("externalLink", "externalLinks/externalLink1.xml")],
        extra_ct=[("xl/externalLinks/externalLink1.xml", f"{CT}.spreadsheetml.externalLink+xml")],
        extra_parts=[
            ("xl/externalLinks/externalLink1.xml", '<externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><externalBook xmlns:r="%s" r:id="rId1"/></externalLink>' % REL),
            ("xl/externalLinks/_rels/externalLink1.xml.rels", rels([("externalLinkPath", "https://files.example.com/rates/2024.xlsx", True)])),
        ],
    )

    # Macro-enabled workbook with a summing macro and a hidden sheet.
    vba = cfb_bytes(vba_project([("ThisWorkbook", "", True), ("Module1", WORKBOOK_MACRO, False)]))
    xlsx_like(
        "budget.xlsm",
        [("Fees", None, sheet(rows, "A1:B4")), ("Workings", "hidden", sheet([[("n", 2)]], "A1"))],
        "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
        shared=["Berth", "Fee (EUR)", "North quay", "South quay", "Total"],
        extra_rels=[("http://schemas.microsoft.com/office/2006/relationships/vbaProject", "vbaProject.bin")],
        extra_ct=[("xl/vbaProject.bin", "application/vnd.ms-office.vbaProject")],
        extra_parts=[("xl/vbaProject.bin", vba)],
    )

    # Presentation: three slides (one hidden), titles, notes.
    P = "http://schemas.openxmlformats.org/presentationml/2006/main"
    A = "http://schemas.openxmlformats.org/drawingml/2006/main"

    def shape(ph, text):
        phx = f'<p:ph type="{ph}"/>' if ph else ""
        return f'<p:sp><p:nvSpPr><p:cNvPr id="2" name="s"/><p:cNvSpPr/><p:nvPr>{phx}</p:nvPr></p:nvSpPr><p:txBody><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp>'

    def slide(title, body, show=True):
        attr = "" if show else ' show="0"'
        return f'<p:sld xmlns:p="{P}" xmlns:a="{A}" xmlns:r="{REL}"{attr}><p:cSld><p:spTree>{shape("title", title)}{shape(None, body)}</p:spTree></p:cSld></p:sld>'

    def notes(text):
        return f'<p:notes xmlns:p="{P}" xmlns:a="{A}"><p:cSld><p:spTree>{shape("sldImg", "")}{shape("body", text)}{shape("sldNum", "1")}</p:spTree></p:cSld></p:notes>'

    slides = [
        ("Harbour Expansion Plan", "Board meeting, June 2024", "Welcome everyone and introduce the plan.", True),
        ("New Quay Wall", "Four hundred metres of new berth on the east side.", "Mention the tender timeline.", True),
        ("Budget (draft)", "Not for distribution.", "", False),
    ]
    pres = (
        f'<p:presentation xmlns:p="{P}" xmlns:r="{REL}"><p:sldIdLst>'
        + "".join(f'<p:sldId id="{255 + i}" r:id="rId{i}"/>' for i in range(1, len(slides) + 1))
        + '</p:sldIdLst><p:sldSz cx="12192000" cy="6858000"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>'
    )
    parts = [("ppt/presentation.xml", f"{CT}.presentationml.presentation.main+xml")]
    entries = [
        ("_rels/.rels", rels([("officeDocument", "ppt/presentation.xml"), ("metadata/core-properties", "docProps/core.xml"), ("extended-properties", "docProps/app.xml")])),
        ("docProps/core.xml", core("Harbour Expansion Plan", "Mira Castell", "2024-06-01T09:00:00Z", "2024-06-04T11:20:00Z")),
        ("docProps/app.xml", app("Microsoft Office PowerPoint", Slides="3", Notes="2", HiddenSlides="1", PresentationFormat="Widescreen")),
        ("ppt/presentation.xml", pres),
        ("ppt/_rels/presentation.xml.rels", rels([("slide", f"slides/slide{i}.xml") for i in range(1, len(slides) + 1)])),
    ]
    for i, (title, body, note, show) in enumerate(slides, 1):
        parts.append((f"ppt/slides/slide{i}.xml", f"{CT}.presentationml.slide+xml"))
        entries.append((f"ppt/slides/slide{i}.xml", slide(title, body, show)))
        if note:
            parts.append((f"ppt/notesSlides/notesSlide{i}.xml", f"{CT}.presentationml.notesSlide+xml"))
            entries.append((f"ppt/notesSlides/notesSlide{i}.xml", notes(note)))
            entries.append((f"ppt/slides/_rels/slide{i}.xml.rels", rels([("notesSlide", f"../notesSlides/notesSlide{i}.xml")])))
    parts += [("docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml"), ("docProps/app.xml", f"{CT}.extended-properties+xml")]
    write("pptx", "expansion.pptx", zip_bytes([("[Content_Types].xml", content_types(parts))] + entries))


# --------------------------------------------------------------------------
# OpenDocument

ODF_NS = (
    'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
    'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
    'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" '
    'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
    'xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0" '
    'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" '
    'xmlns:dc="http://purl.org/dc/elements/1.1/" '
    'xmlns:xlink="http://www.w3.org/1999/xlink" '
    'xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0" '
    'xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" '
    'xmlns:ooo="http://openoffice.org/2004/office"'
)


def odf_meta(title, creator, created, modified, extra=""):
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n<office:document-meta {ODF_NS} office:version="1.3"><office:meta>'
        "<meta:generator>LibreOffice/7.6.4.1$Linux_X86_64 LibreOffice_project/fixture</meta:generator>"
        f"<dc:title>{title}</dc:title><meta:initial-creator>{creator}</meta:initial-creator>"
        f"<meta:creation-date>{created}</meta:creation-date><dc:date>{modified}</dc:date>"
        f"{extra}</office:meta></office:document-meta>"
    )


def odf_manifest(mime, files, encrypted=()):
    out = f'<?xml version="1.0" encoding="UTF-8"?>\n<manifest:manifest {ODF_NS} manifest:version="1.3">'
    out += f'<manifest:file-entry manifest:full-path="/" manifest:media-type="{mime}"/>'
    for f, t in files:
        if f in encrypted:
            out += (
                f'<manifest:file-entry manifest:full-path="{f}" manifest:media-type="{t}" manifest:size="2048">'
                '<manifest:encryption-data manifest:checksum-type="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k" manifest:checksum="AAAA">'
                '<manifest:algorithm manifest:algorithm-name="http://www.w3.org/2001/04/xmlenc#aes256-cbc" manifest:initialisation-vector="AAAA"/>'
                '<manifest:key-derivation manifest:key-derivation-name="PBKDF2" manifest:key-size="32" manifest:iteration-count="100000" manifest:salt="AAAA"/>'
                "</manifest:encryption-data></manifest:file-entry>"
            )
        else:
            out += f'<manifest:file-entry manifest:full-path="{f}" manifest:media-type="{t}"/>'
    return out + "</manifest:manifest>"


def odf_package(fmt, name, mime, content, meta, extra=(), encrypted=()):
    files = [("content.xml", "text/xml"), ("meta.xml", "text/xml")] + [(n, "text/xml") for n, _ in extra]
    entries = [("mimetype", mime), ("content.xml", content), ("meta.xml", meta)] + list(extra)
    entries.append(("META-INF/manifest.xml", odf_manifest(mime, files, encrypted)))
    write(fmt, name, zip_bytes(entries, stored=("mimetype",)))


def odf():
    text = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n<office:document-content {ODF_NS} office:version="1.3"><office:body><office:text>'
        '<text:h text:outline-level="1">Tide Tables</text:h>'
        "<text:p>High and low water times for the old harbour, spring 2024.</text:p>"
        '<text:h text:outline-level="2">April</text:h>'
        '<text:p>Spring tides peak on the <text:span>9th</text:span> and the 24th.<office:annotation><dc:creator>Ana Lima</dc:creator><text:p>Check against the almanac.</text:p></office:annotation></text:p>'
        '<text:h text:outline-level="2">May</text:h>'
        '<text:p>See the <text:a xlink:type="simple" xlink:href="https://tides.example.org/2024/may">tide service</text:a> for live data.</text:p>'
        '<table:table table:name="Times"><table:table-row><table:table-cell><text:p>06:12</text:p></table:table-cell></table:table-row></table:table>'
        "<text:tracked-changes><text:changed-region text:id=\"c1\"><text:insertion/></text:changed-region></text:tracked-changes>"
        "</office:text></office:body></office:document-content>"
    )
    meta = odf_meta(
        "Tide Tables 2024", "Ana Lima", "2024-03-30T10:15:00.123456789", "2024-04-02T18:00:00",
        "<dc:creator>Jonas Wren</dc:creator><dc:description>Spring tide tables for the old harbour</dc:description>"
        "<meta:keyword>tides</meta:keyword><meta:keyword>harbour</meta:keyword><dc:language>en-GB</dc:language>"
        "<meta:editing-cycles>4</meta:editing-cycles><meta:editing-duration>PT2H15M</meta:editing-duration>"
        '<meta:document-statistic meta:table-count="1" meta:page-count="2" meta:paragraph-count="5" meta:word-count="48" meta:character-count="290"/>'
        '<meta:user-defined meta:name="Department">Harbour Office</meta:user-defined>',
    )
    odf_package("odt", "tides.odt", "application/vnd.oasis.opendocument.text", text, meta)

    # A StarBasic helper macro and an encrypted settings part.
    module = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE script:module PUBLIC "-//OpenOffice.org//DTD OfficeDocument 1.0//EN" "module.dtd">'
        f'<script:module {ODF_NS} script:name="Module1" script:language="StarBasic">'
        "Sub InsertDate\n  ThisComponent.Text.getEnd().setString(Date())\nEnd Sub\n</script:module>"
    )
    macro_text = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n<office:document-content {ODF_NS} office:version="1.3">'
        "<office:body><office:text><text:p>Shipping log for the north quay.</text:p></office:text></office:body></office:document-content>"
    )
    odf_package(
        "odt", "macro.odt", "application/vnd.oasis.opendocument.text", macro_text,
        odf_meta("Shipping log", "Harbour Office", "2024-07-01T09:00:00Z", "2024-07-01T09:00:00Z"),
        extra=[
            ("Basic/Standard/Module1.xml", module),
            ("Basic/Standard/script-lb.xml", "<library/>"),
            ("Basic/script-lc.xml", "<libraries/>"),
            ("settings.xml", b"\x8f\x12encrypted-bytes-placeholder"),
        ],
        encrypted=("settings.xml",),
    )

    sheets = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n<office:document-content {ODF_NS} office:version="1.3"><office:body><office:spreadsheet>'
        '<table:table table:name="Arrivals"><table:table-row><table:table-cell office:value-type="string"><text:p>Vessel</text:p></table:table-cell>'
        '<table:table-cell office:value-type="float" office:value="12"><text:p>12</text:p></table:table-cell></table:table-row></table:table>'
        '<table:table table:name="Departures"><table:table-row><table:table-cell><text:p>Vessel</text:p></table:table-cell></table:table-row></table:table>'
        "</office:spreadsheet></office:body></office:document-content>"
    )
    odf_package("ods", "berths.ods", "application/vnd.oasis.opendocument.spreadsheet", sheets,
        odf_meta("Berth allocation", "Tomas Lind", "2024-02-11T07:30:00", "2024-02-12T08:00:00"))

    slides = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n<office:document-content {ODF_NS} office:version="1.3"><office:body><office:presentation>'
        '<draw:page draw:name="Overview"><draw:frame presentation:class="title"><draw:text-box><text:p>Harbour lights</text:p></draw:text-box></draw:frame>'
        '<draw:frame><draw:text-box><text:p>Five new lamps on the north mole.</text:p></draw:text-box></draw:frame></draw:page>'
        '<draw:page draw:name="Costs"><draw:frame><draw:text-box><text:p>Installation in autumn.</text:p></draw:text-box></draw:frame></draw:page>'
        "</office:presentation></office:body></office:document-content>"
    )
    odf_package("odp", "lights.odp", "application/vnd.oasis.opendocument.presentation", slides,
        odf_meta("Harbour lights", "Mira Castell", "2024-08-20T14:00:00Z", "2024-08-21T09:30:00Z"))

    flat = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n<office:document {ODF_NS} office:version="1.3" office:mimetype="application/vnd.oasis.opendocument.text">'
        "<office:meta><dc:title>Pilot boarding notes</dc:title><meta:initial-creator>Jonas Wren</meta:initial-creator>"
        "<meta:creation-date>2024-01-05T06:00:00</meta:creation-date></office:meta>"
        '<office:body><office:text><text:h text:outline-level="1">Boarding</text:h><text:p>Pilots board two miles off the breakwater.</text:p></office:text></office:body>'
        "</office:document>"
    )
    write("fodt", "pilot.fodt", flat)


# --------------------------------------------------------------------------
# Format variants: one small, plain document per remaining format id. The
# macro-enabled variants carry the macro-enabled content type but no macros.


def word_variant(fmt, name, main_ct, title):
    write(fmt, name, zip_bytes([
        ("[Content_Types].xml", content_types([("word/document.xml", main_ct), ("docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml")])),
        ("_rels/.rels", rels([("officeDocument", "word/document.xml"), ("metadata/core-properties", "docProps/core.xml")])),
        ("docProps/core.xml", core(title, "Harbour Office", "2024-04-01T08:00:00Z", "2024-04-01T08:00:00Z")),
        ("word/document.xml", document(para(title) + para("Saltmere Harbour Office, 1 Quay Street."))),
    ]))


def presentation_variant(fmt, name, main_ct, title):
    P = "http://schemas.openxmlformats.org/presentationml/2006/main"
    A = "http://schemas.openxmlformats.org/drawingml/2006/main"
    pres = f'<p:presentation xmlns:p="{P}" xmlns:r="{REL}"><p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst><p:sldSz cx="9144000" cy="6858000"/></p:presentation>'
    slide = (
        f'<p:sld xmlns:p="{P}" xmlns:a="{A}" xmlns:r="{REL}"><p:cSld><p:spTree><p:sp><p:nvSpPr><p:cNvPr id="2" name="t"/><p:cNvSpPr/>'
        f'<p:nvPr><p:ph type="title"/></p:nvPr></p:nvSpPr><p:txBody><a:p><a:r><a:t>{title}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>'
    )
    write(fmt, name, zip_bytes([
        ("[Content_Types].xml", content_types([("ppt/presentation.xml", main_ct), ("ppt/slides/slide1.xml", f"{CT}.presentationml.slide+xml"), ("docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml")])),
        ("_rels/.rels", rels([("officeDocument", "ppt/presentation.xml"), ("metadata/core-properties", "docProps/core.xml")])),
        ("docProps/core.xml", core(title, "Mira Castell", "2024-06-01T09:00:00Z", "2024-06-01T09:00:00Z")),
        ("ppt/presentation.xml", pres),
        ("ppt/_rels/presentation.xml.rels", rels([("slide", "slides/slide1.xml")])),
        ("ppt/slides/slide1.xml", slide),
    ]))


def visio_variant(fmt, name, main_ct, title):
    V = "http://schemas.microsoft.com/office/visio/2012/main"
    page = f'<PageContents xmlns="{V}"><Shapes><Shape ID="1" Type="Shape"><Text>Outer mole</Text></Shape><Shape ID="2" Type="Shape"><Text>Berth 5</Text></Shape></Shapes></PageContents>'
    write(fmt, name, zip_bytes([
        ("[Content_Types].xml", content_types([
            ("visio/document.xml", main_ct),
            ("visio/pages/pages.xml", "application/vnd.ms-visio.pages+xml"),
            ("visio/pages/page1.xml", "application/vnd.ms-visio.page+xml"),
            ("docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml"),
        ])),
        ("_rels/.rels", rels([("http://schemas.microsoft.com/visio/2010/relationships/document", "visio/document.xml"), ("metadata/core-properties", "docProps/core.xml")])),
        ("docProps/core.xml", core(title, "Ben Gull", "2024-05-10T10:00:00Z", "2024-05-10T10:00:00Z")),
        ("visio/document.xml", f'<VisioDocument xmlns="{V}"/>'),
        ("visio/_rels/document.xml.rels", rels([("http://schemas.microsoft.com/visio/2010/relationships/pages", "pages/pages.xml")])),
        ("visio/pages/pages.xml", f'<Pages xmlns="{V}" xmlns:r="{REL}"><Page ID="0" NameU="Harbour plan" Name="Harbour plan"><Rel r:id="rId1"/></Page></Pages>'),
        ("visio/pages/_rels/pages.xml.rels", rels([("http://schemas.microsoft.com/visio/2010/relationships/page", "page1.xml")])),
        ("visio/pages/page1.xml", page),
    ]))


def variants():
    word_variant("dotx", "letterhead.dotx", f"{CT}.wordprocessingml.template.main+xml", "Harbour Office letterhead")
    word_variant("dotm", "letterhead.dotm", "application/vnd.ms-word.template.macroEnabledTemplate.main+xml", "Harbour Office letterhead")
    rows = [[("s", 0), ("s", 1)], [("s", 2), ("n", 120)]]
    shared = ["Berth", "Fee (EUR)", "North quay"]
    xlsx_like("fees-template.xltx", [("Fees", None, sheet(rows, "A1:B2"))], f"{CT}.spreadsheetml.template.main+xml", shared=shared)
    xlsx_like("fees-template.xltm", [("Fees", None, sheet(rows, "A1:B2"))], "application/vnd.ms-excel.template.macroEnabled.main+xml", shared=shared)
    xlsx_like("tide-tools.xlam", [("Tools", None, sheet([[("n", 1)]], "A1"))], "application/vnd.ms-excel.addin.macroEnabled.main+xml")
    # Binary workbook: BIFF12 records BrtBeginBook / BrtEndBook only; sheet names come from app.xml.
    write("xlsb", "fees.xlsb", zip_bytes([
        ("[Content_Types].xml", content_types([
            ("xl/workbook.bin", "application/vnd.ms-excel.sheet.binary.macroEnabled.main"),
            ("docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml"),
            ("docProps/app.xml", f"{CT}.extended-properties+xml"),
        ], defaults=(("rels", "application/vnd.openxmlformats-package.relationships+xml"), ("bin", "application/vnd.ms-excel.sheet.binary.macroEnabled.main")))),
        ("_rels/.rels", rels([("officeDocument", "xl/workbook.bin"), ("metadata/core-properties", "docProps/core.xml"), ("extended-properties", "docProps/app.xml")])),
        ("docProps/core.xml", core("Harbour fees (binary)", "Tomas Lind", "2024-03-02T08:00:00Z", "2024-03-02T08:00:00Z")),
        ("docProps/app.xml", app("Microsoft Excel", TitlesOfParts='<vt:vector size="1" baseType="lpstr"><vt:lpstr>Fees</vt:lpstr></vt:vector>')),
        ("xl/workbook.bin", bytes([0x83, 0x01, 0x00, 0x84, 0x01, 0x00])),
    ]))
    presentation_variant("pptm", "briefing.pptm", "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml", "Pilot briefing")
    presentation_variant("potx", "briefing.potx", f"{CT}.presentationml.template.main+xml", "Pilot briefing template")
    presentation_variant("potm", "briefing.potm", "application/vnd.ms-powerpoint.template.macroEnabled.main+xml", "Pilot briefing template")
    presentation_variant("ppsx", "briefing.ppsx", f"{CT}.presentationml.slideshow.main+xml", "Pilot briefing show")
    presentation_variant("ppsm", "briefing.ppsm", "application/vnd.ms-powerpoint.slideshow.macroEnabled.main+xml", "Pilot briefing show")
    visio_variant("vsdx", "harbour-plan.vsdx", "application/vnd.ms-visio.drawing.main+xml", "Harbour plan")
    visio_variant("vsdm", "harbour-plan.vsdm", "application/vnd.ms-visio.drawing.macroEnabled.main+xml", "Harbour plan")
    visio_variant("vstx", "harbour-plan.vstx", "application/vnd.ms-visio.template.main+xml", "Harbour plan template")

    # OpenDocument: templates, master document, drawings, formula, database, chart, flat XML.
    def content(body):
        return f'<?xml version="1.0" encoding="UTF-8"?>\n<office:document-content {ODF_NS} office:version="1.3"><office:body>{body}</office:body></office:document-content>'

    text = content('<office:text><text:h text:outline-level="1">Notice</text:h><text:p>The fuel berth opens at 07:00.</text:p></office:text>')
    sheet_body = content('<office:spreadsheet><table:table table:name="Fees"><table:table-row><table:table-cell><text:p>Berth</text:p></table:table-cell></table:table-row></table:table></office:spreadsheet>')
    pres = content('<office:presentation><draw:page draw:name="Title"><draw:frame><draw:text-box><text:p>Pilot briefing</text:p></draw:text-box></draw:frame></draw:page></office:presentation>')
    drawing = content('<office:drawing><draw:page draw:name="Plan"><draw:frame><draw:text-box><text:p>Outer mole</text:p></draw:text-box></draw:frame></draw:page></office:drawing>')
    meta = lambda title: odf_meta(title, "Harbour Office", "2024-04-01T08:00:00", "2024-04-01T08:00:00")  # noqa: E731
    base = "application/vnd.oasis.opendocument."
    for fmt, name, mime, body, title in [
        ("ott", "notice.ott", "text-template", text, "Notice template"),
        ("odm", "handbook.odm", "text-master", content('<office:text><text:h text:outline-level="1">Harbour handbook</text:h><text:section text:name="Tides"><text:section-source xlink:href="tides.odt"/></text:section></office:text>'), "Harbour handbook"),
        ("ots", "fees.ots", "spreadsheet-template", sheet_body, "Fees template"),
        ("otp", "briefing.otp", "presentation-template", pres, "Briefing template"),
        ("odg", "plan.odg", "graphics", drawing, "Harbour plan"),
        ("otg", "plan.otg", "graphics-template", drawing, "Harbour plan template"),
        ("odf", "tide-formula.odf", "formula", content('<office:formula><math xmlns="http://www.w3.org/1998/Math/MathML"><mi>h</mi><mo>=</mo><mn>5.2</mn></math></office:formula>'), "Tide height"),
        ("odb", "berths.odb", "base", content("<office:database/>"), "Berth register"),
        ("odc", "tides.odc", "chart", content('<office:chart><chart:chart xmlns:chart="urn:oasis:names:tc:opendocument:xmlns:chart:1.0" chart:class="chart:line"/></office:chart>'), "Tide chart"),
    ]:
        odf_package(fmt, name, base + mime, body, meta(title))
    for fmt, mime, body, title in [
        ("fods", "spreadsheet", '<office:spreadsheet><table:table table:name="Arrivals"><table:table-row><table:table-cell><text:p>Vessel</text:p></table:table-cell></table:table-row></table:table></office:spreadsheet>', "Arrivals"),
        ("fodp", "presentation", '<office:presentation><draw:page draw:name="One"><draw:frame><draw:text-box><text:p>Harbour lights</text:p></draw:text-box></draw:frame></draw:page></office:presentation>', "Harbour lights"),
        ("fodg", "graphics", '<office:drawing><draw:page draw:name="Plan"><draw:frame><draw:text-box><text:p>Outer mole</text:p></draw:text-box></draw:frame></draw:page></office:drawing>', "Harbour plan"),
    ]:
        flat = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n<office:document {ODF_NS} office:version="1.3" office:mimetype="{base}{mime}">'
            f"<office:meta><dc:title>{title}</dc:title><meta:initial-creator>Harbour Office</meta:initial-creator></office:meta>"
            f"<office:body>{body}</office:body></office:document>"
        )
        write(fmt, f"{title.lower().replace(' ', '-')}.{fmt}", flat)


# --------------------------------------------------------------------------
# Legacy compound files: plain documents (no macros, no embedded objects)
# for the OLE formats no tool here writes. Real exports can replace them.

import struct  # noqa: E402
import zipfile  # noqa: E402
import io  # noqa: E402


FMTID_HWP_SUMMARY = "9FA2B660-1061-11D4-B4C6-006097C09D8C"


def summary(title, author, created="2024-04-01T08:00:00Z", app_name="Microsoft Office", fmtid=FMTID_SUMMARY):
    return property_set([(fmtid, [
        (2, VT_LPSTR, title), (4, VT_LPSTR, author), (18, VT_LPSTR, app_name),
        (12, VT_FILETIME, filetime(created)), (13, VT_FILETIME, filetime(created)),
    ])])


def record(kind, body=b""):
    return struct.pack("<HH", kind, len(body)) + body


def biff_workbook():
    """A BIFF8 workbook: two sheets, shared strings, a few cells."""
    strings = ["Berth", "Fee (EUR)", "North quay", "South quay"]
    sst = struct.pack("<II", 6, len(strings)) + b"".join(struct.pack("<HB", len(t), 0) + t.encode("latin-1") for t in strings)
    bof = lambda dt: record(0x0809, struct.pack("<HHHHII", 0x0600, dt, 0x2775, 1997, 0, 0x0006))  # noqa: E731
    sheet_names = [("Fees", 0), ("Rates", 1)]
    # Globals first, with BOUNDSHEET offsets patched once the globals size is known.
    def globals_stream(offsets):
        out = bof(0x0005) + record(0x0042, struct.pack("<H", 1252))
        for (name, state), off in zip(sheet_names, offsets):
            out += record(0x0085, struct.pack("<IBBBB", off, state, 0, len(name), 0) + name.encode("latin-1"))
        return out + record(0x00FC, sst) + record(0x000A)

    def cells(rows):
        out = b""
        for r, row in enumerate(rows):
            for c, (kind, v) in enumerate(row):
                if kind == "s":
                    out += record(0x00FD, struct.pack("<HHHI", r, c, 15, v))
                else:
                    out += record(0x0203, struct.pack("<HHHd", r, c, 15, v))
        return out

    sheets = [
        bof(0x0010) + cells([[("s", 0), ("s", 1)], [("s", 2), ("n", 120.0)], [("s", 3), ("n", 80.0)]]) + record(0x000A),
        bof(0x0010) + cells([[("n", 1.5)]]) + record(0x000A),
    ]
    size = len(globals_stream([0, 0]))
    offsets = [size, size + len(sheets[0])]
    return globals_stream(offsets) + b"".join(sheets)


def ppt_document():
    """A PowerPoint 97 document stream: slide titles and body text in the slide list, two slides."""
    def atom(kind, body, inst=0):
        return struct.pack("<HHI", inst << 4, kind, len(body)) + body

    def container(kind, children):
        body = b"".join(children)
        return struct.pack("<HHI", 0x000F, kind, len(body)) + body

    def text(t, ttype):
        return [atom(0x0F9F, struct.pack("<I", ttype)), atom(0x0FA0, t.encode("utf-16-le"))]

    slide_list = container(0x0FF0, text("Pilot briefing", 0) + text("Board two miles off the breakwater.", 1) + text("Approach", 0) + text("Keep the lighthouse fine on the starboard bow.", 1))
    document = container(0x03E8, [atom(0x03E9, b"\0" * 40), slide_list])
    slides = [container(0x03EE, [atom(0x03EF, b"\0" * 24)]) for _ in range(2)]
    return document + b"".join(slides)


def ole_variants():
    write("xls", "fees.xls", cfb_bytes([
        ("Workbook", biff_workbook()),
        ("\x05SummaryInformation", summary("Harbour fees 2024", "Tomas Lind", app_name="Microsoft Excel")),
    ]))
    write("ppt", "briefing.ppt", cfb_bytes([
        ("PowerPoint Document", ppt_document()),
        ("Current User", struct.pack("<IIIHHBBH", 20, 0xF3D1C4DF, 0, 8, 0x03F4, 3, 0, 0) + b"Pilot\0\0\0"),
        ("\x05SummaryInformation", summary("Pilot briefing", "Mira Castell", app_name="Microsoft PowerPoint")),
    ]))
    write("vsd", "harbour-plan.vsd", cfb_bytes([
        ("VisioDocument", b"Visio (TM) Drawing\r\n" + b"\0" * 44),
        ("\x05SummaryInformation", summary("Harbour plan", "Ben Gull", app_name="Microsoft Visio")),
    ]))
    write("pub", "notice.pub", cfb_bytes([
        ("Quill/QuillSub/CONTENTS", b"CHNKINK" + b"\0" * 57),
        ("Contents", b"\0" * 64),
        ("Envelope", b"\0" * 16),
        ("\x05SummaryInformation", summary("Harbour notice", "Harbour Office", app_name="Microsoft Publisher")),
    ]))
    write("mpp", "dredging.mpp", cfb_bytes([
        ("   114/Props", b"\0" * 64),
        ("   114/TBkndTask/Var2Data", b"\0" * 32),
        ("\x05SummaryInformation", summary("Dredging schedule", "Tomas Lind", app_name="Microsoft Project")),
    ]))
    header = b"HWP Document File".ljust(32, b"\0") + struct.pack("<II", 0x05010001, 0) + b"\0" * 216
    write("hwp", "notice.hwp", cfb_bytes([
        ("FileHeader", header),
        ("DocInfo", b"\0" * 32),
        ("BodyText/Section0", b"\0" * 32),
        ("\x05HwpSummaryInformation", summary("Harbour notice", "Harbour Office", app_name="Hancom Office", fmtid=FMTID_HWP_SUMMARY)),
    ]))
    # A thumbnail cache: catalog plus one thumbnail stream (a tiny JPEG-like payload is not decoded).
    name = "chart.png".encode("utf-16-le") + b"\0\0"
    entry = struct.pack("<IIQ", 16 + len(name) + 4, 1, filetime("2024-05-01T08:30:00Z")) + name + b"\0" * 4
    catalog = struct.pack("<HHIII", 16, 7, 1, 96, 96) + entry
    write("thumbs_db", "Thumbs.db", cfb_bytes([
        ("Catalog", catalog),
        ("1", struct.pack("<III", 12, 1, 4) + b"\xff\xd8\xff\xd9"),
    ]))
    write("cfb", "storage.cfb", cfb_bytes([
        ("Contents", b"Saltmere harbour storage file\0" + b"\0" * 34),
        ("Index/Entries", struct.pack("<II", 1, 0)),
        ("\x05SummaryInformation", summary("Harbour storage", "Harbour Office", app_name="whiff fixtures")),
    ]))
    # A password-protected OOXML file's container: an Agile EncryptionInfo
    # descriptor and an encrypted package (deterministic filler, not a real cipher text).
    agile = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" '
        'xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password">'
        '<keyData saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="AAAAAAAAAAAAAAAAAAAAAA=="/>'
        '<keyEncryptors><keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">'
        '<p:encryptedKey spinCount="100000" saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="AAAAAAAAAAAAAAAAAAAAAA=="/>'
        "</keyEncryptor></keyEncryptors></encryption>"
    ).encode()
    filler = bytes((i * 131 + 7) % 256 for i in range(4096))
    write("office_encrypted", "minutes-locked.docx", cfb_bytes([
        ("EncryptionInfo", struct.pack("<HHI", 4, 4, 0x40) + agile),
        ("EncryptedPackage", struct.pack("<Q", 3500) + filler),
        ("\x06DataSpaces/Version", struct.pack("<I", 60) + "Microsoft.Container.DataSpaces".encode("utf-16-le") + struct.pack("<HHHHHH", 1, 0, 1, 0, 1, 0)),
    ]))
    # The VBA project of report.docm on its own (a table-formatting macro).
    with zipfile.ZipFile(io.BytesIO((OUT / "docm" / "report.docm").read_bytes())) as z:
        write("vba_project", "report-vbaProject.bin", z.read("word/vbaProject.bin"))


if __name__ == "__main__":
    ooxml()
    odf()
    variants()
    ole_variants()
