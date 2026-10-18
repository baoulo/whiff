# Fixtures for `ppt` (PowerPoint 97-2003 presentation)

Every file here was made for whiff's tests and, except where the table says otherwise, is released under CC0-1.0. People, places,
companies and addresses (Saltmere, `example.org`, `*.example`) are fictitious.
The crafted file is a minimal, plain compound file; the Apache POI ones are written by an independent
implementation. Exports from Microsoft Office can be added next to them.

| File | Origin | Licence |
|---|---|---|
| `briefing.ppt` | Compound file written by `scripts/fixtures/craft_documents.py`; plain structure, no macros or embedded objects | CC0-1.0 |
| `briefing-poi.ppt` | Written by Apache POI HSLF (`scripts/fixtures/documents/PoiFixtures.java`); three slides with titles and text | CC0-1.0; the slide master and property sets come from Apache POI's blank presentation (Apache-2.0) |
| `briefing-poi-locked.ppt` | The same presentation encrypted by Apache POI with RC4 CryptoAPI (test password `harbourmaster`) | as above |
