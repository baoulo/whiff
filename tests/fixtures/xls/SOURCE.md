# Fixtures for `xls` (Excel 97-2003 workbook)

Every file here was made for whiff's tests and is released under CC0-1.0. People, places,
companies and addresses (Saltmere, `example.org`, `*.example`) are fictitious.
The crafted file is a minimal, plain compound file; the Apache POI ones are written by an independent
implementation. Exports from Microsoft Office can be added next to them.

| File | Origin | Licence |
|---|---|---|
| `fees.xls` | Compound file written by `scripts/fixtures/craft_documents.py`; plain structure, no macros or embedded objects | CC0-1.0 |
| `dues-poi.xls` | Written by Apache POI HSSF (`scripts/fixtures/documents/PoiFixtures.java`); BIFF8 with properties, a hidden sheet, a formula, a defined name, a cell note, a link | CC0-1.0 |
| `dues-poi-locked.xls` | The same workbook encrypted by Apache POI with RC4 CryptoAPI (test password `harbourmaster`) | CC0-1.0 |
