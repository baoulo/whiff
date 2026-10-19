# Fixtures for `office_encrypted` (Encrypted Office document)

Every file here was made for whiff's tests and is released under CC0-1.0. People, places,
companies and addresses (Saltmere, `example.org`, `*.example`) are fictitious.
`minutes-locked.docx` is crafted: deterministic filler behind a real agile `EncryptionInfo` descriptor.
The Apache POI files are genuinely encrypted; their salts are random, so they change whenever they are regenerated.

| File | Origin | Licence |
|---|---|---|
| `minutes-locked.docx` | Compound file written by `scripts/fixtures/craft_documents.py`; plain structure, no macros or embedded objects | CC0-1.0 |
| `notice-agile.docx` | `docx/notice-docxrs.docx` encrypted by Apache POI, agile encryption (AES-128, SHA-1, test password `harbourmaster`) | CC0-1.0 |
| `notice-standard.docx` | The same document with ECMA-376 standard encryption (AES-128) | CC0-1.0 |
