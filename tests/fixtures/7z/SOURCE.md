# Fixtures for `7z` (7-Zip archive)

Every file here was made for whiff's tests and is released under CC0-1.0. The content is a few
short texts about a fictitious harbour (Saltmere, Ben Gull, Ana Lighthouse), with fixed times
and the owner `saltmere:harbour`. Regenerate with `scripts/fixtures/archives.sh`.

| File | Origin | Licence |
|---|---|---|
| `harbour-7zip-bcj.7z` | 7-Zip 24.09 (`7zz a -mf=BCJ -m0=LZMA -ms=off`): a BCJ filter before LZMA, one folder per file | CC0-1.0 |
| `harbour-7zip-copy.7z` | 7-Zip 24.09 (`7zz a -m0=Copy`): stored | CC0-1.0 |
| `harbour-7zip-encrypted.7z` | 7-Zip 24.09 (`7zz a -mhe=on`): AES-256 data and header (password `saltmere`) | CC0-1.0 |
| `harbour-7zip-solid.7z` | 7-Zip 24.09 (`7zz a -mx=9 -ms=on`): one solid LZMA2 folder | CC0-1.0 |
| `harbour-bsdtar.7z` | bsdtar 3.5 / libarchive 3.7 (`--format 7zip`) | CC0-1.0 |
