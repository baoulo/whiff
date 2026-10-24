# Fixtures for `zip` (ZIP archive)

Every file here was made for whiff's tests and is released under CC0-1.0. The content is a few
short texts about a fictitious harbour (Saltmere, Ben Gull, Ana Lighthouse), with fixed times
and the owner `saltmere:harbour`. Regenerate with `scripts/fixtures/archives.sh`.

| File | Origin | Licence |
|---|---|---|
| `harbour-7zip-aes.zip` | 7-Zip 24.09 (`-mem=AES256`, password `saltmere`) | CC0-1.0 |
| `harbour-7zip-zipcrypto.zip` | 7-Zip 24.09 (`-mem=ZipCrypto`, password `saltmere`) | CC0-1.0 |
| `harbour-bsdtar.zip` | bsdtar (`--format zip`) | CC0-1.0 |
| `harbour-infozip.zip` | Info-ZIP 3.0 (`zip -r -y`, then `zip -z` for the comment): Unix extra fields, a symbolic link | CC0-1.0 |
| `harbour-python.zip` | Python `zipfile`: stored, deflate, bzip2 and LZMA entries, a comment and a symbolic link | CC0-1.0 |
