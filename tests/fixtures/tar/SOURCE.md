# Fixtures for `tar` (tar archive)

Every file here was made for whiff's tests and is released under CC0-1.0. The content is a few
short texts about a fictitious harbour (Saltmere, Ben Gull, Ana Lighthouse), with fixed times
and the owner `saltmere:harbour`. Regenerate with `scripts/fixtures/archives.sh`.

| File | Origin | Licence |
|---|---|---|
| `harbour-bsdtar-gnu.tar` | bsdtar (`--format gnutar`) | CC0-1.0 |
| `harbour-bsdtar-pax.tar` | bsdtar (`--format pax`) | CC0-1.0 |
| `harbour-bsdtar-ustar.tar` | bsdtar (`--format ustar`) | CC0-1.0 |
| `harbour-bsdtar-v7.tar` | bsdtar (`--format v7tar`) | CC0-1.0 |
| `harbour-tarfile-gnu.tar` | Python `tarfile` (GNU format): a long name (`././@LongLink`) and a symbolic link | CC0-1.0 |
| `harbour-tarfile-pax.tar` | Python `tarfile` (pax format): a global `comment` and a non-ASCII name | CC0-1.0 |
