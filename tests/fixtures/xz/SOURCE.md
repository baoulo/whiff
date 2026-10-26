# Fixtures for `xz` (xz)

Every file here was made for whiff's tests and is released under CC0-1.0. The content is a few
short texts about a fictitious harbour (Saltmere, Ben Gull, Ana Lighthouse), with fixed times
and the owner `saltmere:harbour`. Regenerate with `scripts/fixtures/archives.sh`.

| File | Origin | Licence |
|---|---|---|
| `harbour-wall-xz.txt.xz` | `xz -6` of one sentence (also used by the xz decoder's unit test) | CC0-1.0 |
| `harbour-xz-x86.txz` | `xz --x86 --lzma2=preset=6` of a pax tar: a BCJ filter before LZMA2 | CC0-1.0 |
| `notes-xz.txt.xz` | `xz -6` | CC0-1.0 |
| `saltmere-tides-1.2.0-noarch-1_saltmere.txz` | `scripts/fixtures/packages.sh` (craft_packages.py): a Slackware package, detected as one inside the xz stream | CC0-1.0 |
