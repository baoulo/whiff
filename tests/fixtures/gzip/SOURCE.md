# Fixtures for `gzip` (gzip)

Every file here was made for whiff's tests and is released under CC0-1.0. The content is a few
short texts about a fictitious harbour (Saltmere, Ben Gull, Ana Lighthouse), with fixed times
and the owner `saltmere:harbour`. Regenerate with `scripts/fixtures/archives.sh`.

| File | Origin | Licence |
|---|---|---|
| `harbour-gzip.tgz` | `gzip -9 -N` of a pax tar of the payload | CC0-1.0 |
| `log-bgzf-crafted.csv.gz` | Written by `craft_archives.py`: BGZF blocks (the `BC` subfield) and the empty end block | CC0-1.0 |
| `notes-crafted.txt.gz` | Written by `craft_archives.py`: name, comment and an extra subfield | CC0-1.0 |
| `notes-gzip-noname.txt.gz` | `gzip -9 -n`: no name, no time | CC0-1.0 |
| `notes-gzip.txt.gz` | `gzip -9 -N` | CC0-1.0 |
