# Fixtures for `udf` (UDF disc image)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-udf102.udf` | mkudffs -r 0x0102 -b 512 -m hd, filled through a Linux loop mount | CC0-1.0 |
| `saltmere-udf201.udf` | mkudffs -r 0x0201 -b 512 -m hd, filled through a Linux loop mount | CC0-1.0 |
