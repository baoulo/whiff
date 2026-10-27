# Fixtures for `e01` (Expert Witness / EnCase evidence file)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-gauge.E01` | ewfacquire -f encase6 -c deflate:best -d sha1 of `raw_disk/saltmere-gpt.img` (fictitious case metadata) | CC0-1.0 |
| `saltmere-card-encase5.E01` | ewfacquire -f encase5 -c none of `fat/saltmere-floppy.ima` | CC0-1.0 |
