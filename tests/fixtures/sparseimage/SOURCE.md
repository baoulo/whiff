# Fixtures for `sparseimage` (Apple sparse disk image)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere.sparseimage` | hdiutil convert -format UDSP -imagekey sparse-band-size=64 of `raw_disk/saltmere-gpt.img` | CC0-1.0 |
