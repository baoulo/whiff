# Fixtures for `srec` (Motorola S-record)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-fw.s19` | srec_cat -header -execution-start-address (S1 records) | CC0-1.0 |
| `saltmere-fw.s37` | srec_cat -address-length=4 (S3 records) | CC0-1.0 |
