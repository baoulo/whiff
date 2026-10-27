# Fixtures for `intel_hex` (Intel HEX)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-fw.hex` | objcopy -I binary -O ihex --change-addresses 0x08000000 | CC0-1.0 |
