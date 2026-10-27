# Fixtures for `uimage` (U-Boot legacy image)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-kernel.uimg` | mkimage -T kernel -C gzip (the stand-in kernel) | CC0-1.0 |
| `saltmere-multi.uimg` | mkimage -T multi (kernel and ramdisk) | CC0-1.0 |
