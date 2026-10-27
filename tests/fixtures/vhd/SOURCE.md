# Fixtures for `vhd` (Microsoft virtual hard disk)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`. Files named `*-head*` are the first 256 KiB of a bigger image (the fixture size limit): every structure whiff reads from the start of the image is there, the data past it is not.

| File | Origin | Licence |
|---|---|---|
| `saltmere-fixed.vhd` | qemu-img convert -O vpc -o subformat=fixed | CC0-1.0 |
| `saltmere-dynamic-head.vhd` | qemu-img convert -O vpc (dynamic); the first 256 KiB of the image (footer copy, dynamic header, BAT, the start of the 2 MiB block); the trailing footer is past the cut | CC0-1.0 |
