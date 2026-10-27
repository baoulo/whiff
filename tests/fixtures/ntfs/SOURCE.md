# Fixtures for `ntfs` (NTFS file system image)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`. Files named `*-head*` are the first 256 KiB of a bigger image (the fixture size limit): every structure whiff reads from the start of the image is there, the data past it is not.

| File | Origin | Licence |
|---|---|---|
| `saltmere-head.ntfs` | mkntfs + ntfscp; the first 256 KiB of a 2 MiB volume (boot sector and MFT) | CC0-1.0 |
