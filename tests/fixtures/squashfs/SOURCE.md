# Fixtures for `squashfs` (squashfs file system)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-gzip.squashfs` | mksquashfs -comp gzip (fragments, a symbolic link) | CC0-1.0 |
| `saltmere-xz.squashfs` | mksquashfs -comp xz | CC0-1.0 |
| `saltmere-zstd.squashfs` | mksquashfs -comp zstd | CC0-1.0 |
