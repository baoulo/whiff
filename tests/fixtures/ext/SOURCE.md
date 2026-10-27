# Fixtures for `ext` (ext2 / ext3 / ext4 file system image)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere.ext2` | mke2fs -t ext2 -d (files copied in by mke2fs) | CC0-1.0 |
| `saltmere.ext4` | mke2fs -t ext4 -O ^has_journal -d (extents, 64bit, flex_bg, metadata_csum) | CC0-1.0 |
