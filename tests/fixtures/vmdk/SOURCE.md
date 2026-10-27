# Fixtures for `vmdk` (VMware virtual disk)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-sparse.vmdk` | qemu-img convert -O vmdk (monolithicSparse) of `raw_disk/saltmere-gpt.img` | CC0-1.0 |
| `saltmere-stream.vmdk` | qemu-img convert -O vmdk -o subformat=streamOptimized (deflate grains) | CC0-1.0 |
| `saltmere-descriptor.vmdk` | qemu-img convert -O vmdk -o subformat=monolithicFlat: the descriptor file (its flat extent is not kept) | CC0-1.0 |
