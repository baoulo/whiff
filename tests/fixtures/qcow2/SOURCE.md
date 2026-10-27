# Fixtures for `qcow2` (QEMU copy-on-write disk)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere.qcow2` | qemu-img convert -O qcow2 -o cluster_size=4096 | CC0-1.0 |
| `saltmere-compressed.qcow2` | qemu-img convert -c (zlib clusters), then qemu-img snapshot -c | CC0-1.0 |
| `saltmere-overlay.qcow2` | qemu-img create -b saltmere.qcow2 (an overlay naming its backing file) | CC0-1.0 |
| `saltmere-v1.qcow` | qemu-img convert -O qcow (version 1) | CC0-1.0 |
