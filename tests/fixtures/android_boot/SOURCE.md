# Fixtures for `android_boot` (Android boot image)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-boot-v2.img` | mkbootimg --header_version 2 (a stand-in kernel from craft_disks.py: zeros, the arm64 Image magic and a version banner, no code; a gzip cpio ramdisk; a dtc device tree) | CC0-1.0 |
| `saltmere-boot-v4.img` | mkbootimg --header_version 4 | CC0-1.0 |
| `saltmere-vendor_boot.img` | mkbootimg --header_version 4 --vendor_boot | CC0-1.0 |
