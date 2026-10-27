# Fixtures for `iso9660` (ISO 9660 disc image)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-rockridge.iso` | xorriso -as mkisofs -R -J (Rock Ridge, Joliet, publisher and preparer) | CC0-1.0 |
| `saltmere-plain.iso` | genisoimage (plain ISO 9660 names) | CC0-1.0 |
| `saltmere-live-efi.iso` | xorriso with an El Torito EFI boot image (mkfs.fat + mtools; the loader is a text placeholder) and a symbolic link | CC0-1.0 |
