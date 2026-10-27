# Fixtures for `raw_disk` (Raw disk image)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-gpt.img` | sgdisk (GPT: an empty EFI system partition and a basic-data partition), mkfs.fat + mtools (FAT12 volume with files) | CC0-1.0 |
| `saltmere-mbr.img` | sfdisk (MBR: a bootable Linux partition, an extended partition with a logical swap partition), mke2fs -d (ext2), mkswap | CC0-1.0 |
