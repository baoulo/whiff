# Fixtures for `appimage` (AppImage)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `Saltmere_Tides-1.2.0-x86_64.AppImage` | craft_disks.py appimage-runtime (an ELF header with the AppImage magic and .upd_info / .sha256_sig sections, no code) followed by mksquashfs of an AppDir (desktop entry, AppStream metadata) | CC0-1.0 |
