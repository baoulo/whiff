# Fixtures for `elf_core` (ELF core dump)

Every file here was made for whiff's tests and is released under CC0-1.0. The programs print a fictitious harbour's tide table (Saltmere Harbour); keys were made for the run and are not secrets. Regenerate with `scripts/fixtures/executables.sh`.

| File | Origin | Licence |
|---|---|---|
| `tides.core` | gdb `generate-core-file` of a static tide program stopped by its trap; craft_executables.py `trim-core` kept the headers and notes and dropped the dumped memory (the segments keep their addresses and sizes) | CC0-1.0 |
