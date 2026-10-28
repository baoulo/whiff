# Fixtures for `pe` (Windows PE executable / DLL)

Every file here was made for whiff's tests and is released under CC0-1.0. The programs print a fictitious harbour's tide table (Saltmere Harbour); keys were made for the run and are not secrets. Regenerate with `scripts/fixtures/executables.sh`.

| File | Origin | Licence |
|---|---|---|
| `tides-mingw64.exe` | x86_64-w64-mingw32-gcc with windres (version resource, manifest), ASLR, DEP, high-entropy ASLR | CC0-1.0 |
| `tides-mingw32.exe` | i686-w64-mingw32-gcc (PE32) | CC0-1.0 |
| `saltmere-mingw64.dll` | x86_64-w64-mingw32-gcc -shared (two exports) | CC0-1.0 |
| `tides-signed.exe` | `tides-mingw64.exe` signed with osslsigncode (SHA-256 Authenticode, a throwaway self-signed key, no timestamp) | CC0-1.0 |
| `tides-setup-nsis.exe` | makensis: an NSIS installer (LZMA) holding the tide table | CC0-1.0 |
