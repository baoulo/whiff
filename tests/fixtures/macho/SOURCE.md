# Fixtures for `macho` (Mach-O / universal binary)

Every file here was made for whiff's tests and is released under CC0-1.0. The programs print a fictitious harbour's tide table (Saltmere Harbour); keys were made for the run and are not secrets. Regenerate with `scripts/fixtures/executables.sh`.

| File | Origin | Licence |
|---|---|---|
| `tides-clang-arm64` | clang -arch arm64 (macOS 12), linker-signed ad hoc | CC0-1.0 |
| `tides-clang-universal` | lipo of the arm64 and x86_64 builds, signed ad hoc with codesign | CC0-1.0 |
| `tides-clang-runtime` | the arm64 build signed ad hoc with codesign: hardened runtime and two entitlements (App Sandbox, library validation off) | CC0-1.0 |
| `libsaltmere.dylib` | clang -dynamiclib with an @rpath install name and versions | CC0-1.0 |
| `tides-clang-dwarf.o` | clang -g -c: an object with DWARF 5 | CC0-1.0 |
