# Fixtures for `wasm` (WebAssembly module)

Every file here was made for whiff's tests and is released under CC0-1.0. The programs print a fictitious harbour's tide table (Saltmere Harbour); keys were made for the run and are not secrets. Regenerate with `scripts/fixtures/executables.sh`.

| File | Origin | Licence |
|---|---|---|
| `tides-clang.wasm` | clang --target=wasm32 / wasm-ld (producers, target features) | CC0-1.0 |
| `tides-wasi.wasm` | wat2wasm --debug-names: WASI imports, memory limits, a data segment | CC0-1.0 |
