# Fixtures for `elf` (ELF executable / shared object)

Every file here was made for whiff's tests and is released under CC0-1.0. The programs print a fictitious harbour's tide table (Saltmere Harbour); keys were made for the run and are not secrets. Regenerate with `scripts/fixtures/executables.sh`.

| File | Origin | Licence |
|---|---|---|
| `tides-gcc-hardened` | gcc -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -z relro -z now, stripped (arm64 Linux) | CC0-1.0 |
| `tides-gcc-plain` | gcc -O0 -fno-stack-protector -no-pie -z norelro -z execstack (arm64 Linux) | CC0-1.0 |
| `libsaltmere.so.1` | gcc -shared with a SONAME and an `$ORIGIN` run path | CC0-1.0 |
| `tides-gcc-dwarf.o` | gcc -g -c: a relocatable object with DWARF 5 | CC0-1.0 |
| `tide-clang-x86_64.o` | clang --target=x86_64-linux-gnu -g -c | CC0-1.0 |
| `tide-clang-riscv64.o` | clang --target=riscv64-linux-gnu -c | CC0-1.0 |
| `tide-clang-armv7.o` | clang --target=armv7-linux-gnueabihf -c (32-bit) | CC0-1.0 |
| `tide-clang-ppc64.o` | clang --target=powerpc64-linux-gnu -c (big-endian) | CC0-1.0 |
