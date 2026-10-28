# Fixtures for `ebpf` (eBPF object)

Every file here was made for whiff's tests and is released under CC0-1.0. The programs print a fictitious harbour's tide table (Saltmere Harbour); keys were made for the run and are not secrets. Regenerate with `scripts/fixtures/executables.sh`.

| File | Origin | Licence |
|---|---|---|
| `tides-xdp.bpf.o` | clang --target=bpf -c: an XDP program that passes every packet | CC0-1.0 |
