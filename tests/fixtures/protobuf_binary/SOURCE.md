# Fixtures for `protobuf_binary` (Protocol Buffers binary)

Files made for whiff's tests, CC0-1.0, for a fictitious harbour (Saltmere Harbour) with fixed times; names, devices, teams and addresses (`example.org`) are fictitious. Regenerate with `scripts/fixtures/binser.sh`.

| File | Origin | Licence |
|---|---|---|
| `tide.binpb` | protoc 3.21.12 `--encode` | CC0-1.0 |
| `readings.pb` | protoc `--encode`, three messages each prefixed with its varint length | CC0-1.0 |
