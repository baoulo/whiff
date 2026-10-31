# Fixtures for `minisign` (minisign / signify)

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour, reserved `.example` domains). Only public material and encrypted containers are kept; the private keys used to make them were thrown away. Regenerate with `scripts/fixtures/crypto.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere.pub` | minisign -G: public key | CC0-1.0 |
| `tides.txt.minisig` | minisign -S: prehashed signature with a trusted comment | CC0-1.0 |
| `saltmere-signify.pub` | signify -G: public key | CC0-1.0 |
| `tides.txt.sig` | signify -S: signature | CC0-1.0 |
