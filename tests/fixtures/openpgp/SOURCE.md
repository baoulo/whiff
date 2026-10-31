# Fixtures for `openpgp` (OpenPGP data)

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour, reserved `.example` domains). Only public material and encrypted containers are kept; the private keys used to make them were thrown away. Regenerate with `scripts/fixtures/crypto.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-office.gpg` | gpg --export: Ed25519 primary key, signing and Cv25519 encryption subkeys, two user IDs | CC0-1.0 |
| `ferry-desk.asc` | gpg --armor --export: RSA 3072 key that expired on 2026-01-01 | CC0-1.0 |
| `tides.txt.sig` | gpg --detach-sign | CC0-1.0 |
| `tides.txt.asc` | gpg --armor --detach-sign | CC0-1.0 |
| `tides-clearsigned.asc` | gpg --clearsign | CC0-1.0 |
| `tides-signed.gpg` | gpg --sign: compressed, one-pass signed literal data | CC0-1.0 |
| `tides-for-office.gpg` | gpg --encrypt: one recipient | CC0-1.0 |
| `tides-two-recipients.asc` | gpg --armor --encrypt: two recipients | CC0-1.0 |
| `tides-passphrase.gpg` | gpg --symmetric --cipher-algo AES256 | CC0-1.0 |
