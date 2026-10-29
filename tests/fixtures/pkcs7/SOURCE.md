# Fixtures for `pkcs7` (PKCS#7 / CMS)

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour, reserved `.example` domains). Only public material and encrypted containers are kept; the private keys used to make them were thrown away. Regenerate with `scripts/fixtures/crypto.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-chain.p7b` | openssl crl2pkcs7: certificate bundle | CC0-1.0 |
| `tides.p7s` | openssl cms -sign: detached Ed25519 signature with the signer chain | CC0-1.0 |
| `tides.p7m` | openssl cms -encrypt: AES-256 envelope for one recipient | CC0-1.0 |
