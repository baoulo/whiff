# Fixtures for `pkcs12` (PKCS#12 / PFX)

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour, reserved `.example` domains). Only public material and encrypted containers are kept; the private keys used to make them were thrown away. Regenerate with `scripts/fixtures/crypto.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-chain.p12` | openssl pkcs12 -export -nokeys: certificates in a PBES2 / AES-256 encrypted safe | CC0-1.0 |
| `saltmere-chain-clear.pfx` | openssl pkcs12 -export -nokeys -certpbe NONE: certificates in the clear | CC0-1.0 |
