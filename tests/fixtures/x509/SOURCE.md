# Fixtures for `x509` (X.509 certificate (DER))

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour, reserved `.example` domains). Only public material and encrypted containers are kept; the private keys used to make them were thrown away. Regenerate with `scripts/fixtures/crypto.sh`.

| File | Origin | Licence |
|---|---|---|
| `tides.cer` | openssl x509 -outform DER: server certificate (EC P-256, SANs, key usage) | CC0-1.0 |
| `saltmere-root.der` | openssl req -x509: self-signed root CA (RSA 3072, SHA-384) | CC0-1.0 |
| `ferry-expired.crt` | openssl x509: certificate valid during 2024 only | CC0-1.0 |
