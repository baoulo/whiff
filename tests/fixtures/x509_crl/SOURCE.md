# Fixtures for `x509_crl` (Certificate revocation list (DER))

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour, reserved `.example` domains). Only public material and encrypted containers are kept; the private keys used to make them were thrown away. Regenerate with `scripts/fixtures/crypto.sh`.

| File | Origin | Licence |
|---|---|---|
| `issuing-ca.crl` | openssl ca -gencrl: one revoked certificate, CRL number 1 | CC0-1.0 |
