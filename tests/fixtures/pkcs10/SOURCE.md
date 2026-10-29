# Fixtures for `pkcs10` (Certificate signing request (DER))

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour, reserved `.example` domains). Only public material and encrypted containers are kept; the private keys used to make them were thrown away. Regenerate with `scripts/fixtures/crypto.sh`.

| File | Origin | Licence |
|---|---|---|
| `tides.p10` | openssl req -outform DER: EC P-256 request with an extension request | CC0-1.0 |
| `signer.csr` | openssl req -outform DER: Ed25519 request | CC0-1.0 |
