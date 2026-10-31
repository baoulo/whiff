# Fixtures for `pem` (PEM file)

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour, reserved `.example` domains). Only public material and encrypted containers are kept; the private keys used to make them were thrown away. Regenerate with `scripts/fixtures/crypto.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-chain.pem` | openssl: leaf (EC P-256), issuing CA (EC P-384), root (RSA 3072) certificates | CC0-1.0 |
| `tides-with-text.crt` | openssl x509 -text: the leaf certificate after its text dump | CC0-1.0 |
| `tides.csr` | openssl req: certificate request with subject alternative names | CC0-1.0 |
| `issuing-ca.crl` | openssl ca -gencrl: CRL revoking one certificate | CC0-1.0 |
| `saltmere-chain.p7b` | openssl crl2pkcs7: PKCS#7 certificate bundle (PEM) | CC0-1.0 |
| `tides-public.pem` | openssl pkey -pubout: EC P-256 and Ed25519 public keys | CC0-1.0 |
| `ferry-rsa-public.pem` | openssl rsa -RSAPublicKey_out: PKCS#1 RSA public key | CC0-1.0 |
