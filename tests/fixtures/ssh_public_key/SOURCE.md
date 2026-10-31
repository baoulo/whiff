# Fixtures for `ssh_public_key` (SSH public key)

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour, reserved `.example` domains). Only public material and encrypted containers are kept; the private keys used to make them were thrown away. Regenerate with `scripts/fixtures/crypto.sh`.

| File | Origin | Licence |
|---|---|---|
| `id_ed25519.pub` | ssh-keygen -t ed25519 | CC0-1.0 |
| `ferry_rsa.pub` | ssh-keygen -t rsa -b 3072 | CC0-1.0 |
| `id_ed25519-cert.pub` | ssh-keygen -s: user certificate with principals, options and validity | CC0-1.0 |
| `gauge_host-cert.pub` | ssh-keygen -s -h: host certificate for an ECDSA P-384 key | CC0-1.0 |
| `gauge-rfc4716.pub` | ssh-keygen -e: the ECDSA key as an RFC 4716 file | CC0-1.0 |
