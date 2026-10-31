# Fixtures for `openssh_private_key` (OpenSSH private key)

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour, reserved `.example` domains): encrypted with the published passphrase "saltmere" (bcrypt KDF, aes256-ctr); throwaway keys used for nothing else. Regenerate with `scripts/fixtures/crypto.sh`.

| File | Origin | Licence |
|---|---|---|
| `id_ed25519` | ssh-keygen -t ed25519 -N saltmere | CC0-1.0 |
| `id_ecdsa` | ssh-keygen -t ecdsa -b 256 -N saltmere | CC0-1.0 |
