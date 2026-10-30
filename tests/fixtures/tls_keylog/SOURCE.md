# Fixtures for `tls_keylog` (TLS key log)

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour, reserved `.example` domains): the secrets of one TLS 1.3 session between openssl s_client and s_server on the loopback interface, with a throwaway certificate. Regenerate with `scripts/fixtures/crypto.sh`.

| File | Origin | Licence |
|---|---|---|
| `tides-session.keylog` | openssl s_client -keylogfile | CC0-1.0 |
