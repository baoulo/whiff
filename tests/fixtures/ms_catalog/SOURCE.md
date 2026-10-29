# Fixtures for `ms_catalog` (Microsoft security catalog)

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour, reserved `.example` domains): a certificate trust list of two members in makecat's layout, built by Python (no makecat runs on Linux) and signed with the throwaway Ed25519 signer certificate. Regenerate with `scripts/fixtures/crypto.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-tides.cat` | Python + openssl pkeyutl -sign | CC0-1.0 |
