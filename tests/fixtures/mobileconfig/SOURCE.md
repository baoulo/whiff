# Fixtures for `mobileconfig` (Apple configuration profile)

Files made for whiff's tests, CC0-1.0, for a fictitious harbour (Saltmere Harbour) with fixed times; names, devices, teams and addresses (`example.org`) are fictitious. Regenerate with `scripts/fixtures/apple.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-guest.mobileconfig` | plutil -create / -insert (Wi-Fi without a password, DNS over HTTPS) | CC0-1.0 |
| `saltmere-guest-signed.mobileconfig` | openssl cms -sign with a throwaway certificate (craft_apple.py) | CC0-1.0 |
