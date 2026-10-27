# Fixtures for `luks` (LUKS encrypted volume)

Every file here was made for whiff's tests and is released under CC0-1.0. The volumes hold a fictitious harbour's tide table (Saltmere Harbour); keys and passphrases were made for the run and are not secrets. Regenerate with `scripts/fixtures/disks.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-vault.luks` | cryptsetup luksFormat --type luks2 (aes-xts-plain64, PBKDF2, a throwaway passphrase) | CC0-1.0 |
