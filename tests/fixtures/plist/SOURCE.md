# Fixtures for `plist` (Apple plist (XML))

Files made for whiff's tests, CC0-1.0, for a fictitious harbour (Saltmere Harbour) with fixed times; names, devices, teams and addresses (`example.org`) are fictitious. Regenerate with `scripts/fixtures/apple.sh`.

| File | Origin | Licence |
|---|---|---|
| `harbour-prefs.plist` | plutil -create / -insert | CC0-1.0 |
| `org.saltmere.tidesync.plist` | plutil -create / -insert (a launchd job) | CC0-1.0 |
| `old-style.plist` | Written by hand (old-style / OpenStep), checked with `plutil -lint` | CC0-1.0 |
