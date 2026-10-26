# Fixtures for `pkg` (macOS installer package)

Every file here was made for whiff's tests and is released under CC0-1.0. The packages describe a fictitious harbour app (Saltmere Tides by Ana Lighthouse, Saltmere Harbour), with fixed times; keys and certificates were made for the run and thrown away. Regenerate with `scripts/fixtures/packages.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-tides-component.pkg` | craft_packages.py (XAR: PackageInfo, gzip cpio Payload and Scripts with a postinstall; checked with xar and 7-Zip) | CC0-1.0 |
| `saltmere-tides-product.pkg` | craft_packages.py (Distribution with installer JavaScript around the component) | CC0-1.0 |
