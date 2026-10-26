# Fixtures for `deb` (Debian package)

Every file here was made for whiff's tests and is released under CC0-1.0. The packages describe a fictitious harbour app (Saltmere Tides by Ana Lighthouse, Saltmere Harbour), with fixed times; keys and certificates were made for the run and thrown away. Regenerate with `scripts/fixtures/packages.sh`.

| File | Origin | Licence |
|---|---|---|
| `saltmere-tides_1.2.0-1_all-zstd.deb` | craft_packages.py (zstd control and data archives, as Ubuntu builds them) | CC0-1.0 |
| `saltmere-tides_1.2.0-1_all.deb` | craft_packages.py (dpkg-deb's layout: control.tar.xz with a postinst, md5sums and conffiles; data.tar.xz with a DEP-5 copyright file) | CC0-1.0 |
