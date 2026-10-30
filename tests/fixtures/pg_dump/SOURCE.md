# Fixtures for `pg_dump` (PostgreSQL custom-format dump)

Every file here was made for whiff's tests and is released under CC0-1.0, for a fictitious harbour (Saltmere Harbour): made with PostgreSQL 17 pg_dump -Fc. Regenerate with `scripts/fixtures/db.sh`.

| File | Origin | Licence |
|---|---|---|
| `harbour.dump` | a schema with two tables, a view, a function, an index and a foreign key (gzip) | CC0-1.0 |
| `harbour-stations-uncompressed.dump` | one table, -Z 0 | CC0-1.0 |
