# Fixtures for `class` (Java class)

Every file here was made for whiff's tests and is released under CC0-1.0. The programs print a fictitious harbour's tide table (Saltmere Harbour). Regenerate with `scripts/fixtures/bytecode.sh`.

| File | Origin | Licence |
|---|---|---|
| `module-info.class` | javac 21 --release 21 -g: a module descriptor (requires java.logging, exports a package) | CC0-1.0 |
| `TideTable.class` | javac 21 --release 21 -g: a final class with a class annotation, a lambda and logging | CC0-1.0 |
| `Tide.class` | javac 21 --release 21 -g: a sealed interface permitting two records | CC0-1.0 |
| `Tide$High.class` | javac 21 --release 21 -g: a record nested in the sealed interface | CC0-1.0 |
| `Gauge.class` | javac 21 --release 21 -g: a runtime-retained annotation type | CC0-1.0 |
| `Tides-java8.class` | javac 21 --release 8 -g:none: a Java 8 class without debug information | CC0-1.0 |
