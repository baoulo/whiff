# Fixtures for `dotnet` (.NET assembly (CLI))

Every file here was made for whiff's tests and is released under CC0-1.0. The programs print a fictitious harbour's tide table (Saltmere Harbour); keys were made for the run and are not secrets. Regenerate with `scripts/fixtures/executables.sh` (`tides-cli.dll`) and `scripts/fixtures/bytecode.sh` (`Saltmere.Tides.dll`).

| File | Origin | Licence |
|---|---|---|
| `tides-cli.dll` | craft_executables.py: a PE32 DLL with a CLI header (runtime 2.5, IL only) and a metadata root (v4.0.30319), no code | CC0-1.0 |
| `Saltmere.Tides.dll` | .NET SDK 8.0 `dotnet build -c Release` (deterministic, embedded PDB): assembly attributes, three references, a P/Invoke import, records | CC0-1.0 |
