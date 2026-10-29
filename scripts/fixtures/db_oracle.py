#!/usr/bin/env python3
"""Compare whiff's database extractors with the engines themselves.

    db_oracle.py generate [N]        write N random SQLite databases (default 100)
                                     into target/db-corpus/generated/
    db_oracle.py collect DIR...      copy SQLite, DBF and Access files into
                                     target/db-corpus/mac/
    db_oracle.py check               compare whiff with the references

References:
* SQLite: Python's sqlite3 module (opened read-only, immutable): page size,
  page count, encoding, user version, application ID, free pages, the
  schema's tables, indexes, views and triggers, every table's columns
  (PRAGMA table_xinfo: name, declared type, NOT NULL, primary key) and
  count(*) (whiff run with --profile full, so counts are exact);
* DBF: ogrinfo (GDAL, in the whiff-db image): record count less deleted
  records, field names, types and widths;
* Access: mdbtools (mdb-ver, mdb-tables, mdb-count) on the fixture and on
  the Access 2016 file db.sh leaves in its work folder;
* engine fixtures: DuckDB's own database_size, mdb_stat, db5.3_stat,
  sst_dump --show_properties and pg_restore -l.

The generated databases vary page size (512 to 65536), text encoding,
auto-vacuum, quoting, declared types, column and table constraints,
WITHOUT ROWID and STRICT tables, FTS5 tables, indexes, views, triggers,
overflowing rows and deleted rows. The corpus is copied (never committed)
from system folders and /Applications, not from the home folder.
"""

import glob
import json
import os
import random
import shutil
import sqlite3
import subprocess
import sys
from collections import Counter, defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CORPUS = os.path.join(ROOT, "target", "db-corpus")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
WHIFF = os.path.join(ROOT, "target", "release", "whiff")
IMAGE = "whiff-db"

TYPES = ["INTEGER", "TEXT", "REAL", "BLOB", "", "VARCHAR(40)", "double precision", "decimal(10, 2)", "NUMERIC",
         "unsigned big int", "DATETIME", "BOOLEAN", "nvarchar ( 12 )", "ANY"]
STRICT_TYPES = ["INTEGER", "TEXT", "REAL", "BLOB", "ANY", "INT"]
WORDS = ["tide", "station", "height", "gauge", "quay", "ferry", "note", "at", "depth", "Ålesund", "high water",
         'say "hi"', "order", "group", "x", "Δ"]


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def generate(n):
    out = os.path.join(CORPUS, "generated")
    os.makedirs(out, exist_ok=True)
    for i in range(n):
        rnd = random.Random(1000 + i)
        path = os.path.join(out, f"gen-{i:03d}.sqlite")
        if os.path.exists(path):
            os.remove(path)
        db = sqlite3.connect(path)
        db.execute(f"PRAGMA page_size={rnd.choice([512, 1024, 2048, 4096, 8192, 16384, 32768, 65536])}")
        db.execute(f"PRAGMA encoding='{rnd.choice(['UTF-8', 'UTF-16le', 'UTF-16be'])}'")
        db.execute(f"PRAGMA auto_vacuum={rnd.choice([0, 1, 2])}")
        db.execute(f"PRAGMA user_version={rnd.randrange(0, 1 << 20)}")
        db.execute(f"PRAGMA application_id={rnd.randrange(0, 1 << 31)}")
        tables = []
        for t in range(rnd.randint(1, 8)):
            name = f"{rnd.choice(WORDS)}_{t}"
            strict = rnd.random() < 0.2
            ncols = rnd.randint(1, 9)
            cols, defs = [], []
            for c in range(ncols):
                cname = f"{rnd.choice(WORDS)} {c}" if rnd.random() < 0.3 else f"{rnd.choice(WORDS).split()[0]}{c}"
                ctype = rnd.choice(STRICT_TYPES if strict else TYPES)
                cons = []
                if rnd.random() < 0.3:
                    cons.append("NOT NULL")
                if rnd.random() < 0.15:
                    cons.append("UNIQUE")
                if rnd.random() < 0.2:
                    cons.append(rnd.choice(["DEFAULT 0", "DEFAULT 'x'", "DEFAULT (1 + 2)", "CHECK (1 OR 0)"]))
                if rnd.random() < 0.1 and tables:
                    cons.append(f"REFERENCES {quote(rnd.choice(tables))}")
                q = rnd.choice([quote, lambda s: "[" + s + "]", lambda s: "`" + s + "`"]) if " " in cname or rnd.random() < 0.3 else (lambda s: s)
                defs.append(" ".join(x for x in [q(cname), ctype] + cons if x))
                cols.append((cname, ctype))
            without = not strict and rnd.random() < 0.2
            if without or rnd.random() < 0.3:
                pk = rnd.sample([c for c, _ in cols], rnd.randint(1, min(2, len(cols))))
                defs.append("PRIMARY KEY (" + ", ".join(quote(c) for c in pk) + ")")
            opts = []
            if without:
                opts.append("WITHOUT ROWID")
            if strict:
                opts.append("STRICT")
            sql = f"CREATE TABLE {quote(name)} (\n  " + ",\n  ".join(defs) + ")" + (" " + ", ".join(opts) if opts else "")
            db.execute(sql)
            tables.append(name)
            rows = rnd.choice([0, 1, 10, 200, 3000, 20000])
            # Large values (overflow pages) only in the smaller tables.
            big = rows <= 3000
            def value(ctype, k):
                if "INT" in ctype.upper():
                    return k
                if ctype.upper() in ("REAL", "DOUBLE PRECISION"):
                    return k / 3
                if ctype.upper() == "BLOB":
                    return bytes(rnd.randrange(256) for _ in range(rnd.choice([0, 10, 3000 if big else 20])))
                return ("Saltmere " * rnd.choice([1, 5, 400]))[: rnd.choice([5, 50, 3000 if big else 40])] + str(k)
            try:
                db.executemany(f"INSERT OR IGNORE INTO {quote(name)} VALUES (" + ",".join("?" * ncols) + ")",
                               [tuple(value(t_, k) for _, t_ in cols) for k in range(rows)])
            except sqlite3.Error:
                pass
            if rnd.random() < 0.4 and cols:
                db.execute(f"CREATE INDEX {quote('idx_' + name)} ON {quote(name)}({quote(cols[0][0])})")
            if rnd.random() < 0.2:
                db.execute(f"CREATE VIEW {quote('v_' + name)} AS SELECT * FROM {quote(name)}")
            if rnd.random() < 0.15:
                db.execute(f"CREATE TRIGGER {quote('tr_' + name)} AFTER DELETE ON {quote(name)} BEGIN SELECT 1; END")
            if rnd.random() < 0.2 and rows:
                db.execute(f"DELETE FROM {quote(name)} WHERE rowid % 3 = 0" if not without else f"DELETE FROM {quote(name)}")
        if rnd.random() < 0.2:
            db.execute("CREATE VIRTUAL TABLE fts USING fts5(body)")
            db.executemany("INSERT INTO fts VALUES (?)", [("tide table %d" % k,) for k in range(300)])
        db.commit()
        db.close()
    print(f"generated: {n} databases", file=sys.stderr)


def collect(dirs):
    out = os.path.join(CORPUS, "mac")
    os.makedirs(out, exist_ok=True)
    random.seed(7)
    found = []
    for d in dirs:
        for base, subdirs, files in os.walk(d):
            if base.startswith(("/System/Volumes", "/Users")):
                subdirs[:] = []
                continue
            for f in files:
                p = os.path.join(base, f)
                try:
                    if not os.path.isfile(p) or os.path.islink(p) or os.path.getsize(p) > 64 << 20:
                        continue
                    with open(p, "rb") as fh:
                        head = fh.read(32)
                except OSError:
                    continue
                if head.startswith(b"SQLite format 3\0") or f.lower().endswith((".dbf", ".mdb", ".accdb")):
                    found.append(p)
    random.shuffle(found)
    n = 0
    for p in found[:1500]:
        try:
            shutil.copyfile(p, os.path.join(out, f"{n:05d}-{os.path.basename(p)}"))
            n += 1
        except OSError:
            pass
    print(f"mac: {n} files", file=sys.stderr)


def whiff(files, profile="full"):
    out = {}
    for i in range(0, len(files), 200):
        r = subprocess.run([WHIFF, "--profile", profile, "--jsonl", *files[i : i + 200]], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            rep = json.loads(line)
            out[rep["source"]["path"]] = rep
    return out


def fmt(rep):
    return rep.get("format", {}).get(rep["identification"]["format"], {})


def sqlite_ref(path):
    uri = "file:" + path + "?mode=ro&immutable=1"
    db = sqlite3.connect(uri, uri=True)
    q = lambda s: db.execute(s).fetchone()[0]
    r = {
        "page_size": q("PRAGMA page_size"),
        "encoding": q("PRAGMA encoding").lower(),
        "user_version": q("PRAGMA user_version"),
        "application_id": q("PRAGMA application_id"),
        "free_pages": q("PRAGMA freelist_count"),
        "tables": {},
    }
    objs = db.execute("SELECT type, name, sql FROM sqlite_schema").fetchall()
    for kind in ("index", "view", "trigger"):
        r[kind] = sorted(n for t, n, _ in objs if t == kind and not n.startswith("sqlite_autoindex"))
    for t, n, sql in objs:
        if t != "table":
            continue
        entry = {}
        virtual = (sql or "").upper().startswith("CREATE VIRTUAL")
        if not virtual:
            try:
                cols = db.execute(f"PRAGMA table_xinfo({quote(n)})").fetchall()
                entry["columns"] = [(c[1], c[2], bool(c[3]), c[5] > 0) for c in cols if c[6] != 1]
                entry["rows"] = q(f"SELECT count(*) FROM {quote(n)}")
            except sqlite3.Error:
                pass
        r["tables"][n] = entry
    db.close()
    return r


def check_sqlite(files):
    ours = whiff(files)
    bad, total = [], 0
    for path in files:
        rep = ours.get(path)
        if not rep or rep["identification"]["format"] != "sqlite":
            continue
        try:
            ref = sqlite_ref(path)
        except sqlite3.Error:
            continue  # encrypted (SQLCipher) or damaged: sqlite3 cannot read it either
        total += 1
        got = fmt(rep)
        d = {}

        def same(k, a, b):
            if a != b:
                d[k] = {"whiff": a, "reference": b}

        for k in ("page_size", "encoding", "user_version", "free_pages"):
            same(k, got.get(k), ref[k])
        app = int(got.get("application_id", "0x0"), 16)
        same("application_id", app, ref["application_id"])
        for kind, key in (("index", "indexes"), ("view", "views"), ("trigger", "triggers")):
            same(key, sorted(o["name"] for o in got.get(key, [])), ref[kind])
        tables = {t["name"]: t for t in got.get("tables", [])}
        # whiff describes the first 256 tables and counts them all.
        if len(ref["tables"]) > 256:
            same("table_count", got.get("object_counts", {}).get("tables"), len(ref["tables"]))
        else:
            same("tables", sorted(tables), sorted(ref["tables"]))
        for name, want in ref["tables"].items():
            t = tables.get(name)
            if not t:
                continue
            if "columns" in want and "columns" in t and len(want["columns"]) <= 128:
                cols = [(c["name"], c.get("type", ""), c.get("not_null", False), c.get("primary_key", False))
                        for c in t["columns"]]
                if cols != want["columns"]:
                    d.setdefault("columns", []).append({"table": name, "whiff": cols, "reference": want["columns"]})
            if "rows" in want and not t.get("rows_estimated"):
                if t.get("rows") != want["rows"]:
                    d.setdefault("rows", []).append({"table": name, "whiff": t.get("rows"), "reference": want["rows"]})
        if d:
            bad.append((os.path.relpath(path, ROOT), d))
    report("sqlite", total, bad)


def container(script, *args):
    r = subprocess.run(["podman", "run", "--rm", "-v", f"{ROOT}:/r:ro", "-w", "/r", IMAGE, "bash", "-c", script, "x", *args],
                       capture_output=True, text=True, errors="replace")
    return r.stdout


def check_dbf(files):
    ours = whiff(files)
    rel = [os.path.relpath(f, ROOT) for f in files if ours.get(f, {}).get("identification", {}).get("format") == "dbf"]
    script = 'for f in "$@"; do echo "@@ $f"; ogrinfo -ro -so -al "$f" 2>/dev/null; done'
    out = container(script, *rel)
    refs, cur = {}, None
    for line in out.splitlines():
        if line.startswith("@@ "):
            cur = line[3:]
            refs[cur] = {"fields": []}
        elif cur and line.startswith("Feature Count:"):
            refs[cur]["count"] = int(line.split(":")[1])
        elif cur and ": " in line and "(" in line and line[0] != " " and not line.startswith(("Layer", "Geometry", "Feature", "Extent", "INFO", "Data")):
            name, rest = line.split(": ", 1)
            width = rest.rsplit("(", 1)[1].split(".")[0].split(")")[0]
            if width.isdigit():
                refs[cur]["fields"].append((name, int(width)))
    bad, total = [], 0
    for r in rel:
        ref = refs.get(r)
        if not ref or "count" not in ref:
            continue
        total += 1
        got = fmt(ours[os.path.join(ROOT, r)])
        d = {}
        # GDAL counts deleted records too.
        if got.get("records") != ref["count"]:
            d["records"] = {"whiff": got.get("records"), "reference": ref["count"]}
        fields = [(f["name"], f["length"]) for f in got.get("fields", [])]
        # ogrinfo leaves out memo and other unsupported types.
        if [f for f in fields if f in ref["fields"]] != ref["fields"]:
            d["fields"] = {"whiff": fields, "reference": ref["fields"]}
        if d:
            bad.append((r, d))
    report("dbf", total, bad)


def check_access(files):
    ours = whiff(files)
    rel = [os.path.relpath(f, ROOT) for f in files if ours.get(f, {}).get("identification", {}).get("format") == "access"]
    script = r'''for f in "$@"; do echo "@@ $f"; echo "ver $(mdb-ver "$f")";
      mdb-tables -1 "$f" | while read -r t; do [ -n "$t" ] && echo "t $(mdb-count "$f" "$t") $t"; done; done'''
    refs, cur = {}, None
    for line in container(script, *rel).splitlines():
        if line.startswith("@@ "):
            cur = line[3:]
            refs[cur] = {"tables": {}}
        elif cur and line.startswith("ver "):
            refs[cur]["version"] = line[4:]
        elif cur and line.startswith("t "):
            _, n, name = line.split(" ", 2)
            refs[cur]["tables"][name] = int(n)
    bad, total = [], 0
    names = {"JET3": "Jet 3", "JET4": "Jet 4", "ACE12": "ACE 12", "ACE14": "ACE 14", "ACE15": "ACE 15", "ACE16": "ACE 16"}
    for r in rel:
        ref = refs.get(r)
        if not ref:
            continue
        total += 1
        got = fmt(ours[os.path.join(ROOT, r)])
        tables = {t["name"]: t.get("rows") for t in got.get("tables", [])}
        d = {}
        if names.get(ref.get("version"), ref.get("version")) != got.get("engine"):
            d["engine"] = {"whiff": got.get("engine"), "reference": ref.get("version")}
        if tables != ref["tables"]:
            d["tables"] = {"whiff": tables, "reference": ref["tables"]}
        if d:
            bad.append((r, d))
    report("access", total, bad)


def check_engines():
    """The engine fixtures against each engine's own tools."""
    script = r'''
cd /r/tests/fixtures
echo "duckdb $(python3 -c "import duckdb; c=duckdb.connect('duckdb/saltmere.duckdb', read_only=True); print(c.execute('PRAGMA database_size').fetchone()[2:4])")"
echo "lmdb $(mdb_stat -n lmdb/saltmere.mdb | grep -E 'Entries|Page size|Tree depth' | tr -s ' ' | tr '\n' ' ')"
for f in berkeley_db/*.db; do echo "bdb $f $(db5.3_stat -d "$f" | grep -E 'magic number|version number|page size' | awk '{print $1}' | tr '\n' ' ')"; done
echo "rocksdb $(sst_dump --file=leveldb_table/rocksdb-000001.sst --show_properties 2>/dev/null | grep -E '# entries|column family name' | tr -s ' ' | tr '\n' ' ')"
for f in pg_dump/*.dump; do echo "pg $f $(pg_restore -l "$f" | grep -cv '^;')"; done
'''
    out = container(script)
    print("engines (reference lines):")
    for line in out.splitlines():
        print("  " + line)
    ours = whiff(sorted(glob.glob(os.path.join(FIXTURES, "*", "*"))), "standard")
    for name in ("duckdb/saltmere.duckdb", "lmdb/saltmere.mdb", "berkeley_db/saltmere-btree.db",
                 "berkeley_db/saltmere-hash.db", "leveldb_table/rocksdb-000001.sst", "pg_dump/harbour.dump",
                 "pg_dump/harbour-stations-uncompressed.dump"):
        rep = ours.get(os.path.join(FIXTURES, name))
        if rep:
            print(f"  whiff {name}: {json.dumps(fmt(rep), sort_keys=True)[:400]}")


def report(kind, total, bad):
    print(f"{kind}: {total} compared, {total - len(bad)} agree")
    for name, d in bad[:12]:
        print(f"  {name}: {json.dumps(d)[:600]}")
    c = Counter(k for _, d in bad for k in d)
    if c:
        print("  by field:", dict(c))


def check():
    files = sorted(glob.glob(os.path.join(CORPUS, "**", "*"), recursive=True))
    files = [f for f in files if os.path.isfile(f)]
    files += sorted(glob.glob(os.path.join(FIXTURES, "sqlite", "*")))
    files += sorted(glob.glob(os.path.join(FIXTURES, "dbf", "*.dbf")))
    files += sorted(glob.glob(os.path.join(FIXTURES, "access", "*.mdb")))
    extra = sorted(glob.glob(os.path.join(ROOT, "target", "db-fixtures.*", "extra", "*.accdb")))
    files += extra[-1:]
    with_head = []
    for f in files:
        with open(f, "rb") as fh:
            with_head.append((f, fh.read(32)))
    check_sqlite([f for f, h in with_head if h.startswith(b"SQLite format 3\0")])
    check_dbf([f for f, _ in with_head if f.lower().endswith(".dbf")])
    check_access([f for f, h in with_head if h[4:19] in (b"Standard Jet DB", b"Standard ACE DB")])
    check_engines()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "generate":
        generate(int(sys.argv[2]) if len(sys.argv) > 2 else 100)
    elif len(sys.argv) > 1 and sys.argv[1] == "collect":
        collect(sys.argv[2:])
    else:
        check()


if __name__ == "__main__":
    main()
