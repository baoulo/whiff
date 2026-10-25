#!/usr/bin/env python3
"""Compare whiff's archive and compression reports with 7-Zip and the
reference decompressors (a dev-time oracle, like score_oracle.py).

    archive_oracle.py <whiff binary> <file or folder>... [--verbose]

Needs 7-Zip (`7zz`) and, for compressed files, gzip, bzip2, xz, zstd, lz4,
brotli and uncompress. For every archive 7-Zip lists: the number of
entries, and the path, type and size of each entry whiff lists. For every
compressed file: the uncompressed size against the reference tool's
output. Prints the agreement per field and the first disagreements.
"""

import json
import subprocess
import sys
from pathlib import Path

ARCHIVES = {"zip", "tar", "7z", "rar", "cab", "lha", "arj", "cpio", "ar"}
DECOMPRESS = {
    "gzip": ["gzip", "-dc"],
    "bzip2": ["bzip2", "-dc"],
    "xz": ["xz", "-dc"],
    "lzma": ["xz", "--format=lzma", "-dc"],
    "zstd": ["zstd", "-dcq"],
    "lz4": ["lz4", "-dcq"],
    "brotli": ["brotli", "-dc"],
    "z": ["uncompress", "-c"],
}


def whiff(binary, path):
    out = subprocess.run([binary, str(path)], capture_output=True, check=False).stdout
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


# Not member files: 7-Zip lists ar symbol tables, whiff does not.
SYMBOL_TABLES = {"__.SYMDEF", "__.SYMDEF SORTED", "/", "/SYM64/", "1.txt", "2.txt"}


def seven_zip(path, fmt):
    """7-Zip's listing: {path: (is_dir, size)} for names listed once, the
    entry count, or None if it cannot list."""
    p = subprocess.run(["7zz", "l", "-slt", "-ba", "-p-", str(path)], capture_output=True, check=False, text=True, errors="replace")
    if p.returncode != 0:
        return None
    items, seen, count, cur = {}, set(), 0, {}
    for line in p.stdout.splitlines() + [""]:
        if not line.strip():
            if "Path" in cur and not (fmt == "ar" and cur["Path"] in SYMBOL_TABLES and cur.get("Size") != "0" and count == 0):
                count += 1
                name = cur["Path"].replace("\\", "/").rstrip("/")
                entry = (cur.get("Folder") == "+" or "D" in cur.get("Attributes", "")[:1], int(cur["Size"]) if cur.get("Size", "").isdigit() else None)
                if name in seen:
                    items.pop(name, None)
                else:
                    items[name] = entry
                seen.add(name)
            cur = {}
            continue
        if " = " in line:
            k, v = line.split(" = ", 1)
            cur[k] = v
    return items, count, seen


def tally(results, field, good, path, detail, misses):
    n, ok = results.get(field, (0, 0))
    results[field] = (n + 1, ok + (1 if good else 0))
    if not good:
        misses.append((path, field, detail))


def check(binary, path, results, misses):
    report = whiff(binary, path)
    if not report:
        return
    fmt = report["identification"]["format"]
    f = report.get("format", {}).get(fmt, {})
    if fmt in ARCHIVES:
        listing = seven_zip(path, fmt)
        if listing is None or f.get("headers_encrypted"):
            return
        theirs, count, seen = listing
        ours = report.get("physical", {}).get("container", {}).get("entries")
        tally(results, "entries", ours == count, path, f"7-Zip {count}, whiff {ours}", misses)
        for e in f.get("entries", []):
            name = e["path"].replace("\\", "/").rstrip("/")
            name = name[2:] if name.startswith("./") else name
            if name in seen and name not in theirs:
                continue  # listed more than once: sizes are ambiguous
            if name not in theirs:
                tally(results, "paths", False, path, f"{name!r} not listed by 7-Zip", misses)
                continue
            tally(results, "paths", True, path, "", misses)
            is_dir, size = theirs[name]
            kind = e.get("type", "file")
            tally(results, "types", (kind == "directory") == is_dir, path, f"{name}: 7-Zip dir={is_dir}, whiff {kind}", misses)
            if kind == "file" and size is not None:
                tally(results, "sizes", e.get("size_bytes") == size, path, f"{name}: 7-Zip {size}, whiff {e.get('size_bytes')}", misses)
    elif fmt in DECOMPRESS:
        p = subprocess.run(DECOMPRESS[fmt] + [str(path)], capture_output=True, check=False)
        if p.returncode != 0:
            return
        ours = report.get("physical", {}).get("container", {}).get("uncompressed_bytes")
        if ours is None:
            # Longer than the parse limit, and the format states no size.
            n, ok = results.get("size_unknown", (0, 0))
            results["size_unknown"] = (n + 1, ok)
        else:
            tally(results, "uncompressed", ours == len(p.stdout), path, f"tool {len(p.stdout)}, whiff {ours}", misses)
        inner = report.get("embedded", [])
        if inner and len(p.stdout) <= 16 << 20:
            got = inner[0].get("physical", {}).get("size_bytes")
            tally(results, "inner_stream", got == len(p.stdout), path, f"tool {len(p.stdout)}, inner {got}", misses)


def main():
    binary = sys.argv[1]
    verbose = "--verbose" in sys.argv
    paths = []
    for a in sys.argv[2:]:
        if a.startswith("--"):
            continue
        p = Path(a)
        paths.extend(sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p])
    results, misses = {}, []
    for path in paths:
        check(binary, path, results, misses)
    print(f"{'field':<14} {'checked':>7} {'agree':>7} {'rate':>7}")
    for field, (n, ok) in results.items():
        print(f"{field:<14} {n:>7} {ok:>7} {100 * ok / max(n, 1):>6.1f}%")
    shown = misses if verbose else misses[:30]
    if shown:
        print("\ndisagreements:")
        for path, field, detail in shown:
            print(f"  {path} {field}: {detail}")


if __name__ == "__main__":
    main()
