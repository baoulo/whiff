#!/usr/bin/env bash
# Build a corpus for archive_oracle.py: archives of a few system folders,
# written by every installed archiver with every method it offers. Never
# committed (the inputs are the system's files); give it a scratch folder:
#
#     scripts/fixtures/archive_corpus.sh /tmp/archive-corpus
#     scripts/fixtures/archive_oracle.py target/release/whiff /tmp/archive-corpus
#
# Needs bsdtar, zip, 7-Zip (7zz), gzip, bzip2, xz, zstd, lz4, brotli and
# compress. Reads only system folders (never the home folder).

set -euo pipefail
out=${1:?usage: archive_corpus.sh <output folder>}
mkdir -p "$out"
export COPYFILE_DISABLE=1

# Inputs: many small text files, binary files with symbolic links, and a
# folder of larger files.
sources=(/usr/share/man/man5 /usr/share/zoneinfo /usr/share/vim/vim*/syntax)
n=0
for src in "${sources[@]}"; do
    [ -d "$src" ] || continue
    n=$((n + 1))
    parent=$(dirname "$src")
    base=$(basename "$src")
    t="$out/s$n"
    for f in pax ustar gnutar v7tar newc odc 7zip zip; do
        bsdtar -C "$parent" -cf "$t-bsdtar.$f" --format "$f" --no-mac-metadata "$base" 2>/dev/null || true
    done
    (cd "$parent" && zip -q -r -y "$t-infozip.zip" "$base")
    (cd "$parent" && zip -q -r -y -Z bzip2 "$t-infozip-bzip2.zip" "$base" 2>/dev/null) || true  # not in every build
    for m in LZMA2 LZMA BZip2 PPMd Deflate Copy; do
        (cd "$parent" && 7zz a -t7z -m0=$m -bso0 -bsp0 "$t-7zip-$m.7z" "$base")
    done
    (cd "$parent" && 7zz a -t7z -ms=off -mhc=off -bso0 -bsp0 "$t-7zip-nonsolid.7z" "$base")
    (cd "$parent" && 7zz a -t7z -mf=BCJ2 -bso0 -bsp0 "$t-7zip-bcj2.7z" "$base")
    for m in Deflate Deflate64 BZip2 LZMA PPMd Copy; do
        (cd "$parent" && 7zz a -tzip -mm=$m -bso0 -bsp0 "$t-7zip-$m.zip" "$base")
    done
    (cd "$parent" && 7zz a -ttar -bso0 -bsp0 "$t-7zip.tar" "$base")
    tarball="$t-bsdtar.pax"
    gzip -9 -c "$tarball" >"$t.tar.gz"
    bzip2 -9 -c "$tarball" >"$t.tar.bz2"
    xz -9 -c "$tarball" >"$t.tar.xz"
    xz --format=lzma -c "$tarball" >"$t.tar.lzma"
    zstd -q -19 -c "$tarball" >"$t.tar.zst"
    lz4 -q -9 -c "$tarball" >"$t.tar.lz4"
    brotli -q 9 -c "$tarball" >"$t.tar.br"
    compress -c -f "$tarball" >"$t.tar.Z"
done
echo "corpus written to $out"
