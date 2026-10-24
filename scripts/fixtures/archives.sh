#!/usr/bin/env bash
# Regenerate the archive and compression fixtures under tests/fixtures/<format>/.
#
# Needs bsdtar (libarchive 3.7), zip, 7-Zip (7zz), gzip, bzip2, xz, lzma,
# zstd, lz4, brotli, compress and, on macOS, compression_tool (LZFSE).
# Several writers make each format on purpose (bsdtar, zip, 7-Zip and
# Python's zipfile for ZIP; bsdtar, 7-Zip and Python's tarfile for tar …),
# so the extractors are not tested against one implementation only.
# craft_archives.py writes what no installed tool does (RAR, CAB, LHA, ARJ,
# lzip, Snappy, lzop, BGZF); each of those that 7-Zip reads is checked with
# `7zz t` here.
#
# The files are a few short texts about a fictitious harbour (Saltmere),
# with fixed times and the owner `saltmere:harbour`, so nothing about the
# machine that ran this ends up in them. The AES and ZipCrypto archives
# use the password `saltmere`. Run from the repository root:
#
#     scripts/fixtures/archives.sh

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# COPYFILE_DISABLE and --no-mac-metadata: no AppleDouble entries carrying
# this machine's extended attributes.
export TZ=UTC LC_ALL=C COPYFILE_DISABLE=1

python3 "$root/scripts/fixtures/craft_archives.py" "$fx"
for f in "$fx"/rar/*-crafted.rar "$fx"/cab/*-crafted.cab "$fx"/lha/*-crafted.lzh "$fx"/arj/*-crafted.arj "$fx"/zip/*-python.zip; do
    7zz t "$f" >/dev/null || { echo "7-Zip rejects $f" >&2; exit 1; }
done

# The payload: a folder with texts, a subfolder and a symbolic link.
p="$work/harbour"
mkdir -p "$p/charts"
cat >"$p/notes.txt" <<'EOF'
Saltmere harbour notes
High water 06:12, low water 12:31. The pilot launch leaves at dawn.
Ben Gull keeps the bell tower log; Ana Lighthouse keeps the charts.
EOF
printf 'date,boat,berth\n2025-09-01,Harbour Bell,3\n2025-09-01,Grey Tern,5\n' >"$p/log.csv"
printf '# Charts\n\nThe harbour wall, the bell tower and the channel buoys.\n' >"$p/charts/README.md"
ln -s notes.txt "$p/latest.txt"
find "$p" -exec touch -h -t 202509011200 {} +
owner=(--uid 1000 --uname saltmere --gid 1000 --gname harbour --no-mac-metadata)

mk() { mkdir -p "$fx/$1"; }
# 7-Zip and zip add to an existing archive: start each one afresh.
fresh() { rm -f "$1"; printf '%s' "$1"; }
for d in tar cpio ar 7z zip gzip zlib bzip2 xz lzma zstd lz4 brotli z lzfse; do mk "$d"; done

# tar: bsdtar in four header formats, Python's tarfile with long GNU names.
(cd "$work" && bsdtar -cf "$fx/tar/harbour-bsdtar-pax.tar" --format pax "${owner[@]}" harbour)
(cd "$work" && bsdtar -cf "$fx/tar/harbour-bsdtar-ustar.tar" --format ustar "${owner[@]}" harbour)
(cd "$work" && bsdtar -cf "$fx/tar/harbour-bsdtar-gnu.tar" --format gnutar "${owner[@]}" harbour)
(cd "$work" && bsdtar -cf "$fx/tar/harbour-bsdtar-v7.tar" --format v7tar "${owner[@]}" harbour)
python3 - "$fx/tar/harbour-tarfile-gnu.tar" <<'EOF'
import io, sys, tarfile
long = "harbour/charts/" + "the-long-channel-between-the-harbour-wall-and-the-bell-tower-buoys/" * 2 + "soundings.txt"
with tarfile.open(sys.argv[1], "w", format=tarfile.GNU_FORMAT) as t:
    for name, data in [("harbour/notes.txt", b"Saltmere harbour notes\n"), (long, b"Soundings: 4.2 m, 3.8 m, 5.1 m\n")]:
        info = tarfile.TarInfo(name)
        info.size, info.mtime, info.mode = len(data), 1756728000, 0o644
        info.uname, info.gname, info.uid, info.gid = "saltmere", "harbour", 1000, 1000
        t.addfile(info, io.BytesIO(data))
    link = tarfile.TarInfo("harbour/latest.txt")
    link.type, link.linkname, link.mtime = tarfile.SYMTYPE, "notes.txt", 1756728000
    link.uname, link.gname = "saltmere", "harbour"
    t.addfile(link)
EOF
python3 - "$fx/tar/harbour-tarfile-pax.tar" <<'EOF'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w", format=tarfile.PAX_FORMAT, pax_headers={"comment": "Saltmere harbour, September tides"}) as t:
    data = "Tidenhub: 3,9 m — Glocke läutet bei Hochwasser\n".encode()
    info = tarfile.TarInfo("harbour/glocke-läutet.txt")
    info.size, info.mtime, info.mode = len(data), 1756728000, 0o644
    info.uname, info.gname = "saltmere", "harbour"
    t.addfile(info, io.BytesIO(data))
EOF

# cpio: new ASCII and old portable ASCII (bsdtar); old binary (Python).
(cd "$work" && bsdtar -cf "$fx/cpio/harbour-bsdtar-newc.cpio" --format newc "${owner[@]}" harbour)
(cd "$work" && bsdtar -cf "$fx/cpio/harbour-bsdtar-odc.cpio" --format odc "${owner[@]}" harbour)
python3 - "$fx/cpio/harbour-python-binary.cpio" "$p/notes.txt" <<'EOF'
import struct, sys
data = open(sys.argv[2], "rb").read()
out = b""
for name, body, mode in [(b"harbour/notes.txt", data, 0o100644), (b"TRAILER!!!", b"", 0)]:
    n = name + b"\0"
    out += struct.pack("<13H", 0o070707, 0, 1, mode, 1000, 1000, 1, 0, 1756728000 >> 16, 1756728000 & 0xFFFF, len(n), len(body) >> 16, len(body) & 0xFFFF)
    out += n + b"\0" * (len(n) % 2) + body + b"\0" * (len(body) % 2)
open(sys.argv[1], "wb").write(out + b"\0" * (-len(out) % 512))
EOF

# ar: GNU / System V and BSD long names (bsdtar).
(cd "$p" && bsdtar -cf "$fx/ar/harbour-bsdtar-gnu.a" --format argnu "${owner[@]}" notes.txt log.csv)
cp "$p/notes.txt" "$work/a-rather-long-member-name-for-the-tide-notes.txt"
touch -t 202509011200 "$work/a-rather-long-member-name-for-the-tide-notes.txt"
(cd "$work" && bsdtar -cf "$fx/ar/harbour-bsdtar-bsd.a" --format arbsd "${owner[@]}" a-rather-long-member-name-for-the-tide-notes.txt harbour/log.csv)

# 7z: bsdtar (LZMA), 7-Zip (solid LZMA2; a BCJ filter before LZMA; stored;
# encrypted headers).
(cd "$work" && bsdtar -cf "$fx/7z/harbour-bsdtar.7z" --format 7zip "${owner[@]}" harbour)
(cd "$work" && 7zz a -t7z -mx=9 -ms=on -bso0 -bsp0 "$(fresh "$fx/7z/harbour-7zip-solid.7z")" harbour)
(cd "$work" && 7zz a -t7z -mf=BCJ -m0=LZMA -ms=off -bso0 -bsp0 "$(fresh "$fx/7z/harbour-7zip-bcj.7z")" harbour/notes.txt harbour/charts/README.md)
(cd "$work" && 7zz a -t7z -m0=Copy -bso0 -bsp0 "$(fresh "$fx/7z/harbour-7zip-copy.7z")" harbour/notes.txt harbour/log.csv)
(cd "$work" && 7zz a -t7z -mhe=on -psaltmere -bso0 -bsp0 "$(fresh "$fx/7z/harbour-7zip-encrypted.7z")" harbour/notes.txt)

# zip: Info-ZIP (with a comment and Unix extra fields), bsdtar, 7-Zip (AES
# and ZipCrypto).
(cd "$work" && zip -q -r -y "$(fresh "$fx/zip/harbour-infozip.zip")" harbour && printf 'Saltmere harbour, September\n' | zip -q -z "$fx/zip/harbour-infozip.zip")
(cd "$work" && bsdtar -cf "$fx/zip/harbour-bsdtar.zip" --format zip "${owner[@]}" harbour)
(cd "$work" && 7zz a -tzip -psaltmere -mem=AES256 -bso0 -bsp0 "$(fresh "$fx/zip/harbour-7zip-aes.zip")" harbour/notes.txt harbour/log.csv)
(cd "$work" && 7zz a -tzip -psaltmere -mem=ZipCrypto -bso0 -bsp0 "$(fresh "$fx/zip/harbour-7zip-zipcrypto.zip")" harbour/notes.txt)

# Compressed streams of one text, and of a tar (tar.gz, tar.zst …).
n="$p/notes.txt"
(cd "$work" && bsdtar -cf "$work/harbour.tar" --format pax "${owner[@]}" harbour)
touch -t 202509011200 "$work/harbour.tar"
gzip -9 -n -c "$n" >"$fx/gzip/notes-gzip-noname.txt.gz"
(cd "$p" && gzip -9 -k -N -f notes.txt && mv notes.txt.gz "$fx/gzip/notes-gzip.txt.gz")
(cd "$work" && gzip -9 -k -N -f harbour.tar && mv harbour.tar.gz "$fx/gzip/harbour-gzip.tgz")
python3 -c 'import sys, zlib; sys.stdout.buffer.write(zlib.compress(open(sys.argv[1], "rb").read(), 9))' "$n" >"$fx/zlib/notes-python.txt.zz"
bzip2 -9 -c "$n" >"$fx/bzip2/notes-bzip2.txt.bz2"
bzip2 -9 -c "$work/harbour.tar" >"$fx/bzip2/harbour-bzip2.tar.bz2"
xz -6 -c "$n" >"$fx/xz/notes-xz.txt.xz"
xz -c --x86 --lzma2=preset=6 "$work/harbour.tar" >"$fx/xz/harbour-xz-x86.txz"
printf 'Harbour wall at dawn, harbour wall at dawn.' | xz -6 >"$fx/xz/harbour-wall-xz.txt.xz"
lzma -c "$n" >"$fx/lzma/notes-lzma.txt.lzma"
zstd -q -19 -c "$n" >"$fx/zstd/notes-zstd.txt.zst"
zstd -q -c "$work/harbour.tar" >"$fx/zstd/harbour-zstd.tar.zst"
lz4 -q -9 -c "$n" >"$fx/lz4/notes-lz4.txt.lz4"
lz4 -q -l -c "$n" >"$fx/lz4/notes-lz4-legacy.txt.lz4"
brotli -q 11 -c "$n" >"$fx/brotli/notes-brotli.txt.br"
compress -c -f "$work/harbour.tar" >"$fx/z/harbour-compress.tar.Z"
if command -v compression_tool >/dev/null; then
    compression_tool -encode -a lzfse -i "$n" -o "$fx/lzfse/notes-compression-tool.txt.lzfse"
fi

echo "archive fixtures written to $fx"
