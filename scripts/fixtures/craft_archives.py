#!/usr/bin/env python3
"""Write the archive and compression fixtures no installed tool writes.

    craft_archives.py <tests/fixtures>

Standard library only. RAR 4 and RAR 5 (stored entries: RAR's compression
is proprietary), Microsoft Cabinet (an uncompressed and an MSZIP folder),
LHA (header levels 0, 1 and 2, stored), ARJ (stored), lzip (LZMA from
Python's lzma module), the Snappy framing format, lzop (a stored block),
BGZF and a gzip file with a comment and extra field, and ZIP archives with
the methods Python's zipfile writes. archives.sh checks every one that
7-Zip reads with `7zz t`.

Names and texts are fictitious (Saltmere harbour). Times are fixed, so
the output is the same on every run.
"""

import binascii
import gzip
import io
import lzma
import struct
import sys
import time
import zipfile
import zlib
from pathlib import Path

# 2025-09-01 12:00:00 UTC
STAMP = 1756728000
DOS_DATE = ((2025 - 1980) << 9) | (9 << 5) | 1
DOS_TIME = (12 << 11) | (0 << 5) | 0

NOTES = (
    b"Saltmere harbour notes\n"
    b"High water 06:12, low water 12:31. The pilot launch leaves at dawn.\n"
    b"Ben Gull keeps the bell tower log; Ana Lighthouse keeps the charts.\n"
)
LOG = b"date,boat,berth\n2025-09-01,Harbour Bell,3\n2025-09-01,Grey Tern,5\n2025-09-02,Low Water,1\n"
README = b"# Saltmere\n\nA small harbour, a long wall and a bell that rings at high tide.\n" * 4


def crc16_arc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
    return crc ^ 0xFFFFFFFF


def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


# ---- RAR 4 ------------------------------------------------------------------

def rar4_block(kind: int, flags: int, body: bytes, add: bytes = b"") -> bytes:
    size = 7 + len(body)
    head = struct.pack("<BHH", kind, flags, size) + body
    return struct.pack("<H", crc32(head) & 0xFFFF) + head + add


def rar4(out: Path):
    data = b"Rar!\x1a\x07\x00"
    # Main header: reserved fields; flags 0x08 solid off, 0x10 new naming.
    data += rar4_block(0x73, 0x0010, b"\0" * 6)
    entries = [("harbour", None), ("harbour\\notes.txt", NOTES), ("harbour\\log.csv", LOG)]
    for name, content in entries:
        dir_ = content is None
        content = content or b""
        raw = name.encode()
        flags = 0x8000 | (0xE0 if dir_ else 0)
        body = struct.pack(
            "<IIBIIBBHI",
            len(content),
            len(content),
            2,  # Windows
            crc32(content),
            (DOS_DATE << 16) | DOS_TIME,
            20,
            0x30,  # store
            len(raw),
            0x10 if dir_ else 0x20,
        ) + raw
        data += rar4_block(0x74, flags, body, content)
    data += rar4_block(0x7B, 0x4000, b"")
    out.write_bytes(data)


# ---- RAR 5 ------------------------------------------------------------------

def vint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def rar5_header(kind: int, flags: int, fields: bytes, extra: bytes = b"", data_size=None) -> bytes:
    body = vint(kind) + vint(flags | (1 if extra else 0) | (2 if data_size is not None else 0))
    if extra:
        body += vint(len(extra))
    if data_size is not None:
        body += vint(data_size)
    body += fields + extra
    sized = vint(len(body)) + body
    return struct.pack("<I", crc32(sized)) + sized


def rar5(out: Path):
    data = b"Rar!\x1a\x07\x01\x00"
    data += rar5_header(1, 0, vint(0))  # main: no archive flags
    for name, content, mode in [
        ("charts", None, 0o040755),
        ("charts/notes.txt", NOTES, 0o100644),
        ("charts/README.md", README, 0o100644),
    ]:
        dir_ = content is None
        content = content or b""
        fflags = (1 if dir_ else 0) | 2 | (0 if dir_ else 4)
        fields = vint(fflags) + vint(len(content)) + vint(mode) + struct.pack("<I", STAMP)
        if not dir_:
            fields += struct.pack("<I", crc32(content))
        fields += vint(0)  # compression: version 0, store
        fields += vint(1)  # Unix
        raw = name.encode()
        fields += vint(len(raw)) + raw
        data += rar5_header(2, 0, fields, data_size=len(content)) + content
    data += rar5_header(5, 0, vint(0))
    out.write_bytes(data)


# ---- Cabinet ----------------------------------------------------------------

def mszip_blocks(content: bytes) -> list:
    blocks, history = [], b""
    for i in range(0, len(content), 32768):
        chunk = content[i:i + 32768]
        c = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=history) if history else zlib.compressobj(9, zlib.DEFLATED, -15)
        blocks.append((b"CK" + c.compress(chunk) + c.flush(), len(chunk)))
        history = (history + chunk)[-32768:]
    return blocks


def cab(out: Path):
    # Folder 0 uncompressed (notes, log), folder 1 MSZIP (a longer file).
    tide = b"".join(b"%02d:%02d high water %d cm, the bell rings\n" % (h, m, 380 + (h * 7 + m) % 90)
                    for h in range(24) for m in range(0, 60, 5)) * 6
    files = [("notes.txt", NOTES, 0), ("log.csv", LOG, 0), ("tides\\year.txt", tide, 1)]
    folder_data = {0: NOTES + LOG, 1: tide}
    datas = {}
    for f, content in folder_data.items():
        if f == 0:
            datas[f] = [(content, len(content))]
        else:
            datas[f] = mszip_blocks(content)
    header_size = 36
    folders_size = 8 * 2
    files_blob = b""
    offsets = {0: 0, 1: 0}
    for name, content, folder in files:
        files_blob += struct.pack("<IIHHHH", len(content), offsets[folder], folder, DOS_DATE, DOS_TIME, 0x20) + name.encode() + b"\0"
        offsets[folder] += len(content)
    data_at = header_size + folders_size + len(files_blob)
    folder_recs, data_blob = b"", b""
    for f in (0, 1):
        folder_recs += struct.pack("<IHH", data_at + len(data_blob), len(datas[f]), 0 if f == 0 else 1)
        for block, raw in datas[f]:
            data_blob += struct.pack("<IHH", 0, len(block), raw) + block
    total = data_at + len(data_blob)
    header = b"MSCF" + struct.pack("<IIIIIBBHHHHH", 0, total, 0, header_size + folders_size, 0, 3, 1, 2, len(files), 0, 0x5A17, 0)
    out.write_bytes(header + folder_recs + files_blob + data_blob)


# ---- LHA --------------------------------------------------------------------

def lha(out: Path):
    data = b""
    stamp_dos = (DOS_DATE << 16) | DOS_TIME
    # Level 0: plain name.
    name = b"NOTES.TXT"
    base = b"-lh0-" + struct.pack("<IIIBB", len(NOTES), len(NOTES), stamp_dos, 0x20, 0) + bytes([len(name)]) + name + struct.pack("<H", crc16_arc(NOTES))
    data += bytes([len(base), sum(base) & 0xFF]) + base + NOTES
    # Level 1: name, then a directory extension header.
    name = b"log.csv"
    dirext = bytes([0x02]) + b"harbour\xff" + struct.pack("<H", 0)
    packed = len(LOG) + len(dirext)
    base = b"-lh0-" + struct.pack("<IIIBB", packed, len(LOG), stamp_dos, 0x20, 1) + bytes([len(name)]) + name + struct.pack("<H", crc16_arc(LOG)) + b"U" + struct.pack("<H", len(dirext))
    data += bytes([len(base), sum(base) & 0xFF]) + base + dirext + LOG
    # Level 2: Unix time, extensions for name, folder and mode; header CRC.
    exts = [bytes([0x01]) + b"README.md", bytes([0x02]) + b"harbour\xffcharts\xff", bytes([0x50]) + struct.pack("<H", 0o100644)]
    ext_blob = b""
    for i, e in enumerate(exts):
        nxt = len(exts[i + 1]) + 2 if i + 1 < len(exts) else 0
        ext_blob += e + struct.pack("<H", nxt)
    # Common header (CRC) first: type 0, CRC16, next size.
    common_len = 1 + 2 + 2
    first_next = common_len
    fixed_len = 26
    total = fixed_len + common_len + len(ext_blob)
    def level2(crc):
        common = bytes([0x00]) + struct.pack("<H", crc) + struct.pack("<H", len(exts[0]) + 2)
        return struct.pack("<H", total) + b"-lh0-" + struct.pack("<IIIBB", len(README), len(README), STAMP, 0x20, 2) + struct.pack("<H", crc16_arc(README)) + b"U" + struct.pack("<H", first_next) + common + ext_blob
    header = level2(crc16_arc(level2(0)))
    data += header + README
    data += b"\0"
    out.write_bytes(data)


# ---- ARJ --------------------------------------------------------------------

def arj_header(basic: bytes) -> bytes:
    return b"\x60\xea" + struct.pack("<H", len(basic)) + basic + struct.pack("<I", crc32(basic)) + struct.pack("<H", 0)


def arj(out: Path):
    stamp = (DOS_DATE << 16) | DOS_TIME
    main = struct.pack("<BBBBBBBBIIIIHHBB", 30, 11, 1, 2, 0, 0, 2, 0, stamp, stamp, 0, 0, 0, 0, 0, 0) + b"saltmere.arj\0" + b"Charts and notes of Saltmere harbour\0"
    data = arj_header(main)
    for name, content in [(b"harbour/notes.txt", NOTES), (b"harbour/README.md", README)]:
        basic = struct.pack("<BBBBBBBBIIIIHHH", 30, 11, 1, 2, 0x10, 0, 0, 0, stamp, len(content), len(content), crc32(content), 8, 0o644, 0) + name + b"\0" + b"\0"
        data += arj_header(basic) + content
    data += b"\x60\xea\x00\x00"
    out.write_bytes(data)


# ---- lzip, Snappy, lzop -----------------------------------------------------

def lzip(out: Path):
    body = lzma.compress(NOTES * 3, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 20, "lc": 3, "lp": 0, "pb": 2}])
    member = b"LZIP\x01" + bytes([20]) + body  # 2^20
    member += struct.pack("<IQQ", crc32(NOTES * 3), len(NOTES * 3), len(member) + 20)
    out.write_bytes(member)


def snappy_literal_block(data: bytes) -> bytes:
    """A Snappy block of one literal (enough for a valid stream)."""
    n = len(data) - 1
    out = bytearray()
    v = len(data)
    while v >= 0x80:
        out.append(v & 0x7F | 0x80)
        v >>= 7
    out.append(v)
    if n < 60:
        out.append(n << 2)
    else:
        out += bytes([61 << 2]) + struct.pack("<H", n)
    return bytes(out) + data


def masked(crc: int) -> int:
    return (((crc >> 15) | (crc << 17)) + 0xA282EAD8) & 0xFFFFFFFF


def snappy(out: Path):
    s = b"\xff\x06\x00\x00sNaPpY"
    block = snappy_literal_block(NOTES)
    body = struct.pack("<I", masked(crc32c(NOTES))) + block
    s += bytes([0x00]) + struct.pack("<I", len(body))[:3] + body
    body = struct.pack("<I", masked(crc32c(LOG))) + LOG
    s += bytes([0x01]) + struct.pack("<I", len(body))[:3] + body
    out.write_bytes(s)


def lzop(out: Path):
    name = b"notes.txt"
    # Flags: Unix, Adler-32 of the uncompressed data.
    h = struct.pack(">HHHBBI", 0x1040, 0x2080, 0x0940, 1, 5, 0x03000001) + struct.pack(">III", 0o100644, STAMP, 0) + bytes([len(name)]) + name
    h += struct.pack(">I", zlib.adler32(h))
    # One block stored as is (compressed size = uncompressed size), Adler-32
    # of the data, then the end marker.
    block = struct.pack(">II", len(NOTES), len(NOTES)) + struct.pack(">I", zlib.adler32(NOTES)) + NOTES
    out.write_bytes(b"\x89LZO\x00\r\n\x1a\n" + h + block + b"\0\0\0\0")


# ---- gzip -------------------------------------------------------------------

def gzip_member(content: bytes, flags: int, extra: bytes = b"", name: bytes = b"", comment: bytes = b"") -> bytes:
    head = b"\x1f\x8b\x08" + bytes([flags]) + struct.pack("<I", STAMP) + b"\x02\x03"
    if flags & 4:
        head += struct.pack("<H", len(extra)) + extra
    if flags & 8:
        head += name + b"\0"
    if flags & 16:
        head += comment + b"\0"
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return head + c.compress(content) + c.flush() + struct.pack("<II", crc32(content), len(content))


def gzips(fx: Path):
    member = gzip_member(NOTES, 4 | 8 | 16, extra=b"Sm\x04\x00tide", name=b"notes.txt", comment=b"Saltmere harbour notes, September")
    (fx / "gzip" / "notes-crafted.txt.gz").write_bytes(member)
    # BGZF: each block carries its size in a BC subfield; an empty block ends it.
    def bgzf_block(content: bytes) -> bytes:
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        cdata = c.compress(content) + c.flush()
        size = 12 + 6 + len(cdata) + 8 - 1
        head = b"\x1f\x8b\x08\x04" + struct.pack("<I", 0) + b"\x00\xff" + struct.pack("<H", 6) + b"BC" + struct.pack("<HH", 2, size)
        return head + cdata + struct.pack("<II", crc32(content), len(content))
    (fx / "gzip" / "log-bgzf-crafted.csv.gz").write_bytes(bgzf_block(LOG) + bgzf_block(NOTES) + bgzf_block(b""))


# ---- ZIP (Python zipfile) ---------------------------------------------------

def zips(out: Path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.comment = b"Saltmere harbour archive, written by Python zipfile"
        for name, content, method in [
            ("harbour/", b"", zipfile.ZIP_STORED),
            ("harbour/notes.txt", NOTES, zipfile.ZIP_STORED),
            ("harbour/log.csv", LOG, zipfile.ZIP_DEFLATED),
            ("harbour/README.md", README, zipfile.ZIP_BZIP2),
            ("harbour/tides.txt", NOTES * 20, zipfile.ZIP_LZMA),
        ]:
            info = zipfile.ZipInfo(name, date_time=(2025, 9, 1, 12, 0, 0))
            info.create_system = 3
            info.external_attr = ((0o40755 if name.endswith("/") else 0o100644) << 16) | (0x10 if name.endswith("/") else 0)
            info.compress_type = method
            z.writestr(info, content)
        link = zipfile.ZipInfo("harbour/latest.txt", date_time=(2025, 9, 1, 12, 0, 0))
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        z.writestr(link, b"notes.txt")
    out.write_bytes(buf.getvalue())


def main():
    fx = Path(sys.argv[1])
    for d in ["rar", "cab", "lha", "arj", "lzip", "snappy", "lzop", "gzip", "zip"]:
        (fx / d).mkdir(parents=True, exist_ok=True)
    rar4(fx / "rar" / "harbour-rar4-crafted.rar")
    rar5(fx / "rar" / "charts-rar5-crafted.rar")
    cab(fx / "cab" / "harbour-crafted.cab")
    lha(fx / "lha" / "harbour-crafted.lzh")
    arj(fx / "arj" / "harbour-crafted.arj")
    lzip(fx / "lzip" / "notes-crafted.txt.lz")
    snappy(fx / "snappy" / "notes-crafted.txt.sz")
    lzop(fx / "lzop" / "notes-crafted.txt.lzo")
    gzips(fx)
    zips(fx / "zip" / "harbour-python.zip")


if __name__ == "__main__":
    main()
