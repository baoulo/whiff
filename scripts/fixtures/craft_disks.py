#!/usr/bin/env python3
"""Write the disk image fixtures no tool available here writes, from the
format documents (and, where noted, from images real tools made):

    aff <raw> <out>        AFF 1.0 (afflib layout: AFF10 header, AFF / ATT
                           segments, case metadata, zlib pages, MD5 / SHA-1)
    capsule <payload> <out>  a UEFI FMP capsule (UEFI 2.10 23.3): capsule
                           header, FMP header, one version-2 image header,
                           an authentication header (WIN_CERTIFICATE_UEFI_GUID,
                           PKCS7 type, placeholder certificate bytes) and an
                           FMP payload header (MSS1)
    cdbin <iso> <out> <mode>  a raw CD image (ECMA-130): each 2048-byte ISO
                           sector in a 2352-byte mode 1 or mode 2 form 1
                           sector with sync, BCD address, EDC; ECC left zero
    ccd <iso> <out>        a CloneCD control file for one mode 1 data track
                           (the layout CloneCD 5 writes)
    appimage-runtime <out> a stand-in AppImage type 2 runtime: an ELF64 header
                           with the AppImage magic (AI 02) and the .upd_info
                           and .sha256_sig sections the real runtime carries,
                           no code; the squashfs image is appended to it
    kernel <out>           a stand-in Linux kernel for boot images: 4 KiB of
                           zeros with the arm64 Image magic and a version
                           banner (no code)

Usage: craft_disks.py <kind> <args...>; see disks.sh.
"""

import hashlib
import struct
import sys
import zlib

STAMP = 1756728000  # 2025-09-01T12:00:00Z


def aff(raw_path, out):
    raw = open(raw_path, "rb").read()
    page = 64 * 1024

    def seg(name, data=b"", arg=0):
        name = name.encode()
        head = b"AFF\0" + struct.pack(">III", len(name), len(data), arg) + name + data
        return head + b"ATT\0" + struct.pack(">I", len(head) + 8)

    def quad(n):
        return struct.pack(">II", n & 0xFFFFFFFF, n >> 32)

    parts = [
        b"AFF10\r\n\0",
        seg("badflag", b"BAD SECTOR\0" + bytes(501)),
        seg("afflib_version", b"3.7.20"),
        seg("creator", b"craft_disks.py"),
        seg("case_num", b"HB-2025-07"),
        seg("examiner", b"R. Keel"),
        seg("acquisition_notes", b"Survey of the harbour tide gauge"),
        seg("acquisition_date", b"2025-09-01 12:00:00"),
        seg("device_model", b"Saltmere TG-1 logger"),
        seg("device_sn", b"TG1-0007"),
        seg("pagesize", arg=page),
        seg("sectorsize", arg=512),
        seg("imagesize", quad(len(raw)), arg=2),
        seg("devicesectors", quad(len(raw) // 512), arg=2),
    ]
    for i in range(0, len(raw), page):
        chunk = raw[i : i + page]
        # Flag 1: zlib-compressed page (AF_PAGE_COMPRESSED).
        parts.append(seg(f"page{i // page}", zlib.compress(chunk, 9), arg=1))
    parts.append(seg("md5", hashlib.md5(raw).digest()))
    parts.append(seg("sha1", hashlib.sha1(raw).digest()))
    open(out, "wb").write(b"".join(parts))


def guid(text):
    a, b, c, d, e = text.split("-")
    return struct.pack("<IHH", int(a, 16), int(b, 16), int(c, 16)) + bytes.fromhex(d + e)


def capsule(payload_path, out):
    payload = open(payload_path, "rb").read()
    cert = b"placeholder, not a signature"
    auth = struct.pack("<QIHH", 1, 24 + len(cert), 0x0200, 0x0EF1)
    auth += guid("4aafd29d-68df-49ee-8aa9-347d375665a7") + cert
    body = auth + b"MSS1" + struct.pack("<III", 16, 0x00010002, 0x00010000) + payload
    image = struct.pack("<I", 2) + guid("5a17e2e0-7e1d-4a7b-9c0d-5a1700000001") + bytes([1, 0, 0, 0])
    image += struct.pack("<IIQ", len(body), 0, 0) + body
    fmp = struct.pack("<IHH", 1, 0, 1) + struct.pack("<Q", 16) + image
    header = guid("6dcbd5ed-e82d-4c44-bda1-7194199ad92a") + struct.pack("<III", 28, 0x50000, 28 + len(fmp))
    open(out, "wb").write(header + fmp)


def edc(data):
    """CD-ROM EDC: CRC-32 with polynomial 0xD8018001 (reflected)."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xD8018001 if crc & 1 else 0)
    return crc


def bcd(n):
    return (n // 10) << 4 | (n % 10)


def cdbin(iso_path, out, mode):
    iso = open(iso_path, "rb").read()
    mode = int(mode)
    sync = b"\x00" + b"\xff" * 10 + b"\x00"
    sectors = []
    for i in range(len(iso) // 2048):
        lba = i + 150
        addr = bytes([bcd(lba // 4500), bcd(lba // 75 % 60), bcd(lba % 75)])
        user = iso[i * 2048 : (i + 1) * 2048]
        if mode == 1:
            head = sync + addr + b"\x01"
            body = head + user
            sectors.append(body + struct.pack("<I", edc(body)) + bytes(8 + 276))
        else:
            sub = b"\x00\x00\x08\x00" * 2  # form 1, data
            body = sub + user
            sectors.append(sync + addr + b"\x02" + body + struct.pack("<I", edc(body)) + bytes(276))
    open(out, "wb").write(b"".join(sectors))


def ccd(iso_path, out):
    sectors = len(open(iso_path, "rb").read()) // 2048
    lead_out = sectors + 150
    lines = [
        "[CloneCD]", "Version=3", "[Disc]", "TocEntries=4", "Sessions=1", "DataTracksScrambled=0",
        "CDTextLength=0", "[Session 1]", "PreGapMode=1", "PreGapSubC=0",
    ]
    for n, (point, pmin, psec, plba) in enumerate([
        (0xA0, 1, 0, -150 + 1 * 4500), (0xA1, 1, 0, -150 + 1 * 4500),
        (0xA2, lead_out // 4500, lead_out // 75 % 60, sectors), (1, 0, 2, 0),
    ]):
        lines += [
            f"[Entry {n}]", "Session=1", f"Point=0x{point:02x}", "ADR=0x01", "Control=0x04", "TrackNo=0",
            "AMin=0", "ASec=0", "AFrame=0", "ALBA=-150", "Zero=0", f"PMin={pmin}", f"PSec={psec}", "PFrame=0",
            f"PLBA={plba}",
        ]
    lines += ["[TRACK 1]", "MODE=1", "INDEX 1=0"]
    open(out, "w", newline="\r\n").write("\n".join(lines) + "\n")


def appimage_runtime(out):
    upd = b"zsync|https://example.org/saltmere/Saltmere_Tides-latest-x86_64.AppImage.zsync"
    upd = upd + bytes(1024 - len(upd))
    sig = bytes(1024)  # unsigned: the signature section is left empty
    names = b"\0.upd_info\0.sha256_sig\0.shstrtab\0"
    body = upd + sig + names
    data_at = 64
    shoff = data_at + len(body)
    shoff += -shoff % 8
    elf = bytearray(b"\x7fELF" + bytes([2, 1, 1, 0]) + b"AI\x02" + bytes(5))
    elf += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 4, 3)
    elf += body + bytes(shoff - data_at - len(body))

    def sh(name, ty, at, size):
        return struct.pack("<IIQQQQIIQQ", name, ty, 0, 0, at, size, 0, 0, 1, 0)

    elf += sh(0, 0, 0, 0)
    elf += sh(1, 1, data_at, len(upd))
    elf += sh(11, 1, data_at + len(upd), len(sig))
    elf += sh(23, 3, data_at + len(upd) + len(sig), len(names))
    open(out, "wb").write(elf)


def kernel(out):
    k = bytearray(4096)
    k[56:60] = b"ARMd"
    banner = b"Linux version 6.1.0-saltmere (builder@example.org) #1 SMP PREEMPT\n"
    k[1024 : 1024 + len(banner)] = banner
    open(out, "wb").write(k)


if __name__ == "__main__":
    kind, *args = sys.argv[1:]
    {"aff": aff, "appimage-runtime": appimage_runtime, "capsule": capsule, "cdbin": cdbin, "ccd": ccd, "kernel": kernel}[kind](*args)
