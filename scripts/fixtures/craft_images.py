#!/usr/bin/env python3
"""Craft the image fixtures that no installed tool writes: camera raw
structures (DNG, CR2, CR3, NEF, ARW, ORF, RW2, PEF, RAF, SRW), GIMP XCF,
EMF / WMF, KTX / KTX2, Windows cursors, and PNGs carrying AI-generator
parameters. Standard library only; output is deterministic.

    python3 scripts/fixtures/craft_images.py tests/fixtures
    python3 scripts/fixtures/craft_images.py --icc profile.icc   # the test ICC profile only

Pixel data is a few placeholder bytes: whiff never decodes it. Every name,
place and caption is fictitious.
"""

import gzip
import io
import json
import struct
import sys
import zlib
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures")

# --------------------------------------------------------------------------
# TIFF builder: IFDs with references to other IFDs and to data blobs.

BYTE, ASCII, SHORT, LONG, RATIONAL, UNDEFINED, SRATIONAL = 1, 2, 3, 4, 5, 7, 10
SIZES = {BYTE: 1, ASCII: 1, SHORT: 2, LONG: 4, RATIONAL: 8, UNDEFINED: 1, SRATIONAL: 8}


class Ref:
    """The offset of a named IFD or blob."""

    def __init__(self, name):
        self.name = name


def ascii_(s):
    return (ASCII, s.encode() + b"\0")


def short(*v):
    return (SHORT, list(v))


def long_(*v):
    return (LONG, list(v))


def rational(*v):
    out = []
    for x in v:
        if isinstance(x, tuple):
            out.append(x)
        else:
            out.append((int(round(x * 10000)), 10000))
    return (RATIONAL, out)


def undefined(b):
    return (UNDEFINED, b)


def byte(*v):
    return (BYTE, bytes(v))


def tiff(le, ifds, blobs=None, header=None, first="ifd0"):
    """Build a TIFF. `ifds` is an ordered dict name -> (entries, next_name)
    where entries map tag -> (type, values). `header` replaces the standard
    8-byte header (it must end with room for the IFD0 offset at 4..8)."""
    blobs = blobs or {}
    e = "<" if le else ">"
    head = header if header is not None else (b"II*\0" if le else b"MM\0*") + b"\0\0\0\0"

    def value_bytes(typ, vals, offsets):
        if typ in (ASCII, UNDEFINED, BYTE):
            return bytes(vals)
        if typ == SHORT:
            return b"".join(struct.pack(e + "H", v) for v in vals)
        if typ == LONG:
            return b"".join(struct.pack(e + "I", offsets[v.name] if isinstance(v, Ref) else v) for v in vals)
        if typ in (RATIONAL, SRATIONAL):
            f = "i" if typ == SRATIONAL else "I"
            return b"".join(struct.pack(e + f + f, n, d) for n, d in vals)
        raise ValueError(typ)

    def count(typ, vals):
        return len(vals)

    def ifd_size(entries):
        size = 2 + 12 * len(entries) + 4
        for typ, vals in entries.values():
            n = count(typ, vals) * SIZES[typ]
            if n > 4:
                size += n + (n & 1)
        return size

    offsets = {}
    pos = len(head)
    for name, (entries, _next) in ifds.items():
        offsets[name] = pos
        pos += ifd_size(entries)
    for name, data in blobs.items():
        offsets[name] = pos
        pos += len(data) + (len(data) & 1)

    out = bytearray(head)
    out[4:8] = struct.pack(e + "I", offsets[first])
    for name, (entries, nxt) in ifds.items():
        assert len(out) == offsets[name]
        data_at = offsets[name] + 2 + 12 * len(entries) + 4
        table = bytearray(struct.pack(e + "H", len(entries)))
        extra = bytearray()
        for tag in sorted(entries):
            typ, vals = entries[tag]
            vb = value_bytes(typ, vals, offsets)
            table += struct.pack(e + "HHI", tag, typ, count(typ, vals))
            if len(vb) <= 4:
                table += vb.ljust(4, b"\0")
            else:
                table += struct.pack(e + "I", data_at + len(extra))
                extra += vb + (b"\0" if len(vb) & 1 else b"")
        table += struct.pack(e + "I", offsets[nxt] if nxt else 0)
        out += table + extra
    for name, data in blobs.items():
        assert len(out) == offsets[name]
        out += data + (b"\0" if len(data) & 1 else b"")
    return bytes(out)


def camera(make, model, when="2024:06:01 09:30:00", offset="+02:00", lat=None, lon=None, artist=None):
    """IFD0 metadata, the Exif IFD and (optionally) the GPS IFD."""
    ifd0 = {
        271: ascii_(make),
        272: ascii_(model),
        274: short(1),
        282: rational(300),
        283: rational(300),
        296: short(2),
        305: ascii_("whiff fixture generator"),
        306: ascii_(when),
        34665: long_(Ref("exif")),
    }
    if artist:
        ifd0[315] = ascii_(artist)
        ifd0[33432] = ascii_(f"(c) 2024 {artist}")
    exif = {
        33434: rational((1, 250)),
        33437: rational(5.6),
        34855: short(200),
        36864: undefined(b"0232"),
        36867: ascii_(when),
        36868: ascii_(when),
        36881: ascii_(offset),
        37386: rational(35),
        42036: ascii_(f"{model} lens 24-70mm"),
    }
    gps = None
    if lat is not None:
        ifd0[34853] = long_(Ref("gps"))

        def dms(x):
            x = abs(x)
            d = int(x)
            m = int((x - d) * 60)
            s = round(((x - d) * 60 - m) * 60, 2)
            return rational((d, 1), (m, 1), (int(s * 100), 100))

        gps = {
            0: byte(2, 3, 0, 0),
            1: ascii_("N" if lat >= 0 else "S"),
            2: dms(lat),
            3: ascii_("E" if lon >= 0 else "W"),
            4: dms(lon),
        }
    return ifd0, exif, gps


def tiff_raw(le, make, model, raw_tags=None, header=None, ifd0_extra=None, preview=True, **kw):
    """IFD0 = small preview strip (NewSubfileType 1), SubIFD 0 = CFA raw."""
    ifd0, exif, gps = camera(make, model, **kw)
    ifd0.update(
        {
            254: long_(1),
            256: long_(16),
            257: long_(12),
            258: short(8, 8, 8),
            259: short(1),
            262: short(2),
            273: long_(Ref("preview")),
            277: short(3),
            278: long_(12),
            279: long_(16 * 12 * 3),
            330: long_(Ref("raw")),
        }
    )
    ifd0.update(ifd0_extra or {})
    raw = {
        254: long_(0),
        256: long_(64),
        257: long_(48),
        258: short(14),
        259: short(1),
        262: short(32803),
        273: long_(Ref("sensor")),
        277: short(1),
        278: long_(48),
        279: long_(64),
        33421: short(2, 2),
        33422: byte(0, 1, 1, 2),
    }
    raw.update(raw_tags or {})
    ifds = {"ifd0": (ifd0, None), "raw": (raw, None), "exif": (exif, None)}
    if gps:
        ifds["gps"] = (gps, None)
    blobs = {"preview": bytes(16 * 12 * 3), "sensor": bytes(64)}
    return tiff(le, ifds, blobs, header=header)


def write(rel, data):
    p = OUT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    print(f"{rel}: {len(data)} bytes")


def jpeg_with_exif(exif_tiff, w=16, h=12):
    """A structurally valid baseline JPEG (one 8x8-block grey frame) with an
    APP1 EXIF segment. The entropy-coded data is a placeholder."""
    app1 = b"Exif\0\0" + exif_tiff
    seg = lambda m, body: b"\xff" + bytes([m]) + struct.pack(">H", len(body) + 2) + body
    sof = struct.pack(">BHHB", 8, h, w, 1) + b"\x01\x11\x00"
    dqt = b"\x00" + bytes([16] * 64)
    return b"\xff\xd8" + seg(0xE1, app1) + seg(0xDB, dqt) + seg(0xC0, sof) + seg(0xDA, b"\x01\x01\x00\x00\x3f\x00") + b"\x00\xff\xd9"


# --------------------------------------------------------------------------
# Camera raw


def raws():
    write(
        "dng/sample.dng",
        tiff_raw(
            True,
            "Example",
            "Example DNG Camera",
            artist="Mira Castell",
            lat=45.4642,
            lon=9.19,
            ifd0_extra={50706: byte(1, 6, 0, 0), 50707: byte(1, 1, 0, 0), 50708: ascii_("Example DNG Camera"), 50827: ascii_("IMG_0001.RAW")},
        ),
    )
    # CR2: TIFF header + "CR" 2.0 + raw IFD offset; IFD0 is the preview.
    cr2_head = b"II*\0\0\0\0\0CR\x02\0\0\0\0\0"
    write("cr2/sample.cr2", tiff_raw(True, "Canon", "Canon EOS Example", header=cr2_head, artist="Jonas Wren"))
    write("nef/sample.nef", tiff_raw(False, "NIKON CORPORATION", "NIKON Z example", lat=-33.8568, lon=151.2153))
    write("arw/sample.arw", tiff_raw(True, "SONY", "ILCE-EXAMPLE"))
    write("pef/sample.pef", tiff_raw(True, "PENTAX", "PENTAX K-EXAMPLE"))
    write("srw/sample.srw", tiff_raw(True, "SAMSUNG", "NX-EXAMPLE"))
    # ORF: "IIRO" magic, otherwise TIFF.
    orf = bytearray(tiff_raw(True, "OLYMPUS IMAGING CORP.", "E-EXAMPLE"))
    orf[2:4] = b"RO"
    write("orf/sample.orf", bytes(orf))
    # RW2: "IIU\0", sensor size in tags 2 / 3, EXIF in an embedded JPEG (0x2E).
    ifd0, exif, gps = camera("Panasonic", "DC-EXAMPLE", lat=48.8584, lon=2.2945)
    inner = tiff(True, {"ifd0": (ifd0, None), "exif": (exif, None), "gps": (gps, None)})
    jpg = jpeg_with_exif(inner)
    rw2_ifd0 = {
        1: undefined(b"0470"),
        2: short(64),
        3: short(48),
        4: short(0),
        5: short(0),
        6: short(48),
        7: short(64),
        10: short(12),
        271: ascii_("Panasonic"),
        272: ascii_("DC-EXAMPLE"),
        46: undefined(jpg),
    }
    rw2 = bytearray(tiff(True, {"ifd0": (rw2_ifd0, None)}))
    rw2[2:4] = b"U\0"
    write("rw2/sample.rw2", bytes(rw2))
    # RAF: header, directory, embedded JPEG with EXIF.
    ifd0, exif, gps = camera("FUJIFILM", "X-EXAMPLE", artist="Ines Halvorsen")
    jpg = jpeg_with_exif(tiff(False, {"ifd0": (ifd0, None), "exif": (exif, None)}))
    head = bytearray(b"FUJIFILMCCD-RAW 0201FF383501")
    head += b"X-EXAMPLE".ljust(32, b"\0")
    head += b"0100"
    head += bytes(20)
    off = 160
    # CFA header: one record, 0x100 = raw image size (height 48, width 64).
    cfa_header = struct.pack(">I", 1) + struct.pack(">HH", 0x100, 4) + struct.pack(">HH", 48, 64)
    cfa_at = off + len(jpg)
    head += struct.pack(">II", off, len(jpg))
    head += struct.pack(">II", cfa_at, len(cfa_header)) + struct.pack(">II", 0, 0)
    head = bytes(head).ljust(off, b"\0")
    write("raf/sample.raf", head + jpg + cfa_header + bytes(32))
    # CR3: ftyp crx, moov with Canon uuid holding CMT1 (IFD0), CMT2 (Exif), CMT4 (GPS).
    ifd0, exif, gps = camera("Canon", "Canon EOS R-Example", lat=35.6586, lon=139.7454, artist="Jonas Wren")
    ifd0.pop(34665)
    ifd0.pop(34853)
    exif[40962] = long_(6000)
    exif[40963] = long_(4000)
    box = lambda kind, body: struct.pack(">I", len(body) + 8) + kind + body
    cmt1 = tiff(True, {"ifd0": (ifd0, None)})
    cmt2 = tiff(True, {"ifd0": (exif, None)})
    cmt4 = tiff(True, {"ifd0": (gps, None)})
    thmb = b"\0\0\0\0" + struct.pack(">HH", 160, 120) + bytes(8)
    canon = bytes.fromhex("85c0b687820f11e08111f4ce462b6a48")
    uuid = box(b"uuid", canon + box(b"CNCV", b"CanonCR3_001/00.10.00/00.00.00") + box(b"CMT1", cmt1) + box(b"CMT2", cmt2) + box(b"CMT4", cmt4) + box(b"THMB", thmb))
    moov = box(b"moov", uuid + box(b"mvhd", bytes(100)))
    ftyp = box(b"ftyp", b"crx \0\0\0\x01crx isom")
    write("cr3/sample.cr3", ftyp + moov + box(b"mdat", bytes(64)))


# --------------------------------------------------------------------------
# A small ICC v4 display profile (whiff's own, CC0) for embedding in fixtures


def icc_profile():
    be = lambda f, *v: struct.pack(">" + f, *v)

    def mluc(text):
        s = text.encode("utf-16-be")
        return b"mluc" + bytes(4) + be("II", 1, 12) + b"enUS" + be("II", len(s), 28) + s

    def xyz(x, y, z):
        f = lambda v: be("i", int(round(v * 65536)))
        return b"XYZ " + bytes(4) + f(x) + f(y) + f(z)

    tags = [
        (b"desc", mluc("whiff test sRGB-like profile")),
        (b"cprt", mluc("CC0-1.0, whiff project")),
        (b"wtpt", xyz(0.9642, 1.0, 0.8249)),
        (b"rXYZ", xyz(0.4361, 0.2225, 0.0139)),
        (b"gXYZ", xyz(0.3851, 0.7169, 0.0971)),
        (b"bXYZ", xyz(0.1431, 0.0606, 0.7141)),
    ]
    table_len = 4 + 12 * len(tags)
    at = 128 + table_len
    table, data = be("I", len(tags)), b""
    for sig, body in tags:
        body += bytes((4 - len(body) % 4) % 4)
        table += sig + be("II", at + len(data), len(body))
        data += body
    size = 128 + table_len + len(data)
    header = be("I", size) + b"none" + be("I", 0x04300000) + b"mntrRGB XYZ " + be("HHHHHH", 2024, 1, 1, 0, 0, 0)
    header += b"acsp" + b"APPL" + be("I", 0) + b"none" + b"none" + bytes(8) + be("I", 0)
    header += be("iii", 63190, 65536, 54061) + b"whff" + bytes(16) + bytes(28)
    assert len(header) == 128, len(header)
    return header + table + data


# --------------------------------------------------------------------------
# GIMP XCF (version 11: 64-bit pointers, precision field)


def xcf():
    be = lambda f, *v: struct.pack(">" + f, *v)
    s = lambda t: be("I", len(t.encode()) + 1) + t.encode() + b"\0"

    def prop(kind, payload):
        return be("II", kind, len(payload)) + payload

    def parasite(name, data):
        return s(name) + be("II", 1, len(data)) + data

    icc_like = b"not a real ICC profile"
    parasites = parasite("gimp-comment", b"Harbour at dusk, painted for the whiff tests\0") + parasite("gimp-image-grid", b"(style solid)\0")
    props = prop(17, b"\x02") + prop(19, be("ff", 300.0, 300.0)) + prop(21, parasites) + prop(0, b"")
    head = b"gimp xcf v011\0" + be("III", 64, 48, 0) + be("I", 150) + props
    # Two layers; pointers are absolute file offsets.
    layer = lambda name: be("III", 64, 48, 1) + s(name) + prop(0, b"") + be("QQ", 0, 0)
    l1, l2 = layer("Sky"), layer("Boats")
    ptr_table = 8 * 3 + 8  # two layer pointers + 0, one channel terminator
    l1_at = len(head) + ptr_table
    l2_at = l1_at + len(l1)
    data = head + be("QQQ", l1_at, l2_at, 0) + be("Q", 0) + l1 + l2
    write("xcf/sample.xcf", data)


# --------------------------------------------------------------------------
# Windows metafiles


def emf():
    le = lambda f, *v: struct.pack("<" + f, *v)
    desc = "whiff fixture generator\0Harbour plan\0\0".encode("utf-16-le")
    header_size = 108
    desc_off = header_size
    body_len = header_size + len(desc)
    eof = le("IIIII", 14, 20, 0, 0x10, 20)
    # EMR_COMMENT holding an EMF+ header record (Type 0x4001, Size 20, DataSize 8).
    plus_record = le("HHII", 0x4001, 1, 20, 8) + le("II", 0xDBC01002, 0)
    plus = le("III", 70, 16 + len(plus_record), 4 + len(plus_record)) + b"EMF+" + plus_record
    total = body_len + len(plus) + len(eof)
    h = le("II", 1, body_len)
    h += le("iiii", 0, 0, 199, 99)  # bounds (device units)
    h += le("iiii", 0, 0, 5291, 2645)  # frame (0.01 mm): 52.91 x 26.45 mm
    h += b" EMF" + le("I", 0x10000) + le("I", total) + le("I", 3) + le("HH", 1, 0)
    h += le("II", len(desc) // 2, desc_off) + le("I", 0)
    h += le("II", 1920, 1080) + le("II", 508, 286)
    h += le("II", 0, 0) + le("I", 0) + le("II", 508000, 285750)
    assert len(h) == header_size, len(h)
    write("emf/sample.emf", h + desc + plus + eof)

    # WMF with a placeable header: 2 x 1 inches at 1440 units per inch.
    ph = le("IHhhhhHI", 0x9AC6CDD7, 0, 0, 0, 2880, 1440, 1440, 0)
    checksum = 0
    for (w,) in struct.iter_unpack("<H", ph[:20]):
        checksum ^= w
    ph += le("H", checksum)
    records = le("IH", 3, 0)  # META_EOF
    header = le("HHHIHIH", 1, 9, 0x300, (18 + len(records)) // 2, 0, 3, 0)
    write("wmf/sample.wmf", ph + header + records)


# --------------------------------------------------------------------------
# Khronos textures


def ktx():
    le = lambda f, *v: struct.pack("<" + f, *v)
    kv = b""
    for k, v in [(b"KTXorientation", b"rd\0"), (b"KTXwriter", b"whiff fixture generator\0")]:
        entry = k + b"\0" + v
        kv += le("I", len(entry)) + entry + b"\0" * ((4 - len(entry) % 4) % 4)
    ident = b"\xabKTX 20\xbb\r\n\x1a\n"
    levels = 3
    index_len = 80 + 24 * levels
    kvd_off = index_len
    data_off = kvd_off + len(kv)
    head = ident + le("IIIIIIIII", 43, 1, 64, 32, 0, 0, 1, levels, 0)
    head += le("IIII", 0, 0, kvd_off, len(kv)) + le("QQ", 0, 0)
    lv = b""
    sizes = [64 * 32 * 4, 32 * 16 * 4, 16 * 8 * 4]
    at = data_off
    for size in sizes:
        lv += le("QQQ", at, size, size)
        at += size
    data = head + lv + kv + bytes(sum(sizes))
    write("ktx2/sample.ktx2", data)

    ident1 = b"\xabKTX 11\xbb\r\n\x1a\n"
    h1 = ident1 + le("IIIIIIIIIIIII", 0x04030201, 0x1401, 1, 0x1908, 0x8058, 0x1908, 32, 16, 0, 0, 1, 1, 0)
    write("ktx/sample.ktx", h1 + le("I", 32 * 16 * 4) + bytes(32 * 16 * 4))


# --------------------------------------------------------------------------
# Windows cursor (two PNG-encoded entries with hotspots)


def png(w, h, chunks=(), color=(40, 90, 160)):
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)

    raw = b"".join(b"\0" + bytes(color) * w for _ in range(h))
    out = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    for kind, body in chunks:
        out += chunk(kind, body)
    return out + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def cur():
    entries = [(32, 32, 4, 4), (16, 16, 2, 2)]
    images = [png(w, h) for w, h, _, _ in entries]
    out = struct.pack("<HHH", 0, 2, len(entries))
    at = 6 + 16 * len(entries)
    for (w, h, hx, hy), img in zip(entries, images):
        out += struct.pack("<BBBBHHII", w, h, 0, 0, hx, hy, len(img), at)
        at += len(img)
    write("cur/pointer.cur", out + b"".join(images))


# --------------------------------------------------------------------------
# TGA 2.0 with an extension area (author, comment, date, software)


def tga():
    le = lambda f, *v: struct.pack("<" + f, *v)
    image_id = b"harbour-tga"
    w, h = 16, 8
    head = le("BBB", len(image_id), 0, 2) + bytes(5) + le("HHHHBB", 0, 0, w, h, 24, 0x20) + image_id
    pixels = bytes([30, 60, 90]) * w * h
    pad = lambda s, n: s.encode("latin-1").ljust(n, b"\0")
    ext = le("H", 495) + pad("Jonas Wren", 41)
    ext += pad("Night harbour, long exposure", 81) + pad("Second line of the comment", 81) + bytes(81 * 2)
    ext += le("HHHHHH", 7, 14, 2023, 22, 5, 30)
    ext += pad("job-17", 41) + le("HHH", 0, 0, 0)
    ext += pad("whiff fixture generator", 41) + le("HB", 100, ord("a"))
    ext += le("I", 0) + le("HH", 1, 1) + le("HH", 0, 0) + le("III", 0, 0, 0) + b"\x00"
    assert len(ext) == 495, len(ext)
    ext_at = len(head) + len(pixels)
    footer = le("II", ext_at, 0) + b"TRUEVISION-XFILE.\0"
    write("tga/v2-extension.tga", head + pixels + ext + footer)


# --------------------------------------------------------------------------
# PNGs with AI-generation parameters


def ai_pngs():
    params = (
        "a lighthouse on a rocky coast at dusk, oil painting, warm light\n"
        "Negative prompt: blurry, text, watermark\n"
        "Steps: 28, Sampler: DPM++ 2M Karras, CFG scale: 6.5, Seed: 1234567, Size: 64x48, Model hash: abc123, Model: example-xl-base"
    )
    write("png/a1111-parameters.png", png(64, 48, [(b"tEXt", b"parameters\0" + params.encode())]))
    graph = {
        "4": {"class_type": "CheckpointLoaderSimple", "inputs": {"ckpt_name": "example_xl.safetensors"}},
        "6": {"class_type": "CLIPTextEncode", "inputs": {"text": "a quiet harbour with fishing boats, morning fog", "clip": ["4", 1]}},
        "7": {"class_type": "CLIPTextEncode", "inputs": {"text": "low quality", "clip": ["4", 1]}},
        "3": {"class_type": "KSampler", "inputs": {"seed": 42, "steps": 20, "cfg": 7, "model": ["4", 0]}},
    }
    itxt = b"prompt\0\x01\0\0\0" + zlib.compress(json.dumps(graph, sort_keys=True).encode())
    ztxt = b"Description\0\0" + zlib.compress("Generated for the whiff test-suite; not a photograph.".encode())
    write("png/comfyui-workflow.png", png(48, 32, [(b"iTXt", itxt), (b"zTXt", ztxt), (b"tIME", struct.pack(">HBBBBB", 2024, 3, 9, 14, 5, 0))]))


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--icc":
        Path(sys.argv[2]).write_bytes(icc_profile())
        sys.exit(0)
    raws()
    xcf()
    emf()
    ktx()
    cur()
    tga()
    ai_pngs()
