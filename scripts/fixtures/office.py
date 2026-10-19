"""Writers shared by the document fixture scripts: ZIP packages, OLE2
compound files (MS-CFB v3), MS-OVBA compression and VBA projects, and OLE
property sets (MS-OLEPS). Standard library only; output is deterministic.
"""

import io
import struct
import zipfile

# --------------------------------------------------------------------------
# ZIP


def zip_bytes(entries, stored=()):
    """A ZIP of (name, bytes|str) entries with a fixed timestamp. Names in
    `stored` are written uncompressed (the `mimetype` of ODF / EPUB)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries:
            if isinstance(data, str):
                data = data.encode("utf-8")
            info = zipfile.ZipInfo(name, date_time=(2024, 9, 1, 12, 0, 0))
            info.compress_type = zipfile.ZIP_STORED if name in stored else zipfile.ZIP_DEFLATED
            info.create_system = 0
            z.writestr(info, data)
    return buf.getvalue()


# --------------------------------------------------------------------------
# OLE2 compound file, version 3 (512-byte sectors)

SECTOR = 512
MINI = 64
CUTOFF = 4096
ENDCHAIN, FREE, FATSECT, DIFSECT = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF


class _Node:
    def __init__(self, name, kind, data=b"", clsid=b"\0" * 16):
        self.name, self.kind, self.data, self.clsid = name, kind, data, clsid
        self.children = []
        self.start, self.size = ENDCHAIN, 0
        self.left = self.right = self.child = NOSTREAM


def cfb_bytes(streams, root_clsid=b"\0" * 16, storage_clsids=None):
    """A compound file holding `streams`: (path, bytes) with `/`-separated
    storages. `storage_clsids` maps storage paths to 16-byte class ids."""
    storage_clsids = storage_clsids or {}
    root = _Node("Root Entry", 5, clsid=root_clsid)
    nodes = [root]
    for path, data in streams:
        parent = root
        parts = path.split("/")
        for i, part in enumerate(parts):
            last = i == len(parts) - 1
            found = next((c for c in parent.children if c.name == part), None)
            if found is None:
                sub = "/".join(parts[: i + 1])
                found = _Node(part, 2 if last else 1, data if last else b"", storage_clsids.get(sub, b"\0" * 16))
                parent.children.append(found)
                nodes.append(found)
            parent = found

    sectors, fat = [], []

    def alloc(data):
        if not data:
            return ENDCHAIN
        first = len(sectors)
        n = (len(data) + SECTOR - 1) // SECTOR
        for k in range(n):
            sectors.append(data[k * SECTOR:(k + 1) * SECTOR].ljust(SECTOR, b"\0"))
            fat.append(ENDCHAIN if k == n - 1 else first + k + 1)
        return first

    mini, minifat = bytearray(), []
    for n in nodes[1:]:
        if n.kind == 2 and 0 < len(n.data) < CUTOFF:
            first = len(mini) // MINI
            count = (len(n.data) + MINI - 1) // MINI
            for k in range(count):
                minifat.append(ENDCHAIN if k == count - 1 else first + k + 1)
            mini += n.data.ljust(count * MINI, b"\0")
            n.start, n.size = first, len(n.data)
    # Children of each storage as a degenerate (all-black, right-leaning) tree,
    # sorted the way Windows compares names (length, then upper case).
    for n in nodes:
        n.children.sort(key=lambda c: (len(c.name), c.name.upper()))
        for a, b in zip(n.children, n.children[1:]):
            a.right = nodes.index(b)
        if n.children:
            n.child = nodes.index(n.children[0])
    # Reserve the FAT sectors first (enough for everything that follows).
    payload = sum((len(n.data) + SECTOR - 1) // SECTOR for n in nodes if n.kind == 2 and len(n.data) >= CUTOFF)
    est = payload + (len(nodes) * 128) // SECTOR + 2 + (len(minifat) * 4) // SECTOR + 2 + len(mini) // SECTOR + 2
    fat_sectors = 1
    while fat_sectors * (SECTOR // 4) < est + fat_sectors:
        fat_sectors += 1
    assert fat_sectors <= 109, "fixture too large for a header-only DIFAT"
    for _ in range(fat_sectors):
        sectors.append(b"\0" * SECTOR)
        fat.append(FATSECT)
    dir_start = alloc(b"\0" * (len(nodes) * 128))
    minifat_bytes = b"".join(struct.pack("<I", v) for v in minifat)
    minifat_start = alloc(minifat_bytes)
    root.start = alloc(bytes(mini))
    root.size = len(mini)
    for n in nodes[1:]:
        if n.kind == 2 and len(n.data) >= CUTOFF:
            n.start, n.size = alloc(n.data), len(n.data)
    directory = bytearray()
    for n in nodes:
        name = n.name.encode("utf-16-le") + b"\0\0"
        rec = name.ljust(64, b"\0")
        rec += struct.pack("<HBB", len(name), n.kind, 1)
        rec += struct.pack("<III", n.left, n.right, n.child)
        rec += n.clsid + b"\0" * 4 + b"\0" * 16
        rec += struct.pack("<IQ", n.start if n.kind != 1 else 0, n.size)
        directory += rec
    for k in range(0, len(directory), SECTOR):
        sectors[dir_start + k // SECTOR] = bytes(directory[k:k + SECTOR]).ljust(SECTOR, b"\0")
    fat_bytes = b"".join(struct.pack("<I", v) for v in fat).ljust(fat_sectors * SECTOR, b"\xff")
    for k in range(fat_sectors):
        sectors[k] = fat_bytes[k * SECTOR:(k + 1) * SECTOR]
    header = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\0" * 16
    header += struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\0" * 6
    header += struct.pack("<IIIII", 0, fat_sectors, dir_start, 0, CUTOFF)
    header += struct.pack("<III", minifat_start, (len(minifat_bytes) + SECTOR - 1) // SECTOR, ENDCHAIN)
    header += struct.pack("<I", 0)
    difat = list(range(fat_sectors)) + [FREE] * (109 - fat_sectors)
    header += b"".join(struct.pack("<I", v) for v in difat)
    return header + b"".join(sectors)


def guid_bytes(s):
    """A GUID string as its little-endian 16-byte layout."""
    h = s.replace("-", "")
    b = bytes.fromhex(h)
    return b[3::-1] + b[5:3:-1] + b[7:5:-1] + b[8:]


# --------------------------------------------------------------------------
# MS-OVBA compression and VBA projects


def ovba_compress(data):
    out = bytearray([1])
    for c in range(0, max(len(data), 1), 4096):
        chunk = data[c:c + 4096]
        body = bytearray()
        pos = 0
        while pos < len(chunk):
            flag_at = len(body)
            body.append(0)
            flags = 0
            for bit in range(8):
                if pos >= len(chunk):
                    break
                bits = max((pos - 1).bit_length() if pos > 1 else 0, 4)
                max_len = (0xFFFF >> bits) + 3
                best_len = best_off = 0
                for off in range(1, min(pos, 1 << bits) + 1):
                    n = 0
                    while n < max_len and pos + n < len(chunk) and chunk[pos + n - off] == chunk[pos + n]:
                        n += 1
                    if n > best_len:
                        best_len, best_off = n, off
                if best_len >= 3:
                    body += struct.pack("<H", ((best_off - 1) << (16 - bits)) | (best_len - 3))
                    flags |= 1 << bit
                    pos += best_len
                else:
                    body.append(chunk[pos])
                    pos += 1
            body[flag_at] = flags
        assert len(body) <= 4096, "chunk does not compress"
        out += struct.pack("<H", 0xB000 | (len(body) + 2 - 3)) + body
    return bytes(out)


def _rec(rid, data):
    return struct.pack("<HI", rid, len(data)) + data


def vba_project(modules, project="Project", prefix=""):
    """Streams of a VBA project: `modules` is a list of (name, source,
    is_document). With `prefix` (e.g. `Macros`) the project sits in that
    storage, as in Word 97-2003 files; without it, it is a vbaProject.bin."""
    d = bytearray()
    d += _rec(0x0001, struct.pack("<I", 1))
    d += _rec(0x0002, struct.pack("<I", 0x409))
    d += _rec(0x0014, struct.pack("<I", 0x409))
    d += _rec(0x0003, struct.pack("<H", 1252))
    d += _rec(0x0004, project.encode())
    d += _rec(0x0005, b"") + _rec(0x0040, b"")
    d += _rec(0x0006, b"") + _rec(0x003D, b"")
    d += _rec(0x0007, struct.pack("<I", 0))
    d += _rec(0x0008, struct.pack("<I", 0))
    d += struct.pack("<HIIH", 0x0009, 4, 1, 0)  # PROJECTVERSION: size says 4, holds 6
    d += _rec(0x000C, b"") + _rec(0x003C, b"")
    d += _rec(0x000F, struct.pack("<H", len(modules)))
    d += _rec(0x0013, struct.pack("<H", 0xFFFF))
    streams = []
    lines = [f'ID="{{00000000-0000-0000-0000-000000000000}}"']
    for name, source, document in modules:
        d += _rec(0x0019, name.encode()) + _rec(0x0047, name.encode("utf-16-le"))
        d += _rec(0x001A, name.encode()) + _rec(0x0032, name.encode("utf-16-le"))
        d += _rec(0x001C, b"") + _rec(0x0048, b"")
        d += _rec(0x0031, struct.pack("<I", 0))
        d += _rec(0x001E, struct.pack("<I", 0))
        d += _rec(0x002C, struct.pack("<H", 0xFFFF))
        d += _rec(0x0022 if document else 0x0021, b"")
        d += _rec(0x002B, b"")
        header = f'Attribute VB_Name = "{name}"\r\n'
        streams.append((f"VBA/{name}", ovba_compress((header + source.replace("\n", "\r\n")).encode("cp1252"))))
        lines.append(f"Document={name}/&H00000000" if document else f"Module={name}")
    d += _rec(0x0010, b"")
    lines += [f'Name="{project}"', 'HelpContextID="0"', 'VersionCompatible32="393222000"', ""]
    streams += [
        ("VBA/dir", ovba_compress(bytes(d))),
        ("VBA/_VBA_PROJECT", b"\xCC\x61\xFF\xFF\x00\x00\x00"),
        ("PROJECT", "\r\n".join(lines).encode("cp1252")),
        ("PROJECTwm", b"".join(n.encode() + b"\0" + n.encode("utf-16-le") + b"\0\0" for n, _, _ in modules) + b"\0\0"),
    ]
    if prefix:
        streams = [(f"{prefix}/{p}", s) for p, s in streams]
    return streams


# --------------------------------------------------------------------------
# OLE property sets

VT_I2, VT_I4, VT_BOOL, VT_LPSTR, VT_LPWSTR, VT_FILETIME = 2, 3, 11, 30, 31, 64
FMTID_SUMMARY = "F29F85E0-4FF9-1068-AB91-08002B27B3D9"
FMTID_DOC_SUMMARY = "D5CDD502-2E9C-101B-9397-08002B2CF9AE"
FMTID_USER = "D5CDD505-2E9C-101B-9397-08002B2CF9AE"


def filetime(iso):
    """`YYYY-MM-DDTHH:MM:SSZ` as FILETIME ticks."""
    import datetime

    t = datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    return int((t.timestamp() + 11644473600) * 10_000_000)


def _value(vt, v):
    if vt == VT_I2:
        return struct.pack("<HHh", vt, 0, v) + b"\0\0"
    if vt == VT_I4:
        return struct.pack("<HHi", vt, 0, v)
    if vt == VT_BOOL:
        return struct.pack("<HHh", vt, 0, -1 if v else 0) + b"\0\0"
    if vt == VT_LPSTR:
        raw = v.encode("cp1252") + b"\0"
        raw = struct.pack("<HHI", vt, 0, len(raw)) + raw
        return raw.ljust((len(raw) + 3) // 4 * 4, b"\0")
    if vt == VT_FILETIME:
        return struct.pack("<HHQ", vt, 0, v)
    raise ValueError(vt)


def _section(props, names=None):
    """props: list of (id, vt, value); names: {id: name} dictionary."""
    entries = [(1, _value(VT_I2, 1252))]
    if names:
        d = struct.pack("<I", len(names))
        for pid, name in names.items():
            raw = name.encode("cp1252") + b"\0"
            d += struct.pack("<II", pid, len(raw)) + raw
        entries.insert(0, (0, d.ljust((len(d) + 3) // 4 * 4, b"\0")))
    entries += [(pid, _value(vt, v)) for pid, vt, v in props]
    head = 8 + 8 * len(entries)
    body, index = b"", b""
    for pid, raw in entries:
        index += struct.pack("<II", pid, head + len(body))
        body += raw
    return struct.pack("<II", head + len(body), len(entries)) + index + body


def property_set(sections):
    """A property-set stream: sections is a list of (fmtid, props[, names])."""
    out = struct.pack("<HHI", 0xFFFE, 0, 0x00020006) + b"\0" * 16 + struct.pack("<I", len(sections))
    offset = 28 + 20 * len(sections)
    blobs = []
    for s in sections:
        fmtid, props = s[0], s[1]
        names = s[2] if len(s) > 2 else None
        blob = _section(props, names)
        out += guid_bytes(fmtid) + struct.pack("<I", offset)
        offset += len(blob)
        blobs.append(blob)
    return out + b"".join(blobs)
