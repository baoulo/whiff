#!/usr/bin/env python3
"""Write the executable fixtures no tool here writes.

    craft_executables.py dos OUT       MS-DOS MZ program printing a line
    craft_executables.py ne OUT        Windows 3.x NE header (module name, description)
    craft_executables.py le OUT        Windows 386 LE virtual device header
    craft_executables.py dotnet OUT    PE32 DLL with a .NET CLI header and metadata root
    craft_executables.py trim-core IN OUT   an ELF core's headers and notes, without the memory

Every file is benign: headers and a few bytes of code that print the
fictitious Saltmere Harbour's name and exit, or no code at all.
"""

import struct
import sys

LIMIT = 256 * 1024


def mz(lfanew, body):
    """A 64-byte MZ header (4 paragraphs) followed by `body`."""
    size = 64 + len(body)
    h = struct.pack(
        "<2sHHHHHHHHHHHHH",
        b"MZ",
        size % 512,
        (size + 511) // 512,
        0,  # relocations
        4,  # header paragraphs
        0,
        0xFFFF,
        0,
        0x100,  # SS:SP
        0,
        0,  # IP
        0,  # CS
        0x40,  # relocation table
        0,
    )
    h += b"\0" * (0x3C - len(h)) + struct.pack("<I", lfanew)
    return h + body


def dos():
    msg = b"Saltmere Harbour tides$"
    # push cs; pop ds; mov dx, msg; mov ah, 9; int 21h; mov ax, 4c00h; int 21h
    code = bytes([0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x00, 0x4C, 0xCD, 0x21])
    return mz(0, code + msg)


def ne():
    stub = mz(0x80, b"")
    stub += b"\0" * (0x80 - len(stub))
    resident = b"\x05TIDES" + struct.pack("<H", 0) + b"\0"
    desc = b"Saltmere tide table for Windows 3.1"
    nonres_at = 0x80 + 0x40 + len(resident)
    nonres = bytes([len(desc)]) + desc + struct.pack("<H", 0) + b"\0"
    h = bytearray(0x40)
    h[0:2] = b"NE"
    h[2], h[3] = 5, 10  # linker version
    struct.pack_into("<H", h, 0x0C, 0x0302)  # program flags
    struct.pack_into("<H", h, 0x1C, 0)  # segments
    struct.pack_into("<H", h, 0x1E, 0)  # module references
    struct.pack_into("<H", h, 0x20, len(nonres))
    struct.pack_into("<H", h, 0x26, 0x40)  # resident names, relative
    struct.pack_into("<I", h, 0x2C, nonres_at)
    h[0x36] = 2  # Windows
    h[0x3E], h[0x3F] = 10, 3  # Windows 3.10
    return stub + bytes(h) + resident + nonres


def le():
    stub = mz(0x80, b"")
    stub += b"\0" * (0x80 - len(stub))
    h = bytearray(0xC4)
    h[0:2] = b"LE"
    struct.pack_into("<H", h, 0x08, 2)  # 80386
    struct.pack_into("<H", h, 0x0A, 4)  # Windows 386
    struct.pack_into("<I", h, 0x0C, 0x0100)  # module version
    struct.pack_into("<I", h, 0x10, 0x28000)  # virtual device driver
    struct.pack_into("<I", h, 0x14, 0)  # pages
    struct.pack_into("<I", h, 0x58, len(h))  # resident names, relative
    names = b"\x0bSALTMERE_TD" + struct.pack("<H", 0) + b"\0"
    return stub + bytes(h) + names


def dotnet():
    """A PE32 DLL whose .text holds a CLI header and a metadata root."""
    file_align, rva = 0x200, 0x2000
    text = bytearray(0x200)
    # COR20 header at RVA 0x2008: size, runtime 2.5, metadata, IL-only.
    struct.pack_into("<IHHIII", text, 8, 72, 2, 5, rva + 0x50, 0x40, 1)
    # Metadata root at RVA 0x2050: BSJB, version string, no streams.
    version = b"v4.0.30319\0\0"
    struct.pack_into("<IHHII", text, 0x50, 0x424A5342, 1, 1, 0, len(version))
    text[0x60 : 0x60 + len(version)] = version
    opt = bytearray(224)
    struct.pack_into("<HBBIII", opt, 0, 0x10B, 8, 0, 0x200, 0, 0)
    struct.pack_into("<III", opt, 16, 0, rva, 0)  # entry, code, data
    struct.pack_into("<III", opt, 28, 0x10000000, 0x2000, file_align)
    struct.pack_into("<HHHHHH", opt, 40, 4, 0, 0, 0, 4, 0)
    struct.pack_into("<III", opt, 56, 0x4000, 0x200, 0)  # image, headers, checksum
    struct.pack_into("<HH", opt, 68, 3, 0x8540)  # console; NX, ASLR, no SEH, TS aware
    struct.pack_into("<IIII", opt, 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<II", opt, 88, 0, 16)
    struct.pack_into("<II", opt, 96 + 14 * 8, rva + 8, 72)  # CLR runtime header
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 1756728000, 0, 0, len(opt), 0x2102)
    sec = struct.pack("<8sIIIIIIHHI", b".text", 0x200, rva, 0x200, file_align, 0, 0, 0, 0, 0x60000020)
    head = mz(0x80, b"")
    head += b"\0" * (0x80 - len(head))
    head += b"PE\0\0" + coff + bytes(opt) + sec
    head += b"\0" * (file_align - len(head))
    return head + bytes(text)


def trim_core(data):
    """Keep the ELF header, program headers and notes of a 64-bit
    little-endian core; memory segments keep their addresses and sizes but
    no dumped bytes (as with a core filter that dumps nothing)."""
    assert data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1
    phoff, = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    out_ph = []
    notes = b""
    base = 64 + phnum * phentsize
    for i in range(phnum):
        ph = bytearray(data[phoff + i * phentsize : phoff + (i + 1) * phentsize])
        kind, = struct.unpack_from("<I", ph, 0)
        off, filesz = struct.unpack_from("<Q", ph, 8)[0], struct.unpack_from("<Q", ph, 32)[0]
        if kind == 4:
            struct.pack_into("<Q", ph, 8, base + len(notes))
            notes += data[off : off + filesz]
        else:
            struct.pack_into("<Q", ph, 8, 0)
            struct.pack_into("<Q", ph, 32, 0)
        out_ph.append(bytes(ph))
    ehdr = bytearray(data[:64])
    struct.pack_into("<Q", ehdr, 32, 64)  # program headers right after
    struct.pack_into("<Q", ehdr, 40, 0)  # no section headers
    struct.pack_into("<HHH", ehdr, 58, 0, 0, 0)
    out = bytes(ehdr) + b"".join(out_ph) + notes
    assert len(out) <= LIMIT
    return out


def main():
    kind = sys.argv[1]
    if kind == "trim-core":
        with open(sys.argv[2], "rb") as f:
            data = trim_core(f.read())
        out = sys.argv[3]
    else:
        data = {"dos": dos, "ne": ne, "le": le, "dotnet": dotnet}[kind]()
        out = sys.argv[2]
    with open(out, "wb") as f:
        f.write(data)


if __name__ == "__main__":
    main()
