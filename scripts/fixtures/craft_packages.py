#!/usr/bin/env python3
"""Write the package fixtures no installed tool writes (or not reproducibly).

    craft_packages.py <tests/fixtures> <work dir>
    craft_packages.py --retime <file>...     (fixed times for tool output)

Standard library plus `openssl` (for real signatures). packages.sh runs the
real tools first and leaves some of their output in <work dir> (a signed
APK, aapt2's protocol-buffer manifest, a JAR, setuptools' egg-info), which
the containers here wrap: AAB, APK set, XAPK, AAR, egg.

Written here: Debian packages (dpkg-deb's layout: ar, control.tar.xz /
.zst / .gz, data.tar.xz), RPM (v4 headers, gzip and xz cpio payloads),
Arch (.pkg.tar.zst), Alpine (signed, three concatenated gzip streams),
conda (.tar.bz2 and .conda), an OCI image layout tarball, iOS IPA (binary
Info.plist, a CMS-signed provisioning profile), NuGet, MSIX / APPX and an
APPX bundle, VSIX, Firefox XPI, Chrome CRX3 (signed with the key
generated in <work dir>), Windows Installer databases (MSI, merge module,
patch: compound files with encoded table streams and a string pool), XAR
and macOS installer packages (component and product), and an Electron
asar. Signing keys and certificates are generated for the run and thrown
away; the certificate subject is fictitious.

Names and texts are fictitious (Saltmere harbour). Times are fixed.
"""

import base64
import bz2
import gzip
import hashlib
import io
import json
import lzma
import plistlib
import struct
import subprocess
import sys
import tarfile
import zipfile
import zlib
from compression import zstd
from datetime import datetime, timezone
from pathlib import Path

# 2025-09-01 12:00:00 UTC
STAMP = 1756728000
DATE = datetime.fromtimestamp(STAMP, timezone.utc)
ZIP_DATE = (2025, 9, 1, 12, 0, 0)

NAME = "saltmere-tides"
VERSION = "1.2.0"
SUMMARY = "Tide tables for Saltmere harbour"
DESCRIPTION = "High and low water times for Saltmere harbour, with the bell tower schedule."
AUTHOR = "Ana Lighthouse"
EMAIL = "ana@example.org"
HOME = "https://example.org/saltmere/tides"
TIDES = b"date,high,low\n2025-09-01,06:12,12:31\n2025-09-02,06:58,13:15\n"
SCRIPT = b"#!/bin/sh\necho 'High water 06:12'\n"
POSTINST = b"#!/bin/sh\nset -e\necho 'Saltmere tides installed'\n"
MIT = (
    "MIT License\n\nCopyright (c) 2025 Saltmere Harbour\n\n"
    "Permission is hereby granted, free of charge, to any person obtaining a copy of this software and "
    "associated documentation files (the \"Software\"), to deal in the Software without restriction.\n"
)


# --- helpers ---------------------------------------------------------------

def tar_bytes(entries, fmt=tarfile.GNU_FORMAT, end=True, owner=("root", "root")):
    """entries: (name, data | None for a folder | ('link', target), mode)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as t:
        for name, data, mode in entries:
            info = tarfile.TarInfo(name)
            info.mtime, info.mode = STAMP, mode
            info.uname, info.gname = owner
            if data is None:
                info.type = tarfile.DIRTYPE
                t.addfile(info)
            elif isinstance(data, tuple):
                info.type, info.linkname = tarfile.SYMTYPE, data[1]
                t.addfile(info)
            else:
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    if not end:
        # Without the end-of-archive blocks (Alpine's signature and control
        # segments run on into the next one).
        raw = raw.rstrip(b"\0")
        raw += b"\0" * (-len(raw) % 512)
    return raw


def gz(data):
    return gzip.compress(data, mtime=STAMP)


def zip_bytes(entries, compress=True):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries:
            info = zipfile.ZipInfo(name, ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED if compress and data else zipfile.ZIP_STORED
            info.external_attr = (0o40755 << 16) | 0x10 if name.endswith("/") else 0o100644 << 16
            z.writestr(info, data)
    return buf.getvalue()


def ar_bytes(members):
    out = b"!<arch>\n"
    for name, data in members:
        out += f"{name:<16}{STAMP:<12}{0:<6}{0:<6}{0o100644:<8o}{len(data):<10}`\n".encode()
        out += data + (b"\n" if len(data) % 2 else b"")
    return out


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def write(fx, fmt, name, data):
    d = fx / fmt
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data)


# --- Debian ----------------------------------------------------------------

def deb(fx):
    md5 = lambda d: hashlib.md5(d).hexdigest()
    copyright_ = (
        "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n"
        f"Upstream-Name: {NAME}\n\nFiles: *\nCopyright: 2025 Saltmere Harbour\nLicense: MIT\n"
        " Permission is hereby granted, free of charge, to any person obtaining a copy.\n"
    ).encode()
    conf = b"[tides]\nport = 8080\n"
    files = [
        ("./", None, 0o755),
        ("./etc/", None, 0o755),
        ("./etc/saltmere/", None, 0o755),
        ("./etc/saltmere/tides.conf", conf, 0o644),
        ("./usr/", None, 0o755),
        ("./usr/bin/", None, 0o755),
        ("./usr/bin/saltmere-tides", SCRIPT, 0o755),
        ("./usr/share/", None, 0o755),
        ("./usr/share/doc/", None, 0o755),
        (f"./usr/share/doc/{NAME}/", None, 0o755),
        (f"./usr/share/doc/{NAME}/copyright", copyright_, 0o644),
        ("./usr/share/saltmere/", None, 0o755),
        ("./usr/share/saltmere/tides.csv", TIDES, 0o644),
    ]
    sums = "".join(f"{md5(d)}  {n[2:]}\n" for n, d, _ in files if isinstance(d, bytes)).encode()
    control = (
        f"Package: {NAME}\nVersion: {VERSION}-1\nArchitecture: all\nMaintainer: {AUTHOR} <{EMAIL}>\n"
        "Installed-Size: 12\nDepends: libc6 (>= 2.34), python3 | python3-minimal\nRecommends: saltmere-charts\n"
        "Conflicts: old-tides (<< 1.0)\nProvides: tide-tables\nSection: misc\nPriority: optional\n"
        f"Homepage: {HOME}\nDescription: {SUMMARY}\n {DESCRIPTION}\n .\n The bell rings at high water.\n"
    ).encode()
    ctrl = [
        ("./", None, 0o755),
        ("./control", control, 0o644),
        ("./md5sums", sums, 0o644),
        ("./conffiles", b"/etc/saltmere/tides.conf\n", 0o644),
        ("./postinst", POSTINST, 0o755),
    ]
    data = tar_bytes(files)
    write(fx, "deb", f"{NAME}_{VERSION}-1_all.deb", ar_bytes([
        ("debian-binary", b"2.0\n"),
        ("control.tar.xz", lzma.compress(tar_bytes(ctrl))),
        ("data.tar.xz", lzma.compress(data)),
    ]))
    # Newer Ubuntu builds: zstd members.
    write(fx, "deb", f"{NAME}_{VERSION}-1_all-zstd.deb", ar_bytes([
        ("debian-binary", b"2.0\n"),
        ("control.tar.zst", zstd.compress(tar_bytes(ctrl))),
        ("data.tar.zst", zstd.compress(data)),
    ]))
    ucontrol = (
        f"Package: {NAME}-udeb\nVersion: {VERSION}-1\nArchitecture: all\nMaintainer: {AUTHOR} <{EMAIL}>\n"
        "Installed-Size: 4\nSection: debian-installer\nPriority: optional\nPackage-Type: udeb\n"
        f"Description: {SUMMARY} (installer)\n"
    ).encode()
    write(fx, "udeb", f"{NAME}-udeb_{VERSION}-1_all.udeb", ar_bytes([
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", gz(tar_bytes([("./", None, 0o755), ("./control", ucontrol, 0o644)]))),
        ("data.tar.xz", lzma.compress(tar_bytes(files[:1] + files[4:7]))),
    ]))


# --- RPM -------------------------------------------------------------------

STRING, STRING_ARRAY, I18N, INT16, INT32, INT64, BIN = 6, 8, 9, 3, 4, 5, 7


def rpm_header(entries):
    """entries: (tag, type, value) → header structure bytes."""
    index, store = b"", b""
    for tag, ty, value in sorted(entries):
        align = {INT16: 2, INT32: 4, INT64: 8}.get(ty, 1)
        store += b"\0" * (-len(store) % align)
        offset = len(store)
        if ty == STRING:
            data, count = value.encode() + b"\0", 1
        elif ty in (STRING_ARRAY, I18N):
            values = value if isinstance(value, list) else [value]
            data, count = b"".join(v.encode() + b"\0" for v in values), len(values)
        elif ty == BIN:
            data, count = value, len(value)
        else:
            values = value if isinstance(value, list) else [value]
            fmt = {INT16: ">H", INT32: ">I", INT64: ">Q"}[ty]
            data, count = b"".join(struct.pack(fmt, v) for v in values), len(values)
        store += data
        index += struct.pack(">IIII", tag, ty, offset, count)
    return b"\x8e\xad\xe8\x01\0\0\0\0" + struct.pack(">II", len(entries), len(store)) + index + store


def cpio_newc(entries):
    out = b""
    for ino, (name, data, mode) in enumerate(entries + [("TRAILER!!!", b"", 0)], 1):
        n = name.encode() + b"\0"
        size = len(data) if isinstance(data, bytes) else 0
        hdr = "070701" + "".join(f"{v:08X}" for v in (ino, mode, 0, 0, 1, STAMP, size, 0, 0, 0, 0, len(n), 0))
        out += hdr.encode() + n
        out += b"\0" * (-len(out) % 4)
        if size:
            out += data + b"\0" * (-size % 4)
    return out


def rpm(fx, source=False):
    files = [
        ("./usr/bin/saltmere-tides", SCRIPT, 0o100755),
        ("./usr/share/doc/saltmere-tides/LICENSE", MIT.encode(), 0o100644),
        ("./usr/share/saltmere/tides.csv", TIDES, 0o100644),
    ]
    if source:
        files = [("saltmere-tides.spec", b"Name: saltmere-tides\nVersion: 1.2.0\n", 0o100644),
                 ("saltmere-tides-1.2.0.tar.gz", gz(TIDES), 0o100644)]
    payload_raw = cpio_newc(files)
    payload = lzma.compress(payload_raw) if source else gz(payload_raw)
    dirs = sorted({n[1:].rsplit("/", 1)[0] + "/" for n, _, _ in files}) if not source else [""]
    base = [n.rsplit("/", 1)[-1] for n, _, _ in files]
    dirindex = [dirs.index(n[1:].rsplit("/", 1)[0] + "/") if not source else 0 for n, _, _ in files]
    h = [
        (100, STRING_ARRAY, ["C"]),
        (1000, STRING, NAME),
        (1001, STRING, VERSION),
        (1002, STRING, "1.fc43" if not source else "1"),
        (1004, I18N, SUMMARY),
        (1005, I18N, DESCRIPTION),
        (1006, INT32, STAMP),
        (1007, STRING, "build.saltmere.example"),
        (1009, INT32, sum(len(d) for _, d, _ in files)),
        (1011, STRING, "Saltmere Harbour"),
        (1014, STRING, "MIT"),
        (1015, STRING, f"{AUTHOR} <{EMAIL}>"),
        (1016, I18N, "Applications/Productivity"),
        (1020, STRING, HOME),
        (1021, STRING, "linux"),
        (1022, STRING, "noarch"),
        (1028, INT32, [len(d) for _, d, _ in files]),
        (1030, INT16, [m for _, _, m in files]),
        (1034, INT32, [STAMP] * len(files)),
        (1036, STRING_ARRAY, [""] * len(files)),
        (1047, STRING_ARRAY, [NAME, "tide-tables"]),
        (1048, INT32, [12, 0, 0x1000000 | 8]),
        (1049, STRING_ARRAY, ["python3", "/bin/sh", "rpmlib(CompressedFileNames)"]),
        (1050, STRING_ARRAY, ["3.9", "", "3.0.4-1"]),
        (1054, STRING_ARRAY, ["old-tides"]),
        (1116, INT32, dirindex),
        (1117, STRING_ARRAY, base),
        (1118, STRING_ARRAY, dirs),
        (1124, STRING, "cpio"),
        (1125, STRING, "xz" if source else "gzip"),
        (1126, STRING, "2" if source else "9"),
        (5046, STRING_ARRAY, ["saltmere-charts"]),
    ]
    if source:
        h = [e for e in h if e[0] not in (1047, 1054, 5046)] + [(1106, INT32, 1)]
    else:
        h += [(1024, STRING, "echo 'Saltmere tides installed'"), (1044, STRING, f"{NAME}-{VERSION}-1.fc43.src.rpm")]
    header = rpm_header(h)
    sig = rpm_header([
        (273, STRING, hashlib.sha256(header).hexdigest()),
        (1000, INT32, len(header) + len(payload)),
        (1004, BIN, hashlib.md5(header + payload).digest()),
        (1007, INT32, len(payload_raw)),
    ])
    sig += b"\0" * (-len(sig) % 8)
    name = f"{NAME}-{VERSION}-1" + (".src" if source else ".fc43.noarch")
    lead = b"\xed\xab\xee\xdb\x03\x00" + struct.pack(">HH", 1 if source else 0, 0)
    lead += f"{NAME}-{VERSION}-1".encode().ljust(66, b"\0") + struct.pack(">HH", 1, 5) + b"\0" * 16
    write(fx, "rpm", name + ".rpm", lead + sig + header + payload)


# --- tar-based packages ----------------------------------------------------

def arch(fx):
    pkginfo = (
        "# Generated by makepkg 7.0.0\n"
        f"pkgname = {NAME}\npkgbase = {NAME}\nxdata = pkgtype=pkg\npkgver = {VERSION}-1\npkgdesc = {SUMMARY}\n"
        f"url = {HOME}\nbuilddate = {STAMP}\npackager = {AUTHOR} <{EMAIL}>\nsize = 4096\narch = any\n"
        "license = MIT\ndepend = python>=3.9\ndepend = bash\noptdepend = saltmere-charts: chart overlays\n"
        "provides = tide-tables\nconflict = old-tides\n"
    ).encode()
    install = b"post_install() {\n  echo 'Saltmere tides installed'\n}\n"
    mtree = gz(b"#mtree\n/set type=file uid=0 gid=0 mode=644\n./usr/bin/saltmere-tides time=1756728000.0 mode=755 size=34\n")
    write(fx, "arch_package", f"{NAME}-{VERSION}-1-any.pkg.tar.zst", zstd.compress(tar_bytes([
        (".BUILDINFO", b"format = 2\npkgname = saltmere-tides\n", 0o644),
        (".MTREE", mtree, 0o644),
        (".PKGINFO", pkginfo, 0o644),
        (".INSTALL", install, 0o644),
        ("usr/", None, 0o755),
        ("usr/bin/", None, 0o755),
        ("usr/bin/saltmere-tides", SCRIPT, 0o755),
        ("usr/share/saltmere/", None, 0o755),
        ("usr/share/saltmere/tides.csv", TIDES, 0o644),
    ], fmt=tarfile.PAX_FORMAT)))


def alpine(fx, work):
    pkginfo = (
        "# Generated by abuild 3.14.1\n# using fakeroot version 1.32\n"
        f"pkgname = {NAME}\npkgver = {VERSION}-r0\npkgdesc = {SUMMARY}\nurl = {HOME}\nbuilddate = {STAMP}\n"
        f"packager = {AUTHOR} <{EMAIL}>\nsize = 4096\narch = noarch\norigin = {NAME}\n"
        f"maintainer = {AUTHOR} <{EMAIL}>\nlicense = MIT\ndepend = python3\ndepend = so:libc.musl-x86_64.so.1\n"
        "provides = cmd:saltmere-tides=1.2.0-r0\n"
    ).encode()
    control = gz(tar_bytes([(".PKGINFO", pkginfo, 0o644), (".post-install", POSTINST, 0o755)], end=False))
    data = gz(tar_bytes([("usr/", None, 0o755), ("usr/bin/", None, 0o755), ("usr/bin/saltmere-tides", SCRIPT, 0o755)]))
    key = work / "alpine.rsa"
    openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key))
    sig = openssl("dgst", "-sha1", "-sign", str(key), data=control)
    signature = gz(tar_bytes([(".SIGN.RSA.saltmere-66cf3a1b.rsa.pub", sig, 0o644)], end=False))
    write(fx, "alpine_package", f"{NAME}-{VERSION}-r0.apk", signature + control + data)


def conda(fx):
    index = {
        "name": NAME, "version": VERSION, "build": "py_0", "build_number": 0, "license": "MIT",
        "depends": ["python >=3.9", "numpy"], "noarch": "python", "subdir": "noarch", "timestamp": STAMP * 1000,
    }
    about = {"summary": SUMMARY, "description": DESCRIPTION, "home": HOME, "dev_url": HOME + "/src", "license": "MIT"}
    post = "bin/.saltmere-tides-post-link.sh"
    paths = {"paths": [
        {"_path": "site-packages/saltmere_tides/__init__.py", "path_type": "hardlink", "size_in_bytes": 15},
        {"_path": post, "path_type": "hardlink", "size_in_bytes": len(POSTINST)},
    ], "paths_version": 1}
    info = [
        ("info/index.json", json.dumps(index, indent=2).encode(), 0o644),
        ("info/about.json", json.dumps(about, indent=2).encode(), 0o644),
        ("info/paths.json", json.dumps(paths, indent=2).encode(), 0o644),
        ("info/files", f"site-packages/saltmere_tides/__init__.py\n{post}\n".encode(), 0o644),
    ]
    pkg = [("site-packages/saltmere_tides/__init__.py", b'HIGH = "06:12"\n', 0o644), (post, POSTINST, 0o755)]
    # The older .tar.bz2 form is detected as bzip2, then as conda inside it.
    write(fx, "bzip2", f"{NAME}-{VERSION}-py_0.tar.bz2", bz2.compress(tar_bytes(info + pkg)))
    stem = f"{NAME}-{VERSION}-py_0"
    write(fx, "conda_package", f"{stem}.conda", zip_bytes([
        ("metadata.json", json.dumps({"conda_pkg_format_version": 2}).encode()),
        (f"info-{stem}.tar.zst", zstd.compress(tar_bytes(info))),
        (f"pkg-{stem}.tar.zst", zstd.compress(tar_bytes(pkg))),
    ], compress=False))


def freebsd(fx):
    compact = {
        "name": NAME, "origin": "misc/saltmere-tides", "version": VERSION, "comment": SUMMARY,
        "maintainer": EMAIL, "www": HOME, "abi": "FreeBSD:14:*", "arch": "freebsd:14:*", "prefix": "/usr/local",
        "flatsize": len(SCRIPT) + len(TIDES), "licenselogic": "single", "licenses": ["MIT"], "desc": DESCRIPTION,
        "deps": {"python311": {"origin": "lang/python311", "version": "3.11.9"}}, "categories": ["misc"],
    }
    full = dict(compact, files={"/usr/local/bin/saltmere-tides": "1$" + hashlib.sha256(SCRIPT).hexdigest(),
                                "/usr/local/share/saltmere/tides.csv": "1$" + hashlib.sha256(TIDES).hexdigest()},
                scripts={"post-install": "echo 'Saltmere tides installed'"})
    write(fx, "freebsd_package", f"{NAME}-{VERSION}.pkg", zstd.compress(tar_bytes([
        ("+COMPACT_MANIFEST", json.dumps(compact).encode(), 0o644),
        ("+MANIFEST", json.dumps(full).encode(), 0o644),
        ("/usr/local/bin/saltmere-tides", SCRIPT, 0o755),
        ("/usr/local/share/saltmere/tides.csv", TIDES, 0o644),
    ], fmt=tarfile.PAX_FORMAT)))


def slackware(fx):
    desc = (
        "# HOW TO EDIT THIS FILE:\n# The \"handy ruler\" below makes it easier to edit a package description.\n"
        f"{NAME}: {NAME} ({SUMMARY})\n{NAME}:\n{NAME}: {DESCRIPTION}\n{NAME}:\n{NAME}: Homepage: {HOME}\n"
    ).encode()
    tar = tar_bytes([
        ("./", None, 0o755),
        ("install/", None, 0o755),
        ("install/slack-desc", desc, 0o644),
        ("install/doinst.sh", b"( cd usr/bin ; ln -sf saltmere-tides tides )\n", 0o644),
        ("usr/", None, 0o755),
        ("usr/bin/", None, 0o755),
        ("usr/bin/saltmere-tides", SCRIPT, 0o755),
    ])
    write(fx, "slackware_package", f"{NAME}-{VERSION}-noarch-1_saltmere.tgz", gz(tar))
    # The usual .txz is detected as xz, then as a Slackware package inside it.
    write(fx, "xz", f"{NAME}-{VERSION}-noarch-1_saltmere.txz", lzma.compress(tar))


def oci(fx):
    layer = tar_bytes([("srv/", None, 0o755), ("srv/tides.csv", TIDES, 0o644), ("srv/tides", SCRIPT, 0o755)])
    sha = lambda d: hashlib.sha256(d).hexdigest()
    config = {
        "architecture": "amd64", "os": "linux", "created": "2025-09-01T12:00:00Z",
        "config": {
            "User": "tides", "Env": ["PATH=/usr/bin:/bin", "TIDE_PORT=8080"], "Entrypoint": ["/srv/tides"],
            "ExposedPorts": {"8080/tcp": {}}, "WorkingDir": "/srv",
            "Labels": {"org.opencontainers.image.title": "Saltmere Tides", "org.opencontainers.image.version": VERSION,
                       "org.opencontainers.image.licenses": "MIT", "org.opencontainers.image.source": HOME},
        },
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + sha(layer)]},
        "history": [{"created": "2025-09-01T12:00:00Z", "created_by": "COPY srv /srv"}],
    }
    cfg = json.dumps(config, separators=(",", ":")).encode()
    manifest = json.dumps({
        "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + sha(cfg), "size": len(cfg)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:" + sha(layer), "size": len(layer)}],
    }, separators=(",", ":")).encode()
    index = json.dumps({"schemaVersion": 2, "manifests": [{
        "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + sha(manifest), "size": len(manifest),
        "annotations": {"org.opencontainers.image.ref.name": VERSION}}]}, separators=(",", ":")).encode()
    docker = json.dumps([{"Config": "blobs/sha256/" + sha(cfg), "RepoTags": [f"saltmere/tides:{VERSION}"],
                          "Layers": ["blobs/sha256/" + sha(layer)]}], separators=(",", ":")).encode()
    write(fx, "docker_image", "saltmere-tides-image.tar", tar_bytes([
        ("blobs/", None, 0o755),
        ("blobs/sha256/", None, 0o755),
        ("blobs/sha256/" + sha(cfg), cfg, 0o644),
        ("blobs/sha256/" + sha(layer), layer, 0o644),
        ("blobs/sha256/" + sha(manifest), manifest, 0o644),
        ("index.json", index, 0o644),
        ("manifest.json", docker, 0o644),
        ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}', 0o644),
        ("repositories", json.dumps({"saltmere/tides": {VERSION: sha(manifest)}}).encode(), 0o644),
    ], fmt=tarfile.USTAR_FORMAT))


# --- ZIP-based packages ----------------------------------------------------

def certificate(work):
    key, cert = work / "signer.key", work / "signer.pem"
    if not cert.exists():
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                "-days", "3650", "-subj", "/CN=Saltmere Harbour/O=Saltmere/C=GB")
    return key, cert


def android_wrappers(fx, work):
    apk = (work / "tides.apk").read_bytes()
    proto = (work / "proto-manifest.xml").read_bytes()
    dex = (work / "classes.dex").read_bytes()
    write(fx, "aab", "saltmere-tides.aab", zip_bytes([
        ("BundleConfig.pb", b"\x0a\x06\x0a\x041.17"),
        ("base/manifest/AndroidManifest.xml", proto),
        ("base/dex/classes.dex", dex),
        ("base/assets/tides.csv", TIDES),
        ("base/lib/arm64-v8a/libtides.so", b"\x7fELF"),
    ]))
    write(fx, "apks", "saltmere-tides.apks", zip_bytes([
        ("toc.pb", b"\x0a\x00"),
        ("splits/base-master.apk", apk),
    ], compress=False))
    manifest = {
        "xapk_version": 2, "package_name": "org.saltmere.tides", "name": "Saltmere Tides", "version_code": "12",
        "version_name": VERSION, "min_sdk_version": "24", "target_sdk_version": "36",
        "permissions": ["android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"],
        "split_apks": [{"file": "org.saltmere.tides.apk", "id": "base"}],
    }
    write(fx, "xapk", "saltmere-tides.xapk", zip_bytes([
        ("manifest.json", json.dumps(manifest, indent=2).encode()),
        ("org.saltmere.tides.apk", apk),
    ], compress=False))
    aar_manifest = (
        b'<?xml version="1.0" encoding="utf-8"?>\n<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        b' package="org.saltmere.tides.lib">\n    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="36" />\n'
        b"</manifest>\n"
    )
    write(fx, "aar", "saltmere-tides.aar", zip_bytes([
        ("AndroidManifest.xml", aar_manifest),
        ("classes.jar", (work / "tides.jar").read_bytes()),
        ("R.txt", b"int string app_name 0x7f010000\n"),
        ("res/values/values.xml", b"<resources><string name=\"app_name\">Saltmere Tides</string></resources>\n"),
    ]))


def egg(fx, work):
    info = work / "egg-info"
    entries = [("saltmere_tides/__init__.py", b'HIGH = "06:12"\n')]
    for f in sorted(info.iterdir()):
        entries.append((f"EGG-INFO/{f.name}", f.read_bytes()))
    write(fx, "egg", "saltmere_tides-1.2.0-py3.14.egg", zip_bytes(entries))


def ipa(fx, work):
    key, cert = certificate(work)
    app = "Payload/SaltmereTides.app/"
    info = plistlib.dumps({
        "CFBundleIdentifier": "org.saltmere.tides", "CFBundleName": "Tides", "CFBundleDisplayName": "Saltmere Tides",
        "CFBundleShortVersionString": VERSION, "CFBundleVersion": "12", "CFBundleExecutable": "SaltmereTides",
        "CFBundlePackageType": "APPL", "MinimumOSVersion": "16.0", "UIDeviceFamily": [1, 2],
        "UIRequiredDeviceCapabilities": ["arm64"], "UIBackgroundModes": ["location"],
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["saltmere-tides"]}],
        "NSLocationWhenInUseUsageDescription": "Shows the tides at the nearest harbour.",
        "NSCameraUsageDescription": "Scans berth QR codes.",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False},
        "DTPlatformName": "iphoneos", "DTSDKName": "iphoneos18.0", "DTXcode": "1600",
    }, fmt=plistlib.FMT_BINARY)
    profile = plistlib.dumps({
        "AppIDName": "Saltmere Tides", "Name": "Saltmere Tides Ad Hoc", "TeamName": "Saltmere Harbour",
        "TeamIdentifier": ["SALTMERE01"], "CreationDate": DATE, "ExpirationDate": datetime(2026, 9, 1, 12, tzinfo=timezone.utc),
        "ProvisionedDevices": ["00008110-000000000000001E"],
        "Entitlements": {"application-identifier": "SALTMERE01.org.saltmere.tides", "get-task-allow": False,
                         "aps-environment": "production"},
        "Version": 1,
    })
    signed = openssl("cms", "-sign", "-signer", str(cert), "-inkey", str(key), "-outform", "DER", "-nodetach", "-binary", data=profile)
    code = plistlib.dumps({"files": {"Info.plist": hashlib.sha1(info).digest(), "tides.csv": hashlib.sha1(TIDES).digest()}})
    write(fx, "ipa", "SaltmereTides.ipa", zip_bytes([
        ("Payload/", b""),
        (app, b""),
        (app + "Info.plist", info),
        (app + "SaltmereTides", b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01" + b"\0" * 24),
        (app + "embedded.mobileprovision", signed),
        (app + "_CodeSignature/CodeResources", code),
        (app + "tides.csv", TIDES),
        (app + "Frameworks/TideKit.framework/Info.plist", plistlib.dumps({"CFBundleIdentifier": "org.saltmere.tidekit"})),
        (app + "PlugIns/TidesWidget.appex/Info.plist", plistlib.dumps({"CFBundleIdentifier": "org.saltmere.tides.widget"})),
    ]))


def opc(parts, rels_target, content_types):
    ct = '<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    ct += "".join(f'<Default Extension="{e}" ContentType="{t}"/>' for e, t in content_types) + "</Types>"
    rels = ('<?xml version="1.0" encoding="utf-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'<Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/{rels_target}" Id="R1"/></Relationships>')
    return [("_rels/.rels", rels.encode())] + parts + [("[Content_Types].xml", ct.encode())]


def nupkg(fx):
    spec = f"""<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Saltmere.Tides</id>
    <version>{VERSION}</version>
    <title>Saltmere Tides</title>
    <authors>{AUTHOR}, Ben Gull</authors>
    <license type="expression">MIT</license>
    <projectUrl>{HOME}</projectUrl>
    <description>{DESCRIPTION}</description>
    <tags>tides harbour</tags>
    <repository type="git" url="{HOME}.git" />
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="System.Text.Json" version="8.0.0" />
      </group>
      <group targetFramework="netstandard2.0" />
    </dependencies>
  </metadata>
</package>
"""
    parts = [
        ("Saltmere.Tides.nuspec", spec.encode()),
        ("lib/net8.0/Saltmere.Tides.dll", b"MZ" + b"\0" * 62),
        ("tools/install.ps1", b"param($installPath, $toolsPath, $package)\nWrite-Host 'Saltmere tides'\n"),
    ]
    write(fx, "nupkg", "Saltmere.Tides.1.2.0.nupkg",
          zip_bytes(opc(parts, "Saltmere.Tides.nuspec", [("nuspec", "application/octet"), ("dll", "application/octet"), ("ps1", "application/octet"), ("rels", "application/vnd.openxmlformats-package.relationships+xml")])))


def msix(fx):
    manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="Saltmere.Tides" Publisher="CN=Saltmere Harbour, O=Saltmere, C=GB" Version="1.2.0.0" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Saltmere Tides</DisplayName>
    <PublisherDisplayName>Saltmere Harbour</PublisherDisplayName>
    <Description>{DESCRIPTION}</Description>
    <Logo>Assets\\StoreLogo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0" />
    <PackageDependency Name="Microsoft.VCLibs.140.00" MinVersion="14.0.30704.0" Publisher="CN=Microsoft Corporation" />
  </Dependencies>
  <Resources><Resource Language="en-gb" /></Resources>
  <Applications>
    <Application Id="Tides" Executable="SaltmereTides.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Saltmere Tides" Description="Tides" BackgroundColor="transparent" Square150x150Logo="Assets\\Square.png" Square44x44Logo="Assets\\Small.png" />
    </Application>
  </Applications>
  <Capabilities>
    <Capability Name="internetClient" />
    <rescap:Capability Name="runFullTrust" />
    <DeviceCapability Name="location" />
  </Capabilities>
</Package>
"""
    blockmap = b'<?xml version="1.0" encoding="UTF-8"?><BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"></BlockMap>'
    ct = b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="exe" ContentType="application/x-msdownload"/><Override PartName="/AppxManifest.xml" ContentType="application/vnd.ms-appx.manifest+xml"/></Types>'
    package = zip_bytes([
        ("SaltmereTides.exe", b"MZ" + b"\0" * 62),
        ("tides.csv", TIDES),
        ("AppxManifest.xml", manifest.encode()),
        ("AppxBlockMap.xml", blockmap),
        ("[Content_Types].xml", ct),
    ])
    write(fx, "msix", "Saltmere.Tides_1.2.0.0_x64.msix", package)
    bundle = f"""<?xml version="1.0" encoding="UTF-8"?>
<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle" SchemaVersion="5.0">
  <Identity Name="Saltmere.Tides" Publisher="CN=Saltmere Harbour, O=Saltmere, C=GB" Version="1.2.0.0" />
  <Packages>
    <Package Type="application" Version="1.2.0.0" Architecture="x64" FileName="Saltmere.Tides_1.2.0.0_x64.msix" Offset="0" Size="{len(package)}" />
  </Packages>
</Bundle>
"""
    write(fx, "msix_bundle", "Saltmere.Tides_1.2.0.0.msixbundle", zip_bytes([
        ("Saltmere.Tides_1.2.0.0_x64.msix", package),
        ("AppxMetadata/AppxBundleManifest.xml", bundle.encode()),
        ("AppxBlockMap.xml", blockmap),
        ("[Content_Types].xml", ct),
    ], compress=False))


def vsix(fx):
    manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Language="en-US" Id="saltmere-tides" Version="{VERSION}" Publisher="saltmere" />
    <DisplayName>Saltmere Tides</DisplayName>
    <Description xml:space="preserve">{SUMMARY}</Description>
    <Tags>tides,harbour</Tags>
    <License>extension/LICENSE.txt</License>
  </Metadata>
  <Installation><InstallationTarget Id="Microsoft.VisualStudio.Code" /></Installation>
  <Assets><Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" /></Assets>
</PackageManifest>
"""
    package = {
        "name": "saltmere-tides", "displayName": "Saltmere Tides", "version": VERSION, "publisher": "saltmere",
        "license": "MIT", "repository": {"type": "git", "url": HOME}, "engines": {"vscode": "^1.90.0"},
        "activationEvents": ["onStartupFinished"], "main": "./out/extension.js",
        "contributes": {"commands": [{"command": "tides.show", "title": "Show tides"}]},
        "dependencies": {"left-pad": "^1.3.0"},
    }
    write(fx, "vsix", "saltmere-tides-1.2.0.vsix", zip_bytes([
        ("extension.vsixmanifest", manifest.encode()),
        ("[Content_Types].xml", b'<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension=".json" ContentType="application/json"/><Default Extension=".js" ContentType="application/javascript"/></Types>'),
        ("extension/package.json", json.dumps(package, indent=2).encode()),
        ("extension/out/extension.js", b"exports.activate = () => console.log('High water 06:12');\n"),
        ("extension/LICENSE.txt", MIT.encode()),
    ]))


def webext(fx, work):
    manifest = {
        "manifest_version": 3, "name": "Saltmere Tides", "version": VERSION, "description": SUMMARY,
        "homepage_url": HOME, "author": AUTHOR, "permissions": ["storage", "tabs"],
        "host_permissions": ["https://example.org/*"], "background": {"service_worker": "background.js"},
        "content_scripts": [{"matches": ["https://example.org/*"], "js": ["tides.js"]}],
        "browser_specific_settings": {"gecko": {"id": "tides@saltmere.example"}},
    }
    files = [
        ("manifest.json", json.dumps(manifest, indent=2).encode()),
        ("background.js", b"chrome.runtime.onInstalled.addListener(() => {});\n"),
        ("tides.js", b"console.log('High water 06:12');\n"),
    ]
    key, cert = certificate(work)
    sig = openssl("cms", "-sign", "-signer", str(cert), "-inkey", str(key), "-outform", "DER", "-binary", data=files[0][1])
    write(fx, "xpi", "saltmere-tides-1.2.0.xpi", zip_bytes(files + [
        ("META-INF/manifest.mf", b"Manifest-Version: 1.0\n\nName: manifest.json\nSHA256-Digest: " + base64.b64encode(hashlib.sha256(files[0][1]).digest()) + b"\n"),
        ("META-INF/mozilla.rsa", sig),
    ]))
    # CRX3: protobuf header with an RSA proof over the signed data and the ZIP.
    archive = zip_bytes(files)
    pub = openssl("pkey", "-in", str(key), "-pubout", "-outform", "DER")
    crx_id = hashlib.sha256(pub).digest()[:16]

    def field(n, data):
        def varint(v):
            out = b""
            while True:
                b, v = v & 0x7F, v >> 7
                out += bytes([b | (0x80 if v else 0)])
                if not v:
                    return out
        return varint(n << 3 | 2) + varint(len(data)) + data

    signed_data = field(1, crx_id)
    message = b"CRX3 SignedData\x00" + struct.pack("<I", len(signed_data)) + signed_data + archive
    signature = openssl("dgst", "-sha256", "-sign", str(key), data=message)
    header = field(2, field(1, pub) + field(2, signature)) + field(10000, signed_data)
    write(fx, "crx", "saltmere-tides-1.2.0.crx", b"Cr24" + struct.pack("<II", 3, len(header)) + header + archive)


# --- Windows Installer -----------------------------------------------------

def msi_encode(name, table):
    def code(c):
        if c.isdigit():
            return ord(c) - 48
        if c.isupper():
            return ord(c) - 65 + 10
        if c.islower():
            return ord(c) - 97 + 36
        return 62 if c == "." else 63

    out = "䡀" if table else ""
    i = 0
    while i < len(name):
        if i + 1 < len(name):
            out += chr(0x3800 + code(name[i]) + (code(name[i + 1]) << 6))
            i += 2
        else:
            out += chr(0x4800 + code(name[i]))
            i += 1
    return out


def cfb(streams, clsid):
    """A version-3 compound file: (name, data) streams at the root."""
    SS, MINI = 512, 64
    names = sorted(streams, key=lambda s: (len(s[0]), s[0].upper()))
    mini, minifat, big = b"", [], []
    starts = []
    for name, data in names:
        if len(data) < 4096:
            start = len(mini) // MINI
            n = max(1, -(-len(data) // MINI)) if data else 0
            mini += data + b"\0" * (n * MINI - len(data))
            minifat += [start + i + 1 for i in range(n - 1)] + ([0xFFFFFFFE] if n else [])
            starts.append(("mini", start if n else 0xFFFFFFFE, len(data)))
        else:
            starts.append(("big", data, len(data)))
            big.append(data)
    # Sector layout: directory, mini FAT, mini stream, big streams, FAT.
    entries = [("Root Entry", 5)] + [(n, 2) for n, _ in names]
    dir_bytes = b""
    sectors = []  # list of (kind, payload)
    def add(data):
        first = len(sectors)
        n = max(1, -(-len(data) // SS))
        for i in range(n):
            sectors.append(data[i * SS:(i + 1) * SS].ljust(SS, b"\0"))
        return first, n
    dir_count = -(-len(entries) // 4)
    dir_first = len(sectors)
    sectors += [None] * dir_count
    chains = [(dir_first, dir_count)]
    minifat_bytes = b"".join(struct.pack("<I", v) for v in minifat)
    mf_first, mf_n = add(minifat_bytes) if minifat else (0xFFFFFFFE, 0)
    if minifat:
        chains.append((mf_first, mf_n))
    ms_first, ms_n = add(mini) if mini else (0xFFFFFFFE, 0)
    if mini:
        chains.append((ms_first, ms_n))
    big_starts = {}
    for name, data in names:
        if len(data) >= 4096:
            first, n = add(data)
            chains.append((first, n))
            big_starts[name] = first
    # FAT sectors (with room for themselves).
    total = len(sectors)
    fat_n = 1
    while fat_n * 128 < total + fat_n:
        fat_n += 1
    fat = [0xFFFFFFFF] * (fat_n * 128)
    for first, n in chains:
        for i in range(n):
            fat[first + i] = first + i + 1 if i < n - 1 else 0xFFFFFFFE
    fat_first = total
    for i in range(fat_n):
        fat[fat_first + i] = 0xFFFFFFFD
    def entry(name, kind, child, right, start, size, clsid_bytes=b"\0" * 16):
        n = name.encode("utf-16-le") + b"\0\0"
        e = n.ljust(64, b"\0") + struct.pack("<HBB", len(n), kind, 1)
        e += struct.pack("<III", 0xFFFFFFFF, right, child) + clsid_bytes + b"\0" * 4 + b"\0" * 16
        e += struct.pack("<IQ", start, size)
        return e
    clsid_bytes = struct.pack("<IHH", *[int(x, 16) for x in clsid.split("-")[:3]]) + bytes.fromhex("".join(clsid.split("-")[3:]))
    dir_bytes = entry("Root Entry", 5, 1 if names else 0xFFFFFFFF, 0xFFFFFFFF, ms_first, len(mini), clsid_bytes)
    for i, (name, data) in enumerate(names):
        right = i + 2 if i + 1 < len(names) else 0xFFFFFFFF
        start = big_starts.get(name, starts[i][1])
        dir_bytes += entry(name, 2, 0xFFFFFFFF, right, start, len(data))
    dir_bytes = dir_bytes.ljust(dir_count * SS, b"\0")
    for i in range(dir_count):
        sectors[dir_first + i] = dir_bytes[i * SS:(i + 1) * SS]
    fat_bytes = b"".join(struct.pack("<I", v) for v in fat)
    for i in range(fat_n):
        sectors.append(fat_bytes[i * SS:(i + 1) * SS])
    difat = [fat_first + i for i in range(fat_n)] + [0xFFFFFFFF] * (109 - fat_n)
    header = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 16 + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6)
    header += b"\0" * 6 + struct.pack("<IIIIIIIII", 0, fat_n, dir_first, 0, 4096, mf_first, mf_n, 0xFFFFFFFE, 0)
    header += b"".join(struct.pack("<I", v) for v in difat)
    return header + b"".join(sectors)


def summary_info(props):
    """props: (id, vt, value) → a SummaryInformation property set."""
    body, offsets = b"", []
    for pid, vt, value in props:
        offsets.append((pid, 8 + 8 * len(props) + len(body)))
        if vt == 2:
            v = struct.pack("<Hxx", value)
        elif vt == 3:
            v = struct.pack("<i", value)
        elif vt == 30:
            s = value.encode("cp1252") + b"\0"
            v = struct.pack("<I", len(s)) + s + b"\0" * (-len(s) % 4)
        else:  # 64: FILETIME
            v = struct.pack("<Q", (value + 11644473600) * 10_000_000)
        body += struct.pack("<I", vt) + v
    section = struct.pack("<II", 8 + 8 * len(props) + len(body), len(props))
    section += b"".join(struct.pack("<II", p, o) for p, o in offsets) + body
    fmtid = struct.pack("<IHH", 0xF29F85E0, 0x4FF9, 0x1068) + bytes.fromhex("AB9108002B27B3D9")
    return struct.pack("<HHI", 0xFFFE, 0, 0x00020006) + b"\0" * 16 + struct.pack("<I", 1) + fmtid + struct.pack("<I", 48) + section


def msi_database(tables, extra_streams, summary, clsid):
    """tables: name → (columns [(name, type)], rows)."""
    strings = [""]
    ids = {}
    def sid(s):
        if s is None:
            return 0
        if s not in ids:
            ids[s] = len(strings)
            strings.append(s)
        return ids[s]
    all_tables = {"_Tables": None, "_Columns": None, **tables}
    for t, (cols, rows) in tables.items():
        sid(t)
        for c, _ in cols:
            sid(c)
    streams = []
    def width(ty):
        return 2 if ty & 0x0800 or ty & 0xFF <= 2 else 4
    def encode(cols, rows):
        out = b""
        for i, (_, ty) in enumerate(cols):
            for r in rows:
                v = r[i]
                if ty & 0x0800:
                    out += struct.pack("<H", sid(v))
                elif v is None:
                    out += b"\0" * width(ty)
                elif width(ty) == 2:
                    out += struct.pack("<H", (v + 0x8000) & 0xFFFF)
                else:
                    out += struct.pack("<I", (v + 0x80000000) & 0xFFFFFFFF)
        return out
    col_rows = []
    for t, (cols, _) in tables.items():
        for n, (c, ty) in enumerate(cols, 1):
            col_rows.append((t, n, c, ty))
    for t, (cols, rows) in tables.items():
        streams.append((msi_encode(t, True), encode(cols, rows)))
    streams.append((msi_encode("_Columns", True), encode([("Table", 0x0D40), ("Number", 0x0502), ("Name", 0x0D40), ("Type", 0x0502)], col_rows)))
    streams.append((msi_encode("_Tables", True), encode([("Name", 0x0D40)], [(t,) for t in tables])))
    pool = struct.pack("<HH", 1252, 0)
    data = b""
    for s in strings[1:]:
        b = s.encode("cp1252")
        pool += struct.pack("<HH", len(b), 1)
        data += b
    streams.append((msi_encode("_StringPool", True), pool))
    streams.append((msi_encode("_StringData", True), data))
    streams.append(("\x05SummaryInformation", summary))
    streams += extra_streams
    return cfb(streams, clsid)


S72, S255, I2, I4, L0 = 0x0D48, 0x1FFF, 0x0502, 0x0104, 0x1D00


def msi(fx):
    cab = next((fx / "cab").glob("*.cab")).read_bytes()
    clsid = "000C1084-0000-0000-C000-000000000046"
    summary = summary_info([
        (1, 2, 1252), (2, 30, "Installation Database"), (3, 30, "Saltmere Tides"), (4, 30, "Saltmere Harbour"),
        (5, 30, "Installer, tides"), (6, 30, SUMMARY), (7, 30, "x64;1033,2057"),
        (9, 30, "{6A1D5C43-2E0F-4B61-9E3A-5A1C0C2B7D10}"), (12, 64, STAMP), (13, 64, STAMP), (14, 3, 500), (15, 3, 2),
        (18, 30, "craft_packages.py"), (19, 3, 2),
    ])
    tables = {
        "Property": ([("Property", S72 | 0x2000), ("Value", L0)], [
            ("ProductName", "Saltmere Tides"), ("ProductVersion", "1.2.0"), ("Manufacturer", "Saltmere Harbour"),
            ("ProductCode", "{0B2C1F44-7E8A-4C7B-9D61-2B4E5C6A7F80}"), ("UpgradeCode", "{A41E3B22-9C5D-4F18-8B7A-6D2C1E0F9A33}"),
            ("ProductLanguage", "1033"), ("ARPURLINFOABOUT", HOME), ("ALLUSERS", "1"),
        ]),
        "File": ([("File", S72 | 0x2000), ("Component_", S72), ("FileName", S255), ("FileSize", I4), ("Version", S72 | 0x1000),
                  ("Language", 0x1D14), ("Attributes", I2 | 0x1000), ("Sequence", I4)], [
            ("tides.exe", "MainComponent", "tides.exe", 2048, "1.2.0.0", None, 512, 1),
            ("tides.csv", "MainComponent", "tides.csv", len(TIDES), None, None, 512, 2),
        ]),
        "Component": ([("Component", S72 | 0x2000), ("ComponentId", 0x1D26), ("Directory_", S72), ("Attributes", I2),
                       ("Condition", 0x1DFF), ("KeyPath", S72 | 0x1000)], [
            ("MainComponent", "{3F0D1E22-1A2B-4C3D-8E9F-0A1B2C3D4E5F}", "INSTALLFOLDER", 256, None, "tides.exe"),
        ]),
        "Feature": ([("Feature", 0x2D26), ("Feature_Parent", 0x1D26), ("Title", 0x1F40), ("Description", 0x1FFF),
                     ("Display", I2 | 0x1000), ("Level", I2), ("Directory_", S72 | 0x1000), ("Attributes", I2)], [
            ("Complete", None, "Saltmere Tides", "Everything", 1, 1, "INSTALLFOLDER", 0),
        ]),
        "Directory": ([("Directory", S72 | 0x2000), ("Directory_Parent", S72 | 0x1000), ("DefaultDir", S255)], [
            ("TARGETDIR", None, "SourceDir"), ("ProgramFiles64Folder", "TARGETDIR", "."),
            ("INSTALLFOLDER", "ProgramFiles64Folder", "Saltmere"),
        ]),
        "CustomAction": ([("Action", S72 | 0x2000), ("Type", I2), ("Source", S72 | 0x1000), ("Target", S255 | 0x1000)], [
            ("SetInstallDir", 51, "INSTALLFOLDER", "[ProgramFiles64Folder]Saltmere"),
            ("RegisterTides", 3090, "tides.exe", "--register"),
            ("CheckHarbour", 38, None, 'MsgBox "Saltmere"'),
        ]),
        "Media": ([("DiskId", I2 | 0x2000), ("LastSequence", I4), ("DiskPrompt", 0x1F40), ("Cabinet", 0x1FFF),
                   ("VolumeLabel", 0x1D20), ("Source", 0x1D48)], [(1, 2, None, "#tides.cab", None, None)]),
    }
    write(fx, "msi", "saltmere-tides-1.2.0.msi", msi_database(tables, [(msi_encode("tides.cab", False), cab)], summary, clsid))
    msm_summary = summary_info([(1, 2, 1252), (2, 30, "Merge Module"), (3, 30, "Saltmere Tides Runtime"),
                                (4, 30, "Saltmere Harbour"), (7, 30, "Intel;1033"), (9, 30, "{5B2E8C11-3D4F-4A6B-9C8D-7E6F5A4B3C2D}"),
                                (12, 64, STAMP), (14, 3, 200), (15, 3, 2), (18, 30, "craft_packages.py")])
    msm_tables = {
        "ModuleSignature": ([("ModuleID", S72 | 0x2000), ("Language", I2 | 0x2000), ("Version", 0x0D20)],
                            [("SaltmereTidesRuntime.5B2E8C11_3D4F_4A6B_9C8D_7E6F5A4B3C2D", 1033, "1.2.0")]),
        "File": tables["File"],
        "Component": tables["Component"],
        "Directory": tables["Directory"],
    }
    write(fx, "msm", "saltmere-tides-runtime.msm", msi_database(msm_tables, [], msm_summary, clsid))
    msp_summary = summary_info([(1, 2, 1252), (2, 30, "Patch"), (3, 30, "Saltmere Tides 1.2.1 patch"),
                                (4, 30, "Saltmere Harbour"), (6, 30, "Fixes the 1.2.0 low-water times"),
                                (7, 30, "{0B2C1F44-7E8A-4C7B-9D61-2B4E5C6A7F80}"), (9, 30, "{7C3D9E55-1F2A-4B3C-8D4E-5F6A7B8C9D0E}"),
                                (12, 64, STAMP), (14, 3, 500), (15, 3, 4), (18, 30, "craft_packages.py")])
    write(fx, "msp", "saltmere-tides-1.2.1.msp",
          msi_database({}, [], msp_summary, "000C1086-0000-0000-C000-000000000046"))


# --- XAR and macOS installer packages --------------------------------------

def xar(files):
    """files: nested list of (name, data | list) → a XAR archive (zlib members)."""
    packed: list[bytes] = []
    next_id = [0]

    def elements(items, indent):
        out = ""
        for name, data in items:
            next_id[0] += 1
            pad = " " * indent
            out += f'{pad}<file id="{next_id[0]}">\n{pad} <name>{name}</name>\n'
            common = f"{pad} <user>root</user>\n{pad} <group>wheel</group>\n{pad} <mtime>2025-09-01T12:00:00Z</mtime>\n"
            if isinstance(data, list):
                out += f"{pad} <type>directory</type>\n{pad} <mode>0755</mode>\n" + common + elements(data, indent + 1)
            else:
                # Heap offsets count from after the TOC checksum (20 bytes).
                offset = 20 + sum(len(p) for p in packed)
                member = zlib.compress(data)
                packed.append(member)
                out += (f"{pad} <type>file</type>\n{pad} <mode>0644</mode>\n" + common
                        + f"{pad} <data>\n{pad}  <length>{len(member)}</length>\n{pad}  <offset>{offset}</offset>\n"
                        f"{pad}  <size>{len(data)}</size>\n{pad}  <encoding style=\"application/x-gzip\"/>\n"
                        f"{pad}  <archived-checksum style=\"sha1\">{hashlib.sha1(member).hexdigest()}</archived-checksum>\n"
                        f"{pad}  <extracted-checksum style=\"sha1\">{hashlib.sha1(data).hexdigest()}</extracted-checksum>\n{pad} </data>\n")
            out += f"{pad}</file>\n"
        return out

    body = elements(files, 2)
    toc = ('<?xml version="1.0" encoding="UTF-8"?>\n<xar>\n <toc>\n  <checksum style="sha1">\n   <offset>0</offset>\n   <size>20</size>\n  </checksum>\n'
           "  <creation-time>2025-09-01T12:00:00</creation-time>\n" + body + " </toc>\n</xar>\n").encode()
    packed_toc = zlib.compress(toc)
    header = b"xar!" + struct.pack(">HHQQI", 28, 1, len(packed_toc), len(toc), 1)
    return header + packed_toc + hashlib.sha1(packed_toc).digest() + b"".join(packed)


def cpio_odc(entries):
    out = b""
    for ino, (name, data, mode) in enumerate(entries + [("TRAILER!!!", b"", 0)], 1):
        n = name.encode() + b"\0"
        size = len(data) if data else 0
        out += f"070707{0:06o}{ino:06o}{mode:06o}{0:06o}{0:06o}{1:06o}{0:06o}{STAMP:011o}{len(n):06o}{size:011o}".encode() + n + (data or b"")
    return out


def macos_pkg(fx):
    payload = gz(cpio_odc([
        (".", None, 0o40755), ("./usr", None, 0o40755), ("./usr/local", None, 0o40755),
        ("./usr/local/share", None, 0o40755), ("./usr/local/share/saltmere", None, 0o40755),
        ("./usr/local/share/saltmere/tides.csv", TIDES, 0o100644),
    ]))
    scripts = gz(cpio_odc([(".", None, 0o40755), ("./postinstall", POSTINST, 0o100755)]))
    info = (
        '<?xml version="1.0" encoding="utf-8"?>\n<pkg-info overwrite-permissions="true" relocatable="false" '
        'identifier="org.saltmere.tides" postinstall-action="none" version="1.2.0" format-version="2" '
        'install-location="/" auth="root">\n    <payload numberOfFiles="6" installKBytes="4"/>\n'
        '    <scripts>\n        <postinstall file="./postinstall"/>\n    </scripts>\n</pkg-info>\n'
    ).encode()
    component = [("PackageInfo", info), ("Payload", payload), ("Scripts", scripts)]
    write(fx, "pkg", "saltmere-tides-component.pkg", xar(component))
    distribution = (
        '<?xml version="1.0" encoding="utf-8"?>\n<installer-gui-script minSpecVersion="2">\n'
        "    <title>Saltmere Tides</title>\n    <options customize=\"never\" hostArchitectures=\"x86_64,arm64\"/>\n"
        '    <allowed-os-versions><os-version min="12.0"/></allowed-os-versions>\n'
        '    <installation-check script="harbourOpen()"/>\n'
        "    <script>function harbourOpen() { return true; }</script>\n"
        '    <choices-outline><line choice="default"><line choice="org.saltmere.tides"/></line></choices-outline>\n'
        '    <choice id="org.saltmere.tides" visible="false"><pkg-ref id="org.saltmere.tides"/></choice>\n'
        '    <pkg-ref id="org.saltmere.tides" version="1.2.0" onConclusion="none">#tides.pkg</pkg-ref>\n'
        '    <product id="org.saltmere.tides.product" version="1.2.0"/>\n</installer-gui-script>\n'
    ).encode()
    write(fx, "pkg", "saltmere-tides-product.pkg", xar([("Distribution", distribution), ("tides.pkg", component)]))
    write(fx, "xar", "harbour.xar", xar([("harbour", [("notes.txt", b"Saltmere harbour notes\nHigh water 06:12.\n"),
                                                      ("charts", [("README.md", b"# Charts\n")])])]))


# --- Electron --------------------------------------------------------------

def asar(fx):
    package = json.dumps({"name": "saltmere-tides", "productName": "Saltmere Tides", "version": VERSION,
                          "description": SUMMARY, "license": "MIT", "author": f"{AUTHOR} <{EMAIL}>",
                          "main": "main.js", "dependencies": {"left-pad": "^1.3.0"}}, indent=2).encode()
    files = [("package.json", package), ("main.js", b"require('electron').app.whenReady();\n"), ("tides.csv", TIDES)]
    offset, tree, data = 0, {"files": {}}, b""
    for name, body in files:
        tree["files"][name] = {"size": len(body), "offset": str(offset),
                               "integrity": {"algorithm": "SHA256", "hash": hashlib.sha256(body).hexdigest(), "blockSize": 4194304,
                                             "blocks": [hashlib.sha256(body).hexdigest()]}}
        offset += len(body)
        data += body
    tree["files"]["node_modules"] = {"files": {"native.node": {"size": 16, "unpacked": True, "executable": True}}}
    j = json.dumps(tree, separators=(",", ":")).encode()
    padded = j + b"\0" * (-len(j) % 4)
    pickle = struct.pack("<II", 4 + len(padded), len(j)) + padded
    write(fx, "asar", "app.asar", struct.pack("<II", 4, len(pickle)) + pickle + data)


def retime(path):
    """Rewrite a tool-made .tgz / .tar.gz / ZIP with fixed times and owner
    (npm, setuptools and helm stamp the time of the run)."""
    raw = path.read_bytes()
    if raw.startswith(b"PK"):
        src = zipfile.ZipFile(io.BytesIO(raw))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as out:
            for info in src.infolist():
                data = src.read(info)
                info.date_time = ZIP_DATE
                out.writestr(info, data, compress_type=info.compress_type)
        path.write_bytes(buf.getvalue())
        return
    src = tarfile.open(fileobj=io.BytesIO(gzip.decompress(raw)))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=src.format) as out:
        for info in src.getmembers():
            data = src.extractfile(info).read() if info.isfile() else None
            info.mtime, info.uid, info.gid, info.uname, info.gname = STAMP, 0, 0, "", ""
            info.pax_headers = {k: v for k, v in info.pax_headers.items() if k not in ("mtime", "atime", "ctime")}
            out.addfile(info, io.BytesIO(data) if data is not None else None)
    path.write_bytes(gz(buf.getvalue()))


def main():
    if sys.argv[1] == "--retime":
        for p in sys.argv[2:]:
            retime(Path(p))
        return
    fx, work = Path(sys.argv[1]), Path(sys.argv[2])
    deb(fx)
    rpm(fx)
    rpm(fx, source=True)
    arch(fx)
    alpine(fx, work)
    conda(fx)
    freebsd(fx)
    slackware(fx)
    oci(fx)
    android_wrappers(fx, work)
    egg(fx, work)
    ipa(fx, work)
    nupkg(fx)
    msix(fx)
    vsix(fx)
    webext(fx, work)
    msi(fx)
    macos_pkg(fx)
    asar(fx)


if __name__ == "__main__":
    main()
