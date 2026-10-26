#!/usr/bin/env python3
"""Compare whiff's package reports with independent readers.

    package_oracle.py <whiff binary> <file or list.txt>...

For each package, the name and version whiff reports are checked against
what another reader finds: the Android SDK's `aapt2 dump badging` (APK),
`gem specification` (gems), `hdiutil imageinfo` (DMG: disk size and
partition count), the `xar` tool (macOS installer packages: identifier and
version from PackageInfo / Distribution), and Python's own zipfile /
tarfile / email / json / tomllib / ElementTree readers for the rest (JAR
manifests, wheel and egg metadata, npm, crates, sdists, conda, Helm,
Arch and Alpine .PKGINFO, Debian control files, NuGet, VSIX, XPI, APPX,
asar headers). Entry counts are compared where the reference lists the
archive. A `.txt` argument is a list of paths, one per line.

Prints one line per mismatch and a summary per format. Exit status 0.
"""

import bz2
import email.parser
import gzip
import io
import json
import lzma
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict
from compression import zstd
from pathlib import Path

SDK = Path(os.environ.get("ANDROID_HOME", Path.home() / "Library/Android/sdk"))


def run(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=120).stdout


def manifest(text):
    """JAR manifest main section (continuation lines joined)."""
    out, last = {}, None
    for line in text.replace("\r\n", "\n").split("\n"):
        if not line:
            break
        if line.startswith(" ") and last:
            out[last] += line[1:]
        elif ":" in line:
            last, v = line.split(":", 1)
            out[last] = v.strip()
    return out


def jar(path):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        m = manifest(z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")) if "META-INF/MANIFEST.MF" in names else {}
        pom = next((n for n in names if n.startswith("META-INF/maven/") and n.endswith("/pom.properties")), None)
        props = {}
        if pom:
            for line in z.read(pom).decode("utf-8", "replace").splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    props[k.strip()] = v.strip()
    name = m.get("Implementation-Title") or m.get("Bundle-Name") or m.get("Bundle-SymbolicName") or props.get("artifactId")
    version = m.get("Implementation-Version") or m.get("Bundle-Version") or props.get("version")
    return name, version, len(names)


def core_metadata(text):
    msg = email.parser.Parser().parsestr(text)
    return msg.get("Name"), msg.get("Version")


def wheel(path):
    with zipfile.ZipFile(path) as z:
        meta = next(n for n in z.namelist() if n.endswith(".dist-info/METADATA"))
        return (*core_metadata(z.read(meta).decode("utf-8", "replace")), len(z.namelist()))


def egg(path):
    with zipfile.ZipFile(path) as z:
        return (*core_metadata(z.read("EGG-INFO/PKG-INFO").decode("utf-8", "replace")), len(z.namelist()))


def untar(path):
    raw = Path(path).read_bytes()
    for magic, f in [(b"\x1f\x8b", gzip.decompress), (b"\x28\xb5\x2f\xfd", zstd.decompress),
                     (b"\xfd7zXZ", lzma.decompress), (b"BZh", bz2.decompress)]:
        if raw.startswith(magic):
            raw = f(raw)
            break
    return tarfile.open(fileobj=io.BytesIO(raw))


def member(t, pred):
    for m in t.getmembers():
        if m.isfile() and pred(m.name.lstrip("./")):
            return t.extractfile(m).read().decode("utf-8", "replace")
    return None


def npm(path):
    t = untar(path)
    v = json.loads(member(t, lambda n: n == "package/package.json"))
    return v.get("name"), v.get("version"), len(t.getmembers())


def crate(path):
    t = untar(path)
    v = tomllib.loads(member(t, lambda n: n.count("/") == 1 and n.endswith("/Cargo.toml")))["package"]
    return v.get("name"), v.get("version"), len(t.getmembers())


def sdist(path):
    t = untar(path)
    return (*core_metadata(member(t, lambda n: n.count("/") == 1 and n.endswith("/PKG-INFO"))), len(t.getmembers()))


def helm(path):
    t = untar(path)
    text = member(t, lambda n: n.count("/") == 1 and n.endswith("/Chart.yaml"))
    get = lambda k: next((re.sub(r"^['\"]|['\"]$", "", l.split(":", 1)[1].strip()) for l in text.splitlines() if l.startswith(k + ":")), None)
    return get("name"), get("version"), len(t.getmembers())


def pkginfo(path):
    t = untar(path)
    text = member(t, lambda n: n == ".PKGINFO") or ""
    get = lambda k: next((l.split(" = ", 1)[1] for l in text.splitlines() if l.startswith(k + " = ")), None)
    return get("pkgname"), get("pkgver"), len(t.getmembers())


def conda(path):
    if path.endswith(".conda"):
        with zipfile.ZipFile(path) as z:
            info = next(n for n in z.namelist() if n.startswith("info-"))
            t = tarfile.open(fileobj=io.BytesIO(zstd.decompress(z.read(info))))
            v = json.loads(member(t, lambda n: n == "info/index.json"))
            pkg = next(n for n in z.namelist() if n.startswith("pkg-"))
            count = len(tarfile.open(fileobj=io.BytesIO(zstd.decompress(z.read(pkg)))).getmembers())
            return v.get("name"), v.get("version"), count
    t = untar(path)
    v = json.loads(member(t, lambda n: n == "info/index.json"))
    return v.get("name"), v.get("version"), len(t.getmembers())


def deb(path):
    raw = Path(path).read_bytes()
    at, members = 8, {}
    while at + 60 <= len(raw):
        name, size = raw[at:at + 16].decode().strip().rstrip("/"), int(raw[at + 48:at + 58])
        members[name] = raw[at + 60:at + 60 + size]
        at += 60 + size + size % 2
    ctl = next(v for k, v in members.items() if k.startswith("control.tar"))
    data = next(v for k, v in members.items() if k.startswith("data.tar"))
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(ctl)
    tmp.close()
    text = member(untar(tmp.name), lambda n: n == "control")
    os.unlink(tmp.name)
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(data)
    tmp.close()
    count = len(untar(tmp.name).getmembers())
    os.unlink(tmp.name)
    f = email.parser.Parser().parsestr(text)
    return f.get("Package"), f.get("Version"), count


def gem(path):
    name = run("gem", "specification", path, "name").strip().removeprefix("--- ").strip()
    version = run("gem", "specification", path, "version").split("version:")[-1].strip().strip("'\"")
    return name or None, version or None, None


def apk(path):
    aapt = sorted((SDK / "build-tools").glob("*/aapt2"))[-1]
    out = run(str(aapt), "dump", "badging", path)
    m = re.search(r"package: name='([^']*)' versionCode='([^']*)' versionName='([^']*)'", out)
    return (m.group(1), m.group(3) or None, None) if m else (None, None, None)


def xar_pkg(path):
    d = tempfile.mkdtemp()
    try:
        subprocess.run(["xar", "-xf", path, "-C", d], capture_output=True, timeout=120)
        dist = Path(d) / "Distribution"
        if dist.exists():
            root = ET.parse(dist).getroot()
            p = root.find("product")
            if p is not None and p.get("id"):
                return p.get("id"), p.get("version"), None
        infos = sorted(Path(d).rglob("PackageInfo"))
        if infos:
            root = ET.parse(infos[0]).getroot()
            return root.get("identifier"), root.get("version"), None
        return None, None, None
    finally:
        shutil.rmtree(d, ignore_errors=True)


def dmg(path):
    out = subprocess.run(["hdiutil", "imageinfo", "-plist", path], capture_output=True, timeout=120).stdout
    if not out:
        return None, None, None
    info = plistlib.loads(out)
    parts = info.get("partitions", {}).get("partitions", [])
    size = info.get("Size Information", {}).get("Total Bytes")
    return None, None, (size, len(parts))


def zip_json(path, name):
    with zipfile.ZipFile(path) as z:
        return json.loads(z.read(name)), len(z.namelist())


def xpi(path):
    v, n = zip_json(path, "manifest.json")
    name = v.get("name")
    return (None if name and name.startswith("__MSG_") else name), v.get("version"), n


def vsix(path):
    with zipfile.ZipFile(path) as z:
        root = ET.fromstring(z.read("extension.vsixmanifest"))
        ident = next(e for e in root.iter() if e.tag.endswith("Identity"))
        return ident.get("Id"), ident.get("Version"), len(z.namelist())


def appx(path):
    with zipfile.ZipFile(path) as z:
        root = ET.fromstring(z.read("AppxManifest.xml"))
        ident = next(e for e in root.iter() if e.tag.endswith("Identity"))
        return ident.get("Name"), ident.get("Version"), len(z.namelist())


def nupkg(path):
    with zipfile.ZipFile(path) as z:
        spec = next(n for n in z.namelist() if "/" not in n and n.endswith(".nuspec"))
        root = ET.fromstring(z.read(spec))
        text = lambda tag: next((e.text for e in root.iter() if e.tag.endswith("}" + tag) or e.tag == tag), None)
        return text("id"), text("version"), len(z.namelist())


def asar(path):
    raw = Path(path).read_bytes()
    n = int.from_bytes(raw[12:16], "little")
    tree = json.loads(raw[16:16 + n])
    count = 0
    stack = [tree]
    while stack:
        node = stack.pop()
        for v in node.get("files", {}).values():
            count += 1
            if "files" in v:
                stack.append(v)
    return None, None, count


READERS = {
    "jar": jar, "war": jar, "ear": jar, "wheel": wheel, "egg": egg, "npm_tarball": npm, "crate": crate,
    "python_sdist": sdist, "helm_chart": helm, "arch_package": pkginfo, "alpine_package": pkginfo,
    "conda_package": conda, "deb": deb, "gem": gem, "apk": apk, "pkg": xar_pkg, "dmg": dmg, "xpi": xpi,
    "vsix": vsix, "msix": appx, "nupkg": nupkg, "asar": asar,
}


def whiff(binary, path):
    out = subprocess.run([binary, path], capture_output=True, text=True, timeout=300).stdout
    r = json.loads(out)
    fmt = r["identification"]["format"]
    f = r.get("format", {})
    f = f.get(fmt, f) if isinstance(f.get(fmt), dict) else f
    entries = r.get("physical", {}).get("container", {}).get("entries")
    errors = [e for e in r.get("diagnostics", {}).get("extractors", []) if e.get("status") not in ("ok", None)]
    return fmt, f, entries, errors


def main():
    binary, args = sys.argv[1], sys.argv[2:]
    paths = []
    for a in args:
        paths += [l.strip() for l in open(a) if l.strip()] if a.endswith(".txt") else [a]
    stats = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for path in paths:
        try:
            fmt, f, entries, errors = whiff(binary, path)
        except Exception as e:  # noqa: BLE001
            print(f"WHIFF FAILED {path}: {e}")
            continue
        s = stats[fmt]
        s["files"][1] += 1
        s["files"][0] += not errors
        if errors:
            print(f"ERROR {fmt} {path}: {errors[0].get('error')}")
        reader = READERS.get(fmt)
        if not reader:
            continue
        try:
            name, version, count = reader(path)
        except Exception as e:  # noqa: BLE001
            print(f"REFERENCE FAILED {fmt} {path}: {e}")
            continue
        if fmt == "dmg":
            if count:
                size, parts = count
                for key, want, got in [("disk bytes", size, f.get("disk_bytes")), ("partitions", parts, len(f.get("partitions", [])))]:
                    s[key][1] += 1
                    s[key][0] += want == got
                    if want != got:
                        print(f"MISMATCH {fmt} {key} {path}: reference {want!r}, whiff {got!r}")
            continue
        for key, want, got in [("name", name, f.get("name")), ("version", version, f.get("version")), ("entries", count, entries)]:
            if want is None:
                continue
            s[key][1] += 1
            ok = str(want).strip() == str(got).strip()
            s[key][0] += ok
            if not ok:
                print(f"MISMATCH {fmt} {key} {path}: reference {want!r}, whiff {got!r}")
    print()
    for fmt in sorted(stats):
        parts = [f"{k} {ok}/{n}" for k, (ok, n) in stats[fmt].items()]
        print(f"{fmt:16} " + ", ".join(parts))


if __name__ == "__main__":
    main()
