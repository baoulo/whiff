#!/usr/bin/env python3
"""Compare whiff's disk image reports with independent tools.

    disk_oracle.py [--whiff target/debug/whiff] PATH...

PATHs are files or folders (walked). For each image whiff recognises as a
disk-family format (or squashfs / Snap / AppImage), the facts are checked
against:

* 7-Zip (`7zz l -slt`): file and folder counts and total size of ISO 9660,
  UDF, FAT, ext, NTFS and squashfs volumes; the partitions (offset, size)
  of raw disks and of VM disks converted to raw with qemu-img;
* `qemu-img info`: virtual size, cluster size, backing file, snapshots;
* `hdiutil imageinfo` (macOS): sparse image sector count;
* in the Debian container of disks.sh (files under shared folders only):
  `blkid -p` (file-system type, label and UUID, whole image or each
  partition), `ewfinfo` (case number, examiner, MD5, sectors),
  `unsquashfs -lls` (entries, total size), `mkimage -l` (uImage name and
  data size), `srec_info` (HEX / S-record data bytes), `unpack_bootimg`
  (boot image OS version, patch level, command line).

Prints one line per mismatch and a summary per format. Needs 7zz,
qemu-img and podman with the `whiff-fixtures` image.
"""

import argparse
import collections
import json
import os
import re
import subprocess
import sys
import tempfile

FS_7Z = {"iso9660", "udf", "fat", "ext", "ntfs"}
VM = {"vdi", "vmdk", "vhd", "vhdx", "qcow2", "qed"}
SHARED = ("/Users/", "/private/", "/var/folders/")
BLKID_TYPES = {
    "ext2": "ext2", "ext3": "ext3", "ext4": "ext4", "fat12": "vfat", "fat16": "vfat", "fat32": "vfat",
    "exfat": "exfat", "ntfs": "ntfs", "hfs_plus": "hfsplus", "hfsx": "hfsplus", "hfs": "hfs", "apfs": "apfs",
    "luks": "crypto_LUKS", "iso9660": "iso9660", "udf": "udf", "squashfs": "squashfs", "swap": "swap",
    "xfs": "xfs", "btrfs": "btrfs", "lvm2": "LVM2_member", "bitlocker": "BitLocker",
}

stats = collections.defaultdict(lambda: collections.Counter())


def run(cmd, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=300, **kw).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def check(fmt, field, path, ref, got):
    stats[fmt][field + " total"] += 1
    if ref == got:
        stats[fmt][field + " ok"] += 1
    else:
        print(f"MISMATCH {fmt} {field} {path}: reference {ref!r}, whiff {got!r}")


def container(path, script):
    """Run `script` in the fixtures container with the file's folder at /d."""
    if not path.startswith(SHARED):
        return None
    d, name = os.path.split(path)
    return run(["podman", "run", "--rm", "-v", f"{d}:/d:ro", "-w", "/d", "whiff-fixtures", "bash", "-c", script.replace("{f}", f"'/d/{name}'")])


def sevenzip(path):
    """Items of a 7-Zip listing: dicts of Path, Size, Folder, Offset."""
    out = run(["7zz", "l", "-slt", "-ba", path])
    items, cur = [], {}
    for line in out.splitlines():
        if not line.strip():
            if cur:
                items.append(cur)
            cur = {}
            continue
        k, _, v = line.partition(" = ")
        cur[k] = v
    if cur:
        items.append(cur)
    return items


def facts_of(report):
    fmt = report["identification"]["format"]
    return fmt, report.get("format", {}).get(fmt, {})


def check_listing(fmt, path, f):
    items = [i for i in sevenzip(path) if "Path" in i and not i["Path"].startswith("[")]
    if not items:
        return
    files = [i for i in items if i.get("Folder") != "+" and not i.get("Symbolic Link")]
    size = sum(int(i.get("Size") or 0) for i in files)
    check(fmt, "files", path, len(files), f.get("files", 0))
    check(fmt, "bytes", path, size, f.get("compressed_bytes"))


def partitions_7z(raw):
    out = []
    for i in sevenzip(raw):
        if "Offset" in i and i.get("Offset"):
            out.append((int(i["Offset"]), int(i.get("Size") or 0)))
    return sorted(out)


def check_partitions(fmt, path, f, raw):
    ours = f.get("partitions")
    if ours is None:
        return
    ref = partitions_7z(raw)
    got = sorted((p["start_bytes"], p["size_bytes"]) for p in ours if p.get("type") not in ("Extended", "Free space", "Partition map"))
    check(fmt, "partitions", path, len(ref), len(got))
    if len(ref) == len(got):
        check(fmt, "partition extents", path, ref, got)


def check_qemu(fmt, path, f):
    info = run(["qemu-img", "info", "--output=json", path])
    try:
        q = json.loads(info)
    except ValueError:
        return
    check(fmt, "virtual size", path, q.get("virtual-size"), f.get("virtual_bytes"))
    if fmt in ("qcow2", "qed"):
        check(fmt, "cluster size", path, q.get("cluster-size"), f.get("cluster_size"))
    if q.get("backing-filename"):
        check(fmt, "backing file", path, q.get("backing-filename"), f.get("backing_file"))
    if fmt == "qcow2":
        check(fmt, "snapshots", path, len(q.get("snapshots", [])), len(f.get("snapshots", [])))
    return q


def blkid(path, offset=0):
    out = container(path, f"blkid -p -o export {'-O ' + str(offset) if offset else ''} {{f}}") or ""
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def check_fs(fmt, path, fs, offset=0):
    if not fs or not path.startswith(SHARED):
        return
    b = blkid(path, offset)
    if not b:
        return
    kind = fs.get("type")
    check(fmt, "fs type", path, b.get("TYPE"), BLKID_TYPES.get(kind, kind))
    if "LABEL" in b and kind not in ("iso9660",):
        check(fmt, "fs label", path, b["LABEL"], fs.get("label"))
    if "UUID" in b and kind in ("ext2", "ext3", "ext4", "luks", "swap", "xfs", "btrfs", "apfs"):
        check(fmt, "fs uuid", path, b["UUID"].lower(), (fs.get("uuid") or "").lower())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--whiff", default="target/debug/whiff")
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args()
    files = []
    for p in a.paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                files += [os.path.abspath(os.path.join(root, n)) for n in names if n != "SOURCE.md"]
        else:
            files.append(os.path.abspath(p))
    for path in sorted(files):
        out = run([a.whiff, "--jsonl", path])
        try:
            report = json.loads(out.splitlines()[0])
        except (ValueError, IndexError):
            print(f"ERROR {path}: no report")
            continue
        fmt, f = facts_of(report)
        family = report["identification"].get("family")
        if family != "disk" and fmt not in ("squashfs", "snap", "appimage", "dmg"):
            continue
        stats[fmt]["files"] += 1
        for d in report.get("diagnostics", {}).get("extractors", []):
            if d.get("status") not in ("ok", None):
                print(f"ERROR {fmt} {path}: {d.get('status')} {d.get('error', '')}")
        if fmt in FS_7Z:
            check_listing(fmt, path, f)
        if fmt in VM:
            check_qemu(fmt, path, f)
            with tempfile.TemporaryDirectory() as t:
                raw = os.path.join(t, "disk.raw")
                if f.get("partitions") and not run(["qemu-img", "convert", "-O", "raw", path, raw]) and os.path.exists(raw):
                    check_partitions(fmt, path, f, raw)
        if fmt == "raw_disk":
            check_partitions(fmt, path, f, path)
        if fmt == "sparseimage" and sys.platform == "darwin":
            info = run(["hdiutil", "imageinfo", path])
            m = re.search(r"Sector Count: (\d+)", info)
            if m:
                check(fmt, "sectors", path, int(m.group(1)), f.get("virtual_bytes", 0) // 512)
        # File systems: the whole image, or each partition (raw disks only).
        if fmt in ("ext", "fat", "exfat", "ntfs", "hfs_plus", "apfs", "luks", "raw_disk", "udf", "iso9660"):
            if "filesystem" in f:
                check_fs(fmt, path, f["filesystem"])
            elif fmt == "iso9660":
                check_fs(fmt, path, {"type": "iso9660"})
            elif fmt == "udf":
                check_fs(fmt, path, {"type": "udf", "label": f.get("logical_volume_id")})
            for p in f.get("partitions", []) if fmt == "raw_disk" else []:
                check_fs(fmt, path, p.get("filesystem"), p["start_bytes"])
        if fmt == "e01":
            info = container(path, "ewfinfo {f}") or ""
            for key, ours in [("Case number", "case_number"), ("Examiner name", "examiner"), ("MD5", "md5")]:
                m = re.search(rf"{key}:\s*(.+)", info)
                if m:
                    check(fmt, ours, path, m.group(1).strip(), f.get(ours))
            m = re.search(r"Number of sectors:\s*(\d+)", info)
            if m:
                check(fmt, "sectors", path, int(m.group(1)), f.get("sectors"))
        if fmt in ("squashfs", "snap", "appimage"):
            off = f.get("payload_offset", 0)
            out = container(path, f"unsquashfs -lls {'-o ' + str(off) if off else ''} {{f}}") or ""
            rows = [l for l in out.splitlines() if re.match(r"^[-dlcbps][rwxsStT-]{9} ", l)]
            if rows:
                regular = [l for l in rows if l.startswith("-")]
                check(fmt, "files", path, len(regular), f.get("files"))
                check(fmt, "directories", path, sum(1 for l in rows if l.startswith("d")) - 1, f.get("directories", 0))
                size = sum(int(l.split()[2]) for l in regular)
                check(fmt, "bytes", path, size, report.get("physical", {}).get("container", {}).get("uncompressed_bytes"))
        if fmt == "uimage":
            out = container(path, "mkimage -l {f}") or ""
            m = re.search(r"Image Name:\s*(.+)", out)
            if m:
                check(fmt, "name", path, m.group(1).strip(), f.get("name"))
            m = re.search(r"Data Size:\s*(\d+)", out)
            if m:
                check(fmt, "data size", path, int(m.group(1)), f.get("data_bytes"))
        if fmt in ("intel_hex", "srec"):
            kind = "-intel" if fmt == "intel_hex" else ""
            out = container(path, f"srec_info {{f}} {kind}") or ""
            total = sum(int(b, 16) - int(a, 16) + 1 for a, b in re.findall(r"([0-9A-F]{4,}) - ([0-9A-F]{4,})", out))
            if total:
                check(fmt, "data bytes", path, total, f.get("data_bytes"))
        if fmt == "android_boot" and f.get("image") == "boot":
            out = container(path, "unpack_bootimg --boot_img {f} --out /tmp/x") or ""
            m = re.search(r"os version: (\S+)", out)
            if m:
                check(fmt, "os version", path, m.group(1), f.get("os_version"))
            m = re.search(r"os patch level: (\S+)", out)
            if m:
                check(fmt, "patch level", path, m.group(1), f.get("security_patch"))
    print()
    for fmt in sorted(stats):
        s = stats[fmt]
        parts = [f"files {s['files']}"]
        for k in sorted(k[:-6] for k in s if k.endswith(" total")):
            parts.append(f"{k} {s[k + ' ok']}/{s[k + ' total']}")
        print(f"{fmt:16} " + ", ".join(parts))


if __name__ == "__main__":
    main()
