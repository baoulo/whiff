#!/usr/bin/env bash
# Regenerate the forensic fixtures under tests/fixtures/<format>/.
#
# Two sources:
# * openly licensed samples, downloaded into target/forensic-samples/ and
#   copied as they are: Eric Zimmerman's test files (MIT: EVTX — themselves
#   from the rust `evtx` project, MIT —, jump lists, Prefetch from Windows
#   XP to 10, a registry hive, shortcuts) and rust-minidump's test dumps
#   (MIT);
# * files written here, in a Debian container run with podman (image
#   `whiff-forensic`, built from the Containerfile below), for a fictitious
#   harbour (Saltmere Harbour): text2pcap and editcap (pcap, nanosecond
#   pcap, pcapng with comments and a decryption-secrets block, btsnoop),
#   hivexregedit (a registry hive), pylnk3 (shortcuts), mkntfs / ntfscp /
#   ntfscat ($MFT), utmpdump (wtmp, in debian:bookworm), systemd-journal-remote
#   (a journal, cut after its last object: the file is preallocated).
#   Formats no Linux tool writes are built by Python from their published
#   layouts: Recycle Bin $I, EVT, ESE header, kernel crash dump header,
#   LiME, hibernation file, unified2, FSEvents; and the text formats by
#   hand: Snort rules, HAR, an .ips crash report, a Zeek log.
#
#     scripts/fixtures/forensic.sh
#
# Containerfile (`podman build -t whiff-forensic`):
#
#     FROM docker.io/library/debian:trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#         tshark python3 python3-pip libhivex-bin libwin-hivex-perl ntfs-3g systemd-journal-remote util-linux ca-certificates
#     RUN pip install --break-system-packages pylnk3==0.4.2 python-evtx==0.8.1 regipy==5.1.0 \
#         LnkParse3==1.5.2 windowsprefetch==4.0.3 minidump==0.0.24 idstools==0.6.5

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
samples="$root/target/forensic-samples"
mkdir -p "$samples"
work=$(mktemp -d "$root/target/forensic-fixtures.XXXXXX")

# ------------------------------------------------------------ the samples
for r in Prefetch evtx JumpList Registry Lnk; do
    if [ ! -d "$samples/$r" ]; then
        mkdir -p "$samples/$r"
        curl -sL "https://codeload.github.com/EricZimmerman/$r/tar.gz/master" | tar -xz -C "$samples/$r" --strip-components=1
    fi
done
mkdir -p "$samples/minidump"
for f in test.dmp linux-mini.dmp simple-crashpad.dmp; do
    [ -f "$samples/minidump/$f" ] ||
        curl -sL -o "$samples/minidump/$f" "https://raw.githubusercontent.com/rust-minidump/rust-minidump/main/testdata/$f"
done
copy() { mkdir -p "$fx/$1"; cp "$2" "$fx/$1/${3:-$(basename "$2")}"; }
ev="$samples/evtx/evtx.Test/TestFiles/rust-evtx"
gzip -dc "$ev/new-user-security.evtx.gz" >"$work/new-user-security.evtx"
gzip -dc "$ev/Application_no_crc32.evtx.gz" >"$work/Application_no_crc32.evtx"
copy evtx "$work/new-user-security.evtx"
copy evtx "$work/Application_no_crc32.evtx"
jl="$samples/JumpList/JumpList.Test/TestFiles"
copy jump_list "$jl/Win7/1b4dd67f29cb1962.automaticDestinations-ms"
copy jump_list "$jl/Win10/7e4dca80246863e3.automaticDestinations-ms"
copy custom_jump_list "$jl/dtformats/5afe4de1b92fc382.customDestinations-ms"
pf="$samples/Prefetch/Prefetch.Test/TestFiles"
copy prefetch "$pf/Win10/CALC.EXE-3FBEF7FD.pf"
copy prefetch "$pf/Win2k3/CMD.EXE-087B4001.pf"
copy prefetch "$pf/Vista/CMD.EXE-89305D47.pf"
copy prefetch "$pf/Win2012/CMD.EXE-4A81B364.pf"
copy registry_hive "$samples/Registry/Registry.Test/Hives/UnicodeValueNames" UnicodeValueNames.dat
copy lnk "$samples/Lnk/Lnk.Test/TestFiles/Win10/$(ls "$samples/Lnk/Lnk.Test/TestFiles/Win10" | grep -m1 -i '\.lnk$')" ez-win10.lnk
copy lnk "$samples/Lnk/Lnk.Test/TestFiles/WinXP/$(ls "$samples/Lnk/Lnk.Test/TestFiles/WinXP" | grep -m1 -i '\.lnk$')" ez-winxp.lnk
for f in test.dmp linux-mini.dmp simple-crashpad.dmp; do copy minidump "$samples/minidump/$f"; done

# ------------------------------------------------- written in a container
podman run --rm -i -e TZ=UTC -v "$work:/w" -w /w whiff-forensic bash -euo pipefail <<'EOF'
mkdir -p out/pcap out/pcapng out/btsnoop out/registry_hive out/lnk out/recycle_bin_info out/ntfs_mft out/utmp \
    out/systemd_journal out/evt out/ese out/windows_crash_dump out/lime out/hiberfil out/unified2 out/ids_rules \
    out/har out/ips_crash out/zeek_log out/fsevents

python3 - <<'PY'
import struct

def eth(src, dst, etype, payload):
    return bytes.fromhex(dst) + bytes.fromhex(src) + struct.pack(">H", etype) + payload

def ipv4(proto, payload, src=b"\xc0\x00\x02\x0a", dst=b"\xc0\x00\x02\x35"):
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst)
    return h + payload

def udp(sp, dp, payload):
    return struct.pack(">HHHH", sp, dp, 8 + len(payload), 0) + payload

def tcp(sp, dp, payload, flags=0x18):
    return struct.pack(">HHIIBBHHH", sp, dp, 1, 1, 0x50, flags, 65535, 0, 0) + payload

A, B = "020000000001", "020000000002"
dns = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05tides\x08saltmere\x07example\x00\x00\x01\x00\x01"
frames = [
    eth(A, B, 0x0800, ipv4(17, udp(53000, 53, dns))),
    eth(B, A, 0x0800, ipv4(17, udp(53, 53000, dns), b"\xc0\x00\x02\x35", b"\xc0\x00\x02\x0a")),
    eth(A, B, 0x0800, ipv4(6, tcp(50000, 80, b"GET /tides HTTP/1.1\r\nHost: tides.saltmere.example\r\n\r\n"))),
    eth(A, B, 0x0800, ipv4(6, tcp(50001, 443, b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00"))),
    eth(A, "ffffffffffff", 0x0806, bytes(28)),
    eth(A, B, 0x86dd, struct.pack(">IHBB16s16s", 0x60000000, 8, 17, 255, bytes(15) + b"\x01", bytes(15) + b"\x02") + udp(5353, 5353, b"")),
]
with open("frames.txt", "w") as f:
    for i, fr in enumerate(frames):
        f.write(f"2025-09-01 12:00:{i * 7:02d}.{i * 125000:06d}\n")
        for off in range(0, len(fr), 16):
            f.write(f"{off:06x} " + " ".join(f"{b:02x}" for b in fr[off:off + 16]) + "\n")
        f.write("\n")
# Bluetooth HCI (H4 with the direction header): a reset command and its event.
with open("bt.txt", "w") as f:
    for i, fr in enumerate([b"\x00\x00\x00\x00\x01\x03\x0c\x00", b"\x00\x00\x00\x01\x04\x0e\x04\x01\x03\x0c\x00"]):
        f.write(f"2025-09-01 12:00:0{i}.000000\n000000 " + " ".join(f"{b:02x}" for b in fr) + "\n\n")
PY
text2pcap -q -F pcap -t "%Y-%m-%d %H:%M:%S." frames.txt out/pcap/saltmere-harbour.pcap
editcap -F nsecpcap out/pcap/saltmere-harbour.pcap out/pcap/saltmere-harbour-ns.pcap
printf 'CLIENT_RANDOM 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\n' >keys.txt
editcap -F pcapng -a "3:Ferry booking request" --inject-secrets tls,keys.txt out/pcap/saltmere-harbour.pcap \
    out/pcapng/saltmere-harbour.pcapng
text2pcap -q -F pcap -l 201 -t "%Y-%m-%d %H:%M:%S." bt.txt bt.pcap
editcap -F btsnoop bt.pcap out/btsnoop/hci-reset.btsnoop

# Registry: hivexregedit merges a .reg file into an empty hive.
python3 - <<'PY'
import struct
bins = bytearray(b"hbin" + struct.pack("<II", 0, 4096) + bytes(20))
def add_cell(data):
    size = (len(data) + 4 + 7) // 8 * 8
    off = len(bins)
    bins.extend(struct.pack("<i", -size) + data + bytes(size - 4 - len(data)))
    return off
# A security cell with an empty self-relative descriptor; it links to itself.
sk_off = len(bins)
descriptor = struct.pack("<BBHIIII", 1, 0, 0x8000, 0, 0, 0, 0)
add_cell(b"sk" + struct.pack("<HIIII", 0, sk_off, sk_off, 1, len(descriptor)) + descriptor)
nk = bytearray(76)
nk[0:2] = b"nk"
struct.pack_into("<H", nk, 2, 0x2c)
struct.pack_into("<IIIIIIII", nk, 16, 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0xFFFFFFFF, sk_off)
struct.pack_into("<I", nk, 48, 0xFFFFFFFF)
name = b"ROOT"
struct.pack_into("<HH", nk, 72, len(name), 0)
root_off = add_cell(bytes(nk) + name)
free = 4096 - len(bins)
bins += struct.pack("<i", free) + bytes(free - 4)
base = bytearray(4096)
base[0:4] = b"regf"
struct.pack_into("<IIQIIIII", base, 4, 1, 1, 133_984_224_000_000_000, 1, 6, 0, 1, 32)
struct.pack_into("<I", base, 36, root_off)
struct.pack_into("<II", base, 40, 4096, 1)
csum = 0
for (v,) in struct.iter_unpack("<I", bytes(base[:508])):
    csum ^= v
struct.pack_into("<I", base, 508, csum)
open("empty.hiv", "wb").write(bytes(base) + bytes(bins))
PY
cat >software.reg <<'REG'
Windows Registry Editor Version 5.00

[\Microsoft]

[\Microsoft\Windows NT]

[\Microsoft\Windows NT\CurrentVersion]
"ProductName"="Windows 11 Pro"
"EditionID"="Professional"
"DisplayVersion"="24H2"
"CurrentBuild"="26100"
"CurrentVersion"="6.3"
"InstallDate"=dword:68b58b00

[\Clients]

[\Clients\StartMenuInternet]

[\Clients\StartMenuInternet\Saltmere Browser]
@="Saltmere Browser"

[\Classes]

[\Classes\.tide]
@="Saltmere.TideTable"

[\Policies]

[\Policies\Saltmere]
"Harbour"="Saltmere"
REG
cp empty.hiv out/registry_hive/SOFTWARE
hivexregedit --merge --prefix '' out/registry_hive/SOFTWARE software.reg

# Shortcuts.
pylnk3 create 'C:\Windows\System32\notepad.exe' out/lnk/tide-table.lnk --arguments 'C:\Users\Public\tides.txt' \
    --description 'Saltmere tide table' --workdir 'C:\Users\Public' >/dev/null
pylnk3 create '\\harbour-nas\charts\approaches.pdf' out/lnk/approaches.lnk --description 'Harbour approaches chart' >/dev/null

# $MFT of a small NTFS volume with a few files.
dd if=/dev/zero of=vol.img bs=1M count=8 status=none
mkntfs -F -f -q -L SALTMERE vol.img
printf 'High water 06:12\n' >tides.txt
printf '%%PDF-1.4\n' >chart.pdf
ntfscp -q vol.img tides.txt tides.txt
ntfscp -q vol.img chart.pdf chart.pdf
ntfscat vol.img '$MFT' >out/ntfs_mft/saltmere.mft

# wtmp from utmpdump's text form.
cat >wtmp.txt <<'TXT'
[2] [00000] [~~  ] [reboot  ] [~           ] [6.12.0-saltmere     ] [0.0.0.0        ] [2025-09-01T06:00:00,000000+00:00]
[1] [00051] [~~  ] [runlevel] [~           ] [6.12.0-saltmere     ] [0.0.0.0        ] [2025-09-01T06:00:05,000000+00:00]
[7] [01234] [ts/0] [harbour ] [pts/0       ] [192.0.2.10          ] [192.0.2.10     ] [2025-09-01T07:12:00,000000+00:00]
[8] [01234] [    ] [        ] [pts/0       ] [                    ] [0.0.0.0        ] [2025-09-01T08:30:00,000000+00:00]
[7] [02345] [tty1] [gauge   ] [tty1        ] [                    ] [0.0.0.0        ] [2025-09-01T09:00:00,000000+00:00]
TXT
# (utmpdump runs in a bookworm container below: trixie keeps logins in wtmpdb.)

# A journal written by systemd-journal-remote from the export format.
python3 - <<'PY' >export.txt
boot = "7e1c4c2a00004000800005a17e7e0001"
for i, msg in enumerate(["Tide gauge 7 online", "High water 4.1 m", "Low water 0.9 m"]):
    t = 1756728000_000000 + i * 60_000_000
    print(f"__CURSOR=s=0;i={i + 1}\n__REALTIME_TIMESTAMP={t}\n__MONOTONIC_TIMESTAMP={1000000 + i}\n_BOOT_ID={boot}\n"
          f"_MACHINE_ID=5a17e7e05a17e7e05a17e7e05a17e7e0\n_HOSTNAME=gauge7\nSYSLOG_IDENTIFIER=tided\nPRIORITY=6\nMESSAGE={msg}\n")
PY
# A small size limit keeps the hash tables (sized from it) small.
mkdir -p /etc/systemd
printf '[Remote]\nMaxFileSize=256K\n' >/etc/systemd/journal-remote.conf
/usr/lib/systemd/systemd-journal-remote --split-mode=none -o gauge7.journal - <export.txt 2>/dev/null
# The file is preallocated: keep it up to the end of its last object.
python3 - <<'PY'
import struct
b = open("gauge7.journal", "rb").read()
tail = struct.unpack_from("<Q", b, 136)[0]
size = struct.unpack_from("<Q", b, tail + 8)[0]
end = (tail + size + 7) // 8 * 8
open("out/systemd_journal/gauge7.journal", "wb").write(b[:end])
PY

# Formats no Linux tool writes, from their published layouts.
python3 - <<'PY'
import gzip, struct, time

def filetime(unix):
    return (unix + 11644473600) * 10_000_000

# Recycle Bin $I, version 2 (Windows 10).
path = "C:\\Users\\Public\\Documents\\tides-2024.xlsx\0"
data = struct.pack("<QQQI", 2, 48213, filetime(1756728000), len(path)) + path.encode("utf-16-le")
open("out/recycle_bin_info/$IHARBR1.xlsx", "wb").write(data)

# EVT: header and two records from a Saltmere source.
def evt_record(num, t, eid, source):
    strings = (source + "\0" + "GAUGE7\0").encode("utf-16-le")
    body = struct.pack("<4sIIIIHHHHIIIIII", b"LfLe", num, t, t, eid, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0) + strings
    size = 4 + len(body) + 4
    size += (-size) % 4
    rec = struct.pack("<I", size) + body
    return rec + bytes(size - len(rec) - 4) + struct.pack("<I", size)
recs = evt_record(1, 1756728000, 100, "Saltmere") + evt_record(2, 1756728600, 101, "Saltmere")
head = struct.pack("<I4sIIIIIIIII", 0x30, b"LfLe", 1, 1, 0x30, 0x30 + len(recs), 3, 1, 0x10000, 0, 0x93a80) + struct.pack("<I", 0x30)
open("out/evt/Saltmere.evt", "wb").write(head + recs)

# ESE header page (database, clean shutdown, 8 KiB pages).
h = bytearray(8192 * 3)
def logtime(y, mo, d, hh, mi, s):
    return bytes([s, mi, hh, d, mo, y - 1900, 0, 0])
struct.pack_into("<II", h, 4, 0x89ABCDEF, 0x620)
struct.pack_into("<I", h, 12, 0)
h[24:28] = struct.pack("<I", 0x5a17)
h[28:36] = logtime(2025, 9, 1, 6, 0, 0)
struct.pack_into("<I", h, 52, 3)
h[64:72] = logtime(2025, 9, 1, 12, 0, 0)
h[72:80] = logtime(2025, 9, 1, 6, 0, 1)
struct.pack_into("<II", h, 232, 0x14, 8192)
open("out/ese/srudb-header.edb", "wb").write(bytes(h))

# Windows kernel crash dump header (64-bit): bug check 0x50.
d = bytearray(0x2000)
d[0:8] = b"PAGEDU64"
struct.pack_into("<II", d, 8, 0x0f, 26100)
struct.pack_into("<II", d, 48, 0x8664, 4)
struct.pack_into("<I", d, 56, 0x50)
struct.pack_into("<QQQQ", d, 64, 0xffffd30a00000000, 0, 0xfffff8063a2b1c00, 2)
open("out/windows_crash_dump/MEMORY-header.DMP", "wb").write(bytes(d))

# LiME: two ranges of zero-filled memory.
lime = b""
for start, size in [(0x1000, 0x2000), (0x100000, 0x1000)]:
    lime += struct.pack("<4sIQQQ", b"EMiL", 1, start, start + size - 1, 0) + bytes(size)
open("out/lime/gauge7.lime", "wb").write(lime)

open("out/hiberfil/hiberfil.sys", "wb").write(b"hibr" + bytes(4092))

# unified2: two v2 IPv4 events and a packet.
def rec(t, body):
    return struct.pack(">II", t, len(body)) + body
def event(eid, sec, sid, prio, blocked):
    return rec(104, struct.pack(">IIIIIIIIII4s4sHHBBBBII2s", 0, eid, sec, 0, sid, 1, 2, 3, prio, 0,
                                 b"\xc0\x00\x02\x0a", b"\xc0\x00\x02\x35", 50000, 80, 6, 0, 0, blocked, 0, 0, b"\0\0"))
u2 = event(1, 1756728000, 2100498, 2, 0) + rec(2, struct.pack(">IIIIIII", 0, 1, 1756728000, 1756728000, 0, 1, 4) + b"\0\0\0\0")
u2 += event(2, 1756728300, 1000001, 1, 1)
open("out/unified2/snort.u2.1756728000", "wb").write(u2)

# FSEvents page (version 2): three records.
recs = b""
for p, eid, flags in [("Users/Public/tides.txt", 1001, 0x1_0001), ("Users/Public/old.txt", 1002, 0x1_0002),
                      ("Library/Harbour", 1003, 0x2_0001)]:
    recs += p.encode() + b"\0" + struct.pack("<QIQ", eid, flags, 4000 + eid)
page = b"2SLD" + struct.pack("<II", 0x1234, 12 + len(recs)) + recs
open("out/fsevents/0000000000001003", "wb").write(page)
PY

cat >out/ids_rules/saltmere.rules <<'RULES'
# Saltmere Harbour local rules
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"SALTMERE tide API over plain HTTP"; flow:to_server,established; content:"/tides"; http_uri; classtype:policy-violation; sid:1000001; rev:2;)
alert udp any any -> $HOME_NET 53 (msg:"SALTMERE DNS query for gauge host"; content:"|05|gauge"; classtype:misc-activity; sid:1000002; rev:1;)
drop tcp any any -> $HOME_NET 23 (msg:"SALTMERE telnet to harbour network"; classtype:attempted-admin; sid:1000003; rev:1;)
# alert icmp any any -> any any (msg:"SALTMERE ping"; classtype:misc-activity; sid:1000004; rev:1;)
alert http any any -> any any (msg:"SALTMERE ferry booking"; http.uri; content:"/ferry"; classtype:policy-violation; sid:1000005; rev:1;)
RULES

python3 - <<'PY'
import json
entries = []
for i, (method, path, status, mime) in enumerate([("GET", "/", 200, "text/html"), ("GET", "/tides.json", 200, "application/json"),
                                                   ("POST", "/ferry/book", 302, "text/html"), ("GET", "/logo.png", 304, "image/png")]):
    req = {"method": method, "url": f"https://tides.saltmere.example{path}", "httpVersion": "HTTP/2",
           "headers": [{"name": "accept", "value": "*/*"}], "cookies": [], "queryString": [], "headersSize": -1, "bodySize": 0}
    if method == "POST":
        req["postData"] = {"mimeType": "application/x-www-form-urlencoded", "text": "seats=2"}
    entries.append({"startedDateTime": f"2025-09-01T12:00:0{i}.000Z", "time": 42.0, "request": req,
                    "response": {"status": status, "statusText": "", "httpVersion": "HTTP/2", "headers": [], "cookies": [],
                                 "content": {"size": 512, "mimeType": mime}, "redirectURL": "", "headersSize": -1,
                                 "bodySize": 512, "_transferSize": 600}, "cache": {}, "timings": {"send": 1, "wait": 30, "receive": 11}})
har = {"log": {"version": "1.2", "creator": {"name": "WebInspector", "version": "537.36"},
               "pages": [{"startedDateTime": "2025-09-01T12:00:00.000Z", "id": "page_1", "title": "Saltmere tides", "pageTimings": {}}],
               "entries": entries}}
json.dump(har, open("out/har/tides.saltmere.example.har", "w"), indent=1)

head = {"app_name": "TideClock", "timestamp": "2025-09-01 12:00:00.00 +0000", "app_version": "1.2", "slice_uuid": "00000000-0000-4000-8000-000000000001",
        "build_version": "12", "platform": 1, "bundleID": "example.saltmere.TideClock", "share_with_app_devs": 0, "is_first_party": 0,
        "bug_type": "309", "os_version": "macOS 15.6 (24G84)", "roots_installed": 0, "name": "TideClock", "incident_id": "5A17E7E0-0000-4000-8000-000000000001"}
body = {"procName": "TideClock", "procPath": "/Applications/TideClock.app/Contents/MacOS/TideClock", "cpuType": "ARM-64",
        "exception": {"codes": "0x0000000000000001, 0x0000000000000000", "type": "EXC_BAD_ACCESS", "signal": "SIGSEGV", "subtype": "KERN_INVALID_ADDRESS at 0x0000000000000000"},
        "termination": {"flags": 0, "code": 11, "namespace": "SIGNAL", "indicator": "Segmentation fault: 11"},
        "faultingThread": 0,
        "threads": [{"triggered": True, "id": 1, "frames": [{"imageOffset": 1234, "symbol": "nextHighWater", "imageIndex": 0},
                                                             {"imageOffset": 2345, "symbol": "main", "imageIndex": 0}]}],
        "usedImages": [{"name": "TideClock", "base": 4294967296, "size": 16384}, {"name": "libsystem_kernel.dylib", "base": 6442450944, "size": 245760}]}
open("out/ips_crash/TideClock-2025-09-01-120000.ips", "w").write(json.dumps(head) + "\n" + json.dumps(body, indent=2) + "\n")
PY

printf '#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#open\t2025-09-01-12-00-00\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\n#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\n1756728000.120000\tCaBcD1\t192.0.2.10\t53000\t192.0.2.53\t53\tudp\tdns\n1756728007.250000\tCaBcD2\t192.0.2.10\t50000\t192.0.2.53\t80\ttcp\thttp\n1756728014.375000\tCaBcD3\t192.0.2.10\t50001\t192.0.2.53\t443\ttcp\tssl\n#close\t2025-09-01-12-05-00\n' >out/zeek_log/conn.log
EOF

podman run --rm -v "$work:/w" -w /w docker.io/library/debian:bookworm bash -c 'utmpdump -r <wtmp.txt >out/utmp/wtmp 2>/dev/null'

for d in "$work"/out/*/; do
    name=$(basename "$d")
    mkdir -p "$fx/$name"
    cp "$d"* "$fx/$name/"
done
echo "fixtures written; work files are in $work"
