"""Apple fixtures written in the `whiff-binser` container (see apple.sh):
a signed configuration profile and a signed provisioning profile (openssl
cms with a throwaway certificate), a .DS_Store (the ds_store package), an
AppleSingle file (RFC 1740 layout) and bookmark / alias data (the CFURL
bookmark layout). Run from the repository root."""

import plistlib
import struct
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from ds_store import DSStore

FX = Path("tests/fixtures")
DATE = datetime(2025, 9, 1, 12, tzinfo=timezone.utc)


def write(fmt, name, data):
    (FX / fmt).mkdir(parents=True, exist_ok=True)
    (FX / fmt / name).write_bytes(data)


def certificate(work):
    key, cert = work / "signer.key", work / "signer.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "365",
         "-subj", "/CN=Saltmere Harbour Profiles/O=Saltmere Harbour/C=GB", "-keyout", key, "-out", cert],
        check=True, capture_output=True)
    return key, cert


def sign(work, data):
    key, cert = certificate(work)
    return subprocess.run(
        ["openssl", "cms", "-sign", "-signer", cert, "-inkey", key, "-outform", "DER", "-nodetach", "-binary"],
        input=data, check=True, capture_output=True).stdout


def profiles(work):
    unsigned = (FX / "mobileconfig" / "saltmere-guest.mobileconfig").read_bytes()
    write("mobileconfig", "saltmere-guest-signed.mobileconfig", sign(work, unsigned))
    profile = plistlib.dumps({
        "AppIDName": "Saltmere Tides", "Name": "Saltmere Tides Development", "TeamName": "Saltmere Harbour",
        "TeamIdentifier": ["SALTMERE01"], "ApplicationIdentifierPrefix": ["SALTMERE01"], "Platform": ["iOS", "xrOS"],
        "UUID": "5a1e0000-0000-4000-8000-000000000020", "CreationDate": DATE,
        "ExpirationDate": datetime(2026, 9, 1, 12, tzinfo=timezone.utc),
        "ProvisionedDevices": ["00008110-000000000000001E", "00008120-000000000000002F"],
        "DeveloperCertificates": [b"\x30\x03\x02\x01\x01"],
        "Entitlements": {"application-identifier": "SALTMERE01.org.saltmere.tides", "get-task-allow": True,
                         "keychain-access-groups": ["SALTMERE01.*"], "com.apple.developer.team-identifier": "SALTMERE01"},
        "TimeToLive": 365, "Version": 1,
    })
    write("mobileprovision", "Saltmere_Tides_Development.mobileprovision", sign(work, profile))


def ds_store(work):
    path = work / "DS_Store"
    with DSStore.open(str(path), "w+") as d:
        d["."]["vSrn"] = ("long", 1)
        d["."]["icvp"] = {"viewOptionsVersion": 1, "gridSpacing": 54.0, "iconSize": 64.0, "textSize": 12.0,
                          "showItemInfo": False, "labelOnBottom": True, "arrangeBy": "none",
                          "backgroundType": 0, "gridOffsetX": 0.0, "gridOffsetY": 0.0, "showIconPreview": True}
        d["."]["bwsp"] = {"ShowStatusBar": False, "ShowPathbar": True, "ShowToolbar": True, "ShowSidebar": True,
                          "WindowBounds": "{{100, 100}, {640, 400}}"}
        d["."]["vstl"] = ("type", b"icnv")
        for i, name in enumerate(["tides.csv", "berths.pdf", "Charts", "harbour-map.png"]):
            d[name]["Iloc"] = (64 + 128 * i, 64)
        # modD: 1/65536 s since 1904, as a `dutc` value.
        stamp = int((DATE.timestamp() + 2_082_844_800) * 65536)
        d["tides.csv"]["modD"] = ("dutc", stamp)
        d["berths.pdf"]["modD"] = ("dutc", stamp + 86_400 * 65536)
        d["tides.csv"]["lg1S"] = ("comp", 1024)
    write("ds_store", "saltmere.DS_Store", path.read_bytes())


def applesingle():
    name = b"buoy.txt"
    data = b"buoy 7: green, flashing\n"
    finder = b"TEXTSLTM" + b"\0" * 24
    epoch = int(DATE.timestamp()) - 946_684_800
    dates = struct.pack(">iiii", epoch, epoch, -0x80000000, epoch)
    entries = [(3, name), (8, dates), (9, finder), (1, data)]
    header = struct.pack(">II16sH", 0x00051600, 0x00020000, b"", len(entries))
    off = len(header) + 12 * len(entries)
    table, body = b"", b""
    for eid, payload in entries:
        table += struct.pack(">III", eid, off + len(body), len(payload))
        body += payload
    write("applesingle", "buoy.as", header + table + body)


def item(kind, payload):
    """A bookmark item: length, type, payload padded to 4 bytes."""
    pad = (-len(payload)) % 4
    return struct.pack("<II", len(payload), kind) + payload + b"\0" * pad


def bookmarks():
    """Bookmark data for /Volumes/Saltmere/Charts/tides.txt, laid out as
    Foundation writes it (macOS 15): items, then the table of contents."""
    def cf_date(d):
        return struct.pack(">d", d.timestamp() - 978_307_200)

    def text(t):
        return item(0x0101, t.encode())

    def num(n):
        return item(0x0304, struct.pack("<q", n))

    region = bytearray(b"\0\0\0\0")
    offsets = {}

    def add(key, raw):
        offsets[key] = len(region)
        region.extend(raw)

    def array(parts):
        offs = []
        for raw in parts:
            offs.append(len(region))
            region.extend(raw)
        return item(0x0601, b"".join(struct.pack("<I", o) for o in offs))

    add(0x1004, array([text("Volumes"), text("Saltmere"), text("Charts"), text("tides.txt")]))
    add(0x1005, array([num(2), num(17), num(18), num(19)]))
    # Resource properties: flags (regular file), valid mask, reserved.
    add(0x1010, item(0x0201, struct.pack("<QQQ", 0x01, 0x0F, 0)))
    add(0x1040, item(0x0400, cf_date(DATE)))
    add(0x2002, text("/Volumes/Saltmere"))
    add(0x2005, item(0x0901, b"file:///Volumes/Saltmere/"))
    add(0x2010, text("Saltmere"))
    add(0x2011, text("5A1E0000-0000-4000-8000-000000000030"))
    add(0x2012, num(2_097_152))
    add(0x2013, item(0x0400, cf_date(DATE)))
    add(0x2020, item(0x0201, struct.pack("<QQQ", 0x81, 0x13EF, 0)))
    add(0x2030, item(0x0500, b""))
    add(0xC001, item(0x0303, struct.pack("<i", 0)))
    add(0xC011, text("keeper"))
    add(0xC012, item(0x0303, struct.pack("<i", 501)))
    add(0xD010, item(0x0303, struct.pack("<i", 0x20000200)))
    add(0xF017, text("tides.txt"))
    toc_at = len(region)
    keys = sorted(offsets)
    toc = struct.pack("<IIIII", 12 + 12 * len(keys), 0xFFFFFFFE, 1, 0, len(keys))
    toc += b"".join(struct.pack("<III", k, offsets[k], 0) for k in keys)
    region.extend(toc)
    region[0:4] = struct.pack("<I", toc_at)
    plain = b"book" + struct.pack("<III", 0x40 + len(region), 0x10050000, 0x40) + b"\0" * 0x30 + bytes(region)
    write("bookmark_data", "tides.bookmark", plain)
    alias = b"book\0\0\0\0mark\0\0\0\0" + struct.pack("<IIII", 0x38, 0x38, len(region), 0x10050000)
    alias += b"\0" * (0x38 - len(alias)) + bytes(region)
    write("alias", "tides.alias", alias)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        profiles(work)
        ds_store(work)
    applesingle()
    bookmarks()


main()
