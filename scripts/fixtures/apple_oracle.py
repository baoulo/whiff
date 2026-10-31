"""Compare whiff's Apple reports with Apple's own tools and other readers.

    python3 scripts/fixtures/apple_oracle.py [--sample N]

macOS only. The corpus is the Apple fixtures plus files from system
folders and /Applications (never the home folder):
* plists: plistlib (encoding, top-level type, value count, depth, keys,
  bundle identifier, keyed-archive objects and root class);
* .strings and .stringsdict: `plutil -convert json` (key counts, plural
  categories);
* asset catalogs: `assetutil --info` (versions, timestamp, platform,
  authoring tool, asset names);
* provisioning profiles and signed configuration profiles: `security cms
  -D` (name, team, expiry, device count, entitlements, payload types);
* Xcode projects: `plutil -convert json` (object count, targets,
  configurations);
* .DS_Store: the ds_store package, in the `whiff-binser` container
  (records, entry names).
"""

import argparse
import json
import plistlib
import random
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WHIFF = ROOT / "target" / "lint" / "debug" / "whiff"
SEARCH = ["/System/Library", "/Library", "/Applications"]


def find(pattern, limit):
    out = subprocess.run(["find", *SEARCH, "-path", "/System/Volumes", "-prune", "-o", "-name", pattern, "-type", "f",
                          "-print"], capture_output=True, text=True).stdout.split("\n")
    files = sorted(p for p in out if p)
    random.Random(7).shuffle(files)
    return files[:limit]


def whiff(paths):
    """Format sections by path (privacy off: profiles name their teams)."""
    out = {}
    for i in range(0, len(paths), 200):
        chunk = paths[i:i + 200]
        r = subprocess.run([WHIFF, "--jsonl", "--privacy", "off", *chunk], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            rep = json.loads(line)
            fmt = rep.get("format", {})
            sec = next(iter(fmt.values()), None) if fmt else None
            out[rep["source"]["path"]] = (next(iter(fmt), None), sec)
    return out


class Tally:
    def __init__(self):
        self.ok = Counter()
        self.total = Counter()
        self.bad = {}

    def check(self, what, path, got, want):
        self.total[what] += 1
        if got == want:
            self.ok[what] += 1
        else:
            self.bad.setdefault(what, []).append((path, got, want))

    def report(self):
        for what in sorted(self.total):
            print(f"{what}: {self.ok[what]}/{self.total[what]}")
            for path, got, want in self.bad.get(what, [])[:5]:
                print(f"    {path}\n      whiff:  {str(got)[:300]}\n      oracle: {str(want)[:300]}")
        return sum(self.ok.values()) == sum(self.total.values())


def census(v):
    stack, n, deepest = [(v, 0)], 0, 0
    while stack:
        x, d = stack.pop()
        n += 1
        deepest = max(deepest, d)
        if isinstance(x, list):
            stack.extend((y, d + 1) for y in x)
        elif isinstance(x, dict):
            stack.extend((y, d + 1) for y in x.values())
    return n, deepest


def plists(t, files):
    reports = whiff(files)
    for f in files:
        try:
            raw = Path(f).read_bytes()
            v = plistlib.loads(raw)
        except Exception:
            continue
        fmt, sec = reports.get(f, (None, None))
        if sec is None or "encoding" not in sec:
            t.check("plist read", f, fmt, "a plist")
            continue
        t.check("plist read", f, "ok", "ok")
        t.check("plist encoding", f, sec["encoding"], "binary" if raw.startswith(b"bplist00") else "xml")
        top = "dictionary" if isinstance(v, dict) else "array" if isinstance(v, list) else "scalar"
        t.check("plist top level", f, sec.get("top_level"), top)
        n, depth = census(v)
        t.check("plist values and depth", f, (sec.get("values"), sec.get("max_depth")), (n, depth))
        if "keys" in sec and isinstance(v, dict):
            t.check("plist keys", f, sec["keys"], [k[:100] for k in list(v)[:100]])
        if sec.get("kind") == "app_info" and v.get("CFBundleIdentifier"):
            t.check("Info.plist bundle id", f, sec.get("bundle_id"), v["CFBundleIdentifier"])
        if sec.get("kind") == "keyed_archive":
            objs = v.get("$objects", [])
            root = v.get("$top", {}).get("root")
            want = None
            if isinstance(root, plistlib.UID) and isinstance(objs[root.data], dict):
                cls = objs[root.data].get("$class")
                if isinstance(cls, plistlib.UID):
                    want = objs[cls.data].get("$classname")
            t.check("keyed archive", f, (sec.get("objects"), sec.get("root_class")), (len(objs), want))


def plutil_json(f):
    r = subprocess.run(["plutil", "-convert", "json", "-o", "-", f], capture_output=True)
    return json.loads(r.stdout) if r.returncode == 0 else None


def strings(t, files, dicts):
    reports = whiff(files + dicts)
    for f in files:
        v = plutil_json(f)
        if not isinstance(v, dict):
            continue
        sec = (reports.get(f) or (None, None))[1] or {}
        t.check(".strings keys", f, sec.get("keys"), len(v))
    for f in dicts:
        v = plutil_json(f)
        if not isinstance(v, dict):
            continue
        sec = (reports.get(f) or (None, None))[1] or {}
        cats = set()
        for entry in v.values():
            if isinstance(entry, dict):
                for k, var in entry.items():
                    if k != "NSStringLocalizedFormatKey" and isinstance(var, dict):
                        cats |= {c for c in var if c in ("zero", "one", "two", "few", "many", "other")}
        order = ["zero", "one", "two", "few", "many", "other"]
        t.check(".stringsdict", f, (sec.get("keys"), sec.get("plural_categories", [])),
                (len(v), [c for c in order if c in cats]))


def cars(t, files):
    reports = whiff(files)
    for f in files:
        r = subprocess.run(["xcrun", "assetutil", "--info", f], capture_output=True, text=True)
        if r.returncode != 0:
            continue
        try:
            info = json.loads(r.stdout)
        except json.JSONDecodeError:
            continue
        head, entries = info[0], info[1:]
        sec = (reports.get(f) or (None, None))[1] or {}
        # assetutil's Timestamp is not stored in current files (the header field is 0).
        want = (head.get("CoreUIVersion"), head.get("StorageVersion"), head.get("SchemaVersion"),
                head.get("Platform"), head.get("PlatformVersion"))
        got = (sec.get("coreui_version"), sec.get("storage_version"), sec.get("schema_version"),
               sec.get("platform"), sec.get("platform_version"))
        t.check("car header", f, got, want)
        strip = lambda v: v.strip() if isinstance(v, str) else v
        t.check("car versions", f, (sec.get("main_version"), sec.get("asset_storage_version"), sec.get("authoring_tool")),
                tuple(strip(head.get(k)) for k in ("MainVersion", "AssetStorageVersion", "Authoring Tool")))
        # Packed-image atlases are listed as entries but are not assets.
        names = {e["Name"] for e in entries if e.get("Name") and not e["Name"].startswith("ZZZZPackedAsset-")}
        if len(names) <= 200 and sec.get("assets", 0) <= 200:
            t.check("car asset names", f, set(sec.get("names", [])), names)


def profiles(t, files):
    reports = whiff(files)
    for f in files:
        r = subprocess.run(["security", "cms", "-D", "-i", f], capture_output=True)
        if r.returncode != 0:
            continue
        try:
            p = plistlib.loads(r.stdout)
        except Exception:
            continue
        sec = (reports.get(f) or (None, None))[1] or {}
        if "PayloadContent" in p:
            types = Counter(x.get("PayloadType") for x in p["PayloadContent"] if isinstance(x, dict))
            t.check("configuration profile", f, (sec.get("identifier"), sec.get("payload_types")),
                    (p.get("PayloadIdentifier"), dict(types) or None))
            continue
        exp = p.get("ExpirationDate")
        want = (p.get("Name"), (p.get("TeamIdentifier") or [None])[0],
                exp.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if exp else None,
                len(p["ProvisionedDevices"]) if "ProvisionedDevices" in p else None,
                list(p.get("Entitlements", {}))[:100] or None)
        got = (sec.get("name"), sec.get("team_id"), sec.get("expires"), sec.get("provisioned_devices"),
               sec.get("entitlements"))
        t.check("provisioning profile", f, got, want)


def projects(t, files):
    reports = whiff(files)
    for f in files:
        v = plutil_json(f)
        if not isinstance(v, dict):
            continue
        objs = v.get("objects", {})
        targets = sorted(o.get("name", "") for o in objs.values() if o.get("isa") in
                         ("PBXNativeTarget", "PBXAggregateTarget", "PBXLegacyTarget"))[:50]
        configs = sorted({o.get("name") for o in objs.values() if o.get("isa") == "XCBuildConfiguration"})
        sec = (reports.get(f) or (None, None))[1] or {}
        got = (sec.get("objects"), sorted(x.get("name", "") for x in sec.get("targets", [])), sec.get("configurations", []))
        t.check("Xcode project", f, got, (len(objs), targets, configs))


def ds_stores(t, files):
    work = ROOT / "target" / "apple-oracle-ds"
    work.mkdir(parents=True, exist_ok=True)
    copies = []
    for i, f in enumerate(files):
        dst = work / f"{i}.DS_Store"
        dst.write_bytes(Path(f).read_bytes())
        copies.append(str(dst))
    script = (
        "import json,sys\nfrom ds_store import DSStore\nout={}\n"
        "for p in sys.argv[1:]:\n"
        "    try:\n"
        "        with DSStore.open(p,'r') as d:\n"
        "            recs=list(d)\n"
        "        out[p]=[len(recs),sorted({r.filename for r in recs if r.filename!='.'})[:200]]\n"
        "    except Exception as e: out[p]=None\n"
        "print(json.dumps(out))\n")
    rel = [str(Path(c).relative_to(ROOT)) for c in copies]
    r = subprocess.run(["podman", "run", "--rm", "-v", f"{ROOT}:/whiff", "-w", "/whiff", "whiff-binser", "python3", "-I",
                        "-c", script, *rel], capture_output=True, text=True)
    want = json.loads(r.stdout)
    reports = whiff(copies)
    for c, rp in zip(copies, rel):
        if want.get(rp) is None:
            continue
        sec = (reports.get(c) or (None, None))[1] or {}
        t.check(".DS_Store", c, (sec.get("records"), sorted(sec.get("names", []))), tuple(want[rp]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=3000)
    a = ap.parse_args()
    t = Tally()
    fx = ROOT / "tests" / "fixtures"
    fixture = lambda *dirs: [str(p) for d in dirs for p in sorted((fx / d).iterdir()) if p.name != "SOURCE.md"]
    plists(t, fixture("plist", "bplist", "info_plist", "ios_backup_plist", "shortcut")
           + find("*.plist", a.sample) + find("Info.plist", a.sample // 3))
    strings(t, fixture("apple_strings") + find("*.strings", a.sample // 2),
            fixture("stringsdict") + find("*.stringsdict", a.sample // 4))
    cars(t, fixture("car") + find("*.car", a.sample // 6))
    profiles(t, fixture("mobileprovision", "mobileconfig") + find("*.provisionprofile", 100)
             + find("*.mobileprovision", 100) + find("*.mobileconfig", 100))
    projects(t, fixture("pbxproj") + find("*.pbxproj", 100))
    ds_stores(t, find(".DS_Store", 100) + fixture("ds_store"))
    sys.exit(0 if t.report() else 1)


main()
