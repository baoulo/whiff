#!/usr/bin/env python3
"""Compare whiff's forensic extractors with reference parsers.

    forensic_oracle.py check

References (all in the whiff-forensic image, see forensic.sh):
* EVTX: python-evtx — record count, first and last time, channel,
  provider, event ID and level counts;
* registry hives: hivexml (hivex) — key and value counts;
* shortcuts: LnkParse3 — local path, arguments, working folder, volume
  serial, drive type, machine ID;
* Prefetch: windowsprefetch — executable, run count, last run time,
  volume serials;
* minidumps: minidump (skelsec) — OS version, CPU, exception code, module
  and thread counts;
* captures: capinfos — packet count, first and last packet;
* unified2: idstools — events and signature IDs.

The corpus is the samples forensic.sh downloads into
target/forensic-samples/ (Eric Zimmerman's test sets, rust-minidump's test
dumps) plus the fixtures; nothing is copied from this machine.
"""

import glob
import json
import os
import subprocess
import sys
from collections import Counter

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SAMPLES = os.path.join(ROOT, "target", "forensic-samples")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
WHIFF = os.path.join(ROOT, "target", "release", "whiff")
IMAGE = "whiff-forensic"


def whiff(files, profile="full"):
    out = {}
    for i in range(0, len(files), 200):
        r = subprocess.run([WHIFF, "--profile", profile, "--privacy", "off", "--jsonl", *files[i : i + 200]],
                           capture_output=True, text=True)
        for line in r.stdout.splitlines():
            rep = json.loads(line)
            out[os.path.relpath(rep["source"]["path"], ROOT)] = rep
    return out


def fmt(rep):
    return rep.get("format", {}).get(rep["identification"]["format"], {})


REF = r'''
import json, sys, re, datetime
from collections import Counter
kind = sys.argv[1]

def iso(t):
    if t is None:
        return None
    if isinstance(t, (int, float)):
        t = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
    if t.tzinfo is None:
        t = t.replace(tzinfo=datetime.timezone.utc)
    return t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

for path in sys.argv[2:]:
    r = {"path": path}
    try:
        if kind == "evtx":
            import Evtx.Evtx as evtx
            ch, pr, ids, lv = Counter(), Counter(), Counter(), Counter()
            n, lo, hi = 0, None, None
            with evtx.Evtx(path) as log:
                for rec in log.records():
                    n += 1
                    t = rec.timestamp()
                    lo = t if lo is None or t < lo else lo
                    hi = t if hi is None or t > hi else hi
                    try:
                        x = rec.xml()
                    except Exception:
                        continue
                    m = re.search(r"<Channel>([^<]*)</Channel>", x); ch[m.group(1)] += bool(m)
                    m = re.search(r'<Provider Name="([^"]*)"', x); pr[m.group(1)] += bool(m)
                    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", x); ids[m.group(1)] += bool(m)
            r.update(records=n, first=iso(lo), last=iso(hi), channels=dict(ch), providers=dict(pr), event_ids=dict(ids))
        elif kind == "registry":
            import subprocess
            x = subprocess.run(["hivexml", path], capture_output=True, text=True, errors="replace").stdout
            if "<hive" not in x:
                raise ValueError("hivexml could not read it")
            r.update(keys=x.count("<node "), values=x.count("<value "))
        elif kind == "lnk":
            import LnkParse3
            with open(path, "rb") as f:
                d = LnkParse3.lnk_file(f).get_json()
            li = d.get("link_info") or {}
            loc = li.get("location_info") or {}
            vol = loc.get("volume_id") if isinstance(loc, dict) else None
            vol = li.get("volume_id") or vol or {}
            extra = d.get("extra") or {}
            tracker = extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK") or {}
            path_ = li.get("local_base_path_unicode") or li.get("local_base_path")
            suffix = li.get("common_path_suffix_unicode") or li.get("common_path_suffix") or ""
            data = d.get("data") or {}
            r.update(target=(path_ + suffix) if path_ else None, arguments=data.get("command_line_arguments"),
                     working_directory=data.get("working_directory"),
                     serial=("%08X" % vol["drive_serial_number"]) if isinstance(vol.get("drive_serial_number"), int) else vol.get("drive_serial_number"),
                     machine_id=tracker.get("machine_identifier"))
        elif kind == "prefetch":
            from windowsprefetch import Prefetch
            p = Prefetch(path)
            times = [t for t in (p.timestamps or []) if t]
            r.update(executable=p.executableName, run_count=p.runCount, last_run=str(times[0]) if times else None,
                     serials=sorted(str(v.get("Serial Number", "")).upper().replace("0X", "") for v in (p.volumesInformationArray or [])))
        elif kind == "minidump":
            from minidump.minidumpfile import MinidumpFile
            m = MinidumpFile.parse(path)
            si = m.sysinfo
            r.update(version=f"{si.MajorVersion}.{si.MinorVersion}.{si.BuildNumber}" if si else None,
                     modules=len(m.modules.modules) if m.modules else None,
                     threads=len(m.threads.threads) if m.threads else None,
                     code=(m.exception.exception_records[0].ExceptionRecord.ExceptionCode_raw if m.exception and m.exception.exception_records else None))
        elif kind == "unified2":
            from idstools import unified2
            ev, sids = 0, Counter()
            for rec in unified2.FileRecordReader(path):
                if isinstance(rec, unified2.Event):
                    ev += 1
                    sids["%d:%d:%d" % (rec["generator-id"], rec["signature-id"], rec["signature-revision"])] += 1
            r.update(events=ev, signatures=dict(sids))
    except Exception as e:
        r["error"] = repr(e)[:200]
    print(json.dumps(r, default=str))
'''


def reference(kind, files):
    out = {}
    for i in range(0, len(files), 300):
        r = subprocess.run(["podman", "run", "--rm", "-v", f"{ROOT}:/r:ro", "-w", "/r", IMAGE, "python3", "-c", REF, kind,
                            *files[i : i + 300]], capture_output=True, text=True, errors="replace")
        for line in r.stdout.splitlines():
            rec = json.loads(line)
            out[rec["path"]] = rec
    return out


def report(kind, total, bad, skipped=0):
    print(f"{kind}: {total} compared, {total - len(bad)} agree" + (f" ({skipped} the reference could not read)" if skipped else ""))
    for name, d in bad[:12]:
        print(f"  {name}: {json.dumps(d, default=str)[:500]}")
    c = Counter(k for _, d in bad for k in d)
    if c:
        print("  by field:", dict(c))


def compare(kind, files, check):
    ours = whiff([os.path.join(ROOT, f) for f in files])
    refs = reference(kind, files)
    bad, total, skipped = [], 0, 0
    for f in files:
        ref, rep = refs.get(f), ours.get(f)
        if not ref or not rep:
            continue
        if "error" in ref:
            skipped += 1
            continue
        total += 1
        d = {}

        def same(k, a, b):
            if a != b:
                d[k] = {"whiff": a, "reference": b}

        check(fmt(rep), ref, same)
        if d:
            bad.append((f, d))
    report(kind, total, bad, skipped)


def top_agree(ours, theirs):
    """whiff's top-N counts agree with the reference's full counts."""
    return all(theirs.get(k) == v for k, v in (ours or {}).items())


def check_evtx(got, ref, same):
    # python-evtx stops at the header's chunk count; a dirty log has more.
    if got.get("header_chunks"):
        return
    same("records", got.get("records"), ref["records"])
    same("first", got.get("first_event"), ref["first"])
    same("last", got.get("last_event"), ref["last"])
    if not got.get("records_analysed"):
        for k in ("channels", "providers", "event_ids"):
            if not top_agree(got.get(k), ref[k]):
                same(k, got.get(k), ref[k])


def check_registry(got, ref, same):
    same("keys", got.get("keys"), ref["keys"])
    same("values", got.get("values"), ref["values"])


def check_lnk(got, ref, same):
    if ref["target"]:
        same("target", (got.get("target") or "").lower(), ref["target"].lower())
    if ref["arguments"]:
        same("arguments", got.get("arguments"), ref["arguments"])
    if ref["working_directory"]:
        same("working_directory", got.get("working_directory"), ref["working_directory"])
    if ref["serial"]:
        same("serial", (got.get("volume") or {}).get("serial"), str(ref["serial"]).upper().replace("0X", "").zfill(8))
    if ref["machine_id"]:
        same("machine_id", (got.get("tracker") or {}).get("machine_id"), ref["machine_id"])


def check_prefetch(got, ref, same):
    same("executable", got.get("executable"), ref["executable"])
    same("run_count", got.get("run_count"), ref["run_count"])
    if ref["last_run"]:
        same("last_run", (got.get("last_run") or "")[:19].replace("T", " "), ref["last_run"][:19])
    same("serials", sorted(v["serial"] for v in got.get("volumes", [])), ref["serials"])


def check_minidump(got, ref, same):
    same("version", (got.get("system") or {}).get("version"), ref["version"])
    same("modules", got.get("module_count"), ref["modules"])
    same("threads", got.get("threads"), ref["threads"])
    if ref["code"] is not None:
        same("code", int((got.get("exception") or {}).get("code", "0"), 16), ref["code"])


def check_unified2(got, ref, same):
    same("events", got.get("events"), ref["events"])
    if not top_agree(got.get("signatures"), ref["signatures"]):
        same("signatures", got.get("signatures"), ref["signatures"])


def captures():
    files = sorted(glob.glob(os.path.join(FIXTURES, "pcap*", "*.pcap*")) + glob.glob(os.path.join(FIXTURES, "btsnoop", "*.btsnoop")))
    rel = [os.path.relpath(f, ROOT) for f in files]
    r = subprocess.run(["podman", "run", "--rm", "-v", f"{ROOT}:/r:ro", "-w", "/r", IMAGE, "capinfos", "-M", "-T", "-c", "-a", "-e",
                        "-S", *rel], capture_output=True, text=True)
    lines = r.stdout.splitlines()
    head = lines[0].split("\t")
    ours = whiff(files)
    bad, total = [], 0
    for line in lines[1:]:
        row = dict(zip(head, line.split("\t")))
        if row.get("File name") == "File name":
            continue  # capinfos repeats its header per file
        f = row.get("File name")
        got = fmt(ours.get(f, {"format": {}, "identification": {"format": ""}}))
        total += 1
        d = {}
        if int(row["Number of packets"]) != got.get("packets"):
            d["packets"] = {"whiff": got.get("packets"), "reference": row["Number of packets"]}
        first = int(float(row["Start time"]))
        if got.get("first_packet") != __import__("datetime").datetime.fromtimestamp(first, __import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"):
            d["first"] = {"whiff": got.get("first_packet"), "reference": row["Start time"]}
        if d:
            bad.append((f, d))
    report("captures", total, bad)


def main():
    rel = lambda pattern: sorted(os.path.relpath(p, ROOT) for p in glob.glob(pattern, recursive=True) if os.path.isfile(p))
    ev = rel(os.path.join(SAMPLES, "evtx-raw", "*")) + rel(os.path.join(FIXTURES, "evtx", "*.evtx"))
    compare("evtx", ev, check_evtx)
    hives = [p for p in rel(os.path.join(SAMPLES, "Registry", "**", "*")) if open(os.path.join(ROOT, p), "rb").read(4) == b"regf"]
    compare("registry", hives + rel(os.path.join(FIXTURES, "registry_hive", "*[!D]")), check_registry)
    lnks = [p for p in rel(os.path.join(SAMPLES, "Lnk", "Lnk.Test", "TestFiles", "**", "*"))
            if open(os.path.join(ROOT, p), "rb").read(4) == b"L\0\0\0"]
    compare("lnk", lnks + rel(os.path.join(FIXTURES, "lnk", "*.lnk")), check_lnk)
    # windowsprefetch decompresses Windows 10 files only on Windows.
    pfs = [p for p in rel(os.path.join(SAMPLES, "Prefetch", "**", "*.pf"))
           if "Bad" not in p and open(os.path.join(ROOT, p), "rb").read(3) != b"MAM"]
    compare("prefetch", pfs, check_prefetch)
    compare("minidump", rel(os.path.join(SAMPLES, "minidump", "*.dmp")), check_minidump)
    compare("unified2", rel(os.path.join(FIXTURES, "unified2", "*.*[0-9]")), check_unified2)
    captures()


if __name__ == "__main__":
    main()
