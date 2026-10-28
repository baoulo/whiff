#!/usr/bin/env python3
"""Compare whiff's executable reports with independent tools.

    exec_oracle.py [--whiff target/debug/whiff] PATH...

PATHs are files or folders (walked). For each file whiff reports in the
`exec` family (or as a .NET assembly), the facts are checked against:

* Mach-O, on macOS: `lipo -archs` (architectures), `otool -hv` (file
  type, PIE), `otool -L` (libraries), `otool -l` (UUID, minimum OS),
  `codesign -dvvv` (identifier, team, first authority, ad hoc, hardened
  runtime) and `codesign -d --entitlements` (entitlement keys);
* in the `whiff-exec` container of executables.sh (files under shared
  folders only), run through this script's `--reference` mode:
  `readelf -h -l -d -n -S -W --dyn-syms` (class, byte order, machine,
  type, entry, sections, interpreter, needed libraries, SONAME, run paths,
  build id, PIE / NX / RELRO, imported symbols), `llvm-readobj
  --file-headers --coff-imports --coff-exports` (machine, sections, entry,
  image base, subsystem, ASLR / DEP / CFG, imported libraries and symbols,
  exports), `osslsigncode verify` (Authenticode signer subject) and
  `wasm-objdump -h` (section counts, custom sections).

Prints one line per mismatch and a summary per format.
"""

import argparse
import collections
import json
import os
import re
import subprocess
import sys

SHARED = ("/Users/", "/private/", "/var/folders/")
EXEC = {"elf", "elf_core", "ebpf", "macho", "pe", "dotnet", "coff", "wasm"}
stats = collections.defaultdict(collections.Counter)


def run(cmd, timeout=120):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def check(fmt, field, path, ref, got):
    stats[fmt][field + " total"] += 1
    if ref == got:
        stats[fmt][field + " ok"] += 1
    else:
        print(f"MISMATCH {fmt} {field} {path}: reference {ref!r}, whiff {got!r}")


# ---------------------------------------------------------------- reference mode (in the container)

ELF_MACHINES = {"AArch64": "arm64", "Advanced Micro Devices X86-64": "x86_64", "Intel 80386": "x86", "ARM": "arm",
                "RISC-V": "riscv", "PowerPC64": "ppc64", "PowerPC": "ppc", "Linux BPF": "bpf", "MIPS R3000": "mips",
                "IBM S/390": "s390", "LoongArch": "loongarch"}
PE_MACHINES = {"AMD64": "x86_64", "I386": "x86", "ARM64": "arm64", "ARMNT": "arm_thumb2", "ARM": "arm"}


def ref_elf(path):
    out = run(["readelf", "-h", "-l", "-d", "-n", "-S", "-W", "--dyn-syms", path])
    if "ELF Header" not in out:
        return None
    r = {}
    g = lambda pat: (re.search(pat, out, re.M) or [None, None])[1]
    r["bits"] = 64 if g(r"Class:\s+ELF(\d+)") == "64" else 32
    r["endianness"] = "little" if "little endian" in (g(r"Data:\s+(.*)$") or "") else "big"
    m = g(r"Machine:\s+(.*)$") or ""
    r["architecture"] = ELF_MACHINES.get(m.strip(), m.strip())
    ty = g(r"Type:\s+(\S+)")
    entry = int(g(r"Entry point address:\s+(0x[0-9a-f]+)") or "0", 16)
    if entry:
        r["entry_point"] = hex(entry)
    n = int(g(r"Number of section headers:\s+(\d+)") or 0)
    if n > 1:
        r["section_count"] = n - 1
    interp = g(r"Requesting program interpreter: ([^\]]+)\]")
    if interp:
        r["interpreter"] = interp
    r["libraries"] = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", out)
    for tag, key in (("SONAME", "soname"), ("RUNPATH", "runpath"), ("RPATH", "rpath")):
        v = g(rf"\({tag}\)\s+Library \w+: \[([^\]]*)\]")
        if v is not None:
            r[key] = v
    bid = g(r"Build ID: ([0-9a-f]+)")
    if bid:
        r["build_id"] = bid
    if ty != "CORE" and ty != "REL":
        stack = re.search(r"^\s+GNU_STACK\s.*\s(R?W?E?)\s+0x[0-9a-f]+$", out, re.M)
        if stack:
            r["nx"] = "E" not in stack.group(1)
        relro = re.search(r"^\s+GNU_RELRO\s", out, re.M) is not None
        now = re.search(r"\((BIND_NOW)\)|\(FLAGS\)\s.*BIND_NOW|\(FLAGS_1\)\s.*\bNOW\b", out) is not None
        r["relro"] = "full" if relro and now else "partial" if relro else "none"
        if ty == "DYN":
            pie = "Position-Independent" in out or re.search(r"\(FLAGS_1\)\s.*\bPIE\b", out) is not None or interp
            r["kind"] = "executable" if pie else "shared_library"
        elif ty == "EXEC":
            r["kind"] = "executable"
    imports = set()
    in_dyn = False
    for line in out.splitlines():
        if line.startswith("Symbol table '.dynsym'"):
            in_dyn = True
            continue
        if in_dyn:
            if not line.strip():
                in_dyn = False
                continue
            f = line.split()
            if len(f) >= 8 and f[6] == "UND":
                imports.add(f[7].split("@")[0])
    if imports:
        r["imported_symbol_count"] = len(imports)
    return r


def ref_pe(path):
    out = run(["llvm-readobj", "--file-headers", "--coff-imports", "--coff-exports", path])
    if "Format: COFF" not in out:
        return None
    r = {}
    g = lambda pat: (re.search(pat, out, re.M) or [None, None])[1]
    m = g(r"Machine: IMAGE_FILE_MACHINE_(\w+)")
    r["architecture"] = PE_MACHINES.get(m, m)
    r["section_count"] = int(g(r"SectionCount: (\d+)") or 0)
    if "ImageOptionalHeader" in out:
        entry = int(g(r"AddressOfEntryPoint: (0x[0-9A-F]+)") or "0", 16)
        if entry:
            r["entry_point"] = hex(entry)
        r["image_base"] = hex(int(g(r"ImageBase: (0x[0-9A-F]+)") or "0", 16))
        stripped = "IMAGE_FILE_RELOCS_STRIPPED" in out
        r["aslr"] = "IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE" in out and not stripped
        r["dep"] = "IMAGE_DLL_CHARACTERISTICS_NX_COMPAT" in out
        r["cfg"] = "IMAGE_DLL_CHARACTERISTICS_GUARD_CF" in out
        libs, symbols = [], 0
        block = None
        for line in out.splitlines():
            s = line.strip()
            if s in ("Import {", "DelayImport {"):
                block = s
            elif s == "}":
                block = None
            elif block == "Import {" and s.startswith("Name: "):
                libs.append(s[6:])
            elif block == "Import {" and s.startswith("Symbol: "):
                symbols += 1
        r["libraries"] = libs
        if symbols:
            r["imported_symbol_count"] = symbols
        exports = len(re.findall(r"^Export \{", out, re.M))
        if exports:
            r["exported_symbol_count"] = exports
        v = run(["osslsigncode", "verify", "-in", path])
        subj = re.search(r"Signer #0:\s*\n\s*Subject: (.*)", v)
        if subj:
            cn = re.search(r"/CN=([^/]*)", subj.group(1))
            r["signer_cn"] = cn.group(1) if cn else None
    return r


WASM_SECTIONS = {"Type": "types", "Import": "imports", "Function": "functions", "Table": "tables",
                 "Memory": "memories", "Global": "globals", "Export": "exports", "Elem": "element_segments",
                 "Code": "function_bodies", "Data": "data_segments", "Tag": "tags"}


def ref_wasm(path):
    out = run(["wasm-objdump", "-h", path])
    if "Sections:" not in out:
        return None
    counts, custom = {}, []
    for line in out.splitlines():
        m = re.match(r"\s*(\w+) start=.*count: (\d+)", line)
        if m and m.group(1) in WASM_SECTIONS:
            counts[WASM_SECTIONS[m.group(1)]] = int(m.group(2))
        m = re.match(r'\s*Custom start=.*"(.*)"', line)
        if m:
            custom.append(m.group(1))
    return {"counts": counts, "custom_sections": custom}


def reference(paths):
    for p in paths:
        kind, path = p.split(":", 1)
        fn = {"elf": ref_elf, "pe": ref_pe, "wasm": ref_wasm}[kind]
        try:
            r = fn(path)
        except Exception as e:  # a tool's odd output must not stop the run
            r = {"error": str(e)}
        print(json.dumps({"path": path, "ref": r}))


# ---------------------------------------------------------------- host mode

def otool_kind(t):
    return {"EXECUTE": "executable", "DYLIB": "shared_library", "BUNDLE": "bundle", "OBJECT": "object",
            "DYLINKER": "dynamic_linker", "KEXTBUNDLE": "kernel_extension", "DSYM": "debug_symbols",
            "CORE": "core", "FILESET": "fileset"}.get(t, t)


def check_macho(path, f):
    arch = f.get("described_architecture") or f.get("architecture")
    lipo_name = {"x86": "i386"}.get(arch, arch)
    archs = run(["lipo", "-archs", path]).split()
    if archs:
        ours = [a["architecture"] for a in f.get("architectures", [])] or [f.get("architecture")]
        check("macho", "architectures", path, sorted(archs), sorted({"x86": "i386"}.get(a, a) for a in ours))
    hv = run(["otool", "-arch", lipo_name, "-hv", path]).splitlines()
    if len(hv) >= 4:
        fields = hv[-1].split()
        if len(fields) >= 5:
            check("macho", "kind", path, otool_kind(fields[4]), f.get("kind"))
            if fields[4] == "EXECUTE":
                check("macho", "pie", path, "PIE" in fields[8:], f.get("hardening", {}).get("pie"))
    libs = run(["otool", "-arch", lipo_name, "-L", path]).splitlines()[1:]
    libs = [l.strip().split(" (compatibility")[0] for l in libs if l.startswith("\t")]
    if f.get("install_name") and libs and libs[0] == f["install_name"]:
        libs = libs[1:]
    if libs or f.get("libraries"):
        check("macho", "library count", path, len(libs), f.get("library_count", 0))
        # whiff lists the first 64, in load order.
        check("macho", "libraries", path, libs[:64], f.get("libraries", []))
    lc = run(["otool", "-arch", lipo_name, "-l", path])
    uuid = re.search(r"^\s+uuid (\S+)", lc, re.M)
    if uuid:
        check("macho", "uuid", path, uuid.group(1), f.get("uuid"))
    minos = re.search(r"^\s+minos (\S+)", lc, re.M) or re.search(r"cmd LC_VERSION_MIN_\w+\n.*\n\s+version (\S+)", lc)
    if minos:
        want = minos.group(1)
        got = f.get("minimum_os")
        if got and want.count(".") == 2 and want.endswith(".0") and got.count(".") == 1:
            want = want[:-2]
        check("macho", "minimum os", path, want, got)
    cs = subprocess.run(["codesign", "-dvvv", "--arch", lipo_name, path], capture_output=True, text=True, errors="replace").stderr
    sig = f.get("signature", {})
    if "Identifier=" in cs:
        check("macho", "identifier", path, re.search(r"^Identifier=(.*)$", cs, re.M).group(1), sig.get("identifier"))
        team = re.search(r"^TeamIdentifier=(.*)$", cs, re.M)
        team = team.group(1) if team else "not set"
        check("macho", "team", path, None if team == "not set" else team, sig.get("team_id"))
        check("macho", "adhoc", path, "Signature=adhoc" in cs, sig.get("adhoc"))
        flags = re.search(r"flags=0x([0-9a-f]+)", cs)
        if flags:
            check("macho", "hardened runtime", path, int(flags.group(1), 16) & 0x10000 != 0,
                  f.get("hardening", {}).get("hardened_runtime"))
        auth = re.search(r"^Authority=(.*)$", cs, re.M)
        if auth:
            check("macho", "signer", path, auth.group(1), sig.get("signer", {}).get("subject_cn"))
        ent = run(["codesign", "-d", "--arch", lipo_name, "--entitlements", "-", "--xml", path])
        keys = re.findall(r"<key>([^<]+)</key>", ent)
        top = []
        depth = 0
        for tok in re.findall(r"<(/?)(dict|key)>([^<]*)", ent):
            close, tag, text = tok
            if tag == "dict":
                depth += -1 if close else 1
            elif not close and depth == 1:
                top.append(text)
        if keys:
            check("macho", "entitlements", path, sorted(top)[:64], sorted(sig.get("entitlements", [])))


def compare(kind, fmt, path, f, ref):
    if not ref:
        return
    if kind == "wasm":
        check(fmt, "section counts", path, ref["counts"], {k: v for k, v in f.get("counts", {}).items()})
        check(fmt, "custom sections", path, ref["custom_sections"][:64], f.get("custom_sections", []))
        return
    hard = f.get("hardening", {})
    for key, ref_v in ref.items():
        if key in ("nx", "relro", "aslr", "dep", "cfg"):
            got = hard.get(key)
        elif key == "signer_cn":
            got = f.get("signature", {}).get("signer", {}).get("subject_cn")
        elif key == "libraries":
            got = f.get("libraries", [])
            ref_v = ref_v[:64]
        else:
            got = f.get(key)
        if key == "kind" and fmt == "elf_core":
            continue
        check(fmt, key.replace("_", " "), path, ref_v, got)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--reference":
        reference(sys.argv[2:])
        return
    ap = argparse.ArgumentParser()
    ap.add_argument("--whiff", default="target/debug/whiff")
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args()
    files = []
    for p in a.paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                files += [os.path.join(root, n) for n in names if n != "SOURCE.md"]
        elif os.path.isfile(p):
            files.append(os.path.abspath(p))
    pending = {}
    for path in sorted(files):
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        out = run([a.whiff, "--jsonl", path])
        try:
            report = json.loads(out.splitlines()[0])
        except (ValueError, IndexError):
            continue
        fmt = report["identification"]["format"]
        if fmt not in EXEC:
            continue
        f = report.get("format", {}).get(fmt, {})
        stats[fmt]["files"] += 1
        for d in report.get("diagnostics", {}).get("extractors", []):
            if d.get("status") not in ("ok", None) and d["id"].startswith("exec."):
                print(f"ERROR {fmt} {path}: {d.get('status')} {d.get('error', '')}")
                stats[fmt]["errors"] += 1
        if fmt == "macho":
            if sys.platform == "darwin":
                check_macho(path, f)
            continue
        kind = {"elf": "elf", "elf_core": "elf", "ebpf": "elf", "pe": "pe", "dotnet": "pe", "coff": "pe", "wasm": "wasm"}[fmt]
        if os.path.abspath(path).startswith(SHARED):
            pending[os.path.abspath(path)] = (kind, fmt, f)
    if pending:
        root = os.path.commonpath(list(pending))
        root = root if os.path.isdir(root) else os.path.dirname(root)
        here = os.path.dirname(os.path.abspath(__file__))
        args = [f"{k}:/d/{os.path.relpath(p, root)}" for p, (k, _, _) in pending.items()]
        out = ""
        for i in range(0, len(args), 400):
            out += run(["podman", "run", "--rm", "-v", f"{root}:/d:ro", "-v", f"{here}:/s:ro", "whiff-exec",
                        "python3", "/s/exec_oracle.py", "--reference", *args[i:i + 400]], timeout=1800)
        for line in out.splitlines():
            r = json.loads(line)
            p = os.path.join(root, r["path"][3:])
            kind, fmt, f = pending[p]
            compare(kind, fmt, p, f, r["ref"])
    print()
    for fmt in sorted(stats):
        s = stats[fmt]
        parts = [f"files {s['files']}"] + ([f"errors {s['errors']}"] if s["errors"] else [])
        for k in sorted(k[:-6] for k in s if k.endswith(" total")):
            parts.append(f"{k} {s[k + ' ok']}/{s[k + ' total']}")
        print(f"{fmt:10} " + ", ".join(parts))


if __name__ == "__main__":
    main()
