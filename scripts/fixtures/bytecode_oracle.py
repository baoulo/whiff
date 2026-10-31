#!/usr/bin/env python3
"""Compare whiff's bytecode extractors with reference tools.

    bytecode_oracle.py collect DIR...   copy a corpus into target/bytecode-corpus/
    bytecode_oracle.py check [KIND...]  compare whiff with the references

Kinds and their references:
* class   javap -v (the host JDK): version, class, superclass,
          interfaces, source file, field and method counts;
* pyc     CPython's own marshal and dis, run by the matching python:X-slim
          image: source file, imports, top-level definitions;
* beam    beam_lib (OTP 28, image erlang:28-slim): module, exports, imported
          modules, vsn, behaviours, compiler version;
* dotnet  dnfile (pure Python, installed into a python:3.12-slim
          container): assembly name, version, culture, public-key token,
          references, P/Invoke modules, type and method counts;
* luac    the Lua version byte and luac -l (Lua 5.4) for the source name.

The corpus is copied (never committed) from system folders, /Applications
and Homebrew, since podman mounts only the home folder. Files are only
read: marshal.loads builds code objects without running them, and
beam_lib reads chunks.
"""

import json
import os
import random
import shutil
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CORPUS = os.path.join(ROOT, "target", "bytecode-corpus")
WHIFF = os.path.join(ROOT, "target", "debug", "whiff")
MAX = {"pyc": 4000, "beam": 4000, "class": 3000, "dotnet": 800, "luac": 100}


def collect(dirs):
    random.seed(7)
    found = defaultdict(list)
    for d in dirs:
        for base, subdirs, files in os.walk(d):
            if base.startswith(("/System/Volumes", "/Users")):
                subdirs[:] = []
                continue
            for f in files:
                p = os.path.join(base, f)
                ext = f.rsplit(".", 1)[-1].lower()
                if ext in ("pyc", "beam", "luac", "jar") or (ext == "dll" and base.startswith("/Applications")):
                    found[ext].append(p)
    for kind in ("pyc", "beam", "luac", "dll", "jar"):
        out = os.path.join(CORPUS, "class" if kind == "jar" else "dotnet" if kind == "dll" else kind)
        os.makedirs(out, exist_ok=True)
        paths = sorted(found[kind])
        random.shuffle(paths)
        n = 0
        for p in paths:
            if kind == "jar":
                n += classes_from_jar(p, out, n)
                if n >= MAX["class"]:
                    break
                continue
            if kind == "dll" and not is_dotnet(p):
                continue
            ext = "dll" if kind == "dll" else kind
            try:
                shutil.copyfile(p, os.path.join(out, f"{n:05d}.{ext}"))
            except OSError:
                continue
            n += 1
            if n >= MAX["dotnet" if kind == "dll" else kind]:
                break
        print(f"{kind}: {n} files", file=sys.stderr)


def classes_from_jar(path, out, start):
    try:
        with zipfile.ZipFile(path) as z:
            names = [i for i in z.namelist() if i.endswith(".class")][:8]
            for i, name in enumerate(names):
                with open(os.path.join(out, f"{start + i:05d}.class"), "wb") as f:
                    f.write(z.read(name))
            return len(names)
    except (zipfile.BadZipFile, OSError, KeyError, NotImplementedError):
        return 0


def is_dotnet(path):
    try:
        with open(path, "rb") as f:
            h = f.read(4096)
        if h[:2] != b"MZ":
            return False
        pe = int.from_bytes(h[0x3C:0x40], "little")
        opt = pe + 24
        magic = int.from_bytes(h[opt : opt + 2], "little")
        dirs = opt + (96 if magic == 0x10B else 112)
        return int.from_bytes(h[dirs + 14 * 8 + 4 : dirs + 14 * 8 + 8], "little") >= 72
    except OSError:
        return False


def whiff(files):
    out = {}
    for i in range(0, len(files), 500):
        r = subprocess.run([WHIFF, "--jsonl", *files[i : i + 500]], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            rep = json.loads(line)
            out[rep["source"]["name"]] = rep
    return out


def fmt(rep, key):
    """The report's format section for `key` (empty when another format won)."""
    return rep.get("format", {}).get(key, {})


def podman(image, script, *args):
    r = subprocess.run(
        ["podman", "run", "--rm", "-v", f"{CORPUS}:/c", "-w", "/c", image, *script, *args],
        capture_output=True,
        text=True,
        errors="replace",
    )
    return r.stdout


def report(kind, total, bad):
    print(f"{kind}: {total} compared, {total - len(bad)} agree")
    for name, diffs in bad[:15]:
        print(f"  {name}: {diffs}")
    c = Counter(k for _, d in bad for k in d)
    if c:
        print("  by field:", dict(c))


def check_class():
    d = os.path.join(CORPUS, "class")
    files = sorted(os.listdir(d))
    ours = whiff([os.path.join(d, f) for f in files])
    bad, total = [], 0
    for i in range(0, len(files), 200):
        batch = files[i : i + 200]
        r = subprocess.run(["javap", "-v", *[os.path.join(d, f) for f in batch]], capture_output=True, text=True)
        for block in r.stdout.split("Classfile ")[1:]:
            name = os.path.basename(block.split("\n", 1)[0].strip())
            ref = javap_facts(block)
            got = fmt(ours.get(name, {}), "class")
            if not ref or not got:
                continue
            total += 1
            diffs = {}
            for k in ("version", "class_name", "super_class", "source_file", "fields", "methods", "interfaces"):
                a, b = ref.get(k), got.get(k)
                if k == "interfaces":
                    b = len(b or [])
                if a != b:
                    diffs[k] = (a, b)
            if diffs:
                bad.append((name, diffs))
    report("class", total, bad)


def javap_facts(block):
    facts = {"fields": 0, "methods": 0, "interfaces": []}
    for line in block.splitlines():
        s = line.strip()
        if s.startswith("minor version:"):
            minor = s.split(":")[1].strip()
        elif s.startswith("major version:"):
            facts["version"] = f"{s.split(':')[1].strip()}.{minor}"
        elif s.startswith("this_class:"):
            facts["class_name"] = s.split("//")[-1].strip().strip('"').replace("/", ".")
        elif s.startswith("super_class:"):
            sup = s.split("//")[-1].strip().replace("/", ".")
            if sup not in ("java.lang.Object", "java.lang.Record", "java.lang.Enum") and "#0" not in s:
                facts["super_class"] = sup
        elif s.startswith("interfaces:"):
            parts = dict(p.strip().split(": ") for p in s.split(","))
            facts["_counts"] = parts
        elif s.startswith('SourceFile: "'):
            facts["source_file"] = s.split('"')[1]
    c = facts.pop("_counts", None)
    if not c or "version" not in facts:
        return None
    facts["fields"], facts["methods"] = int(c["fields"]), int(c["methods"])
    # javap -v lists interfaces by index only: compare their number.
    facts["interfaces"] = int(c["interfaces"])
    if facts.get("class_name", "").endswith("module-info"):
        return None
    return facts


PYC_REF = r"""
import dis, json, marshal, sys, types
out = {}
for f in sys.argv[1:]:
    try:
        b = open(f, "rb").read()
        code = marshal.loads(b[16:])
    except Exception as e:
        continue
    imports, defs, seen = [], [], [code]
    while seen:
        c = seen.pop()
        for ins in dis.get_instructions(c):
            if ins.opname == "IMPORT_NAME" and ins.argval not in imports:
                imports.append(ins.argval)
        for k in c.co_consts:
            if isinstance(k, types.CodeType):
                seen.append(k)
                if c is code and not k.co_name.startswith("<"):
                    defs.append(getattr(k, "co_qualname", k.co_name))
    out[f] = {"source_file": code.co_filename, "imports": imports[:64], "definitions": defs[:64]}
print(json.dumps(out))
"""


def check_pyc():
    d = os.path.join(CORPUS, "pyc")
    files = sorted(os.listdir(d))
    ours = whiff([os.path.join(d, f) for f in files])
    by_version = defaultdict(list)
    for f in files:
        v = fmt(ours.get(f, {}), "pyc").get("python_version")
        if v and tuple(map(int, v.split("."))) >= (3, 8):
            by_version[v].append(f)
    bad, total = [], 0
    for v, group in sorted(by_version.items()):
        ref = {}
        for i in range(0, len(group), 400):
            out = podman(f"docker.io/library/python:{v}-slim", ["python3", "-I", "-c", PYC_REF], *[f"pyc/{f}" for f in group[i : i + 400]])
            ref.update(json.loads(out or "{}"))
        for f in group:
            r = ref.get(f"pyc/{f}")
            if r is None:
                continue
            total += 1
            got = fmt(ours[f], "pyc")
            # Strict privacy (the default) keeps only the file name.
            r["source_file"] = r["source_file"].replace("\\", "/").rsplit("/", 1)[-1]
            diffs = {k: (r[k], got.get(k, [] if k != "source_file" else None)) for k in r if r[k] != got.get(k, [] if k != "source_file" else None)}
            if diffs:
                bad.append((f"{f} ({v})", diffs))
    report("pyc", total, bad)


BEAM_REF = r"""
main(Files) ->
    lists:foreach(fun(F) ->
        case beam_lib:chunks(F, [exports, imports, attributes, compile_info]) of
            {ok, {M, [{exports, E}, {imports, I}, {attributes, A}, {compile_info, C}]}} ->
                Ex = [io_lib:format("~s/~p", [N, Ar]) || {N, Ar} <- E, {N, Ar} =/= {module_info, 0}, {N, Ar} =/= {module_info, 1}],
                Mods = lists:usort([atom_to_list(Mo) || {Mo, _, _} <- I, Mo =/= erlang]),
                Vsn = case lists:keyfind(vsn, 1, A) of {vsn, [V | _]} when is_atom(V) -> atom_to_list(V); {vsn, [V | _]} when is_integer(V) -> integer_to_list(V); {vsn, [V | _]} when is_list(V) -> V; _ -> "" end,
                Beh = [atom_to_list(B) || {K, Bs} <- A, K == behaviour orelse K == behavior, B <- Bs],
                Ver = case lists:keyfind(version, 1, C) of {version, Vv} -> Vv; _ -> "" end,
                io:format("~s\t~s\t~s\t~s\t~s\t~s\t~s~n", [F, M, string:join(lists:sort([lists:flatten(X) || X <- Ex]), ","), string:join(Mods, ","), Vsn, string:join(Beh, ","), Ver]);
            _ -> ok
        end
    end, Files).
"""


def check_beam():
    d = os.path.join(CORPUS, "beam")
    files = sorted(os.listdir(d))
    ours = whiff([os.path.join(d, f) for f in files])
    with open(os.path.join(CORPUS, "ref.escript"), "w") as f:
        f.write("#!/usr/bin/env escript\n" + BEAM_REF)
    ref = {}
    for i in range(0, len(files), 1000):
        out = podman("docker.io/library/erlang:28-slim", ["escript", "ref.escript"], *[f"beam/{f}" for f in files[i : i + 1000]])
        for line in out.splitlines():
            p = line.split("\t")
            if len(p) == 7:
                ref[os.path.basename(p[0])] = p[1:]
    bad, total = [], 0
    for f in files:
        if f not in ref:
            continue
        total += 1
        module, exports, mods, vsn, beh, ver = ref[f]
        got = fmt(ours.get(f, {}), "beam")
        diffs = {}
        if got.get("module") != module:
            diffs["module"] = (module, got.get("module"))
        exp = sorted(got.get("exports", []))
        ref_exp = sorted(exports.split(",")) if exports else []
        if exp != ref_exp[: len(exp)] or (len(ref_exp) <= 64 and exp != ref_exp):
            if len(ref_exp) <= 64:
                diffs["exports"] = (len(ref_exp), len(exp))
        rm = mods.split(",") if mods else []
        if (got.get("imported_modules") or []) != rm[:64]:
            diffs["imported_modules"] = (rm[:5], (got.get("imported_modules") or [])[:5])
        # A module without -vsn gets its MD5 as a number; whiff leaves it out.
        if vsn and not vsn.isdigit() and got.get("vsn") != vsn:
            diffs["vsn"] = (vsn, got.get("vsn"))
        if (got.get("behaviours") or []) != (beh.split(",") if beh else []):
            diffs["behaviours"] = (beh, got.get("behaviours"))
        if ver and got.get("compiler_version") != ver:
            diffs["compiler_version"] = (ver, got.get("compiler_version"))
        if diffs:
            bad.append((f, diffs))
    report("beam", total, bad)


DOTNET_REF = r"""
import hashlib, json, sys, dnfile
out = {}
for f in sys.argv[1:]:
    try:
        pe = dnfile.dnPE(f)
        t = pe.net.mdtables
    except Exception:
        continue
    if t is None:
        continue
    r = {}
    if t.Assembly and t.Assembly.num_rows:
        a = t.Assembly.rows[0]
        r["name"] = str(a.Name)
        r["version"] = f"{a.MajorVersion}.{a.MinorVersion}.{a.BuildNumber}.{a.RevisionNumber}"
        r["culture"] = str(a.Culture) or "neutral"
        key = a.PublicKey.value if a.PublicKey else b""
        r["token"] = hashlib.sha1(key).digest()[-8:][::-1].hex() if key else None
    r["refs"] = [f"{x.Name} {x.MajorVersion}.{x.MinorVersion}.{x.BuildNumber}.{x.RevisionNumber}" for x in (t.AssemblyRef.rows if t.AssemblyRef else [])][:64]
    r["modules"] = [str(x.Name) for x in (t.ModuleRef.rows if t.ModuleRef else [])][:64]
    r["types"] = max((t.TypeDef.num_rows if t.TypeDef else 0) - 1, 0)
    r["methods"] = t.MethodDef.num_rows if t.MethodDef else 0
    out[f] = r
print(json.dumps(out))
"""


def check_dotnet():
    d = os.path.join(CORPUS, "dotnet")
    files = sorted(os.listdir(d))
    ours = whiff([os.path.join(d, f) for f in files])
    with open(os.path.join(CORPUS, "ref_dotnet.py"), "w") as f:
        f.write(DOTNET_REF)
    ref = {}
    for i in range(0, len(files), 200):
        out = podman(
            "docker.io/library/python:3.12-slim",
            ["sh", "-c", 'pip install -q dnfile==0.15.1 2>/dev/null && python3 -I ref_dotnet.py "$@"', "sh"],
            *[f"dotnet/{f}" for f in files[i : i + 200]],
        )
        ref.update(json.loads(out.strip().splitlines()[-1] if out.strip() else "{}"))
    bad, total = [], 0
    for f in files:
        r = ref.get(f"dotnet/{f}")
        if r is None:
            continue
        total += 1
        net = fmt(ours.get(f, {}), "dotnet").get("dotnet", {})
        a = net.get("assembly", {})
        counts = net.get("counts", {})
        got = {
            "name": a.get("name"),
            "version": a.get("version"),
            "culture": a.get("culture"),
            "token": a.get("public_key_token"),
            "refs": net.get("assembly_references", []),
            "modules": net.get("native_modules", []),
            "types": counts.get("types"),
            "methods": counts.get("methods"),
        }
        diffs = {k: (r.get(k), got[k]) for k in got if k in r and r.get(k) != got[k]}
        if diffs:
            bad.append((f, diffs))
    report("dotnet", total, bad)


def check_luac():
    d = os.path.join(CORPUS, "luac")
    files = sorted(os.listdir(d))
    ours = whiff([os.path.join(d, f) for f in files])
    bad, total = [], 0
    for f in files:
        with open(os.path.join(d, f), "rb") as fh:
            h = fh.read(5)
        got = fmt(ours.get(f, {}), "luac")
        total += 1
        if h[:4] == b"\x1bLua":
            want = f"{h[4] >> 4}.{h[4] & 15}"
            if got.get("lua_version") != want:
                bad.append((f, {"lua_version": (want, got.get("lua_version"))}))
                continue
            if want == "5.4":
                r = subprocess.run(["luac", "-l", "-p", os.path.join(d, f)], capture_output=True, text=True)
                line = r.stdout.split("\n", 2)[1] if r.stdout.count("\n") > 1 else ""
                src = line.split("<", 1)[-1].split(":", 1)[0] if line.startswith("main <") else None
                if src in ("?", "=?"):
                    src = None
                want_src = src.lstrip("@=") if src else None
                if got.get("source") != want_src and not (want_src is None and got.get("stripped")):
                    bad.append((f, {"source": (want_src, got.get("source"))}))
        elif h[:3] == b"\x1bLJ":
            if got.get("implementation") != "LuaJIT":
                bad.append((f, {"implementation": ("LuaJIT", got.get("implementation"))}))
    report("luac", total, bad)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "collect":
        collect(sys.argv[2:])
        return
    kinds = sys.argv[2:] or ["class", "pyc", "beam", "dotnet", "luac"]
    for k in kinds:
        globals()[f"check_{k}"]()


if __name__ == "__main__":
    main()
