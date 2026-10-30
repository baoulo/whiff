"""Compare whiff's binary-serialisation reports with the reference libraries.

    podman run --rm -v "$PWD:/whiff" -w /whiff whiff-binser \
        python3 -I scripts/fixtures/binser_oracle.py generate target/binser-oracle
    python3 scripts/fixtures/binser_oracle.py check target/binser-oracle

`generate` (in the `whiff-binser` container) writes random documents with
each format's own library (msgpack, cbor2, bson, py-ubjson, amazon.ion
binary and text, bencode.py, nbtlib, PHP serialize, edn_format), random
pickles (protocols 0–5), Avro containers (fastavro), protobuf messages
(protoc --encode), torrents (mktorrent) and Java streams (OpenJDK), and
records what each library says they hold: the document count, top-level
keys and every schema path with its type (as whiff names them), pickle
globals (an Unpickler that records `find_class`), Avro schema and record
count, protobuf field numbers (protoc --decode_raw), torrent info hashes,
Java class names (javaobj). It also decodes the fixtures. `check` (on the
host) runs whiff and compares.
"""

import json
import random
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WHIFF = ROOT / "target" / "lint" / "debug" / "whiff"
FX = ROOT / "tests" / "fixtures"


# ---------------------------------------------------------------- schema paths

def escape(k):
    if k and all(c.isalnum() or c in "_-" for c in k):
        return k
    return "[" + json.dumps(k, ensure_ascii=False) + "]"


def jtype(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return "string"  # bytes, dates, ids … are placeholders or text


def paths(doc):
    """{path: set(types)} as whiff's schema inference names them."""
    out = {}
    stack = [("$", doc, 0)]
    while stack:
        p, v, d = stack.pop()
        out.setdefault(p, set()).add(jtype(v))
        if isinstance(v, list) and d < 12:
            stack.extend((p + "[]", x, d + 1) for x in v[:200])
        elif isinstance(v, dict) and d < 12:
            stack.extend((f"{p}.{escape(str(k))}", x, d + 1) for k, x in v.items())
    return {k: sorted(t) for k, t in out.items()}


def expect(docs):
    first = docs[0]
    merged = {}
    for d in docs[:1000]:
        for k, t in paths(d).items():
            merged.setdefault(k, set()).update(t)
    return {"documents": len(docs), "keys": [str(k) for k in first][:50] if isinstance(first, dict) else None,
            "paths": {k: sorted(v) for k, v in merged.items()}}


# ---------------------------------------------------------------- generate

WORDS = ["harbour", "berth", "gauge", "tide", "pier", "buoy", "pilot", "level", "chart", "vessel", "quay", "lock"]


def rand_scalar(r, kinds):
    k = r.choice(kinds)
    return {"int": lambda: r.randint(-10**6, 10**6), "float": lambda: round(r.uniform(-1e4, 1e4), 3) + 0.5,
            "str": lambda: r.choice(WORDS) + str(r.randint(0, 99)), "bool": lambda: r.random() < 0.5,
            "none": lambda: None}[k]()


def rand_doc(r, depth=0, kinds=("int", "float", "str", "bool", "none"), keys=None):
    d = {}
    for _ in range(r.randint(1, 6)):
        key = keys(r) if keys else r.choice(WORDS) + ("" if r.random() < 0.7 else str(r.randint(0, 9)))
        roll = r.random()
        if roll < 0.15 and depth < 3:
            d[key] = rand_doc(r, depth + 1, kinds, keys)
        elif roll < 0.3 and depth < 3:
            n = r.randint(0, 4)
            d[key] = [rand_scalar(r, kinds) if r.random() < 0.7 else rand_doc(r, depth + 1, kinds, keys) for _ in range(n)]
        else:
            d[key] = rand_scalar(r, kinds)
    return d


def generate(out):
    import bencode
    import bson
    import cbor2
    import msgpack
    import nbtlib
    import pickle
    import pickletools
    import io
    import ubjson
    import fastavro
    import edn_format
    from amazon.ion import simpleion

    out = Path(out)
    expected = {}
    r = random.Random(20251029)

    def put(fmt, name, data, exp):
        (out / fmt).mkdir(parents=True, exist_ok=True)
        (out / fmt / name).write_bytes(data)
        expected[f"{fmt}/{name}"] = dict(exp, format=fmt)

    for i in range(100):
        docs = [rand_doc(r) for _ in range(r.choice([1, 1, 3]))]
        put("msgpack", f"d{i}.msgpack", b"".join(msgpack.packb(d) for d in docs), expect(docs))
        put("cbor", f"d{i}.cbor", b"".join(cbor2.dumps(d) for d in docs), expect(docs))
        put("bson", f"d{i}.bson", b"".join(bson.encode(d) for d in docs), expect(docs))
        put("ubjson", f"d{i}.ubj", ubjson.dumpb(docs[0], container_count=r.random() < 0.5), expect(docs[:1]))
        ion_doc = rand_doc(r, kinds=("int", "str", "bool", "none"))
        put("ion", f"d{i}.10n", simpleion.dumps(ion_doc, binary=True), expect([ion_doc]))
        put("ion_text", f"d{i}.ion", simpleion.dumps(ion_doc, binary=False).encode(), expect([ion_doc]))
        be = rand_doc(r, kinds=("int", "str"))
        put("bencode", f"d{i}.bencode", bencode.encode(be), expect([dict(sorted(be.items()))]))
        edn_doc = rand_doc(r, kinds=("int", "float", "str", "bool", "none"))
        put("edn", f"d{i}.edn", edn_format.dumps({edn_format.Keyword(k): v for k, v in edn_doc.items()}).encode(),
            expect([{":" + k: edn_like(v) for k, v in edn_doc.items()}]))
        # NBT: compounds of ints, strings, doubles and lists.
        nb = rand_doc(r, kinds=("int", "str", "float"))
        put("nbt", f"d{i}.nbt", nbt_bytes(nbtlib, nb), expect([nb_expected(nb)]))
        # Pickles: standard-library containers, every protocol.
        obj = rand_doc(r)
        if i % 2:
            import collections
            import datetime
            import decimal
            obj.update(when=datetime.datetime(2025, 9, 1, 12, i % 60), order=collections.OrderedDict(a=1, b=2),
                       price=decimal.Decimal("1.5"), gauges={"G7", "G9"}, frozen=frozenset({1}))
        proto = i % 6
        data = pickle.dumps(obj, protocol=proto)
        put("pickle", f"d{i}.pkl", data, {"protocol": proto, "opcodes": sum(1 for _ in pickletools.genops(data)),
                                          "globals": sorted(find_classes(pickle, data))})
    generate_tools(out, put, r)
    # Fixtures decoded by their libraries.
    fixtures(expected)
    (out / "expected.json").write_text(json.dumps(expected, indent=1, sort_keys=True))
    print(len(expected), "expectations written")


def edn_like(v):
    if isinstance(v, dict):
        return {":" + k if False else k: edn_like(x) for k, x in v.items()}
    if isinstance(v, list):
        return [edn_like(x) for x in v]
    return v


def php_like(v):
    """PHP arrays: lists become maps keyed by index."""
    if isinstance(v, dict):
        return {k: php_like(x) for k, x in v.items()}
    if isinstance(v, list):
        return {str(i): php_like(x) for i, x in enumerate(v)}
    return v


def generate_tools(out, put, r):
    """Formats whose writers are programs: PHP, protoc, fastavro, mktorrent, Java, Jackson."""
    import fastavro
    import io
    import os
    import tempfile
    import bencode
    import hashlib

    for i in range(50):
        doc = rand_doc(r)
        data = subprocess.run(["php", "-r", "echo serialize(json_decode(file_get_contents('php://stdin'), true));"],
                              input=json.dumps(doc).encode(), capture_output=True, check=True).stdout
        put("php_serialized", f"d{i}.phpser", data, expect([php_like(doc)]))
    proto = ROOT / "target" / "binser-oracle-tide.proto"
    proto.write_text(PROTO)
    for i in range(50):
        fields = []
        if r.random() < 0.8:
            fields.append(f'harbour: "{r.choice(WORDS)}"')
        for _ in range(r.randint(0, 3)):
            fields.append(f'readings {{ gauge: "G{r.randint(1, 9)}" seq: {r.randint(0, 1000)} level_cm: {r.randint(-500, 500)} }}')
        if r.random() < 0.5:
            fields.append(f"height_m: {r.uniform(0, 9):.3f}")
        if r.random() < 0.5:
            fields.append(f"ratio: {r.uniform(0, 1):.2f}")
        if r.random() < 0.4:
            fields.append(f'berths {{ key: "{r.randint(1, 20)}" value: {r.randint(0, 1)} }}')
        if not fields:
            fields.append('harbour: "x"')
        data = subprocess.run(["protoc", f"--proto_path={proto.parent}", "--encode=saltmere.Tide", proto.name],
                              input=" ".join(fields).encode(), capture_output=True, check=True).stdout
        raw = subprocess.run(["protoc", "--decode_raw"], input=data, capture_output=True, check=True).stdout.decode()
        top = sorted({ln.split(":")[0].split(" ")[0] for ln in raw.splitlines() if ln and not ln.startswith(" ")} - {"}"})
        put("protobuf_binary", f"d{i}.binpb", data, {"protobuf_fields": top})
    schema = fastavro.parse_schema({"type": "record", "name": "R", "fields": [
        {"name": "a", "type": "long"}, {"name": "b", "type": ["null", "string"]}, {"name": "c", "type": "double"}]})
    for i in range(30):
        rows = [{"a": r.randint(0, 10**9), "b": r.choice([None, r.choice(WORDS)]), "c": r.random()} for _ in range(r.randint(0, 400))]
        buf = io.BytesIO()
        codec = r.choice(["null", "deflate"])
        fastavro.writer(buf, schema, rows, codec=codec, sync_interval=r.choice([64, 512, 16000]))
        buf.seek(0)
        rd = fastavro.reader(buf)
        n = sum(1 for _ in rd)
        put("avro", f"d{i}.avro", buf.getvalue(), {"records": n, "fields": ["a", "b", "c"], "codec": codec})
    for i in range(10):
        with tempfile.TemporaryDirectory() as d:
            for j in range(r.randint(1, 4)):
                Path(d, f"chart{j}.txt").write_bytes(os.urandom(r.randint(1, 70000)))
            t = Path(d).parent / f"t{i}.torrent"
            subprocess.run(["mktorrent", "-d", "-a", "http://tracker.example.org/announce", "-l", "15", "-o", str(t), d],
                           capture_output=True, check=True)
            data = t.read_bytes()
            t.unlink()
        info = bencode.decode(data)["info"]
        put("bencode", f"t{i}.torrent", data, {"info_hash": hashlib.sha1(bencode.encode(info)).hexdigest(),
                                                "documents": 1, "keys": list(bencode.decode(data))})
    # Smile and Java streams from the JVM.
    jdir = out / "jvm"
    jdir.mkdir(parents=True, exist_ok=True)
    docs = [rand_doc(r) for _ in range(40)]
    (jdir / "docs.json").write_text("\n".join(json.dumps(d) for d in docs))
    (jdir / "Gen.java").write_text(GEN_JAVA)
    subprocess.run(["java", "-cp", "/opt/jackson/*", str(jdir / "Gen.java"), str(jdir)], check=True)
    for i, d in enumerate(docs):
        put("smile", f"d{i}.sml", (jdir / f"d{i}.sml").read_bytes(), expect([d]))
    import javaobj.v2 as javaobj
    for i in range(20):
        data = (jdir / f"o{i}.ser").read_bytes()
        put("java_serialized", f"o{i}.ser", data, {"classes_include": sorted(java_classes(javaobj, data))})


def java_classes(javaobj, data):
    """Every class description in the stream, by javaobj's parser."""
    import io
    import javaobj.v2.beans as beans
    import javaobj.v2.core as core
    parser = core.JavaStreamParser(io.BytesIO(data), [])
    parser.run()
    seen = set()
    for m in [parser._JavaStreamParser__handles, *parser._JavaStreamParser__handle_maps]:
        for x in (m.values() if isinstance(m, dict) else m):
            if isinstance(x, beans.JavaClassDesc) and x.name:
                seen.add(x.name)
    return seen


PROTO = """syntax = "proto3";
package saltmere;
message Reading { string gauge = 1; uint32 seq = 2; sint32 level_cm = 3; fixed64 at_ms = 4; }
message Tide { string harbour = 1; repeated Reading readings = 2; double height_m = 3; bytes chart = 4;
  map<string, int32> berths = 5; float ratio = 6; }
"""

GEN_JAVA = """
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.smile.*;
import java.io.*;
import java.math.*;
import java.net.URI;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class Gen {
    public static void main(String[] a) throws Exception {
        Path dir = Path.of(a[0]);
        var json = new ObjectMapper();
        var smile = new ObjectMapper(SmileFactory.builder().enable(SmileGenerator.Feature.CHECK_SHARED_STRING_VALUES).build());
        int i = 0;
        for (String line : Files.readAllLines(dir.resolve("docs.json"))) {
            smile.writeValue(dir.resolve("d" + (i++) + ".sml").toFile(), json.readValue(line, Map.class));
        }
        var rnd = new Random(29);
        Object[] pool = {
            new HashMap<>(Map.of("tide", 4)), new TreeMap<>(Map.of("b", 1L, "a", 2L)), new ArrayList<>(List.of(1, 2)),
            new LinkedList<>(List.of("x")), new HashSet<>(Set.of(1.5)), new BigDecimal("12.50"), new BigInteger("123456789012345678901"),
            new Date(1756728000000L), URI.create("https://example.org/tides"), UUID.fromString("5a1e0000-0000-4000-8000-000000000001"),
            new String[] {"G7"}, new int[][] {{1, 2}, {3}}, TimeUnit.MINUTES, Boolean.TRUE, 'c', new StringBuilder("pier"),
            new Vector<>(List.of(3)), new LinkedHashMap<>(Map.of("k", new long[] {1, 2}))
        };
        for (int j = 0; j < 20; j++) {
            var m = new LinkedHashMap<String, Object>();
            for (int k = 0; k < 1 + rnd.nextInt(5); k++) m.put("v" + k, pool[rnd.nextInt(pool.length)]);
            try (var o = new ObjectOutputStream(new FileOutputStream(dir.resolve("o" + j + ".ser").toFile()))) {
                o.writeObject(m);
            }
        }
    }
}
"""


def nb_expected(v):
    """What NBT keeps: booleans become bytes, mixed lists strings."""
    if isinstance(v, dict):
        return {k: nb_expected(x) for k, x in v.items()}
    if isinstance(v, list):
        items = [nb_expected(x) for x in v]
        if len({type(x) for x in items}) > 1:
            return [str(x) for x in v]
        return items
    if isinstance(v, bool):
        return int(v)
    return v


def nbt_bytes(nbtlib, d):
    def conv(v):
        if isinstance(v, dict):
            return nbtlib.Compound({k: conv(x) for k, x in v.items()})
        if isinstance(v, list):
            items = [conv(x) for x in v]
            kinds = {type(x) for x in items}
            if len(kinds) > 1:
                return nbtlib.List[nbtlib.String]([nbtlib.String(str(x)) for x in v])
            return nbtlib.List[kinds.pop()](items) if items else nbtlib.List[nbtlib.Int]([])
        if isinstance(v, bool):
            return nbtlib.Byte(int(v))
        if isinstance(v, int):
            return nbtlib.Int(v)
        if isinstance(v, float):
            return nbtlib.Double(v)
        return nbtlib.String(str(v))
    buf = __import__("io").BytesIO()
    nbtlib.File(conv(d)).write(buf)
    return buf.getvalue()


def find_classes(pickle, data):
    seen = set()

    class Recorder(pickle.Unpickler):
        def find_class(self, module, name):
            seen.add(f"{module}.{name}")
            return super().find_class(module, name)

    import io
    Recorder(io.BytesIO(data)).load()
    return seen


def fixtures(expected):
    try:
        _fixtures(expected)
    except Exception as e:  # report, keep the generated corpus
        print("fixture expectations failed:", repr(e))


def _fixtures(expected):
    import bencode
    import bson
    import cbor2
    import hashlib
    import msgpack
    import pickle
    import pickletools
    import fastavro
    import javaobj.v2 as javaobj
    from amazon.ion import simpleion

    def fx(fmt, name, exp):
        expected[f"fixture:{fmt}/{name}"] = dict(exp, format=fmt)

    for f in sorted((FX / "msgpack").glob("*.msgpack")):
        docs = list(msgpack.Unpacker(open(f, "rb"), raw=False, timestamp=0, strict_map_key=False))
        fx("msgpack", f.name, {"documents": len(docs), "keys": list(docs[0])[:50]})
    for f in sorted((FX / "cbor").glob("*.cbor")):
        data, docs = f.read_bytes(), []
        s = __import__("io").BytesIO(data)
        while s.tell() < len(data):
            v = cbor2.load(s)
            docs.append(v.value if isinstance(v, cbor2.CBORTag) else v)
        fx("cbor", f.name, {"documents": len(docs), "keys": list(docs[0])[:50]})
    for f in sorted((FX / "bson").glob("*.bson")):
        docs = bson.decode_all(f.read_bytes())
        fx("bson", f.name, {"documents": len(docs), "keys": list(docs[0])[:50]})
    for f in sorted((FX / "bencode").glob("*")):
        if f.name == "SOURCE.md":
            continue
        v = bencode.decode(f.read_bytes())
        exp = {"documents": 1, "keys": list(v)[:50]}
        if "info" in v:
            exp["info_hash"] = hashlib.sha1(bencode.encode(v["info"])).hexdigest()
        fx("bencode", f.name, exp)
    for f in sorted((FX / "pickle").glob("*.pkl")):
        data = f.read_bytes()
        fx("pickle", f.name, {"opcodes": sum(1 for _ in pickletools.genops(data)),
                              "globals": sorted(find_classes(pickle, data))})
    for f in sorted((FX / "avro").glob("*.avro")):
        with open(f, "rb") as fh:
            rd = fastavro.reader(fh)
            n = sum(1 for _ in rd)
            fields = [x["name"] for x in rd.writer_schema["fields"]]
        fx("avro", f.name, {"records": n, "fields": fields, "codec": rd.codec})
    for f in sorted((FX / "ion").glob("*.10n")):
        v = simpleion.loads(f.read_bytes())
        fx("ion", f.name, {"documents": 1, "keys": list(v)[:50]})
    for f in sorted((FX / "java_serialized").glob("*.ser")):
        fx("java_serialized", f.name, {"classes_include": sorted(java_classes(None, f.read_bytes()))})


# ---------------------------------------------------------------- check

def asn1(tally):
    """Element count and depth of DER certificates in system folders, forced to
    the generic reader, against `openssl asn1parse` (one line per element)."""
    found = subprocess.run(["find", "/System/Library", "/Library", "/Applications", "-path", "/System/Volumes", "-prune", "-o",
                            "-name", "*.cer", "-type", "f", "-print"], capture_output=True, text=True).stdout.split("\n")
    found = [f for f in found if f]
    found = sorted(found)[:300] + [str(FX / "asn1" / "gauge.der")]
    want = {}
    for f in found:
        r = subprocess.run(["openssl", "asn1parse", "-inform", "DER", "-in", f], capture_output=True, text=True)
        if r.returncode != 0:
            continue
        depths = [int(m.group(1)) for m in re.finditer(r"^\s*\d+:d=(\d+)", r.stdout, re.M)]
        if not depths:
            continue
        lines, depth = depths, max(depths)
        want[f] = (len(lines), depth)
    files = list(want)
    for i in range(0, len(files), 200):
        chunk = files[i:i + 200]
        r = subprocess.run([WHIFF, "--jsonl", "--format", "asn1", *chunk], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            rep = json.loads(line)
            sec = rep.get("format", {}).get("asn1") or {}
            p = rep["source"]["path"]
            tally("asn1 elements and depth", p, (sec.get("elements"), sec.get("max_depth")), want[p])


def check(out):
    out = Path(out)
    expected = json.loads((out / "expected.json").read_text())
    files = {}
    for key in expected:
        if key.startswith("fixture:"):
            files[key] = FX / key.split(":", 1)[1]
        else:
            files[key] = out / key
    reports = {}
    keys = list(files)
    for i in range(0, len(keys), 200):
        chunk = keys[i:i + 200]
        r = subprocess.run([WHIFF, "--jsonl", "--privacy", "off", *map(str, (files[k] for k in chunk))],
                           capture_output=True, text=True)
        by_path = {}
        for line in r.stdout.splitlines():
            rep = json.loads(line)
            by_path[rep["source"]["path"]] = rep
        for k in chunk:
            reports[k] = by_path.get(str(files[k]))
    ok, total, bad = Counter(), Counter(), {}

    def tally(what, key, got, want):
        total[what] += 1
        if got == want:
            ok[what] += 1
        else:
            bad.setdefault(what, []).append((key, got, want))

    for key, exp in expected.items():
        rep = reports.get(key) or {}
        fmt = exp["format"]
        sec = rep.get("format", {}).get(fmt)
        tally(f"{fmt} detected", key, sec is not None, True)
        if sec is None:
            continue
        if "documents" in exp:
            tally(f"{fmt} documents", key, sec.get("documents", 1), exp["documents"])
        if exp.get("keys") is not None:
            tally(f"{fmt} keys", key, sec.get("keys"), exp["keys"])
        if "paths" in exp:
            got = {p: sorted(v["types"]) for p, v in (sec.get("schema") or {}).get("paths", {}).items()}
            tally(f"{fmt} schema", key, got, exp["paths"])
        if "globals" in exp:
            tally(f"{fmt} globals", key, sorted(sec.get("globals", [])), exp["globals"])
            tally(f"{fmt} opcodes", key, sec.get("opcodes"), exp["opcodes"])
        if "info_hash" in exp:
            tally("torrent info hash", key, (sec.get("torrent") or {}).get("info_hash"), exp["info_hash"])
        if "records" in exp:
            tally("avro", key, (sec.get("records"), list(sec.get("fields", {})), sec.get("codec")),
                  (exp["records"], exp["fields"], exp["codec"]))
        if "protobuf_fields" in exp:
            tally("protobuf fields", key, sorted(sec.get("fields", {})), exp["protobuf_fields"])
        if "classes_include" in exp:
            missing = sorted(set(exp["classes_include"]) - set(sec.get("classes", [])))
            tally("java classes", key, missing, [])
    asn1(tally)
    for what in sorted(total):
        print(f"{what}: {ok[what]}/{total[what]}")
        for key, got, want in bad.get(what, [])[:3]:
            print(f"    {key}\n      whiff:  {str(got)[:400]}\n      oracle: {str(want)[:400]}")
    sys.exit(0 if sum(ok.values()) == sum(total.values()) else 1)


if __name__ == "__main__":
    {"generate": generate, "check": check}[sys.argv[1]](sys.argv[2])
