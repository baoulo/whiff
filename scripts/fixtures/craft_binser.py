"""Binary-serialisation fixtures, written in the `whiff-binser` container by
the libraries that own the formats (see binser.sh). Everything describes a
fictitious harbour (Saltmere Harbour) with fixed times. Run from the
repository root after binser.sh has made the tool outputs in $WORK."""

import collections
import datetime as dt
import gzip
import io
import os
import pickle
import struct
import uuid
from pathlib import Path

import bencode
import bson
import cbor2
import fastavro
import msgpack
import nbtlib
import ubjson
from amazon.ion import simpleion

FX = Path("tests/fixtures")
WORK = Path(os.environ["WORK"])
WHEN = dt.datetime(2025, 9, 1, 12, tzinfo=dt.timezone.utc)

BERTH = {
    "harbour": "Saltmere Harbour",
    "berth": 7,
    "length_m": 12.5,
    "occupied": True,
    "vessel": None,
    "tags": ["pontoon", "fuel"],
    "high_water": {"time": "06:12", "height_m": 4.25},
}


def write(fmt, name, data):
    (FX / fmt).mkdir(parents=True, exist_ok=True)
    (FX / fmt / name).write_bytes(data)


def readings(n):
    return [{"gauge": "G7", "seq": i, "level_cm": 412 + 3 * i, "at": WHEN + dt.timedelta(minutes=10 * i)} for i in range(n)]


def main():
    # MessagePack: one document with a timestamp and binary; a stream.
    doc = dict(BERTH, updated=msgpack.Timestamp.from_datetime(WHEN), chart=b"\x89PNG\r\n")
    write("msgpack", "berth.msgpack", msgpack.packb(doc, datetime=False))
    stream = b"".join(msgpack.packb(r, datetime=True) for r in readings(3))
    write("msgpack", "readings.msgpack", stream)

    # CBOR: self-described, with an epoch date, bytes and a tag; a stream.
    write("cbor", "berth.cbor", cbor2.dumps(cbor2.CBORTag(55799, dict(BERTH, updated=WHEN, chart=b"\x89PNG",
                                                                      id=uuid.UUID(int=0x5A1E))),
                                            datetime_as_timestamp=True))
    write("cbor", "readings.cbor", b"".join(cbor2.dumps(r, datetime_as_timestamp=True) for r in readings(3)))

    # BSON: one document; a mongodump-style stream.
    oid = bson.ObjectId(struct.pack(">I", int(WHEN.timestamp())) + bytes.fromhex("5a1e5a1e5a1e0001"))
    one = dict(BERTH, _id=oid, updated=WHEN, chart=bson.Binary(b"\x89PNG", 0),
               uuid=bson.Binary(uuid.UUID(int=0x5A1E).bytes, 4), visits=bson.Int64(3_000_000_000))
    write("bson", "berth.bson", bson.encode(one))
    docs = []
    for i, r in enumerate(readings(3)):
        r["_id"] = bson.ObjectId(struct.pack(">I", int(r["at"].timestamp())) + bytes.fromhex(f"5a1e5a1e5a1e00{i:02x}"))
        docs.append(bson.encode(r))
    write("bson", "readings.bson", b"".join(docs))

    # UBJSON: plain and with optimised (typed, counted) containers.
    write("ubjson", "berth.ubj", ubjson.dumpb(BERTH))
    write("ubjson", "levels.ubj", ubjson.dumpb({"levels": [412, 415, 418, 421]}, container_count=True))

    # Ion: binary with annotations, symbols, a timestamp; the same as text.
    ion = simpleion.loads(
        'saltmere::berth::{harbour: "Saltmere Harbour", berth: 7, length_m: 12.5e0, occupied: true, vessel: null, '
        'tags: ["pontoon", "fuel"], high_water: {time: "06:12", height_m: 4.25d0}, updated: 2025-09-01T12:00:00Z, '
        'kind: berth, depth: 12.50, chart: {{iVBORw==}}, route: (pier 4 to 7)}')
    write("ion", "berth.10n", simpleion.dumps(ion, binary=True))
    write("ion_text", "berth.ion", simpleion.dumps(ion, binary=False).encode())

    # bencode: a torrent from mktorrent, and a plain dictionary.
    write("bencode", "harbour-charts.torrent", (WORK / "harbour-charts.torrent").read_bytes())
    write("bencode", "berth.bencode", bencode.encode({k: v for k, v in BERTH.items()
                                                       if isinstance(v, (str, int, list)) and not isinstance(v, bool)}))

    # PHP: serialize() output written by the PHP CLI.
    write("php_serialized", "session.phpser", (WORK / "session.phpser").read_bytes())

    # NBT: uncompressed Java-edition NBT.
    root = nbtlib.Compound({
        "Harbour": nbtlib.String("Saltmere Harbour"),
        "Berths": nbtlib.List[nbtlib.Compound]([
            nbtlib.Compound({"Id": nbtlib.Int(4), "Length": nbtlib.Float(12.5), "Occupied": nbtlib.Byte(1)}),
            nbtlib.Compound({"Id": nbtlib.Int(7), "Length": nbtlib.Float(9.0), "Occupied": nbtlib.Byte(0)}),
        ]),
        "Levels": nbtlib.IntArray([412, 415, 418]),
        "LastPlayed": nbtlib.Long(int(WHEN.timestamp() * 1000)),
    })
    buf = io.BytesIO()
    nbt_file = nbtlib.File(root)
    nbt_file.root_name = "Saltmere"
    nbt_file.write(buf)
    write("nbt", "harbour.nbt", buf.getvalue())

    # Pickle: protocol 5 and protocol 0, standard-library types only.
    state = {"berths": collections.OrderedDict([("4", "free"), ("7", "taken")]), "updated": WHEN,
             "gauges": {"G7", "G9"}, "chart": b"\x89PNG", "window": (6, 12)}
    write("pickle", "berths.pkl", pickle.dumps(state, protocol=5))
    write("pickle", "berths-p0.pkl", pickle.dumps(state, protocol=0))

    # Smile, written by Jackson with shared names and values (binser.sh).
    write("smile", "readings.sml", (WORK / "readings.sml").read_bytes())

    # Java serialization, written by ObjectOutputStream (binser.sh).
    write("java_serialized", "berths.ser", (WORK / "berths.ser").read_bytes())

    # Avro containers (deflate and null codecs) and the schema.
    schema = {"type": "record", "name": "Reading", "namespace": "org.saltmere.tides", "doc": "A tide gauge reading",
              "fields": [{"name": "gauge", "type": "string"}, {"name": "seq", "type": "long"},
                         {"name": "level_cm", "type": "int"},
                         {"name": "at", "type": {"type": "long", "logicalType": "timestamp-millis"}},
                         {"name": "note", "type": ["null", "string"], "default": None}]}
    parsed = fastavro.parse_schema(schema)
    rows = [dict(r, note=None) for r in readings(5)]
    for codec in ["deflate", "null"]:
        out = io.BytesIO()
        fastavro.writer(out, parsed, rows, codec=codec, sync_interval=200, metadata={"saltmere.source": "gauge G7"},
                        sync_marker=bytes(range(16)))
        write("avro", f"readings-{codec}.avro", out.getvalue())
    import json
    write("avro_schema", "reading.avsc", (json.dumps(schema, indent=2) + "\n").encode())

    # Protocol buffers: binary (protoc --encode), a delimited stream, text.
    write("protobuf_binary", "tide.binpb", (WORK / "tide.binpb").read_bytes())
    msgs = [(WORK / f"reading{i}.binpb").read_bytes() for i in range(3)]

    def varint(n):
        out = b""
        while True:
            b, n = n & 0x7F, n >> 7
            out += bytes([b | (0x80 if n else 0)])
            if not n:
                return out
    write("protobuf_binary", "readings.pb", b"".join(varint(len(m)) + m for m in msgs))
    write("textproto", "tide.txtpb", (WORK / "tide.txtpb").read_bytes())

    # FlatBuffers binary schema (flatc --schema -b).
    write("bfbs", "tide.bfbs", (WORK / "tide.bfbs").read_bytes())

    # A BER/DER structure that is not a certificate (openssl asn1parse -genconf).
    write("asn1", "gauge.der", (WORK / "gauge.der").read_bytes())

    # Android binary XML and resource table, from the CC0 APK fixture.
    import zipfile
    with zipfile.ZipFile(FX / "apk" / "saltmere-tides.apk") as z:
        write("android_binary_xml", "AndroidManifest.xml", z.read("AndroidManifest.xml"))
        write("arsc", "resources.arsc", z.read("resources.arsc"))

    # Godot binary resource header (RSRC, little-endian, Godot 4.3, format 6).
    head = b"RSRC" + struct.pack("<IIIII", 0, 0, 4, 3, 6)
    t = b"Curve\0"
    head += struct.pack("<I", len(t)) + t + struct.pack("<Q", 0) + struct.pack("<I", 0) + b"\0" * 56
    head += struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<I", 0)
    write("godot_binary_resource", "tide_curve.res", head)


main()
