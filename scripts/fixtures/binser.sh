#!/usr/bin/env bash
# Regenerate the binary-serialisation fixtures under tests/fixtures/<format>/.
#
# Written in a Debian container run with podman (image `whiff-binser`, built
# from the Containerfile below) for a fictitious harbour (Saltmere Harbour)
# with fixed times, by the tools and libraries that own each format:
# msgpack, cbor2, pymongo's bson, py-ubjson, amazon.ion, bencode.py, nbtlib,
# pickle, fastavro (craft_binser.py); mktorrent (a private torrent without a
# creation date); the PHP CLI (serialize); ObjectOutputStream (Java 21);
# Jackson's SmileFactory; protoc (--encode, --decode); flatc (--schema -b);
# openssl asn1parse -genconf. Android binary XML and the resource table are
# taken from the APK fixture (aapt2). The Godot binary header is built from
# its layout; the text formats (RON, KDL, HOCON, EDN, S-expressions, Godot
# scenes, Unity YAML, schema languages) are written by hand.
#
#     scripts/fixtures/binser.sh
#
# Containerfile (`podman build -t whiff-binser`):
#
#     FROM docker.io/library/debian:trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#         python3 python3-pip openssl php-cli protobuf-compiler flatbuffers-compiler mktorrent \
#         openjdk-21-jdk-headless curl ca-certificates
#     RUN pip install --break-system-packages msgpack==1.2.4 cbor2==6.1.5 pymongo==4.19.0 py-ubjson==0.16.1 \
#         amazon.ion==0.15.0 nbtlib==2.0.4 fastavro==1.13.1 protobuf==7.36.2 ds_store==1.3.3 bencode.py==4.1.0 \
#         javaobj-py3==0.6.1 pyhocon==0.3.63 edn_format==0.8.0
#     RUN mkdir -p /opt/jackson && cd /opt/jackson && for a in core/jackson-core core/jackson-databind \
#           core/jackson-annotations dataformat/jackson-dataformat-smile; do n=${a#*/}; \
#           curl -sSfLO "https://repo1.maven.org/maven2/com/fasterxml/jackson/${a%%/*}/$n/2.18.2/$n-2.18.2.jar"; done

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d "$root/target/binser-fixtures.XXXXXX")
w="/whiff/${work#"$root"/}"
run() { podman run --rm -v "$root:/whiff" -w /whiff -e WORK="$w" whiff-binser "$@"; }
put() { mkdir -p "$fx/$1"; cp "$2" "$fx/$1/${3:-$(basename "$2")}"; }

# ------------------------------------------------------------ tool outputs
mkdir -p "$work/charts"
printf 'time,height_m\n06:12,4.25\n18:31,4.10\n' >"$work/charts/tide-table.csv"
printf 'berth 4 free\nberth 7 taken\n' >"$work/charts/berths.txt"

cat >"$work/Berths.java" <<'EOF'
import java.io.*;
import java.time.*;
import java.util.*;

public class Berths {
    public static void main(String[] a) throws Exception {
        var m = new LinkedHashMap<String, Object>();
        m.put("harbour", "Saltmere Harbour");
        m.put("berths", new ArrayList<>(List.of(4, 7, 12)));
        m.put("day", DayOfWeek.MONDAY);
        m.put("updated", LocalDate.of(2025, 9, 1));
        m.put("levels", new int[] {412, 415});
        m.put("gauges", new String[] {"G7", "G9"});
        m.put("since", new Date(1_756_728_000_000L));
        try (var o = new ObjectOutputStream(new FileOutputStream(a[0]))) {
            o.writeObject(m);
        }
    }
}
EOF
cat >"$work/Smile.java" <<'EOF'
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.smile.*;
import java.io.File;
import java.util.*;

public class Smile {
    public static void main(String[] a) throws Exception {
        var f = SmileFactory.builder().enable(SmileGenerator.Feature.CHECK_SHARED_STRING_VALUES).build();
        var readings = new ArrayList<Map<String, Object>>();
        for (int i = 0; i < 3; i++) {
            var r = new LinkedHashMap<String, Object>();
            r.put("gauge", "G7");
            r.put("seq", i);
            r.put("level_cm", 412 + 3 * i);
            r.put("unit", "cm");
            r.put("ok", true);
            r.put("ratio", 0.5 + i);
            readings.add(r);
        }
        var doc = new LinkedHashMap<String, Object>();
        doc.put("harbour", "Saltmere Harbour");
        doc.put("readings", readings);
        doc.put("chart", new byte[] {1, 2, 3});
        doc.put("depth", -1234567890123L);
        new ObjectMapper(f).writeValue(new File(a[0]), doc);
    }
}
EOF
cat >"$work/tide.proto" <<'EOF'
syntax = "proto3";
package saltmere;

message Reading {
  string gauge = 1;
  uint32 seq = 2;
  sint32 level_cm = 3;
  fixed64 at_ms = 4;
}

message Tide {
  string harbour = 1;
  repeated Reading readings = 2;
  double height_m = 3;
  bytes chart = 4;
  map<string, int32> berths = 5;
  float ratio = 6;
}
EOF
cat >"$work/tide.txt" <<'EOF'
harbour: "Saltmere Harbour"
readings { gauge: "G7" seq: 1 level_cm: 412 at_ms: 1756728000000 }
readings { gauge: "G7" seq: 2 level_cm: -15 at_ms: 1756728600000 }
height_m: 4.25
chart: "\211PNG"
berths { key: "4" value: 1 }
berths { key: "7" value: 0 }
ratio: 0.5
EOF
cat >"$work/tide.fbs" <<'EOF'
namespace Saltmere.Tides;

enum Unit : byte { Centimetre, Foot }
struct Position { lat: double; lon: double; }
table Reading { gauge: string; seq: uint; level: int; unit: Unit = Centimetre; }
table Gauge { name: string; position: Position; readings: [Reading]; }
union Payload { Reading, Gauge }
table Message { payload: Payload; }
rpc_service Tides { Latest(Gauge): Reading; }

root_type Message;
file_identifier "TIDE";
file_extension "tide";
EOF
cat >"$work/gauge.cnf" <<'EOF'
asn1 = SEQUENCE:gauge
[gauge]
kind = OID:1.3.6.1.4.1.99999.7
name = UTF8String:Saltmere Harbour gauge 7
installed = GENERALIZEDTIME:20250901120000Z
levels = SEQUENCE:levels
calibrated = EXPLICIT:0,BOOLEAN:TRUE
[levels]
a = INTEGER:412
b = INTEGER:415
c = INTEGER:418
EOF
run sh -c "
set -e
cd $w
mktorrent -d -p -a http://tracker.example.org/announce -c 'Saltmere Harbour charts' -n harbour-charts -l 15 \
    -o harbour-charts.torrent charts >/dev/null
php -r 'class Berth { public \$id = 7; protected \$length = 12.5; private \$tags = [\"pontoon\"]; }
    echo serialize([\"harbour\" => \"Saltmere Harbour\", \"berth\" => new Berth(), \"levels\" => [412, 415], \"open\" => true, \"note\" => null]);' >session.phpser
java Berths.java berths.ser
java -cp '/opt/jackson/*' Smile.java readings.sml
protoc --encode=saltmere.Tide tide.proto <tide.txt >tide.binpb
for i in 0 1 2; do
    printf 'gauge: \"G7\" seq: %d level_cm: %d at_ms: %d\n' \$i \$((412 + 3 * i)) \$((1756728000000 + 600000 * i)) |
        protoc --encode=saltmere.Reading tide.proto >reading\$i.binpb
done
{ printf '# proto-file: tide.proto\n# proto-message: saltmere.Tide\n\n'; protoc --decode=saltmere.Tide tide.proto <tide.binpb; } >tide.txtpb
flatc --schema -b tide.fbs
openssl asn1parse -genconf gauge.cnf -out gauge.der >/dev/null
"
run python3 -I scripts/fixtures/craft_binser.py

# ------------------------------------------------------------ text formats
mkdir -p "$fx/ron" "$fx/kdl" "$fx/hocon" "$fx/edn" "$fx/sexp" "$fx/godot_resource" "$fx/unity_yaml" "$fx/unity_meta"
cat >"$fx/ron/harbour.ron" <<'EOF'
#![enable(implicit_some)]
// Saltmere Harbour configuration
Harbour(
    name: "Saltmere Harbour",
    berths: [
        Berth(id: 4, length_m: 12.5, occupied: false, vessel: None),
        Berth(id: 7, length_m: 9.0, occupied: true, vessel: Some("Gull")),
    ],
    high_water: (6, 12),
    gauges: {"G7": North, "G9": Pier(2)},
    raw_note: r#"pilot on "channel 12""#,
)
EOF
cat >"$fx/kdl/harbour.kdl" <<'EOF'
// Saltmere Harbour, KDL 2
harbour "Saltmere Harbour" country="GB" {
    berth 4 length=12.5 occupied=#false
    berth 7 length=9.0 occupied=#true {
        vessel "Gull" (date)arrived="2025-09-01"
    }
    /-berth 12 length=20.0
    gauge "G7" levels=412 note=#"pilot on "channel 12""#
}
tides {
    high "06:12" height=4.25; low "12:30" height=0.8
}
EOF
cat >"$fx/hocon/application.hocon" <<'EOF'
# Saltmere Harbour service settings
include "defaults.conf"

harbour {
  name = "Saltmere Harbour"
  berths = [4, 7, 12]
  gauge.id = G7
  gauge.interval = 10 minutes
}

http {
  port = 8080
  port = ${?HARBOUR_PORT}
  host: "0.0.0.0"
}

tides.high-water = "06:12"
report = """Daily tide
report"""
EOF
cat >"$fx/edn/tides.edn" <<'EOF'
;; Saltmere Harbour tide table
{:harbour "Saltmere Harbour"
 :updated #inst "2025-09-01T12:00:00.000-00:00"
 :id #uuid "5a1e0000-0000-4000-8000-000000000001"
 :berths [{:id 4 :length-m 12.5 :occupied? false}
          {:id 7 :length-m 9.0 :occupied? true :vessel "Gull"}]
 :gauges #{:g7 :g9}
 #_ :retired #_ true
 :high-water {:time "06:12" :height-m 4.25}
 :pilot nil}
EOF
cat >"$fx/sexp/harbour.sexp" <<'EOF'
; Saltmere Harbour as S-expressions
(harbour
  (name "Saltmere Harbour")
  (berth (id 4) (length 12.5) (occupied false))
  (berth (id 7) (length 9.0) (occupied true) (vessel "Gull"))
  (high-water (time "06:12") (height 4.25)))
EOF
cat >"$fx/godot_resource/harbour.tscn" <<'EOF'
[gd_scene load_steps=4 format=3 uid="uid://b5a1e000harbr"]

[ext_resource type="Script" path="res://harbour/tide_gauge.gd" id="1_g7"]
[ext_resource type="Texture2D" uid="uid://c5a1e000chart" path="res://charts/harbour.png" id="2_map"]

[sub_resource type="CircleShape2D" id="CircleShape2D_buoy"]
radius = 16.0

[node name="Harbour" type="Node2D"]

[node name="Chart" type="Sprite2D" parent="."]
texture = ExtResource("2_map")

[node name="Gauge7" type="Area2D" parent="."]
position = Vector2(412, 128)
script = ExtResource("1_g7")

[node name="Shape" type="CollisionShape2D" parent="Gauge7"]
shape = SubResource("CircleShape2D_buoy")

[connection signal="body_entered" from="Gauge7" to="." method="_on_gauge_body_entered"]
EOF
cat >"$fx/godot_resource/tide_curve.tres" <<'EOF'
[gd_resource type="Curve" load_steps=1 format=3 uid="uid://d5a1e000curve"]

[resource]
min_value = -1.0
max_value = 5.0
_data = [Vector2(0, 0.8), 0.0, 0.0, 0, 0, Vector2(0.25, 4.25), 0.0, 0.0, 0, 0]
point_count = 2
EOF
cat >"$fx/unity_yaml/Harbour.unity" <<'EOF'
%YAML 1.1
%TAG !u! tag:unity3d.com,2011:
--- !u!29 &1
OcclusionCullingSettings:
  m_ObjectHideFlags: 0
  serializedVersion: 2
--- !u!104 &2
RenderSettings:
  m_ObjectHideFlags: 0
  serializedVersion: 10
  m_Fog: 0
--- !u!1 &100100
GameObject:
  m_ObjectHideFlags: 0
  serializedVersion: 6
  m_Component:
  - component: {fileID: 100101}
  - component: {fileID: 100102}
  m_Layer: 0
  m_Name: Buoy7
  m_TagString: Untagged
  m_IsActive: 1
--- !u!4 &100101
Transform:
  m_ObjectHideFlags: 0
  m_GameObject: {fileID: 100100}
  m_LocalPosition: {x: 4.12, y: 0, z: 1.28}
  m_Children: []
  m_Father: {fileID: 0}
--- !u!114 &100102
MonoBehaviour:
  m_ObjectHideFlags: 0
  m_GameObject: {fileID: 100100}
  m_Enabled: 1
  m_Script: {fileID: 11500000, guid: 5a1e00000000400080000000000000b1, type: 3}
  m_Name:
  levelCm: 412
--- !u!1 &100200
GameObject:
  m_ObjectHideFlags: 0
  serializedVersion: 6
  m_Component:
  - component: {fileID: 100201}
  - component: {fileID: 100202}
  m_Name: Pier
--- !u!4 &100201
Transform:
  m_GameObject: {fileID: 100200}
  m_LocalPosition: {x: 0, y: 0, z: 0}
--- !u!23 &100202
MeshRenderer:
  m_GameObject: {fileID: 100200}
  m_Materials:
  - {fileID: 2100000, guid: 5a1e00000000400080000000000000c1, type: 2}
--- !u!1660057539 &9223372036854775807
SceneRoots:
  m_ObjectHideFlags: 0
  m_Roots:
  - {fileID: 100101}
  - {fileID: 100201}
EOF
cat >"$fx/unity_meta/TideGauge.cs.meta" <<'EOF'
fileFormatVersion: 2
guid: 5a1e00000000400080000000000000b1
MonoImporter:
  externalObjects: {}
  serializedVersion: 2
  defaultReferences: []
  executionOrder: 0
  icon: {instanceID: 0}
  userData:
  assetBundleName: harbour
  assetBundleVariant:
EOF

# Schema and configuration languages (code.source).
mkdir -p "$fx/thrift" "$fx/capnp" "$fx/flatbuffers" "$fx/dhall" "$fx/jsonnet" "$fx/cuelang"
cp "$work/tide.fbs" "$fx/flatbuffers/tide.fbs"
cat >"$fx/thrift/tides.thrift" <<'EOF'
// Saltmere Harbour tide service
include "shared.thrift"
namespace java org.saltmere.tides
namespace py saltmere.tides

enum Unit { CENTIMETRE = 1, FOOT = 2 }

struct Reading {
  1: required string gauge,
  2: i32 level,
  3: optional Unit unit = Unit.CENTIMETRE,
}

exception NoGauge { 1: string gauge }

service Tides extends shared.Health {
  Reading latest(1: string gauge) throws (1: NoGauge missing),
}
EOF
cat >"$fx/capnp/tides.capnp" <<'EOF'
# Saltmere Harbour tide readings
@0xd5a1e00000000001;
using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("saltmere::tides");

struct Reading {
  gauge @0 :Text;
  level @1 :Int32;
  unit @2 :Unit;
}

enum Unit { centimetre @0; foot @1; }

interface Tides {
  latest @0 (gauge :Text) -> (reading :Reading);
}

const highWater :Text = "06:12";
EOF
cat >"$fx/dhall/harbour.dhall" <<'EOF'
-- Saltmere Harbour configuration
let Berth = { id : Natural, lengthM : Double, occupied : Bool }

let defaults = ./defaults.dhall

let berths
    : List Berth
    = [ { id = 4, lengthM = 12.5, occupied = False }
      , { id = 7, lengthM = 9.0, occupied = True }
      ]

in  defaults // { harbour = "Saltmere Harbour", berths }
EOF
cat >"$fx/jsonnet/harbour.jsonnet" <<'EOF'
// Saltmere Harbour configuration
local defaults = import 'defaults.libsonnet';
local berth(id, length) = { id: id, length_m: length };

defaults {
  harbour: 'Saltmere Harbour',
  berths: [berth(4, 12.5), berth(7, 9.0)],
  high_water: importstr 'high_water.txt',
}
EOF
cat >"$fx/cuelang/harbour.cue" <<'EOF'
// Saltmere Harbour configuration
package harbour

import "strings"

#Berth: {
	id:       int & >0
	length_m: float
	occupied: *false | bool
}

name:   "Saltmere Harbour"
code:   strings.ToUpper("smh")
berths: [...#Berth] & [{id: 4, length_m: 12.5}, {id: 7, length_m: 9.0, occupied: true}]
EOF

echo "binser fixtures written; scratch files in $work"
