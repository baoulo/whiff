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
