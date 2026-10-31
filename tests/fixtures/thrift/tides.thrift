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
