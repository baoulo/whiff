-- Saltmere Harbour configuration
let Berth = { id : Natural, lengthM : Double, occupied : Bool }

let defaults = ./defaults.dhall

let berths
    : List Berth
    = [ { id = 4, lengthM = 12.5, occupied = False }
      , { id = 7, lengthM = 9.0, occupied = True }
      ]

in  defaults // { harbour = "Saltmere Harbour", berths }
