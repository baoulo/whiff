(* Tide model *)
open Printf
open Harbour.Types

type tide = High | Low

let rec count = function
  | [] -> 0
  | _ :: t -> 1 + count t

let () = printf "%d\n" (count [High; Low])

module Table = struct let size = 2 end
