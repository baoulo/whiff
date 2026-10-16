// Tide model
module Harbour.Tides

open System
open System.Collections.Generic

type Tide = { Hour: int; Height: float }

let rec count xs =
    match xs with
    | [] -> 0
    | _ :: t -> 1 + count t

(* block comment *)
let inline double x = x * 2.0
