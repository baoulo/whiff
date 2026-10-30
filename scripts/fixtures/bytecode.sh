#!/usr/bin/env bash
# Regenerate the bytecode fixtures under tests/fixtures/<format>/.
#
# Real compilers build them from small programs that print a fictitious
# harbour's tide table (Saltmere Harbour):
# * a Debian container run with podman (image `whiff-bytecode`, built from
#   the Containerfile below): javac for class files (a module, a record, a
#   sealed interface, an annotation, Java 8 without debug information); d8
#   (R8, downloaded from Google's Maven repository, Apache-2.0) for DEX;
#   luac 5.1 to 5.4 and LuaJIT; erlc; Emacs's byte compiler; mrbc; Ruby's
#   instruction-sequence dump; ocamlc;
# * the .NET SDK image (mcr.microsoft.com/dotnet/sdk:8.0) for an assembly
#   with assembly attributes, references and a P/Invoke import;
# * the Python images (python:3.8-slim, 3.12-slim, 3.14-slim) and Debian's
#   Python 3.13 for .pyc files with timestamp and hash-based headers.
#
#     scripts/fixtures/bytecode.sh
#
# Containerfile (`podman build -t whiff-bytecode`):
#
#     FROM docker.io/library/debian:trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#         openjdk-21-jdk-headless python3 lua5.1 lua5.2 lua5.3 lua5.4 luajit erlang-base emacs-nox \
#         mruby ocaml-nox ruby wget unzip ca-certificates file

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work="$root/target/bytecode-fixtures"
rm -rf "$work"
mkdir -p "$work"
trap 'rm -rf "$work"' EXIT
export TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=1756728000
r8=8.5.35

for d in class dex pyc luac beam elc mruby yarv ocaml_bytecode; do
    mkdir -p "$fx/$d"
done
lx() { podman run --rm -e TZ=UTC -e SOURCE_DATE_EPOCH=1756728000 -v "$work:/w" -w /w "${2:-whiff-bytecode}" bash -euo pipefail -c "$1"; }

# ------------------------------------------------------------------- Java
mkdir -p "$work/java/org/example/saltmere/tides" "$work/java8"
cat >"$work/java/module-info.java" <<'EOF'
/** Tide tables for Saltmere Harbour. */
module org.example.saltmere {
    requires java.logging;
    exports org.example.saltmere.tides;
}
EOF
cat >"$work/java/org/example/saltmere/tides/Tide.java" <<'EOF'
package org.example.saltmere.tides;

/** A high or low tide. */
public sealed interface Tide permits Tide.High, Tide.Low {
    int hour();

    record High(int hour, double metres) implements Tide {}

    record Low(int hour, double metres) implements Tide {}
}
EOF
cat >"$work/java/org/example/saltmere/tides/Gauge.java" <<'EOF'
package org.example.saltmere.tides;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/** The tide gauge a reading came from. */
@Retention(RetentionPolicy.RUNTIME)
public @interface Gauge {
    String value();
}
EOF
cat >"$work/java/org/example/saltmere/tides/TideTable.java" <<'EOF'
package org.example.saltmere.tides;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/** Prints the day's tides for Saltmere Harbour. */
@Gauge("Saltmere pier")
public final class TideTable {
    private static final Logger LOG = Logger.getLogger("saltmere");
    private final List<Tide> tides = new ArrayList<>();

    public void add(Tide t) {
        tides.add(t);
    }

    public static void main(String[] args) {
        TideTable table = new TideTable();
        for (int h = 0; h < 24; h += 6) {
            table.add(h % 12 < 6 ? new Tide.High(h, 4.2) : new Tide.Low(h, 0.9));
        }
        table.tides.forEach(t -> LOG.info("Saltmere Harbour " + t));
    }
}
EOF
cat >"$work/java8/Tides.java" <<'EOF'
public class Tides {
    static int metres(int hour) {
        return hour % 12 < 6 ? 4 : 1;
    }

    public static void main(String[] args) {
        for (int h = 0; h < 24; h += 6) {
            System.out.println("Saltmere Harbour " + h + ":00 " + metres(h) + " m");
        }
    }
}
EOF
lx "
javac --release 21 -g -d out/mod \$(find java -name '*.java')
javac --release 8 -g:none -d out/j8 java8/Tides.java
javac --release 8 -g -d out/j8g java8/Tides.java
wget -q -O r8.jar https://dl.google.com/android/maven2/com/android/tools/r8/$r8/r8-$r8.jar
mkdir -p dex21 dex28
java -cp r8.jar com.android.tools.r8.D8 --release --min-api 21 --output dex21 out/j8/Tides.class
java -cp r8.jar com.android.tools.r8.D8 --debug --min-api 28 --output dex28 out/j8g/Tides.class
"
cp "$work/out/mod/module-info.class" "$fx/class/module-info.class"
cp "$work/out/mod/org/example/saltmere/tides/TideTable.class" "$fx/class/TideTable.class"
cp "$work/out/mod/org/example/saltmere/tides/Tide.class" "$fx/class/Tide.class"
cp "$work/out/mod/org/example/saltmere/tides/Tide\$High.class" "$fx/class/Tide\$High.class"
cp "$work/out/mod/org/example/saltmere/tides/Gauge.class" "$fx/class/Gauge.class"
cp "$work/out/j8/Tides.class" "$fx/class/Tides-java8.class"
cp "$work/dex21/classes.dex" "$fx/dex/tides-release.dex"
cp "$work/dex28/classes.dex" "$fx/dex/tides-debug.dex"

# ----------------------------------------------------------------- Python
cat >"$work/tides.py" <<'EOF'
"""Tide table for Saltmere Harbour."""

import json
from datetime import time


class Tide:
    def __init__(self, hour, metres):
        self.hour, self.metres = hour, metres


def table():
    return [Tide(h, 4.2 if h % 12 < 6 else 0.9) for h in range(0, 24, 6)]


if __name__ == "__main__":
    print(json.dumps([(str(time(t.hour)), t.metres) for t in table()]))
EOF
touch -t 202509011200 "$work/tides.py"
pyc() { # image, invalidation mode, output
    lx "env -u SOURCE_DATE_EPOCH python3 -c \"import py_compile as p; p.compile('tides.py', 'out.pyc', dfile='tides.py', invalidation_mode=p.PycInvalidationMode.$2)\"" "$1"
    cp "$work/out.pyc" "$fx/pyc/$3"
}
pyc docker.io/library/python:3.8-slim TIMESTAMP tides.cpython-38.pyc
pyc docker.io/library/python:3.12-slim UNCHECKED_HASH tides.cpython-312.pyc
pyc whiff-bytecode TIMESTAMP tides.cpython-313.pyc
pyc docker.io/library/python:3.14-slim CHECKED_HASH tides.cpython-314.pyc

# ------------------------------------------------- Lua, Erlang, Emacs Lisp, Ruby, OCaml
cat >"$work/tides.lua" <<'EOF'
-- Tide table for Saltmere Harbour.
local function metres(hour) if hour % 12 < 6 then return 4.2 else return 0.9 end end
for h = 0, 23, 6 do print(("Saltmere Harbour %02d:00 %.1f m"):format(h, metres(h))) end
EOF
cat >"$work/tides.erl" <<'EOF'
%% Tide table for Saltmere Harbour.
-module(tides).
-behaviour(application).
-vsn("1.2.0").
-export([start/2, stop/1, table/0]).

start(_Type, _Args) -> io:format("~p~n", [table()]), {ok, self()}.
stop(_State) -> ok.
table() -> [{H, metres(H)} || H <- lists:seq(0, 23, 6)].
metres(H) when H rem 12 < 6 -> 4.2;
metres(_) -> 0.9.
EOF
cat >"$work/tides.el" <<'EOF'
;;; tides.el --- Tide table for Saltmere Harbour  -*- lexical-binding: t -*-

(defun tides-metres (hour)
  "Tide height in metres at HOUR."
  (if (< (% hour 12) 6) 4.2 0.9))

(defun tides-table ()
  "Print the day's tides for Saltmere Harbour."
  (dolist (h '(0 6 12 18))
    (message "Saltmere Harbour %02d:00 %.1f m" h (tides-metres h))))

(provide 'tides)
;;; tides.el ends here
EOF
cat >"$work/tides.rb" <<'EOF'
# Tide table for Saltmere Harbour.
def metres(hour) = hour % 12 < 6 ? 4.2 : 0.9
0.step(23, 6) { |h| puts format("Saltmere Harbour %02d:00 %.1f m", h, metres(h)) }
EOF
sed 's/def metres(hour) = \(.*\)$/def metres(hour); \1; end/' "$work/tides.rb" >"$work/tides-mruby.rb"
cat >"$work/tides.ml" <<'EOF'
(* Tide table for Saltmere Harbour. *)
let metres hour = if hour mod 12 < 6 then 4.2 else 0.9
let () = List.iter (fun h -> Printf.printf "Saltmere Harbour %02d:00 %.1f m\n" h (metres h)) [0; 6; 12; 18]
EOF
lx "
luac5.1 -o tides-5.1.luac tides.lua
luac5.2 -o tides-5.2.luac tides.lua
luac5.3 -o tides-5.3.luac tides.lua
luac5.4 -s -o tides-5.4-stripped.luac tides.lua
luajit -b -g tides.lua tides-luajit.luac
erlc +debug_info tides.erl
emacs -Q --batch -f batch-byte-compile tides.el
mrbc -g -o tides.mrb tides-mruby.rb
ruby -e 'File.binwrite(\"tides.yarb\", RubyVM::InstructionSequence.compile_file(\"tides.rb\").to_binary)'
ocamlc -c tides.ml
"
cp "$work"/tides-5.1.luac "$work"/tides-5.2.luac "$work"/tides-5.3.luac "$work"/tides-5.4-stripped.luac \
    "$work"/tides-luajit.luac "$fx/luac/"
cp "$work/tides.beam" "$fx/beam/tides.beam"
cp "$work/tides.elc" "$fx/elc/tides.elc"
cp "$work/tides.mrb" "$fx/mruby/tides.mrb"
cp "$work/tides.yarb" "$fx/yarv/tides.yarb"
cp "$work/tides.cmi" "$work/tides.cmo" "$fx/ocaml_bytecode/"

# -------------------------------------------------------------------- .NET
mkdir -p "$work/net"
cat >"$work/net/Saltmere.Tides.csproj" <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>Saltmere.Tides</AssemblyName>
    <Version>1.2.0</Version>
    <Company>Saltmere Harbour Board</Company>
    <Product>Saltmere Tides</Product>
    <Description>Tide table for Saltmere Harbour.</Description>
    <Copyright>Public domain (CC0-1.0)</Copyright>
    <Deterministic>true</Deterministic>
    <DebugType>embedded</DebugType>
    <PathMap>$(MSBuildProjectDirectory)=/_/</PathMap>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
    <ImplicitUsings>disable</ImplicitUsings>
    <IncludeSourceRevisionInInformationalVersion>false</IncludeSourceRevisionInInformationalVersion>
  </PropertyGroup>
</Project>
EOF
cat >"$work/net/Tides.cs" <<'EOF'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Saltmere.Tides
{
    /// <summary>A tide reading.</summary>
    public record Tide(int Hour, double Metres);

    public static class TideTable
    {
        [DllImport("libc", EntryPoint = "getpid")]
        private static extern int ProcessId();

        public static IEnumerable<Tide> Today()
        {
            for (int h = 0; h < 24; h += 6)
                yield return new Tide(h, h % 12 < 6 ? 4.2 : 0.9);
        }

        public static void Print()
        {
            foreach (var t in Today())
                Console.WriteLine($"Saltmere Harbour {t.Hour:00}:00 {t.Metres:0.0} m ({ProcessId()})");
        }
    }
}
EOF
lx "cd net && DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet build -c Release -o ../netout >/dev/null" \
    mcr.microsoft.com/dotnet/sdk:8.0
cp "$work/netout/Saltmere.Tides.dll" "$fx/dotnet/Saltmere.Tides.dll"

ls -l "$fx"/{class,dex,pyc,luac,beam,elc,mruby,yarv,ocaml_bytecode} "$fx/dotnet"
