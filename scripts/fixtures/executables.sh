#!/usr/bin/env bash
# Regenerate the executable fixtures under tests/fixtures/<format>/.
#
# Real toolchains build them from one small program that prints a
# fictitious harbour's tide table (Saltmere Harbour):
# * Linux (a Debian container run with podman, image `whiff-exec`, built
#   from the Containerfile below): gcc for ELF executables (hardened and
#   not), a shared library, objects with DWARF and a core dump (gdb's
#   `generate-core-file`); clang for objects of other architectures
#   (x86-64, RISC-V, 32-bit ARM, big-endian PowerPC) and eBPF; mingw-w64
#   for PE executables (with a version resource and a manifest), a DLL, a
#   32-bit build and a COFF object; osslsigncode for an Authenticode
#   signature with a throwaway self-signed key; makensis for an NSIS
#   installer; clang / wasm-ld and wat2wasm for WebAssembly;
# * macOS: clang, lipo and codesign for Mach-O executables (thin and
#   universal), a dylib, an object with DWARF, and ad-hoc signatures with
#   the hardened runtime and entitlements.
# craft_executables.py writes what no tool here writes (MS-DOS MZ, NE and
# LE headers, a .NET CLI header).
#
#     scripts/fixtures/executables.sh
#
# Containerfile (`podman build -t whiff-exec`):
#
#     FROM docker.io/library/debian:trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#         gcc libc6-dev binutils gcc-mingw-w64-x86-64 gcc-mingw-w64-i686 binutils-mingw-w64 \
#         clang lld llvm osslsigncode nsis wabt gdb file python3 openssl ca-certificates

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
craft="$root/scripts/fixtures/craft_executables.py"
work="$root/target/exec-fixtures"
rm -rf "$work"
mkdir -p "$work"
trap 'rm -rf "$work"' EXIT
export TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=1756728000

for d in elf elf_core ebpf pe dotnet dos_exe coff macho wasm; do
    mkdir -p "$fx/$d"
done

cat >"$work/tides.c" <<'EOF'
#include <stdio.h>
#include <string.h>

const char *harbour = "Saltmere Harbour";

int tide_metres(int hour) { return hour % 12 < 6 ? 4 : 1; }

int main(int argc, char **argv) {
    char line[64];
    for (int h = 0; h < 24; h += 6) {
        snprintf(line, sizeof line, "%s %02d:00 %d m", harbour, h, tide_metres(h));
        puts(line);
    }
    return argc > 1 && strcmp(argv[1], "--crash") == 0 ? (__builtin_trap(), 1) : 0;
}
EOF
# Freestanding (no headers) for the cross-compiled objects.
cat >"$work/tide.c" <<'EOF'
const char harbour[] = "Saltmere Harbour";
int tide_metres(int hour) { return hour % 12 < 6 ? 4 : 1; }
EOF
cat >"$work/lib.c" <<'EOF'
const char *harbour_name(void) { return "Saltmere Harbour"; }
int high_water(int day) { return 612 + day * 50 % 720; }
EOF
cat >"$work/xdp.c" <<'EOF'
#define SEC(n) __attribute__((section(n), used))
SEC("xdp") int tides_pass(void *ctx) { return 2; }
SEC("license") char licence[] = "Dual MIT/GPL";
EOF
cat >"$work/tides.rc" <<'EOF'
1 VERSIONINFO
FILEVERSION 1,2,0,0
PRODUCTVERSION 1,2,0,0
FILEOS 0x40004
FILETYPE 1
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "Saltmere Harbour Authority"
      VALUE "FileDescription", "Saltmere tide table"
      VALUE "FileVersion", "1.2.0.0"
      VALUE "InternalName", "tides"
      VALUE "LegalCopyright", "CC0 1.0, Saltmere Harbour Authority"
      VALUE "OriginalFilename", "tides.exe"
      VALUE "ProductName", "Saltmere Tides"
      VALUE "ProductVersion", "1.2"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
1 24 "tides.manifest"
EOF
cat >"$work/tides.manifest" <<'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Saltmere.Tides" version="1.2.0.0"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/></application>
  </compatibility>
</assembly>
EOF
cat >"$work/installer.nsi" <<'EOF'
Name "Saltmere Tides"
OutFile "tides-setup.exe"
InstallDir "$TEMP\SaltmereTides"
RequestExecutionLevel user
SetCompressor /SOLID lzma
Section
  SetOutPath "$INSTDIR"
  File "tides.txt"
SectionEnd
EOF
printf 'Saltmere tide table\nHigh water 06:12, low water 12:31\n' >"$work/tides.txt"
cat >"$work/tides.wat" <<'EOF'
(module $saltmere_tides
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1 4)
  (data (i32.const 16) "Saltmere Harbour 06:12 4 m\n")
  (func $tide_metres (export "tide_metres") (param $hour i32) (result i32)
    (select (i32.const 4) (i32.const 1) (i32.lt_u (i32.rem_u (local.get $hour) (i32.const 12)) (i32.const 6))))
  (func $main (export "_start")
    (i32.store (i32.const 0) (i32.const 16))
    (i32.store (i32.const 4) (i32.const 27))
    (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))
EOF
cp "$craft" "$work/craft_executables.py"

lx() { podman run --rm -e TZ=UTC -e SOURCE_DATE_EPOCH=1756728000 -v "$work:/w" -w /w whiff-exec bash -euo pipefail -c "$1"; }

# ------------------------------------------------------------ ELF
lx '
gcc -O2 -g0 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now -Wl,--build-id=sha1 \
    -o tides-hardened tides.c
strip tides-hardened
gcc -O0 -fno-stack-protector -no-pie -Wl,-z,norelro -Wl,-z,execstack -Wl,--build-id=sha1 -o tides-plain tides.c
gcc -O2 -fPIC -shared -Wl,-soname,libsaltmere.so.1 -Wl,-rpath,"\$ORIGIN" -Wl,--build-id=sha1 -o libsaltmere.so.1 lib.c
gcc -O1 -g -c -o tides.o tides.c
clang --target=x86_64-linux-gnu -O2 -g -c -o tide-x86_64.o tide.c
clang --target=riscv64-linux-gnu -O2 -c -o tide-riscv64.o tide.c
clang --target=armv7-linux-gnueabihf -O2 -c -o tide-armv7.o tide.c
clang --target=powerpc64-linux-gnu -O2 -c -o tide-ppc64.o tide.c
clang --target=bpf -O2 -c -o tides-xdp.bpf.o xdp.c
# A core dump of the tide program stopped by its trap.
gcc -O1 -static -o tides-static tides.c
gdb -q -batch -ex "run --crash > /dev/null" -ex "generate-core-file tides.core" ./tides-static >/dev/null 2>&1 || true
'
cp "$work/tides-hardened" "$fx/elf/tides-gcc-hardened"
cp "$work/tides-plain" "$fx/elf/tides-gcc-plain"
cp "$work/libsaltmere.so.1" "$fx/elf/libsaltmere.so.1"
cp "$work/tides.o" "$fx/elf/tides-gcc-dwarf.o"
for a in x86_64 riscv64 armv7 ppc64; do cp "$work/tide-$a.o" "$fx/elf/tide-clang-$a.o"; done
cp "$work/tides-xdp.bpf.o" "$fx/ebpf/tides-xdp.bpf.o"
python3 "$craft" trim-core "$work/tides.core" "$fx/elf_core/tides.core"

# ------------------------------------------------------------ PE, COFF, NSIS
lx '
x86_64-w64-mingw32-windres tides.rc -O coff -o tides-res.o
x86_64-w64-mingw32-gcc -O2 -s -Wl,--no-insert-timestamp -Wl,--dynamicbase,--nxcompat,--high-entropy-va \
    -o tides.exe tides.c tides-res.o
i686-w64-mingw32-gcc -O2 -s -Wl,--no-insert-timestamp -o tides32.exe tides.c
x86_64-w64-mingw32-gcc -O2 -s -shared -Wl,--no-insert-timestamp -o saltmere.dll lib.c
x86_64-w64-mingw32-gcc -O2 -c -o tides.obj tides.c
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=Saltmere Harbour Test Signing/O=Saltmere Harbour Authority/C=GB" \
    -addext "extendedKeyUsage=codeSigning" -keyout sign.key -out sign.crt 2>/dev/null
osslsigncode sign -certs sign.crt -key sign.key -n "Saltmere Tides" -i https://saltmere.example/ -h sha256 \
    -in tides.exe -out tides-signed.exe >/dev/null
makensis -V1 installer.nsi
'
cp "$work/tides.exe" "$fx/pe/tides-mingw64.exe"
cp "$work/tides32.exe" "$fx/pe/tides-mingw32.exe"
cp "$work/saltmere.dll" "$fx/pe/saltmere-mingw64.dll"
cp "$work/tides-signed.exe" "$fx/pe/tides-signed.exe"
cp "$work/tides-setup.exe" "$fx/pe/tides-setup-nsis.exe"
cp "$work/tides.obj" "$fx/coff/tides-mingw64.obj"
python3 "$craft" dos "$fx/dos_exe/tides-mz.exe"
python3 "$craft" ne "$fx/dos_exe/tides-ne.exe"
python3 "$craft" le "$fx/dos_exe/tides-le.vxd"
python3 "$craft" dotnet "$fx/dotnet/tides-cli.dll"

# ------------------------------------------------------------ WebAssembly
lx '
clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -Wl,--export=tide_metres -o tides-clang.wasm tide.c
wat2wasm --debug-names -o tides-wasi.wasm tides.wat
'
cp "$work/tides-clang.wasm" "$fx/wasm/tides-clang.wasm"
cp "$work/tides-wasi.wasm" "$fx/wasm/tides-wasi.wasm"

# ------------------------------------------------------------ Mach-O (macOS)
cd "$work"
clang -O2 -arch arm64 -mmacosx-version-min=12.0 -o tides-arm64 tides.c
clang -O2 -arch x86_64 -mmacosx-version-min=10.15 -o tides-x86_64 tides.c
lipo -create -output tides-universal tides-arm64 tides-x86_64
clang -O2 -arch arm64 -dynamiclib -install_name @rpath/libsaltmere.dylib -current_version 1.2 \
    -compatibility_version 1.0 -Wl,-rpath,@loader_path -o libsaltmere.dylib lib.c
clang -O1 -g -arch arm64 -c -o tides-macho.o tides.c
cat >entitlements.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.app-sandbox</key><true/>
  <key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>
EOF
cp tides-arm64 tides-runtime
codesign -f -s - -i org.example.saltmere.tides -o runtime --entitlements entitlements.plist tides-runtime
codesign -f -s - -i org.example.saltmere.tides tides-universal
cp tides-arm64 "$fx/macho/tides-clang-arm64"
cp tides-universal "$fx/macho/tides-clang-universal"
cp tides-runtime "$fx/macho/tides-clang-runtime"
cp libsaltmere.dylib "$fx/macho/libsaltmere.dylib"
cp tides-macho.o "$fx/macho/tides-clang-dwarf.o"

ls -l "$fx"/{elf,elf_core,ebpf,pe,dotnet,dos_exe,coff,macho,wasm}
