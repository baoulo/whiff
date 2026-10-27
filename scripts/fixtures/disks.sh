#!/usr/bin/env bash
# Regenerate the disk image fixtures under tests/fixtures/<format>/.
#
# Real tools write them: on Linux (a Debian container run with podman)
# sgdisk, sfdisk, mkfs.fat + mtools, mke2fs, mkudffs, cryptsetup,
# xorriso, genisoimage, mksquashfs, img2simg, mkbootimg, mkimage, dtc,
# ewfacquire, objcopy and srec_cat; on the podman VM itself (as root,
# for loop mounts) mount / cp to fill UDF volumes; on macOS hdiutil,
# newfs_exfat, newfs_hfs and newfs_apfs; and qemu-img for the VM formats.
# craft_disks.py writes the formats no tool here writes (see its
# docstring). Images bigger than the 256 KiB fixture limit (NTFS, VHDX,
# the 1 MiB VDI block, the 2 MiB VHD block) are kept as their first
# 256 KiB, which holds every structure whiff reads but the data past it;
# SOURCE.md says which. The Amiga and C64 images come from amitools'
# xdftool and the d64 package (`pip install amitools d64`, on PATH).
#
# The podman image is built from the Containerfile below
# (`podman build -t whiff-fixtures`), and copied to the VM's root
# storage once (`podman save whiff-fixtures | podman machine ssh sudo
# podman load`). The volumes hold a fictitious harbour's tide table
# (Saltmere Harbour). Run from the repository root:
#
#     scripts/fixtures/disks.sh
#
# Containerfile:
#
#     FROM docker.io/library/debian:trixie
#     RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#         e2fsprogs squashfs-tools u-boot-tools ewf-tools android-sdk-libsparse-utils mkbootimg \
#         dosfstools mtools ntfs-3g btrfs-progs xfsprogs cryptsetup-bin xorriso genisoimage udftools \
#         gdisk fdisk device-tree-compiler srecord binutils f2fs-tools python3 file

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
craft="$root/scripts/fixtures/craft_disks.py"
# Under the repository (shared with the podman VM), not /tmp.
work="$root/target/disk-fixtures"
rm -rf "$work"
mkdir -p "$work/src/docs" "$work/src/charts/2025"
trap 'rm -rf "$work"' EXIT
export TZ=UTC LC_ALL=C COPYFILE_DISABLE=1 SOURCE_DATE_EPOCH=1756728000
stamp=202509011200

for d in raw_disk ext fat exfat ntfs hfs_plus apfs luks iso9660 udf vdi vmdk vhd vhdx qcow2 qed sparseimage \
    e01 aff android_sparse android_boot uimage fit intel_hex srec uefi_capsule ova ovf cd_bin ccd adf d64 squashfs snap appimage flatpakref; do
    mkdir -p "$fx/$d"
done

# The files every volume holds.
printf 'Saltmere tide table\nHigh water 06:12, low water 12:31\n' >"$work/src/tides.txt"
printf '# Saltmere\n\nTide tables for Saltmere harbour.\n' >"$work/src/docs/readme.md"
printf 'month,high,low\n2025-09,4.2,0.6\n' >"$work/src/charts/2025/september.csv"
find "$work/src" -exec touch -t "$stamp" {} +
cp "$craft" "$work/craft_disks.py"

# Run a script in the Linux container (`/w` is the work folder).
lx() { podman run --rm -e TZ=UTC -e E2FSPROGS_FAKE_TIME=1756728000 -v "$work:/w" -w /w whiff-fixtures bash -euo pipefail -c "$1"; }
# Run a script as root on the podman VM (loop mounts).
vmroot() { podman machine ssh "sudo bash -euo pipefail -c 'cd $work && $1'"; }
# Keep the first 256 KiB of an image.
head256() { head -c 262144 "$1" >"$2"; }

# ------------------------------------------------------------ raw disks

# GPT: an empty EFI system partition and a FAT12 data partition.
lx '
: > gpt.img; truncate -s 192k gpt.img
sgdisk -a 8 -o -n 1:40:+32K -t 1:ef00 -c 1:"EFI System" -n 2:0:0 -t 2:0700 -c 2:"Tides" gpt.img >/dev/null
first=$(sgdisk -i 2 gpt.img | sed -n "s/^First sector: \([0-9]*\).*/\1/p")
last=$(sgdisk -i 2 gpt.img | sed -n "s/^Last sector: \([0-9]*\).*/\1/p")
mkfs.fat -F 12 -n SALTMERE -i 5a17e2e0 --invariant --offset "$first" gpt.img $(( (last - first + 1) / 2 )) >/dev/null
o=$((first * 512))
mcopy -m -s -i "gpt.img@@$o" src/tides.txt src/docs ::/
'
cp "$work/gpt.img" "$fx/raw_disk/saltmere-gpt.img"

# MBR: an ext2 primary partition, and swap in a logical partition.
lx '
: > mbr.img; truncate -s 240k mbr.img
printf "label: dos\nlabel-id: 0x5a17e2e0\nstart=2, size=300, type=83, bootable\nstart=310, type=5\nstart=312, type=82\n" | sfdisk -q mbr.img
mke2fs -q -F -t ext2 -b 1024 -N 32 -L harbour -U 5a17e2e0-0000-4000-8000-000000000001 -E offset=1024 -d src mbr.img 150
mkswap -q -L tidal-swap -U 5a17e2e0-0000-4000-8000-000000000002 --offset $((312 * 512)) mbr.img 2>/dev/null \
    || mkswap -L tidal-swap -U 5a17e2e0-0000-4000-8000-000000000002 --offset $((312 * 512)) mbr.img >/dev/null
'
cp "$work/mbr.img" "$fx/raw_disk/saltmere-mbr.img"

# ------------------------------------------------------------ file-system images

lx '
mke2fs -q -F -t ext2 -b 1024 -N 32 -L saltmere -U 5a17e2e0-0000-4000-8000-000000000003 -d src ext2.img 128
mke2fs -q -F -t ext4 -O ^has_journal -b 1024 -N 64 -L saltmere-ext4 -U 5a17e2e0-0000-4000-8000-000000000004 -d src ext4.img 192
mkfs.fat -C -F 12 -n TIDES -i 5a17e2e0 --invariant fat12.img 160 >/dev/null
mcopy -m -s -i fat12.img src/tides.txt src/docs src/charts ::/
mcopy -m -i fat12.img src/tides.txt "::/High water at Saltmere.txt"
: > ntfs.img; truncate -s 2M ntfs.img
mkntfs -q -F -f -L Saltmere -s 512 -c 512 ntfs.img >/dev/null 2>&1
ntfscp -q ntfs.img src/tides.txt tides.txt
printf "saltmere-fixture" > luks.key
: > luks.img; truncate -s 256k luks.img
cryptsetup luksFormat -q --type luks2 --label saltmere-vault --uuid 5a17e2e0-0000-4000-8000-000000000005 \
    --luks2-metadata-size 16k --luks2-keyslots-size 128k --cipher aes-xts-plain64 --key-size 256 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    --key-file luks.key luks.img
'
cp "$work/ext2.img" "$fx/ext/saltmere.ext2"
cp "$work/ext4.img" "$fx/ext/saltmere.ext4"
cp "$work/fat12.img" "$fx/fat/saltmere-floppy.ima"
head256 "$work/ntfs.img" "$fx/ntfs/saltmere-head.ntfs"
cp "$work/luks.img" "$fx/luks/saltmere-vault.luks"

# macOS volumes: a raw image attached without mounting, formatted, filled.
macvol() { # kind size newfs...
    local kind=$1 size=$2
    shift 2
    : >"$work/$kind.img"
    truncate -s "$size" "$work/$kind.img"
    local dev
    dev=$(hdiutil attach -nomount -imagekey diskimage-class=CRawDiskImage "$work/$kind.img" | awk 'NR==1 {print $1}')
    "$@" "$dev" >/dev/null
    hdiutil detach "$dev" >/dev/null
    local mnt
    mnt=$(hdiutil attach -imagekey diskimage-class=CRawDiskImage "$work/$kind.img" | awk -F'\t' 'END {print $NF}')
    cp -R "$work/src/." "$mnt/" 2>/dev/null || true
    hdiutil detach "$(hdiutil info | awk -v m="$mnt" '$NF == m {print $1}')" >/dev/null 2>&1 || diskutil unmount "$mnt" >/dev/null
    ls -l "$work/$kind.img"
}
macvol exfat 256k newfs_exfat -v TIDES
macvol hfs 512k newfs_hfs -v Saltmere
macvol hfsx 512k newfs_hfs -s -v Saltmere
macvol apfs 1m newfs_apfs -v Saltmere
cp "$work/exfat.img" "$fx/exfat/saltmere.exfat"
head256 "$work/hfs.img" "$fx/hfs_plus/saltmere-head.hfs"
head256 "$work/hfsx.img" "$fx/hfs_plus/saltmere-case-head.hfsx"
head256 "$work/apfs.img" "$fx/apfs/saltmere-head.apfs"

# ------------------------------------------------------------ VM disks (qemu-img)

q() { qemu-img "$@" >/dev/null; }
q convert -O qcow2 -o cluster_size=4096 "$work/gpt.img" "$fx/qcow2/saltmere.qcow2"
q convert -c -O qcow2 -o cluster_size=4096,compat=1.1 "$work/gpt.img" "$work/c.qcow2"
q snapshot -c "harbour survey" "$work/c.qcow2"
cp "$work/c.qcow2" "$fx/qcow2/saltmere-compressed.qcow2"
q create -f qcow2 -u -o cluster_size=4096 -b saltmere.qcow2 -F qcow2 "$work/overlay.qcow2" 192k
cp "$work/overlay.qcow2" "$fx/qcow2/saltmere-overlay.qcow2"
q convert -O qcow "$work/gpt.img" "$fx/qcow2/saltmere-v1.qcow"
q convert -O qed -o cluster_size=4096,table_size=4 "$work/gpt.img" "$fx/qed/saltmere.qed"
q convert -O vmdk "$work/gpt.img" "$work/sparse.vmdk"
cp "$work/sparse.vmdk" "$fx/vmdk/saltmere-sparse.vmdk"
q convert -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic "$work/gpt.img" "$fx/vmdk/saltmere-stream.vmdk"
q convert -O vmdk -o subformat=monolithicFlat "$work/gpt.img" "$work/flat.vmdk"
cp "$work/flat.vmdk" "$fx/vmdk/saltmere-descriptor.vmdk"
q convert -O vpc -o subformat=fixed "$work/gpt.img" "$fx/vhd/saltmere-fixed.vhd"
q convert -O vpc "$work/gpt.img" "$work/dynamic.vhd"
head256 "$work/dynamic.vhd" "$fx/vhd/saltmere-dynamic-head.vhd"
q convert -O vhdx "$work/gpt.img" "$work/disk.vhdx"
head256 "$work/disk.vhdx" "$fx/vhdx/saltmere-head.vhdx"
q convert -O vdi "$work/gpt.img" "$work/disk.vdi"
head256 "$work/disk.vdi" "$fx/vdi/saltmere-head.vdi"
hdiutil convert "$work/gpt.img" -format UDSP -imagekey sparse-band-size=64 -o "$work/sparse" >/dev/null
cp "$work/sparse.sparseimage" "$fx/sparseimage/saltmere.sparseimage"

# ------------------------------------------------------------ virtual appliance

# The descriptor is written here in the shape VirtualBox exports (OVF 1.0
# with vbox extensions left out); bsdtar packs it with a SHA-256 manifest
# and the stream-optimised disk, descriptor first, as OVA requires.
mkdir -p "$work/ova"
cp "$fx/vmdk/saltmere-stream.vmdk" "$work/ova/saltmere-disk1.vmdk"
disk_size=$(wc -c <"$work/ova/saltmere-disk1.vmdk" | tr -d ' ')
cat >"$work/ova/saltmere-gauge.ovf" <<OVF
<?xml version="1.0"?>
<Envelope ovf:version="1.0" xml:lang="en-US" xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:id="file1" ovf:href="saltmere-disk1.vmdk" ovf:size="$disk_size"/>
  </References>
  <DiskSection>
    <Info>List of the virtual disks used in the package</Info>
    <Disk ovf:capacity="196608" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>Logical networks used in the package</Info>
    <Network ovf:name="Harbour">
      <Description>Harbour office network</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="saltmere-gauge">
    <Info>A virtual machine</Info>
    <ProductSection>
      <Info>Meta-information about the installed software</Info>
      <Product>Saltmere Tide Gauge</Product>
      <Vendor>Saltmere Harbour Office</Vendor>
      <Version>1.2.0</Version>
      <ProductUrl>https://example.org/saltmere/gauge</ProductUrl>
    </ProductSection>
    <AnnotationSection>
      <Info>A human-readable annotation</Info>
      <Annotation>Logs and serves the harbour tide gauge readings.</Annotation>
    </AnnotationSection>
    <EulaSection>
      <Info>License agreement for the virtual system</Info>
      <License>Released under CC0-1.0.</License>
    </EulaSection>
    <OperatingSystemSection ovf:id="96">
      <Info>The kind of installed guest operating system</Info>
      <Description>Debian_64</Description>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements for a virtual machine</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>saltmere-gauge</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>virtualbox-2.2</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:Caption>2 virtual CPU</rasd:Caption>
        <rasd:ElementName>2 virtual CPU</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>2</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>MegaBytes</rasd:AllocationUnits>
        <rasd:ElementName>512 MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>512</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>Harbour</rasd:Connection>
        <rasd:ElementName>Ethernet adapter on Harbour</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>E1000</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:ElementName>disk1</rasd:ElementName>
        <rasd:HostResource>/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
OVF
(cd "$work/ova" && for f in saltmere-gauge.ovf saltmere-disk1.vmdk; do
    printf 'SHA256(%s)= %s\n' "$f" "$(shasum -a 256 "$f" | cut -d' ' -f1)"
done >saltmere-gauge.mf)
touch -t "$stamp" "$work"/ova/*
bsdtar --format ustar --uid 0 --gid 0 --uname "" --gname "" -cf "$fx/ova/saltmere-gauge.ova" -C "$work/ova" \
    saltmere-gauge.ovf saltmere-gauge.mf saltmere-disk1.vmdk
cp "$work/ova/saltmere-gauge.ovf" "$fx/ovf/saltmere-gauge.ovf"

# ------------------------------------------------------------ evidence files

lx '
ewfacquire -u -q -t ev -C "HB-2025-07" -D "Tide gauge logger disk" -E "1" -e "R. Keel" \
    -N "Survey of the harbour tide gauge" -m removable -c deflate:best -f encase6 -d sha1 gpt.img >/dev/null
ewfacquire -u -q -t ev-fast -C "HB-2025-08" -D "Spare logger card" -E "2" -e "R. Keel" \
    -N "Uncompressed copy" -c none -f encase5 fat12.img >/dev/null
'
cp "$work/ev.E01" "$fx/e01/saltmere-gauge.E01"
cp "$work/ev-fast.E01" "$fx/e01/saltmere-card-encase5.E01"
python3 "$craft" aff "$work/gpt.img" "$fx/aff/saltmere-gauge.aff"

# ------------------------------------------------------------ Android

mkdir -p "$work/ramdisk"
printf 'on boot\n    start tides\n' >"$work/ramdisk/init.rc"
touch -t "$stamp" "$work/ramdisk/init.rc"
bsdtar --format newc --uid 0 --gid 0 -cf - -C "$work/ramdisk" init.rc | gzip -n -9 >"$work/ramdisk.cpio.gz"
lx '
img2simg ext4.img ext4.simg
python3 craft_disks.py kernel kernel
printf "/dts-v1/;\n/ { model = \"Saltmere tide gauge\"; compatible = \"saltmere,tg1\"; };\n" > board.dts
dtc -q -I dts -O dtb -o board.dtb board.dts
mkbootimg --header_version 2 --kernel kernel --ramdisk ramdisk.cpio.gz --dtb board.dtb --pagesize 2048 \
    --os_version 14.0.0 --os_patch_level 2025-09 --board saltmere --cmdline "console=ttyS0 androidboot.hardware=tg1" \
    -o boot-v2.img
mkbootimg --header_version 4 --kernel kernel --ramdisk ramdisk.cpio.gz --os_version 15.0.0 --os_patch_level 2025-09 \
    --cmdline "console=ttyS0" -o boot-v4.img
mkbootimg --header_version 4 --vendor_boot vendor_boot.img --vendor_ramdisk ramdisk.cpio.gz --dtb board.dtb \
    --board saltmere --vendor_cmdline "androidboot.hardware=tg1" --pagesize 4096
'
cp "$work/ext4.simg" "$fx/android_sparse/saltmere-ext4.simg"
cp "$work/boot-v2.img" "$fx/android_boot/saltmere-boot-v2.img"
cp "$work/boot-v4.img" "$fx/android_boot/saltmere-boot-v4.img"
cp "$work/vendor_boot.img" "$fx/android_boot/saltmere-vendor_boot.img"

# ------------------------------------------------------------ firmware

lx '
{ cat src/tides.txt; head -c 2000 /dev/zero; } > fw.bin
gzip -n -9 -c kernel > kernel.gz
mkimage -q -A arm64 -O linux -T kernel -C gzip -a 0x80000 -e 0x80000 -n "Saltmere TG-1 kernel" -d kernel.gz kernel.uimg
mkimage -q -A arm -O linux -T multi -C none -a 0 -e 0 -n "Saltmere TG-1 multi" -d kernel:ramdisk.cpio.gz multi.uimg >/dev/null
cat > tg1.its <<ITS
/dts-v1/;
/ {
    description = "Saltmere TG-1 firmware";
    #address-cells = <1>;
    images {
        kernel-1 {
            description = "Tide gauge kernel";
            data = /incbin/("kernel.gz");
            type = "kernel"; arch = "arm64"; os = "linux"; compression = "gzip";
            load = <0x80000>; entry = <0x80000>;
            hash-1 { algo = "sha256"; };
        };
        fdt-1 {
            description = "Tide gauge board";
            data = /incbin/("board.dtb");
            type = "flat_dt"; arch = "arm64"; compression = "none";
            hash-1 { algo = "crc32"; };
        };
    };
    configurations {
        default = "conf-1";
        conf-1 { description = "TG-1"; kernel = "kernel-1"; fdt = "fdt-1"; };
    };
};
ITS
mkimage -q -f tg1.its tg1.itb
objcopy -I binary -O ihex --change-addresses 0x08000000 fw.bin fw.hex
srec_cat fw.bin -binary -offset 0x8000 -header "Saltmere TG-1" -execution-start-address 0x8000 -o fw.s19 -Motorola
srec_cat fw.bin -binary -offset 0x00100000 -execution-start-address 0x00100000 -o fw.s37 -Motorola -address-length=4
'
cp "$work/kernel.uimg" "$fx/uimage/saltmere-kernel.uimg"
cp "$work/multi.uimg" "$fx/uimage/saltmere-multi.uimg"
cp "$work/tg1.itb" "$fx/fit/saltmere-tg1.itb"
cp "$work/fw.hex" "$fx/intel_hex/saltmere-fw.hex"
cp "$work/fw.s19" "$fx/srec/saltmere-fw.s19"
cp "$work/fw.s37" "$fx/srec/saltmere-fw.s37"
python3 "$craft" capsule "$work/fw.bin" "$fx/uefi_capsule/saltmere-fmp.cap"

# ------------------------------------------------------------ squashfs, Snap, AppImage, Flatpak

mkdir -p "$work/snap/meta/hooks" "$work/snap/bin" "$work/appdir/usr/bin" "$work/appdir/usr/share/metainfo"
cat >"$work/snap/meta/snap.yaml" <<'YAML'
name: saltmere-tides
version: '1.2.0'
summary: Tide tables for Saltmere harbour
description: |
  High and low water times for Saltmere harbour, from the harbour office.
license: CC0-1.0
base: core22
grade: stable
confinement: strict
architectures: [amd64]
apps:
  tides:
    command: bin/tides
    plugs: [network, home]
  gauge:
    command: bin/tides --serve
    daemon: simple
    plugs: [network-bind]
YAML
printf '#!/bin/sh
echo "High water 06:12"
' >"$work/snap/bin/tides"
printf '#!/bin/sh
exit 0
' >"$work/snap/meta/hooks/install"
chmod +x "$work/snap/bin/tides" "$work/snap/meta/hooks/install"
printf '#!/bin/sh
exec "$APPDIR/usr/bin/tides" "$@"
' >"$work/appdir/AppRun"
cp "$work/snap/bin/tides" "$work/appdir/usr/bin/tides"
chmod +x "$work/appdir/AppRun"
printf '[Desktop Entry]
Type=Application
Name=Saltmere Tides
Comment=Tide tables for Saltmere harbour
Exec=tides
Icon=tides
Categories=Utility;Education;
X-AppImage-Version=1.2.0
' >"$work/appdir/tides.desktop"
cat >"$work/appdir/usr/share/metainfo/org.example.saltmere.tides.appdata.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>org.example.saltmere.tides</id>
  <name>Saltmere Tides</name>
  <summary>Tide tables for Saltmere harbour</summary>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>CC0-1.0</project_license>
  <developer_name>Saltmere Harbour Office</developer_name>
  <url type="homepage">https://example.org/saltmere/tides</url>
</component>
XML
ln -sf usr/bin/tides "$work/appdir/tides"
find "$work/snap" "$work/appdir" -exec touch -h -t "$stamp" {} +
lx '
ln -sf tides.txt src/latest
for c in gzip xz zstd; do
    mksquashfs src sq-$c.squashfs -comp $c -all-root -mkfs-time 1756728000 -all-time 1756728000 -quiet -noappend >/dev/null
done
rm src/latest
# The options `snap pack` uses.
mksquashfs snap tides.snap -comp xz -all-root -no-xattrs -no-fragments -mkfs-time 1756728000 -quiet -noappend >/dev/null
mksquashfs appdir appdir.squashfs -comp gzip -root-owned -noappend -mkfs-time 1756728000 -quiet >/dev/null
'
for c in gzip xz zstd; do cp "$work/sq-$c.squashfs" "$fx/squashfs/saltmere-$c.squashfs"; done
cp "$work/tides.snap" "$fx/snap/saltmere-tides_1.2.0_amd64.snap"
python3 "$craft" appimage-runtime "$work/runtime"
cat "$work/runtime" "$work/appdir.squashfs" >"$fx/appimage/Saltmere_Tides-1.2.0-x86_64.AppImage"
cat >"$fx/flatpakref/org.example.saltmere.Tides.flatpakref" <<'REF'
[Flatpak Ref]
Name=org.example.saltmere.Tides
Branch=stable
Title=Saltmere Tides
IsRuntime=false
Url=https://example.org/saltmere/repo/
SuggestRemoteName=saltmere
RuntimeRepo=https://example.org/saltmere/runtimes.flatpakrepo
Homepage=https://example.org/saltmere/tides
Comment=Tide tables for Saltmere harbour
REF
cat >"$fx/flatpakref/saltmere.flatpakrepo" <<'REPO'
[Flatpak Repo]
Title=Saltmere Harbour apps
Url=https://example.org/saltmere/repo/
Homepage=https://example.org/saltmere
Comment=Apps from the Saltmere harbour office
GPGKey=bWRUYWxlc3MgcGxhY2Vob2xkZXIsIG5vdCBhIGtleQ==
REPO

# ------------------------------------------------------------ home computers

xdftool "$work/tides.hdf" create size=200Ki + format "Saltmere" ffs + makedir docs \
    + write "$work/src/tides.txt" tides.txt + write "$work/src/docs/readme.md" docs/readme.md >/dev/null
xdftool "$work/tides-ofs.hdf" create size=120Ki + format "Tides OFS" ofs + write "$work/src/tides.txt" tides.txt >/dev/null
cp "$work/tides.hdf" "$fx/adf/saltmere-ffs.hdf"
cp "$work/tides-ofs.hdf" "$fx/adf/saltmere-ofs.hdf"
python3 - "$work" <<'PY'
import sys
from pathlib import Path
from d64 import DiskImage
work = sys.argv[1]
DiskImage.create("d64", Path(f"{work}/tides.d64"), b"SALTMERE TIDES", b"ST")
with DiskImage(Path(f"{work}/tides.d64"), mode="w") as img:
    with img.path(b"TIDES").open("w", ftype="seq") as f:
        f.write(open(f"{work}/src/tides.txt", "rb").read().upper())
    with img.path(b"GAUGE").open("w", ftype="prg") as f:
        f.write(bytes([0x01, 0x08]) + bytes(300))
PY
cp "$work/tides.d64" "$fx/d64/saltmere.d64"

# ------------------------------------------------------------ optical discs

lx '
xorriso -as mkisofs -quiet -R -J -V SALTMERE_RR -publisher "Saltmere Harbour Office" -p "Tide Clerk" \
    -A "whiff fixtures" -no-pad -o rr.iso src 2>/dev/null
genisoimage -quiet -V SALTMERE -sysid LINUX -no-pad -o plain.iso src 2>/dev/null
mkfs.fat -C -n EFIBOOT --invariant efi.img 64 >/dev/null
mmd -i efi.img ::/EFI ::/EFI/BOOT
printf "not a real loader\n" > BOOTX64.EFI
mcopy -i efi.img BOOTX64.EFI ::/EFI/BOOT/
mkdir -p boot && cp efi.img boot/
ln -sf tides.txt src/latest
xorriso -as mkisofs -quiet -R -J -V SALTMERE_LIVE -e boot/efi.img -no-emul-boot -isohybrid-gpt-basdat \
    -no-pad -o live.iso -graft-points /=src /boot=boot 2>/dev/null
rm src/latest
for rev in 0x0102 0x0201; do
    : > udf$rev.img; truncate -s 224k udf$rev.img
    mkudffs -b 512 -m hd -r $rev --lvid=Saltmere --vid=SALTMERE udf$rev.img >/dev/null
done
'
vmroot 'mkdir -p /mnt/whiff-udf; for rev in 0x0102 0x0201; do mount -o loop udf$rev.img /mnt/whiff-udf; cp -r --preserve=timestamps src/. /mnt/whiff-udf/; ln -s tides.txt /mnt/whiff-udf/latest; umount /mnt/whiff-udf; done'
cp "$work/rr.iso" "$fx/iso9660/saltmere-rockridge.iso"
cp "$work/plain.iso" "$fx/iso9660/saltmere-plain.iso"
cp "$work/live.iso" "$fx/iso9660/saltmere-live-efi.iso"
cp "$work/udf0x0102.img" "$fx/udf/saltmere-udf102.udf"
cp "$work/udf0x0201.img" "$fx/udf/saltmere-udf201.udf"

# ------------------------------------------------------------ CD images

python3 "$craft" cdbin "$work/rr.iso" "$fx/cd_bin/saltmere-mode1.bin" 1
python3 "$craft" cdbin "$work/rr.iso" "$fx/cd_bin/saltmere-mode2.bin" 2
python3 "$craft" ccd "$work/rr.iso" "$fx/ccd/saltmere.ccd"

ls -l "$fx"/{raw_disk,ext,fat,exfat,ntfs,hfs_plus,apfs,luks,iso9660,udf,vdi,vmdk,vhd,vhdx,qcow2,qed,sparseimage}
