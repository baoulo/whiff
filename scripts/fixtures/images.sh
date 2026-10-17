#!/usr/bin/env bash
# Regenerate the image fixtures under tests/fixtures/<format>/.
#
# Needs: ImageMagick 7 (magick, with HEIC/AVIF/JXL/JP2/EXR/WebP delegates),
# exiftool, python3. On macOS `sips` makes the HEIC (Apple's encoder).
# Formats no tool writes are crafted by craft_images.py.
#
# Every image is a synthetic gradient or pattern; names, places and
# captions are fictitious. Run from the repository root:
#
#     scripts/fixtures/images.sh

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

exif() { exiftool -q -q -overwrite_original "$@"; }
# Deterministic ImageMagick output: no timestamps, no extra profiles.
mk() { magick "$@"; }
plain="-strip -define png:exclude-chunks=date,time +set date:create +set date:modify"

# Our own CC0 test profile, not a vendor's sRGB profile.
icc="$work/whiff-test.icc"
python3 "$root/scripts/fixtures/craft_images.py" --icc "$icc"

# Shared metadata: a full MWG set (EXIF + IPTC + XMP) with GPS.
tag_full() {
    exif -Make="Example Optics" -Model="Example X100" -LensModel="Example 23mm f/2" \
        -Artist="Mira Castell" -Copyright="(c) 2024 Mira Castell, CC BY 4.0" \
        -ImageDescription="Fishing boats in the old harbour at dusk" \
        -DateTimeOriginal="2024:05:01 19:42:10" -OffsetTimeOriginal="+02:00" -CreateDate="2024:05:01 19:42:10" \
        -ExposureTime=1/250 -FNumber=5.6 -ISO=200 -FocalLength=23 \
        -GPSLatitude=43.2951 -GPSLatitudeRef=N -GPSLongitude=5.3739 -GPSLongitudeRef=E -GPSAltitude=12 -GPSAltitudeRef=0 \
        -XMP-dc:Title="Old harbour" -XMP-dc:Description="Fishing boats in the old harbour at dusk" \
        -XMP-dc:Creator="Mira Castell" -XMP-dc:Rights="(c) 2024 Mira Castell, CC BY 4.0" \
        -XMP-dc:Subject=harbour -XMP-dc:Subject=boats -XMP-dc:Subject=dusk \
        -XMP-photoshop:City="Marseille" -XMP-photoshop:Country="France" -XMP-photoshop:Credit="Castell Studio" \
        -XMP-xmpRights:Marked=True -XMP-xmpRights:WebStatement="https://creativecommons.org/licenses/by/4.0/" \
        -IPTC:Keywords=harbour -IPTC:Keywords=boats -IPTC:Keywords=dusk -IPTC:By-line="Mira Castell" \
        -IPTC:Caption-Abstract="Fishing boats in the old harbour at dusk" -IPTC:City="Marseille" \
        -IPTC:ObjectName="Old harbour" -IPTC:CodedCharacterSet=UTF8 \
        "$@"
}

# --- JPEG -----------------------------------------------------------------
mkdir -p "$fx/jpeg"
mk -size 96x64 gradient:'#1d3557-#e9c46a' $plain -quality 85 -density 300 -units PixelsPerInch "$fx/jpeg/harbour.jpg"
tag_full "$fx/jpeg/harbour.jpg"
exif "-ICC_Profile<=$icc" "$fx/jpeg/harbour.jpg"
mk -size 64x48 plasma:fractal -seed 7 $plain -interlace JPEG -quality 70 "$fx/jpeg/progressive.jpg"
exif -XMP-dc:Title="Lighthouse (generated)" \
    -XMP-iptcExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia" \
    -XMP-dc:Creator="Example Image Model" -Orientation#=6 "$fx/jpeg/progressive.jpg"

# --- PNG / APNG -----------------------------------------------------------
mkdir -p "$fx/png" "$fx/apng"
mk -size 64x48 gradient:'#264653-#2a9d8f' $plain -density 72 -units PixelsPerInch "$fx/png/tagged.png"
exif -PNG:Title="Tide chart" -PNG:Author="Jonas Wren" -PNG:Copyright="(c) 2023 Jonas Wren" \
    -PNG:Description="Harbour tide chart, spring tides" -PNG:Software="whiff fixtures" \
    -XMP-dc:Subject=tides -XMP-dc:Subject=chart -DateTimeOriginal="2023:03:20 06:15:00" "$fx/png/tagged.png"
# -strip is applied at write time, so the profile goes in with exiftool.
mk -size 32x32 gradient:'#e76f51-#f4a261' $plain "PNG24:$fx/png/icc.png"
exif "-ICC_Profile<=$icc" "$fx/png/icc.png"
mk -size 24x24 -delay 10 xc:red xc:green xc:blue -loop 0 $plain "APNG:$fx/apng/traffic.apng"

# --- GIF ------------------------------------------------------------------
mkdir -p "$fx/gif"
mk -size 32x24 -delay 25 xc:'#003049' xc:'#d62828' xc:'#f77f00' -loop 0 $plain -set comment "Three frames, a quarter second each" "$fx/gif/blink.gif"
exif -XMP-dc:Title="Blink" "$fx/gif/blink.gif"

# --- WebP -----------------------------------------------------------------
mkdir -p "$fx/webp"
mk -size 64x48 gradient:'#023047-#ffb703' $plain -quality 80 "$fx/webp/lossy.webp"
exif -tagsfromfile "$fx/jpeg/harbour.jpg" -EXIF:all -XMP:all "$fx/webp/lossy.webp"
mk -size 32x32 xc:'rgba(0,128,255,0.5)' $plain -define webp:lossless=true "$fx/webp/lossless-alpha.webp"
mk -size 24x24 -delay 20 xc:red xc:blue -loop 3 $plain "$fx/webp/animated.webp"

# --- BMP / ICO ------------------------------------------------------------
mkdir -p "$fx/bmp" "$fx/ico"
mk -size 40x30 gradient:red-blue $plain -density 96 -units PixelsPerInch "BMP:$fx/bmp/v5.bmp"
mk -size 40x30 xc:navy $plain -colors 16 -type Palette "BMP3:$fx/bmp/palette-v3.bmp"
mk -size 64x64 gradient:'#ff006e-#3a86ff' $plain -define icon:auto-resize=64,32,16 "$fx/ico/app.ico"

# --- TIFF -----------------------------------------------------------------
mkdir -p "$fx/tiff"
mk -size 64x48 gradient:'#6d597a-#eaac8b' $plain -compress LZW -density 300 -units PixelsPerInch "$fx/tiff/tagged.tiff"
tag_full "$fx/tiff/tagged.tiff"
mk -size 32x24 xc:red xc:green xc:blue $plain -compress Zip "$fx/tiff/three-pages.tiff"
mk -size 32x24 xc:'#264653' $plain "TIFF64:$fx/tiff/bigtiff.tif"
mk -size 32x24 xc:cyan $plain -colorspace CMYK -compress None "$fx/tiff/cmyk.tiff"
mk -size 32x24 xc:'#2a9d8f' $plain -endian MSB "$fx/tiff/big-endian.tiff"

# --- HEIC / AVIF ----------------------------------------------------------
mkdir -p "$fx/heic" "$fx/avif"
if command -v sips >/dev/null; then
    sips -s format heic "$fx/jpeg/harbour.jpg" --out "$fx/heic/harbour.heic" >/dev/null
else
    mk "$fx/jpeg/harbour.jpg" -quality 60 "$fx/heic/harbour.heic"
fi
# A generic HEIF: the same file with major brand `mif1` (compatible brands unchanged).
mkdir -p "$fx/heif"
python3 - "$fx/heic/harbour.heic" "$fx/heif/generic.heif" <<'PY'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
assert data[4:12] == b"ftypheic", data[4:12]
data[8:12] = b"mif1"
open(sys.argv[2], "wb").write(bytes(data))
PY
mk -size 64x48 gradient:'#8338ec-#ffbe0b' $plain -quality 50 "$fx/avif/gradient.avif"
exif -tagsfromfile "$fx/jpeg/harbour.jpg" -EXIF:all -XMP:all "$fx/avif/gradient.avif"

# --- JPEG XL / JPEG 2000 --------------------------------------------------
mkdir -p "$fx/jxl" "$fx/jp2" "$fx/j2k"
mk -size 64x48 gradient:'#0b090a-#e5383b' $plain "$fx/jxl/codestream.jxl"
if command -v cjxl >/dev/null; then
    cjxl --quiet --lossless_jpeg=1 "$fx/jpeg/harbour.jpg" "$fx/jxl/recompressed-jpeg.jxl"
fi
mk -size 64x48 gradient:'#344e41-#a3b18a' $plain "JP2:$fx/jp2/gradient.jp2"
exif -XMP-dc:Title="Moss gradient" -XMP-dc:Creator="Jonas Wren" "$fx/jp2/gradient.jp2"
mk -size 64x48 gradient:'#344e41-#a3b18a' $plain -define jp2:number-resolutions=4 "J2K:$fx/j2k/codestream.j2k"

# --- Simple rasters ------------------------------------------------------
mkdir -p "$fx/tga" "$fx/pcx" "$fx/pnm" "$fx/qoi" "$fx/hdr" "$fx/exr" "$fx/dds"
mk -size 32x24 gradient:orange-purple $plain -compress RLE "$fx/tga/rle.tga"
mk -size 32x24 gradient:orange-purple $plain -density 150 -units PixelsPerInch "$fx/pcx/gradient.pcx"
mk -size 16x12 gradient:white-black $plain -compress None "PGM:$fx/pnm/ascii.pgm"
mk -size 16x12 gradient:red-blue $plain "PPM:$fx/pnm/binary.ppm"
mk -size 16x12 xc:'rgba(255,0,0,0.5)' $plain "PAM:$fx/pnm/alpha.pam"
mk -size 32x24 gradient:'#ef476f-#06d6a0' $plain "$fx/qoi/gradient.qoi"
mk -size 32x24 gradient:'#073b4c-#ffd166' $plain "$fx/hdr/sky.hdr"
mk -size 32x24 gradient:'#073b4c-#ffd166' $plain -compress Piz "$fx/exr/sky.exr"
mk -size 32x32 gradient:'#118ab2-#ffd166' $plain -define dds:compression=dxt5 -define dds:mipmaps=3 "$fx/dds/dxt5.dds"
mk -size 32x32 gradient:'#118ab2-#ffd166' $plain -define dds:compression=none -define dds:mipmaps=0 "$fx/dds/uncompressed.dds"

# --- Layered: PSD ---------------------------------------------------------
mkdir -p "$fx/psd"
mk \( -size 64x48 gradient:'#22223b-#c9ada7' \) \
   \( -size 64x48 gradient:'#22223b-#c9ada7' -set label "Background" \) \
   \( -size 32x24 xc:'#f2e9e4' -set label "Sail" -set page +16+12 \) \
   $plain "$fx/psd/layers.psd"
exif -XMP-dc:Title="Sail study" -IPTC:Keywords=sail -IPTC:By-line="Ines Halvorsen" -Copyright="(c) 2024 Ines Halvorsen" "$fx/psd/layers.psd"
mkdir -p "$fx/psb"
mk \( -size 48x32 gradient:'#003049-#fcbf49' \) \( -size 48x32 gradient:'#003049-#fcbf49' -set label "Base" \) \
   $plain "PSB:$fx/psb/large-document.psb"

# --- Crafted formats ------------------------------------------------------
python3 "$root/scripts/fixtures/craft_images.py" "$fx"

echo "image fixtures written under $fx"
