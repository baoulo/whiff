#!/usr/bin/env bash
# Build the Stage 2 oracle corpus: ~200 synthetic images (10 base formats ×
# 20 metadata variants, plus the committed fixtures) for
#
#     cargo run --features dev --bin whiff-dev -- oracle images target/oracle-corpus tests/fixtures
#
# which compares whiff with `exiftool -use MWG`. The corpus is generated,
# not committed. Needs ImageMagick 7, exiftool and python3 (and `sips` on
# macOS for HEIC). Every name, place and caption is fictitious.

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
out="${1:-$root/target/oracle-corpus}"
rm -rf "$out"
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ex() { exiftool -q -q -m -overwrite_original "$@" >/dev/null 2>&1 || true; }
plain="-strip -define png:exclude-chunks=date,time +set date:create +set date:modify"

# Base images, one per container exiftool can write metadata into.
magick -size 120x80 gradient:'#1d3557-#a8dadc' $plain -quality 85 "$work/base.jpg"
magick -size 120x80 gradient:'#1d3557-#a8dadc' $plain -interlace JPEG -quality 60 "$work/base-progressive.jpg"
magick -size 120x80 gradient:'#2a9d8f-#e9c46a' $plain "$work/base.png"
magick -size 120x80 gradient:'#6d597a-#eaac8b' $plain -compress LZW "$work/base.tif"
magick -size 120x80 gradient:'#6d597a-#eaac8b' $plain -endian MSB "$work/base-be.tif"
magick -size 120x80 gradient:'#023047-#ffb703' $plain -quality 80 "$work/base.webp"
magick -size 120x80 gradient:'#8338ec-#ffbe0b' $plain -quality 50 "$work/base.avif"
magick -size 120x80 gradient:'#344e41-#a3b18a' $plain "$work/base.jp2"
magick \( -size 120x80 gradient:'#22223b-#c9ada7' \) \( -size 120x80 gradient:'#22223b-#c9ada7' -set label Layer \) $plain "$work/base.psd"
if command -v sips >/dev/null; then
    sips -s format heic "$work/base.jpg" --out "$work/base.heic" >/dev/null
else
    magick "$work/base.jpg" "$work/base.heic"
fi
bases=(base.jpg base-progressive.jpg base.png base.tif base-be.tif base.webp base.avif base.jp2 base.psd base.heic)

long=$(python3 -c 'print(("The tide came in slowly over the mud flats while the gulls argued. " * 30).strip())')
kw20=()
for i in $(seq 1 20); do kw20+=("-XMP-dc:Subject=keyword-$i" "-IPTC:Keywords=keyword-$i"); done

# Sets `args` to the exiftool arguments of variant $1.
variant() {
    case "$1" in
    full) args=(-Artist="Mira Castell" -Copyright="(c) 2024 Mira Castell" -ImageDescription="Boats at dusk" \
        -DateTimeOriginal="2024:05:01 19:42:10" -OffsetTimeOriginal=+02:00 -GPSLatitude=43.2951 -GPSLatitudeRef=N \
        -GPSLongitude=5.3739 -GPSLongitudeRef=E -XMP-dc:Title="Old harbour" -XMP-dc:Creator="Mira Castell" \
        -XMP-dc:Rights="(c) 2024 Mira Castell" -XMP-dc:Description="Boats at dusk" -XMP-dc:Subject=boats -XMP-dc:Subject=dusk \
        -IPTC:ObjectName="Old harbour" -IPTC:By-line="Mira Castell" -IPTC:CopyrightNotice="(c) 2024 Mira Castell" \
        -IPTC:Caption-Abstract="Boats at dusk" -IPTC:Keywords=boats -IPTC:Keywords=dusk) ;;
    exif-only) args=(-Artist="Jonas Wren" -Copyright="(c) 2019 Jonas Wren" -ImageDescription="Pier in winter" \
        -DateTimeOriginal="2019:01:15 08:00:01" -GPSLatitude=59.3293 -GPSLatitudeRef=N -GPSLongitude=18.0686 -GPSLongitudeRef=E) ;;
    xmp-only) args=(-XMP-dc:Title="Salt marsh" -XMP-dc:Creator="Ines Halvorsen" -XMP-dc:Rights="CC0 Ines Halvorsen" \
        -XMP-dc:Description="Reeds and a heron" -XMP-dc:Subject=heron -XMP-exif:DateTimeOriginal="2022-09-03T07:12:00+01:00" \
        -XMP-exif:GPSLatitude="51.5072 N" -XMP-exif:GPSLongitude="0.1276 W") ;;
    iptc-only) args=(-IPTC:ObjectName="Fish market" -IPTC:By-line="Tomas Lind" -IPTC:CopyrightNotice="(c) 2020 Tomas Lind" \
        -IPTC:Caption-Abstract="Morning auction" -IPTC:Keywords=fish -IPTC:Keywords=market -IPTC:DateCreated=2020:06:11 \
        -IPTC:TimeCreated=05:45:00+03:00 -IPTC:CodedCharacterSet=UTF8) ;;
    unicode) args=(-XMP-dc:Title="Hafen von Kiel – Möwen" -XMP-dc:Creator="Zoë Ångström" -XMP-dc:Rights="© 2023 Zoë Ångström" \
        -XMP-dc:Description="Möwen über dem Wasser, 港の朝" -XMP-dc:Subject=möwe -XMP-dc:Subject=κύμα -XMP-dc:Subject=港 \
        -IPTC:CodedCharacterSet=UTF8 -IPTC:ObjectName="Hafen von Kiel – Möwen" -IPTC:By-line="Zoë Ångström") ;;
    conflict) args=(-XMP-dc:Title="Title from XMP" -IPTC:ObjectName="Title from IPTC" -Artist="EXIF Artist" \
        -XMP-dc:Creator="XMP Creator" -IPTC:By-line="IPTC By-line") ;;
    creators) args=(-XMP-dc:Creator="Ada Lind" -XMP-dc:Creator="Bo Strand" -XMP-dc:Creator="Cy Moor" -IPTC:By-line="Ada Lind" \
        -IPTC:By-line="Bo Strand" -IPTC:By-line="Cy Moor") ;;
    south-west) args=(-GPSLatitude=22.9068 -GPSLatitudeRef=S -GPSLongitude=43.1729 -GPSLongitudeRef=W -GPSAltitude=11 \
        -GPSAltitudeRef=0 -XMP-dc:Title="Bay at noon") ;;
    tz-west) args=(-DateTimeOriginal="2021:12:31 23:59:59" -OffsetTimeOriginal=-05:00 -XMP-dc:Title="New year") ;;
    no-tz) args=(-DateTimeOriginal="2018:07:04 12:00:00" -Copyright="(c) 2018 Example") ;;
    subsec) args=(-DateTimeOriginal="2017:03:02 10:20:30" -SubSecTimeOriginal=25 -OffsetTimeOriginal=+09:00) ;;
    ai) args=(-XMP-dc:Title="Lighthouse (generated)" \
        -XMP-iptcExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia") ;;
    plain) args=() ;;
    long) args=(-XMP-dc:Description="$long" -XMP-dc:Title="Mud flats") ;;
    lang-alt) args=(-XMP-dc:Title-fr="Le vieux port" -XMP-dc:Title="The old port" -XMP-dc:Description-de="Der alte Hafen" \
        -XMP-dc:Description="The old harbour") ;;
    keywords) args=("${kw20[@]}") ;;
    rights) args=(-XMP-dc:Rights="(c) 2025 Castell Studio" -XMP-xmpRights:Marked=True \
        -XMP-xmpRights:WebStatement="https://creativecommons.org/licenses/by/4.0/" -XMP-photoshop:Credit="Castell Studio") ;;
    location) args=(-XMP-photoshop:City=Marseille -XMP-photoshop:Country=France -IPTC:City=Marseille -XMP-dc:Title="Quay") ;;
    dates) args=(-DateTimeOriginal="2016:02:29 06:30:00" -CreateDate="2016:02:29 06:31:00" -ModifyDate="2016:03:01 10:00:00" \
        -OffsetTime=+01:00 -OffsetTimeOriginal=+01:00 -OffsetTimeDigitized=+01:00) ;;
    orientation) args=(-Orientation#=6 -XMP-dc:Title="Rotated" -Copyright="(c) Rotated") ;;
    esac
}
variants=(full exif-only xmp-only iptc-only unicode conflict creators south-west tz-west no-tz subsec ai plain long lang-alt
    keywords rights location dates orientation)

n=0
for b in "${bases[@]}"; do
    ext="${b##*.}"
    stem="${b%.*}"
    for v in "${variants[@]}"; do
        f="$out/${stem/base/img}-$v.$ext"
        cp "$work/$b" "$f"
        variant "$v"
        if [ ${#args[@]} -gt 0 ]; then ex "${args[@]}" "$f"; fi
        n=$((n + 1))
    done
done
echo "$n images written to $out"
