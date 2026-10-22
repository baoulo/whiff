#!/usr/bin/env bash
# Regenerate the audio fixtures under tests/fixtures/<format>/.
#
# Needs: ffmpeg (libmp3lame, libvorbis, libopus, libspeex, libopencore-amrnb),
# lame, flac / metaflac, speexenc, mpcenc, python3; on macOS also afconvert
# (Apple Core Audio: ADTS, ALAC, CAF, AIFF-C). Formats no available tool
# writes (Monkey's Audio, DSF, DFF) and the iXML chunk are crafted by
# craft_audio.py.
#
# Every file is a short synthetic tone with fictitious tags (Saltmere Brass
# Band, Mira Castell…). ffmpeg runs with -bitexact so no version strings or
# times are written; afconvert stamps the time of the run into its MP4 files,
# so those differ on every run. Run from the repository root:
#
#     scripts/fixtures/audio.sh

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ff() { ffmpeg -nostdin -hide_banner -loglevel error -y "$@"; }
# Bit-exact output: no encoder version, no creation time.
bx=(-fflags +bitexact -flags:a +bitexact)

# ---- sources ------------------------------------------------------------------
ff -f lavfi -i "sine=frequency=440:duration=1.5:sample_rate=22050" -c:a pcm_s16le "$work/mono.wav"
ff -f lavfi -i "sine=frequency=330:duration=1.5:sample_rate=44100" -f lavfi \
    -i "sine=frequency=495:duration=1.5:sample_rate=44100" -filter_complex "[0][1]amerge=inputs=2" \
    -c:a pcm_s16le "$work/stereo.wav"
ff -f lavfi -i "color=c=0x2a6f97:s=24x24" -frames:v 1 "$work/cover.png"
ff -f lavfi -i "color=c=0xe0a040:s=32x32" -frames:v 1 -q:v 4 "$work/cover.jpg"

tags=(
    -metadata title="Harbour Bells" -metadata artist="Saltmere Brass Band"
    -metadata album="Tides of Saltmere" -metadata album_artist="Saltmere Brass Band"
    -metadata date=2024 -metadata track=3/9 -metadata disc=1/2 -metadata genre=Brass
    -metadata composer="Mira Castell" -metadata comment="Recorded at the harbour wall"
    -metadata copyright="2024 Saltmere Brass Band" -metadata publisher="Example Records"
)
cat > "$work/chapters.txt" <<'EOF'
;FFMETADATA1
title=Saltmere Harbour Tour
artist=Ana Lighthouse
album=Saltmere Walks
genre=Audiobook
date=2024-04-01

[CHAPTER]
TIMEBASE=1/1000
START=0
END=700
title=The Breakwater

[CHAPTER]
TIMEBASE=1/1000
START=700
END=1500
title=Ferry Steps
EOF

mkdir -p "$fx"/{mp3,mp2,aac,m4a,wav,rf64,w64,flac,ogg,opus,spx,aiff,caf,wma,wv,mpc,amr,au,voc,tta}

# ---- LAME: CBR with ID3v1 + ID3v2.3 and cover art; VBR with Xing/LAME tag --
lame --quiet -b 64 --tt "Harbour Bells" --ta "Saltmere Brass Band" --tl "Tides of Saltmere" --ty 2024 \
    --tn 3/9 --tg Brass --tc "Recorded at the harbour wall" --add-id3v2 --ti "$work/cover.png" \
    "$work/stereo.wav" "$fx/mp3/bells-lame-cbr.mp3"
lame --quiet -V 5 --id3v2-only --tt "Gull Song" --ta "Mira Castell" --tv TBPM=96 --tv TKEY=Am \
    --tv "TXXX=ORIGIN=Saltmere" "$work/mono.wav" "$fx/mp3/gulls-lame-vbr.mp3"

# ---- ffmpeg: ID3v2.4 chapters (CHAP / CTOC), lyrics; a bare frame stream ---
ff -i "$work/mono.wav" -i "$work/chapters.txt" -map_metadata 1 -map 0:a -c:a libmp3lame -b:a 48k "${bx[@]}" \
    -metadata lyrics-eng="Bells across the water, ringing in the tide" "$fx/mp3/tour-chapters-ffmpeg.mp3"
ff -i "$work/mono.wav" -c:a libmp3lame -b:a 32k "${bx[@]}" -id3v2_version 0 -write_xing 0 \
    "$fx/mp3/bare-frames-ffmpeg.mp3"
ff -i "$work/mono.wav" -c:a mp2 -b:a 64k "${bx[@]}" "${tags[@]}" "$fx/mp2/bells-ffmpeg.mp2"

# ---- AAC: ADTS from ffmpeg and Core Audio; M4A, ALAC, an M4B with chapters --
ff -i "$work/mono.wav" -c:a aac -b:a 48k "${bx[@]}" "$fx/aac/bells-ffmpeg.aac"
ff -i "$work/stereo.wav" -i "$work/cover.jpg" -map 0:a -map 1:v -c:a aac -b:a 64k -c:v copy \
    -disposition:v attached_pic "${bx[@]}" "${tags[@]}" -metadata lyrics="Bells across the water" \
    "$fx/m4a/bells-ffmpeg.m4a"
ff -i "$work/mono.wav" -i "$work/chapters.txt" -map_metadata 1 -map 0:a -c:a aac -b:a 32k "${bx[@]}" \
    -f ipod "$fx/m4a/tour-chapters-ffmpeg.m4b"
if command -v afconvert >/dev/null; then
    afconvert -f adts -d aac -b 48000 "$work/mono.wav" "$fx/aac/bells-coreaudio.aac"
    afconvert -f m4af -d alac "$work/stereo.wav" "$fx/m4a/bells-alac-coreaudio.m4a"
    afconvert -f caff -d aac -b 48000 "$work/stereo.wav" "$fx/caf/bells-aac-coreaudio.caf"
    afconvert -f caff -d LEI16 "$work/mono.wav" "$fx/caf/bells-pcm-coreaudio.caf"
    afconvert -f AIFC -d ima4 "$work/mono.wav" "$fx/aiff/bells-ima4-coreaudio.aifc"
else
    echo "afconvert not found: skipping the Core Audio fixtures" >&2
fi

# ---- WAV family: LIST INFO, Broadcast Wave (bext), RF64, Wave64 ------------
ff -i "$work/mono.wav" -c:a pcm_s16le "${bx[@]}" "${tags[@]}" "$fx/wav/bells-info-ffmpeg.wav"
ff -i "$work/mono.wav" -c:a pcm_s24le "${bx[@]}" -write_bext 1 -metadata description="Harbour wall take 2" \
    -metadata originator="Saltmere Sound" -metadata originator_reference="SLT0000000003" \
    -metadata origination_date=2024-04-01 -metadata origination_time=09:30:00 -metadata time_reference=158760000 \
    -metadata coding_history="A=PCM,F=22050,W=24,M=mono,T=ffmpeg" "$work/bwf.wav"
ff -i "$work/mono.wav" -c:a pcm_s16le "${bx[@]}" -rf64 always -f wav "$fx/rf64/bells-ffmpeg.rf64"
ff -i "$work/mono.wav" -c:a pcm_s16le "${bx[@]}" "$fx/w64/bells-ffmpeg.w64"

# ---- FLAC: tags, picture, ReplayGain, a cue sheet ----------------------------
cat > "$work/tides.cue" <<'EOF'
PERFORMER "Saltmere Brass Band"
TITLE "Tides of Saltmere"
FILE "tides.wav" WAVE
  TRACK 01 AUDIO
    TITLE "Low Water"
    INDEX 01 00:00:00
  TRACK 02 AUDIO
    TITLE "High Water"
    INDEX 01 00:01:00
EOF
flac --silent -f -8 --cuesheet="$work/tides.cue" -T "TITLE=Harbour Bells" -T "ARTIST=Saltmere Brass Band" \
    -T "ALBUM=Tides of Saltmere" -T DATE=2024-04-01 -T TRACKNUMBER=3 -T TRACKTOTAL=9 -T GENRE=Brass \
    -T "COMPOSER=Mira Castell" -T ISRC=ZZSLT2400003 -T "LABEL=Example Records" \
    -T "MUSICBRAINZ_TRACKID=00000000-0000-4000-8000-000000000003" \
    --picture="3|image/png|Front cover|24x24x24|$work/cover.png" -o "$fx/flac/bells-reference.flac" "$work/stereo.wav"
metaflac --add-replay-gain "$fx/flac/bells-reference.flac"
ff -i "$work/mono.wav" -c:a flac "${bx[@]}" "${tags[@]}" "$fx/flac/bells-ffmpeg.flac"

# ---- Ogg: Vorbis, FLAC in Ogg, Opus, Speex -----------------------------------
ff -i "$work/stereo.wav" -c:a libvorbis -q:a 2 "${bx[@]}" "${tags[@]}" "$fx/ogg/bells-vorbis-ffmpeg.ogg"
ff -i "$work/mono.wav" -c:a flac "${bx[@]}" "${tags[@]}" -f ogg "$fx/ogg/bells-flac-ffmpeg.oga"
ff -i "$work/stereo.wav" -c:a libopus -b:a 32k "${bx[@]}" "${tags[@]}" "$fx/opus/bells-ffmpeg.opus"
speexenc --quiet --title "Harbour Bells" --author "Saltmere Brass Band" --comment "GENRE=Brass" \
    "$work/mono.wav" "$fx/spx/bells-speexenc.spx"
ff -i "$work/mono.wav" -c:a libspeex "${bx[@]}" -metadata title="Gull Song" "$fx/spx/gulls-ffmpeg.spx"

# ---- AIFF, CAF, WMA, WavPack, Musepack, AMR, AU, VOC, TTA ---------------------
ff -i "$work/mono.wav" -c:a pcm_s16be "${bx[@]}" "${tags[@]}" -write_id3v2 1 "$fx/aiff/bells-ffmpeg.aiff"
ff -i "$work/mono.wav" -c:a pcm_s16le "${bx[@]}" "${tags[@]}" -f caf "$fx/caf/bells-ffmpeg.caf"
ff -i "$work/stereo.wav" -c:a wmav2 -b:a 64k "${bx[@]}" "${tags[@]}" "$fx/wma/bells-ffmpeg.wma"
ff -i "$work/mono.wav" -c:a wavpack "${bx[@]}" "${tags[@]}" "$fx/wv/bells-ffmpeg.wv"
mpcenc --silent --overwrite --title "Harbour Bells" --artist "Saltmere Brass Band" --album "Tides of Saltmere" \
    --year 2024 --track 3 --genre Brass "$work/stereo.wav" "$fx/mpc/bells-mpcenc.mpc"
ff -i "$work/mono.wav" -ar 8000 -c:a libopencore_amrnb -b:a 12.2k "${bx[@]}" "$fx/amr/bells-ffmpeg.amr"
ff -i "$work/mono.wav" -c:a pcm_mulaw -ar 8000 "${bx[@]}" -metadata comment="Harbour bells" "$fx/au/bells-ffmpeg.au"
ff -i "$work/mono.wav" -c:a pcm_u8 -ar 11025 "${bx[@]}" "$fx/voc/bells-ffmpeg.voc"
ff -i "$work/mono.wav" -c:a tta "${bx[@]}" "${tags[@]}" "$fx/tta/bells-ffmpeg.tta"

# ---- crafted: iXML chunk on the Broadcast Wave file, APE, DSF, DFF ----------
python3 "$root/scripts/fixtures/craft_audio.py" "$fx" "$work/bwf.wav" "$work/mono.wav"

echo "audio fixtures regenerated; review with: cargo insta test --review"
