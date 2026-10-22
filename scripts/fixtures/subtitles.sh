#!/usr/bin/env bash
# Regenerate the subtitle and playlist fixtures under tests/fixtures/<format>/.
#
# Needs: ffmpeg (libx264, aac), GStreamer 1.x with the good / bad / ugly /
# libav plugin sets (subparse, srtenc, webvttenc, hlssink2, dashsink,
# x264enc), flac and metaflac, and Python 3 with network access once:
# pysubs2 1.9.0, pycaption 2.3.14 and m3u8 6.0.0 are installed into a
# throwaway virtual environment. Several writers produce each format on
# purpose (ffmpeg, GStreamer, pysubs2, pycaption, the m3u8 library,
# metaflac), so the extractors are not tested only against one
# implementation; craft_subtitles.py writes what none of them does.
#
# The script is a fictitious harbour documentary (Saltmere, Ana Lighthouse,
# Ben Gull); hosts are under `.example`. The media behind the HLS, DASH and
# Smooth Streaming manifests are a few seconds of a test pattern and a sine
# tone; only the manifests are kept. Run from the repository root:
#
#     scripts/fixtures/subtitles.sh

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ff() { ffmpeg -nostdin -hide_banner -loglevel error -y "$@"; }
gst() { gst-launch-1.0 -q -e "$@" >/dev/null; }
out() { mkdir -p "$fx/$1"; echo "$fx/$1/$2"; }

# ---- crafted fixtures and the source script -----------------------------------
python3 "$root/scripts/fixtures/craft_subtitles.py" "$fx" "$work"

# ---- third-party Python writers -----------------------------------------------
python3 -m venv "$work/venv"
PIP_DISABLE_PIP_VERSION_CHECK=1 "$work/venv/bin/pip" install -q pysubs2==1.9.0 pycaption==2.3.14 m3u8==6.0.0
"$work/venv/bin/python" "$root/scripts/fixtures/subtitle_tools.py" "$fx" "$work"

# ---- ffmpeg ---------------------------------------------------------------------
ff -i "$work/script.ass" -f srt "$(out srt harbour-ffmpeg.srt)"
ff -i "$work/script.ass" -f webvtt "$(out vtt harbour-ffmpeg.vtt)"
ff -i "$work/script.srt" -c:s ass "$(out ass harbour-ffmpeg.ass)"
ff -i "$work/script.ass" -metadata:s:s:0 language=eng -f ttml "$(out ttml harbour-ffmpeg.ttml)"
ff -i "$work/script.srt" -f lrc "$(out lrc harbour-ffmpeg.lrc)"

# ---- GStreamer --------------------------------------------------------------------
gst filesrc location="$work/script.srt" ! subparse ! srtenc ! filesink location="$(out srt harbour-gstreamer.srt)"
gst filesrc location="$work/script.srt" ! subparse ! webvttenc ! filesink location="$(out vtt harbour-gstreamer.vtt)"

# ---- streaming manifests --------------------------------------------------------
v=(-f lavfi -i "testsrc2=size=160x90:rate=25:duration=6")
a=(-f lavfi -i "sine=frequency=440:duration=6:sample_rate=48000")
mkdir -p "$work/hls" "$work/dash" "$work/ghls" "$work/gdash"
ff "${v[@]}" "${a[@]}" -map 0:v -map 0:v -map 1:a -c:v libx264 -preset veryfast -g 50 -b:v:0 200k \
    -s:v:1 96x54 -b:v:1 80k -c:a aac -b:a 48k -metadata:s:a:0 language=eng \
    -f hls -hls_time 2 -hls_playlist_type vod -hls_segment_type fmp4 -master_pl_name master.m3u8 \
    -var_stream_map "v:0,agroup:aud v:1,agroup:aud a:0,agroup:aud,language:en,name:English" \
    -hls_segment_filename "$work/hls/s%v_%03d.m4s" "$work/hls/stream_%v.m3u8"
cp "$work/hls/master.m3u8" "$(out hls harbour-master-ffmpeg.m3u8)"
cp "$work/hls/stream_0.m3u8" "$(out hls harbour-fmp4-ffmpeg.m3u8)"
gst videotestsrc num-buffers=150 ! video/x-raw,width=160,height=90,framerate=25/1 ! x264enc key-int-max=50 \
    ! h264parse ! hlssink2 playlist-location="$work/ghls/index.m3u8" location="$work/ghls/seg%05d.ts" \
    target-duration=2 max-files=0 playlist-length=0
cp "$work/ghls/index.m3u8" "$(out hls harbour-ts-gstreamer.m3u8)"
ff "${v[@]}" "${a[@]}" -map 0:v -map 0:v -map 1:a -c:v libx264 -preset veryfast -g 50 -b:v:0 200k \
    -s:v:1 96x54 -b:v:1 80k -c:a aac -b:a 48k -metadata:s:a:0 language=eng \
    -f dash -seg_duration 2 -use_template 1 -use_timeline 1 -adaptation_sets "id=0,streams=v id=1,streams=a" \
    "$work/dash/harbour.mpd"
cp "$work/dash/harbour.mpd" "$(out mpd harbour-ffmpeg.mpd)"
gst dashsink name=d mpd-root-path="$work/gdash" mpd-filename=harbour.mpd target-duration=2 dynamic=false \
    videotestsrc num-buffers=150 ! video/x-raw,width=160,height=90,framerate=25/1 ! x264enc key-int-max=50 \
    ! h264parse ! d.video_0 \
    audiotestsrc num-buffers=282 ! audio/x-raw,rate=48000 ! avenc_aac ! aacparse ! d.audio_0
cp "$work/gdash/harbour.mpd" "$(out mpd harbour-gstreamer.mpd)"
ff "${v[@]}" "${a[@]}" -c:v libx264 -preset veryfast -g 50 -b:v 200k -c:a aac -b:a 48k \
    -metadata:s:a:0 language=eng -f smoothstreaming -min_frag_duration 2000000 "$work/ss"
cp "$work/ss/Manifest" "$(out ismc harbour-ffmpeg.ismc)"

# ---- a cue sheet through flac and metaflac -------------------------------------
ff -f lavfi -i "sine=frequency=330:duration=8:sample_rate=44100" -ac 2 -c:a pcm_s16le "$work/harbour-suite.wav"
cat > "$work/harbour-suite.cue" <<'EOF'
REM GENRE Brass
PERFORMER "Saltmere Brass Band"
TITLE "Harbour Suite"
FILE "harbour-suite.wav" WAVE
  TRACK 01 AUDIO
    TITLE "Breakwater"
    ISRC ZZSAL2400101
    INDEX 01 00:00:00
  TRACK 02 AUDIO
    TITLE "Ferry Steps"
    INDEX 00 00:02:00
    INDEX 01 00:02:30
  TRACK 03 AUDIO
    TITLE "Outer Mole"
    INDEX 01 00:05:00
EOF
flac -s -f --cuesheet="$work/harbour-suite.cue" -o "$work/harbour-suite.flac" "$work/harbour-suite.wav" 2>/dev/null
# From the work directory, so the FILE line names the file and not the path.
cue_out=$(out cue harbour-suite-metaflac.cue)
(cd "$work" && metaflac --export-cuesheet-to="$cue_out" harbour-suite.flac)

echo "subtitle and playlist fixtures written to $fx"
