#!/usr/bin/env bash
# Regenerate the video fixtures under tests/fixtures/<format>/.
#
# Needs: ffmpeg (libx264, libx265, libsvtav1, libvpx, libxvid, libtheora,
# libvorbis, libopus, libmp3lame, libopencore-amrnb), GStreamer 1.x with the
# good / bad / ugly / libav plugin sets, the x264 and x265 command-line
# encoders; on macOS also avconvert (AVFoundation) and GStreamer's
# VideoToolbox encoders. Several muxers write each container on purpose
# (ffmpeg, GStreamer, AVFoundation) so the extractors are not tested only
# against one implementation.
#
# Every file is a second or less of a synthetic test pattern and tone with
# fictitious tags (Saltmere Harbour, Ana Lighthouse, Saltmere Optics…); the
# camera location is a point in the open Atlantic. ffmpeg runs with
# -bitexact where the muxer honours it; GStreamer, avconvert and the x264 /
# x265 CLIs write their version and the time of the run, so those files
# differ between runs and versions. Run from the repository root:
#
#     scripts/fixtures/video.sh

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ff() { ffmpeg -nostdin -hide_banner -loglevel error -y "$@"; }
gst() { gst-launch-1.0 -q -e "$@" >/dev/null; }
bx=(-fflags +bitexact -flags:v +bitexact -flags:a +bitexact)
out() { mkdir -p "$fx/$1"; echo "$fx/$1/$2"; }

# ---- sources ------------------------------------------------------------------
v=(-f lavfi -i "testsrc2=size=160x90:rate=25:duration=1")
a=(-f lavfi -i "sine=frequency=440:duration=1:sample_rate=48000")
ff "${v[@]}" -pix_fmt yuv420p "$work/src.y4m"
ff -f lavfi -i "color=c=0x2a6f97:s=32x32" -frames:v 1 -q:v 4 "$work/cover.jpg"
cat > "$work/subs.srt" <<'EOF'
1
00:00:00,100 --> 00:00:00,600
The ferry leaves the breakwater.

2
00:00:00,600 --> 00:00:00,950
Gulls follow it out.
EOF
cat > "$work/chapters.txt" <<'EOF'
;FFMETADATA1
title=Saltmere Harbour at Dawn
artist=Ana Lighthouse
comment=A test pattern filmed nowhere
date=2024-04-01
genre=Documentary
copyright=2024 Saltmere Harbour Films

[CHAPTER]
TIMEBASE=1/1000
START=0
END=500
title=Breakwater

[CHAPTER]
TIMEBASE=1/1000
START=500
END=1000
title=Ferry Steps
EOF
tags=(-metadata title="Saltmere Harbour at Dawn" -metadata artist="Ana Lighthouse"
    -metadata comment="A test pattern filmed nowhere" -metadata date=2024-04-01
    -metadata copyright="2024 Saltmere Harbour Films")
gv="videotestsrc num-buffers=25 pattern=smpte ! video/x-raw,format=I420,width=160,height=90,framerate=25/1"
ga="audiotestsrc num-buffers=47 freq=440 ! audio/x-raw,rate=48000,channels=2"

# ---- MP4 ----------------------------------------------------------------------
ff "${v[@]}" "${a[@]}" -i "$work/chapters.txt" -map 0 -map 1 -map_metadata 2 -map_chapters 2 \
    -c:v libx264 -profile:v high -preset veryfast -crf 32 -c:a aac -b:a 48k -metadata:s:a:0 language=eng \
    -movflags +faststart "${bx[@]}" "$(out mp4 harbour-h264-aac-ffmpeg.mp4)"
ff "${v[@]}" -c:v libx265 -pix_fmt yuv420p10le -tag:v hvc1 -preset ultrafast -crf 34 \
    -color_primaries bt2020 -color_trc smpte2084 -colorspace bt2020nc \
    -x265-params "log-level=none:hdr10=1:colorprim=bt2020:transfer=smpte2084:colormatrix=bt2020nc:master-display=G(13250,34500)B(7500,3000)R(34000,16000)WP(15635,16450)L(10000000,50):max-cll=1000,400" \
    "${bx[@]}" "$(out mp4 harbour-hevc-hdr10-ffmpeg.mp4)"
ff "${v[@]}" "${a[@]}" -c:v libsvtav1 -preset 12 -crf 50 -svtav1-params log-level=0 -c:a libopus -b:a 24k \
    -movflags frag_keyframe+empty_moov+default_base_moof "${bx[@]}" "$(out mp4 harbour-av1-opus-fragmented-ffmpeg.mp4)"
gst $gv ! x264enc bitrate=96 speed-preset=veryfast ! h264parse ! mp4mux name=m ! filesink location="$(out mp4 harbour-h264-gstreamer.mp4)" \
    $ga ! faac bitrate=48000 ! m.

# ---- QuickTime ------------------------------------------------------------------
ff -noautorotate -display_rotation:v:0 -90 "${v[@]}" "${a[@]}" -c:v libx264 -preset veryfast -crf 32 -c:a aac -b:a 48k \
    -timecode 01:00:00:00 -movflags use_metadata_tags \
    -metadata com.apple.quicktime.make="Saltmere Optics" -metadata com.apple.quicktime.model="SO-100" \
    -metadata com.apple.quicktime.software="SO-100 Firmware 2.1" \
    -metadata com.apple.quicktime.location.ISO6709="+50.0000-030.0000+000.000/" \
    -metadata com.apple.quicktime.creationdate="2024-04-01T06:30:00+0100" \
    -metadata com.apple.quicktime.title="Pier at Dawn" \
    "${bx[@]}" "$(out mov pier-rotated-ffmpeg.mov)"
gst videotestsrc num-buffers=10 ! video/x-raw,format=I420,width=64,height=36,framerate=10/1 ! vtenc_prores ! qtmux ! \
    filesink location="$(out mov pier-prores-videotoolbox.mov)"
ff "${v[@]}" "${a[@]}" -c:v libx264 -crf 30 -c:a aac "$work/av-src.mov"
avconvert --source "$work/av-src.mov" --preset PresetHEVCHighestQuality --output "$work/av.mov" --replace >/dev/null
cp "$work/av.mov" "$(out mov pier-hevc-avconvert.mov)"

# ---- 3GPP -----------------------------------------------------------------------
ff -f lavfi -i "testsrc2=size=176x144:rate=15:duration=1" -f lavfi -i "sine=frequency=440:duration=1:sample_rate=8000" \
    -c:v h263 -b:v 64k -c:a libopencore_amrnb -ar 8000 -ac 1 -b:a 12.2k "${bx[@]}" "$(out 3gp ferry-h263-amr-ffmpeg.3gp)"
gst $gv ! x264enc bitrate=64 speed-preset=veryfast ! h264parse ! 3gppmux name=m ! filesink location="$(out 3gp ferry-h264-gstreamer.3gp)" \
    audiotestsrc num-buffers=10 ! audio/x-raw,rate=8000,channels=1 ! amrnbenc ! m.

# ---- Matroska / WebM ------------------------------------------------------------
ff "${v[@]}" -f lavfi -i "sine=frequency=440:duration=1:sample_rate=48000" -i "$work/subs.srt" -i "$work/chapters.txt" \
    -map 0 -map 1 -map 2 -map_metadata 3 -map_chapters 3 -c:v libx264 -preset veryfast -crf 32 -c:a ac3 -b:a 96k -c:s srt \
    -metadata:s:a:0 language=eng -metadata:s:s:0 language=fra -metadata:s:s:0 title="Sous-titres" -disposition:s:0 forced \
    -attach "$work/cover.jpg" -metadata:s:t mimetype=image/jpeg -metadata:s:t filename=cover.jpg \
    "${bx[@]}" "$(out mkv harbour-h264-ac3-subs-ffmpeg.mkv)"
ff "${v[@]}" -c:v libx265 -pix_fmt yuv420p10le -preset ultrafast -crf 34 \
    -x265-params log-level=none:colorprim=bt2020:transfer=arib-std-b67:colormatrix=bt2020nc \
    -color_primaries bt2020 -color_trc arib-std-b67 -colorspace bt2020nc -color_range tv \
    "${bx[@]}" "$(out mkv harbour-hevc-hlg-ffmpeg.mkv)"
gst $gv ! x264enc bitrate=96 speed-preset=veryfast ! h264parse ! matroskamux name=m ! filesink location="$(out mkv harbour-h264-vorbis-gstreamer.mkv)" \
    $ga ! audioconvert ! vorbisenc ! m.
ff "${v[@]}" "${a[@]}" -c:v libvpx-vp9 -b:v 80k -deadline realtime -cpu-used 8 -c:a libopus -b:a 24k "${tags[@]}" \
    "${bx[@]}" "$(out webm gulls-vp9-opus-ffmpeg.webm)"
gst $gv ! vp8enc target-bitrate=96000 deadline=1 ! webmmux name=m ! filesink location="$(out webm gulls-vp8-vorbis-gstreamer.webm)" \
    $ga ! audioconvert ! vorbisenc ! m.
ff "${v[@]}" -c:v libsvtav1 -preset 12 -crf 50 -svtav1-params log-level=0 -live 1 -cluster_size_limit 4096 \
    "${bx[@]}" "$(out webm gulls-av1-live-ffmpeg.webm)"
ff -i "$work/subs.srt" -c:s srt -metadata:s:s:0 language=eng -f matroska "${bx[@]}" "$(out mks ferry-subtitles-ffmpeg.mks)"
ff -f lavfi -i "sine=frequency=330:duration=1:sample_rate=44100" -c:a flac \
    -metadata title="Harbour Bells" -metadata artist="Saltmere Brass Band" -metadata album="Tides of Saltmere" \
    -metadata track=3 -metadata date=2024 "${bx[@]}" "$(out mka bells-flac-ffmpeg.mka)"

# ---- AVI ------------------------------------------------------------------------
ff "${v[@]}" "${a[@]}" -c:v libxvid -q:v 8 -c:a libmp3lame -b:a 48k "${tags[@]}" "${bx[@]}" "$(out avi harbour-xvid-mp3-ffmpeg.avi)"
ff -f lavfi -i "testsrc2=size=64x36:rate=10:duration=1" -f lavfi -i "sine=frequency=440:duration=1:sample_rate=8000" \
    -c:v mjpeg -q:v 10 -c:a pcm_u8 "${bx[@]}" "$(out avi harbour-mjpeg-pcm-ffmpeg.avi)"
gst $gv ! x264enc bitrate=96 speed-preset=veryfast ! h264parse ! avimux name=m ! filesink location="$(out avi harbour-h264-mp3-gstreamer.avi)" \
    $ga ! audioconvert ! lamemp3enc bitrate=48 ! m.

# ---- MPEG transport and program streams -----------------------------------------
ff "${v[@]}" "${a[@]}" -c:v libx264 -preset veryfast -crf 32 -c:a aac -b:a 48k -metadata:s:a:0 language=eng \
    -metadata service_name="Saltmere One" -metadata service_provider="Saltmere Broadcasting" \
    "${bx[@]}" "$(out ts harbour-h264-aac-ffmpeg.ts)"
ff "${v[@]}" "${a[@]}" -c:v mpeg2video -b:v 300k -c:a mp2 -b:a 64k "${bx[@]}" "$(out ts harbour-mpeg2-mp2-ffmpeg.ts)"
gst $gv ! x265enc bitrate=64 speed-preset=ultrafast ! h265parse ! mpegtsmux name=m ! filesink location="$(out ts harbour-hevc-ac3-gstreamer.ts)" \
    $ga ! audioconvert ! avenc_ac3 bitrate=96000 ! m.
ff "${v[@]}" "${a[@]}" -c:v libx264 -preset veryfast -crf 32 -c:a ac3 -b:a 96k -mpegts_m2ts_mode 1 -f mpegts \
    "${bx[@]}" "$(out m2ts harbour-h264-ac3-ffmpeg.m2ts)"
ff "${v[@]}" -f lavfi -i "sine=frequency=440:duration=1:sample_rate=44100" -c:v mpeg1video -b:v 200k -c:a mp2 -b:a 64k \
    -f mpeg "${bx[@]}" "$(out mpg harbour-mpeg1-ffmpeg.mpg)"
ff "${v[@]}" "${a[@]}" -c:v mpeg2video -b:v 300k -c:a ac3 -b:a 96k -f vob "${bx[@]}" "$(out mpg harbour-dvd-ffmpeg.vob)"

# ---- Flash Video, Windows Media, RealMedia, Ogg ---------------------------------
ff "${v[@]}" "${a[@]}" -c:v libx264 -preset veryfast -crf 32 -c:a aac -b:a 48k "${tags[@]}" "${bx[@]}" "$(out flv harbour-h264-aac-ffmpeg.flv)"
gst $gv ! avenc_flv bitrate=96000 ! flvmux name=m ! filesink location="$(out flv harbour-flv1-mp3-gstreamer.flv)" \
    audiotestsrc num-buffers=22 ! audio/x-raw,rate=44100,channels=1 ! lamemp3enc bitrate=32 ! mpegaudioparse ! m.
ff "${v[@]}" "${a[@]}" -c:v wmv2 -b:v 120k -c:a wmav2 -b:a 48k "${tags[@]}" "${bx[@]}" "$(out wmv harbour-wmv2-wma-ffmpeg.wmv)"
gst $gv ! avenc_wmv2 bitrate=120000 ! asfmux name=m ! filesink location="$(out wmv harbour-wmv2-gstreamer.wmv)" \
    $ga ! audioconvert ! avenc_wmav2 bitrate=48000 ! m.
ff -f lavfi -i "testsrc2=size=176x144:rate=10:duration=1" -f lavfi -i "sine=frequency=440:duration=1:sample_rate=8000" -c:v rv20 -b:v 120k -c:a real_144 -ac 1 \
    "${tags[@]}" "${bx[@]}" "$(out rm harbour-rv20-ffmpeg.rm)"
ff "${v[@]}" "${a[@]}" -c:v libtheora -q:v 3 -c:a libvorbis -q:a 0 "${tags[@]}" "${bx[@]}" "$(out ogv harbour-theora-vorbis-ffmpeg.ogv)"
gst $gv ! theoraenc bitrate=96 ! oggmux name=m ! filesink location="$(out ogv harbour-theora-opus-gstreamer.ogv)" \
    $ga ! audioconvert ! opusenc bitrate=24000 ! m.

# ---- elementary streams ---------------------------------------------------------
x264 --quiet --preset veryfast --crf 32 --output "$(out h264 harbour-x264.264)" "$work/src.y4m" 2>/dev/null
x265 --log-level none --preset ultrafast --crf 34 --output "$(out hevc harbour-x265.hevc)" "$work/src.y4m" 2>/dev/null
ff "${v[@]}" -c:v mpeg2video -b:v 300k -f mpeg2video "${bx[@]}" "$(out m2v harbour-ffmpeg.m2v)"
ff "${v[@]}" -c:v libvpx-vp9 -b:v 80k -deadline realtime -cpu-used 8 "${bx[@]}" "$(out ivf harbour-vp9-ffmpeg.ivf)"
ff "${v[@]}" -c:v libsvtav1 -preset 12 -crf 50 -svtav1-params log-level=0 "${bx[@]}" "$(out ivf harbour-av1-ffmpeg.ivf)"
ff "${v[@]}" -c:v libsvtav1 -preset 12 -crf 50 -svtav1-params log-level=0 -f obu "${bx[@]}" "$(out obu harbour-av1-ffmpeg.obu)"
ff -f lavfi -i "testsrc2=size=32x18:rate=10" -frames:v 3 -pix_fmt yuv420p "$(out y4m tiny-ffmpeg.y4m)"

echo "video fixtures written"
du -sh "$fx"/{mp4,mov,3gp,mkv,webm,mka,avi,ts,m2ts,mpg,flv,wmv,rm,ogv,h264,hevc,m2v,ivf,obu,y4m}/* | sort -h | tail -5
