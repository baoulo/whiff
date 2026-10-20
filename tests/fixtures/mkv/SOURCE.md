# Fixtures for `mkv` (Matroska video)

Every file here was made for whiff's tests and is released under CC0-1.0. The pictures are
synthetic test patterns and the sound a sine tone; titles, names and places (Saltmere Harbour,
Ana Lighthouse, Saltmere Optics, Saltmere Broadcasting) are fictitious, and any camera location
is a point in the open Atlantic. Regenerate with `scripts/fixtures/video.sh`.

| File | Origin | Licence |
|---|---|---|
| `harbour-h264-ac3-subs-ffmpeg.mkv` | ffmpeg 7.1 (libx264, AC-3, SubRip in French marked forced), tags, chapters, a cover attachment | CC0-1.0 |
| `harbour-h264-vorbis-gstreamer.mkv` | GStreamer 1.x `matroskamux` (x264enc, vorbisenc) | CC0-1.0 |
| `harbour-hevc-hlg-ffmpeg.mkv` | ffmpeg 7.1 (libx265 Main 10), BT.2020 / HLG `Colour` element | CC0-1.0 |
