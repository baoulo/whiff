# Fixtures for `mp4` (MPEG-4 video)

Every file here was made for whiff's tests and is released under CC0-1.0. The pictures are
synthetic test patterns and the sound a sine tone; titles, names and places (Saltmere Harbour,
Ana Lighthouse, Saltmere Optics, Saltmere Broadcasting) are fictitious, and any camera location
is a point in the open Atlantic. Regenerate with `scripts/fixtures/video.sh`.

| File | Origin | Licence |
|---|---|---|
| `harbour-av1-opus-fragmented-ffmpeg.mp4` | ffmpeg 7.1 (SVT-AV1, Opus), fragmented (`moof`, no `mdat` in the movie) | CC0-1.0 |
| `harbour-h264-aac-ffmpeg.mp4` | ffmpeg 7.1 (libx264 High, AAC-LC), faststart, tags and chapters | CC0-1.0 |
| `harbour-h264-gstreamer.mp4` | GStreamer 1.x `mp4mux` (x264enc, faac) | CC0-1.0 |
| `harbour-hevc-hdr10-ffmpeg.mp4` | ffmpeg 7.1 (libx265 Main 10), BT.2020 / PQ colour in the VUI, HDR10 SEI | CC0-1.0 |
| `ferry-h264-movtext-ffmpeg.mp4` | ffmpeg 7.1 (libx264, a 3GPP timed text subtitle track) | CC0-1.0 |
| `ferry-h264-tx3g-gstreamer.mp4` | GStreamer 1.26 `mp4mux` (x264enc, a `tx3g` subtitle track from `subparse`) | CC0-1.0 |
