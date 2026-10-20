# Fixtures for `mov` (QuickTime movie)

Every file here was made for whiff's tests and is released under CC0-1.0. The pictures are
synthetic test patterns and the sound a sine tone; titles, names and places (Saltmere Harbour,
Ana Lighthouse, Saltmere Optics, Saltmere Broadcasting) are fictitious, and any camera location
is a point in the open Atlantic. Regenerate with `scripts/fixtures/video.sh`.

| File | Origin | Licence |
|---|---|---|
| `pier-hevc-avconvert.mov` | Apple `avconvert` (AVFoundation), HEVC + AAC, from an ffmpeg source | CC0-1.0 |
| `pier-prores-videotoolbox.mov` | GStreamer 1.x `qtmux` with Apple VideoToolbox ProRes 422 | CC0-1.0 |
| `pier-rotated-ffmpeg.mov` | ffmpeg 7.1 (libx264, AAC), 90° display matrix, timecode track, `com.apple.quicktime.*` make / model / software / location / creation date | CC0-1.0 |

`pier-prores-videotoolbox.mov` and `pier-hevc-avconvert.mov` carry the time of the run, so they differ
whenever they are regenerated; so do the GStreamer files in the other directories.
