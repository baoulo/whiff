# Fixtures for `mpd` (MPEG-DASH manifest)

Every file here was made for whiff's tests and is released under CC0-1.0. Titles, artists,
paths and hosts (Saltmere Brass Band, Mira Castell, Ben Gull, `*.example`) are fictitious; the
media behind any manifest were a few seconds of a test pattern and a sine tone, and are not kept.
Regenerate with `scripts/fixtures/subtitles.sh`.

| File | Origin | Licence |
|---|---|---|
| `harbour-ffmpeg.mpd` | ffmpeg 7.1 (`dash` muxer, segment templates with timelines) | CC0-1.0 |
| `harbour-gstreamer.mpd` | GStreamer 1.26 `dashsink` (MPEG-TS segments) | CC0-1.0 |
