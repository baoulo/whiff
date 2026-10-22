# Fixtures for `vtt` (WebVTT)

Every file here was made for whiff's tests and is released under CC0-1.0. The text is a script
for a fictitious harbour documentary; names, places and hosts (Saltmere, Ana Lighthouse, Ben Gull,
Mira Castell, `*.example`) are fictitious. Regenerate with `scripts/fixtures/subtitles.sh`.

| File | Origin | Licence |
|---|---|---|
| `harbour-ffmpeg.vtt` | ffmpeg 7.1 (`webvtt` muxer) | CC0-1.0 |
| `harbour-gstreamer.vtt` | GStreamer 1.26 `subparse ! webvttenc` | CC0-1.0 |
| `harbour-pysubs2.vtt` | pysubs2 1.9.0 | CC0-1.0 |
| `harbour-voices-crafted.vtt` | Written by `scripts/fixtures/craft_subtitles.py`: header fields, a note, style and region blocks, voices, cue settings | CC0-1.0 |
