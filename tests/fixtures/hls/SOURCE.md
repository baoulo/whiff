# Fixtures for `hls` (HLS playlist)

Every file here was made for whiff's tests and is released under CC0-1.0. Titles, artists,
paths and hosts (Saltmere Brass Band, Mira Castell, Ben Gull, `*.example`) are fictitious; the
media behind any manifest were a few seconds of a test pattern and a sine tone, and are not kept.
Regenerate with `scripts/fixtures/subtitles.sh`.

| File | Origin | Licence |
|---|---|---|
| `harbour-encrypted-m3u8lib.m3u8` | m3u8 6.0.0 (Python): an AES-128 media playlist | CC0-1.0 |
| `harbour-fmp4-ffmpeg.m3u8` | ffmpeg 7.1 (`hls` muxer, fMP4 segments) | CC0-1.0 |
| `harbour-master-ffmpeg.m3u8` | ffmpeg 7.1 (`hls` muxer, master playlist with an audio group) | CC0-1.0 |
| `harbour-master-m3u8lib.m3u8` | m3u8 6.0.0: variants, audio and subtitle renditions, an I-frame playlist, session data | CC0-1.0 |
| `harbour-ts-gstreamer.m3u8` | GStreamer 1.26 `hlssink2` | CC0-1.0 |
