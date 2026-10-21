#!/usr/bin/env python3
"""Write subtitle and playlist fixtures with third-party Python libraries,
so the extractors are tested against more than one writer.

    subtitle_tools.py <tests/fixtures> <work dir from craft_subtitles.py>

Needs pysubs2 1.9.0, pycaption 2.3.14 and m3u8 6.0.0 (subtitles.sh installs
them in a throwaway virtual environment).

* pysubs2: SRT, WebVTT, ASS, SSA, MicroDVD (25 fps) and MPL2
  from the source ASS script.
* pycaption: SCC (CEA-608 pop-on captions), DFXP and a two-language SAMI
  from the English and French SRT scripts.
* m3u8: an HLS master playlist (variants, audio and subtitle renditions,
  I-frame playlist, session data) and an encrypted media playlist.
"""

import sys
from pathlib import Path

import m3u8
import m3u8.model
import pycaption
import pysubs2


def pysubs2_files(fx: Path, work: Path):
    subs = pysubs2.load(str(work / "script.ass"))
    for fmt, folder, name, kw in [
        ("srt", "srt", "harbour-pysubs2.srt", {}),
        ("vtt", "vtt", "harbour-pysubs2.vtt", {}),
        ("ass", "ass", "harbour-pysubs2.ass", {}),
        ("ssa", "ssa", "harbour-pysubs2.ssa", {}),
        ("microdvd", "microdvd", "harbour-pysubs2.sub", {"fps": 25}),
        ("mpl2", "mpl2", "harbour-pysubs2.txt", {}),
    ]:
        out = fx / folder / name
        out.parent.mkdir(parents=True, exist_ok=True)
        subs.save(str(out), format_=fmt, **kw)


def pycaption_files(fx: Path, work: Path):
    en = pycaption.SRTReader().read((work / "script.srt").read_text(), lang="en-US")
    fr = pycaption.SRTReader().read((work / "script-fr.srt").read_text(), lang="fr-FR")
    both = pycaption.CaptionSet(
        {"en-US": en.get_captions("en-US"), "fr-FR": fr.get_captions("fr-FR")},
        styles=en.get_styles(),
    )
    for folder, name, text in [
        ("scc", "harbour-pycaption.scc", pycaption.SCCWriter().write(en)),
        ("ttml", "harbour-pycaption.dfxp", pycaption.DFXPWriter().write(en)),
        ("sami", "harbour-two-languages-pycaption.smi", pycaption.SAMIWriter().write(both)),
    ]:
        out = fx / folder / name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")


def m3u8_files(fx: Path):
    master = m3u8.M3U8()
    master.version = 6
    master.is_independent_segments = True
    for group, lang, name, default in (("aud", "en", "English", True), ("aud", "fr", "Français", False)):
        master.add_media(m3u8.Media(uri=f"audio/{lang}/index.m3u8", type="AUDIO", group_id=group, language=lang,
                                    name=name, default="YES" if default else "NO", autoselect="YES", channels="2"))
    master.add_media(m3u8.Media(uri="subs/en/index.m3u8", type="SUBTITLES", group_id="subs", language="en",
                                name="English", default="NO", autoselect="YES", forced="NO"))
    for bw, res, codecs in ((800_000, (640, 360), "avc1.4d401e,mp4a.40.2"),
                            (2_400_000, (1280, 720), "avc1.4d401f,mp4a.40.2"),
                            (6_000_000, (1920, 1080), "hvc1.2.4.L123.B0,mp4a.40.2")):
        master.add_playlist(m3u8.Playlist(
            uri=f"video/{res[1]}p/index.m3u8",
            stream_info={"bandwidth": bw, "average_bandwidth": bw * 9 // 10, "resolution": f"{res[0]}x{res[1]}",
                         "codecs": codecs, "frame_rate": 25.0, "audio": "aud", "subtitles": "subs",
                         "video_range": "SDR"},
            media=master.media, base_uri=""))
    master.add_iframe_playlist(m3u8.IFramePlaylist(
        uri="video/720p/iframes.m3u8", iframe_stream_info={"bandwidth": 240_000, "resolution": "1280x720",
                                                           "codecs": "avc1.4d401f"}, base_uri=""))
    master.session_data.append(m3u8.model.SessionData("com.saltmere.title", value="Saltmere Harbour"))
    (fx / "hls").mkdir(parents=True, exist_ok=True)
    (fx / "hls" / "harbour-master-m3u8lib.m3u8").write_text(master.dumps())

    media = m3u8.M3U8()
    media.version = 3
    media.target_duration = 6
    media.media_sequence = 0
    media.playlist_type = "vod"
    key = m3u8.Key(method="AES-128", uri="https://keys.saltmere.example/k1", base_uri="", iv="0x00000000000000000000000000000001")
    for n, d in enumerate([6.0, 6.0, 6.0, 4.5]):
        media.add_segment(m3u8.Segment(uri=f"https://cdn.saltmere.example/harbour/seg{n:03d}.ts", duration=d,
                                       keyobject=key, base_uri=""))
    media.is_endlist = True
    (fx / "hls" / "harbour-encrypted-m3u8lib.m3u8").write_text(media.dumps())


def main():
    fx, work = Path(sys.argv[1]), Path(sys.argv[2])
    pysubs2_files(fx, work)
    pycaption_files(fx, work)
    m3u8_files(fx)


if __name__ == "__main__":
    main()
