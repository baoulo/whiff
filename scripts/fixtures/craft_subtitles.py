#!/usr/bin/env python3
"""Craft the subtitle and playlist fixtures no available tool writes, and
the source script the other tools convert.

    craft_subtitles.py <tests/fixtures> <work dir>

Writes into <work dir>: `script.srt` and `script-fr.srt` (the source script
in English and French), `script.ass` (the same with speakers and styles),
and `vobsub.sub` (the VobSub picture stream that goes with the index; it is
an MPEG program stream, kept out of the fixtures).

Writes into <tests/fixtures>:

* sbv/harbour-crafted.sbv: YouTube SBV.
* subviewer/harbour-crafted.sub: SubViewer 2 with its [INFORMATION] header;
  subviewer/harbour-v1-crafted.sub: SubViewer 1 (`[hh:mm:ss]` lines).
* spruce_stl/harbour-crafted.stl: Spruce STL (DVD Studio Pro's text
  subtitles: settings, timecodes in frames, `^I` italics).
* srv3/harbour-crafted.srv3, json3/harbour-crafted.json3: YouTube timed
  text, XML and JSON flavours.
* ebu_stl/harbour-crafted.stl: EBU Tech 3264 subtitles (GSI block and TTI
  blocks, ISO 6937 text, a comment subtitle).
* pgs/harbour-crafted.sup: Blu-ray presentation graphics (one tiny bitmap
  per cue, one forced cue).
* vobsub/harbour-crafted.idx: a VobSub index with English and French tracks.
* lrc/harbour-bells-crafted.lrc: LRC lyrics with ID tags, an offset, word
  times (enhanced LRC) and a line with two time stamps.
* ttml/harbour-ebu-tt-crafted.ttml: EBU-TT style TTML timed in ticks and
  frames, with nested time containers, agents and document metadata.
* vtt/harbour-voices-crafted.vtt: WebVTT with header fields, a note, a
  style and a region block, voices and cue settings.
* m3u, pls, xspf, asx, wpl, cue: hand-written playlists and cue sheets.

Every name, place and host is fictitious (Saltmere, `*.example`). Standard
library only; the output is the same on every run.
"""

import json
import struct
import sys
from pathlib import Path

# (start s, end s, speaker, English, French)
SCRIPT = [
    (0.5, 3.0, "Ana", "Morning on the Saltmere breakwater.", "Le matin sur la digue de Saltmere."),
    (3.2, 5.8, "Ana", "The ferry leaves at seven,\nas it has for forty years.", "Le ferry part à sept heures,\ncomme depuis quarante ans."),
    (6.0, 8.0, None, "[gulls calling]", "[cris de mouettes]"),
    (8.2, 11.0, "Ben", "Tide's turning. We should check\nthe mooring buoys.", "La marée tourne. Vérifions\nles bouées d'amarrage."),
    (11.2, 14.0, "Ana", "The lighthouse keeper logs\nevery boat that passes.", "Le gardien du phare note\nchaque bateau qui passe."),
    (14.2, 16.5, None, "♪ brass band playing ♪", "♪ fanfare au loin ♪"),
    (16.8, 19.5, "Ben", "Harbour office, this is the pilot launch.", "Capitainerie, ici la vedette du pilote."),
    (19.7, 22.0, "Ana", "Fog rolls in from the outer mole by noon.", "Le brouillard arrive du môle vers midi."),
    (22.2, 25.0, "Ben", "Keep to the marked channel\npast the red buoy.", "Restez dans le chenal balisé\naprès la bouée rouge."),
    (25.2, 28.0, "Ana", "By evening the quay is quiet again.", "Le soir, le quai redevient calme."),
]


def clock(t, sep=",", hours=2):
    ms = round(t * 1000)
    h, ms = divmod(ms, 3_600_000)
    m, ms = divmod(ms, 60_000)
    s, ms = divmod(ms, 1000)
    return f"{h:0{hours}d}:{m:02d}:{s:02d}{sep}{ms:03d}"


def write(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)


def sources(work: Path):
    for name, col in (("script.srt", 3), ("script-fr.srt", 4)):
        out = []
        for i, cue in enumerate(SCRIPT, 1):
            out.append(f"{i}\n{clock(cue[0])} --> {clock(cue[1])}\n{cue[col]}\n")
        write(work / name, "\n".join(out))
    ass = [
        "[Script Info]",
        "Title: Saltmere Harbour",
        "Original Script: Ana Lighthouse",
        "Original Translation: Mira Castell",
        "ScriptType: v4.00+",
        "PlayResX: 1280",
        "PlayResY: 720",
        "WrapStyle: 0",
        "",
        "[V4+ Styles]",
        "Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, "
        "Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, "
        "MarginR, MarginV, Encoding",
        "Style: Default,Open Sans,42,&H00FFFFFF,&H000000FF,&H00000000,&H64000000,0,0,0,0,100,100,0,0,1,2,1,2,40,40,30,1",
        "Style: Sound,Open Sans,38,&H00C0E0FF,&H000000FF,&H00000000,&H64000000,0,1,0,0,100,100,0,0,1,2,1,8,40,40,30,1",
        "",
        "[Events]",
        "Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text",
    ]
    for start, end, who, en, _ in SCRIPT:
        style = "Default" if who else "Sound"
        text = en.replace("\n", "\\N")
        if not who:
            text = "{\\an8\\i1}" + text
        ass.append(f"Dialogue: 0,{clock(start, '.', 1)[:-1]},{clock(end, '.', 1)[:-1]},{style},{who or ''},0,0,0,,{text}")
    ass.append("Comment: 0,0:00:28.00,0:00:30.00,Default,,0,0,0,,end of the reel")
    write(work / "script.ass", "\n".join(ass) + "\n")


def sbv():
    return "\n".join(f"{clock(s, '.', 1)},{clock(e, '.', 1)}\n{en}\n" for s, e, _, en, _ in SCRIPT)


def subviewer():
    head = (
        "[INFORMATION]\n[TITLE]Saltmere Harbour\n[AUTHOR]Ana Lighthouse\n[SOURCE]Saltmere Harbour Films\n"
        "[PRG]\n[FILEPATH]\n[DELAY]0\n[CD TRACK]0\n[COMMENT]Fixture for whiff\n[END INFORMATION]\n"
        "[SUBTITLE]\n[COLF]&HFFFFFF,[STYLE]bd,[SIZE]18,[FONT]Arial\n"
    )

    def cs(t):
        c = round(t * 100)
        h, c = divmod(c, 360_000)
        m, c = divmod(c, 6000)
        s, c = divmod(c, 100)
        return f"{h:02d}:{m:02d}:{s:02d}.{c:02d}"

    body = "\n".join(f"{cs(s)},{cs(e)}\n{en.replace(chr(10), '[br]')}\n" for s, e, _, en, _ in SCRIPT)
    return head + body


def srv3():
    out = ['<?xml version="1.0" encoding="utf-8" ?><timedtext format="3">', "<head>",
           '<pen id="1" b="1"/>', '<ws id="1" ju="2"/>', '<wp id="1" ap="7" ah="50" av="100"/>', "</head>", "<body>"]
    for s, e, _, en, _ in SCRIPT:
        t = en.replace("&", "&amp;").replace("<", "&lt;").replace("\n", "<br/>")
        out.append(f'<p t="{round(s * 1000)}" d="{round((e - s) * 1000)}" wp="1" ws="1">{t}</p>')
    out += ["</body>", "</timedtext>", ""]
    return "\n".join(out)


def json3():
    events = [{"tStartMs": 0, "dDurationMs": 28000, "id": 1, "wpWinPosId": 1, "wsWinStyleId": 1}]
    for s, e, _, en, _ in SCRIPT:
        segs = [{"utf8": w} for w in en.replace("\n", " ").split(" ")]
        for g in segs[1:]:
            g["utf8"] = " " + g["utf8"]
        events.append({"tStartMs": round(s * 1000), "dDurationMs": round((e - s) * 1000), "wWinId": 1, "segs": segs})
        events.append({"tStartMs": round(e * 1000) - 10, "wWinId": 1, "aAppend": 1, "segs": [{"utf8": "\n"}]})
    doc = {"wireMagic": "pb3", "pens": [{}], "wsWinStyles": [{}], "wpWinPositions": [{}], "events": events}
    return json.dumps(doc, ensure_ascii=False, indent=1) + "\n"


# ---- EBU STL --------------------------------------------------------------------

ISO6937 = {"é": b"\xc2e", "è": b"\xc1e", "à": b"\xc1a", "ô": b"\xc3o", "ç": b"\xcbc", "♪": b"\xd5", "'": b"'"}


def iso6937(s):
    out = b""
    for ch in s:
        if ch == "\n":
            out += b"\x8a"
        elif ch in ISO6937:
            out += ISO6937[ch]
        else:
            out += ch.encode("ascii")
    return out


def ebu_stl():
    def f(s, n):
        b = s.encode("ascii")
        assert len(b) <= n
        return b + b" " * (n - len(b))

    cues = [(s, e, fr) for s, e, _, _, fr in SCRIPT[:6]]
    gsi = b"850" + b"STL25.01" + b"1" + b"00" + b"0F"
    gsi += f("Saltmere Harbour", 32) + f("Morning", 32) + f("Le port de Saltmere", 32) + f("Le matin", 32)
    gsi += f("Mira Castell", 32) + f("", 32) + f("SALT-0001", 16)
    gsi += b"240401" + b"240402" + b"01"
    gsi += f"{len(cues) + 1:05d}".encode() + f"{len(cues):05d}".encode() + b"001" + b"40" + b"23" + b"1"
    gsi += b"10000000" + b"10000000" + b"1" + b"1" + b"FRA"
    gsi += f("Saltmere Broadcasting", 32) + f("Ana Lighthouse", 32) + f("", 32)
    gsi += b" " * (448 - len(gsi))
    gsi += b" " * (1024 - len(gsi))
    assert len(gsi) == 1024

    def tc(t):
        frames = round(t * 25)
        s, fr = divmod(frames, 25)
        return bytes([10, s // 60, s % 60, fr])

    blocks = b""
    for i, (s, e, text) in enumerate(cues + [(28.0, 30.0, "fin de bobine")]):
        comment = i == len(cues)
        tf = b"\x0d" + iso6937(text) if not comment else iso6937(text)
        if not comment and text.startswith("["):
            tf = b"\x80" + tf + b"\x81"
        tf = tf + b"\x8f" * (112 - len(tf))
        assert len(tf) == 112
        blocks += bytes([0]) + struct.pack("<H", i + 1) + bytes([0xFF, 0]) + tc(s) + tc(e)
        blocks += bytes([20, 2, 1 if comment else 0]) + tf
    return gsi + blocks


# ---- PGS ------------------------------------------------------------------------


def pgs():
    def seg(pts, kind, data):
        return b"PG" + struct.pack(">IIBH", round(pts * 90000), 0, kind, len(data)) + data

    w, h = 8, 2
    rle = (b"\x01" * w + b"\x00\x00") * h
    out = b""
    for n, (s, e, _, _, _) in enumerate(SCRIPT[:4]):
        forced = 0x40 if n == 2 else 0
        state = 0x80 if n == 0 else 0x00
        pcs = struct.pack(">HHBHBBBB", 1920, 1080, 0x10, n * 2, state, 0, 0, 1)
        pcs += struct.pack(">HBBHH", 0, 0, forced, 956, 960)
        wds = bytes([1]) + struct.pack(">BHHHH", 0, 956, 960, w, h)
        pds = bytes([0, 0]) + bytes([1, 235, 128, 128, 255])
        ods = struct.pack(">HBB", 0, 0, 0xC0) + struct.pack(">I", len(rle) + 4)[1:] + struct.pack(">HH", w, h) + rle
        out += seg(s, 0x16, pcs) + seg(s, 0x17, wds) + seg(s, 0x14, pds) + seg(s, 0x15, ods) + seg(s, 0x80, b"")
        clear = struct.pack(">HHBHBBBB", 1920, 1080, 0x10, n * 2 + 1, 0, 0, 0, 0)
        out += seg(e, 0x16, clear) + seg(e, 0x17, wds) + seg(e, 0x80, b"")
    return out


# ---- VobSub -----------------------------------------------------------------------


def vobsub():
    """The index and the program stream of 2 tracks × 3 subpictures."""

    def pts_bytes(pts):
        v = round(pts * 90000)
        return bytes([
            0x21 | ((v >> 29) & 0x0E),
            (v >> 22) & 0xFF,
            0x01 | ((v >> 14) & 0xFE),
            (v >> 7) & 0xFF,
            0x01 | ((v << 1) & 0xFE),
        ])

    def spu(duration):
        # A 4×2 picture in the pattern colour: one line per field, the
        # 2-nibble code 0001 0001 (4 pixels of colour 1). Display at once,
        # stop after `duration` (control delays count 1024 / 90 000 s).
        rle_top = b"\x11"
        rle_bottom = b"\x11"
        data_start = 4
        rle = rle_top + rle_bottom
        ctrl1 = 4 + len(rle)
        stop = round(duration * 90000 / 1024)
        seq1 = struct.pack(">HH", 0, 0)  # delay, next (patched)
        seq1 += b"\x01" + b"\x03\x01\x23" + b"\x04\xff\xf0" + b"\x05" + bytes([0x00, 0x00, 0x03, 0x00, 0x00, 0x01])
        seq1 += b"\x06" + struct.pack(">HH", data_start, data_start + len(rle_top)) + b"\xff"
        ctrl2 = ctrl1 + len(seq1)
        seq1 = struct.pack(">HH", 0, ctrl2) + seq1[4:]
        seq2 = struct.pack(">HH", stop, ctrl2) + b"\x02\xff"
        body = rle + seq1 + seq2
        size = 4 + len(body)
        return struct.pack(">HH", size, ctrl1) + body

    def pack(pts, track, payload):
        scr = b"\x44\x00\x04\x00\x04\x01"  # SCR 0, MPEG-2
        head = b"\x00\x00\x01\xba" + scr + b"\x01\x89\xc3\xf8"
        pes_data = bytes([0x81, 0x80, 5]) + pts_bytes(pts) + bytes([0x20 + track]) + payload
        pes = b"\x00\x00\x01\xbd" + struct.pack(">H", len(pes_data)) + pes_data
        packet = head + pes
        room = 2048 - len(packet)
        assert room >= 6
        return packet + b"\x00\x00\x01\xbe" + struct.pack(">H", room - 6) + b"\xff" * (room - 6)

    sub = b""
    lines = [
        "# VobSub index file, v7 (do not modify this line!)",
        "# Fixture for whiff: two tracks of the Saltmere Harbour script.",
        "size: 720x576",
        "org: 0, 0",
        "scale: 100%, 100%",
        "alpha: 100%",
        "smooth: OFF",
        "fadein/out: 50, 50",
        "align: OFF at LEFT TOP",
        "time offset: 0",
        "forced subs: OFF",
        "palette: 000000, f0f0f0, cccccc, 999999, 3333fa, 1111bb, fa3333, bb1111, 33fa33, 11bb11, fafa33, bbbb11, "
        "33fafa, 11bbbb, fa33fa, bb11bb",
        "custom colors: OFF, tridx: 0000, colors: 000000, 000000, 000000, 000000",
        "",
        "langidx: 0",
        "",
    ]
    for track, lang in ((0, "en"), (1, "fr")):
        lines.append(f"# {'English' if lang == 'en' else 'French'}")
        lines.append(f"id: {lang}, index: {track}")
        for s, e, *_ in SCRIPT[:3]:
            ms = round(s * 1000)
            stamp = f"{ms // 3600000:02d}:{ms // 60000 % 60:02d}:{ms // 1000 % 60:02d}:{ms % 1000:03d}"
            lines.append(f"timestamp: {stamp}, filepos: {len(sub):09x}")
            sub += pack(s, track, spu(e - s))
        lines.append("")
    return "\n".join(lines) + "\n", sub


# ---- playlists --------------------------------------------------------------------

TRACKS = [
    ("Saltmere Brass Band", "Harbour Bells", "Tides of Saltmere", 183.4),
    ("Saltmere Brass Band", "Low Water", "Tides of Saltmere", 241.0),
    ("Mira Castell", "Fog on the Mole", "Outer Mole", 205.6),
    ("Ben Gull", "Pilot Launch", "Outer Mole", 167.2),
]


def playlists(fx: Path):
    m3u = ["#EXTM3U", "#PLAYLIST:Saltmere Evenings"]
    paths = [
        "../Music/Saltmere Brass Band/Tides of Saltmere/03 Harbour Bells.flac",
        "../Music/Saltmere Brass Band/Tides of Saltmere/04 Low Water.flac",
        "C:\\Music\\Mira Castell\\Outer Mole\\Fog on the Mole.mp3",
        "https://media.saltmere.example/ben-gull/pilot-launch.m4a?session=fixture",
    ]
    for (artist, title, album, dur), p in zip(TRACKS, paths):
        m3u += [f"#EXTINF:{round(dur)},{artist} - {title}", f"#EXTALB:{album}", "#EXTGENRE:Brass", p]
    m3u += ["#EXTINF:-1,Saltmere Radio", "http://radio.saltmere.example:8000/live.mp3"]
    write(fx / "m3u/saltmere-evenings-crafted.m3u", "\n".join(m3u) + "\n")

    iptv = [
        '#EXTM3U url-tvg="https://epg.saltmere.example/guide.xml"',
        '#EXTINF:-1 tvg-id="harbour.tv" tvg-name="Harbour TV" tvg-logo="https://img.saltmere.example/harbour.png" group-title="Local",Harbour TV',
        "https://tv.saltmere.example/harbour/index.m3u8",
        '#EXTINF:-1 tvg-id="tides.tv" tvg-name="Tides Channel" group-title="Local",Tides Channel',
        "https://tv.saltmere.example/tides/index.m3u8",
        '#EXTINF:-1 tvg-id="news.tv" tvg-name="Saltmere News" tvg-logo="https://img.saltmere.example/news.png" group-title="News",Saltmere News',
        "https://tv.saltmere.example/news/index.m3u8",
    ]
    write(fx / "m3u/channels-crafted.m3u8", "\n".join(iptv) + "\n")
    write(fx / "m3u/plain-paths-crafted.m3u", "\n".join(paths[:2] + ["../Music/Outer Mole/Fog on the Mole.ogg"]) + "\n")

    pls = ["[playlist]"]
    entries = [("http://radio.saltmere.example:8000/live", "Saltmere Radio", -1)]
    entries += [(f"Music/{a}/{t}.mp3", f"{a} - {t}", round(d)) for a, t, _, d in TRACKS[:2]]
    for i, (f, t, d) in enumerate(entries, 1):
        pls += [f"File{i}={f}", f"Title{i}={t}", f"Length{i}={d}"]
    pls += [f"NumberOfEntries={len(entries)}", "Version=2"]
    write(fx / "pls/saltmere-radio-crafted.pls", "\n".join(pls) + "\n")

    x = ['<?xml version="1.0" encoding="UTF-8"?>', '<playlist version="1" xmlns="http://xspf.org/ns/0/">',
         "  <title>Saltmere Evenings</title>", "  <creator>Ana Lighthouse</creator>",
         "  <annotation>Tunes for the harbour wall at dusk.</annotation>",
         "  <date>2024-04-01T19:30:00Z</date>", "  <license>https://creativecommons.org/publicdomain/zero/1.0/</license>",
         "  <trackList>"]
    for artist, title, album, dur in TRACKS:
        loc = f"file:///media/music/{artist.replace(' ', '%20')}/{title.replace(' ', '%20')}.ogg"
        x += ["    <track>", f"      <location>{loc}</location>", f"      <title>{title}</title>",
              f"      <creator>{artist}</creator>", f"      <album>{album}</album>",
              f"      <duration>{round(dur * 1000)}</duration>", "    </track>"]
    x += ["  </trackList>", "</playlist>", ""]
    write(fx / "xspf/saltmere-evenings-crafted.xspf", "\n".join(x))

    asx = ['<ASX VERSION="3.0">', "  <TITLE>Saltmere Radio</TITLE>", "  <AUTHOR>Saltmere Broadcasting</AUTHOR>",
           "  <COPYRIGHT>2024 Saltmere Broadcasting</COPYRIGHT>", "  <ABSTRACT>Harbour news and music</ABSTRACT>",
           "  <ENTRY>", "    <TITLE>Morning Tide</TITLE>", "    <AUTHOR>Ana Lighthouse</AUTHOR>",
           '    <REF HREF="mms://radio.saltmere.example/morning"/>', '    <REF HREF="http://radio.saltmere.example/morning.wma"/>',
           '    <DURATION VALUE="00:30:00"/>', "  </ENTRY>",
           "  <ENTRY>", "    <TITLE>Saltmere Brass Band - Harbour Bells</TITLE>",
           '    <REF HREF="http://radio.saltmere.example/bells.wma"/>', '    <DURATION VALUE="00:03:03.4"/>', "  </ENTRY>",
           '  <ENTRYREF HREF="http://radio.saltmere.example/evening.asx"/>', "</ASX>", ""]
    write(fx / "asx/saltmere-radio-crafted.asx", "\r\n".join(asx))

    total = round(sum(t[3] for t in TRACKS[:3]) * 1000)
    wpl = ['<?wpl version="1.0"?>', "<smil>", "    <head>",
           '        <meta name="Generator" content="Microsoft Windows Media Player -- 12.0.19041.1"/>',
           f'        <meta name="ItemCount" content="3"/>', f'        <meta name="TotalDuration" content="{total}"/>',
           "        <author>Ana Lighthouse</author>", "        <title>Harbour Wall</title>", "    </head>",
           "    <body>", "        <seq>"]
    for n, (artist, title, album, _) in enumerate(TRACKS[:3]):
        wpl.append(f'            <media src="..\\Music\\{artist}\\{album}\\{title}.wma" '
                   f'tid="{{0D1C2B3A-4F5E-6D7C-8B9A-0{n}1F2E3D4C5B}}"/>')
    wpl += ["        </seq>", "    </body>", "</smil>", ""]
    write(fx / "wpl/harbour-wall-crafted.wpl", "\r\n".join(wpl))

    cue = ['REM GENRE Brass', 'REM DATE 2024', 'REM DISCID 3A0B4C05', 'REM COMMENT "Fixture for whiff"',
           'CATALOG 0000000000017', 'PERFORMER "Saltmere Brass Band"', 'TITLE "Tides of Saltmere"',
           'FILE "Saltmere Brass Band - Tides of Saltmere.flac" WAVE']
    start = 0.0
    for n, (artist, title, _, dur) in enumerate(TRACKS[:3], 1):
        cue += [f"  TRACK {n:02d} AUDIO", f'    TITLE "{title}"', f'    PERFORMER "{artist}"',
                f"    ISRC ZZSAL24000{n:02d}"]
        if n == 2:
            cue += ["    INDEX 00 03:01:00"]
        frames = round(start * 75)
        cue.append(f"    INDEX 01 {frames // 4500:02d}:{frames // 75 % 60:02d}:{frames % 75:02d}")
        start += dur
    write(fx / "cue/tides-of-saltmere-crafted.cue", "\r\n".join(cue) + "\r\n")

    disc = ['FILE "SALTMERE_DISC.BIN" BINARY', "  TRACK 01 MODE1/2352", "    INDEX 01 00:00:00",
            "  TRACK 02 AUDIO", '    TITLE "Harbour Bells"', "    PREGAP 00:02:00", "    INDEX 01 00:10:00",
            "  TRACK 03 AUDIO", '    TITLE "Low Water"', "    FLAGS DCP", "    INDEX 01 03:13:30"]
    write(fx / "cue/disc-image-crafted.cue", "\n".join(disc) + "\n")


def lrc():
    out = ["[ti:Harbour Bells]", "[ar:Saltmere Brass Band]", "[al:Tides of Saltmere]", "[au:Ana Lighthouse]",
           "[by:Mira Castell]", "[length:01:02]", "[offset:+250]", "[re:whiff fixture]", ""]
    for i, (s, _, _, en, _) in enumerate(SCRIPT[:6]):
        line = en.replace("\n", " ")
        m, sec = divmod(s, 60)
        stamp = f"[{int(m):02d}:{sec:05.2f}]"
        if i == 1:
            # Enhanced LRC: a time for each word.
            words = line.split(" ")
            line = " ".join(f"<{int(m):02d}:{sec + 0.4 * k:05.2f}>{w}" for k, w in enumerate(words))
        if i == 5:
            stamp += "[00:40.00]"  # the chorus again
        out.append(stamp + line)
    return "\n".join(out) + "\n"


def ttml_ticks():
    """EBU-TT-D style TTML: ticks, frames, nested time containers, agents."""
    def esc(t):
        return t.replace("&", "&amp;").replace("<", "&lt;")

    body = []
    for i, (s, e, who, en, _) in enumerate(SCRIPT[:6]):
        agent = f' ttm:agent="{who.lower()}"' if who else ""
        text = "<br/>".join(esc(x) for x in en.split("\n"))
        if i < 3:
            body.append(f'      <p xml:id="s{i}" begin="{round(s * 10_000_000)}t" end="{round(e * 10_000_000)}t"{agent}>'
                        f'<span style="white">{text}</span></p>')
        else:
            # Times relative to the second div, which starts at 8 s.
            body.append(f'      <p xml:id="s{i}" begin="{round((s - 8) * 25)}f" dur="{e - s:.1f}s"{agent}>{text}</p>')
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<tt xmlns="http://www.w3.org/ns/ttml" xmlns:ttp="http://www.w3.org/ns/ttml#parameter"
    xmlns:tts="http://www.w3.org/ns/ttml#styling" xmlns:ttm="http://www.w3.org/ns/ttml#metadata"
    xmlns:ebuttm="urn:ebu:tt:metadata" xmlns:ebutts="urn:ebu:tt:style"
    ttp:timeBase="media" ttp:frameRate="25" ttp:tickRate="10000000" ttp:cellResolution="50 30" xml:lang="en-GB">
  <head>
    <metadata>
      <ttm:title>Saltmere Harbour</ttm:title>
      <ttm:copyright>2024 Saltmere Broadcasting</ttm:copyright>
      <ttm:agent xml:id="ana" type="person"><ttm:name type="full">Ana Lighthouse</ttm:name></ttm:agent>
      <ttm:agent xml:id="ben" type="person"><ttm:name type="full">Ben Gull</ttm:name></ttm:agent>
      <ebuttm:documentMetadata>
        <ebuttm:documentOriginalProgrammeTitle>Saltmere Harbour</ebuttm:documentOriginalProgrammeTitle>
        <ebuttm:documentOriginalEpisodeTitle>Morning</ebuttm:documentOriginalEpisodeTitle>
      </ebuttm:documentMetadata>
    </metadata>
    <styling>
      <style xml:id="white" tts:color="#FFFFFF" tts:fontFamily="sansSerif"/>
      <style xml:id="yellow" tts:color="#FFFF00"/>
    </styling>
    <layout>
      <region xml:id="bottom" tts:origin="10% 80%" tts:extent="80% 15%"/>
    </layout>
  </head>
  <body region="bottom">
    <div>
{chr(10).join(body[:3])}
    </div>
    <div begin="8s">
{chr(10).join(body[3:])}
    </div>
  </body>
</tt>
"""


def vtt_voices():
    out = ["WEBVTT - Saltmere Harbour", "Kind: captions", "Language: en-GB", "",
           "NOTE Written for whiff's tests.", "",
           "STYLE", "::cue(v[voice=\"Ana\"]) { color: yellow }", "",
           "REGION", "id:bottom width:80% lines:3 regionanchor:0%,100% viewportanchor:10%,90%", ""]
    for i, (s, e, who, en, _) in enumerate(SCRIPT):
        if i % 3 == 0:
            out.append(f"cue-{i + 1}")
        settings = " region:bottom align:center" if i == 0 else (" line:10% position:50%" if who is None else "")
        out.append(f"{clock(s, '.')[3:] if s < 3600 else clock(s, '.')} --> {clock(e, '.')}{settings}")
        text = en if who is None else f"<v {who}>{en}"
        if i == 4:
            text = f"<v.loud Ana><i>{en}</i>"
        out.append(text)
        out.append("")
    return "\n".join(out)


def subviewer1():
    head = "[TITLE]\nSaltmere Harbour\n[AUTHOR]\nAna Lighthouse\n[SOURCE]\nFixture for whiff\n[FILEPATH]\n\n[DELAY]\n0\n[COMMENT]\n\n[END INFORMATION]\n[SUBTITLE]\n******** START SCRIPT ********\n"

    def hms(t):
        t = int(t)
        return f"[{t // 3600:02d}:{t // 60 % 60:02d}:{t % 60:02d}]"

    body = []
    for s, e, _, en, _ in SCRIPT[:6]:
        body += [hms(s), en.replace("\n", "|"), hms(e), ""]
    return head + "\n".join(body) + "\n"


def spruce():
    def tc(t):
        f = round(t * 25)
        s, f = divmod(f, 25)
        return f"{s // 3600:02d}:{s // 60 % 60:02d}:{s % 60:02d}:{f:02d}"

    out = ["//" + "=" * 60, "// Spruce subtitle file: fixture for whiff", "//" + "=" * 60,
           "$FontName       = Arial", "$FontSize       = 36", "$Bold           = FALSE", "$Italic         = FALSE",
           "$HorzAlign      = Center", "$VertAlign      = Bottom", ""]
    for i, (s, e, who, en, _) in enumerate(SCRIPT):
        text = en.replace("\n", "|")
        if who is None:
            text = "^I" + text + "^I"
        out.append(f"{tc(s)} , {tc(e)} , {text}")
    return "\r\n".join(out) + "\r\n"


def main():
    fx, work = Path(sys.argv[1]), Path(sys.argv[2])
    sources(work)
    write(fx / "sbv/harbour-crafted.sbv", sbv())
    write(fx / "subviewer/harbour-crafted.sub", subviewer())
    write(fx / "subviewer/harbour-v1-crafted.sub", subviewer1())
    write(fx / "spruce_stl/harbour-crafted.stl", spruce())
    write(fx / "srv3/harbour-crafted.srv3", srv3())
    write(fx / "json3/harbour-crafted.json3", json3())
    write(fx / "ebu_stl/harbour-crafted.stl", ebu_stl())
    write(fx / "pgs/harbour-crafted.sup", pgs())
    idx, sub = vobsub()
    write(fx / "vobsub/harbour-crafted.idx", idx)
    write(work / "vobsub.sub", sub)
    write(work / "vobsub.idx", idx)
    write(fx / "lrc/harbour-bells-crafted.lrc", lrc())
    write(fx / "ttml/harbour-ebu-tt-crafted.ttml", ttml_ticks())
    write(fx / "vtt/harbour-voices-crafted.vtt", vtt_voices())
    playlists(fx)


if __name__ == "__main__":
    main()
