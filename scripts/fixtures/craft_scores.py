#!/usr/bin/env python3
"""Craft the score fixtures no available tool writes.

    craft_scores.py <tests/fixtures>

* mod, xm, s3m, it, mptm: tracker modules with a few notes and the
  commands that change timing (speed, tempo, pattern break, position jump,
  pattern loop, pattern delay), so their length is known:
  mod 11.52 s, xm 6.17 s (then it loops), s3m 8.86 s, it and mptm 4.32 s.
  The headers name no real tracker (the version fields are left unknown).
* rmi: a Standard MIDI file wrapped in RIFF `RMID` with an `INFO` list.
* abc: a two-tune book with lyrics and a single tune.
* lilypond: a score with a header, a staff, lyrics and an include.
* mscx, mscz: MuseScore scores (the compressed one with its container).
* musicxml: a timewise MusicXML score.

Every title, name and place is fictitious (Saltmere, Ana Lighthouse,
Ben Gull). Standard library only; the output is the same on every run.
"""

import io
import struct
import sys
import zipfile
from pathlib import Path


def write(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)


def pad(s: str, n: int) -> bytes:
    b = s.encode("latin-1")
    assert len(b) <= n
    return b + b"\0" * (n - len(b))


# ---- MOD -------------------------------------------------------------------------


def mod():
    out = pad("Saltmere Tide", 20)
    names = ["harbour bells", "written for whiff's", "test fixtures"]
    for i in range(31):
        name = names[i] if i < len(names) else ""
        length = 32 if i == 0 else 0  # in words
        out += pad(name, 22) + struct.pack(">HBBHH", length, 0, 64 if i == 0 else 0, 0, 1)
    orders = [0, 1, 0]
    out += bytes([len(orders), 127]) + bytes(orders + [0] * (128 - len(orders))) + b"M.K."

    def cell(sample=0, period=0, effect=0, param=0):
        return bytes([(sample & 0xF0) | (period >> 8), period & 0xFF, ((sample & 0x0F) << 4) | effect, param])

    empty = cell()
    # Pattern 0: speed 3 (0.06 s a row), a break at row 31 (32 rows played).
    p0 = []
    for row in range(64):
        cells = [empty] * 4
        if row == 0:
            cells[0] = cell(1, 428, 0x0F, 3)
        if row == 31:
            cells[1] = cell(0, 0, 0x0D, 0)
        p0.append(b"".join(cells))
    # Pattern 1: speed 6 (0.12 s a row), 64 rows.
    p1 = []
    for row in range(64):
        cells = [empty] * 4
        if row == 0:
            cells[0] = cell(1, 381, 0x0F, 6)
        p1.append(b"".join(cells))
    out += b"".join(p0) + b"".join(p1)
    out += bytes((i * 8) & 0x7F for i in range(64))  # sample data
    return out


# ---- XM --------------------------------------------------------------------------


def xm():
    head = b"Extended Module: " + pad("Low Water", 20) + b"\x1a" + pad("whiff fixture", 20) + struct.pack("<H", 0x0104)
    orders = [0, 1]
    body = struct.pack("<HHHHHHHH", len(orders), 0, 4, 2, 1, 1, 6, 125) + bytes(orders + [0] * (256 - len(orders)))
    head += struct.pack("<I", 4 + len(body)) + body

    def pattern(rows, cells):
        data = b""
        for r in range(rows):
            for ch in range(4):
                c = cells.get((r, ch))
                if c is None:
                    data += b"\x80"
                else:
                    flags, values = 0x80, b""
                    for bit, v in enumerate(c):
                        if v is not None:
                            flags |= 1 << bit
                            values += bytes([v])
                    data += bytes([flags]) + values
        return struct.pack("<IBHH", 9, 0, rows, len(data)) + data

    # (note, instrument, volume, effect, parameter); None leaves a field out.
    p0 = pattern(16, {(0, 0): (49, 1, None, None, None)})  # 16 rows at 0.12 s
    p1 = pattern(32, {
        (0, 0): (53, 1, None, 0x0F, 0x78),  # 120 bpm: 0.125 s a row
        (8, 1): (None, None, None, 0x0E, 0xE2),  # the row plays 3 times
        (31, 2): (None, None, None, 0x0B, 0x00),  # back to the start: the song loops
    })
    inst = struct.pack("<I", 263) + pad("Gull cry", 22) + b"\0" + struct.pack("<H", 1) + struct.pack("<I", 40)
    inst += b"\0" * (263 - len(inst))
    sample = struct.pack("<IIIBbBBbB", 16, 0, 0, 64, 0, 0, 128, 0, 0) + pad("from the outer mole", 22)
    data = bytes([4] * 16)
    return head + p0 + p1 + inst + sample + data


# ---- S3M -------------------------------------------------------------------------


def s3m():
    orders = [0, 1, 255, 255]
    hdr = pad("Pilot Launch", 28) + b"\x1a\x10\0\0"
    hdr += struct.pack("<HHHHHH", len(orders), 1, 2, 0, 0x0000, 2) + b"SCRM"
    hdr += bytes([64, 3 * 2, 125, 0xB0, 0, 0]) + b"\0" * 8 + struct.pack("<H", 0)
    hdr += bytes([0, 1, 2, 3] + [255] * 28)
    assert len(hdr) == 96
    table_end = 96 + len(orders) + 2 + 4
    inst_at, p0_at = 112, 192

    def pattern(cmds):
        data = b""
        for r in range(64):
            for ch, (c, p) in cmds.get(r, {}).items():
                data += bytes([0x80 | ch, c, p])
            data += b"\0"
        return struct.pack("<H", len(data) + 2) + data

    # Pattern 0: speed 3 (0.06 s), break at row 40 (41 rows).
    p0 = pattern({0: {0: (1, 3)}, 40: {1: (3, 0)}})
    # Pattern 1: tempo 150 and speed 6 (0.1 s), 64 rows.
    p1 = pattern({0: {0: (20, 150), 1: (1, 6)}})
    p1_at = p0_at + ((len(p0) + 15) // 16) * 16
    out = bytearray(hdr + bytes(orders) + struct.pack("<H", inst_at // 16) + struct.pack("<HH", p0_at // 16, p1_at // 16))
    out += b"\0" * (inst_at - len(out))
    inst = bytes([1]) + pad("BUOY.SMP", 12) + b"\0\0\0" + struct.pack("<III", 0, 0, 0) + bytes([64, 0, 0, 0])
    inst += struct.pack("<I", 8363) + b"\0" * 12 + pad("red buoy bell", 28) + b"SCRS"
    out += inst
    out += b"\0" * (p0_at - len(out))
    out += p0
    out += b"\0" * (p1_at - len(out))
    out += p1
    assert table_end <= inst_at
    return bytes(out)


# ---- IT --------------------------------------------------------------------------


def it():
    orders = [0, 1, 255]
    message = b"Written for whiff's tests.\rSaltmere harbour at dawn.\0"
    hdr = b"IMPM" + pad("Fog on the Mole", 26) + struct.pack("<H", 0x0410)
    hdr += struct.pack("<HHHHHHHH", len(orders), 0, 1, 2, 0xF000, 0xF000, 0x0009, 0x0001)
    hdr += bytes([128, 48, 6, 125, 128, 0])
    offsets_at = 192 + len(orders)
    smp_at = offsets_at + 4 + 8
    msg_at = smp_at + 80
    p0_at = msg_at + len(message)
    hdr += struct.pack("<HI", len(message), msg_at) + b"\0" * 4
    hdr += bytes([32] * 4 + [160] * 60) + bytes([64] * 64)
    assert len(hdr) == 192

    def pattern(rows, cmds):
        data = b""
        for r in range(rows):
            for ch, (c, p) in cmds.get(r, {}).items():
                data += bytes([0x80 | (ch + 1), 0x08, c, p])
            data += b"\0"
        return struct.pack("<HH", len(data), rows) + b"\0" * 4 + data

    # Pattern 0: speed 4 (0.08 s); rows 5 and 6 loop once (34 rows).
    p0 = pattern(32, {0: {0: (1, 4)}, 5: {0: (19, 0xB0)}, 6: {0: (19, 0xB1)}})
    # Pattern 1: tempo 100 (0.1 s); a break at the last row ends the song.
    p1 = pattern(16, {0: {1: (20, 100)}, 15: {1: (3, 0)}})
    p1_at = p0_at + len(p0)
    out = hdr + bytes(orders) + struct.pack("<I", smp_at) + struct.pack("<II", p0_at, p1_at)
    sample = b"IMPS" + pad("TIDE.WAV", 12) + bytes([0, 64, 0, 64]) + pad("tide gauge", 26)
    sample += bytes([1, 32]) + struct.pack("<IIIIIIIB", 0, 0, 0, 8363, 0, 0, 0, 0) + bytes([0, 0, 0])
    sample += b"\0" * (80 - len(sample))
    out += sample + message + p0 + p1
    return out


# ---- RIFF MIDI ---------------------------------------------------------------------


def rmi():
    def track(events):
        return b"MTrk" + struct.pack(">I", len(events)) + events

    t0 = (b"\x00\xff\x03\x0dHarbour Bells" + b"\x00\xff\x51\x03\x07\xa1\x20" + b"\x00\xff\x58\x04\x04\x02\x18\x08"
          + b"\x00\xff\x2f\x00")
    notes = b"\x00\xc0\x0e"  # tubular bells
    for pitch in (72, 76, 79, 84):
        notes += b"\x00\x90" + bytes([pitch, 80]) + b"\x83\x60\x80" + bytes([pitch, 0])
    notes += b"\x00\xff\x2f\x00"
    smf = b"MThd" + struct.pack(">IHHH", 6, 1, 2, 480) + track(t0) + track(notes)

    def chunk(kind, data):
        return kind + struct.pack("<I", len(data)) + data + (b"\0" if len(data) % 2 else b"")

    info = b"INFO"
    for k, v in (("INAM", "Harbour Bells"), ("IART", "Saltmere Brass Band"), ("ICOP", "CC0 1.0"), ("ICMT", "Fixture for whiff")):
        info += chunk(k.encode(), v.encode() + b"\0")
    body = b"RMID" + chunk(b"data", smf) + chunk(b"LIST", info)
    return b"RIFF" + struct.pack("<I", len(body)) + body


# ---- text notation -----------------------------------------------------------------

ABC_BOOK = """%abc-2.1
%%abc-creator whiff fixture
B:Saltmere Tunes
Z:Fixture for whiff

X:1
T:The Harbour Wall
T:A Jig for the Ferry
C:Ana Lighthouse
O:Saltmere
R:jig
M:6/8
L:1/8
Q:3/8=100
K:D
|:"D"A2F A2d|"G"B2G B2d|"D"A2F "A"E2D|"D"F3 D3:|
w:Har-bour wall at dawn, the fer-ry waits for gulls and men, home a-gain
|:"G"g2e "D"f2d|"A"e2c "D"d3:|

X:2
T:Low Water
C:Ben Gull
R:reel
M:4/4
L:1/8
K:Ador
|:EAAB c2BA|GBdB G2BG|EAAB c2Bc|dBGB A4:|
"""

ABC_TUNE = """X:7
T:Pilot Launch
C:Mira Castell
M:3/4
L:1/4
Q:1/4=90
K:Bb
!p!B,DF|B2A|"Eb"G2F|"Bb"F3|
w:Out past the bu-oy, out to sea
"""

LILYPOND = r"""% A score for whiff's tests.
\version "2.24.0"
\include "english.ly"

\header {
  title = "The Harbour Wall"
  subtitle = "for flute"
  composer = \markup { \italic "Ana Lighthouse" }
  poet = "Ben Gull"
  copyright = "CC0 1.0"
  tagline = ##f
}

melody = \relative c'' {
  \key d \major
  \time 6/8
  \tempo 4. = 100
  a4 fs8 a4 d8 | b4 g8 b4 d8 | a4 fs8 e4 d8 | fs4. d4. \bar "|."
}

\score {
  <<
    \new Staff \with { instrumentName = "Flute" } \melody
    \addlyrics { Har -- bour wall at dawn, the fer -- ry waits for gulls and men }
  >>
  \layout { }
  \midi { }
}
"""

MSCX = """<?xml version="1.0" encoding="UTF-8"?>
<museScore version="4.20">
  <Score>
    <metaTag name="workTitle">The Harbour Wall</metaTag>
    <metaTag name="movementTitle">Dawn</metaTag>
    <metaTag name="composer">Ana Lighthouse</metaTag>
    <metaTag name="lyricist">Ben Gull</metaTag>
    <metaTag name="copyright">CC0 1.0</metaTag>
    <metaTag name="creationDate">2024-04-01</metaTag>
    <metaTag name="source">Fixture for whiff</metaTag>
    <Part id="1">
      <Staff id="1"/>
      <trackName>Flute</trackName>
      <Instrument id="flute">
        <longName>Flute</longName>
        <Channel><program value="73"/></Channel>
      </Instrument>
    </Part>
    <Staff id="1">
      <VBox><Text><style>title</style><text>The Harbour Wall</text></Text></VBox>
      <Measure>
        <voice>
          <KeySig><concertKey>2</concertKey></KeySig>
          <TimeSig><sigN>3</sigN><sigD>4</sigD></TimeSig>
          <Tempo><tempo>1.66667</tempo><text>q = 100</text></Tempo>
          <Chord><durationType>quarter</durationType><Lyrics><syllabic>begin</syllabic><text>Har</text></Lyrics><Note><pitch>74</pitch><tpc>16</tpc></Note></Chord>
          <Chord><durationType>quarter</durationType><Lyrics><syllabic>end</syllabic><text>bour</text></Lyrics><Note><pitch>78</pitch><tpc>20</tpc></Note></Chord>
          <Chord><durationType>quarter</durationType><Lyrics><text>wall</text></Lyrics><Note><pitch>81</pitch><tpc>17</tpc></Note></Chord>
        </voice>
      </Measure>
      <Measure>
        <voice>
          <Chord><durationType>half</durationType><Note><pitch>79</pitch><tpc>15</tpc></Note><Note><pitch>83</pitch><tpc>19</tpc></Note></Chord>
          <Rest><durationType>quarter</durationType></Rest>
          <BarLine><subtype>end</subtype></BarLine>
        </voice>
      </Measure>
    </Staff>
  </Score>
</museScore>
"""

TIMEWISE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE score-timewise PUBLIC "-//Recordare//DTD MusicXML 4.0 Timewise//EN" "http://www.musicxml.org/dtds/timewise.dtd">
<score-timewise version="4.0">
  <work><work-title>Low Water</work-title></work>
  <identification>
    <creator type="composer">Ben Gull</creator>
    <rights>CC0 1.0</rights>
    <encoding><software>whiff fixture</software><encoding-date>2024-04-01</encoding-date></encoding>
  </identification>
  <part-list>
    <score-part id="P1"><part-name>Oboe</part-name></score-part>
    <score-part id="P2"><part-name>Bassoon</part-name></score-part>
  </part-list>
  <measure number="1">
    <part id="P1">
      <attributes><divisions>1</divisions><key><fifths>0</fifths><mode>minor</mode></key><time><beats>4</beats><beat-type>4</beat-type></time></attributes>
      <direction><direction-type><metronome><beat-unit>quarter</beat-unit><per-minute>120</per-minute></metronome></direction-type></direction>
      <note><pitch><step>A</step><octave>4</octave></pitch><duration>2</duration><type>half</type></note>
      <note><pitch><step>E</step><octave>5</octave></pitch><duration>2</duration><type>half</type></note>
    </part>
    <part id="P2">
      <attributes><divisions>1</divisions></attributes>
      <note><pitch><step>A</step><octave>2</octave></pitch><duration>4</duration><type>whole</type></note>
    </part>
  </measure>
  <measure number="2">
    <part id="P1"><note><rest/><duration>4</duration><type>whole</type></note></part>
    <part id="P2"><note><pitch><step>E</step><octave>2</octave></pitch><duration>4</duration><type>whole</type></note></part>
  </measure>
</score-timewise>
"""


def mscz():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in (
            ("META-INF/container.xml", '<?xml version="1.0" encoding="UTF-8"?>\n<container><rootfiles>'
             '<rootfile full-path="harbour-wall.mscx"/></rootfiles></container>\n'),
            ("harbour-wall.mscx", MSCX),
        ):
            info = zipfile.ZipInfo(name, date_time=(2024, 4, 1, 12, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return buf.getvalue()


def main():
    fx = Path(sys.argv[1])
    write(fx / "mod/saltmere-tide-crafted.mod", mod())
    write(fx / "xm/low-water-crafted.xm", xm())
    write(fx / "s3m/pilot-launch-crafted.s3m", s3m())
    write(fx / "it/fog-on-the-mole-crafted.it", it())
    write(fx / "mptm/fog-on-the-mole-crafted.mptm", it())
    write(fx / "rmi/harbour-bells-crafted.rmi", rmi())
    write(fx / "abc/saltmere-tunes-crafted.abc", ABC_BOOK)
    write(fx / "abc/pilot-launch-crafted.abc", ABC_TUNE)
    write(fx / "lilypond/harbour-wall-crafted.ly", LILYPOND)
    write(fx / "mscx/harbour-wall-crafted.mscx", MSCX)
    write(fx / "mscz/harbour-wall-crafted.mscz", mscz())
    write(fx / "musicxml/low-water-timewise-crafted.musicxml", TIMEWISE)


if __name__ == "__main__":
    main()
