#!/usr/bin/env python3
"""Write score fixtures with third-party Python libraries, so the
extractors are tested against more than one writer.

    score_tools.py <tests/fixtures>

Needs mido 1.3.3, music21 9.9.1, verovio 6.3.0 and pyguitarpro 0.11
(scores.sh installs them in a throwaway virtual environment).

* mido: Standard MIDI files in formats 0, 1 and 2 (a tempo map, time and
  key signatures, markers, programs, percussion, lyrics, a GM system
  message) and a karaoke file.
* music21: MusicXML, compressed MusicXML and MIDI from one score.
* verovio: MEI and MIDI from that MusicXML, and MEI from an ABC tune.
* pyguitarpro: Guitar Pro 3, 4 and 5 tablatures.
"""

import base64
import sys
from pathlib import Path

import guitarpro
import mido
import music21
import verovio

TITLE = "Harbour Bells"


def midi_files(fx: Path):
    out = fx / "midi"
    out.mkdir(parents=True, exist_ok=True)
    ppq = 480
    song = mido.MidiFile(type=1, ticks_per_beat=ppq)
    conductor = mido.MidiTrack()
    conductor += [
        mido.MetaMessage("track_name", name=TITLE, time=0),
        mido.MetaMessage("copyright", text="CC0 1.0 Saltmere Brass Band", time=0),
        mido.MetaMessage("time_signature", numerator=3, denominator=4, time=0),
        mido.MetaMessage("key_signature", key="D", time=0),
        mido.MetaMessage("set_tempo", tempo=mido.bpm2tempo(100), time=0),
        mido.MetaMessage("marker", text="Verse", time=0),
        mido.MetaMessage("marker", text="Chorus", time=ppq * 6),
        mido.MetaMessage("set_tempo", tempo=mido.bpm2tempo(80), time=0),
        mido.MetaMessage("cue_marker", text="Bells", time=ppq * 3),
        mido.MetaMessage("end_of_track", time=ppq * 3),
    ]
    song.tracks.append(conductor)
    for name, channel, program, pitches, lyric in (
        ("Violin", 0, 40, [74, 76, 78, 79, 81, 83, 85, 86], None),
        ("Flute", 1, 73, [86, 85, 83, 81, 79, 78, 76, 74], ["Har", "bour", "bells", "ring", "out", "o", "ver", "sea"]),
    ):
        t = mido.MidiTrack()
        t.append(mido.MetaMessage("track_name", name=name, time=0))
        t.append(mido.MetaMessage("instrument_name", name=name, time=0))
        if channel == 0:
            t.append(mido.Message("sysex", data=[0x7E, 0x7F, 0x09, 0x01], time=0))
        t.append(mido.Message("program_change", channel=channel, program=program, time=0))
        for i, p in enumerate(pitches):
            if lyric:
                t.append(mido.MetaMessage("lyrics", text=lyric[i] + ("" if i in (0, 5) else " "), time=0))
            t.append(mido.Message("note_on", channel=channel, note=p, velocity=80, time=0))
            t.append(mido.Message("note_off", channel=channel, note=p, velocity=0, time=ppq * 3 // 2))
        song.tracks.append(t)
    drums = mido.MidiTrack()
    drums.append(mido.MetaMessage("track_name", name="Drums", time=0))
    for _ in range(12):
        drums.append(mido.Message("note_on", channel=9, note=42, velocity=60, time=0))
        drums.append(mido.Message("note_off", channel=9, note=42, velocity=0, time=ppq))
    song.tracks.append(drums)
    song.save(out / "harbour-bells-mido.mid")

    flat = mido.MidiFile(type=0, ticks_per_beat=ppq)
    flat.tracks.append(mido.merge_tracks(song.tracks))
    flat.save(out / "harbour-bells-type0-mido.mid")

    # Format 2: independent patterns, each with its own tempo.
    loops = mido.MidiFile(type=2, ticks_per_beat=96)
    for bpm, note in ((120, 60), (90, 67)):
        t = mido.MidiTrack()
        t.append(mido.MetaMessage("set_tempo", tempo=mido.bpm2tempo(bpm), time=0))
        for _ in range(4):
            t.append(mido.Message("note_on", note=note, velocity=70, time=0))
            t.append(mido.Message("note_off", note=note, velocity=0, time=96))
        loops.tracks.append(t)
    loops.save(out / "bell-patterns-type2-mido.mid")

    kar = mido.MidiFile(type=1, ticks_per_beat=ppq)
    words = mido.MidiTrack()
    words.append(mido.MetaMessage("track_name", name="Words", time=0))
    for text in ("@KMIDI KARAOKE FILE", "@V0100", "@LENGL", "@TThe Harbour Wall", "@TBen Gull"):
        words.append(mido.MetaMessage("text", text=text, time=0))
    for i, syl in enumerate(["\\Har", "bour ", "wall ", "at ", "dawn", "/the ", "fer", "ry ", "waits"]):
        words.append(mido.MetaMessage("text", text=syl, time=0 if i == 0 else ppq // 2))
    kar.tracks.append(words)
    melody = mido.MidiTrack()
    melody.append(mido.Message("program_change", program=52, time=0))
    for p in (62, 64, 66, 67, 69, 71, 73, 74, 76):
        melody.append(mido.Message("note_on", note=p, velocity=80, time=0))
        melody.append(mido.Message("note_off", note=p, velocity=0, time=ppq // 2))
    kar.tracks.append(melody)
    kar.save(out / "harbour-wall-mido.kar")


def score():
    s = music21.stream.Score()
    s.metadata = music21.metadata.Metadata()
    s.metadata.title = "The Harbour Wall"
    s.metadata.composer = "Ana Lighthouse"
    s.metadata.copyright = "CC0 1.0"
    words = ["Har", "bour", "wall", "at", "dawn", "the", "fer", "ry", "waits", "for", "gulls", "and"]
    for name, instrument, octave in (("Flute", music21.instrument.Flute(), 5), ("Cello", music21.instrument.Violoncello(), 3)):
        p = music21.stream.Part()
        p.partName = name
        p.insert(0, instrument)
        p.append(music21.key.Key("D"))
        p.append(music21.meter.TimeSignature("3/4"))
        if octave == 5:
            p.append(music21.tempo.MetronomeMark(number=100))
        for i, step in enumerate(["D", "F#", "A", "B", "A", "F#", "E", "D", "F#", "A", "G", "D"]):
            n = music21.note.Note(f"{step}{octave}", quarterLength=1)
            if octave == 5:
                n.lyric = words[i]
            p.append(n)
        s.insert(0, p)
    return s


def music21_files(fx: Path):
    s = score()
    for folder, name, fmt in (
        ("musicxml", "harbour-wall-music21.musicxml", "musicxml"),
        ("mxl", "harbour-wall-music21.mxl", "mxl"),
        ("midi", "harbour-wall-music21.mid", "midi"),
    ):
        (fx / folder).mkdir(parents=True, exist_ok=True)
        s.write(fmt, fp=str(fx / folder / name))


def verovio_files(fx: Path):
    tk = verovio.toolkit()
    assert tk.loadFile(str(fx / "musicxml" / "harbour-wall-music21.musicxml"))
    (fx / "mei").mkdir(parents=True, exist_ok=True)
    (fx / "mei" / "harbour-wall-verovio.mei").write_text(tk.getMEI())
    (fx / "midi" / "harbour-wall-verovio.mid").write_bytes(base64.b64decode(tk.renderToMIDI()))
    tk = verovio.toolkit()
    assert tk.loadFile(str(fx / "abc" / "pilot-launch-crafted.abc"))
    (fx / "mei" / "pilot-launch-verovio.mei").write_text(tk.getMEI())


def guitar_pro_files(fx: Path):
    (fx / "guitar_pro").mkdir(parents=True, exist_ok=True)
    for version, ext in (((3, 0, 0), "gp3"), ((4, 0, 6), "gp4"), ((5, 1, 0), "gp5")):
        song = guitarpro.Song()
        song.title = "Pilot Launch"
        song.subtitle = "Harbour Riff"
        song.artist = "Saltmere Brass Band"
        song.album = "Tides of Saltmere"
        song.words = "Ben Gull"
        song.music = "Mira Castell"
        song.copyright = "CC0 1.0"
        song.tab = "Ana Lighthouse"
        song.instructions = "Play it slow"
        song.notice = ["Fixture for whiff"]
        song.tempo = 96
        guitarpro.write(song, str(fx / "guitar_pro" / f"pilot-launch-pyguitarpro.{ext}"), version=version)


def main():
    fx = Path(sys.argv[1])
    midi_files(fx)
    music21_files(fx)
    verovio_files(fx)
    guitar_pro_files(fx)


if __name__ == "__main__":
    main()
