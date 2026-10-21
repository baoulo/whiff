#!/usr/bin/env python3
"""Compare whiff's score reports with music21 and mido (a dev-time oracle,
like `whiff-dev oracle media` for ffprobe).

    score_oracle.py <whiff binary> <music21 corpus dir> [--midi N] [--verbose]

Needs music21 9.9.1 and mido 1.3.3 (scores.sh's virtual environment).
For every MusicXML / MXL score in the corpus: the number of staves and of
measures in the first part, the notes (chord notes counted one by one,
grace notes included) and the first part's length in quarter notes. For
every ABC file: the number of tunes and their titles. For the first N
corpus scores (default 100) rendered to MIDI by music21: the duration
against mido's. Prints the agreement per field and the first
disagreements.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import mido
import music21


def whiff(binary, path):
    out = subprocess.run([binary, str(path)], capture_output=True, check=False).stdout
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def tally(results, field, want, got, path, misses):
    n, ok = results.get(field, (0, 0))
    good = want == got if not isinstance(want, float) else got is not None and abs(want - got) <= 0.01
    results[field] = (n + 1, ok + (1 if good else 0))
    if not good:
        misses.append((path, field, want, got))


def scores(binary, corpus, results, misses):
    files = sorted(p for p in corpus.rglob("*") if p.suffix in (".mxl", ".xml", ".musicxml"))
    for path in files:
        report = whiff(binary, path)
        if not report or report["identification"]["format"] not in ("musicxml", "mxl"):
            continue
        try:
            s = music21.converter.parse(str(path), forceSource=True)
        except Exception:  # music21 cannot read it: nothing to compare
            continue
        if not hasattr(s, "parts") or not s.parts:
            continue
        f = report["format"][report["identification"]["format"]]
        first = s.parts[0]
        # music21 splits a part of several staves (a piano) into one part
        # per staff: compare with whiff's staves.
        tally(results, "staves", len(s.parts), f.get("staves"), path, misses)
        tally(results, "measures", len(first.getElementsByClass("Measure")), f.get("measures"), path, misses)
        # Notated notes only: chord symbols are harmony, not notes.
        notes = 0
        for n in s.recurse().notes:
            if isinstance(n, music21.harmony.ChordSymbol):
                continue
            notes += len(n.notes) if isinstance(n, music21.chord.ChordBase) else 1
        for n in s.recurse().getElementsByClass("Unpitched"):
            notes += 1
        tally(results, "notes", notes, f.get("notes"), path, misses)
        tally(results, "quarter_notes", float(first.duration.quarterLength), f.get("quarter_notes"), path, misses)


def abc(binary, corpus, results, misses):
    for path in sorted(corpus.rglob("*.abc")):
        report = whiff(binary, path)
        if not report or report["identification"]["format"] != "abc":
            tally(results, "abc_detected", True, False, path, misses)
            continue
        tally(results, "abc_detected", True, True, path, misses)
        f = report["format"]["abc"]
        try:
            handler = music21.abcFormat.ABCHandler()
            handler.process(path.read_text(encoding="latin-1"))
            tunes = len(handler.splitByReferenceNumber() or {}) or 1
        except Exception:
            continue
        tally(results, "abc_tunes", tunes, f.get("tunes"), path, misses)


def midi(binary, corpus, count, results, misses):
    files = sorted(p for p in corpus.rglob("*") if p.suffix in (".mxl", ".xml"))[:count]
    with tempfile.TemporaryDirectory() as tmp:
        for i, path in enumerate(files):
            try:
                out = Path(tmp) / f"{i}.mid"
                music21.converter.parse(str(path)).write("midi", fp=str(out))
                want = round(mido.MidiFile(str(out)).length, 3)
            except Exception:
                continue
            report = whiff(binary, out)
            got = ((report or {}).get("physical", {}).get("media") or {}).get("duration_s")
            tally(results, "midi_duration", want, got, path, misses)


def main():
    binary, corpus = sys.argv[1], Path(sys.argv[2])
    count = int(sys.argv[sys.argv.index("--midi") + 1]) if "--midi" in sys.argv else 100
    verbose = "--verbose" in sys.argv
    results, misses = {}, []
    scores(binary, corpus, results, misses)
    abc(binary, corpus, results, misses)
    midi(binary, corpus, count, results, misses)
    print(f"{'field':<15} {'checked':>7} {'agree':>7} {'rate':>7}")
    for field, (n, ok) in results.items():
        print(f"{field:<15} {n:>7} {ok:>7} {100 * ok / max(n, 1):>6.1f}%")
    shown = misses if verbose else misses[:30]
    if shown:
        print("\ndisagreements:")
        for path, field, want, got in shown:
            print(f"  {path} {field}: music21/mido {want!r}, whiff {got!r}")


if __name__ == "__main__":
    main()
