#!/usr/bin/env bash
# Regenerate the score fixtures under tests/fixtures/<format>/.
#
# Needs Python 3 with network access once: mido 1.3.3, music21 9.9.1,
# verovio 6.3.0 and pyguitarpro 0.11 are installed into a throwaway
# virtual environment. Several writers produce each format on purpose
# (mido, music21 and verovio for MIDI; music21 and craft_scores.py for
# MusicXML; verovio for MEI; pyguitarpro for Guitar Pro), so the extractors
# are not tested only against one implementation; craft_scores.py writes
# what none of them does (tracker modules, RIFF MIDI, ABC, LilyPond,
# MuseScore).
#
# Titles and names are fictitious (Saltmere, Ana Lighthouse, Ben Gull).
# music21 writes the date of the run into its MusicXML, so those files
# differ between runs. Run from the repository root:
#
#     scripts/fixtures/scores.sh

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

python3 "$root/scripts/fixtures/craft_scores.py" "$fx"
python3 -m venv "$work/venv"
PIP_DISABLE_PIP_VERSION_CHECK=1 "$work/venv/bin/pip" install -q \
    mido==1.3.3 music21==9.9.1 verovio==6.3.0 pyguitarpro==0.11
"$work/venv/bin/python" "$root/scripts/fixtures/score_tools.py" "$fx"

echo "score fixtures written to $fx"
