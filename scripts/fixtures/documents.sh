#!/usr/bin/env bash
# Regenerate the document fixtures under tests/fixtures/<format>/.
#
# Needs: python3; on macOS also textutil (Word/ODT/RTF), swiftc (Quartz
# PDFs); Ghostscript (gs) for PDF and PostScript; poppler's pdfattach.
# Formats no available tool writes are crafted by craft_documents.py,
# craft_ebooks.py and craft_email.py. The FDF, EPS, LaTeX and BibTeX fixtures
# are hand-written and kept as they are.
#
# Every document is plain and fictitious (Saltmere, Mira Castell, Ana
# Lighthouse…). Run from the repository root:
#
#     scripts/fixtures/documents.sh

set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fx="$root/tests/fixtures"
src="$root/scripts/fixtures/documents"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# ---- crafted with the standard library ----------------------------------------
# Office / OpenDocument packages and plain compound files, ebooks, and the
# e-mail, calendar and contact files.
python3 "$root/scripts/fixtures/craft_documents.py" "$fx"
python3 "$root/scripts/fixtures/craft_ebooks.py" "$root"
python3 "$root/scripts/fixtures/craft_email.py" "$root"

# ---- textutil (macOS): Word, Word 97, ODT and RTF from one HTML page --------
if command -v textutil >/dev/null; then
    for fmt in docx doc odt rtf; do
        mkdir -p "$fx/$fmt"
        textutil -convert "$fmt" -title "Ferry timetable" -subject "Harbour ferries" -author "Mira Castell" \
            -company "Example Ferries" -keywords "ferry, timetable" -creationtime "2024-04-01T04:00:00Z" \
            -output "$fx/$fmt/ferry-textutil.$fmt" "$src/ferry.html"
    done
else
    echo "textutil not found: skipping the ferry-textutil.* fixtures" >&2
fi

# ---- Ghostscript: PDF (xref streams, classic xref, RC4) and PostScript ------
# The EPS and the hand-written PostScript are kept as written.
gs_pdf() { gs -q -dNOPAUSE -dBATCH -sDEVICE=pdfwrite "$@"; }
mkdir -p "$fx/pdf" "$fx/ps" "$fx/eps"
gs_pdf -sPAPERSIZE=a4 -o "$fx/pdf/tides.pdf" "$src/tides.ps"
gs_pdf -sPAPERSIZE=letter -dWriteObjStms=false -dWriteXRefStm=false -o "$fx/pdf/tides-classic.pdf" "$src/tides.ps"
# Encrypted only to set permissions (empty user password).
gs_pdf -sPAPERSIZE=a4 -sOwnerPassword=harbourmaster -dEncryptionR=3 -dKeyLength=128 -dPermissions=-3904 \
    -o "$fx/pdf/tides-locked.pdf" "$src/tides.ps"
printf 'berth,max_draught_m,dries\n3,1.8,yes\n5,4.5,no\n' > "$work/berths.csv"
pdfattach "$fx/pdf/tides.pdf" "$work/berths.csv" "$fx/pdf/tides-attached.pdf"
cp "$src/tides.ps" "$fx/ps/tides.ps"
gs -q -dNOPAUSE -dBATCH -sDEVICE=ps2write -o "$fx/ps/tides-ps2write.ps" "$fx/pdf/tides.pdf"
cp "$src/chart.eps" "$fx/eps/chart.eps"

# ---- Quartz (macOS): a plain PDF and an AES-128 one --------------------------
if command -v swiftc >/dev/null; then
    swiftc -O "$src/quartz_pdf.swift" -o "$work/quartz_pdf"
    "$work/quartz_pdf" "$fx/pdf/log-quartz.pdf" 0
    "$work/quartz_pdf" "$fx/pdf/log-quartz-aes.pdf" 128
else
    echo "swiftc not found: skipping the log-quartz*.pdf fixtures" >&2
fi

echo "document fixtures regenerated; review with: cargo insta test --review"
