#!/usr/bin/env bash
# Regenerate the document fixtures under tests/fixtures/<format>/.
#
# Needs: python3, cargo; on macOS also textutil (Word/ODT/RTF), swiftc
# (Quartz PDFs); Ghostscript (gs) for PDF and PostScript; poppler's
# pdfattach; Java 11+ and curl for the Apache POI files (xls, ppt, encrypted
# OOXML), whose jars are fetched once from Maven Central.
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
            -company "Example Ferries" -keywords "(ferry, timetable)" -creationtime "2024-04-01T04:00:00Z" \
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
rm -f "$fx/pdf/tides-attached.pdf"
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

# ---- third-party Rust writers: xlsx, docx, pptx ------------------------------
# rust_xlsxwriter, simple_excel_writer, docx-rs and ppt-rs (scripts/fixtures/office_gen,
# a crate of its own with a committed Cargo.lock).
cargo run -q --release --locked --manifest-path "$root/scripts/fixtures/office_gen/Cargo.toml" -- "$fx"
python3 "$root/scripts/fixtures/pin_dates.py" "$fx/xlsx/harbour-dues-xlsxwriter.xlsx" \
    "$fx/xlsx/berths-simple.xlsx" "$fx/docx/notice-docxrs.docx"
python3 "$root/scripts/fixtures/pin_dates.py" --core 2024-04-01T09:00:00Z "$fx/pptx/briefing-pptrs.pptx"

# ---- Apache POI (Java 11+): xls, ppt, encrypted OOXML -----------------------
# BIFF8 workbooks and PowerPoint 97 slide shows, plain and RC4 CryptoAPI
# encrypted, and agile / standard encrypted copies of notice-docxrs.docx.
# The jars come from Maven Central into a cache and are checked by SHA-256.
# Encryption salts are random, so the encrypted files differ on every run.
poi_jars=(
    "org/apache/poi/poi/5.4.1/poi-5.4.1.jar da5abf42da4604c5a7bca38956af6e9d6f196d9b6d4cb7eabee4f480b580d505"
    "org/apache/poi/poi-scratchpad/5.4.1/poi-scratchpad-5.4.1.jar 6497ba15c1cba7062aa71661a8d776d321b1f998bb2bfa19b57d7e35606381f1"
    "commons-codec/commons-codec/1.18.0/commons-codec-1.18.0.jar ba005f304cef92a3dede24a38ad5ac9b8afccf0d8f75839d6c1338634cf7f6e4"
    "org/apache/commons/commons-collections4/4.4/commons-collections4-4.4.jar 1df8b9430b5c8ed143d7815e403e33ef5371b2400aadbe9bda0883762e0846d1"
    "org/apache/commons/commons-math3/3.6.1/commons-math3-3.6.1.jar 1e56d7b058d28b65abd256b8458e3885b674c1d588fa43cd7d1cbb9c7ef2b308"
    "commons-io/commons-io/2.18.0/commons-io-2.18.0.jar f3ca0f8d63c40e23a56d54101c60d5edee136b42d84bfb85bc7963093109cf8b"
    "com/zaxxer/SparseBitSet/1.3/SparseBitSet-1.3.jar f76b85adb0c00721ae267b7cfde4da7f71d3121cc2160c9fc00c0c89f8c53c8a"
    "org/apache/logging/log4j/log4j-api/2.24.3/log4j-api-2.24.3.jar 5b4a0a0cd0e751ded431c162442bdbdd53328d1f8bb2bae5fc1bbeee0f66d80f"
)
if command -v java >/dev/null; then
    cache="${XDG_CACHE_HOME:-$HOME/.cache}/whiff-fixtures/poi-5.4.1"
    mkdir -p "$cache"
    cp_list=""
    for entry in "${poi_jars[@]}"; do
        path=${entry% *} sum=${entry#* } jar="$cache/$(basename "${entry% *}")"
        [ -f "$jar" ] || curl -sSfL -o "$jar" "https://repo1.maven.org/maven2/$path"
        echo "$sum  $jar" | shasum -a 256 -c -q
        cp_list="$cp_list:$jar"
    done
    mkdir -p "$fx/xls" "$fx/ppt" "$fx/office_encrypted"
    # POI logs through log4j-api without a provider; drop that one notice.
    java -cp "${cp_list#:}" "$src/PoiFixtures.java" "$fx" "$fx/docx/notice-docxrs.docx" 2>&1 |
        { grep -v 'could not find a logging provider' || true; }
else
    echo "java not found: skipping the Apache POI fixtures (xls, ppt, office_encrypted)" >&2
fi

echo "document fixtures regenerated; review with: cargo insta test --review"
