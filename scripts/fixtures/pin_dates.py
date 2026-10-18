"""Pin the dates writers stamp from the clock, so regenerated fixtures (and
their snapshots) only change when their content does.

    python3 pin_dates.py [--core 2024-04-01T09:00:00Z] FILE...

Every ZIP entry gets the DOS epoch (1980-01-01) as its time; with --core the
created / modified values in docProps/core.xml are replaced as well.
Entry order, names and compression are kept.
"""

import re
import sys
import zipfile


def pin(path, core):
    with zipfile.ZipFile(path) as z:
        entries = [(i, z.read(i.filename)) for i in z.infolist()]
    with zipfile.ZipFile(path, "w") as out:
        for info, data in entries:
            if core and info.filename == "docProps/core.xml":
                data = re.sub(
                    rb"(<dcterms:(created|modified)\b[^>]*>)[^<]*",
                    lambda m: m.group(1) + core.encode(),
                    data,
                )
            fixed = zipfile.ZipInfo(info.filename, (1980, 1, 1, 0, 0, 0))
            fixed.compress_type = info.compress_type
            fixed.external_attr = info.external_attr
            out.writestr(fixed, data)


def main(argv):
    core = None
    if argv[:1] == ["--core"]:
        core, argv = argv[1], argv[2:]
    for path in argv:
        pin(path, core)


if __name__ == "__main__":
    main(sys.argv[1:])
