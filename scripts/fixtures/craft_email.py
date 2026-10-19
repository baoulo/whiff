#!/usr/bin/env python3
"""Write the e-mail, calendar and contact fixtures (EML, mbox, MHTML, EMLX, MSG,
iCalendar, vCalendar, vCard) with the standard library.

Usage: python3 scripts/fixtures/craft_email.py [repo-root]

All people, domains and messages are fictitious (`*.example` domains); the
files are CC0-1.0. One message carries phishing *signals* (mismatched
Reply-To, display name and link text, failed authentication) so the risk
detection has a fixture; it has no attachment and no payload.
"""

import base64
import struct
import sys
import zlib
from email import policy
from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from office import cfb_bytes  # noqa: E402

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[2])
FIX = ROOT / "tests" / "fixtures"
CEST = timezone(timedelta(hours=2))


def fix_boundaries(m):
    """Deterministic MIME boundaries (the email package picks random ones)."""
    for i, part in enumerate(m.walk()):
        if part.is_multipart():
            part.set_boundary(f"=_saltmere_{i}")
    return m


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print("wrote", path.relative_to(ROOT))


def png(width, height, rgb):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    raw = (b"\x00" + bytes(rgb) * width) * height
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def received(by, frm, when):
    return f"from {frm} ({frm} [192.0.2.25]) by {by} with ESMTPS id 4Vt1; {format_datetime(when)}"


def berth_notice():
    m = EmailMessage(policy=policy.SMTP)
    when = datetime(2024, 5, 1, 8, 30, tzinfo=CEST)
    m["Received"] = received("mx.example.org", "mail.saltmere.example", when + timedelta(minutes=1))
    m["Authentication-Results"] = "mx.example.org; spf=pass smtp.mailfrom=saltmere.example; dkim=pass header.d=saltmere.example; dmarc=pass header.from=saltmere.example"
    m["DKIM-Signature"] = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=saltmere.example; s=mail; h=from:to:subject:date; bh=AAAA; b=BBBB"
    m["From"] = "Saltmere Harbour Office <office@saltmere.example>"
    m["To"] = "Mira Castell <mira@example.org>, Ben Gull <ben@example.org>"
    m["Subject"] = "Berth 5 is free on Friday"
    m["Date"] = format_datetime(when)
    m["Message-ID"] = "<berth5.20240501@saltmere.example>"
    m["X-Mailer"] = "Harbour Mailer 2.1"
    m["Content-Language"] = "en"
    m.set_content("Hello,\n\nBerth 5 is free from Friday noon until Sunday evening.\nPlease confirm by Thursday.\n\nSaltmere Harbour Office\n")
    write(FIX / "eml" / "berth-notice.eml", m.as_bytes())


def newsletter():
    m = EmailMessage(policy=policy.SMTP)
    when = datetime(2024, 5, 3, 7, 0, tzinfo=timezone.utc)
    m["Received"] = received("mx.example.org", "lists.saltmere.example", when + timedelta(seconds=40))
    m["Authentication-Results"] = "mx.example.org; spf=pass smtp.mailfrom=lists.saltmere.example; dkim=pass header.d=saltmere.example"
    m["From"] = "Saltmere Tides <tides@lists.saltmere.example>"
    m["To"] = "mira@example.org"
    m["Subject"] = "Tides for the week of 6 May"
    m["Date"] = format_datetime(when)
    m["Message-ID"] = "<week19.tides@lists.saltmere.example>"
    m["List-Id"] = "Saltmere Tides <tides.lists.saltmere.example>"
    m["List-Unsubscribe"] = "<https://lists.saltmere.example/unsubscribe>"
    m["Precedence"] = "list"
    text = "Spring tides this week: high water 5.2 m on Wednesday.\nFull table: https://tides.example.org/saltmere\n"
    html = (
        "<html><body><h1>Tides for the week of 6 May</h1>"
        "<p>Spring tides this week: high water <b>5.2&nbsp;m</b> on Wednesday.</p>"
        '<p><a href="https://tides.example.org/saltmere">tides.example.org/saltmere</a></p>'
        '<p><a href="https://lists.saltmere.example/unsubscribe">Unsubscribe</a></p></body></html>'
    )
    m.set_content(text)
    m.add_alternative(html, subtype="html")
    m.add_attachment(b"day,high_water_m,low_water_m\nMon,4.8,0.9\nWed,5.2,0.6\nFri,4.9,0.8\n", maintype="text", subtype="csv", filename="tides-week19.csv")
    write(FIX / "eml" / "tides-newsletter.eml", fix_boundaries(m).as_bytes())


def suspicious():
    m = EmailMessage(policy=policy.SMTP)
    when = datetime(2024, 5, 4, 22, 15, tzinfo=timezone.utc)
    m["Received"] = received("mx.example.org", "relay.other.example", when + timedelta(seconds=5))
    m["Authentication-Results"] = "mx.example.org; spf=fail smtp.mailfrom=other.example; dkim=none; dmarc=fail header.from=other.example"
    m["From"] = '"office@saltmere.example" <billing@other.example>'
    m["Reply-To"] = "payments@third.example"
    m["To"] = "mira@example.org"
    m["Subject"] = "Mooring fee reminder"
    m["Date"] = format_datetime(when)
    m["Message-ID"] = "<reminder.20240504@other.example>"
    html = (
        "<html><body><p>Your mooring fee for May is due.</p>"
        '<p><a href="https://other.example/pay">https://saltmere.example/fees</a></p></body></html>'
    )
    m.set_content("Your mooring fee for May is due.\n")
    m.add_alternative(html, subtype="html")
    write(FIX / "eml" / "fee-reminder-signals.eml", fix_boundaries(m).as_bytes())


def mbox():
    msgs = [
        ("office@saltmere.example", "Saltmere Harbour Office <office@saltmere.example>", "Harbour closed on 9 May", datetime(2024, 5, 2, 9, 0, tzinfo=CEST), "The harbour closes for the regatta on 9 May.\n"),
        ("ben@example.org", "Ben Gull <ben@example.org>", "Re: Harbour closed on 9 May", datetime(2024, 5, 2, 10, 12, tzinfo=CEST), "Thanks. Is the fuel berth open?\n\n> The harbour closes for the regatta on 9 May.\n"),
        ("office@saltmere.example", "Saltmere Harbour Office <office@saltmere.example>", "Re: Harbour closed on 9 May", datetime(2024, 5, 2, 11, 3, tzinfo=CEST), "Yes, the fuel berth stays open.\n\nFrom the office: ask on channel 12.\n"),
    ]
    out = []
    for envelope, frm, subject, when, body in msgs:
        m = EmailMessage(policy=policy.default)
        m["From"] = frm
        m["To"] = "harbour-users@lists.saltmere.example"
        m["Subject"] = subject
        m["Date"] = format_datetime(when)
        m["Message-ID"] = f"<{when:%Y%m%d%H%M}.{envelope.split('@')[0]}@{envelope.split('@')[1]}>"
        m.set_content(body)
        # mboxrd: quote body lines starting with "From ".
        raw = m.as_bytes(policy=policy.default.clone(linesep="\n"))
        head, _, rest = raw.partition(b"\n\n")
        rest = b"\n".join(b">" + l if l.startswith(b"From ") or l.startswith(b">From ") else l for l in rest.split(b"\n"))
        stamp = when.astimezone(timezone.utc).strftime("%a %b %e %H:%M:%S %Y")
        out.append(f"From {envelope} {stamp}\n".encode() + head + b"\n\n" + rest.rstrip(b"\n") + b"\n\n")
    write(FIX / "mbox" / "harbour-users.mbox", b"".join(out))


def mhtml():
    boundary = "----=_NextPart_saltmere"
    html = (
        '<!DOCTYPE html><html><head><title>Saltmere tide table</title><link rel="stylesheet" href="style.css"></head>'
        "<body><h1>Saltmere tide table</h1><p>High water today at 12:40 (5.2 m), low water at 18:55 (0.6 m).</p>"
        '<img src="chart.png" alt="Tide curve"></body></html>'
    )
    parts = [
        ("text/html; charset=utf-8", "quoted-printable", "https://tides.example.org/saltmere", html.encode()),
        ("text/css", "quoted-printable", "https://tides.example.org/style.css", b"body { font-family: sans-serif; }\n"),
        ("image/png", "base64", "https://tides.example.org/chart.png", png(32, 16, (30, 90, 160))),
    ]
    lines = [
        "From: <Saved by whiff fixtures>",
        "Snapshot-Content-Location: https://tides.example.org/saltmere",
        "Subject: Saltmere tide table",
        "Date: Wed, 1 May 2024 12:00:00 +0200",
        "MIME-Version: 1.0",
        f'Content-Type: multipart/related; type="text/html"; boundary="{boundary}"',
        "",
    ]
    import quopri

    for ctype, enc, loc, data in parts:
        body = quopri.encodestring(data).decode() if enc == "quoted-printable" else "\n".join(base64.encodebytes(data).decode().split())
        lines += [f"--{boundary}", f"Content-Type: {ctype}", f"Content-Transfer-Encoding: {enc}", f"Content-Location: {loc}", "", body]
    lines.append(f"--{boundary}--")
    write(FIX / "mhtml" / "tide-table.mhtml", ("\r\n".join(lines) + "\r\n").encode())


def emlx():
    m = EmailMessage(policy=policy.SMTP)
    when = datetime(2024, 5, 5, 16, 45, tzinfo=CEST)
    m["From"] = "Ben Gull <ben@example.org>"
    m["To"] = "Mira Castell <mira@example.org>"
    m["Subject"] = "Lighthouse open day"
    m["Date"] = format_datetime(when)
    m["Message-ID"] = "<openday.20240505@example.org>"
    m.set_content("The lighthouse is open to visitors on Saturday from 10:00.\n")
    raw = m.as_bytes(policy=policy.SMTP.clone(linesep="\n"))
    plist = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        "<plist version=\"1.0\">\n<dict>\n\t<key>date-received</key>\n\t<real>1714920300</real>\n\t<key>flags</key>\n\t<integer>8590195713</integer>\n"
        "\t<key>remote-id</key>\n\t<string>4242</string>\n</dict>\n</plist>\n"
    ).encode()
    write(FIX / "emlx" / "4242.emlx", f"{len(raw)}\n".encode() + raw + plist)


def utf16(s):
    return s.encode("utf-16-le")


def fixed(entries, header):
    out = b"\0" * header
    for tag, value in entries:
        out += struct.pack("<II", tag, 6) + value
    return out


def filetime(dt):
    return struct.pack("<Q", int((dt.timestamp() + 11644473600) * 10_000_000))


def msg():
    when = datetime(2024, 5, 1, 8, 30, tzinfo=CEST)
    headers = (
        f"Received: {received('mx.example.org', 'mail.saltmere.example', when)}\r\n"
        "Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=saltmere.example; dkim=pass header.d=saltmere.example\r\n"
        "From: Saltmere Harbour Office <office@saltmere.example>\r\nTo: Mira Castell <mira@example.org>\r\n"
        "Subject: Berth 5 is free on Friday\r\nMessage-ID: <berth5.20240501@saltmere.example>\r\n"
    )
    streams = [
        ("__properties_version1.0", fixed([(0x00390040, filetime(when)), (0x0E060040, filetime(when + timedelta(minutes=1))), (0x00170003, struct.pack("<Q", 1))], 32)),
        ("__substg1.0_001A001F", utf16("IPM.Note")),
        ("__substg1.0_0037001F", utf16("Berth 5 is free on Friday")),
        ("__substg1.0_0070001F", utf16("Berth 5 is free on Friday")),
        ("__substg1.0_0C1A001F", utf16("Saltmere Harbour Office")),
        ("__substg1.0_5D01001F", utf16("office@saltmere.example")),
        ("__substg1.0_0E04001F", utf16("Mira Castell")),
        ("__substg1.0_1000001F", utf16("Hello,\r\n\r\nBerth 5 is free from Friday noon until Sunday evening.\r\n")),
        ("__substg1.0_1035001F", utf16("<berth5.20240501@saltmere.example>")),
        ("__substg1.0_007D001F", utf16(headers)),
        ("__recip_version1.0_#00000000/__properties_version1.0", fixed([(0x0C150003, struct.pack("<Q", 1))], 8)),
        ("__recip_version1.0_#00000000/__substg1.0_3001001F", utf16("Mira Castell")),
        ("__recip_version1.0_#00000000/__substg1.0_39FE001F", utf16("mira@example.org")),
        ("__attach_version1.0_#00000000/__properties_version1.0", fixed([(0x37050003, struct.pack("<Q", 1))], 8)),
        ("__attach_version1.0_#00000000/__substg1.0_3707001F", utf16("berths.csv")),
        ("__attach_version1.0_#00000000/__substg1.0_370E001F", utf16("text/csv")),
        ("__attach_version1.0_#00000000/__substg1.0_37010102", b"berth,max_draught_m,dries\r\n3,1.8,yes\r\n5,4.5,no\r\n"),
        ("__nameid_version1.0/__substg1.0_00020102", b""),
    ]
    write(FIX / "msg" / "berth-notice.msg", cfb_bytes(streams))


def crlf(text):
    return text.strip("\n").replace("\n", "\r\n").encode() + b"\r\n"


def ics():
    write(
        FIX / "ics" / "harbour-events.ics",
        crlf(
            """
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Saltmere Harbour//Events 1.0//EN
CALSCALE:GREGORIAN
METHOD:PUBLISH
X-WR-CALNAME:Saltmere harbour events
X-WR-CALDESC:Regattas, open days and closures at the fictitious port of Saltmere.
X-WR-TIMEZONE:Europe/Paris
BEGIN:VTIMEZONE
TZID:Europe/Paris
BEGIN:DAYLIGHT
TZOFFSETFROM:+0100
TZOFFSETTO:+0200
DTSTART:19700329T020000
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU
TZNAME:CEST
END:DAYLIGHT
BEGIN:STANDARD
TZOFFSETFROM:+0200
TZOFFSETTO:+0100
DTSTART:19701025T030000
RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU
TZNAME:CET
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
UID:regatta-2024@saltmere.example
DTSTAMP:20240401T090000Z
CREATED:20240401T090000Z
LAST-MODIFIED:20240415T120000Z
DTSTART;TZID=Europe/Paris:20240509T100000
DTEND;TZID=Europe/Paris:20240509T170000
RRULE:FREQ=YEARLY
SUMMARY:Saltmere regatta
DESCRIPTION:The harbour is closed to traffic during the regatta.\nResults: https://saltmere.example/regatta
LOCATION:Outer mole
GEO:43.2951;5.3739
CATEGORIES:Sailing,Closure
STATUS:CONFIRMED
ORGANIZER;CN=Saltmere Harbour Office:mailto:office@saltmere.example
ATTENDEE;CN=Mira Castell;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED:mailto:mira@example.org
ATTENDEE;CN=Ben Gull;ROLE=OPT-PARTICIPANT;PARTSTAT=TENTATIVE:mailto:ben@example.org
BEGIN:VALARM
ACTION:DISPLAY
DESCRIPTION:Regatta tomorrow
TRIGGER:-P1D
END:VALARM
END:VEVENT
BEGIN:VEVENT
UID:openday-2024@saltmere.example
DTSTAMP:20240401T090000Z
DTSTART;VALUE=DATE:20240601
DTEND;VALUE=DATE:20240602
SUMMARY:Lighthouse open day
LOCATION:Saltmere light
CLASS:PUBLIC
END:VEVENT
BEGIN:VTODO
UID:buoys-2024@saltmere.example
DTSTAMP:20240401T090000Z
DUE:20240430T160000Z
SUMMARY:Inspect the visitors' mooring buoys
STATUS:NEEDS-ACTION
CLASS:PRIVATE
END:VTODO
END:VCALENDAR
"""
        ),
    )


def vcs():
    write(
        FIX / "vcs" / "ferry-strike.vcs",
        crlf(
            """
BEGIN:VCALENDAR
VERSION:1.0
PRODID:-//Example Ferries//Planner 3//EN
BEGIN:VEVENT
DTSTART:20240520T060000Z
DTEND:20240520T180000Z
SUMMARY:No ferry service to Gull Island
DESCRIPTION;ENCODING=QUOTED-PRINTABLE:Ferries do not run on 20 May.=0D=0AThe first ferry on 21 May leaves at 07:15.
CATEGORIES:FERRY
AALARM:20240519T180000Z
END:VEVENT
END:VCALENDAR
"""
        ),
    )


def vcf():
    photo = "\n ".join(base64.encodebytes(png(8, 8, (90, 120, 160))).decode().split())
    write(
        FIX / "vcf" / "harbour-crew.vcf",
        crlf(
            f"""
BEGIN:VCARD
VERSION:4.0
PRODID:-//Saltmere Harbour//Contacts 1.0//EN
KIND:individual
FN:Mira Castell
N:Castell;Mira;;;
ORG:Example Ferries;Timetables
TITLE:Scheduler
EMAIL;TYPE=work:mira@example.org
TEL;TYPE=cell,voice;VALUE=uri:tel:+1-555-0100
ADR;TYPE=work:;;1 Quay Street;Saltmere;;SM1 1AA;Freedonia
BDAY:19800203
URL:https://ferries.example.org/team/mira
CATEGORIES:Ferries,Crew
NOTE:Prefers the morning shift.
REV:20240401T090000Z
END:VCARD
BEGIN:VCARD
VERSION:3.0
FN:Ben Gull
N:Gull;Ben;;;
ORG:Saltmere Harbour Office
EMAIL;TYPE=INTERNET,HOME:ben@example.org
TEL;TYPE=HOME:+1-555-0101
PHOTO;ENCODING=b;TYPE=PNG:{photo}
END:VCARD
BEGIN:VCARD
VERSION:2.1
N;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:Lighthouse;Ana;;;
FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:Ana Lighthouse
TEL;WORK;FAX:+1-555-0102
EMAIL;INTERNET:ana@saltmere.example
END:VCARD
BEGIN:VCARD
VERSION:4.0
KIND:org
FN:Saltmere Harbour Office
ORG:Saltmere Harbour Office
EMAIL:office@saltmere.example
TEL;TYPE=work:+1-555-0199
END:VCARD
"""
        ),
    )


if __name__ == "__main__":
    berth_notice()
    newsletter()
    suspicious()
    mbox()
    mhtml()
    emlx()
    msg()
    ics()
    vcs()
    vcf()
