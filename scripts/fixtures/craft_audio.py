#!/usr/bin/env python3
"""Craft the audio fixtures no available tool writes.

    craft_audio.py <tests/fixtures> <bwf.wav from ffmpeg> <mono.wav>

* wav/bwf-ixml-ffmpeg.wav: ffmpeg's Broadcast Wave file with an iXML chunk
  appended (ffmpeg writes `bext` but not iXML).
* ape/bells-crafted.ape: a Monkey's Audio 3.99 descriptor and header with an
  APEv2 tag. The frame data is a placeholder: whiff reads headers only.
* dsf/bells-crafted.dsf, dff/bells-crafted.dff: DSD Stream File and DSDIFF
  files holding 0.1 s of DSD silence (the 0x69 idle pattern), with an ID3v2
  tag (DSF) and DIIN title / artist chunks (DFF). Both play as silence.

Standard library only; the output is the same on every run.
"""

import struct
import sys
from pathlib import Path


def ape_tag(items, header=True):
    body = b""
    for key, value in items:
        v = value.encode()
        body += struct.pack("<II", len(v), 0) + key.encode() + b"\0" + v
    size = len(body) + 32
    flags = 0x80000000 if header else 0
    head = b"APETAGEX" + struct.pack("<IIII", 2000, size, len(items), flags | 0x20000000) + b"\0" * 8
    foot = b"APETAGEX" + struct.pack("<IIII", 2000, size, len(items), flags) + b"\0" * 8
    return (head if header else b"") + body + foot


TAGS = [
    ("Title", "Harbour Bells"),
    ("Artist", "Saltmere Brass Band"),
    ("Album", "Tides of Saltmere"),
    ("Year", "2024"),
    ("Track", "3/9"),
    ("Genre", "Brass"),
]


def ixml(bwf: Path, out: Path):
    data = bytearray(bwf.read_bytes())
    assert data[:4] == b"RIFF" and data[8:12] == b"WAVE"
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<BWFXML><IXML_VERSION>2.10</IXML_VERSION>'
        "<PROJECT>Saltmere Harbour</PROJECT><SCENE>12</SCENE><TAKE>2</TAKE><TAPE>DAY01</TAPE>"
        "<NOTE>Bells from the harbour wall</NOTE><SPEED><TIMECODE_RATE>25/1</TIMECODE_RATE>"
        "<TIMECODE_FLAG>NDF</TIMECODE_FLAG></SPEED><TRACK_LIST><TRACK_COUNT>1</TRACK_COUNT>"
        "<TRACK><CHANNEL_INDEX>1</CHANNEL_INDEX><NAME>Boom</NAME></TRACK></TRACK_LIST></BWFXML>\n"
    ).encode()
    if len(xml) % 2:
        xml += b"\0"
    data += b"iXML" + struct.pack("<I", len(xml)) + xml
    struct.pack_into("<I", data, 4, len(data) - 8)
    out.write_bytes(bytes(data))


def ape(out: Path, samples: int, rate: int):
    blocks_per_frame = 73728
    frames = (samples + blocks_per_frame - 1) // blocks_per_frame
    final = samples - (frames - 1) * blocks_per_frame
    wav_header = b"RIFF" + struct.pack("<I", 36 + samples * 2) + b"WAVEfmt " + struct.pack(
        "<IHHIIHH", 16, 1, 1, rate, rate * 2, 2, 16
    ) + b"data" + struct.pack("<I", samples * 2)
    frame_data = bytes(range(256)) * 4  # placeholder, never decoded
    seek = struct.pack("<I", 52 + 24 + 4 * frames + len(wav_header)) * frames
    descriptor = b"MAC " + struct.pack(
        "<HHIIIIIII", 3990, 0, 52, 24, len(seek), len(wav_header), len(frame_data), 0, 0
    ) + b"\0" * 16
    header = struct.pack("<HHIIIHHI", 2000, 0, blocks_per_frame, final, frames, 16, 1, rate)
    out.write_bytes(descriptor + header + seek + wav_header + frame_data + ape_tag(TAGS))


def id3v24(frames):
    body = b""
    for fid, text in frames:
        payload = b"\x03" + text.encode()
        n = len(payload)
        syncsafe = bytes([(n >> 21) & 0x7F, (n >> 14) & 0x7F, (n >> 7) & 0x7F, n & 0x7F])
        body += fid.encode() + syncsafe + b"\0\0" + payload
    n = len(body)
    return b"ID3\x04\x00\x00" + bytes([(n >> 21) & 0x7F, (n >> 14) & 0x7F, (n >> 7) & 0x7F, n & 0x7F]) + body


def dsf(out: Path):
    rate, channels, seconds = 2822400, 2, 0.1
    samples = int(rate * seconds)
    block = 4096
    blocks = (samples // 8 + block - 1) // block
    data = b"\x69" * (block * blocks * channels)
    tag = id3v24([("TIT2", "Harbour Bells"), ("TPE1", "Saltmere Brass Band"), ("TDRC", "2024")])
    data_chunk = b"data" + struct.pack("<Q", 12 + len(data)) + data
    fmt = b"fmt " + struct.pack("<QIIIIIIQII", 52, 1, 0, 2, channels, rate, 1, samples, block, 0)
    total = 28 + len(fmt) + len(data_chunk) + len(tag)
    head = b"DSD " + struct.pack("<QQQ", 28, total, 28 + len(fmt) + len(data_chunk))
    out.write_bytes(head + fmt + data_chunk + tag)


def chunk(cid, body):
    pad = b"\0" if len(body) % 2 else b""
    return cid + struct.pack(">Q", len(body)) + body + pad


def dff(out: Path):
    rate, channels = 2822400, 2
    data = b"\x69" * (rate // 8 * channels // 10)  # 0.1 s
    prop = b"SND " + chunk(b"FS  ", struct.pack(">I", rate)) + chunk(
        b"CHNL", struct.pack(">H", channels) + b"SLFTSRGT"
    ) + chunk(b"CMPR", b"DSD " + b"\x0enot compressed\0")
    diin = chunk(b"DITI", struct.pack(">I", 13) + b"Harbour Bells") + chunk(
        b"DIAR", struct.pack(">I", 19) + b"Saltmere Brass Band"
    )
    body = b"DSD " + chunk(b"FVER", struct.pack(">I", 0x01050000)) + chunk(b"PROP", prop) + chunk(
        b"DSD ", data
    ) + chunk(b"DIIN", diin)
    out.write_bytes(b"FRM8" + struct.pack(">Q", len(body)) + body)


def main():
    fx, bwf, mono = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    for d in ("wav", "ape", "dsf", "dff"):
        (fx / d).mkdir(parents=True, exist_ok=True)
    ixml(bwf, fx / "wav" / "bwf-ixml-ffmpeg.wav")
    raw = mono.read_bytes()
    rate = struct.unpack_from("<I", raw, 24)[0]
    ape(fx / "ape" / "bells-crafted.ape", (len(raw) - 44) // 2, rate)
    dsf(fx / "dsf" / "bells-crafted.dsf")
    dff(fx / "dff" / "bells-crafted.dff")


if __name__ == "__main__":
    main()
