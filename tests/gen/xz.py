#!/usr/bin/env python3
"""Generate LZMA / LZMA2 / .xz fixtures using only the Python stdlib `lzma`
module (liblzma) as the oracle. Output: tests/fixtures/lzma/.

Run from the repo root:  python3 -I tests/gen/xz.py
"""
import lzma
import os
import random
import struct
import zlib

OUT = os.path.join(os.path.dirname(__file__), "..", "fixtures", "lzma")
os.makedirs(OUT, exist_ok=True)


def w(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)


# ---------------------------------------------------------------- inputs
def compressible():
    # Must match `compressible()` in tests/lzma_decode.rs.
    return b"".join(b"sediment lzma fixture line %05d\n" % i for i in range(2000))


rng = random.Random(20261019)
random_data = rng.randbytes(4096)
words = [b"alpha", b"beta", b"gamma", b"delta", b"archive", b"stream", b"block",
         b"index", b"range", b"coder", b"literal", b"match", b"rep", b"\n"]
text = b" ".join(rng.choice(words) for _ in range(3500))

inputs = {
    "empty": b"",
    "one": b"A",
    "text": text,
    "random": random_data,
    # "comp" is not stored; tests rebuild it from the formula.
    "comp": compressible(),
}
w("random.bin", random_data)
w("text.bin", text)

RAW_DICT = 1 << 20

for name, data in inputs.items():
    for preset, tag in ((0, "p0"), (6, "p6"), (9 | lzma.PRESET_EXTREME, "p9e")):
        w(f"{name}.{tag}.xz", lzma.compress(data, format=lzma.FORMAT_XZ, preset=preset))
    w(f"{name}.lzma", lzma.compress(data, format=lzma.FORMAT_ALONE))
    w(f"{name}.lzma2.raw", lzma.compress(
        data, format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA2, "dict_size": RAW_DICT}]))
    w(f"{name}.lzma1.raw", lzma.compress(
        data, format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA1, "dict_size": RAW_DICT}]))

# Check variants on the compressible and text inputs.
for cname, cid in (("none", lzma.CHECK_NONE), ("crc32", lzma.CHECK_CRC32),
                   ("crc64", lzma.CHECK_CRC64), ("sha256", lzma.CHECK_SHA256)):
    w(f"comp.check_{cname}.xz", lzma.compress(compressible(), format=lzma.FORMAT_XZ, check=cid))
    w(f"text.check_{cname}.xz", lzma.compress(text, format=lzma.FORMAT_XZ, check=cid))

# Unusual lc/lp/pb in LZMA-alone and LZMA2.
for lc, lp, pb in ((0, 2, 0), (4, 0, 4), (1, 3, 1)):
    filt = {"id": lzma.FILTER_LZMA1, "dict_size": RAW_DICT, "lc": lc, "lp": lp, "pb": pb}
    w(f"text.alone_lc{lc}lp{lp}pb{pb}.lzma", lzma.compress(text, format=lzma.FORMAT_ALONE, filters=[filt]))
    filt2 = dict(filt, id=lzma.FILTER_LZMA2)
    w(f"text.xz_lc{lc}lp{lp}pb{pb}.xz", lzma.compress(text, format=lzma.FORMAT_XZ, filters=[filt2]))

# Multi-stream concatenations (with and without stream padding).
a = lzma.compress(text, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32)
b = lzma.compress(random_data, format=lzma.FORMAT_XZ, check=lzma.CHECK_SHA256)
c = lzma.compress(b"", format=lzma.FORMAT_XZ, check=lzma.CHECK_NONE)
w("multi.text_random.xz", a + b)
w("multi.padded.xz", a + b"\0" * 4 + c + b"\0" * 8 + b + b"\0" * 4)
w("multi.badpad.xz", a + b"\0" * 3 + b)

# Unsupported filter chains.
w("text.delta.xz", lzma.compress(text, format=lzma.FORMAT_XZ,
                                 filters=[{"id": lzma.FILTER_DELTA, "dist": 4}, {"id": lzma.FILTER_LZMA2}]))
w("text.x86.xz", lzma.compress(text, format=lzma.FORMAT_XZ,
                               filters=[{"id": lzma.FILTER_X86}, {"id": lzma.FILTER_LZMA2}]))


# ---------------------------------------------- hand-assembled multi-block .xz
def crc64(data):
    crc = 0xFFFFFFFFFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xC96C5795D7870F42 if crc & 1 else crc >> 1
    return crc ^ 0xFFFFFFFFFFFFFFFF


def vli(n):
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def block(data, sizes):
    comp = lzma.compress(data, format=lzma.FORMAT_RAW,
                         filters=[{"id": lzma.FILTER_LZMA2, "dict_size": RAW_DICT}])
    flags = 0
    extra = b""
    if sizes:
        flags |= 0xC0
        extra = vli(len(comp)) + vli(len(data))
    dict_byte = 16  # 2 << (8 + 11) = 1 MiB
    filt = vli(0x21) + vli(1) + bytes([dict_byte])
    body = bytes([flags]) + extra + filt
    hsize = (1 + len(body) + 4 + 3) // 4 * 4
    body = body + b"\0" * (hsize - 4 - 1 - len(body))
    hdr = bytes([hsize // 4 - 1]) + body
    hdr += struct.pack("<I", zlib.crc32(hdr))
    blk = hdr + comp
    unpadded = len(blk) + 8
    blk += b"\0" * (-len(blk) % 4)
    blk += struct.pack("<Q", crc64(data))
    return blk, unpadded, len(data)


def multiblock(chunks):
    flags = b"\x00\x04"  # CRC64
    out = b"\xfd7zXZ\x00" + flags + struct.pack("<I", zlib.crc32(flags))
    recs = []
    for i, d in enumerate(chunks):
        blk, unp, unc = block(d, sizes=(i % 2 == 0))
        out += blk
        recs.append((unp, unc))
    idx = b"\x00" + vli(len(recs)) + b"".join(vli(u) + vli(c) for u, c in recs)
    idx += b"\0" * (-len(idx) % 4)
    idx += struct.pack("<I", zlib.crc32(idx))
    out += idx
    back = struct.pack("<I", len(idx) // 4 - 1) + flags
    out += struct.pack("<I", zlib.crc32(back)) + back + b"YZ"
    return out


mb = multiblock([text[:5000], random_data[:2000], text[5000:]])
assert lzma.decompress(mb) == text[:5000] + random_data[:2000] + text[5000:]
w("multiblock.xz", mb)


# ------------------------------------------------------- malformed variants
def locate_check(xz, check_len):
    back = struct.unpack("<I", xz[-8:-4])[0]
    index_size = (back + 1) * 4
    idx_start = len(xz) - 12 - index_size
    return idx_start - check_len


for cname, clen in (("crc32", 4), ("crc64", 8), ("sha256", 32)):
    good = bytearray(lzma.compress(text, format=lzma.FORMAT_XZ,
                                   check=getattr(lzma, "CHECK_" + cname.upper())))
    good[locate_check(good, clen)] ^= 0x01
    try:
        lzma.decompress(bytes(good))
        raise SystemExit("oracle accepted bad check")
    except lzma.LZMAError:
        pass
    w(f"bad_check_{cname}.xz", bytes(good))
