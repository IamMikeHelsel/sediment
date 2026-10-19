#!/usr/bin/env python3
"""Generate Zstandard fixtures for tests/zstd_decode.rs.

Oracle: the Python 3.14+ stdlib `compression.zstd` module (libzstd) and
`tarfile` (mode "w:zst"). Hand-built frames (raw/RLE blocks, raw/RLE/
Huffman literals with direct weights, error cases) follow RFC 8878.

Output: tests/fixtures/zstd/ plus manifest.txt with one line per fixture:
    <name> OK <length> <sha256 of decoded content>
    <name> ERR <ZstdError variant>
Run from the repo root:  python3 -I tests/gen/zstd.py
"""
import hashlib
import io
import os
import random
import struct
import sys
import tarfile

try:
    from compression import zstd
except ImportError:  # pragma: no cover
    sys.exit("needs Python 3.14+ (compression.zstd)")

OUT = os.path.join(os.path.dirname(__file__), "..", "fixtures", "zstd")
os.makedirs(OUT, exist_ok=True)
for f in os.listdir(OUT):
    os.remove(os.path.join(OUT, f))
manifest = []
P = zstd.CompressionParameter


def ok(name, blob, content):
    # Self-check against the oracle decoder where it applies.
    if not name.endswith(".tar.zst"):
        assert zstd.decompress(blob) == content, name
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(blob)
    manifest.append(f"{name} OK {len(content)} {hashlib.sha256(content).hexdigest()}")


def err(name, blob, variant):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(blob)
    manifest.append(f"{name} ERR {variant}")


# ---------------------------------------------------------------- inputs
rng = random.Random(20261019)
WORDS = [b"alpha", b"beta", b"gamma", b"delta", b"archive", b"stream", b"block",
         b"sediment", b"zstandard", b"frame", b"literal", b"sequence", b"offset",
         b"huffman", b"entropy", b"window", b"\xc3\xa9t\xc3\xa9", b"\xe6\x97\xa5"]


def text(n):
    out = bytearray()
    while len(out) < n:
        line = b" ".join(rng.choice(WORDS) for _ in range(rng.randint(3, 12)))
        out += line + (b".\n" if rng.random() < 0.3 else b"\n")
    return bytes(out[:n])


INPUTS = {
    "empty": b"",
    "one": b"A",
    "hello": b"Hello, zstd!\n",
    "text": text(24_000),
    "lines": b"".join(b"sediment zstd fixture line %06d of the long test\n" % i for i in range(9000)),
    "random": rng.randbytes(6_000),
    "zeros": bytes(300_000),
    "binary": b"".join(struct.pack("<IHB", i * 37, i % 977, rng.randrange(4))
                       for i in range(1500)),
}


def comp(data, **params):
    opts = {getattr(P, k): v for k, v in params.items()}
    return zstd.compress(data, options=opts)


for name, data in INPUTS.items():
    ok(f"{name}.l3.zst", data and comp(data, compression_level=3) or zstd.compress(data), data)
for lvl in (-5, 1, 9, 19, 22):
    ok(f"text.l{lvl}.zst", comp(INPUTS["text"], compression_level=lvl), INPUTS["text"])
ok("lines.l19.zst", comp(INPUTS["lines"], compression_level=19), INPUTS["lines"])
ok("binary.l19.zst", comp(INPUTS["binary"], compression_level=19), INPUTS["binary"])
for s in zstd.Strategy:
    ok(f"binary.{s.name}.zst", comp(INPUTS["binary"], strategy=s, compression_level=3), INPUTS["binary"])
# Header variants.
ok("text.check.zst", comp(INPUTS["text"], checksum_flag=1), INPUTS["text"])
ok("text.nosize.zst", comp(INPUTS["text"], content_size_flag=0, checksum_flag=1), INPUTS["text"])
ok("text.win10.zst", comp(INPUTS["text"], window_log=10, checksum_flag=1), INPUTS["text"])
ok("lines.ldm.zst", comp(INPUTS["lines"], enable_long_distance_matching=1, window_log=22,
                         checksum_flag=1), INPUTS["lines"])

# Streaming: many small blocks (exercises repeat tables / treeless literals)
# and an unknown content size.
c = zstd.ZstdCompressor(options={P.compression_level: 7, P.checksum_flag: 1})
blob = b""
t = INPUTS["text"]
for i in range(0, len(t), 700):
    blob += c.compress(t[i:i + 700], zstd.ZstdCompressor.FLUSH_BLOCK)
blob += c.flush(zstd.ZstdCompressor.FLUSH_FRAME)
ok("text.stream_blocks.zst", blob, t)

# Multiple frames, skippable frames.
a = comp(INPUTS["hello"], checksum_flag=1)
b = comp(INPUTS["text"], compression_level=5)
skip = struct.pack("<II", 0x184D2A5A, 5) + b"skip!"
ok("multi.zst", a + b, INPUTS["hello"] + INPUTS["text"])
ok("multi_skippable.zst", skip + a + skip + b + struct.pack("<II", 0x184D2A50, 0), INPUTS["hello"] + INPUTS["text"])
ok("only_skippable.zst", skip, b"")
err("multi_trailing.zst", a + b"\x00\x01\x02", "TrailingData")
err("skippable_truncated.zst", struct.pack("<II", 0x184D2A50, 9) + b"abc", "Truncated")

# Dictionary frame: not supported (no dictionary available).
samples = [text(400) for _ in range(200)]
d = zstd.train_dict(samples, 2048)
err("dict.zst", zstd.compress(samples[0], zstd_dict=d), "Unsupported")

# .tar.zst written by tarfile.
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:zst", format=tarfile.PAX_FORMAT) as tf:
    for nm, data in (("a/hello.txt", INPUTS["hello"]), ("a/text.txt", INPUTS["text"]),
                     ("a/empty", b"")):
        ti = tarfile.TarInfo(nm)
        ti.size, ti.mtime, ti.mode = len(data), 1_700_000_000, 0o644
        tf.addfile(ti, io.BytesIO(data))
    ti = tarfile.TarInfo("a/sub")
    ti.type, ti.mtime, ti.mode = tarfile.DIRTYPE, 1_700_000_000, 0o755
    tf.addfile(ti)
tarbytes = zstd.decompress(buf.getvalue())
ok("tree.tar.zst", buf.getvalue(), tarbytes)


# ---------------------------------------------------------------- hand-built
MAGIC = struct.pack("<I", 0xFD2FB528)


def frame(blocks, content_size=None, checksum_of=None, fhd_extra=0):
    """Single-segment frame (FCS 4 bytes) or, without content_size, a frame
    with a 1 MiB window descriptor and no FCS."""
    if content_size is not None:
        fhd = 0x80 | 0x20 | fhd_extra
        hdr = bytes([fhd]) + struct.pack("<I", content_size)
    else:
        fhd = fhd_extra
        hdr = bytes([fhd, (20 - 10) << 3])
    out = MAGIC + hdr
    for i, (btype, size, payload) in enumerate(blocks):
        last = 1 if i == len(blocks) - 1 else 0
        out += struct.pack("<I", last | btype << 1 | size << 3)[:3] + payload
    if checksum_of is not None:
        out += struct.pack("<I", xxh64(checksum_of) & 0xFFFFFFFF)
    return out


M64 = (1 << 64) - 1
P1, P2, P3, P4, P5 = (0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9,
                      0x85EBCA77C2B2AE63, 0x27D4EB2F165667C5)


def rotl(x, r):
    return ((x << r) | (x >> (64 - r))) & M64


def xxh64(data, seed=0):
    """XXH64 (public xxHash spec), used for hand-built checksums."""
    n = len(data)
    i = 0
    if n >= 32:
        v = [(seed + P1 + P2) & M64, (seed + P2) & M64, seed, (seed - P1) & M64]
        while i + 32 <= n:
            for k in range(4):
                lane = struct.unpack_from("<Q", data, i + 8 * k)[0]
                v[k] = rotl((v[k] + lane * P2) & M64, 31) * P1 & M64
            i += 32
        h = (rotl(v[0], 1) + rotl(v[1], 7) + rotl(v[2], 12) + rotl(v[3], 18)) & M64
        for k in range(4):
            h ^= rotl(v[k] * P2 & M64, 31) * P1 & M64
            h = (h * P1 + P4) & M64
    else:
        h = (seed + P5) & M64
    h = (h + n) & M64
    while i + 8 <= n:
        k1 = rotl(struct.unpack_from("<Q", data, i)[0] * P2 & M64, 31) * P1 & M64
        h = (rotl(h ^ k1, 27) * P1 + P4) & M64
        i += 8
    if i + 4 <= n:
        h = (rotl(h ^ (struct.unpack_from("<I", data, i)[0] * P1 & M64), 23) * P2 + P3) & M64
        i += 4
    while i < n:
        h = rotl(h ^ (data[i] * P5 & M64), 11) * P1 & M64
        i += 1
    h ^= h >> 33
    h = h * P2 & M64
    h ^= h >> 29
    h = h * P3 & M64
    h ^= h >> 32
    return h


assert xxh64(b"") == 0xEF46DB3751D8E999


def lit_raw(data):
    n = len(data)
    if n < 32:
        return bytes([n << 3]) + data
    if n < 4096:
        return struct.pack("<H", (n << 4) | 0b0100) + data
    return struct.pack("<I", (n << 4) | 0b1100)[:3] + data


def lit_rle(byte, n):
    return struct.pack("<I", (n << 4) | 0b1101)[:3] + bytes([byte])


def huff_literals(data):
    """Compressed literals, 1 stream, direct (4-bit) weights, no sequences."""
    syms = sorted(set(data))
    assert len(syms) >= 2
    # Give every symbol up to the largest one a weight: present ones 1..,
    # absent ones 0. Weights: most frequent symbols get larger weights.
    freq = {s: data.count(s) for s in syms}
    order = sorted(syms, key=lambda s: -freq[s])
    nb = {}
    # Simple complete code: first symbol 1 bit, next 2 bits, ..., last two equal.
    for i, s in enumerate(order):
        nb[s] = min(i + 1, len(order) - 1)
    max_bits = max(nb.values())
    assert max_bits <= 11
    weights = {s: max_bits + 1 - nb[s] for s in syms}
    maxsym = max(syms)
    explicit = list(range(maxsym))  # last symbol (maxsym) implicit
    wlist = [weights.get(s, 0) for s in explicit]
    # Canonical codes: ascending weight, then symbol, codes counted from 0.
    codes = {}
    code = 0
    for w in range(1, max_bits + 1):
        for s in range(maxsym + 1):
            if weights.get(s) == w:
                n = max_bits + 1 - w
                codes[s] = (code >> (max_bits - n), n)
                code += 1 << (max_bits - n)
    assert code == 1 << max_bits
    # Backward stream: the last symbol written is read first, so write the
    # data in reverse. Bits are appended from the LSB side.
    acc, nbits = 0, 0
    for s in reversed(data):
        c, n = codes[s]
        acc |= c << nbits
        nbits += n
    acc |= 1 << nbits  # end marker
    nbits += 1
    stream = acc.to_bytes((nbits + 7) // 8, "little")
    tree = bytes([127 + len(wlist)])
    for i in range(0, len(wlist), 2):
        hi = wlist[i]
        lo = wlist[i + 1] if i + 1 < len(wlist) else 0
        tree += bytes([hi << 4 | lo])
    body = tree + stream
    regen, csize = len(data), len(body)
    assert regen < 1024 and csize < 1024
    hdr = struct.pack("<I", 0b10 | (0 << 2) | (regen << 4) | (csize << 14))[:3]
    return hdr + body


hello = INPUTS["hello"]
ok("hand.raw.zst", frame([(0, len(hello), hello)], len(hello), hello, 0x04), hello)
ok("hand.rle.zst", frame([(1, 1000, b"z")], 1000), b"z" * 1000)
ok("hand.empty_raw.zst", frame([(0, 0, b"")], 0), b"")
mixed = b"abcabcabd" * 20
body1 = lit_raw(hello) + b"\x00"
body2 = lit_rle(ord("q"), 300) + b"\x00"
body3 = huff_literals(mixed) + b"\x00"
want = hello + b"q" * 300 + mixed + b"tail" + b"r" * 7
ok("hand.mixed.zst", frame([(2, len(body1), body1), (2, len(body2), body2), (2, len(body3), body3),
                            (0, 4, b"tail"), (1, 7, b"r")], None, want, 0x04), want)
big = bytes(range(256)) * 20
body4 = lit_raw(big) + b"\x00"
ok("hand.rawlit_3byte.zst", frame([(2, len(body4), body4)], None), big)
# A compressed block larger than a single-segment window (= content size).
err("bad.block_over_window.zst", frame([(2, len(body4), body4)], len(big)), "InvalidBlock")

# Sequences with RLE-mode tables (no state bits): block 1 uses repeat
# offset 2 (literal length 4), block 2 has literal length 0 and
# Offset_Value 3, i.e. "repeat offset 1 minus one" (RFC 8878 3.1.1.5).
sq1 = lit_raw(b"abcdefgh") + bytes([1, 0x54, 4, 1, 0, 0x02])
sq2 = lit_raw(b"XY") + bytes([1, 0x54, 0, 1, 0, 0x03])
want = b"abcdabcefghfghXY"
ok("hand.rle_seq_repeat.zst", frame([(2, len(sq1), sq1), (2, len(sq2), sq2)], None, want, 0x04), want)
# Same second block first: repeat offset 1 - 1 = 0 is invalid.
err("bad.rep_minus_one_zero.zst", frame([(2, len(sq2), sq2)], None), "Corrupt")
# Match reaching before the start of the frame (offset 8 > 2 bytes).
sq3 = lit_raw(b"ab") + bytes([1, 0x54, 2, 1, 0, 0x03])
err("bad.offset_too_far.zst", frame([(2, len(sq3), sq3)], None), "Corrupt")

# Error cases.
err("bad.reserved_bit.zst", frame([(0, 5, b"hello")], 5, None, 0x08), "InvalidHeader")
err("bad.reserved_block.zst", frame([(3, 5, b"hello")], 5), "InvalidBlock")
err("bad.checksum.zst", frame([(0, 5, b"hello")], 5, b"hellp", 0x04), "ChecksumMismatch")
err("bad.size_short.zst", frame([(0, 5, b"hello")], 6), "SizeMismatch")
err("bad.size_long.zst", frame([(0, 3, b"hel"), (0, 3, b"lo!")], 4), "SizeMismatch")
err("bad.raw_truncated.zst", frame([(0, 9, b"hello")], 9), "Truncated")
err("bad.block_too_big.zst", frame([(1, 200_000, b"x")], None), "InvalidBlock")
err("bad.magic.zst", b"\x28\xb5\x2f\xfe" + b"\x00" * 8, "BadMagic")
# Huffman stream whose last byte has no end marker.
hb = bytearray(huff_literals(mixed))
hb[-1] = 0
hb += b"\x00"
err("bad.huff_marker.zst", frame([(2, len(hb), bytes(hb))], len(mixed)), "Corrupt")
# Treeless literals without a previous Huffman table.
tl = bytes([0b11 | (0 << 2) | ((4 << 4) & 0xF0), (4 >> 4) | (1 << 6), 0]) + b"\x80" + b"\x00"
err("bad.treeless_first.zst", frame([(2, len(tl), tl)], None), "Corrupt")
# Sequences with 'repeat' table mode in the first block.
seqb = lit_raw(b"abc") + bytes([1, 0b11111100]) + b"\x80"
err("bad.repeat_first.zst", frame([(2, len(seqb), seqb)], None), "Corrupt")
# Zero sequences but trailing bytes in the block.
tr = lit_raw(b"abc") + b"\x00\x00"
err("bad.seq_trailing.zst", frame([(2, len(tr), tr)], None), "InvalidBlock")

with open(os.path.join(OUT, "manifest.txt"), "w") as f:
    f.write("\n".join(manifest) + "\n")
print(f"{len(manifest)} fixtures, {sum(os.path.getsize(os.path.join(OUT, x)) for x in os.listdir(OUT))} bytes")
