#!/usr/bin/env python3
"""Generate Deflate64 (ZIP method 9) fixtures for tests/deflate64.rs.

There is no Deflate64 encoder in the Python stdlib, so this script contains a
tiny Deflate64 encoder written from the public descriptions (RFC 1951 plus
the Deflate64 deltas: 64 KiB window, distance codes 30/31 with base
32769/49153 and 14 extra bits, length code 285 = base 3 + 16 extra bits,
up to 32 distance codes in a dynamic header). It hand-assembles stored,
fixed and dynamic blocks so every extended feature is exercised.

It also writes plain RFC 1951 streams produced by the stdlib `zlib` oracle
whose data provably cannot contain a length-258 match (all 258-byte windows
are distinct) and whose distances are <= 32768, so they never use the codes
whose meaning differs in Deflate64. tests/deflate64.rs checks that both
decoders agree on them.

Outputs (tests/fixtures/deflate64/):
  <name>.d64       raw Deflate64 stream
  <name>.deflate   raw RFC 1951 stream from zlib (cross-check set)
  manifest.txt     "<file> <size> <crc32 hex>" of the expected output

Optional: `--verify-unzip` wraps every .d64 stream in a ZIP entry with
method 9 and decodes it with Info-ZIP `unzip -p` (built with USE_DEFLATE64),
an independent decoder, comparing against the expected bytes. Nothing from
that check is written into the fixture directory.
"""
import heapq
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "fixtures", "deflate64")

# ---------------------------------------------------------------- tables
LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43,
            51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 3]
LEN_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4,
            4, 4, 5, 5, 5, 5, 16]
DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257,
             385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289,
             16385, 24577, 32769, 49153]
DIST_BITS = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9,
             10, 10, 11, 11, 12, 12, 13, 13, 14, 14]
CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
WINDOW = 65536
MAX_MATCH = 65538


def length_code(length, force285=False):
    """(symbol, extra_value, extra_bits) for a Deflate64 match length."""
    assert 3 <= length <= MAX_MATCH
    if force285 or length > 258:
        return 285, length - 3, 16
    for i in range(27, -1, -1):
        if length >= LEN_BASE[i]:
            extra = length - LEN_BASE[i]
            assert extra < (1 << LEN_BITS[i])
            return 257 + i, extra, LEN_BITS[i]
    raise AssertionError


def dist_code(dist):
    assert 1 <= dist <= WINDOW
    for i in range(31, -1, -1):
        if dist >= DIST_BASE[i]:
            extra = dist - DIST_BASE[i]
            assert extra < (1 << DIST_BITS[i])
            return i, extra, DIST_BITS[i]
    raise AssertionError


# ---------------------------------------------------------------- bits
class BitWriter:
    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def bits(self, value, width):
        assert 0 <= value < (1 << width) or width == 0
        self.acc |= value << self.n
        self.n += width
        while self.n >= 8:
            self.out.append(self.acc & 0xFF)
            self.acc >>= 8
            self.n -= 8

    def code(self, code, length):
        """Huffman codes are sent most-significant bit first."""
        rev = 0
        for i in range(length):
            rev |= ((code >> i) & 1) << (length - 1 - i)
        self.bits(rev, length)

    def align(self):
        if self.n:
            self.bits(0, 8 - self.n)

    def finish(self):
        self.align()
        return bytes(self.out)


# ---------------------------------------------------------------- huffman
def canonical(lengths):
    max_len = max(lengths) if lengths else 0
    bl_count = [0] * (max_len + 1)
    for length in lengths:
        if length:
            bl_count[length] += 1
    code = 0
    next_code = [0] * (max_len + 2)
    for bits in range(1, max_len + 1):
        code = (code + bl_count[bits - 1]) << 1 if bits > 1 else 0
        next_code[bits] = code
    codes = [0] * len(lengths)
    for sym, length in enumerate(lengths):
        if length:
            codes[sym] = next_code[length]
            next_code[length] += 1
    return codes


def huffman_lengths(freqs, max_bits):
    """Length-limited Huffman code lengths. Always yields a complete code
    when two or more symbols are used; one used symbol gets length 1 plus a
    dummy partner so the code stays complete."""
    used = [i for i, f in enumerate(freqs) if f]
    lengths = [0] * len(freqs)
    if not used:
        return lengths
    if len(used) == 1:
        lengths[used[0]] = 1
        partner = 0 if used[0] != 0 else 1
        lengths[partner] = 1
        return lengths
    scale = 1
    while True:
        heap = [(max(1, freqs[i] // scale), i, (i,)) for i in used]
        heapq.heapify(heap)
        depth = {i: 0 for i in used}
        tie = len(freqs)
        while len(heap) > 1:
            f1, _, s1 = heapq.heappop(heap)
            f2, _, s2 = heapq.heappop(heap)
            for s in s1 + s2:
                depth[s] += 1
            tie += 1
            heapq.heappush(heap, (f1 + f2, tie, s1 + s2))
        if max(depth.values()) <= max_bits:
            for i in used:
                lengths[i] = depth[i]
            return lengths
        scale *= 2


# ---------------------------------------------------------------- lz77
def lz77(data, max_chain=48, max_len=MAX_MATCH, window=WINDOW, start=0,
         history=b""):
    """Greedy hash-chain LZ77 over `history + data`; only positions from
    len(history) onward are emitted. Tokens: ('L', b) or ('M', len, dist)."""
    buf = history + data
    pos = len(history)
    heads = {}
    prev = {}
    for i in range(max(0, len(history) - window), max(0, len(history) - 2)):
        key = buf[i:i + 3]
        prev[i] = heads.get(key)
        heads[key] = i
    tokens = []
    n = len(buf)
    while pos < n:
        best_len, best_dist = 0, 0
        if pos + 3 <= n:
            key = buf[pos:pos + 3]
            cand = heads.get(key)
            chain = 0
            limit = min(max_len, n - pos)
            while cand is not None and chain < max_chain and pos - cand <= window:
                length = 3
                while length < limit and buf[cand + length] == buf[pos + length]:
                    length += 1
                if length > best_len:
                    best_len, best_dist = length, pos - cand
                    if length == limit:
                        break
                cand = prev.get(cand)
                chain += 1
        step = best_len if best_len >= 3 else 1
        if best_len >= 3:
            tokens.append(("M", best_len, best_dist))
        else:
            tokens.append(("L", buf[pos]))
        for i in range(pos, min(pos + step, n - 2)):
            key = buf[i:i + 3]
            prev[i] = heads.get(key)
            heads[key] = i
        pos += step
    return tokens


def replay(tokens, history=b""):
    out = bytearray(history)
    for t in tokens:
        if t[0] == "L":
            out.append(t[1])
        else:
            _, length, dist = t
            assert 1 <= dist <= min(WINDOW, len(out)), (dist, len(out))
            for _ in range(length):
                out.append(out[-dist])
    return bytes(out[len(history):])


# ---------------------------------------------------------------- blocks
def fixed_lengths():
    lit = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
    return lit, [5] * 32


def write_tokens(w, tokens, lit_len, dist_len, force285=False):
    lit_codes = canonical(lit_len)
    dist_codes = canonical(dist_len) if any(dist_len) else None
    for t in tokens:
        if t[0] == "L":
            w.code(lit_codes[t[1]], lit_len[t[1]])
        else:
            _, length, dist = t
            sym, extra, nbits = length_code(length, force285)
            w.code(lit_codes[sym], lit_len[sym])
            w.bits(extra, nbits)
            dsym, dextra, dbits = dist_code(dist)
            assert dist_len[dsym], "distance symbol without a code"
            w.code(dist_codes[dsym], dist_len[dsym])
            w.bits(dextra, dbits)
    w.code(lit_codes[256], lit_len[256])


def stored_block(w, data, final):
    assert len(data) <= 0xFFFF
    w.bits(1 if final else 0, 1)
    w.bits(0, 2)
    w.align()
    w.bits(len(data), 16)
    w.bits(len(data) ^ 0xFFFF, 16)
    for b in data:
        w.bits(b, 8)


def fixed_block(w, tokens, final, force285=False):
    w.bits(1 if final else 0, 1)
    w.bits(1, 2)
    lit, dist = fixed_lengths()
    write_tokens(w, tokens, lit, dist, force285)


def token_freqs(tokens, force285=False):
    lf = [0] * 286
    df = [0] * 32
    for t in tokens:
        if t[0] == "L":
            lf[t[1]] += 1
        else:
            lf[length_code(t[1], force285)[0]] += 1
            df[dist_code(t[2])[0]] += 1
    lf[256] += 1
    return lf, df


def rle_lengths(lengths):
    """Code-length alphabet encoding: list of (symbol, extra, extra_bits)."""
    out = []
    i = 0
    n = len(lengths)
    while i < n:
        cur = lengths[i]
        run = 1
        while i + run < n and lengths[i + run] == cur:
            run += 1
        if cur == 0 and run >= 3:
            r = min(run, 138)
            if r >= 11:
                out.append((18, r - 11, 7))
            else:
                out.append((17, r - 3, 3))
            i += r
            continue
        if cur != 0 and run >= 4:
            out.append((cur, 0, 0))
            r = min(run - 1, 6)
            out.append((16, r - 3, 2))
            i += 1 + r
            continue
        out.append((cur, 0, 0))
        i += 1
    return out


def dynamic_block(w, tokens, final, force285=False, min_hdist=1,
                  lit_lengths=None, dist_lengths=None):
    lf, df = token_freqs(tokens, force285)
    lit_len = lit_lengths or huffman_lengths(lf, 15)
    if dist_lengths is not None:
        dist_len = dist_lengths
    elif any(df):
        dist_len = huffman_lengths(df, 15)
    else:
        dist_len = [0] * 32
    hlit = 286
    while hlit > 257 and lit_len[hlit - 1] == 0:
        hlit -= 1
    hdist = 32
    while hdist > min_hdist and dist_len[hdist - 1] == 0:
        hdist -= 1
    seq = rle_lengths(list(lit_len[:hlit]) + list(dist_len[:hdist]))
    cf = [0] * 19
    for sym, _, _ in seq:
        cf[sym] += 1
    cl_len = huffman_lengths(cf, 7)
    hclen = 19
    while hclen > 4 and cl_len[CL_ORDER[hclen - 1]] == 0:
        hclen -= 1
    w.bits(1 if final else 0, 1)
    w.bits(2, 2)
    w.bits(hlit - 257, 5)
    w.bits(hdist - 1, 5)
    w.bits(hclen - 4, 4)
    for i in range(hclen):
        w.bits(cl_len[CL_ORDER[i]], 3)
    cl_codes = canonical(cl_len)
    for sym, extra, nbits in seq:
        w.code(cl_codes[sym], cl_len[sym])
        w.bits(extra, nbits)
    padded_dist = list(dist_len) + [0] * (32 - len(dist_len))
    write_tokens(w, tokens, lit_len, padded_dist, force285)


# ---------------------------------------------------------------- data
def lcg_bytes(seed, n):
    s = seed
    out = bytearray()
    for _ in range(n):
        s = (s * 1103515245 + 12345) & 0xFFFFFFFF
        out.append((s >> 16) & 0xFF)
    return bytes(out)


WORDS = [b"the", b"quick", b"brown", b"fox", b"jumps", b"over", b"lazy",
         b"dog", b"sediment", b"archive", b"deflate64", b"window", b"\n",
         b"enhanced", b"pkware", b"method", b"nine", b"zip"]


def text(seed, n):
    s = seed
    out = bytearray()
    while len(out) < n:
        s = (s * 1103515245 + 12345) & 0xFFFFFFFF
        out += WORDS[(s >> 16) % len(WORDS)]
        out += b" "
    return bytes(out[:n])


def unique_text(seed, n):
    """Text whose 258-byte windows are all distinct (checked by caller):
    numbered, varied words so no long repeat exists."""
    s = seed
    out = bytearray()
    k = 0
    while len(out) < n:
        s = (s * 1103515245 + 12345) & 0xFFFFFFFF
        out += WORDS[(s >> 16) % len(WORDS)]
        out += b"%d " % ((s >> 8) % 997)
        k += 1
        if k % 9 == 0:
            out += b"#%d\n" % k
    return bytes(out[:n])


def windows_distinct(data, width=258):
    seen = set()
    for i in range(0, len(data) - width + 1):
        w = data[i:i + width]
        if w in seen:
            return False
        seen.add(w)
    return True


# ---------------------------------------------------------------- cases
def build_cases():
    cases = {}

    w = BitWriter()
    stored_block(w, b"", True)
    cases["empty_stored"] = (w.finish(), b"")

    w = BitWriter()
    fixed_block(w, [], True)
    cases["empty_fixed"] = (w.finish(), b"")

    a, b, c = lcg_bytes(1, 1000), b"", lcg_bytes(2, 500)
    w = BitWriter()
    stored_block(w, a, False)
    stored_block(w, b, False)
    stored_block(w, c, True)
    cases["stored_multi"] = (w.finish(), a + b + c)

    data = b"Hello, Deflate64! Hello, Deflate64!"
    toks = lz77(data)
    w = BitWriter()
    fixed_block(w, toks, True)
    cases["fixed_hello"] = (w.finish(), replay(toks))

    # Length code 285: max length (extra 0xFFFF), min length (extra 0), and
    # a length <= 258 forced through code 285.
    toks = [("L", ord("a")), ("L", ord("b")), ("L", ord("c")),
            ("M", MAX_MATCH, 3), ("M", 3, 1), ("M", 200, 7)]
    w = BitWriter()
    fixed_block(w, toks, True, force285=True)
    cases["fixed_len285"] = (w.finish(), replay(toks))

    # Length 258 via code 284 + 31 and 259 via code 285.
    toks = [("L", 1), ("L", 2), ("M", 258, 2), ("M", 259, 1)]
    w = BitWriter()
    fixed_block(w, toks, True)
    cases["fixed_len258_259"] = (w.finish(), replay(toks))

    # Far distances: codes 30 and 31 including the exact maximum 65536.
    head = lcg_bytes(3, 1200)
    toks = [("L", x) for x in head]
    toks += [("M", 30000, 1), ("M", 30000, 1), ("M", 6000, 1)]  # pad to 67200
    toks += [("M", 1000, 65536)]          # code 31, extra 16383
    toks += [("M", 100, 49153)]           # code 31, extra 0
    toks += [("M", 100, 49152)]           # code 30, extra 16383
    toks += [("M", 100, 32769)]           # code 30, extra 0
    toks += [("M", 100, 32768)]           # code 29 (largest RFC 1951 code)
    toks += [("M", 5000, 40000)]
    w = BitWriter()
    fixed_block(w, toks, True)
    cases["fixed_far_dist"] = (w.finish(), replay(toks))

    # Dynamic block, real LZ77 over data with long-range repeats + long runs.
    base = text(7, 8000)
    r1, r2 = lcg_bytes(9, 3000), lcg_bytes(10, 2000)
    data = base + r1 + r2 + b"z" * 40000 + text(8, 3000) + r2 + \
        b"y" * 12000 + r1 + base[1000:5000]
    toks = lz77(data)
    assert any(t[0] == "M" and t[1] > 258 for t in toks)
    assert any(t[0] == "M" and t[2] > 49152 for t in toks)  # code 31
    w = BitWriter()
    dynamic_block(w, toks, True)
    cases["dynamic_ext"] = (w.finish(), replay(toks))

    # Dynamic block declaring all 32 distance codes but using only short ones.
    data = text(11, 6000)
    toks = lz77(data, max_len=258, window=32768)
    w = BitWriter()
    dynamic_block(w, toks, True, min_hdist=32)
    cases["dynamic_hdist32"] = (w.finish(), replay(toks))

    # Dynamic block with only literals (single zero-length distance code).
    data = lcg_bytes(12, 300)
    toks = [("L", x) for x in data]
    w = BitWriter()
    dynamic_block(w, toks, True)
    cases["dynamic_no_dist"] = (w.finish(), data)

    # Dynamic block with exactly one distance code of length 1 (an
    # incomplete code, permitted by RFC 1951 3.2.7).
    toks = [("L", x) for x in lcg_bytes(15, 600)] + [("M", 40, 600)]
    dl = [0] * 32
    dl[dist_code(600)[0]] = 1
    w = BitWriter()
    dynamic_block(w, toks, True, dist_lengths=dl)
    cases["dynamic_single_dist"] = (w.finish(), replay(toks))

    # Mixed blocks; matches cross block boundaries and reach back into
    # stored data with far distances.
    s1 = lcg_bytes(21, 4000)
    t1 = text(22, 30000)
    t2 = text(23, 40000) + s1
    w = BitWriter()
    stored_block(w, s1, False)
    toks1 = lz77(t1, history=s1)
    fixed_block(w, toks1, False)
    hist = s1 + t1
    toks2 = lz77(t2, history=hist)
    assert any(t[0] == "M" and t[2] > 32768 for t in toks2)
    dynamic_block(w, toks2, False)
    toks3 = [("M", 3, 65536), ("M", 65538, 65000)]
    dynamic_block(w, toks3, True)
    out = s1 + replay(toks1, s1)
    out += replay(toks2, out)
    out += replay(toks3, out)
    cases["mixed_blocks"] = (w.finish(), out)

    # Multi-block dynamic encoding of a larger text corpus.
    data = text(31, 150000)
    w = BitWriter()
    chunk = 50000
    hist = b""
    for i in range(0, len(data), chunk):
        part = data[i:i + chunk]
        toks = lz77(part, history=hist[-WINDOW:])
        assert replay(toks, hist[-WINDOW:]) == part
        dynamic_block(w, toks, i + chunk >= len(data))
        hist += part
    cases["dynamic_corpus"] = (w.finish(), data)

    return cases


def build_zlib_cases():
    """Plain RFC 1951 streams from the zlib oracle."""
    cases = {}
    for name, data in [("u_small", unique_text(41, 2000)),
                       ("u_40k", unique_text(42, 40000)),
                       ("u_bin", lcg_bytes(43, 5000) + unique_text(44, 3000))]:
        assert windows_distinct(data), name
        for level in (1, 9):
            co = zlib.compressobj(level, zlib.DEFLATED, -15)
            cases["%s_l%d" % (name, level)] = (co.compress(data) + co.flush(), data)
        co = zlib.compressobj(9, zlib.DEFLATED, -15, 8, zlib.Z_FIXED)
        cases["%s_fixed" % name] = (co.compress(data) + co.flush(), data)
    # Stored-only stream (level 0).
    data = unique_text(45, 1000)
    co = zlib.compressobj(0, zlib.DEFLATED, -15)
    cases["u_stored_l0"] = (co.compress(data) + co.flush(), data)
    # A stream that DOES use length code 285 (=258 in RFC 1951); Deflate64
    # interprets it differently. Used by the "diverges" test.
    data = b"a" * 1000
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    cases["uses_code285"] = (co.compress(data) + co.flush(), data)
    for name, (raw, data) in cases.items():
        assert zlib.decompress(raw, -15) == data, name
    return cases


def zip_method9(name, raw, data):
    crc = zlib.crc32(data) & 0xFFFFFFFF
    fn = name.encode()
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 21, 0, 9, 0, 0, crc,
                        len(raw), len(data), len(fn), 0) + fn
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 21, 21, 0, 9, 0,
                          0, crc, len(raw), len(data), len(fn), 0, 0, 0, 0, 0,
                          0) + fn
    cd_off = len(local) + len(raw)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central),
                       cd_off, 0)
    return local + raw + central + eocd


def verify_unzip(cases):
    unzip = shutil.which("unzip")
    if unzip is None:
        sys.exit("unzip not found")
    with tempfile.TemporaryDirectory() as tmp:
        for name, (raw, data) in cases.items():
            path = os.path.join(tmp, name + ".zip")
            with open(path, "wb") as f:
                f.write(zip_method9(name, raw, data))
            got = subprocess.run([unzip, "-p", path], capture_output=True)
            if got.returncode != 0 or got.stdout != data:
                sys.exit("unzip disagrees on %s (rc=%d, %d vs %d bytes): %s" % (
                    name, got.returncode, len(got.stdout), len(data),
                    got.stderr.decode(errors="replace")))
            print("unzip ok: %s (%d -> %d)" % (name, len(raw), len(data)))


def main():
    cases = build_cases()
    zcases = build_zlib_cases()
    if "--verify-unzip" in sys.argv:
        verify_unzip(cases)
    os.makedirs(OUT, exist_ok=True)
    for f in os.listdir(OUT):
        os.remove(os.path.join(OUT, f))
    lines = []
    total = 0
    for name, (raw, data) in sorted(cases.items()):
        fn = name + ".d64"
        with open(os.path.join(OUT, fn), "wb") as f:
            f.write(raw)
        total += len(raw)
        lines.append("%s %d %08x" % (fn, len(data), zlib.crc32(data) & 0xFFFFFFFF))
    for name, (raw, data) in sorted(zcases.items()):
        fn = name + ".deflate"
        with open(os.path.join(OUT, fn), "wb") as f:
            f.write(raw)
        total += len(raw)
        lines.append("%s %d %08x" % (fn, len(data), zlib.crc32(data) & 0xFFFFFFFF))
    with open(os.path.join(OUT, "manifest.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote %d files, %d bytes" % (len(lines), total))
    assert total <= 200 * 1024


if __name__ == "__main__":
    main()
