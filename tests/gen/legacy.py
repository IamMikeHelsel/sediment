#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fixture generator for the legacy read-only formats (tail-legacy).

Python stdlib only (zlib for CRC-32). Every container and codec here is a
hand-written *encoder* built from public format descriptions:

* Unix compress (.Z): LZW, LSB-first codes, 9..maxbits, block mode with
  CLEAR, and compress's "groups of 8 codes" padding on width change/CLEAR.
* LHA/LZH: header levels 0, 1 and 2 (LHa header documentation), methods
  -lh0-, -lhd-, -lh5-, -lh6-, -lh7- (static Huffman blocks as described in
  the ar002/LHa format notes: T/C/P length tables, MSB-first bits).
* ARJ: archive/local headers per the ARJ technical notes, methods 0 (store),
  1 (the LHA-style static Huffman coder, 26624-byte window) and 4 (the
  "fastest" unary-prefixed length/pointer coder).
* ZIP methods 1 (Shrink: LZW 9..13 bits with 256,1 / 256,2 controls) and
  6 (Implode: Shannon-Fano trees) per PKWARE APPNOTE 6.3.x sections 5.1/5.3.

The encoders were cross-checked against an independent decoder (the pinned
7-Zip 26.04 `7zz` binary, run as a black box: `7zz t`), and the .Z files
against the system `uncompress`/`gzip -dc`. Run:

    python3 tests/gen/legacy.py tests/fixtures/legacy
"""
import heapq
import os
import struct
import sys
import zlib

# ---------------------------------------------------------------------------
# Deterministic sample data
# ---------------------------------------------------------------------------

WORDS = (b"the quick brown fox jumps over lazy dog archive legacy format "
         b"huffman window lempel ziv welch shrink implode arj lha compress "
         b"sediment block table code length distance literal").split()


class Lcg:
    def __init__(self, seed):
        self.s = seed & 0xFFFFFFFF

    def next(self):
        self.s = (self.s * 1103515245 + 12345) & 0x7FFFFFFF
        return self.s >> 8


def text_data(n, seed=1):
    r = Lcg(seed)
    out = bytearray()
    while len(out) < n:
        out += WORDS[r.next() % len(WORDS)]
        out += b"\n" if r.next() % 11 == 0 else b" "
    return bytes(out[:n])


def noise_data(n, seed=7):
    r = Lcg(seed)
    return bytes(r.next() & 0xFF for _ in range(n))


def mixed_data(n, seed=3):
    """Text with long-distance repeats and binary runs."""
    r = Lcg(seed)
    base = text_data(n // 3 + 1, seed)
    out = bytearray()
    while len(out) < n:
        k = r.next() % 4
        if k == 0 and len(out) > 64:
            ln = 3 + r.next() % 300
            d = 1 + r.next() % len(out)
            for _ in range(ln):
                out.append(out[-d])
        elif k == 1:
            out += bytes([r.next() & 0xFF]) * (1 + r.next() % 40)
        else:
            s = r.next() % len(base)
            out += base[s:s + 1 + r.next() % 200]
    return bytes(out[:n])


# ---------------------------------------------------------------------------
# Bit writers
# ---------------------------------------------------------------------------


class MsbWriter:
    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, nbits, value):
        for i in range(nbits - 1, -1, -1):
            self.acc = (self.acc << 1) | ((value >> i) & 1)
            self.n += 1
            if self.n == 8:
                self.out.append(self.acc)
                self.acc = 0
                self.n = 0

    def finish(self):
        if self.n:
            self.out.append(self.acc << (8 - self.n))
            self.acc = 0
            self.n = 0
        return bytes(self.out)


class LsbWriter:
    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, nbits, value):
        self.acc |= (value & ((1 << nbits) - 1)) << self.n
        self.n += nbits
        while self.n >= 8:
            self.out.append(self.acc & 0xFF)
            self.acc >>= 8
            self.n -= 8

    def bitpos(self):
        return len(self.out) * 8 + self.n

    def finish(self):
        if self.n:
            self.out.append(self.acc & 0xFF)
            self.acc = 0
            self.n = 0
        return bytes(self.out)


# ---------------------------------------------------------------------------
# LZ77 matcher (greedy, hash chains)
# ---------------------------------------------------------------------------


def lz77(data, window, min_match, max_match, depth=48):
    """Tokens: int literal, or (length, distance) with 1 <= distance <= window."""
    head = {}
    prev = [0] * len(data)
    toks = []
    i = 0
    n = len(data)

    def insert(p):
        if p + 3 <= n:
            h = data[p:p + 3]
            prev[p] = head.get(h, -1)
            head[h] = p

    while i < n:
        best_len, best_d = 0, 0
        if i + 3 <= n:
            cand = head.get(data[i:i + 3], -1)
            tries = depth
            while cand >= 0 and i - cand <= window and tries:
                tries -= 1
                ln = 0
                lim = min(max_match, n - i)
                while ln < lim and data[cand + ln] == data[i + ln]:
                    ln += 1
                if ln > best_len:
                    best_len, best_d = ln, i - cand
                    if ln == lim:
                        break
                cand = prev[cand]
        if best_len >= min_match:
            toks.append((best_len, best_d))
            for p in range(i, i + best_len):
                insert(p)
            i += best_len
        else:
            toks.append(data[i])
            insert(i)
            i += 1
    return toks


# ---------------------------------------------------------------------------
# Huffman code lengths with a length limit (package-merge)
# ---------------------------------------------------------------------------


def limited_lengths(freqs, limit):
    syms = [i for i, f in enumerate(freqs) if f > 0]
    lens = [0] * len(freqs)
    if not syms:
        return lens
    if len(syms) == 1:
        lens[syms[0]] = 1
        return lens
    leaves = sorted((freqs[s], [s]) for s in syms)
    packages = list(leaves)
    for _ in range(limit - 1):
        merged = []
        for j in range(0, len(packages) - 1, 2):
            merged.append((packages[j][0] + packages[j + 1][0], packages[j][1] + packages[j + 1][1]))
        packages = sorted(leaves + merged, key=lambda x: x[0])
    for _, ss in packages[:2 * len(syms) - 2]:
        for s in ss:
            lens[s] += 1
    return lens


def canonical_codes(lens):
    """Canonical MSB-first codes (shorter first, then by symbol)."""
    maxl = max(lens) if lens else 0
    bl_count = [0] * (maxl + 2)
    for l in lens:
        if l:
            bl_count[l] += 1
    code = 0
    next_code = [0] * (maxl + 2)
    for b in range(1, maxl + 1):
        code = (code + bl_count[b - 1]) << 1
        next_code[b] = code
    codes = [0] * len(lens)
    for s, l in enumerate(lens):
        if l:
            codes[s] = next_code[l]
            next_code[l] += 1
    return codes


# ---------------------------------------------------------------------------
# LHA-style static Huffman coder (-lh4..7-, ARJ methods 1..3)
# ---------------------------------------------------------------------------

NC = 510
NT = 19
TBIT = 5
CBIT = 9


def pcode(p):
    return 0 if p == 0 else p.bit_length()


def write_pt_len(w, lens, nbit, i_special):
    n = len(lens)
    while n > 0 and lens[n - 1] == 0:
        n -= 1
    w.put(nbit, n)
    i = 0
    while i < n:
        k = lens[i]
        i += 1
        if k <= 6:
            w.put(3, k)
        else:
            w.put(k - 3, (1 << (k - 3)) - 2)
        if i == i_special:
            while i < 6 and lens[i] == 0:
                i += 1
            w.put(2, (i - 3) & 3)


def c_len_runs(c_len):
    n = len(c_len)
    while n > 0 and c_len[n - 1] == 0:
        n -= 1
    items = []  # (t_symbol, extra_bits, extra_value)
    i = 0
    while i < n:
        k = c_len[i]
        i += 1
        if k == 0:
            cnt = 1
            while i < n and c_len[i] == 0:
                i += 1
                cnt += 1
            if cnt <= 2:
                items += [(0, 0, 0)] * cnt
            elif cnt <= 18:
                items.append((1, 4, cnt - 3))
            elif cnt == 19:
                items.append((0, 0, 0))
                items.append((1, 4, 15))
            else:
                items.append((2, CBIT, cnt - 20))
        else:
            items.append((k + 2, 0, 0))
    return n, items


def lh_encode(data, dicbit, np_, pbit, window, block_tokens=0x4000, single_block=False):
    toks = lz77(data, window, 3, 256)
    w = MsbWriter()
    blocks = [toks] if single_block else [toks[i:i + block_tokens] for i in range(0, len(toks), block_tokens)]
    for blk in blocks:
        c_freq = [0] * NC
        p_freq = [0] * np_
        for t in blk:
            if isinstance(t, int):
                c_freq[t] += 1
            else:
                ln, d = t
                c_freq[256 + ln - 3] += 1
                p_freq[pcode(d - 1)] += 1
        w.put(16, len(blk))
        c_used = [i for i in range(NC) if c_freq[i]]
        if len(c_used) == 1:
            c_len = [0] * NC
            w.put(TBIT, 0)
            w.put(TBIT, 0)
            w.put(CBIT, 0)
            w.put(CBIT, c_used[0])
            c_codes = [0] * NC
        else:
            c_len = limited_lengths(c_freq, 16)
            c_codes = canonical_codes(c_len)
            n, items = c_len_runs(c_len)
            t_freq = [0] * NT
            for s, _, _ in items:
                t_freq[s] += 1
            t_used = [i for i in range(NT) if t_freq[i]]
            if len(t_used) == 1:
                w.put(TBIT, 0)
                w.put(TBIT, t_used[0])
                t_len = [0] * NT
                t_codes = [0] * NT
            else:
                t_len = limited_lengths(t_freq, 16)
                t_codes = canonical_codes(t_len)
                write_pt_len(w, t_len, TBIT, 3)
            w.put(CBIT, n)
            for s, eb, ev in items:
                w.put(t_len[s], t_codes[s])
                if eb:
                    w.put(eb, ev)
        p_used = [i for i in range(np_) if p_freq[i]]
        if len(p_used) <= 1:
            w.put(pbit, 0)
            w.put(pbit, p_used[0] if p_used else 0)
            p_len = [0] * np_
            p_codes = [0] * np_
        else:
            p_len = limited_lengths(p_freq, 16)
            p_codes = canonical_codes(p_len)
            write_pt_len(w, p_len, pbit, -1)
        for t in blk:
            if isinstance(t, int):
                w.put(c_len[t], c_codes[t])
            else:
                ln, d = t
                c = 256 + ln - 3
                w.put(c_len[c], c_codes[c])
                p = d - 1
                pc = pcode(p)
                w.put(p_len[pc], p_codes[pc])
                if pc > 1:
                    w.put(pc - 1, p - (1 << (pc - 1)))
    return w.finish()


LH_PARAMS = {  # method -> (dicbit, np, pbit)
    b"-lh4-": (12, 13, 4),
    b"-lh5-": (13, 14, 4),
    b"-lh6-": (15, 16, 5),
    b"-lh7-": (16, 17, 5),
}


def lh_compress(method, data, **kw):
    dicbit, np_, pbit = LH_PARAMS[method]
    return lh_encode(data, dicbit, np_, pbit, 1 << dicbit, **kw)


# ---------------------------------------------------------------------------
# LHA archive writer
# ---------------------------------------------------------------------------


def crc16(data, crc=0):
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def dos_time(y, mo, d, h, mi, s):
    return ((y - 1980) << 25) | (mo << 21) | (d << 16) | (h << 11) | (mi << 5) | (s // 2)


DOS_T = dos_time(2020, 5, 17, 13, 45, 30)
UNIX_T = 1589723130


def lzh_member(level, name, data, method=b"-lh5-", packed=None, unix_mode=None, dirname=None):
    """One LHA member: header + payload. `packed` overrides compression."""
    if packed is None:
        if method == b"-lh0-" or method == b"-lhd-":
            packed = data
        else:
            packed = lh_compress(method, data)
    crc = crc16(data)
    if level == 0:
        body = method + struct.pack("<IIIBB", len(packed), len(data), DOS_T, 0x20, 0)
        body += bytes([len(name)]) + name + struct.pack("<H", crc)
        hdr = bytes([len(body), sum(body) & 0xFF]) + body
        return hdr + packed
    exts = []
    if dirname is not None:
        exts.append(b"\x02" + dirname)
    if unix_mode is not None:
        exts.append(b"\x50" + struct.pack("<H", unix_mode))
    if level == 1:
        exts.append(b"\x54" + struct.pack("<I", UNIX_T))
        ext_blob = b""
        sizes = [len(e) + 2 for e in exts]
        for i, e in enumerate(exts):
            nxt = sizes[i + 1] if i + 1 < len(exts) else 0
            ext_blob += e + struct.pack("<H", nxt)
        first = sizes[0] if exts else 0
        body = method + struct.pack("<IIIBB", len(packed) + len(ext_blob), len(data), DOS_T, 0x20, 1)
        body += bytes([len(name)]) + name + struct.pack("<H", crc) + b"U" + struct.pack("<H", first)
        hdr = bytes([len(body) - 2, 0]) + body  # size excludes the next-size field? see below
        # Level-1 header size counts the bytes after the first two, up to and
        # including the first "next extended header size" field.
        hdr = bytes([len(body), sum(body) & 0xFF]) + body
        return hdr + ext_blob + packed
    if level == 2:
        exts = [b"\x00\x00\x00", b"\x01" + name] + exts  # header CRC first, patched below
        sizes = [len(e) + 2 for e in exts]
        ext_blob = bytearray()
        for i, e in enumerate(exts):
            nxt = sizes[i + 1] if i + 1 < len(exts) else 0
            ext_blob += e + struct.pack("<H", nxt)
        fixed = bytearray(method + struct.pack("<IIIBB", len(packed), len(data), UNIX_T, 0x20, 2))
        fixed += struct.pack("<H", crc) + b"U" + struct.pack("<H", sizes[0])
        total = 2 + len(fixed) + len(ext_blob)
        hdr = bytearray(struct.pack("<H", total) + fixed + ext_blob)
        hcrc = crc16(bytes(hdr))
        off = 2 + len(fixed) + 1
        hdr[off:off + 2] = struct.pack("<H", hcrc)
        return bytes(hdr) + packed
    raise ValueError(level)


def lzh_archive(members):
    return b"".join(members) + b"\x00"


# ---------------------------------------------------------------------------
# ARJ
# ---------------------------------------------------------------------------

ARJ_WINDOW = 26624


def arj_m4_encode(data):
    toks = lz77(data, 15872, 3, 256)
    w = MsbWriter()

    def put_unary(v, strt, stop):
        # value v encoded as: (ones, zero-terminated unless at stop) + width bits
        plus = 0
        pwr = 1 << strt
        width = strt
        while width < stop and v >= plus + pwr:
            plus += pwr
            pwr <<= 1
            width += 1
        ones = width - strt
        for _ in range(ones):
            w.put(1, 1)
        if width < stop:
            w.put(1, 0)
        if width:
            w.put(width, v - plus)

    for t in toks:
        if isinstance(t, int):
            put_unary(0, 0, 7)
            w.put(8, t)
        else:
            ln, d = t
            put_unary(ln - 2, 0, 7)
            put_unary(d - 1, 9, 13)
    return w.finish()


def arj_m1_encode(data):
    return lh_encode(data, 16, 17, 5, ARJ_WINDOW, block_tokens=0x3000)


def arj_header(fields):
    basic = fields
    out = b"\x60\xea" + struct.pack("<H", len(basic)) + basic
    out += struct.pack("<I", zlib.crc32(basic) & 0xFFFFFFFF)
    out += b"\x00\x00"  # no extended headers
    return out


def arj_main(name=b"test.arj"):
    fixed = struct.pack("<BBBBBBBBIIIIHHBB", 30, 11, 1, 0, 0x10, 0, 2, 0, DOS_T, DOS_T, 0, 0, 0, 0, 0, 0)
    return arj_header(fixed + name + b"\x00" + b"\x00")


def arj_local(name, data, method, ftype=0, mode=0x20, host=0, packed=None, flags=0x10):
    if packed is None:
        if method == 0:
            packed = data
        elif method in (1, 2, 3):
            packed = arj_m1_encode(data)
        elif method == 4:
            packed = arj_m4_encode(data)
        else:
            raise ValueError(method)
    crc = zlib.crc32(data) & 0xFFFFFFFF
    fixed = struct.pack("<BBBBBBBBIIIIHHBB", 30, 11, 1, host, flags, method, ftype, 0, DOS_T,
                        len(packed), len(data), crc, 0, mode, 0, 0)
    return arj_header(fixed + name + b"\x00" + b"\x00") + packed


def arj_archive(members, prefix=b""):
    return prefix + arj_main() + b"".join(members) + b"\x60\xea\x00\x00"


# ---------------------------------------------------------------------------
# Unix compress (.Z)
# ---------------------------------------------------------------------------


def lzw_z_encode(data, maxbits=16, block=True, clear_at=None):
    """compress(1)-compatible output. `clear_at`: emit CLEAR every that many codes."""
    w = LsbWriter()
    w.out += bytes([0x1F, 0x9D, maxbits | (0x80 if block else 0)])
    first_free = 257 if block else 256
    max_entries = 1 << maxbits
    st = {"n": 9, "maxcode": 511, "count": 0}

    def put(code):
        w.put(st["n"], code)
        st["count"] += 1

    def pad_group():
        rem = (8 - st["count"] % 8) % 8
        for _ in range(rem):
            w.put(st["n"], 0)
        st["count"] = 0

    if not data:
        return w.finish()
    table = {}
    free_ent = first_free
    written = 0
    ent = data[0]
    for c in data[1:]:
        key = (ent, c)
        if key in table:
            ent = table[key]
            continue
        put(ent)
        written += 1
        # compress's output(): widen after writing a code when free_ent > maxcode
        if free_ent > st["maxcode"]:
            pad_group()
            st["n"] += 1
            st["maxcode"] = max_entries if st["n"] == maxbits else (1 << st["n"]) - 1
        ent = c
        if clear_at is not None and block and written % clear_at == 0:
            put(256)
            pad_group()
            st["n"], st["maxcode"] = 9, 511
            table = {}
            free_ent = first_free
            continue
        if free_ent < max_entries:
            table[key] = free_ent
            free_ent += 1
    put(ent)
    return w.finish()


# ---------------------------------------------------------------------------
# ZIP Shrink (method 1)
# ---------------------------------------------------------------------------


def shrink_encode(data, max_code=8191, clear_on_full=True, clear_after_any=False):
    """Shrink per APPNOTE 5.1. Width grows only on 256,1; 256,2 partially clears.

    The decoder adds entry (prev, first(cur)) at the lowest free code when it
    reads each code after the first, even when `prev` itself was just freed
    by a partial clear; the encoder mirrors that exactly. By default a
    partial clear is emitted only right after a literal code (codes < 256 are
    never cleared); `clear_after_any` also clears after string codes, which
    exercises the freed-prefix case (verified against 7zz).
    """
    w = LsbWriter()
    width = 9
    in_use = {}  # code -> (prefix, byte)
    lookup = {}  # (prefix, byte) -> code
    free = 257

    def lowest_free(start=257):
        c = start
        while c <= max_code and c in in_use:
            c += 1
        return c if c <= max_code else None

    def emit(code):
        nonlocal width
        while code >= (1 << width):
            w.put(width, 256)
            w.put(width, 1)
            width += 1
        w.put(width, code)

    def partial_clear():
        prefixes = {p for (p, _) in in_use.values()}
        for c in [c for c in in_use if c not in prefixes]:
            del lookup[in_use[c]]
            del in_use[c]

    if not data:
        return w.finish()
    ent = data[0]
    i = 1
    while i < len(data):
        c = data[i]
        i += 1
        if (ent, c) in lookup:
            ent = lookup[(ent, c)]
            continue
        emit(ent)
        nf = lowest_free()
        if nf is None and clear_on_full and (ent < 256 or clear_after_any):
            w.put(width, 256)
            w.put(width, 2)
            partial_clear()
            nf = lowest_free()
        if nf is not None:
            in_use[nf] = (ent, c)
            lookup[(ent, c)] = nf
        ent = c
    emit(ent)
    return w.finish()


# ---------------------------------------------------------------------------
# ZIP Implode (method 6)
# ---------------------------------------------------------------------------


def sf_codes(lens):
    """APPNOTE 5.3.x Shannon-Fano code assignment: returns MSB-first codes."""
    n = len(lens)
    order = sorted(range(n), key=lambda s: (lens[s], s))
    codes = [0] * n
    code = 0
    inc = 0
    last = 0
    for idx in range(n - 1, -1, -1):
        s = order[idx]
        code = (code + inc) & 0xFFFF
        if lens[s] != last:
            last = lens[s]
            inc = 1 << (16 - last)
        codes[s] = code >> (16 - lens[s])
    return codes


def sf_tree_bytes(lens):
    runs = []
    i = 0
    while i < len(lens):
        j = i
        while j < len(lens) and lens[j] == lens[i] and j - i < 16:
            j += 1
        runs.append(((j - i - 1) << 4) | (lens[i] - 1))
        i = j
    return bytes([len(runs) - 1]) + bytes(runs)


def implode_encode(data, big_dict, lit_tree):
    dbits = 7 if big_dict else 6
    window = 8192 if big_dict else 4096
    minm = 3 if lit_tree else 2
    maxm = minm + 63 + 255
    toks = lz77(data, window, max(minm, 3), maxm)
    lit_f = [1] * 256
    len_f = [1] * 64
    dist_f = [1] * 64
    for t in toks:
        if isinstance(t, int):
            lit_f[t] += 1
        else:
            ln, d = t
            len_f[min(ln - minm, 63)] += 1
            dist_f[(d - 1) >> dbits] += 1
    trees = b""
    lit_len = limited_lengths(lit_f, 16) if lit_tree else None
    len_len = limited_lengths(len_f, 16)
    dist_len = limited_lengths(dist_f, 16)
    if lit_tree:
        trees += sf_tree_bytes(lit_len)
    trees += sf_tree_bytes(len_len) + sf_tree_bytes(dist_len)
    lit_c = sf_codes(lit_len) if lit_tree else None
    len_c = sf_codes(len_len)
    dist_c = sf_codes(dist_len)
    w = LsbWriter()

    def put_code(code, ln):
        # Codes go out MSB first (first stream bit = code MSB), not inverted.
        for k in range(ln - 1, -1, -1):
            w.put(1, (code >> k) & 1)

    for t in toks:
        if isinstance(t, int):
            w.put(1, 1)
            if lit_tree:
                put_code(lit_c[t], lit_len[t])
            else:
                w.put(8, t)
        else:
            ln, d = t
            w.put(1, 0)
            dd = d - 1
            w.put(dbits, dd & ((1 << dbits) - 1))
            hi = dd >> dbits
            put_code(dist_c[hi], dist_len[hi])
            L = ln - minm
            if L >= 63:
                put_code(len_c[63], len_len[63])
                w.put(8, L - 63)
            else:
                put_code(len_c[L], len_len[L])
    return trees + w.finish()


# ---------------------------------------------------------------------------
# Minimal ZIP writer for arbitrary methods
# ---------------------------------------------------------------------------


def zip_archive(entries):
    """entries: (name, data, method, flags, packed)."""
    out = bytearray()
    central = bytearray()
    dt, dd = 0x6000, 0x50B1
    for name, data, method, flags, packed in entries:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        off = len(out)
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 10, flags, method, dt, dd, crc, len(packed), len(data),
                           len(name), 0) + name + packed
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 0x031E, 10, flags, method, dt, dd, crc,
                               len(packed), len(data), len(name), 0, 0, 0, 0, 0o100644 << 16, off) + name
    cd_off = len(out)
    out += central
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(central), cd_off, 0)
    return bytes(out)


# ---------------------------------------------------------------------------
# Fixture set
# ---------------------------------------------------------------------------


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    files = {}
    t1 = text_data(9000, 1)
    t2 = text_data(30000, 2)
    t5 = text_data(80000, 5)
    mx = mixed_data(70000, 3)
    nz = noise_data(3000, 7)
    nz2 = noise_data(16000, 11)
    small = b"hello, legacy world\n"
    files["src_small.bin"] = small
    # Expected member contents: name -> (length, crc32). Written to MANIFEST.
    expect = {
        "text1": t1, "text2": t2, "text5": t5, "mixed": mx, "mixed40k": mx[:40000],
        "mixed60k": mx[:60000], "mixed20k": mx[:20000], "mixed30k": mx[:30000],
        "noise": nz, "noise16k": nz2, "small": small, "zeros5000": bytes(5000), "A": b"A", "empty": b"",
    }

    # .Z (text9/text16 are byte-identical to the system `compress -b N`)
    files["text16.Z"] = lzw_z_encode(t2, 16)
    files["text9.Z"] = lzw_z_encode(t1, 9)
    files["text12_clear.Z"] = lzw_z_encode(t2, 12, clear_at=700)
    files["noblock12.Z"] = lzw_z_encode(t1, 12, block=False)

    # LZH
    files["lh5_l0.lzh"] = lzh_archive([lzh_member(0, b"text1.txt", t1, b"-lh5-")])
    files["lh5_l1.lzh"] = lzh_archive([
        lzh_member(1, b"text2.txt", t2, b"-lh5-", unix_mode=0o100644, dirname=b"docs\xff"),
        lzh_member(1, b"small.txt", small, b"-lh0-"),
    ])
    files["lh6_l2.lzh"] = lzh_archive([
        lzh_member(2, b"", b"", b"-lhd-", dirname=b"dir\xff", unix_mode=0o040755),
        lzh_member(2, b"mixed.bin", mx, b"-lh6-", dirname=b"dir\xff", unix_mode=0o100600),
        lzh_member(2, b"noise.bin", nz, b"-lh5-"),
    ])
    files["lh7_l2.lzh"] = lzh_archive([lzh_member(2, b"mixed.bin", mx, b"-lh7-")])
    files["lh4_l1.lzh"] = lzh_archive([lzh_member(1, b"text1.txt", t1, b"-lh4-")])
    files["lh5_rle.lzh"] = lzh_archive([
        lzh_member(0, b"zeros.bin", bytes(5000), b"-lh5-"),
        lzh_member(0, b"one.bin", b"A", b"-lh5-"),
        lzh_member(0, b"empty.bin", b"", b"-lh5-", packed=b""),
    ])

    # ARJ
    files["m1.arj"] = arj_archive([
        arj_local(b"text2.txt", t2, 1),
        arj_local(b"sub/mixed.bin", mx[:40000], 2),
    ])
    files["m4.arj"] = arj_archive([
        arj_local(b"text1.txt", t1, 4),
        arj_local(b"noise.bin", nz, 4),
    ])
    files["m0_dir.arj"] = arj_archive([
        arj_local(b"folder", b"", 0, ftype=3, mode=0x10),
        arj_local(b"folder\\small.txt", small, 0, flags=0),
        arj_local(b"m3.bin", t1, 3),
    ])

    # ZIP legacy methods
    files["shrink.zip"] = zip_archive([
        (b"text2.txt", t2, 1, 0, shrink_encode(t2)),
        (b"mixed.bin", mx[:60000], 1, 0, shrink_encode(mx[:60000])),
        (b"small.txt", small, 1, 0, shrink_encode(small)),
        (b"noise.bin", nz2, 1, 0, shrink_encode(nz2)),
        (b"text5.txt", t5, 1, 0, shrink_encode(t5, clear_after_any=True)),
    ])
    files["implode.zip"] = zip_archive([
        (b"i4k2.txt", t1, 6, 0, implode_encode(t1, False, False)),
        (b"i8k2.bin", mx[:20000], 6, 2, implode_encode(mx[:20000], True, False)),
        (b"i4k3.txt", t2, 6, 4, implode_encode(t2, False, True)),
        (b"i8k3.bin", mx[:30000], 6, 6, implode_encode(mx[:30000], True, True)),
    ])

    manifest = "".join(f"{k} {len(v)} {zlib.crc32(v) & 0xFFFFFFFF:08x}\n" for k, v in sorted(expect.items()))
    files["MANIFEST"] = manifest.encode()
    total = 0
    for name, blob in sorted(files.items()):
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(blob)
        total += len(blob)
    print(f"wrote {len(files)} files, {total} bytes")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/legacy")
