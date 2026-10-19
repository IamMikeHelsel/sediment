#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generate Microsoft-format fixtures for tests/ms_*.rs (CAB, LZX, CFB, CHM).

Python stdlib only. Run from the repo root:  python3 tests/gen/ms.py
Output: tests/fixtures/{cab,cfb,chm}/

Everything here is written from the public format descriptions:
  - [MS-CAB] Cabinet File Format (CFHEADER/CFFOLDER/CFFILE/CFDATA, the
    CFDATA checksum, MSZIP = "CK" + one RFC 1951 deflate stream per block
    with the previous block's output as the preset history).
  - The LZX format as described in [MS-PATCH] (LZX DELTA) section 2 and the
    Microsoft Cabinet SDK LZX description: 16-bit LE words read MSB first,
    E8 header, 3-bit block type + 24-bit block size, pretree-coded main and
    length trees, aligned-offset tree, repeated offsets R0..R2, 32 KiB
    frames realigned to 16 bits, E8 call translation.
  - [MS-CFB] Compound File Binary format (header, DIFAT, FAT, mini FAT,
    directory entries, mini stream).
  - The CHM / ITSS layout as publicly documented (ITSF header, ITSP
    directory, PMGL/PMGI chunks with ENCINT fields, the MSCompressed section:
    LZXC ControlData, ResetTable, Content).

The LZX encoder below is a small greedy encoder that emits verbatim,
aligned-offset and uncompressed blocks; it exists only to produce fixtures.
Fixtures were cross-checked with an external 7-Zip 26.04 `7zz` binary on
sparky (see tests/gen/ms_oracle.sh); no 7-Zip code is used.

Each archive FOO gets FOO.expect: one line per entry, tab separated:
  kind path size crc32hex
kind: f (file) or d (dir); crc32 of the extracted bytes ('-' for dirs).
"""
import heapq, os, struct, uuid, zlib

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")


def area(name):
    base = name.split(".")[1]
    return {"cab": "cab", "lzx": "cab", "out": "cab", "cfb": "cfb", "msi": "cfb", "chm": "chm"}[base]

FRAME = 32768


# --------------------------------------------------------------------------
# deterministic test data
class Rng:
    def __init__(self, seed):
        self.s = seed & 0xFFFFFFFF

    def next(self):
        self.s = (self.s * 1103515245 + 12345) & 0x7FFFFFFF
        return self.s >> 8


WORDS = ("alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi "
         "omicron pi rho sigma tau upsilon phi chi psi omega cabinet folder stream "
         "storage window frame block match literal offset").split()


def text(seed, n):
    r = Rng(seed)
    out = []
    size = 0
    while size < n:
        w = WORDS[r.next() % len(WORDS)]
        if r.next() % 11 == 0:
            w += "\n"
        else:
            w += " "
        out.append(w)
        size += len(w)
    return "".join(out).encode()[:n]


def binary(seed, n):
    r = Rng(seed)
    return bytes(r.next() & 0xFF for _ in range(n))


def x86ish(seed, n):
    """Bytes with plenty of E8 xx xx xx xx call-like sequences."""
    r = Rng(seed)
    b = bytearray()
    while len(b) < n:
        k = r.next() % 7
        if k < 3:
            target = (r.next() % 60000) - 3000
            b += b"\xe8" + struct.pack("<i", target)
        elif k == 3:
            b += b"\x55\x8b\xec\x83\xec\x10"
        else:
            b += bytes([r.next() & 0xFF])
    return bytes(b[:n])


def crc(b):
    return "%08x" % (zlib.crc32(b) & 0xFFFFFFFF)


def write(name, data):
    os.makedirs(os.path.join(OUT, area(name)), exist_ok=True)
    with open(os.path.join(OUT, area(name), name), "wb") as f:
        f.write(data)


def write_expect(name, rows):
    with open(os.path.join(OUT, area(name), name + ".expect"), "w") as f:
        for kind, path, data in rows:
            if kind == "d":
                f.write("d\t%s\t0\t-\n" % path)
            else:
                f.write("f\t%s\t%d\t%s\n" % (path, len(data), crc(data)))


# --------------------------------------------------------------------------
# Huffman helpers
def huff_lengths(freqs, maxlen):
    syms = [i for i, f in enumerate(freqs) if f > 0]
    L = [0] * len(freqs)
    if not syms:
        return L
    if len(syms) == 1:
        s = syms[0]
        L[s] = 1
        L[1 if s == 0 else 0] = 1
        return L
    f = list(freqs)
    while True:
        heap = [(f[s], i, [s]) for i, s in enumerate(syms)]
        heapq.heapify(heap)
        depth = {s: 0 for s in syms}
        cnt = len(heap)
        while len(heap) > 1:
            a = heapq.heappop(heap)
            b = heapq.heappop(heap)
            for s in a[2] + b[2]:
                depth[s] += 1
            heapq.heappush(heap, (a[0] + b[0], cnt, a[2] + b[2]))
            cnt += 1
        if max(depth.values()) <= maxlen:
            for s in syms:
                L[s] = depth[s]
            return L
        f = [(x >> 1) | 1 if x else 0 for x in f]


def canon(L):
    codes = [0] * len(L)
    code = 0
    for l in range(1, (max(L) if L else 0) + 1):
        for s in range(len(L)):
            if L[s] == l:
                codes[s] = code
                code += 1
        code <<= 1
    return codes


# --------------------------------------------------------------------------
# LZX encoder (fixtures only)
EXTRA = []
j = 0
for i in range(0, 52, 2):
    EXTRA += [j, j]
    if i != 0 and j < 17:
        j += 1
BASE = []
b = 0
for i in range(52):
    BASE.append(b)
    b += 1 << EXTRA[i]
SLOTS = {15: 30, 16: 32, 17: 34, 18: 36, 19: 38, 20: 42, 21: 50}


class BitW:
    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, v, nb):
        for k in range(nb - 1, -1, -1):
            self.acc = (self.acc << 1) | ((v >> k) & 1)
            self.n += 1
            if self.n == 16:
                self.out += struct.pack("<H", self.acc)
                self.acc = 0
                self.n = 0

    def align(self):
        if self.n:
            self.put(0, 16 - self.n)

    def pad_uncompressed(self):
        self.put(0, 16 - self.n)  # 1..16 bits

    def raw(self, b):
        assert self.n == 0
        self.out += b


def e8_encode(data, tsize, base_frame=0):
    d = bytearray(data)
    for fs in range(0, len(d), FRAME):
        frame_no = base_frame + fs // FRAME
        flen = min(FRAME, len(d) - fs)
        if frame_no >= 32768 or flen <= 10:
            continue
        i = 0
        while i < flen - 10:
            if d[fs + i] != 0xE8:
                i += 1
                continue
            cur = fs + i
            rel = struct.unpack_from("<i", d, fs + i + 1)[0]
            if -cur <= rel < tsize:
                a = rel + cur if rel + cur < tsize else rel - tsize
                struct.pack_into("<i", d, fs + i + 1, a)
            i += 5
    return bytes(d)


def find_tokens(data, start, end, window, R, allow_rep=True):
    """Greedy LZ77 parse of data[start:end]; matches never cross 32 KiB frames.
    Returns tokens ('L', byte) / ('M', length, offset) and updates nothing."""
    toks = []
    maxoff = window - 3
    table = {}
    pos = start
    R = list(R)
    while pos < end:
        frame_end = min(end, (pos // FRAME + 1) * FRAME)
        limit = min(257, frame_end - pos)
        best_len, best_off = 0, 0
        if limit >= 2:
            if allow_rep:
                for off in R:
                    if off <= pos:
                        l = 0
                        while l < limit and data[pos + l] == data[pos + l - off]:
                            l += 1
                        if l >= 2 and l > best_len:
                            best_len, best_off = l, off
            if limit >= 3:
                key = data[pos:pos + 3]
                for cand in reversed(table.get(key, [])[-16:]):
                    off = pos - cand
                    if off > maxoff:
                        continue
                    l = 0
                    while l < limit and data[pos + l] == data[cand + l]:
                        l += 1
                    if l > best_len + 1:
                        best_len, best_off = l, off
        if best_len >= 3 or (best_len == 2 and best_off in R):
            toks.append(("M", best_len, best_off))
            n = best_len
            # update R exactly like the bitstream will
            if best_off == R[0]:
                pass
            elif best_off == R[1]:
                R[0], R[1] = R[1], R[0]
            elif best_off == R[2]:
                R[0], R[2] = R[2], R[0]
            else:
                R = [best_off, R[0], R[1]]
        else:
            toks.append(("L", data[pos]))
            n = 1
        for k in range(n):
            p = pos + k
            if p + 3 <= len(data):
                table.setdefault(data[p:p + 3], []).append(p)
        pos += n
    return toks


class LzxEncoder:
    def __init__(self, window_bits, e8_size=None):
        self.wb = window_bits
        self.window = 1 << window_bits
        self.nslots = SLOTS[window_bits]
        self.main_prev = [0] * (256 + 8 * self.nslots)
        self.len_prev = [0] * 249
        self.R = [1, 1, 1]
        self.w = BitW()
        self.e8 = e8_size
        self.pos = 0
        self.frame_offsets = []  # compressed byte offset at each frame boundary

    def _after_output(self, n):
        old = self.pos
        self.pos += n
        if self.pos // FRAME != old // FRAME:
            assert self.pos % FRAME == 0, "match crossed a frame boundary"
            self.w.align()
            self.frame_offsets.append(len(self.w.out))

    @staticmethod
    def _length_tokens(new, prev):
        toks = []
        i, n = 0, len(new)
        while i < n:
            if new[i] == 0:
                run = 1
                while i + run < n and new[i + run] == 0:
                    run += 1
                if run >= 20:
                    r = min(run, 51)
                    toks.append((18, r - 20, 5, None))
                    i += r
                    continue
                if run >= 4:
                    r = min(run, 19)
                    toks.append((17, r - 4, 4, None))
                    i += r
                    continue
            run = 1
            while i + run < n and new[i + run] == new[i] and run < 5:
                run += 1
            if run >= 4 and new[i] != 0:
                toks.append((19, run - 4, 1, (prev[i] - new[i]) % 17))
                i += run
                continue
            toks.append(((prev[i] - new[i]) % 17, 0, 0, None))
            i += 1
        return toks

    def _write_lengths(self, new, prev):
        toks = self._length_tokens(new, prev)
        freqs = [0] * 20
        for s, _, _, z in toks:
            freqs[s] += 1
            if z is not None:
                freqs[z] += 1
        pl = huff_lengths(freqs, 15)
        pc = canon(pl)
        for l in pl:
            self.w.put(l, 4)
        for s, ev, en, z in toks:
            self.w.put(pc[s], pl[s])
            if en:
                self.w.put(ev, en)
            if z is not None:
                self.w.put(pc[z], pl[z])

    def _slot_for(self, off):
        f = off + 2
        s = 3
        while s + 1 < self.nslots and BASE[s + 1] <= f:
            s += 1
        assert BASE[s] <= f < BASE[s] + (1 << EXTRA[s])
        return s, f - BASE[s]

    def _symbolize(self, toks):
        out = []
        R = self.R
        for t in toks:
            if t[0] == "L":
                out.append((t[1], None, None))
                continue
            _, ln, off = t
            if off == R[0]:
                slot, foot = 0, None
            elif off == R[1]:
                slot, foot = 1, None
                R[0], R[1] = R[1], R[0]
            elif off == R[2]:
                slot, foot = 2, None
                R[0], R[2] = R[2], R[0]
            else:
                slot, foot = self._slot_for(off)
                R[2], R[1], R[0] = R[1], R[0], off
            lh = min(ln - 2, 7)
            out.append((256 + slot * 8 + lh, ln, (slot, foot)))
        return out

    def header(self):
        if self.e8 is None:
            self.w.put(0, 1)
        else:
            self.w.put(1, 1)
            self.w.put(self.e8 >> 16, 16)
            self.w.put(self.e8 & 0xFFFF, 16)

    def block(self, data, start, end, btype):
        """Encode data[start:end] (absolute positions) as one block."""
        assert start == self.pos
        size = end - start
        self.w.put(btype, 3)
        self.w.put(size >> 8, 16)
        self.w.put(size & 0xFF, 8)
        if btype == 3:
            self.w.pad_uncompressed()
            self.w.raw(struct.pack("<III", *self.R))
            p = start
            while p < end:
                n = min(end - p, FRAME - p % FRAME)
                self.w.raw(data[p:p + n])
                self._after_output_raw(n)
                p += n
            if size & 1:
                self.w.raw(b"\0")
            return
        toks = find_tokens(data, start, end, self.window, self.R)
        syms = self._symbolize(toks)
        nmain = 256 + 8 * self.nslots
        mf = [0] * nmain
        lf = [0] * 249
        af = [0] * 8
        for s, ln, sf in syms:
            mf[s] += 1
            if ln is not None:
                if ln - 2 >= 7:
                    lf[ln - 2 - 7] += 1
                slot, foot = sf
                if slot >= 3 and EXTRA[slot] >= 3:
                    af[foot & 7] += 1
        ml = huff_lengths(mf, 16)
        ll = huff_lengths(lf, 16)
        if btype == 2:
            al = huff_lengths(af, 7)
            if not any(al):
                al = [3] * 8
            for l in al:
                self.w.put(l, 3)
            ac = canon(al)
        self._write_lengths(ml[:256], self.main_prev[:256])
        self._write_lengths(ml[256:], self.main_prev[256:])
        self._write_lengths(ll, self.len_prev)
        self.main_prev, self.len_prev = ml, ll
        mc, lc = canon(ml), canon(ll)
        for s, ln, sf in syms:
            self.w.put(mc[s], ml[s])
            if ln is None:
                self._after_output(1)
                continue
            if ln - 2 >= 7:
                self.w.put(lc[ln - 9], ll[ln - 9])
            slot, foot = sf
            if slot >= 3:
                e = EXTRA[slot]
                if btype == 2 and e >= 3:
                    if e > 3:
                        self.w.put(foot >> 3, e - 3)
                    self.w.put(ac[foot & 7], al[foot & 7])
                elif e:
                    self.w.put(foot, e)
            self._after_output(ln)

    def _after_output_raw(self, n):
        old = self.pos
        self.pos += n
        if self.pos // FRAME != old // FRAME:
            self.frame_offsets.append(len(self.w.out))

    def finish(self):
        self.w.align()
        return bytes(self.w.out)


def lzx_compress(data, window_bits, plan, e8_size=None):
    """plan: list of (btype, size); sizes must sum to len(data).
    Returns (compressed, per-frame compressed offsets)."""
    src = e8_encode(data, e8_size) if e8_size is not None else data
    enc = LzxEncoder(window_bits, e8_size)
    enc.header()
    p = 0
    for bt, sz in plan:
        enc.block(src, p, p + sz, bt)
        p += sz
    assert p == len(data)
    return enc.finish(), [0] + enc.frame_offsets


# --------------------------------------------------------------------------
# CAB writer
def cab_checksum(b, seed=0):
    cs = seed
    n = len(b) // 4
    for i in range(n):
        cs ^= struct.unpack_from("<I", b, 4 * i)[0]
    ul = 0
    rest = b[4 * n:]
    if len(rest) == 3:
        ul = (rest[0] << 16) | (rest[1] << 8) | rest[2]
    elif len(rest) == 2:
        ul = (rest[0] << 8) | rest[1]
    elif len(rest) == 1:
        ul = rest[0]
    return cs ^ ul


def dos(y, mo, d, h, mi, s):
    return ((y - 1980) << 9) | (mo << 5) | d, (h << 11) | (mi << 5) | (s // 2)


def build_cab(folders, files, reserve=None, prev=None, nxt=None, checksum=True,
              set_id=0x5ED1, icab=0):
    """folders: [(typeCompress, [(cdata, uncomp_len), ...])]
    files: [(name_bytes, size, iFolder, uoffFolderStart, (date, time), attribs)]"""
    flags = 0
    if prev:
        flags |= 1
    if nxt:
        flags |= 2
    if reserve:
        flags |= 4
    cbh, cbf, cbd = reserve if reserve else (0, 0, 0)
    hdr_len = 36 + (4 + cbh if reserve else 0)
    for pair in (prev, nxt):
        if pair:
            hdr_len += len(pair[0]) + 1 + len(pair[1]) + 1
    folder_len = len(folders) * (8 + cbf)
    files_blob = b""
    for name, size, ifo, off, (dd, tt), at in files:
        files_blob += struct.pack("<IIHHHH", size, off, ifo, dd, tt, at) + name + b"\0"
    coff_files = hdr_len + folder_len
    data_start = coff_files + len(files_blob)
    folder_blob = b""
    data_blob = b""
    for ftype, blocks in folders:
        folder_blob += struct.pack("<IHH", data_start + len(data_blob), len(blocks), ftype)
        folder_blob += bytes(range(1, cbf + 1))
        for cdata, ulen in blocks:
            # checksum: ab[] first, then cbData, cbUncomp and abReserve
            sizes = struct.pack("<HH", len(cdata), ulen) + bytes([0xAA] * cbd)
            cs = cab_checksum(sizes, cab_checksum(cdata)) if checksum else 0
            data_blob += struct.pack("<I", cs) + sizes + cdata
    total = data_start + len(data_blob)
    h = b"MSCF" + struct.pack("<IIIIIBBHHHHH", 0, total, 0, coff_files, 0, 3, 1,
                              len(folders), len(files), flags, set_id, icab)
    if reserve:
        h += struct.pack("<HBB", cbh, cbf, cbd) + bytes([0x55] * cbh)
    for pair in (prev, nxt):
        if pair:
            h += pair[0] + b"\0" + pair[1] + b"\0"
    assert len(h) == hdr_len
    return h + folder_blob + files_blob + data_blob


def mszip_blocks(data):
    out = []
    hist = b""
    for p in range(0, max(len(data), 1), FRAME):
        chunk = data[p:p + FRAME]
        if hist:
            c = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=hist[-FRAME:])
        else:
            c = zlib.compressobj(9, zlib.DEFLATED, -15)
        comp = c.compress(chunk) + c.flush()
        out.append((b"CK" + comp, len(chunk)))
        hist += chunk
    return out


def stored_blocks(data, step=FRAME):
    return [(data[p:p + step], len(data[p:p + step])) for p in range(0, len(data), step)]


def lzx_blocks(data, wb, plan, e8=None):
    comp, offs = lzx_compress(data, wb, plan, e8)
    blocks = []
    nframes = (len(data) + FRAME - 1) // FRAME
    offs = offs[:nframes] + [len(comp)]
    for k in range(nframes):
        blocks.append((comp[offs[k]:offs[k + 1]], min(FRAME, len(data) - k * FRAME)))
    return blocks


def layout(entries):
    """entries: [(name, bytes)] -> (folder_data, [(name, size, offset)])"""
    blob = b""
    out = []
    for name, d in entries:
        out.append((name, len(d), len(blob)))
        blob += d
    return blob, out


T1 = dos(2024, 5, 17, 13, 45, 30)


def gen_cab():
    # 1. MSZIP, multi-block with cross-block history, subdirectory names.
    ents = [
        (b"readme.txt", text(1, 1500)),
        (b"docs\\guide.txt", text(2, 70000)),
        (b"empty.dat", b""),
        (b"bin\\data.bin", binary(3, 9000) + text(1, 1500)),
    ]
    blob, lay = layout(ents)
    files = [(n, s, 0, o, T1, 0x20) for n, s, o in lay]
    write("mszip.cab", build_cab([(1, mszip_blocks(blob))], files))
    write_expect("mszip.cab", [("f", n.decode().replace("\\", "/"), d) for n, d in ents])

    # 2. Stored, two folders, reserve fields, UTF-8 name flag, attributes.
    e1 = [(b"a.txt", b"hello cab\n"), (b"b.txt", text(4, 33000))]
    e2 = [("über/日本.txt".replace("/", "\\").encode("utf-8"), text(5, 300))]
    b1, l1 = layout(e1)
    b2, l2 = layout(e2)
    files = [(n, s, 0, o, T1, 0x21) for n, s, o in l1]
    files += [(n, s, 1, o, dos(2001, 1, 2, 3, 4, 6), 0xA0) for n, s, o in l2]
    write("stored.cab", build_cab([(0, stored_blocks(b1)), (0, stored_blocks(b2))],
                                  files, reserve=(6, 3, 2)))
    write_expect("stored.cab", [("f", n.decode().replace("\\", "/"), d) for n, d in e1 + e2])

    # 3. LZX window 2^15: verbatim + aligned + uncompressed (spanning a frame), E8.
    ents = [
        (b"prog.exe", x86ish(7, 30000)),
        (b"notes.txt", text(8, 30000)),
        (b"rand.bin", binary(9, 6000)),
    ]
    blob, lay = layout(ents)
    plan = [(1, 10000), (2, 15000), (3, 20000), (1, len(blob) - 45000)]
    files = [(n, s, 0, o, T1, 0x20) for n, s, o in lay]
    write("lzx15.cab", build_cab([(0x0F03, lzx_blocks(blob, 15, plan, e8=12000000))], files))
    write_expect("lzx15.cab", [("f", n.decode(), d) for n, d in ents])

    # 4. LZX window 2^21, single aligned block spanning several frames, no E8,
    #    plus an MSZIP folder in the same cabinet.
    ents = [(b"big.txt", text(10, 100000) + text(10, 50000))]
    blob, lay = layout(ents)
    files = [(n, s, 0, o, T1, 0x20) for n, s, o in lay]
    e2 = [(b"z.txt", text(11, 5000))]
    b2, l2 = layout(e2)
    files += [(n, s, 1, o, T1, 0x20) for n, s, o in l2]
    write("lzx21.cab", build_cab([(0x1503, lzx_blocks(blob, 21, [(2, len(blob))])),
                                  (1, mszip_blocks(b2))], files))
    write_expect("lzx21.cab", [("f", n.decode(), d) for n, d in ents + e2])

    # 5. Quantum folder: listed, extraction unsupported. Data is not real Quantum.
    files = [(b"q.txt", 100, 0, 0, T1, 0x20)]
    write("quantum.cab", build_cab([(0x1202, [(b"\x00" * 20, 100)])], files))

    # 6. Multi-cabinet set member: file continued to the next cabinet.
    d = text(12, 3000)
    files = [(b"whole.txt", 1000, 0, 0, T1, 0x20), (b"split.txt", 5000, 0xFFFE, 1000, T1, 0x20)]
    write("spanned.cab", build_cab([(0, stored_blocks(d))], files,
                                   prev=(b"prev.cab", b"Disk 1"), nxt=(b"next.cab", b"Disk 3"), icab=1))
    write_expect("spanned.cab", [("f", "whole.txt", d[:1000])])

    # Raw LZX stream (continuous frames) for decoder-level tests.
    data = x86ish(13, 10000) + text(14, 23000)
    comp, offs = lzx_compress(data, 16, [(2, 10000), (3, 9999), (1, 1), (1, 13000)], e8_size=1 << 20)
    write("raw16.lzx", comp)
    write("raw16.out", data)


# --------------------------------------------------------------------------
# CFB writer (MS-CFB)
FREESECT, ENDOFCHAIN, FATSECT, DIFSECT, NOSTREAM = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC, 0xFFFFFFFF


def cfb_key(name):
    return (len(name), name.upper())


def build_cfb(tree, version=3, min_fat=0, mtime=0):
    """tree: dict name -> bytes (stream) or dict (storage). Names are str
    (may contain any BMP chars). Returns file bytes."""
    shift = 9 if version == 3 else 12
    ss = 1 << shift
    dirents = []  # [name, type, left, right, child, start, size, data]

    def add(name, typ, data=None):
        dirents.append([name, typ, NOSTREAM, NOSTREAM, NOSTREAM, ENDOFCHAIN, 0, data])
        return len(dirents) - 1

    def build(storage_idx, children):
        idxs = []
        for nm, v in children.items():
            if isinstance(v, dict):
                i = add(nm, 1)
                build(i, v)
            else:
                i = add(nm, 2, v)
            idxs.append(i)
        idxs.sort(key=lambda i: cfb_key(dirents[i][0]))

        def bal(lo, hi):
            if lo >= hi:
                return NOSTREAM
            mid = (lo + hi) // 2
            dirents[idxs[mid]][2] = bal(lo, mid)
            dirents[idxs[mid]][3] = bal(mid + 1, hi)
            return idxs[mid]

        dirents[storage_idx][4] = bal(0, len(idxs))

    root = add("Root Entry", 5)
    build(root, tree)

    sectors = []  # list of bytes, each ss long
    fat = {}

    def alloc_chain(data):
        n = (len(data) + ss - 1) // ss
        first = len(sectors)
        for k in range(n):
            sectors.append(data[k * ss:(k + 1) * ss].ljust(ss, b"\0"))
            fat[first + k] = first + k + 1 if k + 1 < n else ENDOFCHAIN
        return first if n else ENDOFCHAIN

    # streams: big ones in regular sectors, small ones in the mini stream
    mini = bytearray()
    minifat = []
    for e in dirents:
        if e[1] != 2:
            continue
        d = e[7]
        e[6] = len(d)
        if len(d) == 0:
            continue
        if len(d) >= 4096:
            e[5] = alloc_chain(d)
        else:
            n = (len(d) + 63) // 64
            first = len(mini) // 64
            mini += d.ljust(n * 64, b"\0")
            for k in range(n):
                minifat.append(first + k + 1 if k + 1 < n else ENDOFCHAIN)
            e[5] = first
    if mini:
        dirents[root][5] = alloc_chain(bytes(mini))
        dirents[root][6] = len(mini)
    mf_first, mf_count = ENDOFCHAIN, 0
    if minifat:
        mfb = b"".join(struct.pack("<I", x) for x in minifat)
        mfb += b"\xff" * ((-len(mfb)) % ss)
        mf_first = alloc_chain(mfb)
        mf_count = len(mfb) // ss
    # directory
    db = bytearray()
    for name, typ, left, right, child, start, size, _ in dirents:
        u = name.encode("utf-16-le")
        assert len(u) <= 62
        db += u.ljust(64, b"\0") + struct.pack("<HBB", len(u) + 2, typ, 1)
        db += struct.pack("<III", left, right, child) + b"\0" * 16 + struct.pack("<I", 0)
        t = mtime if typ in (1, 5) else 0
        db += struct.pack("<QQ", t, t) + struct.pack("<IQ", start, size if typ != 1 else 0)
    unused = b"\0" * 64 + struct.pack("<HBB", 0, 0, 0) + struct.pack("<III", NOSTREAM, NOSTREAM, NOSTREAM) + b"\0" * 36 + struct.pack("<IQ", 0, 0)
    assert len(unused) == 128
    while len(db) % ss:
        db += unused
    dir_first = alloc_chain(bytes(db))
    dir_count = len(db) // ss
    # FAT + DIFAT sectors
    per = ss // 4
    nfat = max(min_fat, 1)
    while True:
        ndif = 0 if nfat <= 109 else (nfat - 109 + per - 2) // (per - 1)
        if (len(sectors) + nfat + ndif) <= nfat * per:
            break
        nfat += 1
    fat_start = len(sectors)
    dif_start = fat_start + nfat
    total = dif_start + ndif
    for k in range(nfat):
        fat[fat_start + k] = FATSECT
    for k in range(ndif):
        fat[dif_start + k] = DIFSECT
    fatb = b"".join(struct.pack("<I", fat.get(i, FREESECT)) for i in range(nfat * per))
    for k in range(nfat):
        sectors.append(fatb[k * ss:(k + 1) * ss])
    fat_ids = list(range(fat_start, fat_start + nfat))
    for k in range(ndif):
        ents = fat_ids[109 + k * (per - 1):109 + (k + 1) * (per - 1)]
        blob = b"".join(struct.pack("<I", x) for x in ents)
        blob = blob.ljust((per - 1) * 4, b"\xff")
        blob += struct.pack("<I", dif_start + k + 1 if k + 1 < ndif else ENDOFCHAIN)
        sectors.append(blob)
    assert len(sectors) == total
    hdr = bytearray(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 16)
    hdr += struct.pack("<HHHHH", 0x3E, version, 0xFFFE, shift, 6) + b"\0" * 6
    hdr += struct.pack("<IIIIIIIII", dir_count if version == 4 else 0, nfat, dir_first, 0, 4096,
                       mf_first, mf_count, dif_start if ndif else ENDOFCHAIN, ndif)
    difat = fat_ids[:109] + [FREESECT] * (109 - min(109, nfat))
    hdr += b"".join(struct.pack("<I", x) for x in difat)
    assert len(hdr) == 512
    hdr = bytes(hdr).ljust(ss, b"\0")
    return hdr + b"".join(sectors)


MSI_TABLE = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"


def msi_encode(name, table=False):
    out = [chr(0x4840)] if table else []
    i = 0
    while i < len(name):
        c1 = MSI_TABLE.index(name[i])
        if i + 1 < len(name) and name[i + 1] in MSI_TABLE:
            c2 = MSI_TABLE.index(name[i + 1])
            out.append(chr(0x3800 + c1 + (c2 << 6)))
            i += 2
        else:
            out.append(chr(0x4800 + c1))
            i += 1
    return "".join(out)


def esc(name):
    return "".join("[%d]" % ord(c) if ord(c) < 0x20 else c for c in name)


def flatten(tree, prefix=""):
    rows = []
    for nm, v in sorted(tree.items(), key=lambda kv: cfb_key(kv[0])):
        p = prefix + esc(nm)
        if isinstance(v, dict):
            rows.append(("d", p, None))
            rows += flatten(v, p + "/")
        else:
            rows.append(("f", p, v))
    return rows


FT = 133500000000000000  # a FILETIME in 2024


def gen_cfb():
    tree = {
        "\x05SummaryInformation": binary(20, 300),
        "WordDocument": text(21, 9000),
        "1Table": binary(22, 4095),
        "Data": b"",
        "ObjectPool": {"_1234": {"\x01Ole": binary(23, 20), "CONTENTS": text(24, 5000)}},
        "Small": b"x",
    }
    write("doc.cfb", build_cfb(tree, mtime=FT))
    write_expect("doc.cfb", flatten(tree))

    tree4 = {"Big": text(25, 4200), "Tiny": b"tiny\n", "Dir": {"Inner": binary(26, 4100)}}
    write("v4.cfb", build_cfb(tree4, version=4))
    write_expect("v4.cfb", flatten(tree4))

    # Forces 110 FAT sectors, so the DIFAT spills into one DIFAT sector.
    treed = {"Stream": text(27, 6000)}
    write("difat.cfb", build_cfb(treed, min_fat=110))
    write_expect("difat.cfb", flatten(treed))

    # MSI-style encoded stream names.
    treem = {msi_encode("_Tables", True): b"\x01\x00", msi_encode("_StringData", True): text(28, 100),
             msi_encode("Binary.icon"): binary(29, 600), "\x05SummaryInformation": binary(30, 200)}
    write("names.msi", build_cfb(treem))
    # names as presented after MSI name decoding (7-Zip shows the same)
    write_expect("names.msi", [("f", "!_Tables", b"\x01\x00"), ("f", "!_StringData", text(28, 100)),
                               ("f", "Binary.icon", binary(29, 600)),
                               ("f", "[5]SummaryInformation", binary(30, 200))])


# --------------------------------------------------------------------------
# CHM writer
def encint(v):
    out = [v & 0x7F]
    v >>= 7
    while v:
        out.append(0x80 | (v & 0x7F))
        v >>= 7
    return bytes(reversed(out))


def guid(s):
    return uuid.UUID(s).bytes_le


LZX_GUID = "{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}"


def build_chm(sec0_files, sec1_files, chunk_size=0x1000, reset_frames=2, window_units=2,
              dirs=(), use_index=True, pad_stream=True):
    """sec0_files/sec1_files: [(name, bytes)]. Returns (chm bytes, rows)."""
    # section 1 (LZX) stream
    s1 = b""
    sec1_ent = []
    for n, d in sec1_files:
        sec1_ent.append((n, 1, len(s1), len(d)))
        s1 += d
    wb = {1: 15, 2: 16, 4: 17, 8: 18, 16: 19, 32: 20, 64: 21}[window_units]
    span = reset_frames * FRAME
    s1_len = len(s1)
    if pad_stream:
        s1 = s1 + b"\0" * ((-len(s1)) % FRAME)
    comp = b""
    frame_offs = []
    for p in range(0, len(s1), span):
        piece = s1[p:p + span]
        plan = []
        q = 0
        while q < len(piece):
            n = min(len(piece) - q, 20000)
            plan.append((1 if (q // 20000) % 2 == 0 else 2, n))
            q += n
        c, offs = lzx_compress(piece, wb, plan)
        nf = (len(piece) + FRAME - 1) // FRAME
        frame_offs += [len(comp) + o for o in offs[:nf]]
        comp += c
    # 7-Zip wants floor(len / 32 KiB) + 1 entries: add the end offset when the
    # length is an exact multiple of the frame size.
    if s1_len % FRAME == 0:
        frame_offs.append(len(comp))
    reset = struct.pack("<IIII", 2, len(frame_offs), 8, 0x28) + struct.pack("<QQQ", s1_len, len(comp), FRAME)
    reset += b"".join(struct.pack("<Q", o) for o in frame_offs)
    control = struct.pack("<I", 6) + b"LZXC" + struct.pack("<IIIII", 2, reset_frames, window_units, 2, 0)
    namelist = b""
    names = ["Uncompressed", "MSCompressed"]
    body = b"".join(struct.pack("<H", len(n)) + n.encode("utf-16-le") + b"\0\0" for n in names)
    namelist = struct.pack("<HH", (4 + len(body)) // 2, len(names)) + body
    sys0 = [
        ("::DataSpace/NameList", namelist),
        ("::DataSpace/Storage/MSCompressed/Content", comp),
        ("::DataSpace/Storage/MSCompressed/ControlData", control),
        ("::DataSpace/Storage/MSCompressed/SpanInfo", struct.pack("<Q", s1_len)),
        ("::DataSpace/Storage/MSCompressed/Transform/List", LZX_GUID.encode("utf-16-le")),
        ("::DataSpace/Storage/MSCompressed/Transform/" + LZX_GUID + "/InstanceData/ResetTable", reset),
    ]
    s0 = b""
    ents = []
    for n, d in sec0_files + sys0:
        ents.append((n, 0, len(s0), len(d)))
        s0 += d
    for d in dirs:
        ents.append((d, 0, 0, 0))
    ents += sec1_ent
    ents.sort(key=lambda e: e[0].lower())
    # PMGL chunks
    chunks = []
    cur = b""
    firsts = []
    count = 0
    pmgls = []
    for n, sec, off, ln in ents:
        nb = n.encode("utf-8")
        e = encint(len(nb)) + nb + encint(sec) + encint(off) + encint(ln)
        if 0x14 + len(cur) + len(e) + 2 > chunk_size:
            pmgls.append((cur, count))
            cur, count = b"", 0
        if count == 0:
            firsts.append(nb)
        cur += e
        count += 1
    pmgls.append((cur, count))
    np = len(pmgls)
    for k, (body, cnt) in enumerate(pmgls):
        free = chunk_size - 0x14 - len(body)
        hdr = b"PMGL" + struct.pack("<IIii", free, 0, k - 1 if k else -1, k + 1 if k + 1 < np else -1)
        ch = hdr + body + b"\0" * (free - 2) + struct.pack("<H", cnt)
        assert len(ch) == chunk_size
        chunks.append(ch)
    root = -1
    if use_index:
        body = b"".join(encint(len(f)) + f + encint(k) for k, f in enumerate(firsts))
        free = chunk_size - 8 - len(body)
        chunks.append(b"PMGI" + struct.pack("<I", free) + body + b"\0" * (free - 2) + struct.pack("<H", np))
        root = np
    itsp = b"ITSP" + struct.pack("<IIIIIiiiiiII", 1, 0x54, 0x0A, chunk_size, 2, 2 if use_index else 1,
                                 root, 0, np - 1, -1, len(chunks), 0x409)
    itsp += guid("5D02926A-212E-11D0-9DF9-00A0C922E6EC") + struct.pack("<Iiii", 0x54, -1, -1, -1)
    assert len(itsp) == 0x54
    directory = itsp + b"".join(chunks)
    hs0_off = 0x60
    dir_off = hs0_off + 0x18
    content_off = dir_off + len(directory)
    total = content_off + len(s0)
    hs0 = struct.pack("<IIQII", 0x1FE, 0, total, 0, 0)
    itsf = b"ITSF" + struct.pack("<IIIII", 3, 0x60, 1, 0x12345678, 0x409)
    itsf += guid("7C01FD10-7BAA-11D0-9E0C-00A0C922E6EC") + guid("7C01FD11-7BAA-11D0-9E0C-00A0C922E6EC")
    itsf += struct.pack("<QQQQQ", hs0_off, 0x18, dir_off, len(directory), content_off)
    assert len(itsf) == 0x60
    data = itsf + hs0 + directory + s0
    contents = dict(sec0_files + sys0 + sec1_files)
    rows = []
    for n, sec, off, ln in ents:
        if n.endswith("/"):
            rows.append(("d", n, None))
        else:
            rows.append(("f", n, contents[n]))
    return data, rows


def gen_chm():
    sec1 = [("/index.html", b"<html><body>" + text(40, 5000) + b"</body></html>")]
    for k in range(80):
        sec1.append(("/docs/page_%03d_with_a_rather_long_name_for_chunking.html" % k, text(100 + k, 600)))
    sec1.append(("/big.txt", text(41, 20000)))
    sec0 = [("/#SYSTEM", binary(42, 200)), ("/img.bin", binary(43, 1500)), ("/empty.txt", b"")]
    data, rows = build_chm(sec0, sec1, dirs=["/", "/docs/"])
    write("help.chm", data)
    write_expect("help.chm", rows)
    # single chunk, no index, window 2^15 and reset every 4 frames
    sec1 = [("/a.htm", text(50, 40000)), ("/b.htm", text(51, 30000))]
    data, rows = build_chm([("/c.bin", binary(52, 100))], sec1, reset_frames=4, window_units=1,
                           use_index=False)
    write("small.chm", data)
    write_expect("small.chm", rows)
    # exact multiple of the frame size (terminal reset-table entry)
    sec1 = [("/x.htm", text(53, 40000)), ("/y.htm", text(54, 25536))]
    data, rows = build_chm([], sec1, use_index=False)
    write("exact.chm", data)
    write_expect("exact.chm", rows)
    # final frame not padded to 32 KiB (7-Zip rejects this; Sediment accepts)
    sec1 = [("/p.htm", text(55, 2000)), ("/q.htm", text(56, 1000))]
    data, rows = build_chm([], sec1, use_index=False, pad_stream=False)
    write("partial_frame.chm", data)
    write_expect("partial_frame.chm.local", rows)


if __name__ == "__main__":
    gen_cab()
    gen_cfb()
    gen_chm()
