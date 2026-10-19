#!/usr/bin/env python3
"""Generate WIM and raw XPRESS Huffman fixtures for tests/wim_read.rs.

Python stdlib only. The WIM writer follows the Microsoft "Windows Imaging
File Format (WIM)" white paper (header, RESHDR_DISK_SHORT, offset table,
metadata resource with security block + DIRENTRY + stream entries, chunked
compressed resources) and the XPRESS Huffman encoder follows [MS-XCA]
2.1/2.2 (it is written to mirror the decoder pseudo-code bit for bit).
The generated WIMs were cross-checked with an independent reader, 7-Zip
`7zz` (see tests/gen/wim_oracle.sh); no 7-Zip code is used.

Outputs (tests/fixtures/wim/):
  *.wim                WIM files
  *.wim.list           expected listing: image<TAB>kind<TAB>size<TAB>sha256<TAB>path
  xpress_*.xp / .sha   raw XPRESS Huffman streams, out length + sha256
Run from the repo root:  python3 -I tests/gen/wim.py
"""
import hashlib
import heapq
import os
import random
import struct

OUT = os.path.join(os.path.dirname(__file__), "..", "fixtures", "wim")
os.makedirs(OUT, exist_ok=True)
for f in os.listdir(OUT):
    if not f.startswith(("7zz_", "wimlib_")):  # third-party: wim_oracle.sh
        os.remove(os.path.join(OUT, f))


# ===================================================================== XPRESS
def huffman_lengths(freq, max_len=15):
    syms = [s for s in range(512) if freq[s]]
    if len(syms) == 0:
        syms = [0, 1]
        freq = list(freq)
        freq[0] = freq[1] = 1
    if len(syms) == 1:
        other = 0 if syms[0] != 0 else 1
        syms.append(other)
        freq = list(freq)
        freq[other] = 1
    f = list(freq)
    while True:
        heap = [(f[s], i, [s]) for i, s in enumerate(syms)]
        heapq.heapify(heap)
        depth = {s: 0 for s in syms}
        n = len(heap)
        while len(heap) > 1:
            a = heapq.heappop(heap)
            b = heapq.heappop(heap)
            for s in a[2] + b[2]:
                depth[s] += 1
            n += 1
            heapq.heappush(heap, (a[0] + b[0], n, a[2] + b[2]))
        if max(depth.values()) <= max_len:
            lengths = [0] * 512
            for s, d in depth.items():
                lengths[s] = d
            return lengths
        f = [max(1, x // 2) if x else 0 for x in f]


def canonical_codes(lengths):
    codes = {}
    code = 0
    for ln in range(1, 16):
        for s in range(512):
            if lengths[s] == ln:
                codes[s] = (code, ln)
                code += 1
        code <<= 1
    return codes


def lz77(data, max_len=1 << 20):
    """Greedy LZ77 over the whole chunk: list of literal ints / (len, off)."""
    items = []
    heads = {}
    i, n = 0, len(data)
    while i < n:
        best_len, best_off = 0, 0
        if i + 3 <= n:
            key = data[i:i + 3]
            for p in reversed(heads.get(key, [])[-24:]):
                off = i - p
                if off > 65535:
                    continue
                ln = 0
                while i + ln < n and ln < max_len and data[p + ln] == data[i + ln]:
                    ln += 1
                if ln > best_len:
                    best_len, best_off = ln, off
                    if ln >= 258:
                        break
        if best_len >= 3:
            items.append((best_len, best_off))
            step = best_len
        else:
            items.append(data[i])
            step = 1
        for k in range(i, min(i + step, n - 2)):
            heads.setdefault(data[k:k + 3], []).append(k)
        i += step
    return items


def symbol_of(item):
    if isinstance(item, int):
        return item
    ln, off = item
    ob = off.bit_length() - 1
    return 256 + (ob << 4) + min(ln - 3, 15)


def xpress_compress(data):
    items = lz77(data)
    out = bytearray()
    idx, pos = 0, 0
    while pos < len(data) or (idx == 0 and not data):
        block_end = pos + 65536
        # Items of this block: until the output position reaches block_end.
        blk = []
        p = pos
        while idx < len(items) and p < block_end:
            it = items[idx]
            blk.append(it)
            p += 1 if isinstance(it, int) else it[0]
            idx += 1
        last = idx >= len(items)
        freq = [0] * 512
        for it in blk:
            freq[symbol_of(it)] += 1
        if last:
            # End-of-data symbol (256 = match length 3, offset 1, no extra
            # bits). WIM readers stop at the chunk size and do not need it,
            # but some decoders (7-Zip) expect it, as Microsoft writes it.
            freq[256] += 1
        lengths = huffman_lengths(freq)
        codes = canonical_codes(lengths)
        out += bytes(lengths[2 * i] | lengths[2 * i + 1] << 4 for i in range(256))
        # Bitstream simulation mirroring the [MS-XCA] decoder.
        slots = [len(out), len(out) + 2]
        out += b"\0\0\0\0"
        bits = []
        state = {"C": 0, "L": 32}

        def put(val, n):
            for k in range(n - 1, -1, -1):
                bits.append((val >> k) & 1)
            state["C"] += n
            if state["L"] - state["C"] < 16:
                slots.append(len(out))
                out.extend(b"\0\0")
                state["L"] += 16

        for it in blk:
            sym = symbol_of(it)
            put(*codes[sym])
            if isinstance(it, int):
                continue
            ln, off = it
            L = ln - 3
            if L >= 15:
                if L - 15 < 255:
                    out.append(L - 15)
                else:
                    out.append(255)
                    if L <= 0xFFFF:
                        out.extend(struct.pack("<H", L))
                    else:
                        out.extend(struct.pack("<HI", 0, L))
            ob = off.bit_length() - 1
            if ob:
                put(off - (1 << ob), ob)
        if last:
            put(*codes[256])
        for k, slot in enumerate(slots):
            w = 0
            for b in bits[16 * k:16 * k + 16]:
                w = (w << 1) | b
            w <<= 16 - len(bits[16 * k:16 * k + 16])
            out[slot:slot + 2] = struct.pack("<H", w)
        pos = p
        if not data:
            break
    return bytes(out)


# ===================================================================== WIM
FT = 133_540_000_000_000_000  # a FILETIME in 2024
DIR, ARCHIVE, REPARSE = 0x10, 0x20, 0x400
HDR_COMPRESSION, HDR_XPRESS, HDR_LZX, HDR_LZMS = 0x2, 0x20000, 0x40000, 0x80000
RES_METADATA, RES_COMPRESSED, RES_SOLID = 0x2, 0x4, 0x10


def sha1(b):
    return hashlib.sha1(b).digest() if b else bytes(20)


def utf16(s):
    return s.encode("utf-16-le")


class Node:
    def __init__(self, name, data=None, children=None, ads=None, hlg=0, reparse=None,
                 unnamed_in_ads=False, empty_list=False, attrs=None):
        self.name, self.data, self.children = name, data, children
        self.ads = ads or []
        self.hlg, self.reparse = hlg, reparse
        self.unnamed_in_ads, self.empty_list = unnamed_in_ads, empty_list
        self.attrs = attrs


def ads_entry(name, h):
    nb = utf16(name)
    ln = 38 + len(nb) + (2 if nb else 0)
    pad = (-ln) % 8
    return struct.pack("<QQ20sH", ln + pad, 0, h, len(nb)) + nb + (b"\0\0" if nb else b"") + b"\0" * pad


def dentry(node, subdir):
    nb = utf16(node.name)
    is_dir = node.children is not None
    if node.attrs is not None:
        attrs = node.attrs
    elif is_dir:
        attrs = DIR
    elif node.reparse is not None:
        attrs = ARCHIVE | REPARSE
    else:
        attrs = ARCHIVE
    data = node.data if node.reparse is None else node.reparse[1]
    h = sha1(data) if data else bytes(20)
    streams = []
    if node.unnamed_in_ads:
        streams.append(ads_entry("", h))
        h = bytes(20)
    for sname, sdata in node.ads:
        streams.append(ads_entry(sname, sha1(sdata)))
    union = struct.pack("<IHH", node.reparse[0], 0, 0) if node.reparse else struct.pack("<Q", node.hlg)
    ln = 102 + len(nb) + (2 if nb else 0)
    pad = (-ln) % 8
    fixed = struct.pack("<QIiQQQQQQ20sI", ln + pad, attrs, -1, subdir, 0, 0, FT, FT + 1, FT + 2, h, 0)
    fixed += union + struct.pack("<HHH", len(streams), 0, len(nb))
    assert len(fixed) == 102
    return fixed + nb + (b"\0\0" if nb else b"") + b"\0" * pad + b"".join(streams)


def metadata(root):
    """Security block, root dentry + end marker, then directory lists."""
    sec = struct.pack("<II", 8, 0)
    # Layout pass: assign list offsets breadth-first.
    lists = []  # (dir node, offset)

    def size_of_list(node):
        return sum(len(dentry(c, 0)) for c in node.children) + 8

    root_len = len(dentry(root, 0))
    off = len(sec) + root_len + 8
    queue = [root]
    offsets = {}
    while queue:
        d = queue.pop(0)
        if d.children or d.empty_list:
            offsets[id(d)] = off
            off += size_of_list(d)
            lists.append(d)
        for c in d.children:
            if c.children is not None:
                queue.append(c)
    out = bytearray(sec)
    out += dentry(root, offsets.get(id(root), 0)) + bytes(8)
    for d in lists:
        assert len(out) == offsets[id(d)]
        for c in d.children:
            out += dentry(c, offsets.get(id(c), 0))
        out += bytes(8)
    return bytes(out)


def walk(node, prefix=""):
    """(path, kind, data) in reader order: each list, then its subdirs."""
    res = []
    subdirs = []
    for c in node.children:
        p = f"{prefix}/{c.name}" if prefix else c.name
        if c.children is not None:
            res.append((p, "dir", b""))
            subdirs.append((c, p))
        elif c.reparse is not None:
            res.append((p, "reparse", c.reparse[1]))
        else:
            res.append((p, "file", c.data))
    for c, p in subdirs:
        res.extend(walk(c, p))
    return res


def resource(blob, compression, chunk, force_raw=False):
    """Returns (stored bytes, flags)."""
    if compression is None or force_raw or not blob:
        return blob, 0
    chunks = [blob[i:i + chunk] for i in range(0, len(blob), chunk)]
    comp = []
    for c in chunks:
        x = compression(c)
        comp.append(x if len(x) < len(c) else c)
    esz = 8 if len(blob) > 0xFFFFFFFF else 4
    table, pos = b"", 0
    for c in comp[:-1]:
        pos += len(c)
        table += struct.pack("<I" if esz == 4 else "<Q", pos)
    stored = table + b"".join(comp)
    if len(stored) >= len(blob):
        return blob, 0
    return stored, RES_COMPRESSED


def reshdr(size, flags, offset, orig):
    return struct.pack("<Q", size)[:7] + bytes([flags]) + struct.pack("<QQ", offset, orig)


def build_wim(images, hdr_comp=None, chunk=32768, compress_fn=None, version=0x10D00,
              extra_flags=0, meta_flags=0, names=None):
    f = bytearray(208)
    lookup = []
    seen = {}

    def add_stream(data, extra=0):
        h = sha1(data)
        if h in seen:
            seen[h][1] += 1
            return
        stored, flags = resource(data, compress_fn, chunk)
        ent = [len(f), 1, stored, flags | extra, len(data), h]
        f.extend(stored)
        seen[h] = ent
        lookup.append(ent)

    def collect(node):
        for c in node.children:
            if c.children is not None:
                collect(c)
                continue
            d = c.data if c.reparse is None else c.reparse[1]
            if d:
                add_stream(d)
            for _, sd in c.ads:
                if sd:
                    add_stream(sd)

    for root in images:
        collect(root)
    for root in images:
        md = metadata(root)
        stored, flags = resource(md, compress_fn, chunk)
        ent = [len(f), 1, stored, flags | RES_METADATA | meta_flags, len(md), sha1(md)]
        f.extend(stored)
        lookup.append(ent)
    lt = b"".join(reshdr(len(e[2]), e[3], e[0], e[4]) + struct.pack("<HI", 1, e[1]) + e[5] for e in lookup)
    lt_off = len(f)
    f.extend(lt)
    names = names or [f"image{i + 1}" for i in range(len(images))]
    xml = "<WIM><TOTALBYTES>0</TOTALBYTES>" + "".join(
        f'<IMAGE INDEX="{i + 1}"><NAME>{n}</NAME><DIRCOUNT>0</DIRCOUNT><FILECOUNT>0</FILECOUNT>'
        f"<TOTALBYTES>0</TOTALBYTES></IMAGE>" for i, n in enumerate(names)) + "</WIM>"
    xml_b = b"\xff\xfe" + utf16(xml)
    xml_off = len(f)
    f.extend(xml_b)
    flags = extra_flags
    if hdr_comp:
        flags |= HDR_COMPRESSION | hdr_comp
    hdr = b"MSWIM\0\0\0" + struct.pack("<III", 208, version, flags)
    hdr += struct.pack("<I", chunk if hdr_comp else 0)
    hdr += hashlib.md5(b"guid" + bytes(len(images))).digest()
    hdr += struct.pack("<HHI", 1, 1, len(images))
    hdr += reshdr(len(lt), 0, lt_off, len(lt))
    hdr += reshdr(len(xml_b), 0, xml_off, len(xml_b))
    hdr += reshdr(0, 0, 0, 0) + struct.pack("<I", 0) + reshdr(0, 0, 0, 0)
    hdr += bytes(208 - len(hdr))
    assert len(hdr) == 208
    f[:208] = hdr
    return bytes(f)


rng = random.Random(20261019)
WORDS = [b"alpha", b"beta", b"gamma", b"delta", b"archive", b"image", b"chunk", b"wim",
         b"xpress", b"huffman", b"window", b"stream", b"entry"]


def text(n):
    out = bytearray()
    while len(out) < n:
        out += b" ".join(rng.choice(WORDS) for _ in range(rng.randint(3, 11))) + b"\n"
    return bytes(out[:n])


HELLO = b"Hello, WIM!\n"
TEXT = text(34_000)
TEXT_XP = text(70_000)
RANDOM = rng.randbytes(3000)
ZEROS = bytes(34_000)
NESTED = b"nested\n" * 3
META = b"alternate stream data\n"


def tree1(small=False):
    t, z = (TEXT[:5000], ZEROS[:5000]) if small else (TEXT, ZEROS)
    return Node("", children=[
        Node("hello.txt", HELLO),
        Node("text.txt", t),
        Node("empty.txt", b""),
        Node("random.bin", RANDOM),
        Node("zeros.bin", z),
        Node("dup.txt", HELLO),
        Node("h\u00e9llo_\u65e5\u672c.txt", b"unicode name\n"),
        Node("ads.txt", b"main data\n", ads=[("meta", META)]),
        Node("unnamed_ads.txt", b"unnamed in stream entry\n", ads=[("x", b"x\n")], unnamed_in_ads=True),
        Node("link_a.txt", b"hard linked\n", hlg=0x1234),
        Node("link_b.txt", b"hard linked\n", hlg=0x1234),
        Node("dir", children=[
            Node("sub", children=[Node("nested.txt", NESTED)]),
            Node("note.txt", b"in dir\n"),
        ]),
        Node("emptydir", children=[]),
        Node("emptylist", children=[], empty_list=True),
    ])


def tree2():
    return Node("", children=[
        Node("second.txt", b"second image\n"),
        Node("shared.txt", HELLO),
        Node("d", children=[Node("t.txt", TEXT[:5000])]),
    ])


def symlink_reparse(target, relative=True):
    t = utf16(target)
    return struct.pack("<HHHHI", 0, len(t), len(t), len(t), 1 if relative else 0) + t + t


def tree_reparse():
    return Node("", children=[
        Node("target.txt", HELLO),
        Node("rel_link", reparse=(0xA000000C, symlink_reparse("target.txt"))),
        Node("abs_link", reparse=(0xA000000C, symlink_reparse("C:\\Windows", False))),
    ])


def write(name, blob, images):
    with open(os.path.join(OUT, name), "wb") as fh:
        fh.write(blob)
    lines = []
    for i, root in enumerate(images):
        for p, kind, data in walk(root):
            lines.append(f"{i + 1}\t{kind}\t{len(data)}\t{hashlib.sha256(data).hexdigest()}\t{p}")
    with open(os.path.join(OUT, name + ".list"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


write("none.wim", build_wim([tree1(True)]), [tree1(True)])
write("xpress.wim", build_wim([tree1()], HDR_XPRESS, 32768, xpress_compress), [tree1()])
write("xpress_4k.wim", build_wim([tree1()], HDR_XPRESS, 4096, xpress_compress), [tree1()])
write("xpress_multi.wim", build_wim([tree1(), tree2()], HDR_XPRESS, 32768, xpress_compress,
                                    names=["one", "two"]), [tree1(), tree2()])
write("reparse.wim", build_wim([tree_reparse()]), [tree_reparse()])
# Unsupported variants: LZX / LZMS headers whose metadata is "compressed"
# (payload is a stand-in; it must never be decoded), solid resources.
fake = lambda b: b"\x00" * max(1, len(b) // 4)  # noqa: E731
write("lzx.wim", build_wim([tree2()], HDR_LZX, 32768, fake), [tree2()])
write("lzms.wim", build_wim([tree2()], HDR_LZMS, 32768, fake), [tree2()])
write("solid.wim", build_wim([tree2()], None, meta_flags=RES_SOLID, version=0x10E00), [tree2()])

# Raw XPRESS Huffman streams (multi-block and long-length cases).
xp_inputs = {
    "text": TEXT_XP,              # > 65536: two Huffman blocks
    "zeros": bytes(200_000),      # matches crossing 64 KiB blocks, 32-bit length
    "random": RANDOM,
    "one": b"x",
}
for n, data in xp_inputs.items():
    with open(os.path.join(OUT, f"xpress_{n}.xp"), "wb") as fh:
        fh.write(xpress_compress(data))
    with open(os.path.join(OUT, f"xpress_{n}.sha"), "w") as fh:
        fh.write(f"{len(data)} {hashlib.sha256(data).hexdigest()}\n")
print("ok", sum(os.path.getsize(os.path.join(OUT, x)) for x in os.listdir(OUT)), "bytes")
