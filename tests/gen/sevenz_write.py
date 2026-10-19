#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Independent differential check of the 7z writer fixtures.

Python-stdlib-only 7z reader written from the public 7z format description
(7zFormat.txt): parses the signature header, follows an encoded header, walks
PackInfo / UnpackInfo / SubStreamsInfo / FilesInfo, decodes each folder with
the stdlib `lzma` module (raw LZMA1 / LZMA2, BCJ x86 / ARM / ... via the liblzma
raw filter chain, Copy) and checks every member against the source tree that
`SEVENZ_WRITE_REGEN=<dir> cargo test --test sevenz_write regen` writes next to
the archives (`<dir>/src`; symlinks appear as `<name>.symlink-target`).

Usage: python3 -I tests/gen/sevenz_write.py <dir>
Exits non-zero on the first mismatch. Prints one OK line per archive.
"""
import binascii
import lzma
import os
import struct
import sys

BCJ = {
    b"\x03\x03\x01\x03": lzma.FILTER_X86,
    b"\x03\x03\x02\x05": lzma.FILTER_POWERPC,
    b"\x03\x03\x04\x01": lzma.FILTER_IA64,
    b"\x03\x03\x05\x01": lzma.FILTER_ARM,
    b"\x03\x03\x07\x01": lzma.FILTER_ARMTHUMB,
    b"\x03\x03\x08\x05": lzma.FILTER_SPARC,
}


class Cur:
    def __init__(self, b):
        self.b, self.p = b, 0

    def byte(self):
        v = self.b[self.p]
        self.p += 1
        return v

    def take(self, n):
        v = self.b[self.p:self.p + n]
        assert len(v) == n, "eof"
        self.p += n
        return v

    def num(self):
        first = self.byte()
        mask, extra = 0x80, 0
        while extra < 8 and first & mask:
            extra += 1
            mask >>= 1
        v = int.from_bytes(self.take(extra), "little")
        if extra < 8:
            v |= (first & (mask - 1)) << (8 * extra)
        return v

    def bits(self, n):
        raw = self.take((n + 7) // 8)
        return [bool(raw[i // 8] & (0x80 >> (i % 8))) for i in range(n)]

    def opt_bits(self, n):
        return [True] * n if self.byte() else self.bits(n)

    def digests(self, n):
        return [struct.unpack("<I", self.take(4))[0] if d else None for d in self.opt_bits(n)]


def read_streams(c):
    pack_pos, pack_sizes, folders, subs = 0, [], [], None
    while True:
        t = c.byte()
        if t == 0x00:
            return pack_pos, pack_sizes, folders, subs
        if t == 0x06:
            pack_pos = c.num()
            n = c.num()
            assert c.byte() == 0x09
            pack_sizes = [c.num() for _ in range(n)]
            t2 = c.byte()
            if t2 == 0x0A:
                c.digests(n)
                t2 = c.byte()
            assert t2 == 0x00
        elif t == 0x07:
            assert c.byte() == 0x0B
            nf = c.num()
            assert c.byte() == 0
            for _ in range(nf):
                coders = []
                for _ in range(c.num()):
                    flags = c.byte()
                    mid = c.take(flags & 0x0F)
                    assert not flags & 0x10, "complex coder"
                    props = c.take(c.num()) if flags & 0x20 else b""
                    coders.append((mid, props))
                pairs = [(c.num(), c.num()) for _ in range(len(coders) - 1)]
                folders.append({"coders": coders, "pairs": pairs})
            assert c.byte() == 0x0C
            for f in folders:
                f["sizes"] = [c.num() for _ in f["coders"]]
            t2 = c.byte()
            if t2 == 0x0A:
                for f, d in zip(folders, c.digests(nf)):
                    f["crc"] = d
                t2 = c.byte()
            assert t2 == 0x00
        elif t == 0x08:
            nums = [1] * len(folders)
            t2 = c.byte()
            if t2 == 0x0D:
                nums = [c.num() for _ in folders]
                t2 = c.byte()
            sizes = []
            if t2 == 0x09:
                for f, n in zip(folders, nums):
                    part = [c.num() for _ in range(n - 1)] if n else []
                    sizes += part + ([f["sizes"][0] - sum(part)] if n else [])
                t2 = c.byte()
            else:
                for f, n in zip(folders, nums):
                    if n:
                        sizes.append(f["sizes"][0])
            crcs = []
            if t2 == 0x0A:
                crcs = c.digests(sum(nums))
                t2 = c.byte()
            assert t2 == 0x00
            subs = (nums, sizes, crcs)
        else:
            raise AssertionError("unexpected property %#x" % t)


def decode_folder(archive, pack_off, packed_len, f):
    data = archive[pack_off:pack_off + packed_len]
    # Chain written by Sediment: coder k's input is bound to coder k+1's output.
    for k, (a, b) in enumerate(f["pairs"]):
        assert (a, b) == (k, k + 1), "unexpected bind pair"
    # Decode innermost coder first. LZMA1 has no end marker in 7z, so it goes
    # through the .lzma ("alone") container with the exact size; a BCJ filter
    # is applied by round-tripping through a raw [BCJ, LZMA2] chain (liblzma
    # only flushes a BCJ decoder at the end of an LZMA2 stream).
    out = data
    for (mid, props), size_k in reversed(list(zip(f["coders"], f["sizes"]))):
        if mid == b"\x00":
            pass
        elif mid == b"\x03\x01\x01":
            alone = props + struct.pack("<Q", size_k) + out
            out = lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(alone)
        elif mid == b"\x21":
            b = props[0]
            filt = [{"id": lzma.FILTER_LZMA2, "dict_size": (2 | (b & 1)) << (b // 2 + 11)}]
            dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filt)
            out = dec.decompress(out)
            assert dec.eof and dec.unused_data == b"", "lzma2 stream end"
        elif mid in BCJ:
            wrap = [{"id": lzma.FILTER_LZMA2, "preset": 0}]
            raw = lzma.compress(out, format=lzma.FORMAT_RAW, filters=wrap)
            out = lzma.decompress(raw, format=lzma.FORMAT_RAW, filters=[{"id": BCJ[mid]}] + wrap)
        else:
            raise AssertionError("method %s" % mid.hex())
        assert len(out) == size_k, "coder size %d != %d" % (len(out), size_k)
    size = f["sizes"][0]
    assert len(out) == size, "folder size %d != %d" % (len(out), size)
    if f.get("crc") is not None:
        assert binascii.crc32(out) == f["crc"], "folder crc"
    return out


def parse(archive):
    assert archive[:6] == b"7z\xbc\xaf\x27\x1c"
    assert binascii.crc32(archive[12:32]) == struct.unpack("<I", archive[8:12])[0]
    off, size, crc = struct.unpack("<QQI", archive[12:32])
    if size == 0:
        return [], []
    hdr = archive[32 + off:32 + off + size]
    assert len(hdr) == size and binascii.crc32(hdr) == crc
    while hdr[0] == 0x17:
        c = Cur(hdr)
        c.byte()
        pp, ps, folders, _ = read_streams(c)
        assert len(folders) == 1 and len(ps) == 1
        hdr = decode_folder(archive, 32 + pp, ps[0], folders[0])
    c = Cur(hdr)
    assert c.byte() == 0x01
    t = c.byte()
    pack_pos, pack_sizes, folders, subs = 0, [], [], None
    if t == 0x04:
        pack_pos, pack_sizes, folders, subs = read_streams(c)
        t = c.byte()
    files = []
    if t == 0x05:
        n = c.num()
        files = [{"empty_stream": False, "empty_file": False} for _ in range(n)]
        while True:
            p = c.byte()
            if p == 0:
                break
            body = Cur(c.take(c.num()))
            if p == 0x0E:
                for f, b in zip(files, body.bits(n)):
                    f["empty_stream"] = b
            elif p == 0x0F:
                es = [f for f in files if f["empty_stream"]]
                for f, b in zip(es, body.bits(len(es))):
                    f["empty_file"] = b
            elif p == 0x11:
                assert body.byte() == 0
                names = body.b[1:].decode("utf-16-le").split("\0")
                assert names[-1] == "" and len(names) == n + 1
                for f, nm in zip(files, names):
                    f["name"] = nm
            elif p in (0x12, 0x13, 0x14, 0x15):
                key = {0x12: "ctime", 0x13: "atime", 0x14: "mtime", 0x15: "attr"}[p]
                defined = body.opt_bits(n)
                assert body.byte() == 0
                w = 4 if p == 0x15 else 8
                for f, d in zip(files, defined):
                    if d:
                        f[key] = int.from_bytes(body.take(w), "little")
            else:
                raise AssertionError("file property %#x" % p)
        t = c.byte()
    assert t == 0x00 and c.p == len(hdr), "trailing header bytes"
    # Map substreams to files.
    nums, sizes, crcs = subs if subs else ([], [], [])
    datas, pos, si = [], 32 + pack_pos, 0
    for fi, f in enumerate(folders):
        out = decode_folder(archive, pos, pack_sizes[fi], f)
        pos += pack_sizes[fi]
        o = 0
        for _ in range(nums[fi]):
            d = out[o:o + sizes[si]]
            o += sizes[si]
            assert crcs[si] is None or binascii.crc32(d) == crcs[si], "substream crc"
            datas.append(d)
            si += 1
        assert o == len(out)
    assert pos == 32 + off or archive[pos:32 + off], "pack layout"
    it = iter(datas)
    for f in files:
        f["data"] = b"" if f["empty_stream"] else next(it)
    assert next(it, None) is None
    return files, folders


def main(d):
    src = os.path.join(d, "src")
    for name in sorted(os.listdir(d)):
        if not name.endswith(".7z"):
            continue
        archive = open(os.path.join(d, name), "rb").read()
        files, folders = parse(archive)
        assert files, name
        for f in files:
            p = os.path.join(src, f["name"])
            mode = f["attr"] >> 16
            ftype = mode & 0o170000
            if ftype == 0o040000:
                assert os.path.isdir(p) and f["attr"] & 0x10 and f["data"] == b"", f["name"]
            elif ftype == 0o120000:
                assert open(p + ".symlink-target", "rb").read() == f["data"], f["name"]
            else:
                assert ftype == 0o100000
                want = open(p, "rb").read()
                assert want == f["data"], f["name"]
                assert f["empty_file"] == (want == b""), f["name"]
            assert f["mtime"] == (1709618828 + 11644473600) * 10**7, f["name"]
        print("OK %s: %d files, %d folders, methods %s" % (
            name, len(files), len(folders),
            sorted({"+".join(m.hex() for m, _ in fo["coders"]) for fo in folders})))


if __name__ == "__main__":
    main(sys.argv[1])
