#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Oracle fixtures for Sediment archive updates (u / d / rn).

Python stdlib only (zipfile, tarfile, gzip, bz2, lzma, zlib, struct).

  python3 tests/gen/update_ops.py            # (re)write tests/fixtures/update_ops/
  python3 tests/gen/update_ops.py check F... # read archives with zipfile/tarfile,
                                             # verify every member, print a listing

`check` prints one line per member: type<TAB>size<TAB>crc32(hex)<TAB>name
(type F file, D directory, L symlink, H hard link, with the link target
appended after another TAB for L/H). Members are read in full, so CRC errors
fail the check. The Rust tests in tests/update_ops.rs call `check` (when a
python3 is available) on archives Sediment rewrote and compare the listing
with the one they expect.

Every generated archive also gets NAME.list.tsv: the same listing, taken
from the source archive with the stdlib reader.
"""
import bz2
import gzip
import io
import lzma
import os
import struct
import sys
import tarfile
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.normpath(os.path.join(HERE, "..", "fixtures", "update_ops"))
T = 1_600_000_000  # 2020-09-13T12:26:40Z


def text(n):
    words = ["sediment", "update", "delete", "rename", "layer", "silt"]
    return "".join(f"{i:04d} {words[i % 6]} {words[(i * 5) % 6]}\n" for i in range(n)).encode()


def lcg(n, seed=7):
    out = bytearray()
    x = seed
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


class Unseekable(io.RawIOBase):
    """Forces zipfile to write data descriptors."""

    def __init__(self):
        self.buf = bytearray()

    def writable(self):
        return True

    def write(self, b):
        self.buf += b
        return len(b)


def zinfo(name, method=zipfile.ZIP_DEFLATED, mode=0o644, t=(2021, 5, 6, 7, 8, 10)):
    zi = zipfile.ZipInfo(name, date_time=t)
    zi.compress_type = method
    zi.external_attr = ((0o040755 if name.endswith("/") else 0o100000 | mode) << 16) | (0x10 if name.endswith("/") else 0)
    zi.create_system = 3
    return zi


def make_zip_mixed():
    raw = Unseekable()
    with zipfile.ZipFile(raw, "w") as z:
        z.comment = b"sediment update fixture"
        z.writestr(zinfo("readme.txt"), text(40))
        z.writestr(zinfo("docs/"), b"")
        z.writestr(zinfo("docs/guide.md"), text(120))
        z.writestr(zinfo("docs/notes.txt", zipfile.ZIP_STORED), b"stored notes\n")
        z.writestr(zinfo("docs/old.bak"), b"backup\n")
        z.writestr(zinfo("data/"), b"")
        z.writestr(zinfo("data/random.bin", zipfile.ZIP_STORED), lcg(3000))
        z.writestr(zinfo("data/old.bak", zipfile.ZIP_STORED), b"another backup\n")
        z.writestr(zinfo("héllo_日本.txt"), "unicode name\n".encode())
        z.writestr(zinfo("empty.txt", zipfile.ZIP_STORED), b"")
    return bytes(raw.buf)


def make_zip_seekable():
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(zinfo("a.txt"), text(10))
        z.writestr(zinfo("b/"), b"")
        z.writestr(zinfo("b/c.txt"), text(30))
        z.writestr(zinfo("d.bin", zipfile.ZIP_STORED), lcg(500, 3))
    return b.getvalue()


def make_zip_sfx():
    stub = b"#!/bin/sh\necho self-extractor stub\nexit 0\n" + bytes(64)
    b = io.BytesIO()
    b.write(stub)
    with zipfile.ZipFile(b, "a") as z:
        z.writestr(zinfo("one.txt"), text(5))
        z.writestr(zinfo("two.txt"), text(7))
    return b.getvalue()


def make_zip64_offsets():
    """Hand-built archive whose central records keep the local header offset
    in a ZIP64 extra field (APPNOTE 4.5.3), as some streaming writers do."""
    out = bytearray()
    central = bytearray()
    files = [("first.txt", text(3)), ("second.txt", text(4)), ("third.txt", text(6))]
    for name, data in files:
        off = len(out)
        crc = zlib.crc32(data)
        nb = name.encode()
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 45, 0, 0, 0x4000, 0x5221, crc, len(data), len(data), len(nb), 0)
        out += nb + data
        extra = struct.pack("<HHQ", 1, 8, off)
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, (3 << 8) | 45, 45, 0, 0, 0x4000, 0x5221, crc, len(data), len(data),
            len(nb), len(extra), 0, 0, 0, (0o100644 << 16), 0xFFFFFFFF)
        central += nb + extra
    cd_off = len(out)
    out += central
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(files), len(files), len(central), cd_off, 0)
    return bytes(out)


def add_file(t, name, data, mode=0o644, mtime=T):
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mode = mode
    ti.mtime = mtime
    ti.uid, ti.gid, ti.uname, ti.gname = 1000, 1000, "mike", "staff"
    t.addfile(ti, io.BytesIO(data))


def add_special(t, name, typ, link="", mode=0o755):
    ti = tarfile.TarInfo(name)
    ti.type = typ
    ti.linkname = link
    ti.mode = mode
    ti.mtime = T
    ti.uid, ti.gid, ti.uname, ti.gname = 1000, 1000, "mike", "staff"
    t.addfile(ti)


LONG_DIR = "deep/" + "d" * 70 + "/" + "e" * 70
LONG_NAME = LONG_DIR + "/" + "f" * 110 + ".txt"  # last part > 100 bytes: needs pax/GNU long name


def fill_tar(t):
    add_special(t, "src", tarfile.DIRTYPE)
    add_file(t, "src/main.c", text(50))
    add_file(t, "src/util.c", text(20), 0o600)
    add_file(t, "src/old.o", lcg(700, 9))
    add_special(t, "src/link", tarfile.SYMTYPE, "main.c", 0o777)
    add_special(t, "src/hard", tarfile.LNKTYPE, "src/main.c", 0o644)
    add_file(t, "README", b"tar fixture\n")
    add_file(t, LONG_NAME, text(8))
    add_special(t, "longlink", tarfile.SYMTYPE, LONG_NAME, 0o777)
    add_file(t, "empty", b"")


def make_tar(fmt, compress=None, pax_headers=None):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w", format=fmt, pax_headers=pax_headers or {}) as t:
        fill_tar(t)
    raw = b.getvalue()
    if compress == "gz":
        return gzip.compress(raw, mtime=0)
    if compress == "bz2":
        return bz2.compress(raw)
    if compress == "xz":
        return lzma.compress(raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64)
    return raw


def listing_zip(data):
    z = zipfile.ZipFile(io.BytesIO(data))
    bad = z.testzip()
    if bad is not None:
        raise SystemExit(f"CRC error in {bad}")
    lines = []
    for i in z.infolist():
        if i.is_dir():
            lines.append(f"D\t0\t00000000\t{i.filename.rstrip('/')}")
        else:
            d = z.read(i)
            kind = "L" if (i.external_attr >> 16) & 0o170000 == 0o120000 else "F"
            lines.append(f"{kind}\t{len(d)}\t{zlib.crc32(d):08x}\t{i.filename}")
    return lines


def listing_tar(data):
    t = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    lines = []
    for m in t.getmembers():
        if m.isdir():
            lines.append(f"D\t0\t00000000\t{m.name.rstrip('/')}")
        elif m.issym():
            lines.append(f"L\t0\t00000000\t{m.name}\t{m.linkname}")
        elif m.islnk():
            lines.append(f"H\t0\t00000000\t{m.name}\t{m.linkname}")
        else:
            d = t.extractfile(m).read()
            if len(d) != m.size:
                raise SystemExit(f"short member {m.name}")
            lines.append(f"F\t{len(d)}\t{zlib.crc32(d):08x}\t{m.name}")
    return lines


def listing(path):
    data = open(path, "rb").read()
    if data[:2] == b"PK" or zipfile.is_zipfile(io.BytesIO(data)):
        return listing_zip(data)
    return listing_tar(data)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        for p in sys.argv[2:]:
            print(f"# {os.path.basename(p)}")
            for line in listing(p):
                print(line)
        return
    os.makedirs(FIX, exist_ok=True)
    out = {
        "mixed.zip": make_zip_mixed(),
        "seekable.zip": make_zip_seekable(),
        "sfx.zip": make_zip_sfx(),
        "zip64_offsets.zip": make_zip64_offsets(),
        "pax.tar": make_tar(tarfile.PAX_FORMAT, pax_headers={"comment": "global header"}),
        "gnu.tar": make_tar(tarfile.GNU_FORMAT),
        "pax.tar.gz": make_tar(tarfile.PAX_FORMAT, "gz"),
        "gnu.tar.bz2": make_tar(tarfile.GNU_FORMAT, "bz2"),
        "pax.tar.xz": make_tar(tarfile.PAX_FORMAT, "xz"),
    }
    for name, data in out.items():
        path = os.path.join(FIX, name)
        with open(path, "wb") as f:
            f.write(data)
        with open(path + ".list.tsv", "w", encoding="utf-8") as f:
            f.write("\n".join(listing(path)) + "\n")
    print(f"wrote {len(out)} archives to {FIX}")


if __name__ == "__main__":
    main()
