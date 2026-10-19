#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fixtures for tests/difftest_fixes.rs: regression inputs for the
mismatches found by the differential harness (tests/diff/run_diff.py).

Python stdlib only (zipfile, gzip, lzma, tarfile) is the oracle; output is
deterministic. The few archives Python cannot write (ZIP Deflate64 / XZ
methods, xz ARM64/RISC-V filters) come from the pinned 7zz oracle via
tests/gen/difftest_7z.sh and are committed under tests/fixtures/difftest/7z/.

Usage:
  python3 -I tests/gen/difftest.py            # write tests/fixtures/difftest
  python3 -I tests/gen/difftest.py --stage D  # only write the input tree to D

Layout of tests/fixtures/difftest:
  tree/a.txt, tree/b.bin, tree/dir/c.txt   reference files
  zip_<case>.zip     the tree with ZIP methods/layouts the old reader refused
  multi.gz           two gzip members (RFC 1952 2.2) -> a.txt
  multi_junk.gz      the same plus non-gzip trailing bytes (must be Err)
  filter_<f>.xz      a.txt or b.bin through [<f>, LZMA2] xz filter chains
  empty.tar          two zero blocks (an empty tar archive)
"""
import gzip
import io
import lzma
import os
import shutil
import sys
import zipfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "fixtures", "difftest")
DT = (2024, 3, 5, 6, 7, 8)


def lcg_bytes(n, seed):
    out = bytearray()
    x = seed
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def words(n, seed):
    vocab = [b"alpha", b"beta", b"gamma", b"delta", b"stream", b"\n"]
    out = bytearray()
    x = seed
    while len(out) < n:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out += vocab[(x >> 16) % len(vocab)] + b" "
    return bytes(out[:n])


def prog_bytes(n):
    """Code-like bytes with x86 E8 calls and ARM BL patterns for BCJ."""
    out = bytearray()
    i = 0
    while len(out) < n:
        out += b"\x55\x48\x89\xe5\xe8" + ((0x100 + i * 0x40) & 0xFFFFFFFF).to_bytes(4, "little")
        out += ((i * 4) & 0xFFFFFF).to_bytes(3, "little") + b"\xeb"
        i += 1
    return bytes(out[:n])


TREE = {
    "a.txt": words(20000, 5),
    "b.bin": lcg_bytes(5000, 9),
    "dir/c.txt": b"nested\n",
    "prog.bin": prog_bytes(8192),
}


def stage(root):
    for rel, data in TREE.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)


def make_zip(method, descriptor=False, zip64=False):
    raw = io.BytesIO()

    class NoSeek(io.RawIOBase):
        def writable(self):
            return True

        def write(self, b):
            return raw.write(b)

    with zipfile.ZipFile(NoSeek() if descriptor else raw, "w") as zf:
        zi = zipfile.ZipInfo("dir/", DT)
        zi.external_attr = (0o40755 << 16) | 0x10
        zf.writestr(zi, b"")
        for rel, data in TREE.items():
            zi = zipfile.ZipInfo(rel, DT)
            zi.compress_type = method
            zi.external_attr = 0o100644 << 16
            if zip64:
                with zf.open(zi, "w", force_zip64=True) as w:
                    w.write(data)
            else:
                zf.writestr(zi, data)
    return raw.getvalue()


def gz(data, name):
    buf = io.BytesIO()
    with gzip.GzipFile(filename=name, fileobj=buf, mode="wb", mtime=1709618828) as g:
        g.write(data)
    return buf.getvalue()


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--stage":
        stage(sys.argv[2])
        return
    keep = os.path.join(OUT, "7z")
    saved = {}
    if os.path.isdir(keep):
        for n in os.listdir(keep):
            with open(os.path.join(keep, n), "rb") as f:
                saved[n] = f.read()
    shutil.rmtree(OUT, ignore_errors=True)
    stage(os.path.join(OUT, "tree"))
    os.makedirs(keep)
    for n, b in saved.items():
        with open(os.path.join(keep, n), "wb") as f:
            f.write(b)

    def w(name, data):
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(data)

    w("zip_bzip2.zip", make_zip(zipfile.ZIP_BZIP2))
    w("zip_lzma.zip", make_zip(zipfile.ZIP_LZMA))
    w("zip_descriptor.zip", make_zip(zipfile.ZIP_DEFLATED, descriptor=True))
    w("zip_stored_descriptor.zip", make_zip(zipfile.ZIP_STORED, descriptor=True))
    w("zip_zip64.zip", make_zip(zipfile.ZIP_DEFLATED, zip64=True))
    a = TREE["a.txt"]
    multi = gz(a[:7000], "a.txt") + gz(a[7000:], "a.txt")
    w("multi.gz", multi)
    w("multi_junk.gz", multi + b"junk")
    lz2 = {"id": lzma.FILTER_LZMA2, "preset": 6}
    prog = TREE["prog.bin"]
    w("filter_delta.xz", lzma.compress(TREE["b.bin"], filters=[{"id": lzma.FILTER_DELTA, "dist": 7}, lz2]))
    for n, fid in (("x86", lzma.FILTER_X86), ("arm", lzma.FILTER_ARM), ("armthumb", lzma.FILTER_ARMTHUMB),
                   ("powerpc", lzma.FILTER_POWERPC), ("sparc", lzma.FILTER_SPARC), ("ia64", lzma.FILTER_IA64)):
        w(f"filter_{n}.xz", lzma.compress(prog, filters=[{"id": fid}, lz2]))
    w("filter_x86_start.xz", lzma.compress(prog, filters=[{"id": lzma.FILTER_X86, "start_offset": 0x1000}, lz2]))
    w("filter_delta_x86.xz", lzma.compress(prog, filters=[
        {"id": lzma.FILTER_DELTA, "dist": 2}, {"id": lzma.FILTER_X86}, lz2]))
    w("empty.tar", bytes(1024))


if __name__ == "__main__":
    main()
