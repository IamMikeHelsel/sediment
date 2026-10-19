#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fixtures for tests/streams_volumes.rs (-si/-so and split volumes).

Python stdlib only (gzip, bz2, lzma, tarfile, zipfile) is the oracle; the
output is deterministic.

Usage: python3 -I tests/gen/streams_volumes.py   # writes tests/fixtures/streams_volumes

Files:
  payload.bin                 16000 deterministic pseudo-random + text bytes
  hello.txt                   short text member
  payload.bin.gz/.bz2/.xz     single streams of payload.bin (gz has FNAME)
  pair.tar.gz.whole           tar (ustar) of hello.txt then payload.bin
  pair.tar.gz.001..           pair.tar.gz split into 2048-byte volumes
  pair.zip.001..              zip (deflate) of the same members, 5000-byte volumes
  gap.tar.gz.001, .003        a split set whose second volume is missing
"""
import bz2
import gzip
import io
import lzma
import os
import shutil
import sys
import tarfile
import zipfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "fixtures", "streams_volumes")
MTIME = 1709618828
DT = (2024, 3, 5, 6, 7, 8)


def payload():
    x = 0x12345678
    out = bytearray()
    for _ in range(10000):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    line = b"streams and volumes: the quick brown fox jumps over the lazy dog\n"
    while len(out) < 16000:
        out += line
    return bytes(out[:16000])


def split(data, size, base):
    n = 0
    for i in range(0, max(len(data), 1), size):
        n += 1
        with open(f"{base}.{n:03d}", "wb") as f:
            f.write(data[i:i + size])
    return n


def main():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    p = payload()
    hello = b"hello, volumes\n"
    w = lambda name, b: open(os.path.join(OUT, name), "wb").write(b)
    w("payload.bin", p)
    w("hello.txt", hello)

    gz = io.BytesIO()
    with gzip.GzipFile(filename="payload.bin", mode="wb", fileobj=gz, mtime=MTIME) as g:
        g.write(p)
    w("payload.bin.gz", gz.getvalue())
    w("payload.bin.bz2", bz2.compress(p, 9))
    w("payload.bin.xz", lzma.compress(p, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64))

    tb = io.BytesIO()
    with tarfile.open(fileobj=tb, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, data in (("hello.txt", hello), ("payload.bin", p)):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = MTIME
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    tgz = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=tgz, mtime=MTIME) as g:
        g.write(tb.getvalue())
    tgz = tgz.getvalue()
    w("pair.tar.gz.whole", tgz)
    split(tgz, 2048, os.path.join(OUT, "pair.tar.gz"))
    n = split(tgz, 2048, os.path.join(OUT, "gap.tar.gz"))
    assert n >= 3
    for i in range(4, n + 1):
        os.remove(os.path.join(OUT, f"gap.tar.gz.{i:03d}"))
    os.remove(os.path.join(OUT, "gap.tar.gz.002"))

    zb = io.BytesIO()
    with zipfile.ZipFile(zb, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in (("hello.txt", hello), ("payload.bin", p)):
            z.writestr(zipfile.ZipInfo(name, DT), data, compress_type=zipfile.ZIP_DEFLATED)
    split(zb.getvalue(), 5000, os.path.join(OUT, "pair.zip"))


if __name__ == "__main__":
    main()
