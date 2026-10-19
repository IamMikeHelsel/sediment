#!/usr/bin/env python3
"""Generate ZIP fixtures for the extraction tests (stdlib zipfile only).

Run from the repo root: python3 -I tests/gen/extract.py
Output: tests/fixtures/extract/*.zip (deterministic).
"""
import os
import sys
import zipfile

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "extract")
DT = (2020, 1, 2, 3, 4, 6)


def info(name, mode=0o644, method=zipfile.ZIP_DEFLATED, kind="file"):
    zi = zipfile.ZipInfo(name, DT)
    zi.create_system = 3
    zi.compress_type = method
    if kind == "dir":
        zi.external_attr = ((0o040000 | mode) << 16) | 0x10
        zi.compress_type = zipfile.ZIP_STORED
    elif kind == "symlink":
        zi.external_attr = (0o120000 | 0o777) << 16
        zi.compress_type = zipfile.ZIP_STORED
    else:
        zi.external_attr = (0o100000 | mode) << 16
    return zi


def write(name, members):
    path = os.path.join(OUT, name)
    with zipfile.ZipFile(path, "w") as z:
        for zi, data in members:
            z.writestr(zi, data)
    return path


def main():
    os.makedirs(OUT, exist_ok=True)
    text = b"Sediment extraction fixture.\n" * 40
    write("basic.zip", [
        (info("docs/", 0o755, kind="dir"), b""),
        (info("docs/readme.txt"), text),
        (info("hello.txt", method=zipfile.ZIP_STORED), b"hello, world\n"),
        (info("bin/run.sh", 0o755), b"#!/bin/sh\necho hi\n"),
        (info("a/b/c/deep.txt"), b"deep\n"),
        (info("empty.txt", method=zipfile.ZIP_STORED), b""),
    ])
    write("slip.zip", [
        (info("good.txt"), b"good\n"),
        (info("../evil.txt"), b"evil\n"),
    ])
    write("slip_nested.zip", [
        (info("a/../../evil.txt"), b"evil\n"),
    ])
    write("absolute.zip", [
        (info("/tmp/sediment-evil.txt"), b"evil\n"),
    ])
    write("backslash.zip", [
        (info("..\\..\\evil.txt"), b"evil\n"),
    ])
    write("drive.zip", [
        (info("C:/evil.txt"), b"evil\n"),
    ])
    write("symlink_ok.zip", [
        (info("target.txt"), b"target\n"),
        (info("link.txt", kind="symlink"), b"target.txt"),
    ])
    write("symlink_escape.zip", [
        (info("link", kind="symlink"), b"../../outside"),
    ])
    write("symlink_absolute.zip", [
        (info("link", kind="symlink"), b"/etc"),
    ])
    write("symlink_through.zip", [
        (info("sub/", kind="dir"), b""),
        (info("link", kind="symlink"), b"sub"),
        (info("link/x.txt"), b"through\n"),
    ])
    write("flat.zip", [
        (info("a/", kind="dir"), b""),
        (info("a/x.txt"), b"x\n"),
        (info("b/y.txt"), b"y\n"),
    ])
    write("flat_dupe.zip", [
        (info("a/same.txt"), b"first\n"),
        (info("b/same.txt"), b"second\n"),
    ])
    # CRC corrupted in both headers: parses, fails integrity check.
    p = write("badcrc.zip", [(info("data.txt", method=zipfile.ZIP_STORED), b"payload\n")])
    raw = bytearray(open(p, "rb").read())
    good = zipfile.crc32(b"payload\n").to_bytes(4, "little")
    bad = (zipfile.crc32(b"payload\n") ^ 1).to_bytes(4, "little")
    raw = raw.replace(good, bad)
    open(p, "wb").write(bytes(raw))
    open(os.path.join(OUT, "notzip.bin"), "wb").write(b"this is not an archive\n")


if __name__ == "__main__":
    sys.exit(main())
