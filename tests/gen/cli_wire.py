#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fixtures for tests/cli_wire.rs (end-to-end `sediment l|t|x|e|a`).

Python stdlib only (zipfile, tarfile, gzip, bz2, lzma) is the oracle. The
output is deterministic.

Usage:
  python3 -I tests/gen/cli_wire.py            # write tests/fixtures/cli_wire
  python3 -I tests/gen/cli_wire.py --stage D  # only write the input tree to D
                                              # (used by tests/gen/cli_wire_7z.sh)

Layout of tests/fixtures/cli_wire:
  tree/            the reference input tree (regular files only)
  tree.dirs        every directory of the tree, one per line (git cannot
                   store empty directories)
  *.zip *.tar ...  archives of that tree, single streams, hostile and corrupt
                   inputs (see main()).
  7z/              7z archives of the tree made by the pinned 7zz oracle
                   (tests/gen/cli_wire_7z.sh), plus Python-built hostile 7z.
"""
import bz2
import gzip
import importlib.util
import io
import lzma
import os
import shutil
import sys
import tarfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "fixtures", "cli_wire")
MTIME = 1709618828  # 2024-03-05 06:07:08 UTC
DT = (2024, 3, 5, 6, 7, 8)


def lcg_bytes(n, seed):
    out = bytearray()
    x = seed
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def prog_bytes(n):
    """x86-like code: E8/E9 rel32 calls between filler, for BCJ."""
    out = bytearray()
    i = 0
    while len(out) < n:
        out += b"\x55\x48\x89\xe5"
        out += b"\xe8" + ((0x100 + i * 0x40) & 0xFFFFFFFF).to_bytes(4, "little")
        out += b"\x90\x90\xc3"
        i += 1
    return bytes(out[:n])


LONG = "docs/deep/nested/" + "long_" * 18 + ".txt"

FILES = {
    "hello.txt": b"Hello, sediment!\n",
    "empty.txt": b"",
    "docs/readme.md": "".join("# line %03d: the quick brown fox jumps over the lazy dog\n" % i
                              for i in range(70)).encode(),
    "docs/deep/nested/leaf.txt": b"leaf\n",
    LONG: b"a long path name\n",
    "docs/caf\u00e9.txt": "caf\u00e9 cr\u00e8me\n".encode(),
    "data/random.bin": lcg_bytes(1024, 7),
    "data/prog.bin": prog_bytes(2048),
    "data/words.txt": b"".join(b"%d alpha beta gamma delta\n" % (i % 50) for i in range(220)),
}
DIRS = ["data", "docs", "docs/deep", "docs/deep/nested", "emptydir"]


def stage(root):
    """Write the input tree (files + dirs, fixed mtimes and modes)."""
    for d in DIRS:
        os.makedirs(os.path.join(root, d), exist_ok=True)
    for name, data in FILES.items():
        p = os.path.join(root, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        os.chmod(p, 0o644)
        os.utime(p, (MTIME, MTIME))
    for d in sorted(DIRS, key=len, reverse=True):
        p = os.path.join(root, d)
        os.chmod(p, 0o755)
        os.utime(p, (MTIME, MTIME))


def members():
    """(name, data or None for dirs) in archive order: dirs first."""
    return [(d, None) for d in sorted(DIRS)] + sorted(FILES.items())


# --- tar ---------------------------------------------------------------------

def tinfo(name, kind=tarfile.REGTYPE, size=0, linkname="", mode=0o644):
    ti = tarfile.TarInfo(name)
    ti.type = kind
    ti.size = size
    ti.mode = mode
    ti.mtime = MTIME
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    ti.linkname = linkname
    return ti


def tar_bytes(entries, fmt=tarfile.USTAR_FORMAT):
    """entries: list of (TarInfo, data or None). Archives are padded to
    512-byte records (not tarfile's default 10 KiB) to keep fixtures small;
    the two zero end blocks are still written."""
    tarfile.RECORDSIZE = 512
    buf = io.BytesIO()
    with tarfile.TarFile(fileobj=buf, mode="w", format=fmt, encoding="utf-8") as t:
        for ti, data in entries:
            t.addfile(ti, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def tree_tar(fmt):
    ents = []
    for name, data in members():
        if data is None:
            ents.append((tinfo(name, tarfile.DIRTYPE, mode=0o755), None))
        else:
            ents.append((tinfo(name, size=len(data)), data))
    return tar_bytes(ents, fmt)


# --- compression -------------------------------------------------------------

def gz(data, fname=None):
    buf = io.BytesIO()
    # filename="" suppresses FNAME; mtime fixed for determinism.
    with gzip.GzipFile(filename=fname or "", mode="wb", fileobj=buf, mtime=MTIME, compresslevel=9) as g:
        g.write(data)
    return buf.getvalue()


def gz_raw(data, fname):
    """gzip member with an arbitrary FNAME (GzipFile would strip the path)."""
    import struct
    import zlib
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = c.compress(data) + c.flush()
    head = b"\x1f\x8b\x08\x08" + struct.pack("<I", MTIME) + b"\x02\x03" + fname + b"\x00"
    return head + body + struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data))


def bz(data):
    return bz2.compress(data, 9)


def xz(data):
    return lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=6)


# --- zip ---------------------------------------------------------------------

def tree_zip(method):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members():
            if data is None:
                zi = zipfile.ZipInfo(name + "/", DT)
                zi.create_system = 3
                zi.external_attr = ((0o040755) << 16) | 0x10
                z.writestr(zi, b"")
            else:
                zi = zipfile.ZipInfo(name, DT)
                zi.create_system = 3
                zi.compress_type = method
                zi.external_attr = (0o100644) << 16
                z.writestr(zi, data)
    return buf.getvalue()


def load_sevenz_builder():
    spec = importlib.util.spec_from_file_location("sevenz_gen", os.path.join(HERE, "sevenz.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--stage":
        stage(sys.argv[2])
        return
    out = os.path.abspath(OUT)
    tree = os.path.join(out, "tree")
    if os.path.isdir(tree):
        shutil.rmtree(tree)
    os.makedirs(tree)
    for name, data in FILES.items():
        p = os.path.join(tree, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
    with open(os.path.join(out, "tree.dirs"), "w") as f:
        f.write("".join(d + "\n" for d in sorted(DIRS)))

    ustar = tree_tar(tarfile.USTAR_FORMAT)
    fx = {
        "tree.zip": tree_zip(zipfile.ZIP_DEFLATED),
        "tree_stored.zip": tree_zip(zipfile.ZIP_STORED),
        "tree_ustar.tar": ustar,
        "tree_gnu.tar": tree_tar(tarfile.GNU_FORMAT),
        "tree_pax.tar": tree_tar(tarfile.PAX_FORMAT),
        "tree.tar.gz": gz(ustar, "tree.tar"),
        "tree.tgz": gz(ustar),
        "tree.tar.bz2": bz(ustar),
        "tree.tbz2": bz(ustar),
        "tree.tar.xz": xz(ustar),
        "tree.txz": xz(ustar),
        # gzip whose FNAME names a tar: opened as tar despite the .gz name.
        "bundle.gz": gz(ustar, "bundle.tar"),
        # Single streams.
        "words.txt.gz": gz(FILES["data/words.txt"], "words.txt"),
        "noname.gz": gz(FILES["hello.txt"]),
        "random.bin.bz2": bz(FILES["data/random.bin"]),
        "readme.md.xz": xz(FILES["docs/readme.md"]),
        "fname_slip.gz": gz_raw(b"gz evil\n", b"../../evil.txt"),
        # Symlinks (extracted only with -snl).
        "links.tar": tar_bytes([
            (tinfo("target.txt", size=4), b"tgt\n"),
            (tinfo("sub", tarfile.DIRTYPE, mode=0o755), None),
            (tinfo("sub/up.txt", tarfile.SYMTYPE, linkname="../target.txt", mode=0o777), None),
            (tinfo("hard.txt", tarfile.LNKTYPE, linkname="target.txt"), None),
        ]),
        # Hostile tars: every one must be refused before anything is written.
        "slip.tar": tar_bytes([(tinfo("ok.txt", size=3), b"ok\n"), (tinfo("../evil.txt", size=5), b"evil\n")]),
        "slip_nested.tar": tar_bytes([(tinfo("a/b/../../../evil.txt", size=5), b"evil\n")]),
        "abs.tar": tar_bytes([(tinfo("/tmp/sediment-cli-wire-evil.txt", size=5), b"evil\n")]),
        "link_escape.tar": tar_bytes([(tinfo("esc", tarfile.SYMTYPE, linkname="../../outside", mode=0o777), None)]),
        "link_through.tar": tar_bytes([
            (tinfo("esc", tarfile.SYMTYPE, linkname=".", mode=0o777), None),
            (tinfo("esc/pwn.txt", size=4), b"pwn\n"),
        ]),
        "hardlink_escape.tar": tar_bytes([(tinfo("h", tarfile.LNKTYPE, linkname="../../etc/passwd"), None)]),
    }
    fifo = tinfo("pipe", tarfile.FIFOTYPE)
    chardev = tinfo("null", tarfile.CHRTYPE)
    chardev.devmajor, chardev.devminor = 1, 3
    fx["specials.tar"] = tar_bytes([(fifo, None), (chardev, None), (tinfo("plain.txt", size=6), b"plain\n")])
    fx["slip.tar.gz"] = gz(fx["slip.tar"], "slip.tar")
    fx["slip.tar.xz"] = xz(fx["slip.tar"])
    fx["slip.tar.bz2"] = bz(fx["slip.tar"])
    # Corrupt inputs.
    bad = bytearray(fx["tree.tar.gz"])
    bad[-8] ^= 0xFF  # gzip CRC32 trailer
    fx["bad_crc.tar.gz"] = bytes(bad)
    fx["truncated.tar.xz"] = fx["tree.tar.xz"][: len(fx["tree.tar.xz"]) // 2]
    bad = bytearray(fx["random.bin.bz2"])
    bad[len(bad) // 2] ^= 0x55
    fx["corrupt.bz2"] = bytes(bad)
    bad = bytearray(fx["links.tar"])
    bad[148] ^= 0x01  # first header checksum field
    fx["bad_checksum.tar"] = bytes(bad)

    # Hostile 7z archives built from the 7z format description (Copy method).
    sz = load_sevenz_builder()
    t = sz.filetime(MTIME)
    os.makedirs(os.path.join(out, "7z"), exist_ok=True)
    fx["7z/slip.7z"] = sz.build([sz.Entry("ok.txt", b"ok\n", attr=sz.file_attr(), mtime=t),
                                 sz.Entry("../evil.txt", b"evil\n", attr=sz.file_attr(), mtime=t)], [2])
    fx["7z/abs.7z"] = sz.build([sz.Entry("/tmp/sediment-cli-wire-evil.txt", b"evil\n", mtime=t)], [1])
    fx["7z/drive.7z"] = sz.build([sz.Entry("C:\\evil.txt", b"evil\n", mtime=t)], [1])
    fx["7z/backslash_slip.7z"] = sz.build([sz.Entry("a\\..\\..\\evil.txt", b"evil\n", mtime=t)], [1])

    for name, data in sorted(fx.items()):
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
        print("%s %d bytes" % (name, len(data)))


if __name__ == "__main__":
    main()
