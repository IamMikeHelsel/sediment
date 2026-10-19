#!/usr/bin/env python3
"""Generate tar fixtures for tests/tar_read.rs and tests/archive_detect.rs.

Oracle: Python stdlib tarfile (plus zipfile/gzip/bz2/lzma for detection).
Run from the repo root:  python3 tests/gen/tar.py
Each *.tar gets a *.manifest written by reading the archive back with tarfile:
one line per member, tab separated:
  kind path_hex size mode mtime_secs mtime_nanos uid gid uname_hex gname_hex
  link_hex dev_major dev_minor offset_data
kind: f d l h c b p ; link_hex '-' when absent; empty hex fields are '-'.
"""
import bz2, gzip, io, lzma, os, tarfile, zipfile

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "tar")
DET = os.path.join(OUT, "detect")
os.makedirs(DET, exist_ok=True)
MTIME = 1700000000


def info(name, type=tarfile.REGTYPE, size=0, **kw):
    t = tarfile.TarInfo(name)
    t.type = type
    t.size = size
    t.mtime = kw.pop("mtime", MTIME)
    t.mode = kw.pop("mode", 0o644)
    t.uid = kw.pop("uid", 1000)
    t.gid = kw.pop("gid", 1000)
    t.uname = kw.pop("uname", "alice")
    t.gname = kw.pop("gname", "staff")
    for k, v in kw.items():
        setattr(t, k, v)
    return t


def members(fmt):
    m = []
    m.append((info("d/", tarfile.DIRTYPE, mode=0o755), None))
    m.append((info("d/hello.txt", size=6), b"hello\n"))
    m.append((info("empty"), b""))
    big = bytes((i * 7 + 3) % 251 for i in range(1000))
    m.append((info("d/block-cross.bin", size=len(big), mode=0o600), big))
    exact = b"x" * 512
    m.append((info("exact512", size=512), exact))
    m.append((info("link", tarfile.SYMTYPE, linkname="d/hello.txt", mode=0o777), None))
    m.append((info("hard", tarfile.LNKTYPE, linkname="d/hello.txt"), None))
    u = "ünï/日本語.txt"
    m.append((info(u, size=3), b"uni"))
    m.append((info("fifo", tarfile.FIFOTYPE), None))
    m.append((info("chr", tarfile.CHRTYPE, devmajor=4, devminor=64), None))
    m.append((info("blk", tarfile.BLKTYPE, devmajor=8, devminor=1), None))
    # 150-char path splittable into ustar prefix/name.
    split = "p" * 90 + "/" + "q" * 59
    m.append((info(split, size=2), b"ok"))
    if fmt != tarfile.USTAR_FORMAT:
        long = "L" * 60 + "/" + "N" * 120 + "/file.txt"
        m.append((info(long, size=4), b"long"))
        m.append((info("longlink", tarfile.SYMTYPE, linkname="T" * 150), None))
        m.append((info("longhard", tarfile.LNKTYPE, linkname=long), None))
    if fmt == tarfile.GNU_FORMAT:
        m.append((info("negmtime", mtime=-1000), b""))
        m.append((info("bigid", uid=8 ** 7 + 5, gid=8 ** 8), b""))
    if fmt == tarfile.PAX_FORMAT:
        m.append((info("frac", mtime=MTIME + 0.5, size=1), b"f"))
        m.append((info("negfrac", mtime=-1.25), b""))
        m.append((info("bigid", uid=8 ** 7 + 5, gid=8 ** 8, uname="u" * 40, gname="ünïgrp"), b""))
    return m


def kind(t):
    if t.isreg(): return "f"
    if t.isdir(): return "d"
    if t.issym(): return "l"
    if t.islnk(): return "h"
    if t.ischr(): return "c"
    if t.isblk(): return "b"
    if t.isfifo(): return "p"
    raise ValueError(t.type)


def hx(b):
    return b.hex() if b else "-"


def mtime_parts(t):
    raw = t.pax_headers.get("mtime")
    if raw is None:
        return int(t.mtime), 0
    neg = raw.startswith("-")
    body = raw[1:] if neg else raw
    i, _, f = body.partition(".")
    secs, nanos = int(i), int((f + "0" * 9)[:9])
    if neg:
        secs = -secs
        if nanos:
            secs -= 1
            nanos = 1_000_000_000 - nanos
    return secs, nanos


def manifest(path):
    lines = []
    with tarfile.open(path, encoding="utf-8") as tf:
        for t in tf:
            enc = lambda s: s.encode("utf-8", "surrogateescape")
            secs, nanos = mtime_parts(t)
            link = hx(enc(t.linkname)) if (t.issym() or t.islnk()) else "-"
            lines.append("\t".join(str(x) for x in [
                kind(t), hx(enc(t.name)), t.size if t.isreg() else 0, t.mode, secs, nanos,
                t.uid, t.gid, hx(enc(t.uname)), hx(enc(t.gname)), link,
                t.devmajor if (t.ischr() or t.isblk()) else 0,
                t.devminor if (t.ischr() or t.isblk()) else 0, t.offset_data]))
    with open(path[:-4] + ".manifest", "w") as f:
        f.write("\n".join(lines) + "\n")


def write_tar(name, fmt, mem, record=512, **kw):
    path = os.path.join(OUT, name)
    old = tarfile.RECORDSIZE
    tarfile.RECORDSIZE = record
    try:
        with tarfile.open(path, "w", format=fmt, encoding="utf-8", **kw) as tf:
            for t, data in mem:
                tf.addfile(t, io.BytesIO(data) if data is not None else None)
    finally:
        tarfile.RECORDSIZE = old
    manifest(path)
    return path


def fix_checksum(block):
    block = bytearray(block)
    block[148:156] = b" " * 8
    block[148:156] = b"%06o\0 " % sum(block)
    return bytes(block)


def raw(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)


ustar = write_tar("ustar.tar", tarfile.USTAR_FORMAT, members(tarfile.USTAR_FORMAT))
write_tar("gnu.tar", tarfile.GNU_FORMAT, members(tarfile.GNU_FORMAT))
write_tar("pax.tar", tarfile.PAX_FORMAT, members(tarfile.PAX_FORMAT))
# Global pax header ('g') applied to all following members.
write_tar("pax_global.tar", tarfile.PAX_FORMAT,
          [(info("a", size=1), b"a"), (info("b"), b"")],
          pax_headers={"gname": "globalgrp", "comment": "ignored"})
# Default 10240-byte record padding.
write_tar("ustar_record.tar", tarfile.USTAR_FORMAT, [(info("one", size=3), b"one")], record=tarfile.RECORDSIZE)

# Headers only for >= 8 GiB members; data is not materialized.
HUGE = 8 * 1024 ** 3 + 12345
raw("gnu_huge.hdr", info("huge.bin", size=HUGE).tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape"))
raw("pax_huge.hdr", info("huge.bin", size=HUGE).tobuf(tarfile.PAX_FORMAT, "utf-8", "surrogateescape"))
with open(os.path.join(OUT, "huge.txt"), "w") as f:
    f.write("%d\n" % HUGE)

# Malformed cases.
one = info("m.txt", size=3).tobuf(tarfile.USTAR_FORMAT, "utf-8", "surrogateescape")
body = b"abc" + b"\0" * 509 + b"\0" * 1024
bad = bytearray(one); bad[0] ^= 0x01
raw("bad_checksum.tar", bytes(bad) + body)
neg = bytearray(one); neg[124:136] = tarfile.itn(-5, 12, tarfile.GNU_FORMAT)
raw("negative_size.tar", fix_checksum(neg) + body)
ovf = bytearray(one); ovf[124:136] = b"\x80" + b"\xff" * 11
raw("overflow_size.tar", fix_checksum(ovf) + body)
octbad = bytearray(one); octbad[124:136] = b"0000000009x\0"
raw("bad_octal_size.tar", fix_checksum(octbad) + body)
pax_rec = b"99 path=x\n"
ph = info("././@PaxHeader", tarfile.XHDTYPE, size=len(pax_rec)).tobuf(tarfile.USTAR_FORMAT, "utf-8", "surrogateescape")
raw("bad_pax.tar", ph + pax_rec + b"\0" * (512 - len(pax_rec)) + one + body)
sparse = bytearray(one); sparse[156:157] = b"S"
raw("sparse.tar", fix_checksum(sparse) + body)

# Format detection samples.
payload = b"hello sediment\n" * 4
with open(os.path.join(DET, "sample.gz"), "wb") as f:
    f.write(gzip.compress(payload, mtime=0))
with open(os.path.join(DET, "sample.bz2"), "wb") as f:
    f.write(bz2.compress(payload))
with open(os.path.join(DET, "sample.xz"), "wb") as f:
    f.write(lzma.compress(payload, format=lzma.FORMAT_XZ))
with open(os.path.join(DET, "sample.lzma"), "wb") as f:
    f.write(lzma.compress(payload, format=lzma.FORMAT_ALONE))
zb = io.BytesIO()
with zipfile.ZipFile(zb, "w") as z:
    z.writestr(zipfile.ZipInfo("a.txt", (2020, 1, 1, 0, 0, 0)), payload)
with open(os.path.join(DET, "sample.zip"), "wb") as f:
    f.write(zb.getvalue())
zb = io.BytesIO()
with zipfile.ZipFile(zb, "w"):
    pass
with open(os.path.join(DET, "empty.zip"), "wb") as f:
    f.write(zb.getvalue())
# v7-style tar: ustar header with the magic/version wiped.
v7 = bytearray(info("v7.txt", size=3).tobuf(tarfile.USTAR_FORMAT, "utf-8", "surrogateescape"))
v7[257:265] = b"\0" * 8
v7[265:345] = b"\0" * 80
raw("v7.tar", fix_checksum(v7) + body)
with open(os.path.join(DET, "v7.tar"), "wb") as f:
    f.write(fix_checksum(v7) + body)
