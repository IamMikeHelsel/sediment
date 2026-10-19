#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fixtures for tests/unix_formats.rs: cpio, ar, deb, rpm and xar.

Python has no cpio/ar/rpm/xar module, so this script writes those
containers byte by byte from the public specs (cpio(5), ar(5), deb(5),
the rpm.org "RPM Package format" / LSB package file format, and the xar
format description). The stdlib supplies everything else the oracle needs:
tarfile (deb tarballs), gzip/zlib/bz2/lzma (compression) and hashlib
(digests).

For every archive X a manifest X.manifest lists the members a reader must
report, one per line, tab separated:

    kind  size  mode  mtime  sha256(content)  hex(path)  hex(link target)

kind is F (file), D (dir), L (symlink), H (hard link); mode is octal
permission bits or '-'; '-' also marks an absent target. Hostile and
corrupt inputs have no manifest; tests/unix_formats.rs names the error.

Usage: python3 -I tests/gen/unix.py   (writes tests/fixtures/unix)
"""
import bz2
import gzip
import hashlib
import io
import lzma
import os
import struct
import sys
import tarfile
import zlib

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "fixtures", "unix")
MTIME = 1709618828  # 2024-03-05T06:07:08Z


def blob(n, seed):
    out = bytearray()
    x = seed
    while len(out) < n:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


README = b"Sediment unix fixture.\nSecond line.\n"
TOOL = blob(3001, 7)
TEXT = (b"lorem ipsum dolor sit amet " * 200)[:5003]
UTF8_NAME = "naïve.txt".encode()

S_IFREG, S_IFDIR, S_IFLNK, S_IFCHR = 0o100000, 0o040000, 0o120000, 0o020000


def write(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)


def manifest(name, rows):
    lines = []
    for kind, size, mode, mtime, content, path, target in rows:
        lines.append("\t".join([
            kind,
            str(size),
            "-" if mode is None else "%o" % mode,
            "-" if mtime is None else str(mtime),
            hashlib.sha256(content).hexdigest(),
            path.hex(),
            "-" if target is None else target.hex(),
        ]))
    write(name + ".manifest", ("\n".join(lines) + "\n").encode())


# ---------------------------------------------------------------------------
# cpio
# ---------------------------------------------------------------------------

# (name, mode, ino, nlink, data, rdev) in archive order. Inode 5 is a
# two-link hard-link group.
CPIO_MEMBERS = [
    (b".", S_IFDIR | 0o755, 1, 3, b"", 0),
    (b"docs", S_IFDIR | 0o750, 2, 2, b"", 0),
    (b"docs/readme.txt", S_IFREG | 0o644, 3, 1, README, 0),
    (b"bin/tool", S_IFREG | 0o755, 4, 1, TOOL, 0),
    (b"docs/a-link", S_IFREG | 0o600, 5, 2, TEXT, 0),
    (b"docs/b-link", S_IFREG | 0o600, 5, 2, TEXT, 0),
    (b"empty", S_IFREG | 0o644, 6, 1, b"", 0),
    (b"link", S_IFLNK | 0o777, 7, 1, b"docs/readme.txt", 0),
    (b"dev/null", S_IFCHR | 0o666, 8, 1, b"", 0x0103),
    (UTF8_NAME, S_IFREG | 0o644, 9, 1, b"x", 0),
]


def pad(buf, a):
    while len(buf) % a:
        buf.append(0)


def cpio_newc(members, crc=False):
    out = bytearray()
    groups = {}
    for m in members:
        if m[3] > 1 and (m[1] & 0o170000) == S_IFREG:
            groups.setdefault(m[2], []).append(m[0])

    def one(name, mode, ino, nlink, data, rdev):
        # newc: the data of a hard-link group is stored with the last link.
        if ino in groups and groups[ino][-1] != name:
            data = b""
        out.extend(b"070702" if crc else b"070701")
        check = sum(data) & 0xFFFFFFFF if crc else 0
        fields = [ino, mode, 1000, 100, nlink, MTIME, len(data), 8, 1,
                  rdev >> 8, rdev & 0xFF, len(name) + 1, check]
        out.extend(b"".join(b"%08X" % f for f in fields))
        out.extend(name + b"\0")
        pad(out, 4)
        out.extend(data)
        pad(out, 4)

    for m in members:
        one(*m)
    one(b"TRAILER!!!", 0, 0, 1, b"", 0)
    while len(out) % 512:
        out.append(0)
    return bytes(out)


def cpio_odc(members):
    out = bytearray()

    def one(name, mode, ino, nlink, data, rdev):
        out.extend(b"070707")
        out.extend(b"%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o" % (
            0o1234, ino, mode, 1000, 100, nlink, rdev, MTIME, len(name) + 1, len(data)))
        out.extend(name + b"\0")
        out.extend(data)

    for m in members:
        one(*m)
    one(b"TRAILER!!!", 0, 0, 1, b"", 0)
    return bytes(out)


def cpio_bin(members, big):
    out = bytearray()
    fmt = ">13H" if big else "<13H"

    def one(name, mode, ino, nlink, data, rdev):
        out.extend(struct.pack(fmt, 0o070707, 0o1234, ino, mode & 0xFFFF, 1000, 100, nlink, rdev,
                               MTIME >> 16, MTIME & 0xFFFF, len(name) + 1, len(data) >> 16, len(data) & 0xFFFF))
        out.extend(name + b"\0")
        pad(out, 2)
        out.extend(data)
        pad(out, 2)

    for m in members:
        one(*m)
    one(b"TRAILER!!!", 0, 0, 1, b"", 0)
    return bytes(out)


def cpio_expect(members, shared):
    """Rows a reader reports: root dropped, devices skipped; with `shared`
    (newc) the first link of a group is the file and later ones hard links."""
    rows = []
    first = {}
    for name, mode, ino, nlink, data, rdev in members:
        t = mode & 0o170000
        perm = mode & 0o7777
        if t == S_IFDIR:
            if name in (b".", b"./"):
                continue
            rows.append(("D", 0, perm, MTIME, b"", name, None))
        elif t == S_IFLNK:
            rows.append(("L", 0, perm, MTIME, b"", name, data))
        elif t == S_IFREG:
            if shared and nlink > 1:
                if ino in first:
                    rows.append(("H", len(data), perm, MTIME, b"", name, first[ino]))
                    continue
                first[ino] = name
            rows.append(("F", len(data), perm, MTIME, data, name, None))
    return rows


def gen_cpio():
    m = CPIO_MEMBERS
    for name, data, shared in [
        ("newc.cpio", cpio_newc(m), True),
        ("crc.cpio", cpio_newc(m, crc=True), True),
        ("odc.cpio", cpio_odc(m), False),
        ("bin-le.cpio", cpio_bin(m, big=False), False),
        ("bin-be.cpio", cpio_bin(m, big=True), False),
    ]:
        write(name, data)
        manifest(name, cpio_expect(m, shared))
    write("newc.cpio.gz", gzip.compress(cpio_newc(m), mtime=0))
    manifest("newc.cpio.gz", cpio_expect(m, True))
    # Hostile / corrupt.
    write("evil.cpio", cpio_newc([(b"../evil.txt", S_IFREG | 0o644, 1, 1, b"pwned", 0)]))
    crc = bytearray(cpio_newc(m, crc=True))
    i = crc.index(README)
    crc[i] ^= 0x20
    write("crc-bad.cpio", bytes(crc))
    write("no-trailer.cpio", cpio_newc(m)[: cpio_newc(m).index(b"TRAILER!!!") - 110])
    write("stripped.cpio", b"07070X" + b"0" * 200)


# ---------------------------------------------------------------------------
# ar / deb
# ---------------------------------------------------------------------------

def ar_header(name, size, mode=0o644, mtime=MTIME, uid=0, gid=0):
    h = b"%-16s%-12d%-6d%-6d%-8o%-10d`\n" % (name, mtime, uid, gid, mode, size)
    assert len(h) == 60
    return h


def ar_member(name, data, **kw):
    out = ar_header(name, len(data), **kw) + data
    if len(data) % 2:
        out += b"\n"
    return out


def gen_ar():
    long1 = b"a_rather_long_object_name.o"
    long2 = b"another_very_long_member_name.txt"
    table = long1 + b"/\n" + long2 + b"/\n"
    gnu = b"!<arch>\n"
    gnu += ar_member(b"/", b"\0\0\0\0")  # empty symbol table
    gnu += ar_member(b"//", table)
    gnu += ar_member(b"short.o/", TOOL[:101], mode=0o755)
    gnu += ar_member(b"/0", README)
    gnu += ar_member(b"/" + str(len(long1) + 2).encode(), TEXT[:77])
    gnu += ar_member(b"even.txt/", b"ab")
    write("gnu.a", gnu)
    manifest("gnu.a", [
        ("F", 101, 0o755, MTIME, TOOL[:101], b"short.o", None),
        ("F", len(README), 0o644, MTIME, README, long1, None),
        ("F", 77, 0o644, MTIME, TEXT[:77], long2, None),
        ("F", 2, 0o644, MTIME, b"ab", b"even.txt", None),
    ])
    bsd_long = b"bsd_style_long_name_here.o"
    padded = bsd_long + b"\0\0"  # BSD pads the name with NULs
    bsd = b"!<arch>\n"
    bsd += ar_member(b"__.SYMDEF", b"\0" * 8)
    bsd += ar_member(b"#1/" + str(len(padded)).encode(), padded + README)
    bsd += ar_member(b"plain.o", TOOL[:33], mode=0o600)
    write("bsd.a", bsd)
    manifest("bsd.a", [
        ("F", 8, 0o644, MTIME, b"\0" * 8, b"__.SYMDEF", None),
        ("F", len(README), 0o644, MTIME, README, bsd_long, None),
        ("F", 33, 0o600, MTIME, TOOL[:33], b"plain.o", None),
    ])
    write("ar-badname.a", b"!<arch>\n" + ar_member(b"/5", b"xx"))
    write("ar-trunc.a", gnu[:-30])


def tar_bytes(items, compression=""):
    """items: (name, type, data_or_target, mode)."""
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, typ, payload, mode in items:
            ti = tarfile.TarInfo(name)
            ti.mtime = MTIME
            ti.mode = mode
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            if typ == "d":
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            elif typ == "l":
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload
                tf.addfile(ti)
            elif typ == "h":
                ti.type = tarfile.LNKTYPE
                ti.linkname = payload
                tf.addfile(ti)
            else:
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
    raw = bio.getvalue()
    if compression == "gz":
        return gzip.compress(raw, mtime=0)
    if compression == "xz":
        return lzma.compress(raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64)
    if compression == "bz2":
        return bz2.compress(raw)
    if compression == "lzma":
        return lzma.compress(raw, format=lzma.FORMAT_ALONE)
    return raw


CONTROL = b"Package: hello\nVersion: 1.0-1\nArchitecture: all\nMaintainer: Nobody <n@example.org>\nDescription: test\n"
MD5SUMS = hashlib.md5(TOOL).hexdigest().encode() + b"  usr/bin/hello\n"
DEB_CONTROL = [
    ("./", "d", b"", 0o755),
    ("./control", "f", CONTROL, 0o644),
    ("./md5sums", "f", MD5SUMS, 0o644),
]
DEB_DATA = [
    ("./", "d", b"", 0o755),
    ("./usr/", "d", b"", 0o755),
    ("./usr/bin/", "d", b"", 0o755),
    ("./usr/bin/hello", "f", TOOL, 0o755),
    ("./usr/bin/hi", "l", "hello", 0o777),
    ("./usr/bin/hello2", "h", "./usr/bin/hello", 0o755),
    ("./usr/share/doc/hello/", "d", b"", 0o755),
    ("./usr/share/doc/hello/copyright", "f", README, 0o644),
]


def deb_expect():
    rows = []
    for prefix, items in [(b"", DEB_DATA), (b"DEBIAN/", DEB_CONTROL)]:
        for name, typ, payload, mode in items:
            if name == "./":
                continue
            raw = name.encode()
            if typ == "d":
                raw = raw.rstrip(b"/")  # tar readers drop a directory's trailing slash
            path = prefix + raw[2:] if prefix else raw
            if typ == "d":
                rows.append(("D", 0, mode, MTIME, b"", path, None))
            elif typ == "l":
                rows.append(("L", 0, mode, MTIME, b"", path, payload.encode()))
            elif typ == "h":
                rows.append(("H", len(TOOL), mode, MTIME, b"", path, payload.encode()))
            else:
                rows.append(("F", len(payload), mode, MTIME, payload, path, None))
    return rows


def deb(control_comp, data_comp, data_override=None):
    out = b"!<arch>\n" + ar_member(b"debian-binary", b"2.0\n")
    cname = b"control.tar" + (b"." + control_comp.encode() if control_comp else b"")
    dname = b"data.tar" + (b"." + data_comp.encode() if data_comp else b"")
    out += ar_member(cname, tar_bytes(DEB_CONTROL, control_comp))
    data = data_override if data_override is not None else tar_bytes(DEB_DATA, data_comp)
    out += ar_member(dname, data)
    return out


def gen_deb():
    for name, cc, dc in [("hello-xz.deb", "gz", "xz"), ("hello-bz2.deb", "xz", "bz2"),
                         ("hello-plain.deb", "", ""), ("hello-lzma.deb", "gz", "lzma")]:
        write(name, deb(cc, dc))
        manifest(name, deb_expect())
    write("hello-zst.deb", deb("gz", "zst", data_override=b"\x28\xb5\x2f\xfd" + b"\0" * 32))


# ---------------------------------------------------------------------------
# rpm
# ---------------------------------------------------------------------------

T_INT32, T_STRING, T_BIN, T_STRING_ARRAY = 4, 6, 7, 8


def rpm_header(tags):
    """tags: list of (tag, type, value). Returns header structure bytes."""
    index = b""
    store = bytearray()
    for tag, typ, value in tags:
        if typ == T_INT32:
            pad(store, 4)
            off, count = len(store), len(value)
            store.extend(b"".join(struct.pack(">I", v) for v in value))
        elif typ == T_STRING:
            off, count = len(store), 1
            store.extend(value + b"\0")
        elif typ == T_STRING_ARRAY:
            off, count = len(store), len(value)
            store.extend(b"".join(v + b"\0" for v in value))
        elif typ == T_BIN:
            off, count = len(store), len(value)
            store.extend(value)
        index += struct.pack(">IIII", tag, typ, off, count)
    n = len(tags)
    return b"\x8e\xad\xe8\x01\0\0\0\0" + struct.pack(">II", n, len(store)) + index + bytes(store)


RPM_FILES = [
    (b"./usr", S_IFDIR | 0o755, 1, 2, b"", 0),
    (b"./usr/bin/hello", S_IFREG | 0o755, 2, 1, TOOL, 0),
    (b"./usr/bin/hi", S_IFLNK | 0o777, 3, 1, b"hello", 0),
    (b"./usr/share/doc/hello/README", S_IFREG | 0o644, 4, 1, README, 0),
    (b"./usr/share/hello/data.txt", S_IFREG | 0o644, 5, 1, TEXT, 0),
]


def rpm(compressor, payload_override=None, corrupt_header=False, algo=8):
    cpio = cpio_newc(RPM_FILES)
    if payload_override is not None:
        payload = payload_override
    elif compressor == "gzip":
        payload = gzip.compress(cpio, mtime=0)
    elif compressor == "xz":
        payload = lzma.compress(cpio, format=lzma.FORMAT_XZ)
    elif compressor == "bzip2":
        payload = bz2.compress(cpio)
    elif compressor == "lzma":
        payload = lzma.compress(cpio, format=lzma.FORMAT_ALONE)
    else:
        payload = cpio
    hfun = {1: hashlib.md5, 2: hashlib.sha1, 8: hashlib.sha256, 10: hashlib.sha512}[algo]
    main = rpm_header([
        (1000, T_STRING, b"hello"),
        (1001, T_STRING, b"1.0"),
        (1002, T_STRING, b"1"),
        (1022, T_STRING, b"noarch"),
        (1116, T_INT32, [0, 0, 1, 2]),
        (1117, T_STRING_ARRAY, [b"hello", b"hi", b"README", b"data.txt"]),
        (1118, T_STRING_ARRAY, [b"/usr/bin/", b"/usr/share/doc/hello/", b"/usr/share/hello/"]),
        (1124, T_STRING, b"cpio"),
        (1125, T_STRING, compressor.encode()),
        (5092, T_STRING_ARRAY, [hfun(payload).hexdigest().encode()]),
        (5093, T_INT32, [algo]),
    ])
    sig = rpm_header([
        (269, T_STRING, hashlib.sha1(main).hexdigest().encode()),
        (273, T_STRING, hashlib.sha256(main).hexdigest().encode()),
        (1004, T_BIN, hashlib.md5(main + payload).digest()),
    ])
    lead = b"\xed\xab\xee\xdb" + bytes([3, 0]) + struct.pack(">HH", 0, 0)
    lead += b"hello-1.0-1".ljust(66, b"\0") + struct.pack(">HH", 1, 5) + b"\0" * 16
    assert len(lead) == 96
    sig_padded = sig + b"\0" * ((8 - len(sig) % 8) % 8)
    if corrupt_header:
        main = main.replace(b"noarch", b"noarcH")
    return lead + sig_padded + main + payload


def rpm_expect():
    rows = cpio_expect(RPM_FILES, True)
    return rows


def gen_rpm():
    for comp, algo in [("gzip", 8), ("xz", 2), ("bzip2", 10), ("lzma", 1)]:
        name = "hello-%s.rpm" % comp
        write(name, rpm(comp, algo=algo))
        manifest(name, rpm_expect())
    write("hello-zstd.rpm", rpm("zstd", payload_override=b"\x28\xb5\x2f\xfd" + b"\0" * 40))
    write("hello-badsum.rpm", rpm("gzip", corrupt_header=True))
    good = bytearray(rpm("gzip"))
    good[-12] ^= 1  # inside the gzip payload: payload digest / md5 mismatch
    write("hello-badpayload.rpm", bytes(good))
    write("rpm-trunc.rpm", rpm("gzip")[:200])


# ---------------------------------------------------------------------------
# xar
# ---------------------------------------------------------------------------

def xml_esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Xar:
    def __init__(self, toc_alg="sha1"):
        self.heap = bytearray()
        self.toc_alg = toc_alg
        self.hsize = {"sha1": 20, "md5": 16, "sha256": 32}[toc_alg]
        self.heap.extend(b"\0" * self.hsize)  # TOC digest slot
        self.next_id = 1

    def data(self, content, encoding):
        if encoding == "application/octet-stream":
            stored = content
        elif encoding == "application/x-gzip":
            stored = zlib.compress(content, 9)
        elif encoding == "application/x-bzip2":
            stored = bz2.compress(content)
        elif encoding == "application/x-xz":
            stored = lzma.compress(content, format=lzma.FORMAT_XZ)
        elif encoding == "application/x-lzma":
            stored = lzma.compress(content, format=lzma.FORMAT_ALONE)
        off = len(self.heap)
        self.heap.extend(stored)
        return (
            "<data><length>%d</length><offset>%d</offset><size>%d</size>"
            '<encoding style="%s"/>'
            '<archived-checksum style="sha1">%s</archived-checksum>'
            '<extracted-checksum style="md5">%s</extracted-checksum></data>'
            % (len(stored), off, len(content), encoding, hashlib.sha1(stored).hexdigest(), hashlib.md5(content).hexdigest())
        )

    def file(self, name, ftype, mode, inner="", children="", fid=None, name_b64=False, type_attr=""):
        fid = fid or self.next_id
        self.next_id = max(self.next_id, fid) + 1
        if name_b64:
            import base64
            nm = '<name enctype="base64">%s</name>' % base64.b64encode(name.encode()).decode()
        else:
            nm = "<name>%s</name>" % xml_esc(name)
        return ('<file id="%d">%s<type%s>%s</type><mode>%04o</mode><uid>0</uid><gid>0</gid>'
                "<mtime>2024-03-05T06:07:08Z</mtime>%s%s</file>" % (fid, nm, type_attr, ftype, mode, inner, children))

    def build(self, files_xml):
        alg_id = {"sha1": 1, "md5": 2, "sha256": 3}[self.toc_alg]
        toc = ('<?xml version="1.0" encoding="UTF-8"?>\n<xar><toc>'
               '<creation-time>2024-03-05T06:07:08</creation-time>'
               '<checksum style="%s"><offset>0</offset><size>%d</size></checksum>%s</toc></xar>\n'
               % (self.toc_alg, self.hsize, files_xml)).encode()
        ctoc = zlib.compress(toc, 9)
        self.heap[: self.hsize] = hashlib.new(self.toc_alg, ctoc).digest()
        if alg_id == 3:
            name = b"sha256\0"
            hsize = 28 + len(name) + (-len(name)) % 4
            extra = name + b"\0" * (hsize - 28 - len(name))
        else:
            hsize, extra = 28, b""
        hdr = b"xar!" + struct.pack(">HHQQI", hsize, 1, len(ctoc), len(toc), alg_id) + extra
        return hdr + ctoc + bytes(self.heap)


def gen_xar():
    for toc_alg in ["sha1", "sha256"]:
        x = Xar(toc_alg)
        f_readme = x.file("readme.txt", "file", 0o644, x.data(README, "application/octet-stream"), fid=3)
        f_tool = x.file("tool", "file", 0o755, x.data(TOOL, "application/x-gzip"), fid=4)
        f_text = x.file("text.txt", "file", 0o644, x.data(TEXT, "application/x-bzip2"), fid=5)
        f_xz = x.file("xz.bin", "file", 0o600, x.data(TOOL[:999], "application/x-xz"), fid=6)
        f_lz = x.file("lzma.bin", "file", 0o600, x.data(TEXT[:777], "application/x-lzma"), fid=7)
        f_orig = x.file("orig", "hardlink", 0o644, x.data(b"shared\n", "application/octet-stream"), fid=8,
                        type_attr=' link="original"')
        f_link = x.file("twin", "hardlink", 0o644, fid=9, type_attr=' link="8"')
        f_sym = x.file("sym", "symlink", 0o777, '<link type="file">docs/readme.txt</link>', fid=10)
        f_utf = x.file("naïve & <odd>.txt", "file", 0o644, x.data(b"x", "application/octet-stream"),
                       fid=11, name_b64=True)
        f_empty = x.file("empty", "file", 0o644, fid=12)
        f_fifo = x.file("fifo", "fifo", 0o644, fid=13)
        sub = x.file("sub", "directory", 0o700, children=f_xz + f_lz, fid=2)
        docs = x.file("docs", "directory", 0o755, children=f_readme + f_tool + f_text + sub, fid=1)
        data = x.build(docs + f_orig + f_link + f_sym + f_utf + f_empty + f_fifo)
        name = "sample-%s.xar" % toc_alg
        write(name, data)
        M = MTIME
        manifest(name, [
            ("D", 0, 0o755, M, b"", b"docs", None),
            ("F", len(README), 0o644, M, README, b"docs/readme.txt", None),
            ("F", len(TOOL), 0o755, M, TOOL, b"docs/tool", None),
            ("F", len(TEXT), 0o644, M, TEXT, b"docs/text.txt", None),
            ("D", 0, 0o700, M, b"", b"docs/sub", None),
            ("F", 999, 0o600, M, TOOL[:999], b"docs/sub/xz.bin", None),
            ("F", 777, 0o600, M, TEXT[:777], b"docs/sub/lzma.bin", None),
            ("F", 7, 0o644, M, b"shared\n", b"orig", None),
            ("H", 7, 0o644, M, b"", b"twin", b"orig"),
            ("L", 0, 0o777, M, b"", b"sym", b"docs/readme.txt"),
            ("F", 1, 0o644, M, b"x", "naïve & <odd>.txt".encode(), None),
            ("F", 0, 0o644, M, b"", b"empty", None),
        ])
    # Corrupt: TOC digest slot flipped; member data flipped.
    good = bytearray(open(os.path.join(OUT, "sample-sha1.xar"), "rb").read())
    hs = struct.unpack(">H", good[4:6])[0]
    tc = struct.unpack(">Q", good[8:16])[0]
    bad = bytearray(good)
    bad[hs + tc] ^= 1
    write("bad-toc.xar", bytes(bad))
    bad = bytearray(good)
    i = bad.index(README)
    bad[i] ^= 1
    write("bad-data.xar", bytes(bad))
    # Hostile: member escaping the destination.
    x = Xar()
    write("evil.xar", x.build(x.file("..", "directory", 0o755, children=x.file("evil.txt", "file", 0o644,
                                                                                   x.data(b"pwned", "application/octet-stream")))))


def main():
    os.makedirs(OUT, exist_ok=True)
    for f in os.listdir(OUT):
        os.remove(os.path.join(OUT, f))
    gen_cpio()
    gen_ar()
    gen_deb()
    gen_rpm()
    gen_xar()


if __name__ == "__main__":
    main()
