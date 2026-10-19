#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Hand-built disc image fixtures for tests/disc.rs (Python stdlib only).

Images are laid out directly from the public specifications:
  - ECMA-119 4th ed. (ISO-9660 volume descriptors, directory records,
    path tables), IEEE P1281 SUSP 1.12 and IEEE P1282 RRIP 1.12 (Rock Ridge);
  - ECMA-167 3rd ed. + OSTA UDF 1.02 / 2.01 (UDF volume and file structure);
  - the IBM PC MBR layout and UEFI 2.x chapter 5 (GPT) for detection tests.

Every image is written gzip-compressed (mtime 0, deterministic) together
with a `.manifest` listing what a correct reader must report:
    kind<TAB>path<TAB>size<TAB>mode-octal-or-"-"<TAB>mtime-or-"-"<TAB>sha256-or-link-target
kind is f (file), d (dir), l (symlink) or o (other).

Usage: python3 tests/gen/disc.py [outdir]   (default tests/fixtures/disc)
"""

import gzip
import hashlib
import os
import struct
import sys
import zlib

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "disc")


def write_fixture(name, image, manifest):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name + ".gz"), "wb") as f:
        f.write(gzip.compress(bytes(image), 9, mtime=0))
    lines = []
    for m in manifest:
        lines.append("\t".join(str(x) for x in m))
    with open(os.path.join(OUT, name + ".manifest"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def pattern(n, seed):
    return bytes((i * 31 + seed * 7 + (i >> 8)) & 0xFF for i in range(n))


# =================================================================== ISO-9660

ISO_BS = 2048


def b16(v):
    return struct.pack("<H", v) + struct.pack(">H", v)


def b32(v):
    return struct.pack("<I", v) + struct.pack(">I", v)


def iso_date7(y, mo, d, h, mi, s, off_q):
    return bytes([y - 1900, mo, d, h, mi, s, off_q & 0xFF])


def unix(y, mo, d, h, mi, s):
    import calendar
    return calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))


DEFAULT_DATE = iso_date7(2021, 6, 7, 8, 9, 10, 8)  # +02:00 -> 06:09:10 UTC
DEFAULT_UNIX = unix(2021, 6, 7, 6, 9, 10)


def dir_record(extent, size, flags, name, su=b"", xa=0, date=DEFAULT_DATE):
    nl = len(name)
    pad = b"\x00" if nl % 2 == 0 else b""
    body = bytes([0, xa]) + b32(extent) + b32(size) + date + bytes([flags, 0, 0]) + b16(1) + bytes([nl]) + name + pad + su
    if len(body) % 2:
        body += b"\x00"
    assert len(body) <= 255, (name, len(body))
    return bytes([len(body)]) + body[1:]


# --- SUSP / RRIP entries
def su_entry(sig, data, ver=1):
    return sig + bytes([4 + len(data), ver]) + data


def SP(skip=0):
    return su_entry(b"SP", bytes([0xBE, 0xEF, skip]))


def ER():
    ident = b"RRIP_1991A"
    des = b"THE ROCK RIDGE INTERCHANGE PROTOCOL PROVIDES SUPPORT FOR POSIX FILE SYSTEM SEMANTICS"
    src = b"PLEASE CONTACT DISC PUBLISHER FOR SPECIFICATION SOURCE."
    return su_entry(b"ER", bytes([len(ident), len(des), len(src), 1]) + ident + des + src)


def PX(mode, nlink=1, uid=0, gid=0, ino=0):
    return su_entry(b"PX", b32(mode) + b32(nlink) + b32(uid) + b32(gid) + b32(ino))


def NM(name, flags=0):
    return su_entry(b"NM", bytes([flags]) + name)


def SL(components, flags=0):
    # components: list of (flags, bytes)
    body = bytes([flags]) + b"".join(bytes([f, len(c)]) + c for f, c in components)
    return su_entry(b"SL", body)


def TF_short(modify, access=None):
    flags = 0x02
    data = modify
    if access is not None:
        flags |= 0x04
        data += access
    return su_entry(b"TF", bytes([flags]) + data)


def TF_long(create, modify):
    def l(y, mo, d, h, mi, s, off):
        return b"%04d%02d%02d%02d%02d%02d00" % (y, mo, d, h, mi, s) + bytes([off & 0xFF])
    return su_entry(b"TF", bytes([0x80 | 0x01 | 0x02]) + l(*create) + l(*modify))


def CE(block, offset, length):
    return su_entry(b"CE", b32(block) + b32(offset) + b32(length))


def CL(block):
    return su_entry(b"CL", b32(block))


def PL(block):
    return su_entry(b"PL", b32(block))


def RE():
    return su_entry(b"RE", b"")


ST = su_entry(b"ST", b"")


class Iso:
    """Block-addressed image under construction."""

    def __init__(self, blocks):
        self.img = bytearray(blocks * ISO_BS)
        self.next = 0

    def alloc(self, nblocks):
        b = self.next
        self.next += max(nblocks, 1)
        assert self.next * ISO_BS <= len(self.img)
        return b

    def put(self, block, data, offset=0):
        at = block * ISO_BS + offset
        self.img[at:at + len(data)] = data


def pack_dir(records):
    """Concatenate records so none crosses a sector boundary (ECMA-119 6.8.1.1)."""
    out = bytearray()
    for r in records:
        room = ISO_BS - (len(out) % ISO_BS)
        if len(r) > room:
            out += b"\x00" * room
        out += r
    return bytes(out)


def pvd(root_rec, vol_blocks, vol_id, path_l, path_m, pt_size):
    d = bytearray(ISO_BS)
    d[0] = 1
    d[1:6] = b"CD001"
    d[6] = 1
    d[8:40] = b"SEDIMENT".ljust(32)
    d[40:72] = vol_id.ljust(32)
    d[80:88] = b32(vol_blocks)
    d[120:124] = b16(1)
    d[124:128] = b16(1)
    d[128:132] = b16(ISO_BS)
    d[132:140] = b32(pt_size)
    d[140:144] = struct.pack("<I", path_l)
    d[148:152] = struct.pack(">I", path_m)
    d[156:190] = root_rec
    for off in (813, 830, 847, 864):
        d[off:off + 16] = b"0" * 16
    d[813:829] = b"2021060708091000"
    d[829] = 8
    d[881] = 1
    return d


def xa_record():
    """ECMA-119 9.5 Extended Attribute Record (no application use)."""
    r = bytearray(250)
    r[0:4] = b16(0)
    r[4:8] = b16(0)
    r[8:10] = struct.pack(">H", 0x5555)
    for i in range(4):
        r[10 + i * 17:26 + i * 17] = b"0" * 16
    r[180] = 1
    return bytes(r)


def terminator():
    d = bytearray(ISO_BS)
    d[0] = 255
    d[1:6] = b"CD001"
    d[6] = 1
    return d


def path_tables(dirs):
    """dirs: list of (name_bytes, extent, parent_number) in path-table order."""
    lt, mt = bytearray(), bytearray()
    for name, extent, parent in dirs:
        nl = len(name)
        pad = b"\x00" if nl % 2 else b""
        lt += bytes([nl, 0]) + struct.pack("<IH", extent, parent) + name + pad
        mt += bytes([nl, 0]) + struct.pack(">IH", extent, parent) + name + pad
    return bytes(lt), bytes(mt)


def build_rr_iso(skip=()):
    """ISO-9660 + Rock Ridge with NM continuation, CE chains, SL forms, deep
    directory relocation (CL/RE/PL), a multi-extent file, an extended
    attribute record, a FIFO, a multi-sector directory and TF stamps."""
    iso = Iso(120)
    iso.alloc(16)
    pvd_blk = iso.alloc(1)
    term_blk = iso.alloc(1)
    pt_l = iso.alloc(1)
    pt_m = iso.alloc(1)
    root = iso.alloc(1)
    deep = iso.alloc(1)
    moved = iso.alloc(1)
    reloc = iso.alloc(1)
    many = iso.alloc(3)
    ce1 = iso.alloc(1)
    ce2 = iso.alloc(1)
    manifest = []
    dir_mode = 0o040755
    f_mode = 0o100644

    def file_at(data):
        blk = iso.alloc((len(data) + ISO_BS - 1) // ISO_BS)
        iso.put(blk, data)
        return blk

    # files
    hello = b"hello rock ridge\n"
    hello_blk = file_at(hello)
    long_name = b"A rather long Rock Ridge name, split over two NM entries.txt"
    split_data = pattern(3000, 1)
    split_blk = file_at(split_data)
    ce_name = (b"continuation-" * 12) + b"end.bin"  # 163 bytes, lives in CE areas
    ce_data = pattern(777, 2)
    ce_blk = file_at(ce_data)
    # multi-extent: 4096 + 904 bytes in two non-adjacent extents
    multi = pattern(5000, 3)
    m1 = file_at(multi[:4096])
    iso.alloc(1)  # gap block
    m2 = file_at(multi[4096:])
    # extended attribute record: 1 block in front of the data
    xa_data = b"data after an extended attribute record\n"
    xa_blk = iso.alloc(2)
    iso.put(xa_blk, xa_record())
    iso.put(xa_blk + 1, xa_data)
    inner = b"inside the relocated directory\n"
    inner_blk = file_at(inner)
    empty_blk = iso.alloc(1)

    # continuation areas: ce1 holds the first part of the NM + CE to ce2
    part1, part2 = ce_name[:100], ce_name[100:]
    area2 = NM(part2) + TF_long((2001, 2, 3, 4, 5, 6, 0), (2019, 12, 31, 23, 59, 58, -4)) + ST
    iso.put(ce2, area2, offset=512)
    area1 = NM(part1, flags=0x01) + CE(ce2, 512, len(area2))
    iso.put(ce1, area1, offset=100)

    def dots(self_ext, self_size, parent_ext, parent_size, su_self=b"", su_parent=b""):
        return [
            dir_record(self_ext, self_size, 0x02, b"\x00", su_self),
            dir_record(parent_ext, parent_size, 0x02, b"\x01", su_parent),
        ]

    # --- many/: 40 entries so the directory spans two sectors
    many_recs_body = []
    for i in range(40):
        nm = b"entry-%02d-with-a-longer-rock-ridge-name.dat" % i
        data_len = i  # tiny files, all share the empty block (content zeros)
        many_recs_body.append(dir_record(empty_blk, data_len, 0, b"E%02d.;1" % i, PX(f_mode) + NM(nm)))
        manifest_many = ("f", "many/" + nm.decode(), data_len, "%o" % f_mode, DEFAULT_UNIX, sha(b"\x00" * data_len))
        many_recs_body[-1] = (many_recs_body[-1], manifest_many)
    many_size = 3 * ISO_BS

    # --- reloc (lives in rr_moved, logically root/deep/moved_dir)
    reloc_recs = dots(reloc, ISO_BS, moved, ISO_BS, PX(dir_mode), PX(dir_mode) + PL(deep))
    reloc_recs.append(dir_record(inner_blk, len(inner), 0, b"INNER.TXT;1", PX(f_mode) + NM(b"inner.txt")))
    iso.put(reloc, pack_dir(reloc_recs))

    # --- rr_moved
    moved_recs = dots(moved, ISO_BS, root, ISO_BS, PX(dir_mode), PX(dir_mode))
    moved_recs.append(dir_record(reloc, ISO_BS, 0x02, b"MOVED_DI", PX(dir_mode) + NM(b"moved_dir") + RE()))
    iso.put(moved, pack_dir(moved_recs))

    # --- deep: holds the CL placeholder (a file record)
    deep_recs = dots(deep, ISO_BS, root, ISO_BS, PX(dir_mode), PX(dir_mode))
    deep_recs.append(dir_record(empty_blk, 0, 0, b"MOVED_DI", PX(dir_mode) + NM(b"moved_dir") + CL(reloc)))
    iso.put(deep, pack_dir(deep_recs))

    # --- many
    iso.put(many, pack_dir(dots(many, many_size, root, ISO_BS, PX(dir_mode), PX(dir_mode)) + [r for r, _ in many_recs_body]))
    many_len = len(pack_dir(dots(many, many_size, root, ISO_BS, PX(dir_mode), PX(dir_mode)) + [r for r, _ in many_recs_body]))
    assert 2 * ISO_BS < many_len <= many_size, many_len

    # --- root
    root_recs = dots(root, ISO_BS, root, ISO_BS, SP() + PX(dir_mode) + ER(), PX(dir_mode))
    entries = []
    entries.append((dir_record(split_blk, len(split_data), 0, b"ARATHERL.TXT;1", PX(f_mode) + NM(long_name[:20], 0x01) + NM(long_name[20:])),
                    ("f", long_name.decode(), len(split_data), "%o" % f_mode, DEFAULT_UNIX, sha(split_data))))
    entries.append((dir_record(ce_blk, len(ce_data), 0, b"CONTINUA.BIN;1", PX(f_mode) + CE(ce1, 100, len(area1))),
                    ("f", ce_name.decode(), len(ce_data), "%o" % f_mode, unix(2020, 1, 1, 0, 59, 58), sha(ce_data))))
    entries.append((dir_record(deep, ISO_BS, 0x02, b"DEEP", PX(dir_mode) + NM(b"deep")),
                    ("d", "deep", 0, "%o" % dir_mode, DEFAULT_UNIX, "-")))
    entries.append((None, ("d", "deep/moved_dir", 0, "%o" % dir_mode, DEFAULT_UNIX, "-")))
    entries.append((None, ("f", "deep/moved_dir/inner.txt", len(inner), "%o" % f_mode, DEFAULT_UNIX, sha(inner))))
    entries.append((dir_record(empty_blk, 0, 0, b"FIFO.;1", PX(0o010644) + NM(b"fifo")),
                    ("o", "fifo", 0, "10644", DEFAULT_UNIX, "-")))
    entries.append((dir_record(hello_blk, len(hello), 0, b"HELLO.TXT;1", PX(0o100640) + NM(b"hello.txt") + TF_short(iso_date7(2022, 1, 2, 3, 4, 5, 0))),
                    ("f", "hello.txt", len(hello), "100640", unix(2022, 1, 2, 3, 4, 5), sha(hello))))
    sl_abs = SL([(0x08, b""), (0, b"etc"), (0x01, b"ho"), (0, b"sts")])
    entries.append((dir_record(empty_blk, 0, 0, b"LINKABS.;1", PX(0o120777) + NM(b"link_abs") + sl_abs),
                    ("l", "link_abs", 0, "120777", DEFAULT_UNIX, "/etc/hosts")))
    # relative link split over two SL entries
    sl_rel = SL([(0x02, b""), (0x04, b"")], flags=0x01) + SL([(0, b"many")])
    entries.append((dir_record(empty_blk, 0, 0, b"LINKREL.;1", PX(0o120777) + NM(b"link_rel") + sl_rel),
                    ("l", "link_rel", 0, "120777", DEFAULT_UNIX, "./../many")))
    entries.append((dir_record(many, many_size, 0x02, b"MANY", PX(dir_mode) + NM(b"many")),
                    ("d", "many", 0, "%o" % dir_mode, DEFAULT_UNIX, "-")))
    for r, m in many_recs_body:
        entries.append((None, m))
    entries.append((dir_record(m1, 4096, 0x80, b"MULTI.BIN;1", PX(f_mode) + NM(b"multi.bin")), None))
    entries.append((dir_record(m2, 904, 0, b"MULTI.BIN;1", PX(f_mode) + NM(b"multi.bin")),
                    ("f", "multi.bin", len(multi), "%o" % f_mode, DEFAULT_UNIX, sha(multi))))
    entries.append((dir_record(moved, ISO_BS, 0x02, b"RR_MOVED", PX(dir_mode) + NM(b"rr_moved")),
                    ("d", "rr_moved", 0, "%o" % dir_mode, DEFAULT_UNIX, "-")))
    entries.append((dir_record(xa_blk, len(xa_data), 0, b"XA.TXT;1", PX(f_mode) + NM(b"xa.txt"), xa=1),
                    ("f", "xa.txt", len(xa_data), "%o" % f_mode, DEFAULT_UNIX, sha(xa_data))))
    kept = []
    dropping = False
    for r, m in entries:
        if r is not None:
            dropping = any(k in r for k in skip)
            if not dropping:
                root_recs.append(r)
        if m is not None and not dropping:
            kept.append(m)
    iso.put(root, pack_dir(root_recs))
    manifest = kept

    lt, mt = path_tables([(b"\x00", root, 1), (b"DEEP", deep, 1), (b"MANY", many, 1), (b"RR_MOVED", moved, 1), (b"MOVED_DI", reloc, 4)])
    iso.put(pt_l, lt)
    iso.put(pt_m, mt)
    root_rec = dir_record(root, ISO_BS, 0x02, b"\x00")
    total = iso.next
    iso.img = iso.img[: total * ISO_BS]
    iso.put(pvd_blk, pvd(root_rec, total, b"RRHAND", pt_l, pt_m, len(lt)))
    iso.put(term_blk, terminator())
    return iso.img, manifest


def build_plain_iso():
    """Primary names only (no SUSP): ;1 versions, trailing dots, nested dir."""
    iso = Iso(40)
    iso.alloc(16)
    pvd_blk = iso.alloc(1)
    term_blk = iso.alloc(1)
    pt_l = iso.alloc(1)
    pt_m = iso.alloc(1)
    root = iso.alloc(1)
    sub = iso.alloc(1)
    readme = b"plain iso9660\n"
    r_blk = iso.alloc(1)
    iso.put(r_blk, readme)
    noext = pattern(2500, 9)
    n_blk = iso.alloc(2)
    iso.put(n_blk, noext)
    nested = b"nested\n"
    s_blk = iso.alloc(1)
    iso.put(s_blk, nested)
    date = iso_date7(1999, 12, 31, 23, 0, 0, -20)  # -05:00
    t = unix(2000, 1, 1, 4, 0, 0)
    iso.put(sub, pack_dir([
        dir_record(sub, ISO_BS, 2, b"\x00"),
        dir_record(root, ISO_BS, 2, b"\x01"),
        dir_record(s_blk, len(nested), 0, b"NESTED.TXT;1", date=date),
    ]))
    iso.put(root, pack_dir([
        dir_record(root, ISO_BS, 2, b"\x00"),
        dir_record(root, ISO_BS, 2, b"\x01"),
        dir_record(n_blk, len(noext), 0, b"NOEXT.;1", date=date),
        dir_record(r_blk, len(readme), 0, b"README.TXT;1", date=date),
        dir_record(sub, ISO_BS, 2, b"SUBDIR", date=date),
    ]))
    lt, mt = path_tables([(b"\x00", root, 1), (b"SUBDIR", sub, 1)])
    iso.put(pt_l, lt)
    iso.put(pt_m, mt)
    total = iso.next
    iso.img = iso.img[: total * ISO_BS]
    iso.put(pvd_blk, pvd(dir_record(root, ISO_BS, 2, b"\x00"), total, b"PLAIN", pt_l, pt_m, len(lt)))
    iso.put(term_blk, terminator())
    manifest = [
        ("f", "NOEXT", len(noext), "-", t, sha(noext)),
        ("f", "README.TXT", len(readme), "-", t, sha(readme)),
        ("d", "SUBDIR", 0, "-", t, "-"),
        ("f", "SUBDIR/NESTED.TXT", len(nested), "-", t, sha(nested)),
    ]
    return iso.img, manifest


# ======================================================================= UDF


def crc_ccitt(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def tag(ident, version, location, body):
    """ECMA-167 3/7.2 descriptor tag + body (body excludes the 16-byte tag)."""
    t = bytearray(struct.pack("<HHBBHHHI", ident, version, 0, 0, 1, crc_ccitt(body), len(body), location))
    t[4] = sum(t) & 0xFF
    return bytes(t) + body


def regid(ident, suffix=b""):
    return bytes([0]) + ident.ljust(23, b"\x00") + suffix.ljust(8, b"\x00")


def charspec():
    return bytes([0]) + b"OSTA Compressed Unicode".ljust(63, b"\x00")


def cs0(s):
    if all(ord(c) < 256 for c in s):
        return bytes([8]) + s.encode("latin-1")
    return bytes([16]) + s.encode("utf-16-be")


def dstring(s, size):
    if not s:
        return bytes(size)
    b = cs0(s)
    assert len(b) < size
    return b.ljust(size - 1, b"\x00") + bytes([len(b)])


def udf_ts(y, mo, d, h, mi, s, tz_minutes=0):
    return struct.pack("<HhBBBBBBBB", 0x1000 | (tz_minutes & 0xFFF), y, mo, d, h, mi, s, 0, 0, 0)


def extent_ad(length, loc):
    return struct.pack("<II", length, loc)


def long_ad(length, lbn, part=0, ext_type=0):
    return struct.pack("<IIH", (ext_type << 30) | length, lbn, part) + bytes(6)


def short_ad(length, lbn, ext_type=0):
    return struct.pack("<II", (ext_type << 30) | length, lbn)


def unix_perm(mode):
    """Unix rwx bits -> UDF permissions (other bits 0-4, group 5-9, owner 10-14)."""
    p = 0
    for shift_u, shift_d in ((0, 0), (3, 5), (6, 10)):
        bits = (mode >> shift_u) & 7
        p |= bits << shift_d
        # grant chattr/delete to whoever may write
        if bits & 2:
            p |= 0x18 << shift_d
    return p


class Udf:
    def __init__(self, bs, revision, efe, ads, total_blocks):
        self.bs = bs
        self.rev = revision
        self.efe = efe
        self.ads = ads  # "short" or "long"
        self.desc_ver = 3 if revision >= 0x0200 else 2
        self.img = bytearray(total_blocks * bs)
        self.part_start = 0
        self.part_next = 0
        self.uid = 16

    def sector(self, n, data):
        assert len(data) <= self.bs or n * self.bs + len(data) <= len(self.img)
        self.img[n * self.bs:n * self.bs + len(data)] = data

    def palloc(self, n=1):
        b = self.part_next
        self.part_next += max(n, 1)
        return b

    def pput(self, lbn, data):
        at = (self.part_start + lbn) * self.bs
        assert at + len(data) <= len(self.img)
        self.img[at:at + len(data)] = data

    def tagd(self, ident, location, body):
        return tag(ident, self.desc_ver, location, body)

    def recorded_blocks(self, ad_area, ad_type):
        if ad_type == 3:
            return 0
        size = 8 if ad_type == 0 else 16
        n = 0
        for i in range(0, len(ad_area) - size + 1, size):
            raw = struct.unpack_from("<I", ad_area, i)[0]
            if raw >> 30 == 0:
                n += ((raw & 0x3FFFFFFF) + self.bs - 1) // self.bs
        return n

    def file_entry(self, lbn, file_type, info_len, ad_area, ad_type, mode, mtime, links=1, recorded=None):
        icb = struct.pack("<IHHHBB", 0, 4, 0, 1, 0, file_type) + bytes(6) + struct.pack("<H", ad_type)
        perms = unix_perm(mode & 0o777)
        self.uid += 1
        if recorded is None:
            recorded = self.recorded_blocks(ad_area, ad_type)
        if self.efe:
            body = (icb + struct.pack("<IIIHBBI", 0xFFFFFFFF, 0xFFFFFFFF, perms, links, 0, 0, 0)
                    + struct.pack("<QQQ", info_len, info_len, recorded)
                    + mtime + mtime + mtime + mtime
                    + struct.pack("<II", 1, 0) + bytes(16) + bytes(16)
                    + regid(b"*SEDIMENT TEST") + struct.pack("<QII", self.uid, 0, len(ad_area)) + ad_area)
            d = self.tagd(266, lbn, body)
        else:
            body = (icb + struct.pack("<IIIHBBI", 0xFFFFFFFF, 0xFFFFFFFF, perms, links, 0, 0, 0)
                    + struct.pack("<QQ", info_len, recorded)
                    + mtime + mtime + mtime
                    + struct.pack("<I", 1) + bytes(16)
                    + regid(b"*SEDIMENT TEST") + struct.pack("<QII", self.uid, 0, len(ad_area)) + ad_area)
            d = self.tagd(261, lbn, body)
        assert len(d) <= self.bs, len(d)
        self.pput(lbn, d)

    def ad(self, length, lbn, ext_type=0):
        return short_ad(length, lbn, ext_type) if self.ads == "short" else long_ad(length, lbn, 0, ext_type)

    def ad_type(self):
        return 0 if self.ads == "short" else 1

    def put_data(self, data):
        """Store data contiguously; returns its AD list."""
        if not data:
            return b""
        n = (len(data) + self.bs - 1) // self.bs
        lbn = self.palloc(n)
        self.pput(lbn, data)
        return self.ad(len(data), lbn)

    def fid(self, block, name, icb_lbn, chars=0):
        fi = cs0(name) if name is not None else b""
        body = struct.pack("<HBB", 1, chars, len(fi)) + long_ad(self.bs, icb_lbn) + struct.pack("<H", 0) + fi
        # ECMA-167 4/14.4.9: padding to a multiple of 4 is part of the
        # descriptor, so the CRC covers it.
        body += bytes((-(16 + len(body))) % 4)
        return self.tagd(257, block, body)

    def directory(self, lbn, parent_lbn, children, mode, mtime):
        """children: list of (name, icb_lbn, chars). Writes the FIDs into
        freshly allocated blocks and the FE at lbn."""
        # FID tag locations depend on where they land: compute iteratively.
        est = 40 + sum(40 + len(cs0(n)) + 3 for n, _, _ in children)
        nblocks = (est + self.bs - 1) // self.bs
        start = self.palloc(nblocks)
        data = bytearray()
        data += self.fid(start, None, parent_lbn, 0x0A)
        for name, icb, chars in children:
            data += self.fid(start + len(data) // self.bs, name, icb, chars)
        assert len(data) <= nblocks * self.bs
        self.pput(start, bytes(data))
        self.file_entry(lbn, 4, len(data), self.ad(len(data), start), self.ad_type(), mode, mtime, links=2)


def build_udf(bs, revision, efe, ads, with_ie, total_blocks, part_len, meta_map=False, keep=None, symlinks=True):
    u = Udf(bs, revision, efe, ads, total_blocks)
    sec_per_2k = max(1, 2048 // bs)
    # Volume recognition sequence at byte 32768, one descriptor per 2048 bytes.
    nsr = b"NSR03" if revision >= 0x0200 else b"NSR02"
    for i, ident in enumerate((b"BEA01", nsr, b"TEA01")):
        at = 32768 + i * 2048
        u.img[at:at + 7] = bytes([0]) + ident + bytes([1])
    main_vds, reserve_vds = 32 * sec_per_2k, 48 * sec_per_2k
    lvid = 80 * sec_per_2k
    u.part_start = 260 * sec_per_2k
    u.part_len = part_len
    rec_time = udf_ts(2023, 4, 5, 6, 7, 8, 60)

    # ---- file set contents
    fsd = u.palloc()
    u.palloc()  # terminating descriptor after the FSD
    root_icb = u.palloc()
    files = []  # (name, lbn) for root
    manifest = []
    t_default = udf_ts(2024, 1, 2, 3, 4, 5, 120)  # +02:00
    unix_default = unix(2024, 1, 2, 1, 4, 5)

    def add_file(name, data, mode=0o644, mtime=t_default, unix_t=unix_default, path=None, ads=None, info_len=None, embedded=False, recorded=None):
        lbn = u.palloc()
        if embedded:
            u.file_entry(lbn, 5, len(data), data, 3, mode, mtime)
        else:
            area = u.put_data(data) if ads is None else ads
            u.file_entry(lbn, 5, len(data) if info_len is None else info_len, area, u.ad_type(), mode, mtime, recorded=recorded)
        manifest.append(("f", path or name, len(data), "%o" % (0o100000 | mode), unix_t, sha(data)))
        return lbn

    hello = b"hello udf\n"
    files.append(("hello.txt", add_file("hello.txt", hello, 0o640), 0))
    latin = "Grüße.txt"
    latin_data = pattern(1234, 4)
    files.append((latin, add_file(latin, latin_data), 0))
    uni = "日本語 ファイル.txt"
    uni_data = "unicode name\n".encode()
    files.append((uni, add_file(uni, uni_data), 0))
    files.append(("embedded.txt", add_file("embedded.txt", b"stored inside the ICB\n", embedded=True), 0))

    # sparse: recorded, allocated-unrecorded, unallocated, recorded (short tail)
    sp_a = u.palloc()
    sp_b = u.palloc()
    sp_d = u.palloc()
    a_data = pattern(bs, 5)
    d_data = pattern(100, 6)
    u.pput(sp_a, a_data)
    u.pput(sp_b, b"\xEE" * bs)  # garbage that must read as zeros
    u.pput(sp_d, d_data)
    sparse = a_data + bytes(2 * bs) + d_data
    sp_ads = u.ad(bs, sp_a) + u.ad(bs, sp_b, 1) + u.ad(bs, 0, 2) + u.ad(100, sp_d)
    files.append(("sparse.bin", add_file("sparse.bin", sparse, ads=sp_ads), 0))

    # fragmented with an Allocation Extent Descriptor continuation
    pieces = [pattern(bs, 10 + i) for i in range(6)]
    frag_lbns = []
    for p in pieces:
        frag_lbns.append(u.palloc())
        u.palloc()  # leave a hole between pieces
        u.pput(frag_lbns[-1], p)
    aed = u.palloc()
    tail_ads = b"".join(u.ad(bs, l) for l in frag_lbns[2:])
    u.pput(aed, u.tagd(258, aed, struct.pack("<II", 0, len(tail_ads)) + tail_ads))
    head_ads = u.ad(bs, frag_lbns[0]) + u.ad(bs, frag_lbns[1]) + u.ad(bs, aed, 3)
    frag = b"".join(pieces)
    files.append(("frag.bin", add_file("frag.bin", frag, ads=head_ads, recorded=len(pieces)), 0))

    # empty file (no allocation descriptors)
    files.append(("empty.txt", add_file("empty.txt", b""), 0))

    # absolute symlink: root + etc + hosts ; relative symlink in subdir
    def symlink(name, comps, path):
        body = b""
        for ty, ci in comps:
            c = cs0(ci) if ci else b""
            body += struct.pack("<BBH", ty, len(c), 0) + c
        lbn = u.palloc()
        u.file_entry(lbn, 12, len(body), body, 3, 0o777, t_default)
        target = ("/" if comps[0][0] == 2 else "") + "/".join(
            {3: "..", 4: "."}.get(ty, ci) for ty, ci in comps if ty != 2)
        manifest.append(("l", path, 0, "120777", unix_default, target))
        return lbn

    if symlinks:
        files.append(("abs_link", symlink("abs_link", [(2, ""), (5, "etc"), (5, "hosts")], "abs_link"), 0))

    # deleted entry pointing at hello's ICB: must be skipped
    files.append(("deleted.txt", files[0][1], 0x04))

    # sub directory with nested file + relative link + many-entry dir
    sub_icb = u.palloc()
    nested = b"nested file\n"
    sub_manifest_idx = len(manifest)
    manifest.append(("d", "sub", 0, "40755", unix_default, "-"))
    nested_lbn = add_file("nested.txt", nested, path="sub/nested.txt")
    rel = symlink("rel_link", [(3, ""), (5, "hello.txt")], "sub/rel_link") if symlinks else None
    if with_ie:
        # Indirect Entry -> the real File Entry
        ie = u.palloc()
        icb = struct.pack("<IHHHBB", 0, 4096, 0, 2, 0, 3) + bytes(6) + struct.pack("<H", 0)
        u.pput(ie, u.tagd(259, ie, icb + long_ad(bs, nested_lbn)))
        nested_ref = ie
    else:
        nested_ref = nested_lbn
    big_icb = u.palloc()
    manifest.append(("d", "sub/big", 0, "40700", unix_default, "-"))
    big_children = []
    for i in range(30):
        nm = "file-number-%02d-with-padding-name.txt" % i
        data = ("entry %d\n" % i).encode()
        big_children.append((nm, add_file(nm, data, path="sub/big/" + nm), 0))
    u.directory(big_icb, sub_icb, big_children, 0o700, t_default)
    sub_children = [("nested.txt", nested_ref, 0)] + ([("rel_link", rel, 0)] if symlinks else []) + [("big", big_icb, 0x02)]
    u.directory(sub_icb, root_icb, sub_children, 0o755, t_default)
    files.append(("sub", sub_icb, 0x02))

    # root directory + manifest order = FID order
    root_order = []
    for name, lbn, chars in files:
        if chars & 0x04:
            continue
        if name == "sub":
            continue
        root_order.append(name)
    u.directory(root_icb, root_icb, [f for f in files if keep is None or f[0] in keep], 0o755, t_default)

    by_path = {m[1]: m for m in manifest}
    sub_block = manifest[sub_manifest_idx:]
    ordered = [by_path[n] for n in root_order] + [m for m in sub_block if m[1] == "sub"]
    ordered += [by_path[p] for p in ("sub/nested.txt", "sub/rel_link", "sub/big") if p in by_path]
    ordered += [m for m in manifest if m[1].startswith("sub/big/")]

    # File Set Descriptor + TD
    part_ref = 1 if meta_map else 0
    fsd_body = (rec_time + struct.pack("<HHIIII", 3, 3, 1, 1, 0, 0) + charspec() + dstring("SEDLV", 128)
                + charspec() + dstring("SEDFS", 32) + bytes(32) + bytes(32)
                + long_ad(bs, root_icb, part_ref) + regid(b"*OSTA UDF Compliant", struct.pack("<HB", revision, 3))
                + bytes(16) + bytes(16) + bytes(32))
    u.pput(fsd, u.tagd(256, fsd, fsd_body))
    u.pput(fsd + 1, u.tagd(8, fsd + 1, bytes(496)))
    assert u.part_next <= part_len, (u.part_next, part_len)

    # ---- volume descriptor sequences
    def vds(start):
        s = start
        pvd = (struct.pack("<II", 1, 0) + dstring("SEDUDFVOL", 32) + struct.pack("<HHHHII", 1, 1, 2, 2, 1, 1)
               + dstring("SEDSET", 128) + charspec() + charspec() + bytes(16) + regid(b"*SEDIMENT TEST")
               + rec_time + regid(b"*SEDIMENT TEST") + bytes(64) + struct.pack("<IH", 0, 0) + bytes(22))
        u.sector(s, u.tagd(1, s, pvd))
        contents = b"+NSR03" if revision >= 0x0200 else b"+NSR02"
        pd = (struct.pack("<IHH", 2, 1, 0) + regid(contents) + bytes(128)
              + struct.pack("<III", 1, u.part_start, part_len) + regid(b"*SEDIMENT TEST") + bytes(128) + bytes(156))
        u.sector(s + 1, u.tagd(5, s + 1, pd))
        maps = struct.pack("<BBHH", 1, 6, 1, 0)
        if meta_map:
            maps += struct.pack("<BBH", 2, 64, 0) + regid(b"*UDF Metadata Partition", struct.pack("<H", revision)) \
                + struct.pack("<HHIIIIHB", 1, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 32, 1, 0) + bytes(5)
        lvd = (struct.pack("<I", 3) + charspec() + dstring("SEDLV", 128) + struct.pack("<I", bs)
               + regid(b"*OSTA UDF Compliant", struct.pack("<HB", revision, 3))
               + long_ad(bs, fsd, part_ref) + struct.pack("<II", len(maps), len(maps) // 6 if not meta_map else 2)
               + regid(b"*SEDIMENT TEST") + bytes(128) + extent_ad(2 * bs, lvid) + maps)
        u.sector(s + 2, u.tagd(6, s + 2, lvd))
        u.sector(s + 3, u.tagd(7, s + 3, struct.pack("<II", 4, 0)))
        u.sector(s + 4, u.tagd(8, s + 4, bytes(496)))

    vds(main_vds)
    vds(reserve_vds)
    # Logical Volume Integrity Descriptor (closed) + TD
    iu = regid(b"*SEDIMENT TEST") + struct.pack("<IIHHH", 40, 3, revision, revision, revision)
    lvid_body = (rec_time + struct.pack("<I", 1) + extent_ad(0, 0) + struct.pack("<Q", 1000) + bytes(24)
                 + struct.pack("<II", 1, len(iu)) + struct.pack("<II", 0, part_len) + iu)
    u.sector(lvid, u.tagd(9, lvid, lvid_body))
    u.sector(lvid + 1, u.tagd(8, lvid + 1, bytes(496)))
    # Anchors at 256 and N-1
    n = total_blocks
    for loc in (256, n - 1):
        u.sector(loc, u.tagd(2, loc, extent_ad(16 * bs, main_vds) + extent_ad(16 * bs, reserve_vds) + bytes(480)))
    return u.img, ordered


# ================================================================ MBR / GPT


def build_mbr():
    img = bytearray(64 * 512)
    parts = [(0x80, 0x0C, 2, 20), (0x00, 0x83, 22, 30)]
    for i, (st, ty, lba, cnt) in enumerate(parts):
        e = bytes([st, 0, 0, 0, ty, 0, 0, 0]) + struct.pack("<II", lba, cnt)
        img[446 + i * 16:462 + i * 16] = e
    img[510:512] = b"\x55\xAA"
    return img


def build_gpt(sector=512):
    n_entries, entry_size = 4, 128
    total = 64 if sector == 512 else 24
    img = bytearray(total * sector)
    img[446:462] = bytes([0, 0, 2, 0, 0xEE, 0xFF, 0xFF, 0xFF]) + struct.pack("<II", 1, total - 1)
    img[510:512] = b"\x55\xAA"
    entries = bytearray(n_entries * entry_size)
    linux = bytes.fromhex("af3dc60f838472478e793d69d8477de4")
    for i, (first, last, name) in enumerate([(6, 9, "boot"), (10, 15, "data")]):
        e = linux + bytes([i + 1] * 16) + struct.pack("<QQQ", first, last, 0) + name.encode("utf-16-le").ljust(72, b"\x00")
        entries[i * entry_size:(i + 1) * entry_size] = e
    img[2 * sector:2 * sector + len(entries)] = entries
    hdr = bytearray(92)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ", hdr, 8, 0x00010000, 92, 0, 0, 1, total - 1, 6, total - 2)
    hdr[56:72] = bytes(range(16))
    struct.pack_into("<QIII", hdr, 72, 2, n_entries, entry_size, zlib.crc32(entries))
    struct.pack_into("<I", hdr, 16, zlib.crc32(hdr))
    img[sector:sector + 92] = hdr
    return img


# ===================================================================== main

def main():
    # 7-Zip 26.04 rejects images with extended attribute records, so the
    # XA case lives in its own fixture and rr_hand.iso stays oracle-checkable.
    img, man = build_rr_iso(skip=(b"XA.TXT",))
    write_fixture("rr_hand.iso", img, man)
    img, man = build_rr_iso(skip=(b"ARATHERL", b"CONTINUA", b"DEEP", b"FIFO", b"HELLO", b"LINKABS", b"LINKREL", b"MANY", b"MULTI", b"RR_MOVED"))
    write_fixture("rr_xa.iso", img, man)
    img, man = build_plain_iso()
    write_fixture("plain.iso", img, man)
    img, man = build_udf(2048, 0x0102, efe=False, ads="short", with_ie=False, total_blocks=600, part_len=300)
    write_fixture("udf102.img", img, man)
    # 7-Zip 26.04 refuses UDF images containing symlinks; this variant is the
    # one tests/gen/disc_oracle.sh cross-checks with 7zz.
    img, man = build_udf(2048, 0x0102, efe=False, ads="short", with_ie=False, total_blocks=600, part_len=300, symlinks=False)
    write_fixture("udf102_nolink.img", img, man)
    img, man = build_udf(512, 0x0201, efe=True, ads="long", with_ie=True, total_blocks=2000, part_len=700)
    write_fixture("udf201_512.img", img, man)
    img, man = build_udf(2048, 0x0250, efe=True, ads="long", with_ie=False, total_blocks=600, part_len=300, meta_map=True)
    write_fixture("udf_metadata_map.img", img, [])
    write_fixture("mbr.img", build_mbr(), [])
    write_fixture("gpt.img", build_gpt(), [])


if __name__ == "__main__":
    main()
