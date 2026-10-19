#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Build Copy-method 7z fixtures straight from the published 7z format
description (7zFormat.txt): signature header, packed streams, a header made of
property IDs, and CRC32s. Python stdlib only (zlib.crc32 is the CRC oracle).

Usage: python3 tests/gen/sevenz.py [out_dir]
Default out_dir: tests/fixtures/sevenz/gen (relative to the crate root).

The output is deterministic. Expected contents are mirrored in
tests/sevenz_read.rs.
"""
import os
import struct
import sys
import zlib

SIG = b"7z\xbc\xaf\x27\x1c"

K_END, K_HEADER, K_MAIN_STREAMS = 0x00, 0x01, 0x04
K_FILES, K_PACK, K_UNPACK, K_SUBSTREAMS = 0x05, 0x06, 0x07, 0x08
K_SIZE, K_CRC, K_FOLDER, K_CODERS_UNPACK_SIZE = 0x09, 0x0A, 0x0B, 0x0C
K_NUM_UNPACK, K_EMPTY_STREAM, K_EMPTY_FILE = 0x0D, 0x0E, 0x0F
K_NAME, K_CTIME, K_ATIME, K_MTIME, K_ATTR = 0x11, 0x12, 0x13, 0x14, 0x15
K_ENCODED_HEADER, K_DUMMY = 0x17, 0x19

FILETIME_UNIX_EPOCH = 116444736000000000
ATTR_DIR, ATTR_ARCHIVE, ATTR_UNIX = 0x10, 0x20, 0x8000


def crc(b):
    return zlib.crc32(b) & 0xFFFFFFFF


def num(v):
    """7z NUMBER: leading 1-bits of the first byte count extra LE bytes."""
    assert 0 <= v < 1 << 64
    for i in range(8):
        if v < 1 << (8 * i + 7 - i):
            first = ((0xFF << (8 - i)) & 0xFF) | (v >> (8 * i))
            return bytes([first]) + v.to_bytes(8, "little")[:i]
    return b"\xff" + v.to_bytes(8, "little")


def bits(flags):
    out = bytearray((len(flags) + 7) // 8)
    for i, f in enumerate(flags):
        if f:
            out[i // 8] |= 0x80 >> (i % 8)
    return bytes(out)


def defined_vector(flags):
    """AllAreDefined byte, then a bit vector only when some are missing."""
    if all(flags):
        return b"\x01"
    return b"\x00" + bits(flags)


def digests(values):
    """Digests record for a list of Optional[int] CRCs."""
    out = defined_vector([v is not None for v in values])
    for v in values:
        if v is not None:
            out += struct.pack("<I", v)
    return out


def filetime(unix_secs, frac_100ns=0):
    return unix_secs * 10_000_000 + frac_100ns + FILETIME_UNIX_EPOCH


def file_attr(mode=0o644):
    return ATTR_ARCHIVE | ATTR_UNIX | ((0o100000 | mode) << 16)


def dir_attr(mode=0o755):
    return ATTR_DIR | ATTR_UNIX | ((0o040000 | mode) << 16)


class Entry:
    def __init__(self, name, data=None, is_dir=False, attr=None, mtime=None, ctime=None, atime=None):
        self.name = name
        self.data = data  # None for dirs; b"" for empty files
        self.is_dir = is_dir
        self.attr = attr
        self.mtime, self.ctime, self.atime = mtime, ctime, atime

    @property
    def has_stream(self):
        return not self.is_dir and self.data is not None and len(self.data) > 0


def coder_copy():
    return bytes([0x01, 0x00])  # flags: id size 1, simple, no props; id 00


def folder_record(chain):
    if not chain:
        return num(1) + coder_copy()
    # Two Copy coders; coder 0's input (in 0) is fed by coder 1's output (out 1).
    # The packed stream feeds in 1 (implicit because only one is unbound).
    return num(2) + coder_copy() + coder_copy() + num(0) + num(1)


def prop(pid, data):
    return bytes([pid]) + num(len(data)) + data


def streams_info(pack_pos, folders, *, pack_crcs, folder_crc_in_unpack, chain=False, substreams=True):
    """folders: list of lists of byte strings (substreams of a Copy folder)."""
    packed = [b"".join(f) for f in folders]
    out = bytes([K_PACK]) + num(pack_pos) + num(len(packed))
    out += bytes([K_SIZE]) + b"".join(num(len(p)) for p in packed)
    if pack_crcs:
        out += bytes([K_CRC]) + digests([crc(p) for p in packed])
    out += bytes([K_END])

    out += bytes([K_UNPACK, K_FOLDER]) + num(len(folders)) + b"\x00"
    for _ in folders:
        out += folder_record(chain)
    out += bytes([K_CODERS_UNPACK_SIZE])
    for p in packed:
        out += num(len(p)) * (2 if chain else 1)
    folder_crcs = [crc(p) if (len(f) == 1 and i in folder_crc_in_unpack) else None
                   for i, (f, p) in enumerate(zip(folders, packed))]
    if any(c is not None for c in folder_crcs):
        out += bytes([K_CRC]) + digests(folder_crcs)
    out += bytes([K_END])

    if substreams:
        out += bytes([K_SUBSTREAMS, K_NUM_UNPACK]) + b"".join(num(len(f)) for f in folders)
        if any(len(f) > 1 for f in folders):
            out += bytes([K_SIZE])
            for f in folders:
                out += b"".join(num(len(s)) for s in f[:-1])
        sub_crcs = []
        for f, fc in zip(folders, folder_crcs):
            if not (len(f) == 1 and fc is not None):
                sub_crcs += [crc(s) for s in f]
        if sub_crcs:
            out += bytes([K_CRC]) + digests(sub_crcs)
        out += bytes([K_END])
    out += bytes([K_END])
    return out


def files_info(entries, dummy):
    n = len(entries)
    out = bytes([K_FILES]) + num(n)
    empty_stream = [not e.has_stream for e in entries]
    if any(empty_stream):
        out += prop(K_EMPTY_STREAM, bits(empty_stream))
        empties = [e for e in entries if not e.has_stream]
        empty_file = [not e.is_dir for e in empties]
        if any(empty_file):
            out += prop(K_EMPTY_FILE, bits(empty_file))
    for pid, attr in ((K_CTIME, "ctime"), (K_ATIME, "atime"), (K_MTIME, "mtime")):
        vals = [getattr(e, attr) for e in entries]
        if any(v is not None for v in vals):
            body = defined_vector([v is not None for v in vals]) + b"\x00"
            body += b"".join(struct.pack("<Q", v) for v in vals if v is not None)
            out += prop(pid, body)
    names = b"\x00" + b"".join(e.name.encode("utf-16-le") + b"\x00\x00" for e in entries)
    if dummy:
        out += prop(K_DUMMY, b"\x00" * 3)
    out += prop(K_NAME, names)
    attrs = [e.attr for e in entries]
    if any(a is not None for a in attrs):
        body = defined_vector([a is not None for a in attrs]) + b"\x00"
        body += b"".join(struct.pack("<I", a) for a in attrs if a is not None)
        out += prop(K_ATTR, body)
    out += bytes([K_END])
    return out


def group_folders(entries, folder_counts):
    streams = [e.data for e in entries if e.has_stream]
    assert sum(folder_counts) == len(streams), (folder_counts, len(streams))
    folders, i = [], 0
    for c in folder_counts:
        folders.append(streams[i:i + c])
        i += c
    return folders


def build(entries, folder_counts, *, pack_crcs=False, folder_crc_in_unpack=(), chain=False,
          dummy=False, encoded=False, substreams=True, minor=4):
    folders = group_folders(entries, folder_counts)
    body = b"".join(b"".join(f) for f in folders)
    header = bytes([K_HEADER])
    if folders:
        header += bytes([K_MAIN_STREAMS]) + streams_info(
            0, folders, pack_crcs=pack_crcs, folder_crc_in_unpack=set(folder_crc_in_unpack),
            chain=chain, substreams=substreams)
    if entries:
        header += files_info(entries, dummy)
    header += bytes([K_END])
    if encoded:
        # The real header becomes a Copy-coded packed stream right after the
        # file data; the next header is kEncodedHeader + StreamsInfo.
        pack_pos = len(body)
        body += header
        header = bytes([K_ENCODED_HEADER]) + streams_info(
            pack_pos, [[header]], pack_crcs=False, folder_crc_in_unpack={0}, substreams=False)
    next_off = len(body)
    start = struct.pack("<QQI", next_off, len(header), crc(header))
    sig = SIG + bytes([0, minor]) + struct.pack("<I", crc(start)) + start
    return sig + body + header


def empty_archive():
    start = struct.pack("<QQI", 0, 0, 0)
    return SIG + b"\x00\x04" + struct.pack("<I", crc(start)) + start


# --- fixture contents (mirrored in tests/sevenz_read.rs) ---------------------
HELLO = b"Hello, 7z!\n"
A_TXT = "".join("alpha line %d\n" % i for i in range(40)).encode()
B_BIN = bytes((i * 31 + 7) & 0xFF for i in range(300))
UNI = b"unicode name\n"
EMOJI = "\U0001F600 smile\n".encode()
D_TXT = b"standalone folder\n"

T0 = filetime(1_700_000_000, 1_234_567)  # 2023-11-14 22:13:20.1234567 UTC
T1 = filetime(1_600_000_000)  # 2020-09-13 12:26:40 UTC


def fixtures():
    single = [Entry("hello.txt", HELLO, attr=file_attr(0o640), mtime=T0)]
    solid = [
        Entry("dir", is_dir=True, attr=dir_attr(), mtime=T1),
        Entry("dir/sub", is_dir=True, attr=dir_attr(0o700), mtime=T1),
        Entry("empty.txt", b"", attr=file_attr(), mtime=T1, ctime=T1),
        Entry("a.txt", A_TXT, attr=file_attr(), mtime=T0, ctime=T1),
        Entry("b.bin", B_BIN, attr=None, mtime=T0),
        Entry("dir/héllo_日本.txt", UNI, attr=file_attr(0o600), mtime=T0),
        Entry("\U0001F600.txt", EMOJI, attr=file_attr(), mtime=T0, ctime=T1),
        Entry("d.txt", D_TXT, attr=file_attr(0o444), mtime=T1, ctime=T1),
    ]
    nonsolid = [
        Entry("one.txt", HELLO, attr=file_attr(), mtime=T0),
        Entry("two.txt", A_TXT, attr=file_attr(), mtime=T0),
        Entry("three.bin", B_BIN, attr=file_attr(), mtime=T0),
    ]
    two = [
        Entry("hello.txt", HELLO, attr=file_attr(), mtime=T0),
        Entry("a.txt", A_TXT, attr=file_attr(), mtime=T0),
    ]
    return {
        "single.7z": build(single, [1]),
        "solid.7z": build(solid, [4, 1], pack_crcs=True, folder_crc_in_unpack=[1], dummy=True),
        "nonsolid_no_substreams.7z": build(nonsolid, [1, 1, 1], folder_crc_in_unpack=[0, 1, 2],
                                           substreams=False, minor=3),
        "encoded_header.7z": build(two, [2], encoded=True),
        "chain.7z": build(single, [1], chain=True),
        "empty.7z": empty_archive(),
    }


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, "tests", "fixtures", "sevenz", "gen")
    os.makedirs(out, exist_ok=True)
    for name, data in fixtures().items():
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
        print("%s %d bytes" % (name, len(data)))


if __name__ == "__main__":
    main()
