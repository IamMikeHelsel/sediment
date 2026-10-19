#!/usr/bin/env python3
"""Generate fixtures for the zip64 / descriptor / extra-field / reader2 tests.

Oracle: CPython's stdlib `zipfile` (plus `struct`/`zlib` for the few records
zipfile cannot emit itself). Run from the repository root:

    python3 tests/gen/zip_ext.py

Writes tests/fixtures/zip_ext/*.zip and tests/fixtures/zip_ext/manifest.tsv.
The manifest is produced by re-reading every archive with zipfile, so it is
the oracle the Rust tests compare against.
"""
import io
import os
import struct
import time
import zipfile
import zlib

OUT = os.path.join(os.path.dirname(__file__), "..", "fixtures", "zip_ext")
DATE = (2024, 5, 17, 12, 34, 56)


class NonSeekable(io.RawIOBase):
    """Write-only stream with no seek/tell, forcing data descriptors."""

    def __init__(self):
        self.buf = bytearray()

    def writable(self):
        return True

    def seekable(self):
        return False

    def write(self, b):
        self.buf += b
        return len(b)


def payload(seed, n):
    out = bytearray()
    x = seed & 0xFFFFFFFF
    words = [b"sediment ", b"zip64 ", b"descriptor ", b"\x00\x01\x02", b"lorem ", b"ipsum "]
    while len(out) < n:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out += words[x % len(words)]
        out.append(x & 0xFF)
    return bytes(out[:n])


def zinfo(name, method=zipfile.ZIP_DEFLATED):
    zi = zipfile.ZipInfo(name, DATE)
    zi.compress_type = method
    zi.external_attr = 0o100644 << 16
    zi.create_system = 3
    return zi


def write(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)


def build_zip(entries, stream=False, force_zip64=False, comment=b""):
    """entries: list of (ZipInfo, bytes)."""
    target = NonSeekable() if stream else io.BytesIO()
    with zipfile.ZipFile(target, "w") as zf:
        for zi, data in entries:
            if force_zip64:
                with zf.open(zi, "w", force_zip64=True) as w:
                    w.write(data)
            else:
                zf.writestr(zi, data)
        zf.comment = comment
    return bytes(target.buf if stream else target.getvalue())


# ---------------------------------------------------------------- crc forging

def _crc_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        t.append(c)
    return t


TABLE = _crc_table()


def forge_crc(data, target):
    """Return 4 bytes that, appended to `data`, make zlib.crc32 == target."""
    # Work backwards from the target register through four table steps.
    state = target ^ 0xFFFFFFFF
    idx = []
    for _ in range(4):
        hi = state >> 24
        k = next(i for i in range(256) if TABLE[i] >> 24 == hi)
        idx.append(k)
        state = ((state ^ TABLE[k]) << 8) & 0xFFFFFFFF
    idx.reverse()
    reg = zlib.crc32(data) ^ 0xFFFFFFFF
    out = bytearray()
    for k in idx:
        b = (reg ^ k) & 0xFF
        out.append(b)
        reg = (reg >> 8) ^ TABLE[k]
    assert zlib.crc32(data + bytes(out)) == target
    return bytes(out)


# ---------------------------------------------------------------- hand-built archives

def hand_zip(entries, comment=b"", prefix=b""):
    """entries: dicts with name, data(stored payload), method, flags, crc,
    usize, extra_local, extra_central, descriptor(bytes or None),
    local_zero (zero crc/sizes in local header)."""
    body = bytearray(prefix)
    central = bytearray()
    for e in entries:
        off = len(body) - len(prefix)
        lc, lcs, lus = (0, 0, 0) if e.get("local_zero") else (e["crc"], len(e["data"]), e["usize"])
        body += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, e["flags"], e["method"], 0x6000, 0x58B1,
                            lc, lcs, lus, len(e["name"]), len(e.get("extra_local", b"")))
        body += e["name"] + e.get("extra_local", b"") + e["data"]
        if e.get("descriptor") is not None:
            body += e["descriptor"]
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 0x0314, 20, e["flags"], e["method"], 0x6000,
                               0x58B1, e["crc"], len(e["data"]), e["usize"], len(e["name"]),
                               len(e.get("extra_central", b"")), 0, 0, 0, 0o100644 << 16, off)
        central += e["name"] + e.get("extra_central", b"")
    cd_off = len(body) - len(prefix)
    body += central
    body += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(central), cd_off,
                        len(comment)) + comment
    return bytes(body)


def stored_entry(name, data, descriptor=None, flags=0, **kw):
    e = dict(name=name, data=data, method=0, flags=flags, crc=zlib.crc32(data), usize=len(data))
    if descriptor is not None:
        e["flags"] |= 0x08
        e["descriptor"] = descriptor(e)
        e["local_zero"] = True
    e.update(kw)
    return e


def deflated_entry(name, raw, descriptor=None, flags=0, **kw):
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    data = co.compress(raw) + co.flush()
    e = dict(name=name, data=data, method=8, flags=flags | 0x02, crc=zlib.crc32(raw), usize=len(raw))
    if descriptor is not None:
        e["flags"] |= 0x08
        e["descriptor"] = descriptor(e)
        e["local_zero"] = True
    e.update(kw)
    return e


def desc32_nosig(e):
    return struct.pack("<III", e["crc"], len(e["data"]), e["usize"])


def desc32_sig(e):
    return struct.pack("<IIII", 0x08074B50, e["crc"], len(e["data"]), e["usize"])


def ex(id_, data):
    return struct.pack("<HH", id_, len(data)) + data


# ---------------------------------------------------------------- fixtures

def gen():
    os.makedirs(OUT, exist_ok=True)
    fixtures = {}

    small = [
        (zinfo("a.txt"), payload(1, 300)),
        (zinfo("stored.bin", zipfile.ZIP_STORED), payload(2, 200)),
        (zinfo("empty.txt"), b""),
        (zinfo("dir/", zipfile.ZIP_STORED), b""),
    ]

    # 1. force_zip64 on every entry, seekable: local zip64 extras, central plain.
    fixtures["zip64_forced.zip"] = build_zip(small, force_zip64=True, comment=b"forced zip64")

    # 2. Lowered limits: zip64 extras in the central directory (sizes and
    #    offsets) and the zip64 EOCD record + locator.
    saved = (zipfile.ZIP64_LIMIT, zipfile.ZIP_FILECOUNT_LIMIT)
    zipfile.ZIP64_LIMIT, zipfile.ZIP_FILECOUNT_LIMIT = 100, 2
    try:
        entries = [(zinfo("big%d.bin" % i, zipfile.ZIP_STORED if i % 2 else zipfile.ZIP_DEFLATED),
                    payload(10 + i, 150 + 40 * i)) for i in range(5)]
        fixtures["zip64_eocd.zip"] = build_zip(entries)
    finally:
        zipfile.ZIP64_LIMIT, zipfile.ZIP_FILECOUNT_LIMIT = saved

    # 3. Streamed (non-seekable): data descriptors with signature, 32-bit.
    fixtures["stream_desc.zip"] = build_zip(small + [(zinfo("big.txt"), payload(3, 5000))], stream=True)

    # 4. Streamed + force_zip64: descriptors with 64-bit sizes.
    fixtures["stream_desc64.zip"] = build_zip(small, stream=True, force_zip64=True)

    # 5. Hand-built descriptors without signature, including a CRC equal to
    #    the descriptor signature value (ambiguous layout).
    tricky = b"crc collides with signature "
    tricky += forge_crc(tricky, 0x08074B50)
    fixtures["desc_nosig.zip"] = hand_zip([
        stored_entry(b"one.txt", payload(4, 64), desc32_nosig),
        deflated_entry(b"two.txt", payload(5, 700), desc32_nosig),
        stored_entry(b"sigcrc.bin", tricky, desc32_nosig),
        stored_entry(b"sigcrc2.bin", tricky, desc32_sig),
        stored_entry(b"plain.txt", b"no descriptor here"),
    ])

    # 6. Unicode names: UTF-8 flag (zipfile native), plus CP437 raw names with
    #    Info-ZIP Unicode Path records (fresh and stale), and metadata extras.
    uni = build_zip([
        (zinfo("naïve.txt"), b"utf-8 flag set\n"),
        (zinfo("日本語/ファイル.txt", zipfile.ZIP_STORED), "こんにちは".encode()),
    ])
    fixtures["unicode_flag.zip"] = uni

    cp437_name = "café.txt".encode("cp437")
    stale_name = "résumé.txt".encode("cp437")
    up = ex(0x7075, b"\x01" + struct.pack("<I", zlib.crc32(cp437_name)) + "café.txt".encode())
    stale = ex(0x7075, b"\x01" + struct.pack("<I", 0xDEADBEEF) + "wrong.txt".encode())
    ut_local = ex(0x5455, struct.pack("<Biii", 7, 1700000000, 1700000100, 1600000000))
    ut_central = ex(0x5455, struct.pack("<Bi", 7, 1700000000))
    ux = ex(0x7875, b"\x01\x04" + struct.pack("<I", 1000) + b"\x02" + struct.pack("<H", 50))
    ft = lambda unix: unix * 10_000_000 + 116444736000000000
    ntfs = ex(0x000A, struct.pack("<I", 0) + struct.pack("<HH", 1, 24) +
              struct.pack("<QQQ", ft(1700000000) + 1234567, ft(1700000100), ft(1600000000)))
    unknown = ex(0xCAFE, b"opaque")
    fixtures["extras.zip"] = hand_zip([
        stored_entry(cp437_name, b"cp437 name with unicode path\n",
                     extra_local=up + ut_local, extra_central=up + ut_central + ux),
        stored_entry(stale_name, b"stale unicode path\n", extra_local=stale, extra_central=stale),
        deflated_entry(b"ntfs.txt", payload(6, 400), extra_local=ntfs + unknown, extra_central=ntfs + unknown),
    ], comment=b"extras")

    # 7. Encrypted entries (listing only): traditional and WinZip AES.
    enc_payload = bytes(range(12)) + b"ciphertext!!"
    aes_extra = ex(0x9901, struct.pack("<H", 2) + b"AE" + bytes([3]) + struct.pack("<H", 8))
    fixtures["encrypted.zip"] = hand_zip([
        dict(name=b"zipcrypto.txt", data=enc_payload, method=8, flags=0x01, crc=0x12345678, usize=40),
        dict(name=b"aes.txt", data=b"\x11" * 16 + b"\x22" * 2 + b"x" * 30 + b"\x33" * 10, method=99,
             flags=0x01, crc=0, usize=30, extra_local=aes_extra, extra_central=aes_extra),
        stored_entry(b"clear.txt", b"not encrypted\n"),
    ])

    # 8. Leading junk (SFX-style stub) before a classic and a zip64 archive.
    stub = b"MZ" + b"\x90" * 510
    fixtures["prefixed.zip"] = stub + build_zip(small)
    zipfile.ZIP64_LIMIT, zipfile.ZIP_FILECOUNT_LIMIT = 100, 2
    try:
        z = build_zip([(zinfo("p%d" % i), payload(20 + i, 250)) for i in range(3)])
    finally:
        zipfile.ZIP64_LIMIT, zipfile.ZIP_FILECOUNT_LIMIT = saved
    fixtures["prefixed_zip64.zip"] = stub + z

    manifest = ["#file\tidx\traw_hex\tname_hex\tfile_size\tcompress_size\tcrc\tmethod\tflags\theader_offset\tdata_crc\tdata_len"]
    for name in sorted(fixtures):
        data = fixtures[name]
        write(name, data)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for i, zi in enumerate(zf.infolist()):
                raw = zi.filename.encode("utf-8" if zi.flag_bits & 0x800 else "cp437")
                if zi.flag_bits & 0x1:
                    dcrc, dlen = "-", "-"
                else:
                    content = zf.read(zi)
                    dcrc, dlen = "%08x" % zlib.crc32(content), str(len(content))
                manifest.append("\t".join([
                    name, str(i), raw.hex(), zi.filename.encode().hex(), str(zi.file_size), str(zi.compress_size),
                    "%08x" % zi.CRC, str(zi.compress_type), str(zi.flag_bits), str(zi.header_offset), dcrc, dlen,
                ]))
    write("manifest.tsv", ("\n".join(manifest) + "\n").encode())


if __name__ == "__main__":
    gen()
