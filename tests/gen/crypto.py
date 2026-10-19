#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generate tests/fixtures/crypto/ using only the Python stdlib as oracle.

- hmac_sha1.txt      : hmac.new(key, data, sha1)
- pbkdf2_sha1.txt    : hashlib.pbkdf2_hmac('sha1', ...)
- winzip_kdf.txt     : WinZip AES key split of hashlib.pbkdf2_hmac('sha1', ..., 1000)
- sevenz_kdf.txt     : 7zAES key schedule over hashlib.sha256
- zipcrypto_*.zip    : ZipCrypto-encrypted archives built here and verified
                       by zipfile.ZipFile.read(pwd=...) (the stdlib decrypter)

Run: python3 tests/gen/crypto.py   (from the crate root)
"""
import hashlib
import hmac
import io
import os
import struct
import zipfile
import zlib

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "crypto")


def gen_bytes(n, seed=0x1234_5678):
    """Same LCG as gen_bytes in tests/crypto.rs."""
    out = bytearray()
    s = seed
    for _ in range(n):
        s = (s * 1103515245 + 12345) & 0xFFFFFFFF
        out.append(s >> 24)
    return bytes(out)


def hx(b):
    return b.hex() if b else "-"


def write(name, lines):
    with open(os.path.join(OUT, name), "w") as f:
        f.write("\n".join(lines) + "\n")


def gen_hmac():
    lines = ["# key data mac  (hex, '-' = empty)"]
    for kl in [0, 1, 20, 63, 64, 65, 100, 131]:
        for dl in [0, 1, 55, 56, 63, 64, 65, 200]:
            key = gen_bytes(kl, 1000 + kl)
            data = gen_bytes(dl, 2000 + dl)
            lines.append(f"{hx(key)} {hx(data)} {hmac.new(key, data, hashlib.sha1).hexdigest()}")
    write("hmac_sha1.txt", lines)


def gen_pbkdf2():
    lines = ["# password salt iterations dklen out"]
    cases = [
        (b"password", b"salt", 1, 20),
        (b"password", b"salt", 3, 41),
        (b"", b"", 1, 20),
        (b"", b"salt", 7, 1),
        (gen_bytes(64, 7), gen_bytes(16, 8), 10, 60),
        (gen_bytes(65, 9), gen_bytes(8, 10), 100, 66),
        (gen_bytes(200, 11), gen_bytes(32, 12), 5, 100),
        ("pässwörd€".encode(), b"\x00\x01\x02", 1000, 34),
    ]
    for pw, salt, it, dk in cases:
        out = hashlib.pbkdf2_hmac("sha1", pw, salt, it, dk)
        lines.append(f"{hx(pw)} {hx(salt)} {it} {dk} {out.hex()}")
    write("pbkdf2_sha1.txt", lines)


def gen_winzip():
    lines = ["# strength password salt aes_key mac_key verifier"]
    for strength, kl in [(1, 16), (2, 24), (3, 32)]:
        for pw in [b"secret", b"", "日本語パスワード".encode(), gen_bytes(80, strength)]:
            salt = gen_bytes(kl // 2, 300 + strength + len(pw))
            dk = hashlib.pbkdf2_hmac("sha1", pw, salt, 1000, 2 * kl + 2)
            lines.append(
                f"{strength} {hx(pw)} {salt.hex()} {dk[:kl].hex()} {dk[kl:2*kl].hex()} {dk[2*kl:].hex()}"
            )
    write("winzip_kdf.txt", lines)


def sevenz_key(pw_utf16, salt, power):
    if power == 0x3F:
        k = (salt + pw_utf16)[:32]
        return k + bytes(32 - len(k))
    h = hashlib.sha256()
    for i in range(1 << power):
        h.update(salt + pw_utf16 + struct.pack("<Q", i))
    return h.digest()


def gen_sevenz():
    lines = ["# password_utf8 salt power key"]
    pws = ["", "a", "password", "Ünïcödé", "emoji \U0001F600 pw", "x" * 40]
    salts = [b"", gen_bytes(8, 77), gen_bytes(16, 78)]
    for pw in pws:
        for salt in salts:
            for power in [0, 1, 4, 10, 0x3F]:
                key = sevenz_key(pw.encode("utf-16-le"), salt, power)
                lines.append(f"{hx(pw.encode())} {hx(salt)} {power} {key.hex()}")
    # One heavier case (2^16 rounds) for counter carry into the second byte.
    key = sevenz_key("sediment".encode("utf-16-le"), gen_bytes(16, 79), 16)
    lines.append(f"{'sediment'.encode().hex()} {gen_bytes(16, 79).hex()} 16 {key.hex()}")
    write("sevenz_kdf.txt", lines)


# --- ZipCrypto (APPNOTE 6.1) written independently here; zipfile is the oracle.

def _crc_step(crc, b):
    return zlib.crc32(bytes([b]), crc ^ 0xFFFFFFFF) ^ 0xFFFFFFFF


class ZipCryptoEnc:
    def __init__(self, pw):
        self.k = [0x12345678, 0x23456789, 0x34567890]
        for c in pw:
            self.update(c)

    def update(self, c):
        k = self.k
        k[0] = _crc_step(k[0], c)
        k[1] = ((k[1] + (k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k[2] = _crc_step(k[2], k[1] >> 24)

    def encrypt(self, data):
        out = bytearray()
        for p in data:
            t = (self.k[2] | 2) & 0xFFFF
            out.append(p ^ (((t * (t ^ 1)) >> 8) & 0xFF))
            self.update(p)
        return bytes(out)


def build_zip(name, plain, pw, method, use_descriptor, header_random):
    crc = zlib.crc32(plain)
    if method == 8:
        co = zlib.compressobj(9, zlib.DEFLATED, -15)
        body = co.compress(plain) + co.flush()
    else:
        body = plain
    dos_time = (13 << 11) | (37 << 5) | (42 // 2)
    dos_date = ((2026 - 1980) << 9) | (10 << 5) | 19
    flags = 0x0001 | (0x0008 if use_descriptor else 0)
    check = (dos_time >> 8) if use_descriptor else (crc >> 24)
    enc = ZipCryptoEnc(pw)
    payload = enc.encrypt(header_random + bytes([check])) + enc.encrypt(body)
    fname = name.encode()
    csize, usize = len(payload), len(plain)
    lh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, method, dos_time, dos_date,
                     0 if use_descriptor else crc, 0 if use_descriptor else csize,
                     0 if use_descriptor else usize, len(fname), 0)
    buf = io.BytesIO()
    buf.write(lh + fname + payload)
    if use_descriptor:
        buf.write(struct.pack("<IIII", 0x08074B50, crc, csize, usize))
    cd_off = buf.tell()
    cd = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, method, dos_time, dos_date,
                     crc, csize, usize, len(fname), 0, 0, 0, 0, 0, 0) + fname
    buf.write(cd)
    buf.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cd), cd_off, 0))
    data = buf.getvalue()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        assert zf.read(name, pwd=pw) == plain, name
        try:
            zf.read(name, pwd=pw + b"x")
            wrong_ok = True
        except (RuntimeError, zipfile.BadZipFile, zlib.error):
            wrong_ok = False
    return data, wrong_ok


def gen_zipcrypto():
    plain = b"".join(f"sediment zipcrypto line {i:04}\n".encode() for i in range(300))
    lines = ["# file password header_random(11) method descriptor"]
    for fname, pw, method, desc, seed in [
        ("zipcrypto_stored.zip", b"hunter2", 0, False, 1),
        ("zipcrypto_deflate.zip", b"correct horse", 8, False, 2),
        ("zipcrypto_descriptor.zip", "pässwörd".encode(), 0, True, 3),
    ]:
        rnd = gen_bytes(11, 500 + seed)
        data, _ = build_zip("data.txt", plain, pw, method, desc, rnd)
        with open(os.path.join(OUT, fname), "wb") as f:
            f.write(data)
        lines.append(f"{fname} {pw.hex()} {rnd.hex()} {method} {int(desc)}")
    write("zipcrypto.txt", lines)


def main():
    os.makedirs(OUT, exist_ok=True)
    gen_hmac()
    gen_pbkdf2()
    gen_winzip()
    gen_sevenz()
    gen_zipcrypto()


if __name__ == "__main__":
    main()
