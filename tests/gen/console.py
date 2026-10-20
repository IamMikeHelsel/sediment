#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Corrupted-fixture set for tests/console_report.rs (Python stdlib oracle).

Writes into tests/fixtures/console/:
  good.zip    three members, deflate
  badcrc.zip  a.txt's CRC-32 flipped in the local and central headers
  trunc.zip   good.zip cut in half (no end of central directory)
  junk.zip    good.zip + 32 bytes of trailing data
  unsup.zip   a.txt's method set to 77 (unknown)
  notarc.bin  plain text
The 7z/encrypted fixtures and every golden *.stdout/*.stderr/*.code come
from tests/gen/console_oracle.sh (pinned 7zz), run after this script.
"""
import pathlib, struct, zipfile, zlib

OUT = pathlib.Path(__file__).resolve().parent.parent / 'fixtures' / 'console'
FILES = {'a.txt': b'hello sediment\n' * 20, 'bin/data.bin': bytes(range(256)) * 8, 'empty': b''}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    good = OUT / 'good.zip'
    with zipfile.ZipFile(good, 'w', zipfile.ZIP_DEFLATED) as z:
        for n, d in FILES.items():
            info = zipfile.ZipInfo(n, date_time=(2026, 10, 19, 12, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, d)
    b = good.read_bytes()
    crc = struct.pack('<I', zlib.crc32(FILES['a.txt']))
    assert b.count(crc) == 2
    (OUT / 'badcrc.zip').write_bytes(b.replace(crc, struct.pack('<I', zlib.crc32(FILES['a.txt']) ^ 0xDEADBEEF)))
    (OUT / 'trunc.zip').write_bytes(b[:len(b) // 2])
    (OUT / 'junk.zip').write_bytes(b + b'JUNKJUNK' * 4)
    u = bytearray(b)
    i = u.find(b'PK\x03\x04')
    u[i + 8:i + 10] = struct.pack('<H', 77)
    j = u.find(b'PK\x01\x02')
    u[j + 10:j + 12] = struct.pack('<H', 77)
    (OUT / 'unsup.zip').write_bytes(bytes(u))
    (OUT / 'notarc.bin').write_bytes(b'hello\n')


if __name__ == '__main__':
    main()
