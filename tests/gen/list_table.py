#!/usr/bin/env python3
"""Fixtures for the default `sediment l` table (tests/list_table.rs).

Python stdlib only. Writes tests/fixtures/list_table/{basic.zip,basic.tar}.
The expected `*.l.txt` outputs were captured with `TZ=UTC 7zz l <archive>`
(7-Zip 26.04 on sparky); the 7z case reuses tests/fixtures/sevenz_write/lzma2_solid_hc.7z.
"""
import io, pathlib, tarfile, zipfile

OUT = pathlib.Path(__file__).resolve().parent.parent / 'fixtures' / 'list_table'
OUT.mkdir(parents=True, exist_ok=True)
FILES = [
    ('dir/', None, (2024, 3, 5, 6, 7, 8)),
    ('dir/nested.txt', b'nested\n', (2024, 3, 5, 6, 7, 8)),
    ('a.txt', b'hello sediment\n' * 50, (2023, 12, 31, 23, 59, 58)),
    ('empty', b'', (2020, 1, 2, 3, 4, 6)),
    ('café.txt', 'unicode ok\n'.encode(), (2024, 3, 5, 6, 7, 8)),
    ('héllo_日本.txt', b'x' * 12345, (2024, 3, 5, 6, 7, 8)),
]

with zipfile.ZipFile(OUT / 'basic.zip', 'w', zipfile.ZIP_DEFLATED) as z:
    for name, data, dt in FILES:
        info = zipfile.ZipInfo(name, dt)
        info.create_system = 3
        if data is None:
            info.external_attr = (0o40755 << 16) | 0x10
            z.writestr(info, b'')
        else:
            info.external_attr = (0o100644 << 16)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)

import calendar
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as t:
    for name, data, dt in FILES:
        info = tarfile.TarInfo(name.rstrip('/'))
        info.mtime = calendar.timegm(dt + (0, 0, 0))
        info.uname = info.gname = ''
        if data is None:
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            t.addfile(info)
        else:
            info.mode = 0o644
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
(OUT / 'basic.tar').write_bytes(buf.getvalue())
