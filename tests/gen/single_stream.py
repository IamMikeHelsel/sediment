#!/usr/bin/env python3
"""Fixtures for .lzma / .lzma86 / .tar.lzma / .Z single-stream reading.

Oracle: Python stdlib `lzma` (FORMAT_ALONE, and FORMAT_RAW with the x86 BCJ
filter to produce the .lzma86 payload). The `.Z` fixture comes from the
system `compress` tool (no stdlib encoder exists); its plain text is
`payload.bin`. Run from the repo root.
"""
import io, lzma, pathlib, shutil, subprocess, tarfile

out = pathlib.Path('tests/fixtures/single_stream')
out.mkdir(parents=True, exist_ok=True)
payload = b'hello sediment\n' * 50 + bytes(range(256)) * 8 + bytes([0xE8, 1, 2, 3, 4, 0xE9, 0, 0, 0, 0]) * 100
(out / 'payload.bin').write_bytes(payload)
(out / 'payload.bin.lzma').write_bytes(lzma.compress(payload, format=lzma.FORMAT_ALONE))
raw = lzma.compress(payload, format=lzma.FORMAT_RAW, filters=[{'id': lzma.FILTER_X86}, {'id': lzma.FILTER_LZMA1}])
bcj = lzma.decompress(raw, format=lzma.FORMAT_RAW, filters=[{'id': lzma.FILTER_LZMA1}])
alone = bytearray(lzma.compress(bcj, format=lzma.FORMAT_ALONE))
(out / 'payload.bin.lzma86').write_bytes(b'\x01' + alone)
tb = io.BytesIO()
with tarfile.open(fileobj=tb, mode='w', format=tarfile.USTAR_FORMAT) as tf:
    for n, d in (('a.txt', b'alpha\n' * 20), ('dir/b.bin', bytes(range(200)))):
        i = tarfile.TarInfo(n); i.size = len(d); i.mtime = 0; tf.addfile(i, io.BytesIO(d))
(out / 'two.tlz').write_bytes(lzma.compress(tb.getvalue(), format=lzma.FORMAT_ALONE))
if shutil.which('compress'):
    (out / 'payload.bin.Z').write_bytes(subprocess.run(['compress', '-c'], input=payload, capture_output=True, check=True).stdout)
