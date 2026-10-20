#!/usr/bin/env python3
"""Oracle fixtures for zip -mm= methods and tar -mf=pax (Python stdlib only).

Writes tests/fixtures/zip_tar_write_methods/:
  payload.bin   deterministic payload shared by the Rust tests
  py_bzip2.zip  zipfile ZIP_BZIP2 of payload.bin
  py_lzma.zip   zipfile ZIP_LZMA of payload.bin (4-byte LZMA header + props)
  py_pax.tar    tarfile PAX_FORMAT with a >100-byte name, a non-ASCII name
                and a fractional mtime
Run: python3 -I tests/gen/zip_tar_write_methods.py
"""
import io, pathlib, tarfile, zipfile

OUT = pathlib.Path(__file__).resolve().parent.parent / 'fixtures' / 'zip_tar_write_methods'
OUT.mkdir(parents=True, exist_ok=True)

def payload():
    x, out = 12345, bytearray()
    for i in range(6000):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0x0F if i % 3 else 0x41 + (i % 7))
    return bytes(out) + b'sediment ' * 400

LONG = 'd' * 60 + '/' + 'L' * 120 + '.txt'
UNI = 'café-日本.txt'

def main():
    data = payload()
    (OUT / 'payload.bin').write_bytes(data)
    for name, method in (('py_bzip2.zip', zipfile.ZIP_BZIP2), ('py_lzma.zip', zipfile.ZIP_LZMA)):
        info = zipfile.ZipInfo('payload.bin', date_time=(2020, 1, 1, 0, 0, 0))
        info.compress_type = method
        with zipfile.ZipFile(OUT / name, 'w') as z:
            z.writestr(info, data)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as t:
        for n, d, mt in ((LONG, b'long\n', 1_600_000_000), (UNI, b'uni\n', 1_600_000_001), ('short.txt', b'ns\n', 1_600_000_002.5)):
            ti = tarfile.TarInfo(n)
            ti.size, ti.mtime, ti.mode = len(d), mt, 0o644
            t.addfile(ti, io.BytesIO(d))
    (OUT / 'py_pax.tar').write_bytes(buf.getvalue())

if __name__ == '__main__':
    main()
