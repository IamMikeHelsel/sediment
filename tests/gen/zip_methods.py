#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fixtures for ZIP methods 93 (Zstandard) and 98 (PPMd var.I rev1).

Oracle: Python 3.14+ stdlib only (`zipfile.ZIP_ZSTANDARD`, `compression.zstd`).
PPMd zips come from the pinned 7zz (tests/gen/zip_methods_7z.sh), which stages
its input with `--stage`.

Usage (from the crate root):
  python3 -I tests/gen/zip_methods.py              # writes tests/fixtures/zip_methods/zstd*.zip + .slt.txt
  python3 -I tests/gen/zip_methods.py --stage DIR  # writes the input tree only
"""
import pathlib, sys, zipfile, zlib

def tree():
    return {'a.txt': b'hello sediment\n' * 50, 'bin/data.bin': bytes(range(256)) * 40,
            'empty': b'', 'deep/x/y/z.txt': b'nested\n', 'café.txt': 'unicode ok\n'.encode()}

def words(n=30000):
    """Deterministic pseudo-text (LCG word picks) so the encoder emits real sequences."""
    vocab = b'the of and archive stream sediment block window literal match offset frame zip entry'.split()
    x, out = 12345, []
    while sum(len(w) + 1 for w in out) < n:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(vocab[x % len(vocab)] + (b'%d' % (x % 97) if x % 5 == 0 else b''))
    return b' '.join(out) + b'\n'

def stage(root):
    for n, d in {**tree(), 'words.txt': words()}.items():
        p = root / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(d)

def slt(files):
    """Minimal `7z l -slt`-style listing: Path / Size / CRC per file."""
    out = ['----------']
    for n, d in files.items():
        out.append(f'Path = {n}\nSize = {len(d)}\nAttributes = A\nCRC = {zlib.crc32(d):08X}\n')
    return '\n'.join(out)

def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--stage':
        stage(pathlib.Path(sys.argv[2]))
        return
    out = pathlib.Path(__file__).resolve().parents[1] / 'fixtures/zip_methods'
    out.mkdir(parents=True, exist_ok=True)
    for name, level in (('zstd', 3), ('zstd_l19', 19)):
        files = tree() if name == 'zstd' else {**tree(), 'words.txt': words()}
        arc = out / f'{name}.zip'
        with zipfile.ZipFile(arc, 'w', zipfile.ZIP_ZSTANDARD, compresslevel=level) as z:
            for n, d in files.items():
                zi = zipfile.ZipInfo(n, date_time=(2024, 3, 5, 6, 7, 8))
                z.writestr(zi, d, compress_type=zipfile.ZIP_ZSTANDARD, compresslevel=level)
        with zipfile.ZipFile(arc) as z:
            assert all(i.compress_type == 93 for i in z.infolist())
            assert {i.filename: z.read(i) for i in z.infolist()} == files
        (out / f'{name}.slt.txt').write_text(slt(files))

if __name__ == '__main__':
    main()
