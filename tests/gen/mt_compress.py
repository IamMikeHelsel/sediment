#!/usr/bin/env python3
"""Verify the committed multithreaded-encoder fixtures with the Python stdlib.

The Rust test `tests/mt_compress.rs` writes `tests/fixtures/mt_compress/*`
(run `SEDIMENT_BLESS=1 cargo test --test mt_compress`); this script regenerates
the same input and checks that Python's `lzma` (liblzma) and `bz2` (libbz2)
decode the multi-block .xz and multi-stream .bz2 output to it. Stdlib only.
Usage: python3 -I tests/gen/mt_compress.py
"""
import bz2, lzma, pathlib, sys

WORDS = [b'sediment', b'archive', b'thread', b'block', b'pool', b'chunk', b'reset', b'dictionary',
         b'stream', b'parallel', b'the', b'of', b'and', b'a', b'to', b'in', b'is', b'xz', b'bzip2', b'7z']
MASK = (1 << 64) - 1

def mt_input(n=260_000):
    """Must match `mt_input()` in tests/mt_compress.rs."""
    x, out = 0x5EDD_1E47, bytearray()
    while len(out) < n:
        x = (x * 6364136223846793005 + 1442695040888963407) & MASK
        out += WORDS[(x >> 33) % len(WORDS)]
        out += b'\n' if (x >> 20) & 15 == 0 else b' '
    return bytes(out[:n])

def main():
    fx = pathlib.Path(__file__).resolve().parent.parent / 'fixtures' / 'mt_compress'
    data = mt_input()
    ok = True
    for name, dec in (('mt4.xz', lzma.decompress), ('mt4.bz2', bz2.decompress)):
        got = dec((fx / name).read_bytes())
        good = got == data
        ok &= good
        print(('ok   ' if good else 'FAIL ') + name)
    with lzma.open(fx / 'mt4.xz') as f:  # streaming reader walks every block and the index
        good = f.read() == data
        ok &= good
        print(('ok   ' if good else 'FAIL ') + 'mt4.xz (stream)')
    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main())
