#!/usr/bin/env python3
"""Independent model of the `sediment b` data generator (src/bench.rs,
`generate_bench_data`) using only the Python stdlib. Writes the CRC32 (zlib)
and length of the generated buffer for several (len, window, seed) cases to
tests/fixtures/bench/data_crc.txt; tests/bench.rs checks the Rust generator
reproduces them exactly, pinning the data stream across platforms/releases.

Usage: python3 tests/gen/bench_data.py
"""
import os
import zlib

M64 = (1 << 64) - 1
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "bench", "data_crc.txt")
CASES = [(1024, 4096, 1), (65536, 1 << 16, 0x5EDD1E47B3AC0001), (100000, 300, 0), (200000, 1 << 22, 42), (4096, 1, 7)]


class Rng:
    def __init__(self, seed):
        self.s = seed if seed else 0x9E3779B97F4A7C15

    def next(self):
        x = self.s
        x ^= x >> 12
        x ^= (x << 25) & M64
        x ^= x >> 27
        self.s = x
        return (x * 0x2545F4914F6CDD1D) & M64


def generate(n, window, seed):
    rng = Rng(seed)
    out = bytearray()
    while len(out) < n:
        r = rng.next()
        pos = len(out)
        if pos >= 16 and r & 1:
            limit = min(pos, window)
            max_bits = limit.bit_length()
            bits = 1 + (r >> 2) % max_bits
            dist = min(1 + ((r >> 16) & ((1 << bits) - 1)), limit)
            mlen = 2 + ((r >> 8) & 31)
            if (r >> 13) & 7 == 0:
                mlen += (r >> 40) & 0xFF
            mlen = min(mlen, n - pos)
            for i in range(mlen):
                out.append(out[pos + i - dist])
        else:
            run = 1 + ((r >> 2) & 15)
            for _ in range(min(run, n - pos)):
                x = rng.next()
                b = (x & 0xFF) & ((x >> 8) & 0xFF)
                out.append((ord("a") + b % 26) if x >> 63 == 0 else b)
    return bytes(out)


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", newline="\n") as f:
        for n, w, s in CASES:
            d = generate(n, w, s)
            f.write(f"{n} {w} {s} {zlib.crc32(d):08X}\n")


if __name__ == "__main__":
    main()
