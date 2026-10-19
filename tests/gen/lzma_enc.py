#!/usr/bin/env python3
"""Verify the Rust-produced encoder fixtures in tests/fixtures/lzma_enc/ with
the Python stdlib `lzma` module (liblzma) as the oracle, and compare their
sizes with liblzma's own preset-6 output.

The fixtures are written by the Rust encoder:
    SEDIMENT_BLESS=1 cargo test --offline --test xz_encode
then checked here:
    python3 -I tests/gen/lzma_enc.py [CORPUS_FILE ...]

Every fixture must decompress (lzma.decompress, auto-detected .xz / .lzma)
to its input exactly; the .xz ones are also decoded with an explicit
FORMAT_XZ decompressor and must report the expected check type. Optional
CORPUS_FILE arguments are only compressed with Python preset 6 and reported,
for comparison with the Rust level-6 numbers (see the module docs).
Exits non-zero on any mismatch.
"""
import lzma
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")
ENC = os.path.join(ROOT, "lzma_enc")
LZ = os.path.join(ROOT, "lzma")


def compressible():
    # Must match `compressible()` in tests/common/mod.rs.
    return b"".join(b"sediment lzma fixture line %05d\n" % i for i in range(2000))


def read(path):
    with open(path, "rb") as f:
        return f.read()


text = read(os.path.join(LZ, "text.bin"))
random_data = read(os.path.join(LZ, "random.bin"))
INPUTS = {
    "empty": b"",
    "one": b"A",
    "text": text,
    "random": random_data,
    "comp": compressible(),
    # Must match `mixed()` in tests/xz_encode.rs.
    "mixed": text + random_data + random_data + compressible(),
}
CHECKS = {"none": lzma.CHECK_NONE, "crc32": lzma.CHECK_CRC32, "sha256": lzma.CHECK_SHA256}


def main():
    names = sorted(os.listdir(ENC))
    if not names:
        print("no fixtures; run SEDIMENT_BLESS=1 cargo test --test xz_encode", file=sys.stderr)
        return 1
    bad = 0
    for name in names:
        data = read(os.path.join(ENC, name))
        expected = INPUTS[name.split(".")[0]]
        try:
            got = lzma.decompress(data)
            if name.endswith(".xz"):
                d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
                got_xz = d.decompress(data)
                assert d.eof and not d.unused_data and got_xz == expected, "FORMAT_XZ mismatch"
                tag = name.split(".")[1]
                want = CHECKS.get(tag, lzma.CHECK_CRC64)
                assert d.check == want, f"check {d.check} != {want}"
            else:
                d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
                assert d.decompress(data) == expected and d.eof, "FORMAT_ALONE mismatch"
        except Exception as e:  # noqa: BLE001 - report and continue
            print(f"FAIL {name}: {e}")
            bad += 1
            continue
        if got != expected:
            print(f"FAIL {name}: output differs ({len(got)} vs {len(expected)} bytes)")
            bad += 1
            continue
        ref = len(lzma.compress(expected, preset=6)) if name.endswith(".xz") else len(
            lzma.compress(expected, format=lzma.FORMAT_ALONE, preset=6))
        print(f"ok   {name:24} {len(expected):7} -> {len(data):6}  (python preset 6: {ref})")
    for path in sys.argv[1:]:
        data = read(path)
        c = lzma.compress(data, preset=6)
        print(f"corpus {path}: {len(data)} -> {len(c)} ratio {len(c) / max(1, len(data)):.4f} (python preset 6)")
    print(f"{len(names) - bad}/{len(names)} fixtures verified by liblzma")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
