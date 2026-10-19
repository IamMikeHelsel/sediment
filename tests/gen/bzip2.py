#!/usr/bin/env python3
"""Generate bzip2 fixtures using Python's stdlib bz2 module as the oracle.

Writes tests/fixtures/bzip2/*.bz2 plus manifest.txt describing how to rebuild
each file's uncompressed content from small deterministic generators (shared
with tests/bzip2.rs), and bad_*.bz2 malformed cases.

Also verifies the Rust-encoded files rust_*.bz2 (written by
`BZIP2_REGEN=1 cargo test --test bzip2`) with bz2.decompress.

Manifest line: <file> <streams>, streams ';'-separated "level:pieces",
pieces ','-separated: rep.<byte>.<count> | lcg.<seed>.<n> | text.<seed>.<n>
| runs.<seed>.<n> | seq.<n> | empty
"""
import bz2
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "fixtures", "bzip2")

WORDS = [b"the", b"quick", b"brown", b"fox", b"jumps", b"over", b"lazy",
         b"dog", b"sediment", b"archive", b"bzip2", b"block", b"\n"]


def lcg_next(s):
    return (s * 1103515245 + 12345) & 0xFFFFFFFF


def piece(spec):
    parts = spec.split(".")
    kind = parts[0]
    if kind == "empty":
        return b""
    if kind == "rep":
        return bytes([int(parts[1])]) * int(parts[2])
    if kind == "seq":
        return bytes(i % 256 for i in range(int(parts[1])))
    seed, n = int(parts[1]), int(parts[2])
    s = seed
    out = bytearray()
    if kind == "lcg":
        for _ in range(n):
            s = lcg_next(s)
            out.append((s >> 16) & 0xFF)
        return bytes(out)
    if kind == "text":
        while len(out) < n:
            s = lcg_next(s)
            out += WORDS[(s >> 16) % len(WORDS)] + b" "
        return bytes(out[:n])
    if kind == "runs":
        while len(out) < n:
            s = lcg_next(s)
            b = (s >> 16) & 0xFF
            s = lcg_next(s)
            out += bytes([b]) * (1 + (s >> 16) % 600)
        return bytes(out[:n])
    raise ValueError(spec)


def streams(desc):
    res = []
    for st in desc.split(";"):
        level, pieces = st.split(":")
        res.append((int(level), b"".join(piece(p) for p in pieces.split(","))))
    return res


CASES = [
    ("empty_l9.bz2", "9:empty"),
    ("empty_l1.bz2", "1:empty"),
    ("one_byte.bz2", "9:rep.65.1"),
    ("run3.bz2", "9:rep.97.3"),
    ("run4.bz2", "9:rep.97.4"),
    ("run5.bz2", "9:rep.97.5"),
    ("run255.bz2", "9:rep.97.255"),
    ("run256.bz2", "9:rep.97.256"),
    ("run259.bz2", "9:rep.97.259"),
    ("run260.bz2", "9:rep.97.260"),
    ("run_mix.bz2", "9:rep.120.3,rep.121.4,rep.122.256,rep.119.511,rep.120.1,rep.0.1000,rep.255.300"),
    ("zeros_100k_l1.bz2", "1:rep.0.100000"),
    ("seq_1024.bz2", "9:seq.1024"),
    ("random_16k_l9.bz2", "9:lcg.1.16000"),
    ("random_16k_l1.bz2", "1:lcg.2.16000"),
    ("text_50k_l9.bz2", "9:text.3.50000"),
    ("text_300k_l1.bz2", "1:text.4.300000"),
    ("runs_200k_l1.bz2", "1:runs.5.200000"),
    ("multi_stream.bz2", "9:text.6.5000;1:lcg.7.1000;9:empty;5:rep.98.300"),
]


def main():
    os.makedirs(OUT, exist_ok=True)
    manifest = []
    valid = {}
    for name, desc in CASES:
        data = b"".join(bz2.compress(d, compresslevel=lv) for lv, d in streams(desc))
        assert bz2.decompress(data) == b"".join(d for _, d in streams(desc))
        valid[name] = data
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(data)
        manifest.append(f"{name} {desc}")
    with open(os.path.join(OUT, "manifest.txt"), "w") as f:
        f.write("\n".join(manifest) + "\n")

    good = valid["text_50k_l9.bz2"]
    small = valid["run_mix.bz2"]

    def flip(data, i, mask=0xFF):
        b = bytearray(data)
        b[i] ^= mask
        return bytes(b)

    bad = {
        "bad_empty.bz2": b"",
        "bad_signature.bz2": b"BZx" + small[3:],
        "bad_level.bz2": b"BZh0" + small[4:],
        "bad_truncated_header.bz2": b"BZh",
        "bad_truncated_mid.bz2": good[: len(good) // 2],
        "bad_truncated_end.bz2": small[:-1],
        "bad_block_magic.bz2": flip(small, 4),
        "bad_block_crc.bz2": flip(small, 10),
        "bad_randomized.bz2": flip(small, 14, 0x80),
        "bad_stream_crc.bz2": flip(small, len(small) - 1, 0x80),
        "bad_trailing_garbage.bz2": small + b"garbage",
        "bad_second_stream.bz2": small + b"BZh9" + b"\x00" * 12,
    }
    for name, data in bad.items():
        if name in ("bad_trailing_garbage.bz2", "bad_second_stream.bz2", "bad_randomized.bz2"):
            # Python ignores any undecodable data after a valid stream; we reject it.
            # Randomised blocks are valid legacy bzip2 that we do not support
            # (this tiny block is unaffected by derandomisation, so Python
            # accepts it).
            pass
        else:
            try:
                bz2.decompress(data)
                if data:
                    raise SystemExit(f"oracle accepted malformed {name}")
            except (OSError, EOFError, ValueError):
                pass
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(data)

    # Verify Rust-encoded outputs.
    checked = 0
    for name, desc in CASES:
        path = os.path.join(OUT, "rust_" + name)
        if not os.path.exists(path):
            continue
        expected = b"".join(d for _, d in streams(desc))
        with open(path, "rb") as f:
            got = bz2.decompress(f.read())
        if got != expected:
            raise SystemExit(f"Python bz2 decoded rust_{name} incorrectly")
        checked += 1
    total = sum(os.path.getsize(os.path.join(OUT, p)) for p in os.listdir(OUT))
    print(f"wrote {len(CASES)} oracle + {len(bad)} malformed fixtures; "
          f"verified {checked} rust_*.bz2 with Python bz2; total {total} bytes")
    if "--require-rust" in sys.argv and checked != len(CASES):
        raise SystemExit("missing rust_*.bz2 fixtures; run BZIP2_REGEN=1 cargo test --test bzip2")


if __name__ == "__main__":
    main()
