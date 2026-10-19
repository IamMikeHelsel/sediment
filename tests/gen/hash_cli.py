#!/usr/bin/env python3
"""Generate fixtures for tests/cli_hash.rs using only the Python stdlib.

Oracles: zlib.crc32, hashlib (md5, sha1, sha224/256/384/512, sha3_256,
blake2s tree mode for BLAKE2sp), a bitwise CRC-64/XZ (ECMA-182 reflected,
polynomial 0xC96C5795D7870F42) and the spec-based XXH64 from
tests/gen/hashes.py. The script writes a small directory tree and the exact
expected stdout of `sediment h` for it, following the layout documented in
src/cli_hash.rs, so the Rust test is a byte-for-byte differential check.

Usage: python3 tests/gen/hash_cli.py
"""
import hashlib
import importlib.util
import os
import shutil
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "fixtures", "hash_cli")

_spec = importlib.util.spec_from_file_location("hashes_gen", os.path.join(HERE, "hashes.py"))
_hashes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_hashes)

TREE = {
    "a.txt": b"hello\n",
    "empty.bin": b"",
    "B upper.txt": b"x" * 1000,
    "sub/data.bin": _hashes.gen_bytes(70000),
    "sub/deeper/z.txt": b"The quick brown fox jumps over the lazy dog",
}

# (name, digest length, numeric)
METHODS = [
    ("CRC32", 4, True),
    ("CRC64", 8, True),
    ("XXH64", 8, True),
    ("MD5", 16, False),
    ("SHA1", 20, False),
    ("SHA224", 28, False),
    ("SHA256", 32, False),
    ("SHA384", 48, False),
    ("SHA512", 64, False),
    ("SHA3-256", 32, False),
    ("BLAKE2sp", 32, False),
]


def crc64_xz(data):
    crc = 0xFFFFFFFFFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xC96C5795D7870F42 if crc & 1 else crc >> 1
    return crc ^ 0xFFFFFFFFFFFFFFFF


def raw_digest(name, data):
    """Digest bytes as stored by Sediment (numeric checksums little-endian)."""
    if name == "CRC32":
        return zlib.crc32(data).to_bytes(4, "little")
    if name == "CRC64":
        return crc64_xz(data).to_bytes(8, "little")
    if name == "XXH64":
        return _hashes.xxh64(data).to_bytes(8, "little")
    if name == "BLAKE2sp":
        return bytes.fromhex(_hashes.blake2sp(data))
    algo = {"MD5": "md5", "SHA1": "sha1", "SHA224": "sha224", "SHA256": "sha256",
            "SHA384": "sha384", "SHA512": "sha512", "SHA3-256": "sha3_256"}[name]
    return hashlib.new(algo, data).digest()


def add(a, b):
    n = int.from_bytes(a, "little") + int.from_bytes(b, "little")
    return (n % (1 << (8 * len(a)))).to_bytes(len(a), "little")


def to_hex(d, numeric):
    return d[::-1].hex().upper() if numeric else d.hex()


def render(methods, rows):
    """rows: list of (name, data or None for directory)."""
    widths = [max(2 * ln, len(n)) for n, ln, _ in methods]
    out = []

    def line(s):
        out.append(s.rstrip() + "\n")

    line("".join(f"{n:<{w}} " for (n, _, _), w in zip(methods, widths)) + f"{'Size':>13}  Name")
    sep = "".join("-" * w + " " for w in widths) + "-" * 13 + "  " + "-" * 12
    line(sep)
    data_sum = [bytes(ln) for _, ln, _ in methods]
    name_sum = [bytes(ln) for _, ln, _ in methods]
    files = folders = total = 0
    for name, data in rows:
        cells = ""
        for i, ((m, _, num), w) in enumerate(zip(methods, widths)):
            if data is None:
                cells += " " * w + " "
            else:
                d = raw_digest(m, data)
                data_sum[i] = add(data_sum[i], d)
                cells += f"{to_hex(d, num):<{w}} "
            name_sum[i] = add(name_sum[i], raw_digest(m, name.encode()))
        if data is None:
            folders += 1
            line(cells + " " * 13 + "  " + name)
        else:
            files += 1
            total += len(data)
            line(cells + f"{len(data):>13}  " + name)
    line(sep)
    line("".join(f"{to_hex(d, num):<{w}} " for d, (_, _, num), w in zip(data_sum, methods, widths)) + f"{total:>13}")
    out.append("\n")
    multi = len(rows) != 1
    if multi:
        line(f"Folders: {folders}")
        line(f"Files: {files}")
    line(f"Size: {total}")
    out.append("\n")
    for i, (m, _, num) in enumerate(methods):
        label = f"{m:<6} for data:"
        line(f"{label:<29} {to_hex(data_sum[i], num)}")
        if multi:
            label = f"{m:<6} for data and names:"
            line(f"{label:<29} {to_hex(add(data_sum[i], name_sum[i]), num)}")
    return "".join(out)


def tree_rows(root):
    entries = {root: None}
    for rel, data in TREE.items():
        parts = rel.split("/")
        for k in range(1, len(parts)):
            entries[root + "/" + "/".join(parts[:k])] = None
        entries[root + "/" + rel] = data
    # fs_collect order: component-wise by raw bytes.
    return sorted(entries.items(), key=lambda kv: [p.encode() for p in kv[0].split("/")])


def main():
    tree = os.path.join(OUT, "tree")
    shutil.rmtree(tree, ignore_errors=True)
    for rel, data in TREE.items():
        p = os.path.join(tree, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
    by = {n: (n, ln, num) for n, ln, num in METHODS}
    outputs = {
        "expected_all.txt": render(METHODS, tree_rows("tree")),
        "expected_default.txt": render([by["CRC32"]], tree_rows("tree")),
        "expected_single.txt": render([by["SHA256"], by["CRC64"]], [("a.txt", TREE["a.txt"])]),
        "expected_empty.txt": render([by["MD5"]], [("empty.bin", b"")]),
    }
    for name, text in outputs.items():
        with open(os.path.join(OUT, name), "w", newline="\n") as f:
            f.write(text)
    # Per-method digests of every tree file, one line each: method name hex.
    with open(os.path.join(OUT, "digests.txt"), "w", newline="\n") as f:
        for rel, data in sorted(TREE.items()):
            for m, _, num in METHODS:
                f.write(f"{rel}\t{m}\t{to_hex(raw_digest(m, data), num)}\n")


if __name__ == "__main__":
    main()
