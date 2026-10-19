#!/usr/bin/env python3
"""Generate PPMd oracle fixtures for tests/ppmd7.rs and tests/ppmd8.rs.

Python's stdlib has no PPMd codec, so the oracle is a pinned 7-Zip binary
(7zz, recorded by sha256 in the manifest).  This script only uses the Python
stdlib plus that external binary:

  python3 tests/gen/ppmd.py --7zz /path/to/7zz --out tests/fixtures/ppmd

It must be run inside a fresh scratch directory (it creates archives there).
Inputs come from a deterministic generator that tests/ppmd_support/mod.rs
re-implements in Rust, so only the packed streams are committed. Oracle used: 7-Zip (7zz) 26.04 arm64, sha256 in the
manifest. Note 7-Zip shrinks the PPMd memory size for small inputs, so the
manifest records the memory size actually stored in each archive.

For each case it builds a 7z (-m0=PPMd) or zip (-mm=PPMd) archive holding one
file, then cuts out the raw packed stream:
  * 7z: header compression off, single stream at offset 32 with length
    "Packed Size" from `7zz l -slt`.
  * zip: the local file data located with zipfile (includes the 2-byte PPMd
    header of APPNOTE 5.10).
"""
import argparse
import hashlib
import os
import struct
import subprocess
import sys
import zipfile
import zlib

MASK64 = (1 << 64) - 1


class Lcg:
    def __init__(self, seed):
        self.s = (seed * 0x9E3779B97F4A7C15 + 1) & MASK64

    def next(self):
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & MASK64
        return self.s >> 33


def gen_text(seed, n, vocab_size):
    """Word salad over a deterministic vocabulary."""
    r = Lcg(seed)
    letters = b"etaoinshrdlucmfwypvbgkjqxz"
    vocab = []
    for _ in range(vocab_size):
        ln = 1 + r.next() % 9
        vocab.append(bytes(letters[min(r.next() % 26, r.next() % 26)] for _ in range(ln)))
    out = bytearray()
    while len(out) < n:
        w = vocab[min(r.next() % vocab_size, r.next() % vocab_size)]
        out += w
        k = r.next() % 16
        if k == 0:
            out += b".\n"
        elif k == 1:
            out += b", "
        else:
            out += b" "
    return bytes(out[:n])


def gen_binary(seed, n):
    """Skewed binary: runs, small deltas and occasional full-range bytes."""
    r = Lcg(seed)
    out = bytearray()
    prev = 0
    while len(out) < n:
        k = r.next() % 8
        if k == 0:
            out += bytes([r.next() & 0xFF]) * (1 + r.next() % 20)
        elif k < 4:
            prev = (prev + (r.next() % 7) - 3) & 0xFF
            out.append(prev)
        else:
            out.append(r.next() & 0xFF)
    return bytes(out[:n])


def gen_cycle(seed, n):
    """All 256 byte values in a slowly mutating cycle."""
    r = Lcg(seed)
    out = bytearray()
    i = 0
    while len(out) < n:
        out.append((i + (r.next() % 3 if i % 97 == 0 else 0)) & 0xFF)
        i += 1
    return bytes(out[:n])


def make_input(kind, seed, n, param):
    if kind == "text":
        return gen_text(seed, n, param)
    if kind == "bin":
        return gen_binary(seed, n)
    if kind == "cycle":
        return gen_cycle(seed, n)
    raise ValueError(kind)


# name, container, kind, seed, size, param, order, mem-arg
CASES = [
    ("7z_text_o6", "7z", "text", 1, 6000, 200, 6, "16m"),
    ("7z_text_o2", "7z", "text", 2, 3000, 50, 2, "1m"),
    ("7z_text_o32", "7z", "text", 3, 9000, 300, 32, "16m"),
    ("7z_text_o3_mem64k", "7z", "text", 4, 40000, 300, 3, "64k"),
    ("7z_bin_o8", "7z", "bin", 5, 5000, 0, 8, "4m"),
    ("7z_cycle_o4", "7z", "cycle", 6, 3000, 0, 4, "1m"),
    ("7z_tiny_o6", "7z", "text", 7, 1, 10, 6, "16m"),
    ("7z_lowmem_o16", "7z", "text", 8, 120000, 40, 16, "64k"),
    ("7z_lowmem_bin_o5", "7z", "bin", 9, 20000, 0, 5, "64k"),
    ("zip_text_o6", "zip", "text", 11, 6000, 200, 6, "1m"),
    ("zip_text_o2", "zip", "text", 12, 3000, 50, 2, "1m"),
    ("zip_text_o16", "zip", "text", 13, 9000, 300, 16, "16m"),
    ("zip_bin_o8", "zip", "bin", 14, 5000, 0, 8, "2m"),
    ("zip_cycle_o4", "zip", "cycle", 15, 3000, 0, 4, "1m"),
    ("zip_small_o6", "zip", "text", 16, 300, 10, 6, "1m"),
    ("zip_lowmem_o16_restart", "zip", "text", 17, 120000, 40, 16, "1m"),
    ("zip_lowmem_o16_cut", "zip", "text", 18, 240000, 40, 16, "1m:x=9"),
    ("zip_lowmem_bin_o10_cut", "zip", "bin", 19, 30000, 0, 10, "1m:x=9"),
    ("zip_text_o8_cut", "zip", "text", 20, 5000, 100, 8, "1m:x=9"),
]


def run(args, cwd):
    subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.DEVNULL)


def packed_size_7z(exe, archive, cwd):
    out = subprocess.run([exe, "l", "-slt", archive], cwd=cwd, check=True,
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.startswith("Packed Size = ") and line[14:].strip():
            return int(line[14:])
    raise RuntimeError("no packed size")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--7zz", dest="exe", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    exe = os.path.abspath(a.exe)
    out_dir = os.path.abspath(a.out)
    os.makedirs(out_dir, exist_ok=True)
    work = os.getcwd()
    with open(exe, "rb") as f:
        exe_sha = hashlib.sha256(f.read()).hexdigest()
    manifest = ["# PPMd oracle fixtures generated by tests/gen/ppmd.py",
                "# oracle 7zz sha256 %s" % exe_sha,
                "# name container kind seed size param order mem restore input_crc32 stream_file"]
    for name, cont, kind, seed, size, param, order, mem in CASES:
        data = make_input(kind, seed, size, param)
        src = os.path.join(work, "in_" + name)
        with open(src, "wb") as f:
            f.write(data)
        if cont == "7z":
            arc = os.path.join(work, name + ".7z")
            run([exe, "a", "-t7z", "-m0=PPMd:o=%d:mem=%s" % (order, mem), "-mhc=off",
                 "-mtc=off", "-mta=off", "-mtm=off", "-ms=off", arc, src], work)
            psize = packed_size_7z(exe, arc, work)
            with open(arc, "rb") as f:
                raw = f.read()
            stream = raw[32:32 + psize]
            hdr_pos = raw.find(b"\x23\x03\x04\x01\x05", 32 + psize)
            assert hdr_pos > 0
            props = raw[hdr_pos + 5:hdr_pos + 10]
            assert props[0] == order, props
            memsize, = struct.unpack("<I", props[1:])
            restore = 0
        else:
            arc = os.path.join(work, name + ".zip")
            run([exe, "a", "-tzip", "-mm=PPMd:o=%d:mem=%s" % (order, mem), arc, src], work)
            with zipfile.ZipFile(arc) as z:
                info = z.infolist()[0]
                assert info.compress_type == 98, info.compress_type
                assert info.file_size == len(data)
                assert info.CRC == zlib.crc32(data)
            with open(arc, "rb") as f:
                raw = f.read()
            off = info.header_offset
            sig, = struct.unpack_from("<I", raw, off)
            assert sig == 0x04034B50
            nlen, xlen = struct.unpack_from("<HH", raw, off + 26)
            start = off + 30 + nlen + xlen
            stream = raw[start:start + info.compress_size]
            hdr, = struct.unpack_from("<H", stream, 0)
            assert (hdr & 15) + 1 == order
            memsize = ((hdr >> 4) & 0xFF) + 1
            restore = hdr >> 12
        fname = name + ".bin"
        with open(os.path.join(out_dir, fname), "wb") as f:
            f.write(stream)
        manifest.append("%s %s %s %d %d %d %d %d %d %08x %s" % (
            name, cont, kind, seed, size, param, order, memsize, restore,
            zlib.crc32(data), fname))
        print(name, len(stream), file=sys.stderr)
    with open(os.path.join(out_dir, "manifest.txt"), "w") as f:
        f.write("\n".join(manifest) + "\n")


if __name__ == "__main__":
    main()
