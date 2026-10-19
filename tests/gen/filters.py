#!/usr/bin/env python3
"""Generate oracle fixtures for the BCJ / Delta filters.

Oracle: liblzma through Python's stdlib `lzma` module. Each input is
compressed in FORMAT_RAW with the chain [FILTER, LZMA2]; decompressing that
payload with [LZMA2] alone yields exactly the filter stage's output, which is
what the Rust tests compare against. Inputs are synthetic, seeded, and dense
in branch-instruction patterns so every conversion path is exercised.

Python's `lzma` does not expose the ARM64 (0x0A) or RISC-V (0x0B) filters.
For those, if an `xz` binary (XZ Utils >= 5.6) is on PATH it is used through
`subprocess` to produce the same [FILTER, LZMA2] raw payload; otherwise those
fixtures are left as previously committed.

Usage: python3 tests/gen/filters.py [OUT_DIR]
       python3 tests/gen/filters.py --stress DIR N   (large uncommitted set)
"""

import lzma
import os
import random
import shutil
import struct
import subprocess
import sys

LZMA2 = {"id": lzma.FILTER_LZMA2, "preset": 0}
LZMA2_DEC = {"id": lzma.FILTER_LZMA2, "dict_size": 1 << 24}

PY_IDS = {
    "x86": lzma.FILTER_X86,
    "powerpc": lzma.FILTER_POWERPC,
    "ia64": lzma.FILTER_IA64,
    "arm": lzma.FILTER_ARM,
    "armthumb": lzma.FILTER_ARMTHUMB,
    "sparc": lzma.FILTER_SPARC,
}
XZ_ONLY = {"arm64", "riscv"}


def stage(raw_payload):
    return lzma.decompress(raw_payload, format=lzma.FORMAT_RAW, filters=[LZMA2_DEC])


def xz_tool():
    path = shutil.which("xz")
    if not path:
        return None
    try:
        out = subprocess.run([path, "-H"], capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    if b"--riscv" not in out or b"--arm64" not in out:
        return None
    return path


def bcj_stage(arch, data, start, encoding):
    """Return the filter stage output (encode) or None if no oracle."""
    if not encoding:
        raise ValueError("oracle only encodes; decode is checked by inversion")
    if arch in PY_IDS:
        f = {"id": PY_IDS[arch]}
        if start:
            f["start_offset"] = start
        payload = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[f, LZMA2])
        return stage(payload)
    tool = xz_tool()
    if tool is None:
        return None
    opt = "--%s" % arch + ("=start=%d" % start if start else "")
    payload = subprocess.run(
        [tool, "--format=raw", opt, "--lzma2=preset=0", "-c"],
        input=data, capture_output=True, check=True,
    ).stdout
    return stage(payload)


def delta_stage(dist, data):
    payload = lzma.compress(
        data, format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_DELTA, "dist": dist}, LZMA2],
    )
    return stage(payload)


# ---------------------------------------------------------------- generators

def gen_x86(rng, n):
    out = bytearray()
    while len(out) < n:
        r = rng.random()
        if r < 0.35:
            op = rng.choice([0xE8, 0xE9])
            off = rng.randrange(-0x40000, 0x40000) & 0xFFFFFFFF
            out += bytes([op]) + struct.pack("<I", off)
        elif r < 0.45:
            # clusters of E8/E9 to exercise the history mask
            out += bytes(rng.choice([0xE8, 0xE9, 0x00, 0xFF, 0x90]) for _ in range(rng.randrange(1, 9)))
        elif r < 0.5:
            out += bytes([0xE8, rng.randrange(256), rng.randrange(256), rng.randrange(256), rng.choice([0, 0xFF, 0x7F, 0x80])])
        else:
            out += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 6)))
    return bytes(out[:n])


def word_stream(rng, n, make, endian="<"):
    out = bytearray()
    while len(out) < n:
        if rng.random() < 0.45:
            out += struct.pack(endian + "I", make(rng) & 0xFFFFFFFF)
        else:
            out += struct.pack(endian + "I", rng.getrandbits(32))
    return bytes(out[:n])


def gen_arm(rng, n):
    return word_stream(rng, n, lambda r: 0xEB000000 | r.getrandbits(24))


def gen_powerpc(rng, n):
    return word_stream(rng, n, lambda r: 0x48000000 | (r.getrandbits(24) << 2) | r.choice([1, 1, 1, 0, 3]), ">")


def gen_sparc(rng, n):
    def mk(r):
        c = r.random()
        if c < 0.4:
            return 0x40000000 | r.getrandbits(22)  # call, positive small
        if c < 0.8:
            return 0x7FC00000 | r.getrandbits(22)  # call, negative small
        return 0x40000000 | r.getrandbits(30)  # call, large (not converted)
    return word_stream(rng, n, mk, ">")


def gen_armthumb(rng, n):
    out = bytearray()
    while len(out) < n:
        c = rng.random()
        if c < 0.4:
            hi = 0xF000 | rng.getrandbits(11)
            lo = 0xF800 | rng.getrandbits(11)
            out += struct.pack("<HH", hi, lo)
        elif c < 0.5:
            out += struct.pack("<H", 0xF000 | rng.getrandbits(11))
        else:
            out += struct.pack("<H", rng.getrandbits(16))
    return bytes(out[:n])


def gen_arm64(rng, n):
    def mk(r):
        c = r.random()
        if c < 0.4:
            return 0x94000000 | r.getrandbits(26)  # BL
        if c < 0.7:
            imm = r.randrange(-(1 << 17), 1 << 17) & 0x1FFFFF  # in-range ADRP
        else:
            imm = r.getrandbits(21)  # any ADRP
        return 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | r.getrandbits(5)
    return word_stream(rng, n, mk)


def gen_ia64(rng, n):
    out = bytearray()
    while len(out) < n:
        bundle = rng.getrandbits(128)
        tmpl = rng.choice([0x10, 0x11, 0x12, 0x13, 0x16, 0x17, 0x18, 0x19, 0x1C, 0x1D, rng.randrange(32)])
        bundle = (bundle & ~0x1F) | tmpl
        for slot in range(3):
            if rng.random() < 0.6:
                pos = 5 + 41 * slot
                ins = (bundle >> pos) & ((1 << 41) - 1)
                ins &= ~(0xF << 37)
                ins |= 0x5 << 37
                ins &= ~(0x7 << 9)
                bundle &= ~(((1 << 41) - 1) << pos)
                bundle |= ins << pos
        out += bundle.to_bytes(16, "little")
    return bytes(out[:n])


def rv_auipc(rd, imm20):
    return 0x17 | (rd << 7) | ((imm20 & 0xFFFFF) << 12)


def rv_itype(rd, rs1, imm12, opcode=0x13, funct3=0):
    return opcode | (rd << 7) | (funct3 << 12) | (rs1 << 15) | ((imm12 & 0xFFF) << 20)


def gen_riscv(rng, n):
    out = bytearray()
    while len(out) < n:
        c = rng.random()
        if c < 0.2:
            rd = rng.choice([1, 5, 1, 5, 0, 2, 3, 7])
            imm = rng.getrandbits(21) & ~1
            ins = (0x6F | (rd << 7)
                   | (((imm >> 12) & 0xFF) << 12) | (((imm >> 11) & 1) << 20)
                   | (((imm >> 1) & 0x3FF) << 21) | (((imm >> 20) & 1) << 31))
            out += struct.pack("<I", ins)
        elif c < 0.45:
            rd = rng.choice([1, 3, 5, 6, 10, 15, 28, 31, 8, 9])
            rs1 = rd if rng.random() < 0.85 else rng.randrange(32)
            low = rng.choice([3, 3, 3, 1, 2, 0])
            second = rv_itype(rng.randrange(32), rs1, rng.getrandbits(12),
                              opcode=rng.choice([0x13, 0x03, 0x67, 0x23]) & ~3 | low,
                              funct3=rng.randrange(8))
            out += struct.pack("<II", rv_auipc(rd, rng.getrandbits(20)), second)
        elif c < 0.6:
            # AUIPC with rd = x0/x2, crafted to look like (or not like) a marker
            rd = rng.choice([0, 2, 2])
            hi = rng.getrandbits(20)
            if rng.random() < 0.7:
                hi = (hi & ~0x3) | 0x3  # bits 12..13 = 11
            ins = rv_auipc(rd, hi)
            out += struct.pack("<II", ins, rng.getrandbits(32))
        elif c < 0.7:
            # non-pair AUIPC immediately followed by a pair (exercises skips)
            out += struct.pack("<I", rv_auipc(rng.choice([1, 3, 5]), rng.getrandbits(20)))
            rd = rng.choice([6, 7])
            out += struct.pack("<II", rv_auipc(rd, rng.getrandbits(20)), rv_itype(rd, rd, rng.getrandbits(12)))
        elif c < 0.8:
            out += struct.pack("<H", rng.getrandbits(16))  # misalign by a halfword
        else:
            out += struct.pack("<I", rng.getrandbits(32))
    return bytes(out[:n])


GENERATORS = {
    "x86": gen_x86, "powerpc": gen_powerpc, "ia64": gen_ia64, "arm": gen_arm,
    "armthumb": gen_armthumb, "sparc": gen_sparc, "arm64": gen_arm64,
    "riscv": gen_riscv,
}
ALIGN = {"x86": 1, "powerpc": 4, "ia64": 16, "arm": 4, "armthumb": 2,
         "sparc": 4, "arm64": 4, "riscv": 2}


def cases(rng, size):
    """Yield (name, kind, param, input, filtered-or-None)."""
    for arch, gen in GENERATORS.items():
        data = gen(rng, size)
        for start in (0, 0x100000 * ALIGN[arch] + 0x400, 0xFFFFFF00 & ~(ALIGN[arch] - 1)):
            yield ("%s_%x" % (arch, start), "bcj:" + arch, start, data,
                   bcj_stage(arch, data, start, True))
        # tiny / odd sizes from the same stream
        for n in (0, 1, 4, 5, 7, 8, 9, 15, 16, 17, 33):
            small = data[:n]
            yield ("%s_len%d" % (arch, n), "bcj:" + arch, 0, small, bcj_stage(arch, small, 0, True))
    base = bytes(rng.getrandbits(8) for _ in range(size // 2))
    smooth = bytes(((i * 3) + (i >> 4)) & 0xFF for i in range(size // 2))
    for dist in (1, 2, 3, 4, 7, 16, 255, 256):
        yield ("delta_d%d" % dist, "delta", dist, base[: size // 4] + smooth[: size // 4],
               delta_stage(dist, base[: size // 4] + smooth[: size // 4]))


def write(out_dir, size, seed):
    os.makedirs(out_dir, exist_ok=True)
    rng = random.Random(seed)
    manifest = []
    for name, kind, param, data, filtered in cases(rng, size):
        if filtered is None:
            sys.stderr.write("skip %s (no oracle)\n" % name)
            continue
        assert len(filtered) == len(data)
        with open(os.path.join(out_dir, name + ".in"), "wb") as f:
            f.write(data)
        with open(os.path.join(out_dir, name + ".out"), "wb") as f:
            f.write(filtered)
        manifest.append("%s %s %d" % (name, kind, param))
    with open(os.path.join(out_dir, "manifest.txt"), "w") as f:
        f.write("# name kind param(start_offset|distance); NAME.in -> NAME.out (encoder)\n")
        f.write("\n".join(manifest) + "\n")


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--stress":
        out_dir, count = sys.argv[2], int(sys.argv[3])
        write(out_dir, 1 << 16, 0x5ED1 + count)
        return
    here = os.path.dirname(os.path.abspath(__file__))
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "fixtures", "filters")
    write(out_dir, 2048, 0x5ED1)


if __name__ == "__main__":
    main()
