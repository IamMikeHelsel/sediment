#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Oracle for Sediment archive *creation* (zip_create / tar_create / compress_wrap).

Python stdlib only (zipfile, tarfile, gzip, zlib).

  python3 tests/gen/create.py spec            # write tests/fixtures/create/spec.tsv
  SEDIMENT_REGEN=1 cargo test --test create_fixtures   # Rust writes the archives
  python3 tests/gen/create.py check [DIR]     # verify archives in DIR against spec.tsv

spec.tsv lines: kind<TAB>mode(octal)<TAB>mtime<TAB>name(hex)<TAB>payload(hex)
kind is F (file, payload = data), D (directory), L (symlink, payload = target).
Entries are listed in Sediment's canonical order (component-wise byte sort).

`check` also accepts a directory of archives produced by `sediment a` from the
same tree (used by the Rust tests): every *.zip, *.tar, *.tar.gz, *.tgz in DIR is
verified against DIR/spec.tsv.
"""
import datetime
import gzip
import io
import os
import sys
import tarfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.normpath(os.path.join(HERE, "..", "fixtures", "create"))


def lcg_bytes(n, seed=12345):
    out = bytearray()
    x = seed
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def text_bytes():
    words = ["sediment", "archive", "layer", "stone", "river", "delta", "silt", "clay"]
    lines = []
    for i in range(200):
        lines.append(f"line {i:04d}: {words[i % 8]} {words[(i * 3) % 8]} {words[(i * 5) % 8]} deposit\n")
    return "".join(lines).encode()


T = 1_600_000_000  # 2020-09-13T12:26:40Z


def build_spec():
    d60 = "d" * 60
    e60 = "e" * 60
    long_split = f"long/{d60}/{e60}/{'f' * 60}/file.txt"  # 196 bytes: ustar prefix split
    long_comp = "long/" + "x" * 120 + ".txt"  # component > 100: needs pax path
    deep = "long/deep/" + "/".join(["seg%02d" % i + "z" * 20 for i in range(12)])  # > 256
    spec = [
        ("D", 0o755, T, "a_dir", b""),
        ("D", 0o700, T, "a_dir/empty", b""),
        ("F", 0o644, T, "a_dir/random.bin", lcg_bytes(2048)),
        ("F", 0o644, T + 1, "a_dir/text.txt", text_bytes()),
        ("F", 0o755, T, "a_dir/tool.sh", b"#!/bin/sh\necho hi\n"),
        ("F", 0o600, T, "a_dir/zero.bin", b""),
        ("L", 0o777, T, "link_long", (deep + "/x.txt").encode()),
        ("L", 0o777, T, "link_to_text", b"a_dir/text.txt"),
        ("D", 0o755, T, "long", b""),
        ("D", 0o755, T, f"long/{d60}", b""),
        ("D", 0o755, T, f"long/{d60}/{e60}", b""),
        ("D", 0o755, T, f"long/{d60}/{e60}/{'f' * 60}", b""),
        ("F", 0o644, T, long_split, b"split\n"),
        ("D", 0o755, T, "long/deep", b""),
    ]
    acc = "long/deep"
    for i in range(12):
        acc += "/" + "seg%02d" % i + "z" * 20
        spec.append(("D", 0o755, T, acc, b""))
    spec += [
        ("F", 0o644, T, deep + "/x.txt", b"deep file\n"),
        ("F", 0o644, T, long_comp, b"long component\n"),
        ("F", 0o644, 0, "old.txt", b"epoch mtime\n"),
        ("F", 0o644, 8589934592 + 6, "future.txt", b"far future mtime (pax)\n"),
        ("D", 0o755, T, "ünïcødé", b""),
        ("F", 0o644, T, "ünïcødé/日本語.txt", "こんにちは\n".encode()),
    ]
    spec.sort(key=lambda e: e[3].encode().split(b"/"))
    return spec


def write_spec(path):
    with open(path, "w", encoding="ascii", newline="\n") as f:
        for kind, mode, mtime, name, payload in build_spec():
            f.write(f"{kind}\t{mode:o}\t{mtime}\t{name.encode().hex()}\t{payload.hex()}\n")


def read_spec(path):
    out = []
    with open(path, encoding="ascii") as f:
        for line in f:
            kind, mode, mtime, name, payload = line.rstrip("\n").split("\t")
            out.append((kind, int(mode, 8), int(mtime), bytes.fromhex(name).decode("utf-8"), bytes.fromhex(payload)))
    return out


def dos_tuple(mtime):
    lo = 315532800
    hi = 4354819198
    t = min(max(mtime, lo), hi)
    d = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=t)
    return (d.year, d.month, d.day, d.hour, d.minute, d.second // 2 * 2)


def fail(msg):
    raise AssertionError(msg)


def check_zip(path, spec, expect_store):
    with zipfile.ZipFile(path) as z:
        if z.testzip() is not None:
            fail(f"{path}: CRC failure")
        infos = z.infolist()
        want = [e for e in spec if e[0] != "L"]
        names = [i.filename for i in infos]
        exp = [e[3] + ("/" if e[0] == "D" else "") for e in want]
        if names != exp:
            fail(f"{path}: names {names} != {exp}")
        for info, (kind, mode, mtime, name, payload) in zip(infos, want):
            if (info.external_attr >> 16) & 0o7777 != mode:
                fail(f"{path}: {name}: mode {oct(info.external_attr >> 16)}")
            if info.date_time != dos_tuple(mtime):
                fail(f"{path}: {name}: date_time {info.date_time} != {dos_tuple(mtime)}")
            if not name.isascii() and not info.flag_bits & 0x800:
                fail(f"{path}: {name}: UTF-8 flag missing")
            if kind == "D":
                if not info.is_dir() or info.file_size != 0:
                    fail(f"{path}: {name}: not a directory")
                continue
            if z.read(info) != payload:
                fail(f"{path}: {name}: data mismatch")
            if expect_store and info.compress_type != zipfile.ZIP_STORED:
                fail(f"{path}: {name}: expected stored")
            if info.compress_type == zipfile.ZIP_DEFLATED and info.compress_size >= info.file_size:
                fail(f"{path}: {name}: deflate did not shrink")
            if not expect_store and name.endswith("text.txt") and info.compress_type != zipfile.ZIP_DEFLATED:
                fail(f"{path}: {name}: compressible text was stored")
            if name.endswith("random.bin") and info.compress_type != zipfile.ZIP_STORED:
                fail(f"{path}: {name}: incompressible data should be stored")


def check_tar(path, spec):
    with tarfile.open(path) as t:
        members = t.getmembers()
        names = [m.name for m in members]
        exp = [e[3] for e in spec]
        if names != exp:
            fail(f"{path}: names {names} != {exp}")
        for m, (kind, mode, mtime, name, payload) in zip(members, spec):
            if m.mode != mode:
                fail(f"{path}: {name}: mode {oct(m.mode)} != {oct(mode)}")
            if m.mtime != mtime:
                fail(f"{path}: {name}: mtime {m.mtime} != {mtime}")
            if m.uid != 0 or m.gid != 0:
                fail(f"{path}: {name}: uid/gid")
            if kind == "D":
                if not m.isdir():
                    fail(f"{path}: {name}: not dir")
            elif kind == "L":
                if not m.issym() or m.linkname.encode() != payload:
                    fail(f"{path}: {name}: bad symlink {m.linkname!r}")
            else:
                if not m.isfile() or t.extractfile(m).read() != payload:
                    fail(f"{path}: {name}: data mismatch")
    with open(path, "rb") as f:
        raw = f.read()
    if path.endswith((".gz", ".tgz")):
        raw = gzip.decompress(raw)
    if len(raw) % 10240 != 0:
        fail(f"{path}: not padded to a 10240-byte record")


def check_dir(d):
    spec = read_spec(os.path.join(d, "spec.tsv"))
    checked = 0
    for fn in sorted(os.listdir(d)):
        p = os.path.join(d, fn)
        if fn.endswith(".zip"):
            check_zip(p, spec, expect_store="store" in fn)
        elif fn.endswith((".tar", ".tar.gz", ".tgz")):
            check_tar(p, spec)
        else:
            continue
        checked += 1
        print(f"ok {fn}")
    if checked == 0:
        fail(f"no archives in {d}")
    # Cross-check: gzip members decompress to the plain tar fixture.
    plain = os.path.join(d, "create.tar")
    if os.path.exists(plain):
        with open(plain, "rb") as f:
            tar_bytes = f.read()
        for fn in sorted(os.listdir(d)):
            if fn.endswith((".tar.gz", ".tgz")):
                with open(os.path.join(d, fn), "rb") as f:
                    if gzip.decompress(f.read()) != tar_bytes:
                        fail(f"{fn}: does not decompress to create.tar")
    print(f"checked {checked} archives")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "spec":
        os.makedirs(FIX, exist_ok=True)
        write_spec(os.path.join(FIX, "spec.tsv"))
    elif cmd == "check":
        check_dir(sys.argv[2] if len(sys.argv) > 2 else FIX)
    else:
        sys.exit("usage: create.py spec|check [DIR]")


if __name__ == "__main__":
    main()
