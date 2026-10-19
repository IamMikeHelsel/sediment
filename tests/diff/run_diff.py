#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Differential harness: Sediment vs the pinned 7-Zip 26.04 oracle (`7zz`).

The oracle is only run as an external CLI; no 7-Zip code is part of
Sediment. Python stdlib only.

Two modes:

  python3 tests/diff/run_diff.py [--host sync-sparky-local] [--report R.md]
      Driver (default). Ships the working tree (tracked + untracked, not
      ignored) to HOST over ssh into a `mktemp -d` scratch dir, runs this
      script there in --run mode, copies the markdown report back to R
      (default: stdout) and removes the scratch dir. Sediment is rebuilt
      from scratch in the scratch dir every run (about 3 s on sparky; a
      shared target dir is deliberately not used because extracted mtimes
      could make cargo reuse a stale binary).

  python3 -I tests/diff/run_diff.py --run --oracle PATH/7zz [--work DIR]
      Runs locally: builds `sediment` (cargo build --release --offline),
      builds the corpus with Python (zip/tar/gz/bz2/xz/lzma) and with the
      oracle (7z/zip/tar/gz/bz2/xz with various methods), then for every
      archive compares
        * `7zz l -slt` with `sediment l -slt` (falls back to the
          `sediment l` table while -slt is not implemented): entry paths,
          kinds, sizes and CRC32s;
        * `7zz x` with `sediment x`: extracted file trees (paths, kinds,
          bytes, symlink targets, mtimes, permission bits);
        * `7zz t` with `sediment t` on damaged copies (truncated, bit
          flipped): both must reject or both accept; sediment must never
          crash.
      Writes a markdown report; exit status 1 when any mismatch is found.

Other switches: --only REGEX (subset of corpus names), --keep (keep scratch
dir), --sediment BIN (skip the cargo build), --jobs N.

Expected semantic differences that are normalized rather than reported:
  * `.tar.gz`/`.tgz`/`.tar.bz2`/`.tar.xz`/...: 7-Zip opens the outer stream
    (one member `x.tar`); Sediment opens the tar inside. The oracle side is
    the two-step `7zz x outer` then `7zz l/x inner.tar`.
  * Sediment skips symbolic links unless `-snl` is given; both tools are
    run with `-snl`.
"""
import argparse
import bz2
import concurrent.futures
import gzip
import hashlib
import io
import lzma
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
CRATE = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_HOST = "sync-sparky-local"
DEFAULT_ORACLE = "/home/mike/sediment-rust-20261019/reference/7zz"
ORACLE_VERSION = "7-Zip (z) 26.04"
MTIME = 1709618828  # 2024-03-05 06:07:08 UTC
DT = (2024, 3, 5, 6, 7, 8)
CMD_TIMEOUT = 120
COMPRESSED_TAR = (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tbz", ".tar.xz", ".txz")

# ---------------------------------------------------------------------------
# Driver mode
# ---------------------------------------------------------------------------


def git_files(root):
    out = subprocess.run(
        ["git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        check=True, capture_output=True,
    ).stdout
    return [p for p in out.decode().split("\0") if p and os.path.isfile(os.path.join(root, p))]


def crate_tarball(root):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=1) as tf:
        for p in git_files(root):
            tf.add(os.path.join(root, p), arcname=p, recursive=False)
    return buf.getvalue()


def drive(args):
    blob = crate_tarball(CRATE)
    rev = subprocess.run(["git", "-C", CRATE, "describe", "--always", "--dirty"], capture_output=True).stdout.decode().strip()
    passthru = ["--rev", rev or "?"]
    if args.only:
        passthru += ["--only", args.only]
    if args.jobs:
        passthru += ["--jobs", str(args.jobs)]
    keep = "1" if args.keep else ""
    remote = (
        "set -e; D=$(mktemp -d /tmp/sediment-difftest.XXXXXX); "
        "tar -xzmf - -C \"$D\"; cd \"$D\"; "
        "rc=0; python3 -I tests/diff/run_diff.py --run --work \"$D/work\" "
        f"--oracle {shlex.quote(args.oracle)} --report \"$D/report.md\" "
        f"{' '.join(shlex.quote(a) for a in passthru)} >&2 || rc=$?; "
        "cat \"$D/report.md\" 2>/dev/null || true; "
        f"if [ -z '{keep}' ]; then rm -rf \"$D\"; else echo \"kept $D\" >&2; fi; exit $rc"
    )
    t0 = time.time()
    p = subprocess.run(["ssh", args.host, remote], input=blob, stdout=subprocess.PIPE)
    report = p.stdout.decode("utf-8", "replace")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"report: {args.report} (remote exit {p.returncode}, {time.time() - t0:.0f}s)", file=sys.stderr)
    else:
        sys.stdout.write(report)
    return p.returncode


# ---------------------------------------------------------------------------
# Deterministic input tree
# ---------------------------------------------------------------------------


def lcg_bytes(n, seed):
    out = bytearray()
    x = seed
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def prog_bytes(n):
    out = bytearray()
    i = 0
    while len(out) < n:
        out += b"\x55\x48\x89\xe5\xe8" + ((0x100 + i * 0x40) & 0xFFFFFFFF).to_bytes(4, "little") + b"\x90\x90\xc3"
        i += 1
    return bytes(out[:n])


def words(n, seed):
    vocab = [b"sediment", b"archive", b"stream", b"block", b"window", b"literal", b"match", b"header",
             b"zip", b"tar", b"7z", b"lzma", b"bzip2", b"delta", b"filter", b"\n"]
    out = bytearray()
    x = seed
    while len(out) < n:
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out += vocab[(x >> 16) % len(vocab)] + b" "
    return bytes(out[:n])


# (relative path, bytes). Directories listed separately so empty ones exist.
TREE_FILES = [
    ("hello.txt", b"Hello, Sediment!\n"),
    ("empty.txt", b""),
    ("with space.txt", b"spaces in names\n"),
    ("data/random.bin", lcg_bytes(70000, 7)),
    ("data/zeros.bin", bytes(300000)),
    ("data/words.txt", words(120000, 3)),
    ("data/prog.bin", prog_bytes(40000)),
    ("docs/readme.md", b"# Readme\n\n" + words(3000, 11)),
    ("docs/café 文.txt", "unicode name é文\n".encode()),
    ("docs/deep/nested/leaf.txt", b"leaf\n"),
    ("docs/deep/nested/" + "long_" * 30 + ".txt", b"long name\n"),
]
TREE_DIRS = ["data", "docs", "docs/deep", "docs/deep/nested", "emptydir"]
EXEC_FILE = "data/prog.bin"


def stage_tree(root):
    for d in TREE_DIRS:
        os.makedirs(os.path.join(root, d), exist_ok=True)
    for p, b in TREE_FILES:
        fp = os.path.join(root, p)
        with open(fp, "wb") as f:
            f.write(b)
        os.chmod(fp, 0o755 if p == EXEC_FILE else 0o644)
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        for n in filenames + dirnames:
            os.utime(os.path.join(dirpath, n), (MTIME, MTIME))
        os.chmod(dirpath, 0o755)
        os.utime(dirpath, (MTIME, MTIME))


def stage_links(root):
    os.makedirs(os.path.join(root, "sub"), exist_ok=True)
    with open(os.path.join(root, "target.txt"), "wb") as f:
        f.write(b"link target\n")
    os.symlink("../target.txt", os.path.join(root, "sub", "up.txt"))
    os.symlink("target.txt", os.path.join(root, "same.txt"))
    for p in ("target.txt", "sub/up.txt", "same.txt", "sub", "."):
        os.utime(os.path.join(root, p), (MTIME, MTIME), follow_symlinks=False)


# ---------------------------------------------------------------------------
# Python-made corpus
# ---------------------------------------------------------------------------


def walk_tree(root):
    """Sorted (relpath, is_dir) under root, directories before contents."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        rel = os.path.relpath(dirpath, root)
        if rel != ".":
            out.append((rel, True))
        for n in sorted(filenames):
            out.append((os.path.normpath(os.path.join(rel, n)), False))
    return out


def py_zip(path, tree, compression, level=None, dirs=True, descriptor=False, zip64=False):
    raw = io.BytesIO()

    class NoSeek(io.RawIOBase):
        def writable(self):
            return True

        def write(self, b):
            return raw.write(b)

    target = NoSeek() if descriptor else raw
    with zipfile.ZipFile(target, "w", compression=compression, compresslevel=level) as zf:
        for rel, is_dir in walk_tree(tree):
            if is_dir:
                if dirs:
                    zi = zipfile.ZipInfo(rel + "/", DT)
                    zi.external_attr = (0o40755 << 16) | 0x10
                    zf.writestr(zi, b"")
                continue
            with open(os.path.join(tree, rel), "rb") as f:
                data = f.read()
            zi = zipfile.ZipInfo(rel, DT)
            zi.compress_type = compression
            zi.external_attr = (0o100755 if rel == EXEC_FILE else 0o100644) << 16
            if zip64:
                with zf.open(zi, "w", force_zip64=True) as w:
                    w.write(data)
            else:
                zf.writestr(zi, data, compress_type=compression, compresslevel=level)
    with open(path, "wb") as f:
        f.write(raw.getvalue())


def py_tar_bytes(tree, fmt, links_tree=None):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:

        def norm(ti):
            ti.uid = ti.gid = 1000
            ti.uname = ti.gname = "sed"
            ti.mtime = MTIME
            return ti

        for rel, _ in walk_tree(tree):
            if fmt == tarfile.USTAR_FORMAT and (len(os.path.basename(rel)) > 100 or not rel.isascii()):
                continue  # not representable in plain ustar
            tf.add(os.path.join(tree, rel), arcname=rel, recursive=False, filter=norm)
        if links_tree:
            for rel in ("target.txt", "sub", "sub/up.txt", "same.txt"):
                tf.add(os.path.join(links_tree, rel), arcname="links/" + rel, recursive=False, filter=norm)
            hl = tarfile.TarInfo("links/hard.txt")
            hl.type = tarfile.LNKTYPE
            hl.linkname = "links/target.txt"
            hl.mtime = MTIME
            hl.mode = 0o644
            tf.addfile(norm(hl))
    return buf.getvalue()


def write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def gz_bytes(data, name=None, mtime=MTIME):
    buf = io.BytesIO()
    with gzip.GzipFile(filename=name or "", fileobj=buf, mode="wb", mtime=mtime) as g:
        g.write(data)
    return buf.getvalue()


def build_python_corpus(cdir, tree, links):
    """Returns the list of corpus file names created."""
    made = []

    def add(name, data=None):
        if data is not None:
            write(os.path.join(cdir, name), data)
        made.append(name)

    p = lambda n: os.path.join(cdir, n)  # noqa: E731
    py_zip(p("py_stored.zip"), tree, zipfile.ZIP_STORED); add("py_stored.zip")
    py_zip(p("py_deflate9.zip"), tree, zipfile.ZIP_DEFLATED, 9); add("py_deflate9.zip")
    py_zip(p("py_deflate1_nodirs.zip"), tree, zipfile.ZIP_DEFLATED, 1, dirs=False); add("py_deflate1_nodirs.zip")
    py_zip(p("py_bzip2.zip"), tree, zipfile.ZIP_BZIP2); add("py_bzip2.zip")
    py_zip(p("py_lzma.zip"), tree, zipfile.ZIP_LZMA); add("py_lzma.zip")
    py_zip(p("py_descriptor.zip"), tree, zipfile.ZIP_DEFLATED, 6, descriptor=True); add("py_descriptor.zip")
    py_zip(p("py_zip64.zip"), tree, zipfile.ZIP_DEFLATED, 6, zip64=True); add("py_zip64.zip")
    py_zip(p("py_stored_descriptor.zip"), tree, zipfile.ZIP_STORED, descriptor=True); add("py_stored_descriptor.zip")

    for fmt, n in ((tarfile.USTAR_FORMAT, "ustar"), (tarfile.GNU_FORMAT, "gnu"), (tarfile.PAX_FORMAT, "pax")):
        add(f"py_{n}.tar", py_tar_bytes(tree, fmt))
    links_tar = py_tar_bytes(tree, tarfile.PAX_FORMAT, links_tree=links)
    add("py_links.tar", links_tar)
    t = py_tar_bytes(tree, tarfile.PAX_FORMAT)
    add("py_tree.tar.gz", gz_bytes(t))
    add("py_tree.tgz", gz_bytes(t, mtime=0))
    add("py_tree.tar.bz2", bz2.compress(t, 9))
    add("py_tree.tar.xz", lzma.compress(t, preset=6))
    add("py_tree.txz", lzma.compress(t, check=lzma.CHECK_SHA256))
    add("py_links.tar.gz", gz_bytes(links_tar))

    words_b = dict(TREE_FILES)["data/words.txt"]
    rand = dict(TREE_FILES)["data/random.bin"]
    add("py_words.txt.gz", gz_bytes(words_b, name="words.txt"))
    add("py_noname.gz", gz_bytes(words_b, mtime=0))
    add("py_renamed.gz", gz_bytes(words_b, name="inner-name.txt"))
    add("py_multimember.gz", gz_bytes(words_b[:5000], name="mm.txt") + gz_bytes(words_b[5000:], name="mm.txt"))
    add("py_empty.gz", gz_bytes(b"", name="empty"))
    add("py_words.bz2", bz2.compress(words_b, 9))
    add("py_multistream.bz2", bz2.compress(words_b[:7000], 1) + bz2.compress(words_b[7000:], 9))
    add("py_random.bin.bz2", bz2.compress(rand, 1))
    for chk, n in ((lzma.CHECK_NONE, "none"), (lzma.CHECK_CRC32, "crc32"), (lzma.CHECK_CRC64, "crc64"), (lzma.CHECK_SHA256, "sha256")):
        add(f"py_words_{n}.xz", lzma.compress(words_b, check=chk))
    add("py_multistream.xz", lzma.compress(words_b[:9000]) + lzma.compress(words_b[9000:]))
    add("py_padded.xz", lzma.compress(words_b) + bytes(8))
    add("py_delta_x86.xz", lzma.compress(dict(TREE_FILES)["data/prog.bin"], filters=[
        {"id": lzma.FILTER_DELTA, "dist": 4}, {"id": lzma.FILTER_X86}, {"id": lzma.FILTER_LZMA2, "preset": 6}]))
    add("py_lzma1.xz", lzma.compress(words_b, format=lzma.FORMAT_XZ, filters=[{"id": lzma.FILTER_LZMA2, "preset": 1}]))
    add("py_words.lzma", lzma.compress(words_b, format=lzma.FORMAT_ALONE))

    # Edge-case containers.
    add("py_empty.zip", b"PK\x05\x06" + bytes(18))
    add("py_empty.tar", bytes(1024))
    add("py_empty10k.tar", bytes(10240))
    zc = io.BytesIO()
    with zipfile.ZipFile(zc, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.comment = b"archive comment"
        zi = zipfile.ZipInfo("note.txt", DT)
        zi.comment = b"entry comment"
        zf.writestr(zi, words_b[:3000])
    add("py_comment.zip", zc.getvalue())
    dot = io.BytesIO()
    with tarfile.open(fileobj=dot, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for rel, is_dir in walk_tree(tree):
            ti = tf.gettarinfo(os.path.join(tree, rel), arcname="./" + rel)
            ti.mtime = MTIME
            if is_dir:
                tf.addfile(ti)
            else:
                with open(os.path.join(tree, rel), "rb") as f:
                    tf.addfile(ti, f)
    add("py_dotslash.tar", dot.getvalue())
    # Large single streams: several LZMA2 chunks / bzip2 blocks / deflate blocks.
    big = big_bytes()
    write(os.path.join(tree, "..", "big.bin"), big)
    add("py_big.bin.xz", lzma.compress(big, preset=1))
    add("py_big.bin.bz2", bz2.compress(big, 9))
    add("py_big.bin.gz", gz_bytes(big, name="big.bin"))
    return made


def big_bytes():
    """3.5 MB mixing text and noise (multi-chunk, multi-block streams)."""
    parts = []
    for i in range(7):
        parts.append(words(300000, 100 + i))
        parts.append(lcg_bytes(200000, 200 + i))
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Oracle-made corpus
# ---------------------------------------------------------------------------

TREE_ITEMS = ["data", "docs", "emptydir", "empty.txt", "hello.txt", "with space.txt"]
SEVENZ_SPECS = [
    ("z7_lzma_solid.7z", "-t7z -m0=LZMA -ms=on -mhc=on"),
    ("z7_lzma2_nonsolid.7z", "-t7z -m0=LZMA2 -ms=off -mhc=off"),
    ("z7_lzma2_mx9.7z", "-t7z -mx=9"),
    ("z7_mx1.7z", "-t7z -mx=1"),
    ("z7_copy.7z", "-t7z -m0=Copy -ms=on -mhc=off"),
    ("z7_copy_mx0.7z", "-t7z -mx=0"),
    ("z7_bcj_lzma.7z", "-t7z -m0=BCJ -m1=LZMA -ms=on"),
    ("z7_bcj2.7z", "-t7z -m0=BCJ2 -m1=LZMA -m2=LZMA -m3=LZMA -mb0s0:1 -mb0s1:2 -mb0s2:3"),
    ("z7_arm64.7z", "-t7z -m0=ARM64 -m1=LZMA2 -ms=on"),
    ("z7_arm.7z", "-t7z -m0=ARM -m1=LZMA2"),
    ("z7_armt.7z", "-t7z -m0=ARMT -m1=LZMA2"),
    ("z7_ppc.7z", "-t7z -m0=PPC -m1=LZMA2"),
    ("z7_sparc.7z", "-t7z -m0=SPARC -m1=LZMA2"),
    ("z7_ia64.7z", "-t7z -m0=IA64 -m1=LZMA2"),
    ("z7_riscv.7z", "-t7z -m0=RISCV -m1=LZMA2"),
    ("z7_delta.7z", "-t7z -m0=Delta:4 -m1=LZMA2 -ms=on"),
    ("z7_swap4.7z", "-t7z -m0=Swap4 -m1=LZMA2"),
    ("z7_bzip2.7z", "-t7z -m0=BZip2 -ms=on"),
    ("z7_deflate.7z", "-t7z -m0=Deflate -ms=off"),
    ("z7_deflate64.7z", "-t7z -m0=Deflate64 -ms=on"),
    ("z7_ppmd.7z", "-t7z -m0=PPMd -ms=on"),
    ("z7_solid_blocks.7z", "-t7z -m0=LZMA2 -ms=2f"),
    ("z7_lzma2_mt.7z", "-t7z -m0=LZMA2:d=64k -mmt=4"),
    ("z7_no_times.7z", "-t7z -mtm=off"),
    ("z7_aes.7z", "-t7z -pSecret1 -mhe=off"),
    ("z7_aes_he.7z", "-t7z -pSecret1 -mhe=on"),
    ("zz_store.zip", "-tzip -mm=Copy"),
    ("zz_deflate.zip", "-tzip -mm=Deflate -mx=9"),
    ("zz_deflate_mx1.zip", "-tzip -mm=Deflate -mx=1"),
    ("zz_deflate64.zip", "-tzip -mm=Deflate64"),
    ("zz_bzip2.zip", "-tzip -mm=BZip2"),
    ("zz_lzma.zip", "-tzip -mm=LZMA"),
    ("zz_ppmd.zip", "-tzip -mm=PPMd"),
    ("zz_xz.zip", "-tzip -mm=XZ"),
    ("zz_utf8.zip", "-tzip -mcu=on"),
    ("zz_zipcrypto.zip", "-tzip -pSecret1 -mem=ZipCrypto"),
    ("zz_aes256.zip", "-tzip -pSecret1 -mem=AES256"),
    ("zt_tree.tar", "-ttar"),
]
STREAM_SPECS = [
    # (output, -t, switches, input file inside the tree)
    ("zs_words.txt.gz", "gzip", "-mx=9", "data/words.txt"),
    ("zs_random.bin.gz", "gzip", "-mx=1", "data/random.bin"),
    ("zs_words.txt.bz2", "bzip2", "-mx=9", "data/words.txt"),
    ("zs_zeros.bin.bz2", "bzip2", "-mmt=4", "data/zeros.bin"),
    ("zs_words.txt.xz", "xz", "-mx=9", "data/words.txt"),
    ("zs_prog_bcj.bin.xz", "xz", "-mf=BCJ", "data/prog.bin"),
    ("zs_prog_delta.bin.xz", "xz", "-mf=Delta:4", "data/prog.bin"),
    ("zs_random_mt.bin.xz", "xz", "-mmt=4 -mx=1", "data/random.bin"),
]
PASSWORD = "Secret1"

# Differences triaged as 7-Zip behavior rather than Sediment bugs. Matching
# archives get status `known-diff` (not a failure); the issues still print.
KNOWN_DIFFS = {
    "py_multimember.gz": "7zz lists ISIZE/CRC of the last gzip member only; "
                         "extraction (all members) matches. Sediment lists the whole output.",
}


def run(cmd, cwd=None, timeout=CMD_TIMEOUT, env=None):
    """(exit code or 'timeout'/'signal N', stdout bytes, stderr bytes)."""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return "timeout", b"", b""
    rc = p.returncode
    if rc < 0:
        rc = f"signal {-rc}"
    return rc, p.stdout, p.stderr


def build_oracle_corpus(cdir, tree, links, oracle, log, jobs):
    """Create the oracle-made archives (independent jobs run in parallel)."""
    abs_out = os.path.abspath(cdir)
    big = os.path.join(os.path.dirname(abs_out), "big.bin")
    tar = os.path.join(abs_out, "zt_tree.tar")
    first, second = [], []  # second wave depends on zt_tree.tar
    for name, sw in SEVENZ_SPECS:
        mt = [] if "-mmt" in sw else ["-mmt=1"]
        first.append((name, [oracle, "a", "-bd", *mt, "-mtc=off", "-mta=off", *sw.split(), os.path.join(abs_out, name), *TREE_ITEMS], tree))
    for name, sw in (("z7_links.7z", "-t7z -m0=LZMA2"), ("zz_links.zip", "-tzip"), ("zt_links.tar", "-ttar")):
        first.append((name, [oracle, "a", "-bd", "-snl", *sw.split(), os.path.join(abs_out, name), "target.txt", "sub", "same.txt"], links))
    for name, typ, sw, src in STREAM_SPECS:
        first.append((name, [oracle, "a", "-bd", f"-t{typ}", *sw.split(), os.path.join(abs_out, name), src], tree))
    for name, sw in (("z7_big_lzma2.7z", "-t7z -mx=5"), ("z7_big_bzip2_mt.7z", "-t7z -m0=BZip2 -mmt=4"),
                     ("zs_big.bin.xz", "-txz -mx=3"), ("zz_big_deflate64.zip", "-tzip -mm=Deflate64")):
        first.append((name, [oracle, "a", "-bd", *sw.split(), os.path.join(abs_out, name), big], None))
    # Compressed tars made by the oracle: tar first, then the stream.
    for name, typ in (("zt_tree.tar.gz", "gzip"), ("zt_tree.tar.bz2", "bzip2"), ("zt_tree.tar.xz", "xz")):
        second.append((name, [oracle, "a", "-bd", f"-t{typ}", os.path.join(abs_out, name), tar], None))

    def one(job):
        name, cmd, cwd = job
        rc, _, se = run(cmd, cwd=cwd)
        if rc in (0, 1) and os.path.exists(os.path.join(abs_out, name)):
            return name
        log.append(f"oracle could not create {name}: rc={rc} {short(se, 200)}")
        return None

    made = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
        for wave in (first, second):
            made += [n for n in ex.map(one, wave) if n]
    return made


def damaged_variants(cdir, names):
    """Truncated and bit-flipped copies of a selection of archives."""
    made = []
    for n in names:
        with open(os.path.join(cdir, n), "rb") as f:
            b = f.read()
        if len(b) < 64:
            continue
        write(os.path.join(cdir, "trunc60_" + n), b[: len(b) * 6 // 10])
        made.append("trunc60_" + n)
        flipped = bytearray(b)
        flipped[len(b) // 2] ^= 0x10
        write(os.path.join(cdir, "flip_" + n), bytes(flipped))
        made.append("flip_" + n)
    return made


DAMAGE_SOURCES = [
    "py_deflate9.zip", "py_bzip2.zip", "py_lzma.zip", "py_stored.zip", "py_ustar.tar", "py_tree.tar.gz",
    "py_tree.tar.bz2", "py_tree.tar.xz", "py_words.txt.gz", "py_words.bz2", "py_words_crc64.xz",
    "py_words_none.xz", "z7_lzma_solid.7z", "z7_lzma2_nonsolid.7z", "z7_copy.7z", "z7_bzip2.7z",
    "z7_ppmd.7z", "z7_deflate.7z", "zz_deflate64.zip", "zz_ppmd.zip",
]

# ---------------------------------------------------------------------------
# Listing parsers
# ---------------------------------------------------------------------------


def parse_slt(text):
    """Parse `7zz l -slt` output into a list of dicts (entries only)."""
    lines = text.splitlines()
    try:
        start = lines.index("----------") + 1
    except ValueError:
        return None
    entries, cur = [], {}
    for ln in lines[start:]:
        if not ln.strip():
            if cur:
                entries.append(cur)
                cur = {}
            continue
        if " = " in ln:
            k, v = ln.split(" = ", 1)
            cur[k] = v
        elif ln.endswith(" ="):
            cur[ln[:-2]] = ""
    if cur:
        entries.append(cur)
    # Single-stream formats (bzip2, xz) list one entry without a Path.
    return [e if "Path" in e else dict(e, Path="", _noname=True) for e in entries if "Path" in e or "Size" in e]


def unescape_name(s):
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x" and i + 3 < len(s) + 0:
                out.append(int(s[i + 2:i + 4], 16))
                i += 4
                continue
            out += {"\\": b"\\", "t": b"\t", "r": b"\r", "n": b"\n"}.get(n, n.encode())
            i += 2
            continue
        out += c.encode()
        i += 1
    return out.decode("utf-8", "surrogateescape")


def parse_sediment_table(text):
    lines = text.splitlines()
    if not lines or lines[0] != "SIZE\tCRC32\tNAME":
        return None
    out = []
    for ln in lines[1:]:
        parts = ln.split("\t", 2)
        if len(parts) != 3:
            return None
        size, crc, name = parts
        out.append({"Path": unescape_name(name), "Size": size, "CRC": "" if crc == "--------" else crc.upper(), "_table": True})
    return out


def norm_path(p):
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.rstrip("/")


def slt_kind(e):
    if e.get("Folder") == "+" or e.get("Attributes", "").startswith("D"):
        return "dir"
    if e.get("Symbolic Link") or e.get("Link"):
        return "link"
    attr = e.get("Attributes", "")
    m = re.search(r"\b-?l[rwx-]{9}\b", attr)
    if m:
        return "link"
    return "file"


def list_index(entries):
    """path -> (kind, size, crc, hardlink) for a parsed listing."""
    idx = {}
    for e in entries:
        p = norm_path(e["Path"])
        if not p:
            continue
        kind = slt_kind(e) if not e.get("_table") else None
        idx[p] = (kind, e.get("Size", ""), e.get("CRC", "").upper(), bool(e.get("Hard Link")))
    return idx


def compare_listing(oracle_entries, sed_entries, table):
    if len(oracle_entries) == 1 and oracle_entries[0].get("_noname") and len(sed_entries) == 1:
        # Nameless single stream: the member name is Sediment's choice.
        oracle_entries = [dict(oracle_entries[0], Path=sed_entries[0]["Path"])]
    o, s = list_index(oracle_entries), list_index(sed_entries)
    issues = []
    for p in sorted(set(o) - set(s)):
        issues.append(f"missing in sediment listing: `{p}` ({o[p][0]})")
    for p in sorted(set(s) - set(o)):
        issues.append(f"extra in sediment listing: `{p}`")
    for p in sorted(set(o) & set(s)):
        ok, sk = o[p], s[p]
        okind = ok[0]
        if not table and sk[0] != okind:
            issues.append(f"kind of `{p}`: 7zz {okind}, sediment {sk[0]}")
        if okind == "dir":
            # The `l` table prints CRC 00000000 for ZIP directory records
            # (frozen legacy `list` format); that is not a data CRC.
            if table and (sk[1] not in ("0", "") or sk[2] not in ("", "00000000")):
                issues.append(f"`{p}` is a directory for 7zz; sediment lists size {sk[1]} crc {sk[2] or '-'}")
            continue
        if okind == "link":
            # 7zz Size is the target length for 7z/zip, 0 for tar.
            continue
        if ok[3]:
            # Tar hard link: 7zz lists the header size (0); Sediment lists
            # the size of the data it will copy from the link source.
            continue
        if ok[1] and sk[1] and ok[1] != sk[1]:
            issues.append(f"size of `{p}`: 7zz {ok[1]}, sediment {sk[1]}")
        if ok[2] and sk[2] and ok[2] != sk[2]:
            issues.append(f"CRC of `{p}`: 7zz {ok[2]}, sediment {sk[2]}")
        if ok[2] and not sk[2] and ok[1] not in ("0", ""):
            issues.append(f"CRC of `{p}`: 7zz {ok[2]}, sediment none")
    return issues


# ---------------------------------------------------------------------------
# Extracted tree comparison
# ---------------------------------------------------------------------------


def snapshot(root):
    """relpath -> (kind, sha256|target, size, mtime, mode&0o777)."""
    snap = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            full = os.path.join(dirpath, n)
            rel = os.path.relpath(full, root)
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                snap[rel] = ("link", os.readlink(full), 0, int(st.st_mtime), None)
            elif stat.S_ISDIR(st.st_mode):
                snap[rel] = ("dir", None, 0, int(st.st_mtime), stat.S_IMODE(st.st_mode))
            else:
                h = hashlib.sha256()
                with open(full, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                snap[rel] = ("file", h.hexdigest(), st.st_size, int(st.st_mtime), stat.S_IMODE(st.st_mode))
    return snap


def compare_trees(o, s, timed):
    """Returns (content issues, metadata issues). mtimes are compared only
    for paths in `timed` (entries whose 7zz listing has a Modified time;
    for timeless streams 7zz uses the archive's own mtime)."""
    issues, meta = [], []
    for p in sorted(set(o) - set(s)):
        issues.append(f"missing after sediment x: `{p}` ({o[p][0]})")
    for p in sorted(set(s) - set(o)):
        issues.append(f"extra after sediment x: `{p}` ({s[p][0]})")
    for p in sorted(set(o) & set(s)):
        a, b = o[p], s[p]
        if a[0] != b[0]:
            issues.append(f"`{p}`: 7zz made a {a[0]}, sediment a {b[0]}")
            continue
        if a[0] == "file" and (a[1] != b[1] or a[2] != b[2]):
            issues.append(f"`{p}`: bytes differ (7zz {a[2]} B, sediment {b[2]} B)")
        if a[0] == "link" and a[1] != b[1]:
            issues.append(f"`{p}`: link target 7zz `{a[1]}`, sediment `{b[1]}`")
        if a[0] == "file" and p in timed and abs(a[3] - b[3]) > 2:
            meta.append(f"`{p}`: mtime 7zz {a[3]}, sediment {b[3]}")
        if a[0] == "file" and a[4] is not None and b[4] is not None and (a[4] & 0o111) != (b[4] & 0o111):
            meta.append(f"`{p}`: exec bits 7zz {oct(a[4])}, sediment {oct(b[4])}")
    return issues, meta


# ---------------------------------------------------------------------------
# Per-archive differential run
# ---------------------------------------------------------------------------


class Result:
    def __init__(self, name):
        self.name = name
        self.status = "ok"  # ok | mismatch | unsupported | crash | oracle-fail
        self.issues = []
        self.meta = []
        self.notes = []
        self.seconds = 0.0
        self.compared = 0

    def bad(self, status, msg):
        rank = {"ok": 0, "known-diff": 1, "unsupported": 1, "mismatch": 2, "oracle-fail": 2, "crash": 3}
        if rank[status] > rank[self.status]:
            self.status = status
        self.issues.append(msg)


def short(b, n=240):
    return b.decode("utf-8", "replace").strip().replace("\n", " | ")[:n]


def failure_status(stderr, password):
    """Classify a Sediment failure: missing feature or bug candidate."""
    low = stderr.lower()
    if b"unsupported" in low:
        return "unsupported"
    if password and (b"unknown switch" in low or b"too many arguments" in low):
        return "unsupported"  # no -p (password) switch yet
    return "mismatch"


def crashed(rc, stderr):
    return rc == 101 or (isinstance(rc, str)) or b"panicked at" in stderr


def oracle_side(oracle, archive, scratch, password):
    """Oracle listing + extraction dir, unwrapping compressed tars."""
    pw = [f"-p{password}"] if password else []
    target = archive
    if archive.lower().endswith(COMPRESSED_TAR):
        outer = os.path.join(scratch, "outer")
        os.makedirs(outer)
        rc, so, se = run([oracle, "x", "-bd", "-y", f"-o{outer}", archive])
        inner = [os.path.join(outer, n) for n in os.listdir(outer)]
        if rc != 0 or len(inner) != 1:
            return None, None, f"oracle could not unwrap: rc={rc} {short(se)}"
        target = inner[0]
    rc, lo, le = run([oracle, "l", "-slt", "-bd", *pw, target])
    listing = parse_slt(lo.decode("utf-8", "surrogateescape")) if rc == 0 else None
    xdir = os.path.join(scratch, "o")
    os.makedirs(xdir)
    # -snld: also create links whose target leaves their own directory
    # (`sub/up.txt -> ../target.txt` stays inside the tree).
    rc2, xo, xe = run([oracle, "x", "-bd", "-y", "-snl", "-snld", *pw, f"-o{xdir}", target])
    if rc != 0 or rc2 != 0:
        return listing, None, f"oracle l rc={rc}, x rc={rc2}: {short(le + xe)}"
    return listing, xdir, None


def diff_one(name, cdir, sed, oracle, work):
    r = Result(name)
    t0 = time.time()
    archive = os.path.join(cdir, name)
    scratch = tempfile.mkdtemp(prefix="d-", dir=work)
    password = PASSWORD if ("aes" in name or "crypto" in name) else None
    pw = [f"-p{password}"] if password else []
    try:
        if name.startswith(("trunc", "flip")):
            rc_o, _, eo = run([oracle, "t", "-bd", archive])
            rc_s, _, es = run([sed, "t", archive])
            if crashed(rc_s, es):
                r.bad("crash", f"sediment t crashed (rc={rc_s}): {short(es)}")
            ok_o, ok_s = rc_o == 0, rc_s == 0
            if ok_o and not ok_s:
                r.bad("mismatch", f"7zz t accepts, sediment t rejects (rc={rc_s}): {short(es)}")
            elif ok_s and not ok_o:
                r.bad("mismatch", f"7zz t rejects (rc={rc_o}: {short(eo, 120)}), sediment t accepts")
            else:
                r.notes.append(f"both {'accept' if ok_o else 'reject'} (7zz rc={rc_o}, sediment rc={rc_s})")
            xdir = os.path.join(scratch, "s")
            os.makedirs(xdir)
            rc_x, _, ex = run([sed, "x", "-y", "-snl", f"-o{xdir}", archive])
            if crashed(rc_x, ex):
                r.bad("crash", f"sediment x crashed (rc={rc_x}): {short(ex)}")
            return r
        listing, oxdir, ofail = oracle_side(oracle, archive, scratch, password)
        if ofail and listing is None:
            r.bad("oracle-fail", ofail)
            return r
        if ofail:
            r.notes.append(ofail)
        # Listing
        rc, so, se = run([sed, "l", "-slt", *pw, archive])
        table = False
        sl = None
        if crashed(rc, se):
            r.bad("crash", f"sediment l -slt crashed (rc={rc}): {short(se)}")
        if rc == 0 and b"Path = " in so:
            sl = parse_slt(so.decode("utf-8", "surrogateescape"))
        if sl is None:
            rc, so, se = run([sed, "l", *pw, archive] if pw else [sed, "l", archive])
            if crashed(rc, se):
                r.bad("crash", f"sediment l crashed (rc={rc}): {short(se)}")
            if rc != 0:
                status = failure_status(se, password)
                r.bad(status, f"sediment l failed (rc={rc}): {short(se)}")
            else:
                sl = parse_sediment_table(so.decode("utf-8", "surrogateescape"))
                table = True
                if sl is None:
                    r.bad("mismatch", "sediment l output unparseable")
        if sl is not None:
            for msg in compare_listing(listing, sl, table):
                r.bad("mismatch", "list: " + msg)
        # Test
        rc, so, se = run([sed, "t", *pw, archive] if pw else [sed, "t", archive])
        if crashed(rc, se):
            r.bad("crash", f"sediment t crashed (rc={rc}): {short(se)}")
        elif rc != 0 and oxdir:
            status = failure_status(se, password)
            r.bad(status, f"sediment t failed (rc={rc}): {short(se)}")
        # Extract
        if oxdir:
            sxdir = os.path.join(scratch, "s")
            os.makedirs(sxdir)
            rc, so, se = run([sed, "x", "-y", "-snl", *pw, f"-o{sxdir}", archive])
            if crashed(rc, se):
                r.bad("crash", f"sediment x crashed (rc={rc}): {short(se)}")
            elif rc != 0:
                status = failure_status(se, password)
                r.bad(status, f"sediment x failed (rc={rc}): {short(se)}")
            if rc in (0, 1):
                osnap = snapshot(oxdir)
                r.compared = len(osnap)
                timed = {norm_path(e["Path"]) for e in (listing or []) if e.get("Modified")}
                issues, meta = compare_trees(osnap, snapshot(sxdir), timed)
                for m in issues:
                    r.bad("mismatch", "x: " + m)
                r.meta.extend(meta)
    finally:
        r.seconds = time.time() - t0
        if r.status == "mismatch" and name in KNOWN_DIFFS:
            r.status = "known-diff"
            r.notes.append("known difference: " + KNOWN_DIFFS[name])
        shutil.rmtree(scratch, ignore_errors=True)
    return r


# ---------------------------------------------------------------------------
# Run mode
# ---------------------------------------------------------------------------


def build_sediment(log):
    t0 = time.time()
    env = dict(os.environ)
    env.setdefault("RUSTFLAGS", "-Funsafe_code")
    p = subprocess.run(["cargo", "build", "--release", "--offline", "--bin", "sediment", "--message-format=short"],
                       cwd=CRATE, capture_output=True, env=env)
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode(errors="replace"))
        raise SystemExit("cargo build failed")
    tdir = env.get("CARGO_TARGET_DIR") or os.path.join(CRATE, "target")
    log.append(f"cargo build --release: {time.time() - t0:.1f}s")
    return os.path.join(tdir, "release", "sediment")


def render(results, log, oracle_ver, sed_rev, elapsed):
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    out = ["# Sediment vs 7-Zip differential report", ""]
    out.append(f"- Oracle: `{oracle_ver}`")
    out.append(f"- Sediment: {sed_rev}")
    out.append(f"- Archives: {len(results)}; " + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    out.append(f"- Wall time: {elapsed:.0f}s")
    out.append("")
    out.append("Statuses: `ok` identical; `mismatch` Sediment differs from 7zz (bug candidate); "
               "`unsupported` Sediment reports an unsupported feature; `known-diff` triaged 7-Zip quirk "
               "(see KNOWN_DIFFS); `crash` Sediment panicked, "
               "was killed or timed out (always a bug); `oracle-fail` 7zz itself failed.")
    out.append("")
    out.append("| archive | status | issues | metadata diffs | paths compared | s |")
    out.append("|---|---|---|---|---|---|")
    for r in results:
        out.append(f"| `{r.name}` | {r.status} | {len(r.issues)} | {len(r.meta)} | {r.compared} | {r.seconds:.1f} |")
    bad = [r for r in results if r.issues or r.meta]
    if bad:
        out += ["", "## Details", ""]
        for r in bad:
            out.append(f"### `{r.name}` ({r.status})")
            for m in r.issues[:40]:
                out.append(f"- {m}")
            if len(r.issues) > 40:
                out.append(f"- ... {len(r.issues) - 40} more")
            for m in r.meta[:20]:
                out.append(f"- metadata: {m}")
            if len(r.meta) > 20:
                out.append(f"- metadata: ... {len(r.meta) - 20} more")
            for m in r.notes:
                out.append(f"- note: {m}")
            out.append("")
    if log:
        out += ["", "## Log", ""] + [f"- {m}" for m in log]
    return "\n".join(out) + "\n"


def run_mode(args):
    t0 = time.time()
    log = []
    oracle = args.oracle
    rc, so, _ = run([oracle])
    ver = next((ln for ln in so.decode(errors="replace").splitlines() if ln.startswith("7-Zip")), "?")
    if ORACLE_VERSION not in ver:
        log.append(f"WARNING: oracle is not the pinned {ORACLE_VERSION}: {ver}")
    sed = args.sediment or build_sediment(log)
    rev = subprocess.run(["git", "-C", CRATE, "rev-parse", "--short", "HEAD"], capture_output=True).stdout.decode().strip()
    rev = args.rev or rev or "(working tree copy)"
    work = os.path.abspath(args.work or tempfile.mkdtemp(prefix="sediment-diff-"))
    os.makedirs(work, exist_ok=True)
    tree, links, cdir = (os.path.join(work, d) for d in ("tree", "links", "corpus"))
    for d in (tree, links, cdir):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    stage_tree(tree)
    stage_links(links)
    os.environ["TZ"] = "UTC"
    names = build_python_corpus(cdir, tree, links)
    jobs = args.jobs or os.cpu_count() or 4
    names += build_oracle_corpus(cdir, tree, links, oracle, log, jobs)
    names += damaged_variants(cdir, [n for n in DAMAGE_SOURCES if n in names])
    if args.only:
        rx = re.compile(args.only)
        names = [n for n in names if rx.search(n)]
    log.append(f"corpus built: {len(names)} archives, {time.time() - t0:.1f}s")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = [ex.submit(diff_one, n, cdir, sed, oracle, work) for n in names]
        for f in futs:
            results.append(f.result())
    report = render(results, log, ver, rev, time.time() - t0)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report)
    else:
        sys.stdout.write(report)
    if not args.keep and not args.work:
        shutil.rmtree(work, ignore_errors=True)
    bad = sum(1 for r in results if r.status in ("mismatch", "crash"))
    print(f"{len(results)} archives, {bad} with mismatches/crashes", file=sys.stderr)
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run", action="store_true", help="run here instead of shipping to --host")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--oracle", default=DEFAULT_ORACLE)
    ap.add_argument("--sediment", help="prebuilt sediment binary (skips cargo build)")
    ap.add_argument("--work")
    ap.add_argument("--report")
    ap.add_argument("--only")
    ap.add_argument("--jobs", type=int)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--rev", help="revision label for the report (set by the driver)")
    args = ap.parse_args()
    return run_mode(args) if args.run else drive(args)


if __name__ == "__main__":
    sys.exit(main())
