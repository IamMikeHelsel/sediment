#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Oracle cross-check and third-party-writer fixtures for tests/fixtures/wim
# (run on sparky, 2026-10-19). External CLI oracles only; no oracle code is
# part of Sediment and none was read:
#   7-Zip 26.04 linux-arm64 `7zz` (see sevenz_oracle.sh for its sha256)
#   wimlib 1.14.5 built from wimlib-1.14.5.tar.gz
#     sha256 84221a3abd5b91228f15f8e6065c335a336237b5738197b75bf419eea561a194
#     ./configure --without-ntfs-3g --without-fuse --prefix=$W/inst
# Usage: bash wim_oracle.sh <dir with tests/fixtures/wim copied in> <out dir>
#  1. every generated *.wim that should open is tested by both oracles and
#     its extracted files are compared with the *.wim.list manifest;
#  2. wimlib_{none,xpress,lzx}.wim and 7zz_none.wim are written from a fixed
#     tree, with manifests, into <out dir>.
set -euo pipefail
FIX=$1; OUT=$2
Z=${Z:-/home/mike/sediment-rust-20261019/reference/7zz}
W=${W:-/tmp/wimlib-build.7BmC}
export LD_LIBRARY_PATH=$W/inst/lib TZ=UTC LC_ALL=C.UTF-8
WI=$W/inst/bin/wimlib-imagex
T=$(mktemp -d)
check() {  # wim list
  local wim=$1 list=$2 d
  "$Z" t "$wim" | grep -q "Everything is Ok"
  "$WI" verify "$wim" >/dev/null
  d=$T/x7; rm -rf "$d"; "$Z" x -bd -y -o"$d" "$wim" >/dev/null
  python3 -I - "$d" "$list" "7zz" <<'PY'
import hashlib, os, sys
root, listf, who = sys.argv[1:4]
multi = len({l.split("\t")[0] for l in open(listf, encoding="utf-8") if l.strip()}) > 1
bad = 0
for line in open(listf, encoding="utf-8"):
    if not line.strip():
        continue
    img, kind, size, sha, path = line.rstrip("\n").split("\t")
    p = os.path.join(root, img, path) if multi else os.path.join(root, path)
    if kind == "dir":
        ok = os.path.isdir(p)
    elif kind == "file":
        ok = os.path.isfile(p) and hashlib.sha256(open(p, "rb").read()).hexdigest() == sha
    else:
        ok = os.path.lexists(p)
    if not ok:
        bad += 1
        print(f"{who}: MISMATCH {listf}: {path}")
sys.exit(1 if bad else 0)
PY
}
for n in none xpress xpress_4k xpress_multi reparse; do
  check "$FIX/$n.wim" "$FIX/$n.wim.list"
  echo "ok $n"
done
for n in lzx lzms solid; do
  if "$Z" t "$FIX/$n.wim" >/dev/null 2>&1; then echo "unexpected: 7zz opened $n"; exit 1; fi
done
# Third-party writers.
mkdir -p "$T/src/dir/sub" "$T/src/emptydir" "$OUT"
printf 'Hello, WIM!\n' > "$T/src/hello.txt"
python3 -I -c "
import random
r = random.Random(3); w = [b'alpha', b'beta', b'gamma', b'delta', b'wim', b'chunk']
open('$T/src/text.txt', 'wb').write(b' '.join(r.choice(w) for _ in range(4000)))
open('$T/src/zeros.bin', 'wb').write(bytes(6000))
open('$T/src/dir/sub/nested.txt', 'wb').write(b'nested\n' * 3)
open('$T/src/héllo.txt', 'wb').write(b'unicode name\n')
"
: > "$T/src/empty.txt"
find "$T/src" -exec touch -h -d "2024-03-05 06:07:08 UTC" {} +
for c in none xpress lzx; do
  "$WI" capture "$T/src" "$OUT/wimlib_$c.wim" "img" --compress=$c --no-acls >/dev/null
done
( cd "$T/src" && "$Z" a -bd -twim "$OUT/7zz_none.wim" hello.txt text.txt zeros.bin empty.txt dir emptydir "h$(printf '\xc3\xa9')llo.txt" >/dev/null )
python3 -I - "$T/src" "$OUT" <<'PY'
import hashlib, os, sys
src, out = sys.argv[1:3]
lines = []
def walk(d, prefix):
    names = sorted(os.listdir(d))
    subs = []
    for n in names:
        p = os.path.join(d, n)
        rel = f"{prefix}/{n}" if prefix else n
        if os.path.isdir(p):
            lines.append(("dir", 0, hashlib.sha256(b"").hexdigest(), rel)); subs.append((p, rel))
        else:
            b = open(p, "rb").read()
            lines.append(("file", len(b), hashlib.sha256(b).hexdigest(), rel))
    for p, rel in subs:
        walk(p, rel)
walk(src, "")
for c in ("wimlib_none", "wimlib_xpress", "wimlib_lzx", "7zz_none"):
    with open(os.path.join(out, c + ".wim.list"), "w", encoding="utf-8") as f:
        f.write("".join(f"1\t{k}\t{s}\t{h}\t{p}\n" for k, s, h, p in lines))
PY
for c in wimlib_none wimlib_xpress 7zz_none; do check "$OUT/$c.wim" "$OUT/$c.wim.list"; echo "ok $c"; done
rm -rf "$T"
