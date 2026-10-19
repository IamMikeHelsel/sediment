#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Cross-check tests/fixtures/{cab,cfb,chm} against an external 7-Zip `7zz` (26.04
# linux-arm64, see tests/gen/sevenz_oracle.sh for provenance). Used only as a
# black-box CLI oracle; no 7-Zip code is part of Sediment.
# Usage (on a host with 7zz): bash ms_oracle.sh <fixtures/cab|cfb|chm dir>
# For every archive with a .expect file, extracts with 7zz and compares the
# size and CRC-32 of each expected file. Prints OK/FAIL lines.
set -u
D=$1; Z=${Z:-/home/mike/sediment-rust-20261019/reference/7zz}
T=$(mktemp -d)
for e in "$D"/*.expect; do
  case "$e" in *.local.expect) continue;; esac
  a=${e%.expect}; n=$(basename "$a")
  rm -rf "$T/x"; mkdir -p "$T/x"
  "$Z" x -y -o"$T/x" "$a" > "$T/log" 2>&1 || { echo "FAIL $n: 7zz exit"; tail -5 "$T/log"; }
  python3 -I - "$e" "$T/x" "$n" <<'PY'
import sys, zlib, os
exp, root, name = sys.argv[1:4]
bad = 0
for line in open(exp, encoding="utf-8"):
    kind, path, size, crc = line.rstrip("\n").split("\t")
    if kind != "f" or path.startswith("::"):
        continue
    p = os.path.join(root, path.lstrip("/"))
    if not os.path.exists(p):
        print("  missing", path); bad += 1; continue
    d = open(p, "rb").read()
    if len(d) != int(size) or "%08x" % (zlib.crc32(d) & 0xffffffff) != crc:
        print("  mismatch", path, len(d), size); bad += 1
print(("OK " if not bad else "FAIL ") + name)
PY
done
rm -rf "$T"
