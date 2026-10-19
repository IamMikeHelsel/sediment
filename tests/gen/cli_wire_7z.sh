#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Oracle recipe for tests/fixtures/cli_wire/7z/tree_*.7z and links.7z (run on sparky).
# Oracle: the pinned 7-Zip 26.04 linux-arm64 `7zz` described in
# tests/gen/sevenz_oracle.sh. Only used as an external CLI; no 7-Zip code is
# part of Sediment. The input tree comes from tests/gen/cli_wire.py --stage.
# Usage (from the crate root):
#   S=$(mktemp -d); bash tests/gen/cli_wire_7z.sh $S; cp $S/out/*.7z tests/fixtures/cli_wire/7z/; rm -rf $S
set -euo pipefail
S=$1; Z=${Z:-/home/mike/sediment-rust-20261019/reference/7zz}
GEN=$(cd "$(dirname "$0")" && pwd)/cli_wire.py
mkdir -p "$S/in" "$S/out"
python3 -I "$GEN" --stage "$S/in"
cd "$S/in"
export TZ=UTC LC_ALL=C.UTF-8
for spec in \
  "tree_lzma:-m0=LZMA -ms=on -mhc=on" \
  "tree_lzma2:-m0=LZMA2 -ms=off -mhc=off" \
  "tree_copy:-m0=Copy -ms=on -mhc=off" \
  "tree_bcj:-m0=BCJ -m1=LZMA -ms=on" \
  "tree_arm64:-m0=ARM64 -m1=LZMA2 -ms=on" \
  "tree_delta:-m0=Delta:4 -m1=LZMA2 -ms=on" \
  "tree_bzip2:-m0=BZip2 -ms=on" \
  "tree_deflate:-m0=Deflate -ms=off" \
  "tree_deflate64:-m0=Deflate64 -ms=on" \
  "tree_ppmd:-m0=PPMd -ms=on"; do
  n=${spec%%:*}; o=${spec#*:}
  # shellcheck disable=SC2086
  "$Z" a -bd -mmt=1 -mtc=off -mta=off $o "../out/$n.7z" data docs emptydir empty.txt hello.txt > "../out/$n.log" 2>&1 \
    || { cat "../out/$n.log"; exit 1; }
  "$Z" t "../out/$n.7z" | grep -q "Everything is Ok"
  rm "../out/$n.log"
done
# Symlinks stored with -snl (Unix mode S_IFLNK in the attribute high bits,
# the target as the entry data).
mkdir -p "$S/links/sub" && cd "$S/links"
printf 'tgt\n' > target.txt
ln -s ../target.txt sub/up.txt
touch -h -d @1709618828 target.txt sub/up.txt sub .
"$Z" a -bd -mmt=1 -snl -m0=LZMA2 ../out/links.7z target.txt sub > /dev/null
"$Z" t ../out/links.7z | grep -q "Everything is Ok"
ls -la ../out
