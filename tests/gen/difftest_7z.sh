#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Oracle recipe for tests/fixtures/difftest/7z/*.{zip,xz} (run on sparky).
# Oracle: the pinned 7-Zip 26.04 linux-arm64 `7zz` described in
# tests/gen/sevenz_oracle.sh. Only used as an external CLI; no 7-Zip code is
# part of Sediment. The input tree comes from tests/gen/difftest.py --stage.
# Usage (from the crate root):
#   S=$(mktemp -d); bash tests/gen/difftest_7z.sh $S; cp $S/out/* tests/fixtures/difftest/7z/; rm -rf $S
set -euo pipefail
S=$1; Z=${Z:-/home/mike/sediment-rust-20261019/reference/7zz}
GEN=$(cd "$(dirname "$0")" && pwd)/difftest.py
mkdir -p "$S/in" "$S/out"
python3 -I "$GEN" --stage "$S/in"
cd "$S/in"
export TZ=UTC LC_ALL=C.UTF-8
touch -d @1709618828 a.txt b.bin prog.bin dir dir/c.txt
for spec in \
  "zip_deflate64.zip:-tzip -mm=Deflate64" \
  "zip_xz.zip:-tzip -mm=XZ" \
  "zip_lzma_eos.zip:-tzip -mm=LZMA:eos"; do
  n=${spec%%:*}; o=${spec#*:}
  # shellcheck disable=SC2086
  "$Z" a -bd -mmt=1 $o "../out/$n" a.txt b.bin dir prog.bin > /dev/null
  "$Z" t "../out/$n" | grep -q "Everything is Ok"
done
for spec in "arm64:-mf=ARM64" "riscv:-mf=RISCV"; do
  n=${spec%%:*}; o=${spec#*:}
  # shellcheck disable=SC2086
  "$Z" a -bd -mmt=1 -txz $o "../out/prog_$n.bin.xz" prog.bin > /dev/null
  "$Z" t "../out/prog_$n.bin.xz" | grep -q "Everything is Ok"
done
ls -la ../out
