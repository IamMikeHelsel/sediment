#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Oracle recipe for tests/fixtures/zip_methods/ppmd*.zip (run on sparky).
# Oracle: the pinned 7-Zip 26.04 linux-arm64 `7zz` (see tests/gen/sevenz_oracle.sh),
# used only as an external CLI. The input tree comes from tests/gen/zip_methods.py --stage.
# Usage (from the crate root):
#   S=$(mktemp -d); bash tests/gen/zip_methods_7z.sh $S; cp $S/out/* tests/fixtures/zip_methods/; rm -rf $S
set -euo pipefail
S=$1; Z=${Z:-/home/mike/sediment-rust-20261019/reference/7zz}
GEN=$(cd "$(dirname "$0")" && pwd)/zip_methods.py
mkdir -p "$S/in" "$S/out"
python3 -I "$GEN" --stage "$S/in"
cd "$S/in"
export TZ=UTC LC_ALL=C.UTF-8
for spec in \
  "ppmd:-mm=PPMd" \
  "ppmd_o3:-mm=PPMd -mo=3 -mmem=1m" \
  "ppmd_o16:-mm=PPMd -mo=16 -mmem=32m" \
  "ppmd_aes:-mm=PPMd -mem=AES256 -psecret"; do
  n=${spec%%:*}; o=${spec#*:}
  # shellcheck disable=SC2086
  "$Z" a -tzip -bd -mmt=1 -mtc=off $o "../out/$n.zip" a.txt bin deep empty café.txt words.txt > /dev/null
  "$Z" t -psecret "../out/$n.zip" | grep -q "Everything is Ok"
  "$Z" l -slt -psecret "../out/$n.zip" | sed -n '/^----------$/,$p' > "../out/$n.slt.txt"
  grep -q "Method = .*PPMd" "../out/$n.slt.txt"
done
