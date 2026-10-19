#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Oracle recipe for tests/fixtures/update_ops/7z (run on sparky, 2026-10-19).
# Oracle: pinned 7-Zip 26.04 linux-arm64 `7zz` (sha256 a01daa02...d0cd, see
# tests/gen/sevenz_oracle.sh); used only as an external CLI, no 7-Zip code is
# part of Sediment.
# Usage:
#   UPDATE_OPS_REGEN=1 cargo test --test update_ops sevenz_oracle_outputs
#   bash tests/gen/update_ops_7z_oracle.sh tests/fixtures/update_ops/7z
# Every archive must pass `7zz t` ("Everything is Ok"); `7zz l -slt` is saved
# as NAME.slt.txt and compared with Sediment's listing in the test.
set -euo pipefail
D=$(cd "$1" && pwd); Z=${Z:-/home/mike/sediment-rust-20261019/reference/7zz}
export TZ=UTC LC_ALL=C.UTF-8
for a in "$D"/*.7z; do
  n=$(basename "$a")
  "$Z" t "$a" > "$D/$n.t.log" 2>&1 || { cat "$D/$n.t.log"; exit 1; }
  grep -q "Everything is Ok" "$D/$n.t.log" || { cat "$D/$n.t.log"; exit 1; }
  rm "$D/$n.t.log"
  (cd "$D" && "$Z" l -slt "$n" | sed -n '/^----------$/,$p') > "$D/$n.slt.txt"
done
echo "all $(ls "$D"/*.7z | wc -l) archives OK"
