#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Oracle recipe for tests/fixtures/sevenz_write (run on sparky, 2026-10-19).
# Oracle: pinned 7-Zip 26.04 linux-arm64 `7zz` (sha256 a01daa02...d0cd, see
# tests/gen/sevenz_oracle.sh); used only as an external CLI, no 7-Zip code is
# part of Sediment.
# Usage: bash sevenz_write_oracle.sh DIR
#   DIR holds *.7z plus src/ as written by
#   SEVENZ_WRITE_REGEN=DIR cargo test --test sevenz_write regen   (fixtures) or
#   SEVENZ_WRITE_STRESS=DIR cargo test --release --test sevenz_write stress_regen
# For every archive: `7zz t` must say "Everything is Ok", `7zz x -snl` into a
# scratch dir must reproduce src/ byte for byte (symlinks: target text), and
# `7zz l -slt` is saved next to the archive as NAME.slt.txt.
set -euo pipefail
D=$(cd "$1" && pwd); Z=${Z:-/home/mike/sediment-rust-20261019/reference/7zz}
export TZ=UTC LC_ALL=C.UTF-8
for a in "$D"/*.7z; do
  n=$(basename "$a" .7z)
  "$Z" t "$a" > "$D/$n.t.log" 2>&1 || { cat "$D/$n.t.log"; exit 1; }
  grep -q "Everything is Ok" "$D/$n.t.log" || { cat "$D/$n.t.log"; exit 1; }
  rm "$D/$n.t.log"
  (cd "$D" && "$Z" l -slt "$n.7z") > "$D/$n.slt.txt"
  X=$(mktemp -d /tmp/s7w-x.XXXX)
  "$Z" x -bd -snl -o"$X" "$a" > /dev/null
  while IFS= read -r -d '' f; do
    rel=${f#"$D/src/"}
    case "$rel" in
      *.symlink-target)
        l=${rel%.symlink-target}
        [ -L "$X/$l" ] && [ "$(readlink "$X/$l")" = "$(cat "$f")" ] || { echo "$n: symlink $l differs"; exit 1; } ;;
      *) cmp -s "$f" "$X/$rel" || { echo "$n: $rel differs"; exit 1; } ;;
    esac
  done < <(find "$D/src" -type f -print0)
  while IFS= read -r -d '' g; do
    [ -d "$D/src/${g#"$X/"}" ] || { echo "$n: dir ${g#"$X/"} missing from src"; exit 1; }
  done < <(find "$X" -mindepth 1 -type d -print0)
  cnt_src=$(find "$D/src" -mindepth 1 | wc -l); cnt_x=$(find "$X" -mindepth 1 | wc -l)
  [ "$cnt_src" = "$cnt_x" ] || { echo "$n: entry count $cnt_x != $cnt_src"; exit 1; }
  rm -rf "$X"
  echo "OK $n ($(stat -c %s "$a") bytes)"
done
