#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Reverse oracle for Sediment's encrypted writers (run on sparky, 2026-10-19):
#   ENC_ARCHIVES_REGEN=DIR cargo test --test enc_archives regen
#   bash tests/gen/enc_archives_verify.sh DIR
# 7-Zip 26.04 `7zz` (see tests/gen/sevenz_oracle.sh) must report every
# archive as encrypted, test it OK with the right password, fail with a wrong
# one, and extract a tree identical to DIR/src. Headers written with -mhe
# must not be listable without the password.
set -euo pipefail
D=$(cd "$1" && pwd); Z=${Z:-/home/mike/sediment-rust-20261019/reference/7zz}
export LC_ALL=C.UTF-8
for a in "$D"/ours_*; do
  n=$(basename "$a")
  case "$n" in *unicode*) p="pässwörd€";; *) p=secret;; esac
  "$Z" t "-p$p" "$a" > "$D/$n.log" 2>&1 || { cat "$D/$n.log"; echo "FAIL t $n"; exit 1; }
  grep -q "Everything is Ok" "$D/$n.log" || { cat "$D/$n.log"; exit 1; }
  if "$Z" t -pWRONG "$a" > /dev/null 2>&1; then echo "FAIL $n accepted a wrong password"; exit 1; fi
  "$Z" l -slt "-p$p" "$a" | grep -q "Encrypted = +" || { echo "FAIL $n not reported encrypted"; exit 1; }
  case "$n" in *hdr*|*unicode*)
    if "$Z" l -pWRONG "$a" > /dev/null 2>&1; then echo "FAIL $n header listable with wrong password"; exit 1; fi ;;
  esac
  X=$(mktemp -d /tmp/encv-x.XXXX)
  "$Z" x -bd "-p$p" -o"$X" "$a" > /dev/null
  diff -r "$D/src" "$X" || { echo "FAIL $n tree differs"; exit 1; }
  rm -rf "$X" "$D/$n.log"
  echo "OK $n"
done
