#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Oracle fixture recipe for tests/fixtures/enc_archives (run on sparky, 2026-10-19).
# Oracle: 7-Zip 26.04 linux-arm64 `7zz` (sha256 a01daa02...d0cd, see
# tests/gen/sevenz_oracle.sh) and, when installed, Info-ZIP `zip -P`.
# Used only as external CLIs; no 7-Zip code is part of Sediment.
# Source files are written by Python (stdlib only) so the expected plaintext
# is reproducible: tests regenerate the same bytes in Rust (see
# tests/enc_archives.rs `src_files`).
# Usage: S=$(mktemp -d /tmp/enc-fixtures.XXXX); bash enc_archives_oracle.sh $S; cp $S/out/* tests/fixtures/enc_archives/; rm -rf $S
set -euo pipefail
S=$1; Z=${Z:-/home/mike/sediment-rust-20261019/reference/7zz}
mkdir -p "$S/in" "$S/out"; cd "$S/in"
python3 -I -c '
open("a.txt","w").write("".join("line %04d alpha beta gamma\n" % i for i in range(80)))
open("b.bin","wb").write(bytes((i*i*31+i*7+3)&255 for i in range(1500)))
open("small.txt","w").write("tiny\n")
open("empty.txt","w").write("")
import os; os.makedirs("d", exist_ok=True)
open("d/c.txt","w").write("nested file\n")
'
find . -exec touch -h -d "2024-03-05 06:07:08 UTC" {} +
export TZ=UTC LC_ALL=C.UTF-8
F="a.txt b.bin small.txt empty.txt d"
run() { n=$1; shift; "$Z" a -bd -mmt=1 "$@" "../out/$n" $F > /dev/null; }
run aes_lzma2.7z -psecret
run aes_hdr.7z -psecret -mhe=on
run aes_copy.7z -psecret -mx0
run aes_nonsolid.7z -psecret -ms=off -m0=LZMA
run aes_unicode_pw.7z "-ppässwörd€" -mhe=on
run zipcrypto.zip -tzip -psecret
run zipcrypto_store.zip -tzip -psecret -mx0
run aes128.zip -tzip -psecret -mem=AES128
run aes192.zip -tzip -psecret -mem=AES192
run aes256.zip -tzip -psecret -mem=AES256
run aes256_store.zip -tzip -psecret -mem=AES256 -mx0
if command -v zip > /dev/null; then zip -q -r -P secret ../out/infozip_crypt.zip $F; fi
for a in ../out/*; do
  case "$a" in *pässwörd*|*unicode*) p="pässwörd€";; *) p=secret;; esac
  "$Z" t "-p$p" "$a" | grep -q "Everything is Ok" || { echo "oracle self-test failed: $a"; exit 1; }
done
ls -l ../out
