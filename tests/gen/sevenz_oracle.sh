#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Oracle fixture recipe for tests/fixtures/sevenz/oracle (run on sparky, 2026-10-19).
# Oracle: 7-Zip 26.04 linux-arm64 `7zz`, from 7z2604-linux-arm64.tar.xz
#   tarball sha256 5b0ac3aa91c1e3499f011d6af69d7f6b4de3ef2f011d9e2ff44c58ebd04aa388 (matches reference/provenance.json)
#   7zz sha256     a01daa025fcf2dbb76ab40f2854f09b3462d1912add61ee2f4431ce11902d0cd (identical to the tarball member)
# Only used as an external CLI oracle; no 7-Zip code is part of Sediment.
# Usage: S=$(mktemp -d /tmp/sevenz-fixtures.XXXX); bash sevenz_oracle.sh $S; copy $S/out/*; rm -rf $S
set -e
S=$1; Z=${Z:-/home/mike/sediment-rust-20261019/reference/7zz}
mkdir -p $S/in $S/out; cd $S/in
printf "Hello, 7z!\n" > hello.txt
python3 -I -c "
open(\"a.txt\",\"w\").write(\"\".join(\"line %04d alpha beta gamma\\n\" % i for i in range(60)))
open(\"b.bin\",\"wb\").write(bytes((i*7+3)&255 for i in range(700)))
open(\"h\\u00e9llo_\\u65e5\\u672c.txt\",\"w\",encoding=\"utf-8\").write(\"unicode name\\n\")
"
: > empty.txt
mkdir -p dir/sub emptydir
printf "nested\n" > dir/sub/nested.txt
chmod 640 hello.txt; chmod 755 dir
find . -exec touch -h -d "2024-03-05 06:07:08.1234567 UTC" {} +
export TZ=UTC LC_ALL=C.UTF-8
rm -f ../out/*
U="h$(printf '\xc3\xa9')llo_$(printf '\xe6\x97\xa5\xe6\x9c\xac').txt"
for spec in "lzma_solid_hc:-m0=LZMA -ms=on -mhc=on" "lzma_solid_nohc:-m0=LZMA -ms=on -mhc=off" "lzma_nonsolid_nohc:-m0=LZMA -ms=off -mhc=off" "lzma2_solid_hc:-m0=LZMA2 -ms=on -mhc=on" "lzma2_nonsolid_nohc:-m0=LZMA2 -ms=off -mhc=off" "copy_solid_nohc:-m0=Copy -ms=on -mhc=off" "copy_nonsolid_nohc:-m0=Copy -ms=off -mhc=off" "copy_solid_hc_times:-m0=Copy -ms=on -mhc=on -mtc=on -mta=on"; do
  n=${spec%%:*}; o=${spec#*:}
  $Z a -bd -mmt=1 $o ../out/$n.7z hello.txt a.txt b.bin empty.txt dir emptydir "$U" > ../out/$n.log 2>&1 || { cat ../out/$n.log; exit 1; }
  $Z l -slt ../out/$n.7z > ../out/$n.slt.txt
  $Z t ../out/$n.7z | grep -q "Everything is Ok"
  rm ../out/$n.log
done
ls -la ../out
# Differential check of the Python-built Copy fixtures (tests/gen/sevenz.py):
#   for f in tests/fixtures/sevenz/gen/*.7z: `7zz t $f` must print "Everything is Ok",
#   and `7zz l -slt $f > ${f%.7z}.slt.txt` (committed; compared in tests/sevenz_read.rs).
