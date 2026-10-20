#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Oracle fixture recipe for the 7z PPMd and BCJ2 fixtures in
# tests/fixtures/sevenz/oracle (ppmd_*.7z, bcj2_*.7z). Run on sparky.
# Oracle: 7-Zip 26.04 linux-arm64 `7zz` (see sevenz_oracle.sh for provenance),
# used only as an external CLI; no 7-Zip code is part of Sediment.
# The x86 input is an ELF64 x86-64 relocatable object compiled by clang from a
# deterministic C source written by this script (static functions, so the
# assembler resolves the E8/E9/Jcc rel32 operands that BCJ2 converts).
# Usage: S=$(mktemp -d /tmp/ppmd-bcj2.XXXX); bash sevenz_ppmd_bcj2_oracle.sh $S; copy $S/out/*; rm -rf $S
set -e
S=$1; Z=${Z:-/home/mike/sediment-rust-20261019/reference/7zz}
mkdir -p $S/in $S/out; cd $S/in
python3 -I - <<'EOF'
import random
r = random.Random(20261019)
words = "the quick brown fox jumps over lazy dog archive sediment stream coder folder range model context order memory".split()
lines = [" ".join(r.choice(words) for _ in range(r.randint(4, 12))) for _ in range(500)]
open("notes.txt", "w").write("\n".join(lines) + "\n")
src = ["typedef unsigned u32;", "volatile u32 sink;"]
n = 160
for i in range(n):
    body = []
    for j in range(r.randint(1, 4)):
        k = r.randrange(i) if i else None
        if k is not None:
            body.append(f"  if ((x ^ {r.randint(1, 999)}u) & {1 << r.randint(0, 9)}u) x = f{k}(x + {j}u); else x -= f{k}(x >> 1);")
        body.append(f"  x = x * {r.randint(3, 99999)}u + {r.randint(0, 9999)}u;")
    body.append("  sink = x;")
    src.append(f"__attribute__((noinline)) static u32 f{i}(u32 x) {{\n" + "\n".join(body) + "\n  return x ^ sink;\n}")
src.append("u32 entry(u32 x) { return " + " + ".join(f"f{i}(x)" for i in range(n - 8, n)) + "; }")
open("prog.c", "w").write("\n".join(src) + "\n")
EOF
clang -target x86_64-linux-gnu -O1 -fno-asynchronous-unwind-tables -fno-ident -c prog.c -o prog.o
file prog.o
find . -exec touch -h -d "2024-03-05 06:07:08 UTC" {} +
export TZ=UTC LC_ALL=C.UTF-8
for spec in "ppmd_solid:-m0=PPMd -ms=on" "ppmd_o8_nonsolid:-m0=PPMd:o=8:mem=1m -ms=off -mhc=off" "bcj2_solid:-mf=BCJ2 -ms=on" "bcj2_lzma_nohc:-mf=BCJ2 -m0=LZMA -ms=on -mhc=off"; do
  n=${spec%%:*}; o=${spec#*:}
  $Z a -bd -mmt=1 $o ../out/$n.7z prog.o notes.txt > ../out/$n.log 2>&1 || { cat ../out/$n.log; exit 1; }
  $Z l -slt ../out/$n.7z > ../out/$n.slt.txt
  $Z t ../out/$n.7z | grep -q "Everything is Ok"
  rm ../out/$n.log
done
ls -la ../out
grep -h "^Method" ../out/*.slt.txt | sort | uniq -c
