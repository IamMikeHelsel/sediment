#!/bin/sh
# Verify `sediment a -mm=<method>` zips and `-mf=` tars with the pinned 7-Zip
# oracle (7zz). Python's zipfile cannot read Deflate64 (method 9) or XZ (95),
# so those are checked here. Usage (e.g. on sparky):
#   sh tests/gen/zip_tar_write_methods_oracle.sh path/to/sediment path/to/7zz
# Prints one line per archive; exits nonzero on any failure.
set -eu
SED=$(cd "$(dirname "$1")" && pwd)/$(basename "$1"); ORACLE=$2
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
mkdir -p "$D/src/sub"
python3 -I - "$D/src" <<'PY'
import os, random, sys
r = random.Random(7); s = sys.argv[1]
blk = bytes(r.getrandbits(8) for _ in range(50000))
open(os.path.join(s, 'far.bin'), 'wb').write(blk + b'gap' * 2000 + blk + blk[:20000] * 3)
open(os.path.join(s, 'sub', 'a.txt'), 'wb').write(b'hello sediment\n' * 500)
open(os.path.join(s, 'L' * 120 + '.txt'), 'wb').write(b'long\n')
open(os.path.join(s, 'café.txt'), 'wb').write(b'uni\n')
PY
fail=0
for m in Deflate Deflate64 BZip2 LZMA XZ; do
  for l in 1 9; do
    (cd "$D/src" && "$SED" a -mm=$m -mx$l "$D/$m-$l.zip" . >/dev/null)
    if "$ORACLE" t "$D/$m-$l.zip" | grep -q 'Everything is Ok'; then echo "ok   $m -mx$l"; else echo "FAIL $m -mx$l"; fail=1; fi
  done
done
for f in gnu pax posix; do
  (cd "$D/src" && "$SED" a -mf=$f "$D/$f.tar" . >/dev/null)
  if "$ORACLE" t "$D/$f.tar" | grep -q 'Everything is Ok'; then echo "ok   tar -mf=$f"; else echo "FAIL tar -mf=$f"; fail=1; fi
done
exit $fail
