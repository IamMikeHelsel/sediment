#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Golden console output for tests/console_report.rs.
# Oracle: the pinned 7-Zip 26.04 `7zz` from tools/oracle.sh (external CLI
# only; no 7-Zip code is part of Sediment). Run tests/gen/console.py first.
# Usage: bash tests/gen/console_oracle.sh
#   1. builds the 7z / encrypted fixtures with 7zz (new.7z, enc.7z, ench.7z,
#      encaes.zip) and derives badhdr.7z (one header byte flipped) and
#      trunc.7z (first 100 bytes);
#   2. for every line of CASES runs `7zz ARGS` inside tests/fixtures/console
#      and stores NAME.args, NAME.stdout, NAME.stderr and NAME.code.
# `{OUT}` in ARGS stands for a fresh output directory (it never appears in
# the console text). Every case uses -ba, so the banner (which names the
# program and host) is not part of the goldens.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
D="$ROOT/tests/fixtures/console"
Z=${Z:-$(bash "$ROOT/tools/oracle.sh" path)}
export TZ=UTC LC_ALL=C.UTF-8
S=$(mktemp -d /tmp/console-oracle.XXXX)
mkdir -p "$S/src/sub"
printf 'hello\n' > "$S/src/a.txt"
python3 -I -c 'import sys; open(sys.argv[1], "wb").write(b"xyz" * 100)' "$S/src/sub/b.txt"
touch -t 202610191200 "$S/src/a.txt" "$S/src/sub/b.txt" "$S/src/sub"
( cd "$S/src"
  rm -f "$D/new.7z" "$D/enc.7z" "$D/ench.7z" "$D/encaes.zip"
  "$Z" a -bd "$D/new.7z" a.txt sub > /dev/null
  "$Z" a -bd -psecret "$D/enc.7z" a.txt sub > /dev/null
  "$Z" a -bd -psecret -mhe "$D/ench.7z" a.txt sub > /dev/null
  "$Z" a -bd -psecret -mem=AES256 "$D/encaes.zip" a.txt sub > /dev/null )
python3 -I - "$D" <<'EOF'
import pathlib, sys
d = pathlib.Path(sys.argv[1])
b = bytearray((d / 'new.7z').read_bytes())
(d / 'trunc.7z').write_bytes(bytes(b[:100]))
b[-20] ^= 0xFF
(d / 'badhdr.7z').write_bytes(bytes(b))
EOF
CASES='t_good|t -ba good.zip
t_badcrc|t -ba badcrc.zip
t_bb1_badcrc|t -ba -bb1 badcrc.zip
t_junk|t -ba junk.zip
t_unsup|t -ba unsup.zip
t_notarc|t -ba notarc.bin
t_trunc|t -ba trunc.zip
t_new7z|t -ba new.7z
t_bb1_new7z|t -ba -bb1 new.7z
t_wrongpw_7z|t -ba -pwrong enc.7z
t_wrongpw_7zhe|t -ba -pwrong ench.7z
t_wrongpw_aes|t -ba -pwrong encaes.zip
t_badhdr7z|t -ba badhdr.7z
t_trunc7z|t -ba trunc.7z
x_good|x -ba good.zip -o{OUT} -y
x_badcrc|x -ba badcrc.zip -o{OUT} -y
e_good|e -ba good.zip -o{OUT} -y
x_bb1_new7z|x -ba -bb1 new.7z -o{OUT} -y'
while IFS='|' read -r name args; do
  out=$(mktemp -d "$S/out.XXXX")
  printf '%s\n' "$args" > "$D/$name.args"
  # shellcheck disable=SC2086
  set -- ${args//\{OUT\}/$out}
  code=0
  (cd "$D" && "$Z" "$@") > "$D/$name.stdout" 2> "$D/$name.stderr" || code=$?
  printf '%s\n' "$code" > "$D/$name.code"
done <<< "$CASES"
rm -rf "$S"
echo "goldens written to $D"
