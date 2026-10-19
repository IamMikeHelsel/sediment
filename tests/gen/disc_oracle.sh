#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Oracle fixtures for tests/disc.rs, made by independent tools (2026-10-19).
#
#   bash tests/gen/disc_oracle.sh mac   OUTDIR            # macOS: hdiutil UDF 1.02 image
#   bash tests/gen/disc_oracle.sh linux OUTDIR FIXDIR     # sparky: xorriso Rock Ridge image,
#                                                          # plus 7zz extraction manifests of
#                                                          # the hand-built fixtures in FIXDIR
# Tools: hdiutil (macOS 27), xorriso 1.5.6, 7-Zip 26.04 `7zz` (pinned binary, see
# sevenz_oracle.sh). They are only run as external programs; no code from them is used.
# Copy OUTDIR/* into tests/fixtures/disc/.
#
# Manifest format (shared with disc.py): kind path size mode mtime sha256-or-target
set -euo pipefail
MODE=$1; OUT=$(cd "$2" && pwd); FIX=${3:-}
S=$(mktemp -d /tmp/disc-oracle.XXXX)
trap 'rm -rf "$S"' EXIT
export TZ=UTC LC_ALL=C.UTF-8

make_tree() { # $1 = root, $2 = with_specials (1/0)
  python3 -I - "$1" "$2" <<'EOF'
import os, sys
root, specials = sys.argv[1], sys.argv[2] == "1"
os.makedirs(os.path.join(root, "dir1/sub"))
os.makedirs(os.path.join(root, "empty_dir"))
def w(p, b):
    with open(os.path.join(root, p), "wb") as f:
        f.write(b)
w("hello.txt", b"hello oracle\n")
w("dir1/big.bin", bytes((i * 7 + 3) % 251 for i in range(70000)))
w("dir1/sub/deep.txt", b"deep\n")
w("empty.txt", b"")
w("café 日本.txt", "unicode name\n".encode())
w("Long Mixed-Case name with spaces, more than thirty-one chars.txt", b"long\n")
os.chmod(os.path.join(root, "hello.txt"), 0o640)
os.chmod(os.path.join(root, "dir1/sub"), 0o750)
if specials:
    os.symlink("../hello.txt", os.path.join(root, "dir1/link"))
    os.symlink("/etc/hosts", os.path.join(root, "abs_link"))
    os.mkfifo(os.path.join(root, "fifo"))
for dp, dns, fns in os.walk(root, topdown=False):
    for n in fns + dns:
        os.utime(os.path.join(dp, n), (1700000000, 1700000000), follow_symlinks=False)
EOF
}

manifest() { # $1 = root, $2 = manifest file
  python3 -I - "$1" "$2" <<'EOF'
import hashlib, os, stat, sys
root, out = sys.argv[1], sys.argv[2]
rows = []
for dp, dns, fns in os.walk(root):
    for n in sorted(dns + fns):
        p = os.path.join(dp, n)
        rel = os.path.relpath(p, root)
        st = os.lstat(p)
        m = st.st_mode
        if stat.S_ISDIR(m):
            rows.append(("d", rel, 0, "%o" % m, int(st.st_mtime), "-"))
        elif stat.S_ISLNK(m):
            rows.append(("l", rel, 0, "%o" % m, int(st.st_mtime), os.readlink(p)))
        elif stat.S_ISREG(m):
            data = open(p, "rb").read()
            rows.append(("f", rel, len(data), "%o" % m, int(st.st_mtime), hashlib.sha256(data).hexdigest()))
        else:
            rows.append(("o", rel, 0, "%o" % m, int(st.st_mtime), "-"))
rows.sort(key=lambda r: r[1])
with open(out, "w", encoding="utf-8") as f:
    f.write("".join("\t".join(map(str, r)) + "\n" for r in rows))
EOF
}

case $MODE in
mac)
  make_tree "$S/src" 0
  hdiutil makehybrid -quiet -udf -udf-version 1.02 -udf-volume-name ORACLE -o "$S/u.iso" "$S/src"
  gzip -9n < "$S/u.iso" > "$OUT/hdiutil_udf.img.gz"
  manifest "$S/src" "$OUT/hdiutil_udf.img.manifest"
  ;;
linux)
  make_tree "$S/src" 1
  xorriso -as mkisofs -quiet -R -J -V ORACLE -o "$S/r.iso" "$S/src"
  gzip -9n < "$S/r.iso" > "$OUT/xorriso_rr.iso.gz"
  manifest "$S/src" "$OUT/xorriso_rr.iso.manifest"
  # 7zz cross-check of hand-built fixtures: extract and record what it saw.
  Z=${Z:-/home/mike/sediment-rust-20261019/reference/7zz}
  for n in udf102_nolink.img plain.iso; do
    gunzip -c "$FIX/$n.gz" > "$S/$n"
    mkdir -p "$S/x_$n"
    # 7-Zip 26.04 does not extract unrecorded (sparse) extents or allocation
    # extent chains; those files are dropped from its manifest.
    "$Z" x -y -bd -o"$S/x_$n" "$S/$n" > "$S/$n.log" 2>&1 || true
    { grep "Unsupported Method" "$S/$n.log" || true; } | sed 's/.*: //' | while read -r bad; do rm -f "$S/x_$n/$bad"; done
    manifest "$S/x_$n" "$OUT/$n.7zz.manifest"
  done
  ;;
*) echo "usage: $0 mac|linux OUTDIR [FIXDIR]" >&2; exit 2 ;;
esac
