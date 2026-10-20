#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Local 7-Zip 26.04 oracle for differential testing (external CLI only; no
# 7-Zip code is part of Sediment).
#
#   tools/oracle.sh path            print the verified local 7zz path (download
#                                   + verify on first use); exit 1 if none
#   tools/oracle.sh 7zz ARGS...     run the pinned oracle with ARGS
#   tools/oracle.sh diff [ARGS...]  run tests/diff/run_diff.py against the
#                                   oracle. Prefers the local cached binary;
#                                   falls back to `ssh $SEDIMENT_ORACLE_HOST`
#                                   (default sync-sparky-local) when no local
#                                   binary can be provisioned. ARGS go to
#                                   run_diff.py (--only, --report, --sediment,
#                                   --jobs, --keep). The corpus is generated at
#                                   run time under target/oracle-diff (ignored).
#
# Pins come from tools/oracle-reference-lock.json: the package bytes must
# match publisher_sha256, and the extracted executable must match
# executable_sha256 when that is recorded. Nothing found on PATH is used.
#
# Environment: SEDIMENT_ORACLE_CACHE (default ~/.cache/sediment-oracle),
# SEDIMENT_ORACLE_HOST, SEDIMENT_ORACLE_OFFLINE=1 (never download),
# SEDIMENT_ORACLE_REMOTE=1 (skip the local binary, always use ssh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/tools/oracle-reference-lock.json"
CACHE="${SEDIMENT_ORACLE_CACHE:-$HOME/.cache/sediment-oracle}"
HOST="${SEDIMENT_ORACLE_HOST:-sync-sparky-local}"

die() { echo "oracle.sh: $*" >&2; exit 1; }

sha256() {
    if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
    else sha256sum "$1" | cut -d' ' -f1; fi
}

asset_name() {
    case "$(uname -s)/$(uname -m)" in
        Darwin/*) echo "7z2604-mac.tar.xz" ;;
        Linux/x86_64) echo "7z2604-linux-x64.tar.xz" ;;
        Linux/aarch64 | Linux/arm64) echo "7z2604-linux-arm64.tar.xz" ;;
        *) return 1 ;;
    esac
}

# lock_field ASSET FIELD -> value ("" when null/missing)
lock_field() {
    python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
for a in d["selected_official_assets"]:
    if a["name"] == sys.argv[2]:
        v = a.get(sys.argv[3])
        print("" if v is None else v)
        break
else:
    sys.exit(1)
' "$LOCK" "$1" "$2"
}

# Prints the verified local oracle path, provisioning it if needed.
local_oracle() {
    [ -f "$LOCK" ] || die "missing $LOCK"
    local asset tag pkg_sha exe_sha url exe_rel dir exe pkg tmp
    asset="$(asset_name)" || { echo "oracle.sh: no pinned asset for $(uname -sm)" >&2; return 1; }
    tag="$(lock_field "$asset" release_tag)"
    pkg_sha="$(lock_field "$asset" publisher_sha256)"
    exe_sha="$(lock_field "$asset" executable_sha256)"
    url="$(lock_field "$asset" download_url)"
    exe_rel="$(lock_field "$asset" executable_path)"
    [ -n "$pkg_sha" ] && [ -n "$url" ] && [ -n "$exe_rel" ] || die "incomplete lock entry for $asset"
    dir="$CACHE/$tag/${asset%.tar.xz}"
    exe="$dir/x/$exe_rel"
    if [ ! -x "$exe" ]; then
        pkg="$dir/$asset"
        mkdir -p "$dir"
        if [ ! -f "$pkg" ] || [ "$(sha256 "$pkg")" != "$pkg_sha" ]; then
            [ "${SEDIMENT_ORACLE_OFFLINE:-}" = 1 ] && { echo "oracle.sh: offline and $asset not cached" >&2; return 1; }
            echo "oracle.sh: downloading $url" >&2
            curl -fsSL --retry 2 -o "$pkg.part" "$url" || { rm -f "$pkg.part"; echo "oracle.sh: download failed" >&2; return 1; }
            mv "$pkg.part" "$pkg"
        fi
        [ "$(sha256 "$pkg")" = "$pkg_sha" ] || { rm -f "$pkg"; die "$asset digest mismatch (want $pkg_sha)"; }
        tmp="$(mktemp -d "$dir/x.XXXXXX")"
        tar -xJf "$pkg" -C "$tmp"
        rm -rf "$dir/x"
        mv "$tmp" "$dir/x"
        [ -x "$exe" ] || die "$exe_rel not found in $asset"
    fi
    if [ -n "$exe_sha" ] && [ "$(sha256 "$exe")" != "$exe_sha" ]; then
        die "$exe digest mismatch (want $exe_sha); delete $dir to re-provision"
    fi
    "$exe" >/dev/null 2>&1 || { echo "oracle.sh: $exe does not run here" >&2; return 1; }
    echo "$exe"
}

cmd="${1:-}"
[ $# -gt 0 ] && shift
case "$cmd" in
    path)
        local_oracle
        ;;
    7zz)
        exe="$(local_oracle)" || exit 1
        exec "$exe" "$@"
        ;;
    diff)
        exe=""
        if [ "${SEDIMENT_ORACLE_REMOTE:-}" != 1 ]; then
            exe="$(local_oracle)" || exe=""
        fi
        if [ -n "$exe" ]; then
            work="$ROOT/target/oracle-diff"
            rm -rf "$work"
            mkdir -p "$work"
            cd "$ROOT"
            exec python3 -I tests/diff/run_diff.py --run --oracle "$exe" --work "$work" "$@"
        fi
        echo "oracle.sh: no local oracle; using ssh $HOST" >&2
        cd "$ROOT"
        exec python3 -I tests/diff/run_diff.py --host "$HOST" "$@"
        ;;
    *)
        sed -n '4,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
        exit 2
        ;;
esac
