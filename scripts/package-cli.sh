#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
binary=target/cli/release/sediment
[[ -x "$binary" ]] || { echo 'Build with cargo build --locked --release --no-default-features --target-dir target/cli first.' >&2; exit 1; }
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)
platform=$(uname -s | tr '[:upper:]' '[:lower:]')
# Reject stale builds rather than label an older executable as this release.
actual_version=$("target/cli/release/sediment" --version)
[[ "$actual_version" == "sediment $version" ]] || { echo "Build version mismatch: expected sediment $version, got $actual_version" >&2; exit 1; }
arch=$(uname -m)
if [[ "$(uname -s)" == Darwin ]]; then
  binary_arch=$(lipo -archs "$binary")
  [[ "$binary_arch" == "$arch" ]] || { echo "Architecture mismatch: host $arch, executable $binary_arch" >&2; exit 1; }
fi
mkdir -p dist
stage=$(mktemp -d "$PWD/dist/.cli.XXXXXX")
trap 'rm -rf "$stage"' EXIT
cp "$binary" "$stage/sediment"
if [[ "$platform" == darwin && -n "${SEDIMENT_SIGN_IDENTITY:-}" ]]; then
  codesign --force --options runtime --timestamp --sign "$SEDIMENT_SIGN_IDENTITY" "$stage/sediment"
  codesign --verify --strict --verbose=2 "$stage/sediment"
fi
cp docs/CLI_README.md "$stage/README.md"
cp LICENSE THIRD_PARTY_NOTICES.md CHANGELOG.md "$stage/"
mkdir "$stage/docs"
cp docs/UPSTREAM_LICENSES.md "$stage/docs/"
archive="sediment-$version-cli-$platform-$arch.tar.gz"
tar -czf "$stage/$archive" -C "$stage" sediment README.md LICENSE THIRD_PARTY_NOTICES.md CHANGELOG.md docs
mv "$stage/$archive" "dist/$archive"
(cd dist && shasum -a 256 "$archive" > "$archive.sha256")
echo "Created dist/$archive"
