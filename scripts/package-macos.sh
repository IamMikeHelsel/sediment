#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin ]] || { echo 'macOS is required to package sediment.' >&2; exit 1; }
# Build separately so packaging never quietly changes the tested executable.
[[ -x target/release/sediment ]] || { echo 'Run cargo build --release --locked first.' >&2; exit 1; }
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Expected numeric package version.' >&2; exit 1; }
# Reject stale builds rather than label an older executable as this release.
actual_version=$("target/release/sediment" --version)
[[ "$actual_version" == "sediment $version" ]] || { echo "Build version mismatch: expected sediment $version, got $actual_version" >&2; exit 1; }
arch=$(uname -m)
if [[ "$(uname -s)" == Darwin ]]; then
  binary_arch=$(lipo -archs "target/release/sediment")
  [[ "$binary_arch" == "$arch" ]] || { echo "Architecture mismatch: host $arch, executable $binary_arch" >&2; exit 1; }
fi
mkdir -p dist
stage=$(mktemp -d "$PWD/dist/.package.XXXXXX")
trap 'rm -rf "$stage"' EXIT
app="$stage/sediment.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp target/release/sediment "$app/Contents/MacOS/sediment"
chmod 755 "$app/Contents/MacOS/sediment"
[[ ! -f assets/sediment.icns ]] || cp assets/sediment.icns "$app/Contents/Resources/"
for doc in LICENSE README.md THIRD_PARTY_NOTICES.md CHANGELOG.md; do
  [[ ! -f "$doc" ]] || cp "$doc" "$app/Contents/Resources/"
done
[[ ! -d docs ]] || cp -R docs "$app/Contents/Resources/"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>sediment</string>
<key>CFBundleIdentifier</key><string>dev.lab44.sediment</string>
<key>CFBundleName</key><string>sediment</string>
<key>CFBundleDisplayName</key><string>sediment</string>
<key>CFBundleIconFile</key><string>sediment.icns</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>CFBundleVersion</key><string>$version</string>
<key>NSHighResolutionCapable</key><true/>
<key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
</dict></plist>
PLIST
plutil -lint "$app/Contents/Info.plist"
identity="${SEDIMENT_SIGN_IDENTITY:--}"
if [[ "$identity" == '-' ]]; then
  codesign --force --sign - "$app"
else
  codesign --force --options runtime --timestamp --sign "$identity" "$app"
fi
codesign --verify --deep --strict --verbose=2 "$app"
# Replace only generated release products after staging and signature validation succeed.
rm -rf dist/sediment.app
mv "$app" dist/sediment.app
archive="sediment-$version-macos-$arch.zip"
ditto -c -k --sequesterRsrc --keepParent dist/sediment.app "$stage/$archive"
mv "$stage/$archive" "dist/$archive"
(cd dist && shasum -a 256 "$archive" > "$archive.sha256")
echo "Created dist/$archive"
if [[ "$identity" == '-' ]]; then
  echo 'Local preview only: ad-hoc signed, not Developer ID signed or notarized.'
else
  echo 'Developer ID signed; notarization and Gatekeeper validation are still required.'
fi
