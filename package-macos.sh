#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname)" != "Darwin" ]]; then
    echo "Error: This script must be run on macOS." >&2
    exit 1
fi

APP_NAME="Askrypt"
BUNDLE="${APP_NAME}.app"
VERSION=$(grep '^version = ' Cargo.toml | head -1 | cut -d'"' -f2)

echo "Building $APP_NAME $VERSION for macOS..."
cargo build --release

BINARY="target/release/askrypt"

echo "Creating $BUNDLE..."
rm -rf "$BUNDLE"
mkdir -p "$BUNDLE/Contents/MacOS"
mkdir -p "$BUNDLE/Contents/Resources"

# Binary
cp "$BINARY" "$BUNDLE/Contents/MacOS/askrypt"

# Info.plist — substitute version placeholder
sed "s/{{VERSION}}/$VERSION/g" static/Info.plist > "$BUNDLE/Contents/Info.plist"

# Convert PNG to .icns using macOS built-in tools
ICONSET_DIR="$(mktemp -d)/askrypt.iconset"
mkdir -p "$ICONSET_DIR"
sips -z 16   16   static/logo-128.png --out "$ICONSET_DIR/icon_16x16.png"      >/dev/null
sips -z 32   32   static/logo-128.png --out "$ICONSET_DIR/icon_16x16@2x.png"   >/dev/null
sips -z 32   32   static/logo-128.png --out "$ICONSET_DIR/icon_32x32.png"      >/dev/null
sips -z 64   64   static/logo-128.png --out "$ICONSET_DIR/icon_32x32@2x.png"   >/dev/null
sips -z 128  128  static/logo-128.png --out "$ICONSET_DIR/icon_128x128.png"    >/dev/null
sips -z 256  256  static/logo-128.png --out "$ICONSET_DIR/icon_128x128@2x.png" >/dev/null
sips -z 256  256  static/logo-128.png --out "$ICONSET_DIR/icon_256x256.png"    >/dev/null
sips -z 512  512  static/logo-128.png --out "$ICONSET_DIR/icon_256x256@2x.png" >/dev/null
sips -z 512  512  static/logo-128.png --out "$ICONSET_DIR/icon_512x512.png"    >/dev/null
sips -z 1024 1024 static/logo-128.png --out "$ICONSET_DIR/icon_512x512@2x.png" >/dev/null
iconutil -c icns "$ICONSET_DIR" -o "$BUNDLE/Contents/Resources/askrypt.icns"

echo "Done! To open: open \"$BUNDLE\""
