#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)."
    exit 1
fi

echo "Installing askrypt..."

install -Dm755 "$SCRIPT_DIR/target/release/askrypt" /usr/bin/askrypt
install -Dm644 "$SCRIPT_DIR/static/logo-128.png" /usr/share/pixmaps/askrypt.png
install -Dm644 "$SCRIPT_DIR/static/askrypt.desktop" /usr/share/applications/askrypt.desktop

update-desktop-database /usr/share/applications/ 2>/dev/null || true

echo "Done. Askrypt is now available in your application menu"
