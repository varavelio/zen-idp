#!/bin/bash
set -e

VERSION="1.7.0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FONTS_DIR="$SCRIPT_DIR/../internal/ui/static/vendor/fonts"

rm -rf "$FONTS_DIR" && mkdir -p "$FONTS_DIR"
wget -q -O "$FONTS_DIR/LICENSE-GEIST" "https://cdn.jsdelivr.net/npm/geist@$VERSION/LICENSE.txt"
wget -q -P "$FONTS_DIR" "https://cdn.jsdelivr.net/npm/geist@$VERSION/dist/fonts/geist-sans/Geist-Variable.woff2"
wget -q -P "$FONTS_DIR" "https://cdn.jsdelivr.net/npm/geist@$VERSION/dist/fonts/geist-mono/GeistMono-Variable.woff2"

# Verify the WOFF2 magic bytes, which a corrupted or misrouted download would
# fail.
for font in Geist-Variable.woff2 GeistMono-Variable.woff2; do
  if [ "$(head -c 4 "$FONTS_DIR/$font")" != "wOF2" ]; then
    echo "error: $font does not look like a WOFF2 file" >&2
    exit 1
  fi
done
