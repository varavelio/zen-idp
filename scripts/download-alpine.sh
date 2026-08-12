#!/bin/bash
set -e

VERSION="3.16.1"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALPINE_DIR="$SCRIPT_DIR/../internal/ui/static/vendor/alpine"

rm -rf "$ALPINE_DIR" && mkdir -p "$ALPINE_DIR"
wget -q -O "$ALPINE_DIR/alpine.min.js" "https://cdn.jsdelivr.net/npm/alpinejs@$VERSION/dist/cdn.min.js"
wget -q -O "$ALPINE_DIR/LICENSE-ALPINE" "https://cdn.jsdelivr.net/gh/alpinejs/alpine@v$VERSION/LICENSE.md"

# Verify the minified build marker, which the CDN occasionally fails to serve.
if ! grep -q '^(()=>{' "$ALPINE_DIR/alpine.min.js"; then
  echo "error: alpine.min.js does not look like the minified build" >&2
  exit 1
fi
