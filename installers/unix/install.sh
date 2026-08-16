#!/bin/sh
set -e

# ========================================================================================= #
# Zen IdP installer for macOS and Linux.                                                    #
#                                                                                           #
# Usage:                                                                                    #
#   curl -fsSL https://get.varavel.com/zen-idp | sh                                         #
#                                                                                           #
# Options:                                                                                  #
#   VERSION     : Specify a version (e.g., vx.x.x). Defaults to "latest".                   #
#   INSTALL_DIR : Directory to install the binary. Defaults to "/usr/local/bin".            #
#   QUIET       : Set to "true" to suppress all output (e.g., QUIET=true).                  #
#                                                                                           #
# Examples:                                                                                 #
#   # Install or update to latest version                                                   #
#   curl -fsSL https://get.varavel.com/zen-idp | sh                                         #
#                                                                                           #
#   # Install specific version                                                              #
#   curl -fsSL https://get.varavel.com/zen-idp | VERSION=vx.x.x sh                          #
#                                                                                           #
#   # Install to a custom directory quietly                                                 #
#   curl -fsSL https://get.varavel.com/zen-idp | INSTALL_DIR=$HOME/.local/bin QUIET=true sh #
# ========================================================================================= #

REPO="varavelio/zen-idp"
BINARY_NAME="zen-idp"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-}"
QUIET="${QUIET:-false}"

setup_colors() {
  if [ -t 1 ] && [ "$QUIET" != "true" ]; then
    RED="$(printf '\033[31m')"
    GREEN="$(printf '\033[32m')"
    YELLOW="$(printf '\033[33m')"
    BLUE="$(printf '\033[34m')"
    BOLD="$(printf '\033[1m')"
    NC="$(printf '\033[0m')"
  else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    BOLD=''
    NC=''
  fi
}

log_info() {
  if [ "$QUIET" != "true" ]; then printf "%s[INFO]%s %s\n" "$GREEN" "$NC" "$1"; fi
}

log_warn() {
  if [ "$QUIET" != "true" ]; then printf "%s[WARN]%s %s\n" "$YELLOW" "$NC" "$1"; fi
}

log_error() {
  if [ "$QUIET" != "true" ]; then printf "%s[ERROR]%s %s\n" "$RED" "$NC" "$1" >&2; fi
}

print_banner() {
  if [ "$QUIET" != "true" ]; then
    printf "%s%sZen IdP - declarative, zero-maintenance OIDC Identity Provider%s\n" "$BLUE" "$BOLD" "$NC"
  fi
}

cleanup() {
  if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi
}
trap cleanup EXIT

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log_error "Missing dependency: $1 is required."
    exit 1
  fi
}

check_dependencies() {
  require_command curl
  require_command grep
  require_command sed
  require_command tar
  require_command tr
  require_command uname
}

detect_platform() {
  os_name="$(uname -s)"
  arch_name="$(uname -m)"

  case "$os_name" in
    Linux) PLATFORM_OS="linux" ;;
    Darwin) PLATFORM_OS="darwin" ;;
    *) log_error "Unsupported OS: $os_name"; exit 1 ;;
  esac

  case "$arch_name" in
    x86_64|amd64) PLATFORM_ARCH="amd64" ;;
    arm64|aarch64) PLATFORM_ARCH="arm64" ;;
    *) log_error "Unsupported architecture: $arch_name"; exit 1 ;;
  esac
}

get_version() {
  if [ -z "$VERSION" ] || [ "$VERSION" = "latest" ]; then
    log_info "Fetching latest version..."
    VERSION="$(curl -fsSI "https://github.com/$REPO/releases/latest" | tr -d '\r' | sed -nE 's#^[Ll]ocation:[[:space:]]*.*/tag/(v?[^[:space:]]+).*#\1#p' | tail -n 1)"
    if [ -z "$VERSION" ]; then
      log_error "Failed to determine latest version. Set VERSION=vx.y.z and retry."
      exit 1
    fi
  fi

  case "$VERSION" in
    v*) ;;
    *) VERSION="v$VERSION" ;;
  esac

  if [ "$VERSION" = "v" ]; then
    log_error "Invalid version. Set VERSION=vx.y.z and retry."
    exit 1
  fi
}

verify_checksum() {
  cd "$TMP_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    grep "  $FILENAME$" checksums.txt | sha256sum -c - >/dev/null 2>&1 || {
      log_error "Checksum verification failed."
      exit 1
    }
  elif command -v shasum >/dev/null 2>&1; then
    grep "  $FILENAME$" checksums.txt | shasum -a 256 -c - >/dev/null 2>&1 || {
      log_error "Checksum verification failed."
      exit 1
    }
  else
    log_warn "Neither sha256sum nor shasum found. Skipping checksum verification."
  fi
  cd - >/dev/null
}

install_binary() {
  TMP_DIR="$(mktemp -d)"
  FILENAME="${BINARY_NAME}_${PLATFORM_OS}_${PLATFORM_ARCH}.tar.gz"
  DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$FILENAME"
  CHECKSUMS_URL="https://github.com/$REPO/releases/download/$VERSION/checksums.txt"

  log_info "Installing $VERSION"
  log_info "Downloading $FILENAME..."
  curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/$FILENAME"
  curl -fsSL "$CHECKSUMS_URL" -o "$TMP_DIR/checksums.txt"

  log_info "Verifying checksum..."
  verify_checksum

  log_info "Extracting..."
  tar -xzf "$TMP_DIR/$FILENAME" -C "$TMP_DIR"

  BIN_SOURCE="$TMP_DIR/$BINARY_NAME"
  if [ ! -f "$BIN_SOURCE" ]; then
    log_error "Binary not found in archive."
    exit 1
  fi

  log_info "Installing to $INSTALL_DIR..."
  if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR" 2>/dev/null || {
      if command -v sudo >/dev/null 2>&1; then
        sudo mkdir -p "$INSTALL_DIR"
      else
        log_error "Cannot create $INSTALL_DIR. Set INSTALL_DIR to a writable directory."
        exit 1
      fi
    }
  fi

  if [ -w "$INSTALL_DIR" ]; then
    mv "$BIN_SOURCE" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
  elif command -v sudo >/dev/null 2>&1 && [ -t 0 ]; then
    log_warn "$INSTALL_DIR is not writable. Attempting sudo..."
    sudo mv "$BIN_SOURCE" "$INSTALL_DIR/$BINARY_NAME"
    sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
  else
    log_error "Cannot write to $INSTALL_DIR. Retry with INSTALL_DIR=\$HOME/.local/bin."
    exit 1
  fi

  log_info "Installation complete. Run 'zen-idp help' to verify."
}

setup_colors
print_banner
check_dependencies
detect_platform
get_version
install_binary
