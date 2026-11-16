#!/bin/sh
# vpshield installer: downloads the latest release binary for this CPU.
# usage: curl -fsSL https://raw.githubusercontent.com/ciruzz00/vpshield/main/install.sh | sudo sh
set -eu

REPO="${VPSHIELD_REPO:-ciruzz00/vpshield}"   # override with VPSHIELD_REPO
DEST="${VPSHIELD_DEST:-/usr/local/bin/vpshield}"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv7) ARCH=armv7 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo sh)" >&2; exit 1; }

BASE="https://github.com/$REPO/releases/latest/download"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$2" "$1"
  else wget -qO "$2" "$1"; fi
}

echo "downloading vpshield-linux-$ARCH from $REPO ..."
fetch "$BASE/vpshield-linux-$ARCH" "$TMP/vpshield"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS"

( cd "$TMP" && grep " vpshield-linux-$ARCH\$" SHA256SUMS | sed "s/vpshield-linux-$ARCH/vpshield/" | sha256sum -c - ) \
  || { echo "checksum mismatch, aborting" >&2; exit 1; }

install -m 0755 "$TMP/vpshield" "$DEST"
echo "installed $DEST ($("$DEST" version))"
echo "start with: sudo vpshield --dry-run   (preview)   or   sudo vpshield"
