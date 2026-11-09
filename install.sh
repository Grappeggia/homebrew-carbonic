#!/bin/bash
# Carbonic direct installer for Macs without Homebrew (for example Intel Macs).
#
#   curl -fsSL https://raw.githubusercontent.com/Grappeggia/homebrew-carbonic/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/Grappeggia/homebrew-carbonic/main/install.sh | bash -s -- --uninstall
#
# The version and SHA-256 come from this tap's pinned cask, the same values
# `brew install` uses. The archive must match that hash exactly. The installed
# app keeps macOS quarantine, so the normal first-launch approval still applies.
# No sudo is used. Recordings are kept on uninstall.
set -euo pipefail

REPO=Grappeggia/homebrew-carbonic
REF=${CARBONIC_TAP_REF:-main}
BUNDLE_ID=org.carbonic.carbonicapp

fail() { printf 'carbonic-install: %s\n' "$1" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || fail "macOS is required"
major=$(sw_vers -productVersion | cut -d. -f1)
[ "$major" -ge 14 ] || fail "macOS 14 Sonoma or later is required"

if [ -n "${CARBONIC_APPDIR:-}" ]; then
  APPDIR=$CARBONIC_APPDIR
elif [ -w /Applications ]; then
  APPDIR=/Applications
else
  APPDIR="$HOME/Applications"
fi
APP="$APPDIR/Carbonic.app"

quit_app() {
  if pgrep -x Carbonic >/dev/null 2>&1; then
    osascript -e "tell application id \"$BUNDLE_ID\" to quit" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do pgrep -x Carbonic >/dev/null 2>&1 || return 0; sleep 0.5; done
    fail "Carbonic is still running; quit it and retry"
  fi
}

if [ "${1:-}" = --uninstall ]; then
  quit_app
  if [ -d "$APP" ]; then rm -rf "$APP"; echo "Removed $APP (recordings kept)."; else echo "Carbonic is not installed in $APPDIR."; fi
  exit 0
fi
[ $# -eq 0 ] || fail "unknown option: $1"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/carbonic-install.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
curl -fsSL --retry 2 --max-time 60 "https://raw.githubusercontent.com/$REPO/$REF/Casks/carbonic.rb" -o "$WORK/carbonic.rb"
VERSION=$(sed -n 's/^  version "\([0-9][0-9.]*\),\([0-9][0-9]*\)"$/\1-\2/p' "$WORK/carbonic.rb")
SHA=$(sed -n 's/^  sha256 "\([0-9a-f]\{64\}\)"$/\1/p' "$WORK/carbonic.rb")
[ -n "$VERSION" ] && [ -n "$SHA" ] || fail "could not read the pinned version and checksum from the cask"
ZIP="Carbonic-$VERSION-macos-universal2.zip"
echo "Downloading Carbonic $VERSION ..."
curl -fL --retry 2 --max-time 600 --progress-bar "https://github.com/$REPO/releases/download/v$VERSION/$ZIP" -o "$WORK/$ZIP"
ACTUAL=$(shasum -a 256 "$WORK/$ZIP" | cut -d' ' -f1)
[ "$ACTUAL" = "$SHA" ] || fail "checksum mismatch: expected $SHA, got $ACTUAL"
echo "Checksum verified: $SHA"

ditto -xk "$WORK/$ZIP" "$WORK/extract"
[ -d "$WORK/extract/Carbonic.app" ] || fail "archive does not contain Carbonic.app"
codesign --verify --deep --strict "$WORK/extract/Carbonic.app" || fail "code signature check failed"
# Same protection a browser download gets: first launch needs your approval.
xattr -w com.apple.quarantine "0081;$(printf %x "$(date +%s)");carbonic-install;$(uuidgen)" "$WORK/extract/Carbonic.app"

quit_app
mkdir -p "$APPDIR"
rm -rf "$APP"
ditto "$WORK/extract/Carbonic.app" "$APP"
echo "Installed $APP"
cat <<'EOF'
Carbonic is ad-hoc signed and not notarized by Apple. On first launch macOS
blocks it: open System Settings > Privacy & Security, click Open Anyway, and
confirm. To uninstall later, rerun this script with --uninstall.
EOF
