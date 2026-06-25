#!/usr/bin/env bash
#
# aether-blueprint install script.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Matrixx0070/aether-blueprint/main/install.sh | bash
#   # or pin to a version:
#   curl -fsSL https://raw.githubusercontent.com/Matrixx0070/aether-blueprint/main/install.sh | AETHER_VERSION=v0.12.0 bash
#   # or install to a custom prefix:
#   curl -fsSL https://raw.githubusercontent.com/Matrixx0070/aether-blueprint/main/install.sh | AETHER_PREFIX=/usr/local bash
#
# What it does:
#   1. Detects OS + arch via uname.
#   2. Resolves the requested version (default: latest GitHub release tag).
#   3. Downloads the matching tarball + SHA256SUMS from the GitHub release.
#   4. Verifies the SHA256 hash.
#   5. Extracts the `aether` binary to $AETHER_PREFIX/bin (default: ~/.local/bin).
#   6. Prints a success line + a PATH hint if the prefix isn't on PATH.

set -euo pipefail

REPO="Matrixx0070/aether-blueprint"
PREFIX="${AETHER_PREFIX:-$HOME/.local}"
VERSION="${AETHER_VERSION:-latest}"

# ── platform detection ────────────────────────────────────────────────────

os_raw="$(uname -s)"
arch_raw="$(uname -m)"

case "$os_raw" in
  Linux)  os="linux" ;;
  Darwin) os="macos" ;;
  *)
    echo "error: unsupported OS '$os_raw'" >&2
    echo "  aether ships binaries for Linux and macOS only." >&2
    echo "  Build from source: https://github.com/$REPO" >&2
    exit 1
    ;;
esac

case "$arch_raw" in
  x86_64|amd64) arch="x86_64" ;;
  aarch64|arm64) arch="aarch64" ;;
  *)
    echo "error: unsupported arch '$arch_raw'" >&2
    echo "  aether ships binaries for x86_64 and aarch64 only." >&2
    exit 1
    ;;
esac

ARCHIVE_SUFFIX="${os}-${arch}"
echo "[install] detected platform: $ARCHIVE_SUFFIX"

# ── tool detection ────────────────────────────────────────────────────────

# Pick a downloader: curl preferred, wget fallback.
if command -v curl >/dev/null 2>&1; then
  DL_CMD="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
  DL_CMD="wget -qO-"
else
  echo "error: neither curl nor wget found in PATH" >&2
  exit 1
fi

# Pick a sha256 verifier: sha256sum on Linux, shasum on macOS.
if command -v sha256sum >/dev/null 2>&1; then
  SHA_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA_CMD="shasum -a 256"
else
  echo "error: neither sha256sum nor shasum found in PATH" >&2
  exit 1
fi

# ── resolve version ───────────────────────────────────────────────────────

if [ "$VERSION" = "latest" ]; then
  echo "[install] resolving latest release tag…"
  LATEST_URL="https://api.github.com/repos/${REPO}/releases/latest"
  # GitHub returns JSON; grep out the tag_name field.
  TAG="$($DL_CMD "$LATEST_URL" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  if [ -z "$TAG" ]; then
    echo "error: could not resolve latest release tag from $LATEST_URL" >&2
    echo "  (network issue, or no releases published yet)" >&2
    exit 1
  fi
  VERSION="$TAG"
fi
echo "[install] target version: $VERSION"

# ── download + verify ─────────────────────────────────────────────────────

ARCHIVE="aether-${VERSION}-${ARCHIVE_SUFFIX}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
ARCHIVE_URL="${BASE_URL}/${ARCHIVE}"
SHA_URL="${BASE_URL}/SHA256SUMS"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "[install] downloading $ARCHIVE…"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL -o "$TMPDIR/$ARCHIVE" "$ARCHIVE_URL"
  curl -fsSL -o "$TMPDIR/SHA256SUMS" "$SHA_URL"
else
  wget -q -O "$TMPDIR/$ARCHIVE" "$ARCHIVE_URL"
  wget -q -O "$TMPDIR/SHA256SUMS" "$SHA_URL"
fi

echo "[install] verifying SHA256…"
EXPECTED_SHA="$(grep " $ARCHIVE\$" "$TMPDIR/SHA256SUMS" | awk '{print $1}')"
if [ -z "$EXPECTED_SHA" ]; then
  echo "error: $ARCHIVE not found in SHA256SUMS" >&2
  echo "  available entries:" >&2
  sed 's/^/    /' "$TMPDIR/SHA256SUMS" >&2
  exit 1
fi
ACTUAL_SHA="$($SHA_CMD "$TMPDIR/$ARCHIVE" | awk '{print $1}')"
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  echo "error: SHA256 mismatch for $ARCHIVE" >&2
  echo "  expected: $EXPECTED_SHA" >&2
  echo "  actual:   $ACTUAL_SHA" >&2
  exit 1
fi
echo "[install] SHA256 OK"

# ── extract + install ─────────────────────────────────────────────────────

mkdir -p "$PREFIX/bin"
( cd "$TMPDIR" && tar -xzf "$ARCHIVE" )
if [ ! -f "$TMPDIR/aether" ]; then
  echo "error: tarball did not contain an 'aether' binary" >&2
  ls -la "$TMPDIR" >&2
  exit 1
fi
install -m 0755 "$TMPDIR/aether" "$PREFIX/bin/aether"
echo "[install] installed $PREFIX/bin/aether"

# ── verify + PATH hint ────────────────────────────────────────────────────

INSTALLED_VERSION="$("$PREFIX/bin/aether" --version 2>&1 | head -1 || echo "unknown")"
echo "[install] $INSTALLED_VERSION"

case ":$PATH:" in
  *":$PREFIX/bin:"*)
    echo "[install] done. Run \`aether\` to start."
    ;;
  *)
    echo
    echo "[install] $PREFIX/bin is not on your PATH. Add this line to your shell rc:"
    echo
    echo "    export PATH=\"$PREFIX/bin:\$PATH\""
    echo
    echo "Then reopen your terminal or \`source\` the rc file."
    ;;
esac
