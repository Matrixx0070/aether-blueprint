#!/usr/bin/env bash
# Build aether-cli in release mode and install the binary into ~/.local/bin.
# Honors AETHER_PREFIX to override the install destination.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST_DIR="${AETHER_PREFIX:-$HOME/.local/bin}"

# Ensure cargo is reachable even when the parent shell didn't source profile.
if ! command -v cargo >/dev/null 2>&1; then
    for p in "$HOME/.cargo/bin" /usr/local/cargo/bin; do
        if [ -x "$p/cargo" ]; then
            export PATH="$p:$PATH"
            break
        fi
    done
fi
if ! command -v cargo >/dev/null 2>&1; then
    echo "[aether] error: cargo not found. Install Rust: https://rustup.rs" >&2
    exit 1
fi

echo "[aether] building release binary..."
( cd "$REPO_ROOT" && cargo build -p aether-cli --release )

echo "[aether] installing to $DEST_DIR/aether"
mkdir -p "$DEST_DIR"
install -m 0755 "$REPO_ROOT/target/release/aether" "$DEST_DIR/aether"

echo
echo "[aether] installed. Make sure $DEST_DIR is on your PATH."
echo "[aether] Try:"
echo "         aether --model claude-haiku-4-5-20251001 --print 'Reply: pong'"
