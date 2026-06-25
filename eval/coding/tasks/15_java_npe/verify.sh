#!/usr/bin/env bash
# Verifies NPE bugs in Inventory.java were fixed.
# Pass: javac compiles + InventoryTest exits 0 (all 7 assertions pass).

set -euo pipefail
cd "$(dirname "$0")"

WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

if ! command -v javac >/dev/null 2>&1; then
    echo "FAIL: javac not found in PATH" >&2
    exit 1
fi

javac -d "$WORK" Inventory.java InventoryTest.java 2>&1
java -cp "$WORK" InventoryTest 2>&1 | tail -10

echo "OK: Inventory NPE bugs fixed"
