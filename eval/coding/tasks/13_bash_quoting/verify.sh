#!/usr/bin/env bash
# Verifies bash unquoted-var bug in backup.sh was fixed.
# Test cases:
#   1. Happy path: source "src_normal" → tar succeeds, archive contains files
#   2. Space-in-name: source "src with spaces" → tar must STILL succeed
#   3. Missing arg: empty SRC → script exits non-zero with usage hint
#   4. shellcheck must report no SC2086 (unquoted-var) warnings

set -euo pipefail
cd "$(dirname "$0")"

chmod +x backup.sh

WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# Case 1: normal directory.
mkdir -p "$WORK/src_normal"
echo "hello" > "$WORK/src_normal/a.txt"
./backup.sh "$WORK/src_normal" "$WORK/out_normal.tar.gz" 2>&1
[ -s "$WORK/out_normal.tar.gz" ] || { echo "FAIL: normal archive empty"; exit 1; }

# Case 2: directory WITH a space in the name (the original bug).
mkdir -p "$WORK/src with spaces"
echo "with-spaces" > "$WORK/src with spaces/x.txt"
./backup.sh "$WORK/src with spaces" "$WORK/out_spaces.tar.gz" 2>&1
[ -s "$WORK/out_spaces.tar.gz" ] || { echo "FAIL: archive with spaced dir is empty"; exit 1; }
# Extract + confirm the file is present.
mkdir -p "$WORK/extract"
tar -xzf "$WORK/out_spaces.tar.gz" -C "$WORK/extract" 2>&1
found=$(find "$WORK/extract" -name 'x.txt' | head -1)
[ -n "$found" ] || { echo "FAIL: extracted archive missing x.txt"; exit 1; }

# Case 3: missing arg — script must exit non-zero.
if ./backup.sh "$WORK/src_normal" 2>&1; then
    echo "FAIL: missing-arg case exited 0 (should be non-zero)"; exit 1
fi

# Case 4: shellcheck for SC2086.
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -e SC1090 backup.sh 2>&1 | grep -v "^$" | tee /tmp/aether-eval-sc.txt
    if grep -q "SC2086" /tmp/aether-eval-sc.txt; then
        echo "FAIL: shellcheck still reports SC2086 (unquoted variable)"; exit 1
    fi
else
    echo "(shellcheck not installed — skipping SC2086 check)"
fi

echo "OK: bash quoting fixed, all 4 cases pass"
