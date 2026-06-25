#!/usr/bin/env bash
# Verifies the nil-deref bugs in user.go were fixed.
# Pass: `go test` exits 0 with all 4 tests passing — including the two
# nil-Email/nil-Profile cases that panic on the starting code.

set -euo pipefail
cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
    echo "FAIL: go not found in PATH" >&2
    exit 1
fi

go test ./... 2>&1 | tail -10
echo "OK: go test passes (nil-deref fixed)"
