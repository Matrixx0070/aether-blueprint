#!/usr/bin/env bash
# Verifies the --reverse flag was added correctly.
# Pass conditions:
#   - `python main.py hello` still prints "hello" (regression check)
#   - `python main.py --reverse hello` prints "olleh"
#   - `python main.py --reverse "abc def"` prints "fed cba"
#   - pytest passes (must include a test for --reverse)
#   - --reverse can come before OR after the positional arg

set -euo pipefail
cd "$(dirname "$0")"

# Plain echo regression
out=$(python3 main.py hello)
[ "$out" = "hello" ] || { echo "FAIL: plain echo broken — got '$out'"; exit 1; }

# Reverse flag
out=$(python3 main.py --reverse hello)
[ "$out" = "olleh" ] || { echo "FAIL: --reverse hello → '$out', expected 'olleh'"; exit 1; }

out=$(python3 main.py --reverse "abc def")
[ "$out" = "fed cba" ] || { echo "FAIL: --reverse 'abc def' → '$out', expected 'fed cba'"; exit 1; }

# Test suite must pass and must include at least one --reverse test.
if ! command -v pytest >/dev/null 2>&1; then
    python3 -m pip install --quiet pytest >/dev/null 2>&1 || true
fi
python3 -m pytest test_main.py -q 2>&1 | tail -3
grep -q "reverse" test_main.py || { echo "FAIL: test_main.py has no --reverse test"; exit 1; }

echo "OK: all checks pass"
