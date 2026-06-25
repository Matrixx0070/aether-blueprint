#!/usr/bin/env bash
# Verifies the count_words bug was fixed correctly.
# Pass conditions:
#   - count_words("hello world") == 2
#   - count_words("") == 0
#   - count_words("   ") == 0
#   - count_words("one two three four") == 4
# We don't grep the source — we test observable behavior.

set -euo pipefail
cd "$(dirname "$0")"

python3 - <<'PY'
import sys
sys.path.insert(0, ".")
from word_counter import count_words, count_unique_words

checks = [
    ("hello world", 2),
    ("", 0),
    ("   ", 0),
    ("one two three four", 4),
    ("a", 1),
]
failures = []
for inp, expected in checks:
    got = count_words(inp)
    if got != expected:
        failures.append(f"count_words({inp!r}) = {got}, expected {expected}")

# Also ensure count_unique_words still works (regression check).
got = count_unique_words("Hello world hello")
if got != 2:
    failures.append(f"count_unique_words regression: got {got}, expected 2")

if failures:
    print("FAIL:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("OK: all checks pass")
PY
