#!/usr/bin/env bash
# Verifies dedup was optimized to O(n) (or close).
# Pass conditions:
#   - Correctness: dedup preserves order, removes dups, handles empty list.
#   - Performance: 50,000-element input dedups in under 200ms wall.
#     The starting O(n²) implementation takes ~2-3 seconds at this size.

set -euo pipefail
cd "$(dirname "$0")"

python3 - <<'PY'
import time
import sys
sys.path.insert(0, ".")
from dedup import dedup

# Correctness
checks = [
    ([], []),
    (["a"], ["a"]),
    (["a", "a", "a"], ["a"]),
    (["a", "b", "a", "c", "b"], ["a", "b", "c"]),
    (["one", "two", "three"], ["one", "two", "three"]),
]
failures = []
for inp, expected in checks:
    got = dedup(list(inp))  # copy so the impl can't mutate the test data
    if got != expected:
        failures.append(f"dedup({inp!r}) = {got!r}, expected {expected!r}")
if failures:
    print("FAIL correctness:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)

# Performance
big = []
for i in range(50_000):
    big.append(f"item{i % 5_000}")  # ~10x duplication
started = time.perf_counter()
result = dedup(big)
elapsed = time.perf_counter() - started
print(f"dedup of 50k items: {elapsed*1000:.0f}ms; out len={len(result)}")

if len(result) != 5_000:
    print(f"FAIL: expected 5000 unique items, got {len(result)}")
    sys.exit(1)

# 200ms ceiling.
if elapsed * 1000 > 200:
    print(f"FAIL: {elapsed*1000:.0f}ms > 200ms threshold (still O(n²)?)")
    sys.exit(1)

print(f"OK: correctness + performance ({elapsed*1000:.0f}ms ≤ 200ms)")
PY
