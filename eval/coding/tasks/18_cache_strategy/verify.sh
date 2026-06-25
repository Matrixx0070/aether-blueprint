#!/usr/bin/env bash
# Verifies get_value is cached, and the strategy is documented.
#
# Pass conditions:
#   (a) Caching demonstrably works: 100 calls to get_value(SAME_KEY)
#       complete in < 500ms total (the uncached version would take
#       100 × 50ms = 5000ms).
#   (b) Cache returns CONSISTENT values across repeated calls for the
#       same key.
#   (c) The strategy is named in the docstring or a top-level comment:
#       one of LRU / FIFO / TTL / unbounded / memo / lru_cache / cache /
#       cached / functools.

set -euo pipefail
cd "$(dirname "$0")"

python3 - <<'PY'
import sys, importlib.util, time, inspect, re

spec = importlib.util.spec_from_file_location("slow", "./slow.py")
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
except Exception as e:
    print(f"FAIL: import error: {e}"); sys.exit(1)

# (a) Performance: 100 calls with the same key in <500ms.
key = "test-key"
started = time.perf_counter()
results = [mod.get_value(key) for _ in range(100)]
elapsed_ms = (time.perf_counter() - started) * 1000
print(f"  100 same-key calls: {elapsed_ms:.0f}ms (uncached would be ~5000ms)")
if elapsed_ms > 500:
    print(f"FAIL: caching not effective ({elapsed_ms:.0f}ms > 500ms)")
    sys.exit(1)

# (b) Consistency: all results identical.
if len(set(results)) != 1:
    print(f"FAIL: cache returned inconsistent results: {set(results)}")
    sys.exit(1)

# (b2) Different keys give independent results.
v1 = mod.get_value("key-a")
v2 = mod.get_value("key-b")
# These could conceivably collide; we just check the function still works.
print(f"  v(key-a)={v1}, v(key-b)={v2}")

# (c) Strategy documented.
src = open("slow.py").read()
doc = inspect.getdoc(mod.get_value) or ""
combined = src + "\n" + doc
strategies = ["lru", "fifo", "ttl", "unbounded", "memo", "lru_cache", "cache", "cached", "functools"]
found = [s for s in strategies if re.search(rf"\b{s}\b", combined, re.IGNORECASE)]
if not found:
    print(f"FAIL: no caching strategy keyword in docstring or source")
    print(f"  expected one of: {strategies}")
    sys.exit(1)
print(f"  strategy keywords found: {found}")

print("OK: caching effective + strategy documented")
PY
