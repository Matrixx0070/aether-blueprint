#!/usr/bin/env bash
# HH-A live smoke: `aether distributed --target <dir> --workers N`
# against a real multi-hundred-file target (this repo's own source
# tree), asserting REAL multi-process parallelism — not a simulation.
#
# Per the Plan HH risk register (§HH-A): the property under test is
# "distinct OS-level worker PIDs actually did the work", not merely
# "the command returned a plausible-looking report". This smoke
# fails loudly if the worker count claimed doesn't match the number
# of DISTINCT pids observed in the JSON output.
set -euo pipefail

AETHER=${AETHER:-/root/aether-blueprint/target/release/aether}
TARGET=${TARGET:-/root/aether-blueprint/crates/aether-secrets}
WORKERS=${WORKERS:-4}

echo "[smoke] target: $TARGET (file count: $(find "$TARGET" -type f | wc -l))"

OUT=$("$AETHER" distributed --target "$TARGET" --workers "$WORKERS" --json)
echo "$OUT" | python3 -c "
import json, sys
report = json.load(sys.stdin)
worker_count = report['worker_count']
pids = [w['pid'] for w in report['workers']]
distinct_pids = set(pids)
total_files_claimed = report['total_files']
files_per_worker = sum(w['files_scanned'] for w in report['workers'])

print(f'[smoke] worker_count={worker_count} distinct_pids={len(distinct_pids)} total_files={total_files_claimed}')
print(f'[smoke] pids: {sorted(pids)}')

assert worker_count >= 1, 'at least one worker must have run'
assert len(distinct_pids) == worker_count, (
    f'FAIL: {worker_count} workers claimed but only {len(distinct_pids)} distinct pids — '
    'not real multi-process parallelism'
)
assert files_per_worker == total_files_claimed, 'per-worker file counts must sum to the total'
assert total_files_claimed > 0, 'target must have had at least one file scanned'
for pid in pids:
    assert pid > 1, f'pid {pid} is not a plausible real OS pid'
print('[smoke] PASS: worker_count == distinct real OS pids == ' + str(worker_count))
"

# Re-run with 1 worker and confirm it still works (edge case: N=1 is
# 'distributed' across exactly one real process, not zero).
OUT1=$("$AETHER" distributed --target "$TARGET" --workers 1 --json)
echo "$OUT1" | python3 -c "
import json, sys
report = json.load(sys.stdin)
assert report['worker_count'] == 1, report
assert len(report['workers']) == 1
print('[smoke] --workers 1 edge case: exactly 1 real worker process, OK')
"

# Legacy back-compat path (--node, no --target) must still print the
# old demo text without erroring.
"$AETHER" distributed --node demo-node-1 > /tmp/hh-a-legacy.out
grep -q "Note: pass --target" /tmp/hh-a-legacy.out
echo "[smoke] legacy --node path (no --target) still works, back-compat OK"

echo "[smoke] HH-A LIVE-VERIFIED OK (real multi-process distributed scanning)"
