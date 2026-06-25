#!/usr/bin/env bash
# Apply a hand-crafted known-good fix to each task in the suite,
# run verify.sh against it, and report pass/fail.
#
# Purpose: catch verify-script bugs BEFORE shipping. If verify.sh
# rejects a hand-written correct fix, the test is too strict (or
# wrong) — fix the test, not the agent.
#
# Lesson from v0.14: task 07 (JS XSS) shipped with a verify check that
# rejected the agent's correct HTML-escape because the escaped-as-text
# substring `onerror=` happened to appear. A pre-flight known-good run
# would have caught this.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KNOWN_GOOD_DIR="$(dirname "$0")"

run_one() {
    local task="$1"
    local task_dir="$ROOT/tasks/$task"
    local kg_file="$KNOWN_GOOD_DIR/$task.patch"
    if [ ! -f "$kg_file" ]; then
        echo "SKIP $task (no known_good/$task.patch)"
        return 0
    fi

    # Reset the task dir to git HEAD.
    ( cd "$ROOT/.." && git checkout HEAD -- "eval/coding/tasks/$task" )
    ( cd "$ROOT/.." && git clean -fd "eval/coding/tasks/$task" ) >/dev/null 2>&1

    # Apply the known-good patch into the task dir.
    ( cd "$task_dir" && patch -p1 < "$kg_file" )

    # Run verify.
    if "$task_dir/verify.sh" >/dev/null 2>&1; then
        echo "PASS $task — verify accepts known-good fix"
    else
        echo "FAIL $task — verify REJECTS known-good fix (test bug?)"
        return 1
    fi
}

# Reset everything first.
( cd "$ROOT/.." && git checkout HEAD -- eval/coding/tasks/ ) || true
( cd "$ROOT/.." && git clean -fd eval/coding/tasks/ >/dev/null 2>&1 ) || true

# Walk every task dir we have a patch for.
failed=0
for kg in "$KNOWN_GOOD_DIR"/*.patch; do
    [ -e "$kg" ] || continue
    task=$(basename "$kg" .patch)
    if ! run_one "$task"; then
        failed=$((failed + 1))
    fi
done

# Restore everything to clean state when we're done.
( cd "$ROOT/.." && git checkout HEAD -- eval/coding/tasks/ ) || true
( cd "$ROOT/.." && git clean -fd eval/coding/tasks/ >/dev/null 2>&1 ) || true

if [ $failed -gt 0 ]; then
    echo "RESULT: $failed task(s) rejected known-good fix (test bugs)"
    exit 1
fi
echo "RESULT: every verify.sh accepts its known-good fix"
