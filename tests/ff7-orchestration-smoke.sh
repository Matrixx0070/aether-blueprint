#!/usr/bin/env bash
# FF7 live smoke: rerun the 2026-06-27 failing audit prompt against
# /root/sudo-ai-v4 in REPL mode (NOT --print — the bug only fired when
# the REPL main loop was the orchestrator) and assert:
#   1. no "unexpected `tool_use_id`" upstream 400 in the output,
#   2. the REPL reaches the post-turn prompt again (no wedge) and
#      exits cleanly on /exit,
#   3. parallel sub-agent dispatch actually happened (Agent tool used),
#      otherwise the run didn't exercise the bug path and the smoke
#      refuses to claim victory.
set -uo pipefail

AETHER=${AETHER:-/root/aether-blueprint/target/release/aether}
TARGET=${TARGET:-/root/sudo-ai-v4}
OUT=$(mktemp /tmp/ff7-smoke-XXXX.log)

PROMPT='Audit this codebase for release-blocking issues. Dispatch parallel Agent sub-agents to cover: dependencies+build config, CI+ops, and runtime error handling. Then merge their findings into a top-5 list. Be thorough.'

cd "$TARGET"
printf '%s\n/exit\n' "$PROMPT" | timeout 900 "$AETHER" >"$OUT" 2>&1
rc=$?

echo "--- exit code: $rc (124 = wedge/timeout) ---"
tail -5 "$OUT"

fail=0
if grep -q 'unexpected `tool_use_id`' "$OUT"; then
  echo "FAIL: upstream 400 tool_use_id mismatch reproduced"
  fail=1
fi
if [ "$rc" -eq 124 ]; then
  echo "FAIL: REPL wedged (timeout)"
  fail=1
fi
agent_calls=$(grep -c '\[tool\] Agent' "$OUT" || true)
echo "Agent dispatches observed: $agent_calls"
if [ "$agent_calls" -lt 2 ]; then
  echo "FAIL: fewer than 2 parallel Agent dispatches — bug path not exercised"
  fail=1
fi
preflight=$(grep -c '\[preflight\] WARN' "$OUT" || true)
echo "FF7 pre-flight repairs fired: $preflight (0 is fine — repairs only fire on imbalance)"

if [ "$fail" -eq 0 ]; then
  echo "FF7 SMOKE OK: parallel sub-agent dispatch composed without 400, log at $OUT"
else
  echo "FF7 SMOKE FAILED, log at $OUT"
fi
exit $fail
