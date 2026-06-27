#!/usr/bin/env bash
#
# EE4 pre-tag gate: refuses to publish a release when STATUS.md still
# contains the literal "(this commit)" placeholder.
#
# The placeholder pattern hit six successive ship slices in a row
# (Y7 / Z7 / AA7 / BB7 / CC7 / DD7) — each one needed a follow-up
# "fix SHA placeholder" commit because the ship-row's own SHA didn't
# exist at commit time. This script ends that pattern by running in
# CI before the release workflow's build job, exiting non-zero when
# STATUS.md still references the chicken-and-egg placeholder.
#
# Run locally:    bash tests/check-status-no-placeholders.sh
# Escape hatch:   AETHER_SKIP_STATUS_PLACEHOLDER_CHECK=1 — for the rare
#                 legitimate case where a STATUS row genuinely needs to
#                 quote that string.
#
# Exit codes:
#   0  STATUS.md is clean (or check explicitly skipped)
#   1  STATUS.md still has "(this commit)" — refusing release
#   2  STATUS.md not found at the expected path

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
STATUS_FILE="$REPO_ROOT/STATUS.md"
PLACEHOLDER='(this commit)'

if [ "${AETHER_SKIP_STATUS_PLACEHOLDER_CHECK:-0}" = "1" ]; then
    echo "[ee4] AETHER_SKIP_STATUS_PLACEHOLDER_CHECK=1 — skipping check"
    exit 0
fi

if [ ! -f "$STATUS_FILE" ]; then
    echo "[ee4] STATUS.md not found at $STATUS_FILE" >&2
    exit 2
fi

# grep -F so the parentheses are literal, not a regex group.
# -n prints line numbers so the operator can jump straight to the offending row.
if grep -Fn "$PLACEHOLDER" "$STATUS_FILE"; then
    echo "" >&2
    echo "[ee4] STATUS.md contains the '(this commit)' placeholder — refusing release." >&2
    echo "[ee4] Backfill the commit SHA in the offending row(s) above before tagging." >&2
    echo "[ee4] If a row legitimately quotes this string, set AETHER_SKIP_STATUS_PLACEHOLDER_CHECK=1." >&2
    exit 1
fi

echo "[ee4] STATUS.md clean — no '(this commit)' placeholders found"
exit 0
