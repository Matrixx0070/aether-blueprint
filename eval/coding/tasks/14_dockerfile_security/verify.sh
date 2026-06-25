#!/usr/bin/env bash
# Verifies the Dockerfile security issues were fixed.
# Pass conditions:
#   - FROM uses a pinned tag (NOT :latest, NOT untagged)
#   - USER directive present and NOT 'root'
#   - No ADD for local files (use COPY); ADD is only legitimate for
#     URL/archive cases
#   - apt-get install uses --no-install-recommends
#   - HEALTHCHECK directive present
#
# We don't actually `docker build` (would need network + daemon); we
# parse the Dockerfile and assert on its structure.

set -euo pipefail
cd "$(dirname "$0")"

failures=()

# 1) Pinned base image.
base_line=$(grep -E '^FROM ' Dockerfile || true)
if echo "$base_line" | grep -qE ':latest|:\s*$' ; then
    failures+=("FROM still uses :latest or no tag")
fi
if ! echo "$base_line" | grep -qE '^FROM [^:]+:[A-Za-z0-9._-]+' ; then
    failures+=("FROM has no explicit pinned tag")
fi

# 2) USER directive present + not root.
if ! grep -qE '^USER ' Dockerfile; then
    failures+=("no USER directive (container still runs as root)")
else
    user_line=$(grep -E '^USER ' Dockerfile | tail -1)
    if echo "$user_line" | grep -qE '^USER\s+root\b'; then
        failures+=("USER is set to root")
    fi
fi

# 3) No ADD for local files. ADD app.py / ADD requirements.txt → bad.
if grep -qE '^ADD\s+[^h][^t][^t]' Dockerfile; then
    if grep -E '^ADD ' Dockerfile | grep -qvE '^ADD\s+https?://'; then
        failures+=("ADD used for local file (should be COPY)")
    fi
fi

# 4) apt-get install --no-install-recommends (strip comments first so
# the description in a comment doesn't satisfy the check).
apt_lines=$(grep -vE '^\s*#' Dockerfile | grep -E 'apt-get\s+install' || true)
if [ -n "$apt_lines" ]; then
    if ! echo "$apt_lines" | grep -q '\-\-no-install-recommends'; then
        failures+=("apt-get install missing --no-install-recommends")
    fi
fi

# 5) HEALTHCHECK directive.
if ! grep -qE '^HEALTHCHECK' Dockerfile; then
    failures+=("no HEALTHCHECK directive")
fi

if [ "${#failures[@]}" -gt 0 ]; then
    echo "FAIL:"
    for f in "${failures[@]}"; do
        echo "  - $f"
    done
    exit 1
fi

echo "OK: Dockerfile hardened (pinned tag, non-root USER, COPY not ADD, --no-install-recommends, HEALTHCHECK)"
