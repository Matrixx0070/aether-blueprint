#!/usr/bin/env bash
# Verifies the docstring was corrected to match the actual code.
# The starting docstring claims:
#   - Raises ValueError on invalid input         → WRONG (code returns None)
#   - Raises KeyError on missing user            → WRONG (code returns None via .get())
#   - Returns dict with 4 keys incl. created_at  → WRONG (code returns dict with 3 keys: id, name, email)
#
# Pass conditions:
#   - source code (the function body) is UNCHANGED
#   - docstring no longer claims ValueError / KeyError / created_at
#   - docstring is still non-empty (didn't just delete everything)

set -euo pipefail
cd "$(dirname "$0")"

# The code body must be unchanged. Easy way: check for the specific
# fake_db dict + the `if not isinstance(...)` guard.
grep -q 'if not isinstance(user_id, int) or user_id <= 0:' user_api.py || {
    echo "FAIL: function body was modified — guard clause missing or changed"; exit 1
}
grep -q '"alice@example.com"' user_api.py || {
    echo "FAIL: function body was modified — fake_db missing"; exit 1
}

# Docstring must NOT claim the false behaviors.
if grep -q "ValueError" user_api.py; then
    echo "FAIL: docstring still claims ValueError (code never raises it)"; exit 1
fi
if grep -q "KeyError" user_api.py; then
    echo "FAIL: docstring still claims KeyError (code never raises it)"; exit 1
fi
if grep -q "created_at" user_api.py; then
    echo "FAIL: docstring still mentions created_at (code never returns it)"; exit 1
fi

# Docstring must still exist (non-empty).
has_doc=$(python3 - <<'PY'
import ast
with open("user_api.py") as f:
    tree = ast.parse(f.read())
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef) and node.name == "fetch_user":
        d = ast.get_docstring(node)
        print("yes" if d and d.strip() else "no")
        break
PY
)
[ "$has_doc" = "yes" ] || { echo "FAIL: fetch_user has no docstring"; exit 1; }

echo "OK: docstring fixed, code unchanged"
