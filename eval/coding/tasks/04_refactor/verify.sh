#!/usr/bin/env bash
# Verifies process_request was refactored:
#   - process_request function-body LOC dropped from the starting ~40 to ≤20
#     (excluding the docstring line and blank lines)
#   - All 11 behavior tests still pass (no regressions)
#   - At least 2 helper functions emerged (extracted helpers)

set -euo pipefail
cd "$(dirname "$0")"

# Tests must pass — this is the regression check.
if ! command -v pytest >/dev/null 2>&1; then
    python3 -m pip install --quiet pytest >/dev/null 2>&1 || true
fi
python3 -m pytest test_handler.py -q 2>&1 | tail -3

# Count non-blank, non-docstring lines INSIDE process_request.
body_loc=$(python3 - <<'PY'
import ast
with open("handler.py") as f:
    tree = ast.parse(f.read())
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef) and node.name == "process_request":
        # Strip docstring (first statement if it's a string expr).
        body = node.body
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            body = body[1:]
        # Crude line count via AST line numbers, ignoring duplicates.
        lines = set()
        for stmt in body:
            for n in ast.walk(stmt):
                if hasattr(n, "lineno"):
                    lines.add(n.lineno)
        print(len(lines))
        break
PY
)
echo "process_request body LOC: $body_loc"
if [ "$body_loc" -gt 20 ]; then
    echo "FAIL: process_request still has $body_loc lines (refactor target: ≤20)"
    exit 1
fi

# Helper functions: count function defs OTHER than process_request.
helpers=$(python3 - <<'PY'
import ast
with open("handler.py") as f:
    tree = ast.parse(f.read())
n = 0
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name != "process_request":
        n += 1
print(n)
PY
)
echo "extracted helper functions: $helpers"
if [ "$helpers" -lt 2 ]; then
    echo "FAIL: expected at least 2 helper functions; found $helpers"
    exit 1
fi

echo "OK: refactor done, behavior preserved"
