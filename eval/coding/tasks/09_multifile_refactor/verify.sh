#!/usr/bin/env bash
# Verifies the duplicated subtotal/tax math + TAX_RATE constant was
# extracted into a single shared module that both order.py and
# invoice.py import.
#
# Pass conditions:
#   - Tests still pass (no behavior change).
#   - A NEW file exists (totals.py or pricing.py — anything that holds
#     the shared logic). Detected by: there must be at least one .py
#     file in the dir OTHER than order.py / invoice.py / test_totals.py
#     that defines TAX_RATE.
#   - Neither order.py NOR invoice.py defines TAX_RATE anymore (it was
#     hoisted to the shared module).
#   - order_total + invoice_total bodies are now small — each ≤8 LOC,
#     proving the math got extracted (not just constant hoisted).

set -euo pipefail
cd "$(dirname "$0")"

if ! command -v pytest >/dev/null 2>&1; then
    python3 -m pip install --quiet pytest >/dev/null 2>&1 || true
fi
python3 -m pytest test_totals.py -q 2>&1 | tail -3

# Find new .py files (not the original 3 + their __pycache__).
new_files=$(ls *.py 2>/dev/null | grep -v -E '^(order|invoice|test_totals)\.py$' || true)
if [ -z "$new_files" ]; then
    echo "FAIL: no new shared module created"; exit 1
fi

# At least one new file must define TAX_RATE.
found_tax_rate=false
for f in $new_files; do
    if grep -q "TAX_RATE" "$f"; then
        found_tax_rate=true
        break
    fi
done
if ! $found_tax_rate; then
    echo "FAIL: no new module defines TAX_RATE; new files: $new_files"; exit 1
fi

# Neither order.py NOR invoice.py defines TAX_RATE anymore.
if grep -qE '^TAX_RATE\s*=' order.py; then
    echo "FAIL: order.py still defines TAX_RATE (should have been hoisted)"; exit 1
fi
if grep -qE '^TAX_RATE\s*=' invoice.py; then
    echo "FAIL: invoice.py still defines TAX_RATE (should have been hoisted)"; exit 1
fi

# Body-LOC check: order_total + invoice_total each have ≤8 LOC.
loc_check=$(python3 - <<'PY'
import ast
for path, name in [("order.py", "order_total"), ("invoice.py", "invoice_total")]:
    tree = ast.parse(open(path).read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            body = node.body
            # Strip docstring
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                body = body[1:]
            lines = set()
            for stmt in body:
                for n in ast.walk(stmt):
                    if hasattr(n, "lineno"):
                        lines.add(n.lineno)
            print(f"{name}={len(lines)}")
PY
)
echo "$loc_check"
echo "$loc_check" | while IFS='=' read -r fname loc; do
    if [ "$loc" -gt 8 ]; then
        echo "FAIL: $fname has $loc LOC (target ≤8)"
        exit 1
    fi
done

echo "OK: multi-file refactor done, no duplication, tests pass"
