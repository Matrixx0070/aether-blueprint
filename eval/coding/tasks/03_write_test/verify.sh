#!/usr/bin/env bash
# Verifies a comprehensive pytest file was written for math_helpers.py.
# Pass conditions:
#   - test_math_helpers.py exists
#   - pytest passes against it
#   - tests cover ALL five public functions (add, subtract, divide,
#     factorial, is_even) — checked by grep on the test text
#   - tests cover edge cases: division by zero (ZeroDivisionError) AND
#     negative factorial (ValueError)

set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f test_math_helpers.py ]; then
    echo "FAIL: test_math_helpers.py not found"; exit 1
fi

# Each function name must appear in the test file.
for fn in add subtract divide factorial is_even; do
    if ! grep -q "$fn" test_math_helpers.py; then
        echo "FAIL: test file does not exercise '$fn'"; exit 1
    fi
done

# Edge cases must be tested (not just happy path).
grep -q "ZeroDivisionError\|raises" test_math_helpers.py || {
    echo "FAIL: no ZeroDivisionError / pytest.raises test"; exit 1
}
grep -q "ValueError\|negative" test_math_helpers.py || {
    echo "FAIL: no negative-factorial edge case"; exit 1
}

# Tests must actually pass.
if ! command -v pytest >/dev/null 2>&1; then
    python3 -m pip install --quiet pytest >/dev/null 2>&1 || true
fi
python3 -m pytest test_math_helpers.py -q 2>&1 | tail -5

echo "OK: tests written + passing + cover edge cases"
