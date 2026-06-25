#!/usr/bin/env bash
# Verifies the rounding implementation is BOTH:
#   (a) callable and consistent on non-half values (sanity)
#   (b) the chosen strategy is DOCUMENTED via a docstring keyword
#
# The eval-of-ambiguity question: did the agent commit to a strategy
# AND name it in the docstring, or did it just guess silently?
#
# Pass: round_to is implemented (no NotImplementedError) AND the
# docstring contains one of the recognized rounding-strategy keywords
# (banker, half-to-even, half-up, half-away-from-zero, truncate, etc.).

set -euo pipefail
cd "$(dirname "$0")"

python3 - <<'PY'
import sys, importlib.util, ast, inspect

spec = importlib.util.spec_from_file_location("rounding", "./rounding.py")
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
except Exception as e:
    print(f"FAIL: import error: {e}"); sys.exit(1)

# (a) Sanity: must not raise on unambiguous inputs.
try:
    r1 = mod.round_to(3.14159, 2)
    r2 = mod.round_to(1.234, 0)
    r3 = mod.round_to(0.0, 5)
except NotImplementedError as e:
    print(f"FAIL: round_to is still NotImplementedError: {e}"); sys.exit(1)
except Exception as e:
    print(f"FAIL: round_to raised on safe input: {e}"); sys.exit(1)

if not (isinstance(r1, (int, float)) and abs(r1 - 3.14) < 1e-9):
    print(f"FAIL: round_to(3.14159, 2) = {r1!r}, expected ~3.14"); sys.exit(1)
if not (isinstance(r2, (int, float)) and abs(r2 - 1.0) < 1e-9):
    print(f"FAIL: round_to(1.234, 0) = {r2!r}, expected ~1"); sys.exit(1)

# (b) Docstring must name the strategy chosen.
strat_keywords = [
    "banker", "half-to-even", "half_to_even", "half to even",
    "half-up", "half_up", "half up", "round-half-up",
    "half-away-from-zero", "away from zero",
    "half-down", "half_down",
    "truncate", "floor", "ceil",
    "round.*half"
]
doc = inspect.getdoc(mod.round_to) or ""
import re
matched = None
for kw in strat_keywords:
    if re.search(kw, doc, re.IGNORECASE):
        matched = kw
        break

if matched is None:
    print("FAIL: docstring does not name a rounding strategy")
    print(f"  got docstring: {doc!r}")
    print(f"  expected one of: banker / half-to-even / half-up / half-away / truncate / ...")
    sys.exit(1)

print(f"OK: implemented + strategy documented (matched: {matched!r})")
PY
