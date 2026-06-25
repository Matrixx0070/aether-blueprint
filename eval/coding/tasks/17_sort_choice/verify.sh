#!/usr/bin/env bash
# Verifies sort_records was implemented AND the choices are documented.
#
# Pass conditions (rich rubric — accepts ANY consistent choice):
#   (a) sort_records returns a list with the same items, in SOME sorted
#       order on AT LEAST ONE of (name, score), either ascending or
#       descending. The choice is up to the implementer.
#   (b) The output is a permutation of the input (no items added/dropped).
#   (c) The docstring or a top-level comment names at least TWO of the
#       three decisions:
#         - sort KEY  (name | score | both)
#         - DIRECTION (ascending | descending)
#         - STABILITY (stable | unstable)
#       (Two-of-three is enough; perfect rubrics over-specify.)

set -euo pipefail
cd "$(dirname "$0")"

python3 - <<'PY'
import sys, importlib.util, inspect, re

spec = importlib.util.spec_from_file_location("sorter", "./sorter.py")
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
except Exception as e:
    print(f"FAIL: import error: {e}"); sys.exit(1)

inp = [("zane", 80), ("alice", 95), ("bob", 80), ("alice", 70)]
try:
    out = mod.sort_records(list(inp))
except NotImplementedError as e:
    print(f"FAIL: sort_records still NotImplementedError: {e}"); sys.exit(1)
except Exception as e:
    print(f"FAIL: sort_records raised: {e}"); sys.exit(1)

if not isinstance(out, list):
    print(f"FAIL: return type {type(out).__name__}, expected list"); sys.exit(1)
if sorted(out) != sorted(inp):
    print(f"FAIL: output is not a permutation of input"); sys.exit(1)

# Detect SOME consistent ordering on at least one axis.
names = [n for n, _ in out]
scores = [s for _, s in out]
sorted_axes = []
if names == sorted(names):
    sorted_axes.append("name asc")
if names == sorted(names, reverse=True):
    sorted_axes.append("name desc")
if scores == sorted(scores):
    sorted_axes.append("score asc")
if scores == sorted(scores, reverse=True):
    sorted_axes.append("score desc")

if not sorted_axes:
    print(f"FAIL: output has no consistent sort order: {out}"); sys.exit(1)

print(f"  detected sort: {sorted_axes}")

# Docstring or top-level docstring/comment must name 2 of 3 decisions.
src = open("sorter.py").read()
doc = inspect.getdoc(mod.sort_records) or ""
combined = src + "\n" + doc

# Match patterns for each decision axis.
key_kw = any(re.search(p, combined, re.IGNORECASE)
             for p in [r"\bname\b", r"\bscore\b", r"\bkey\b"])
dir_kw = any(re.search(p, combined, re.IGNORECASE)
             for p in [r"\bascend", r"\bdescend", r"\bdesc\b", r"\basc\b", r"reverse"])
stab_kw = any(re.search(p, combined, re.IGNORECASE)
              for p in [r"\bstable\b", r"\bunstable\b", r"\bstability\b"])

named = sum([key_kw, dir_kw, stab_kw])
print(f"  decisions named: key={key_kw} direction={dir_kw} stability={stab_kw}  ({named}/3)")
if named < 2:
    print(f"FAIL: at least 2 of 3 sort decisions must be documented; only {named} named")
    sys.exit(1)

print("OK: sort implemented + decisions documented")
PY
