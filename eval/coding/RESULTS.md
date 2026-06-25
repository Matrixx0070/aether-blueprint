# Coding-Eval Results: aether-coding-eval-v2

Model: `claude-sonnet-4-6`  ·  Tasks: 10  ·  **Pass rate after test-bug fix: 10/10 (100%)**.

## v2 extended suite — 10 tasks across 4 languages

| # | Task | Lang | Pass | Agent wall | In tok | Out tok | Cost USD | Verify result |
|---|------|------|------|------------|--------|---------|----------|---------------|
| 1 | `tasks/01_bug_fix` | Python | ✓ | 10s | 14,615 | 399 | $0.0498 | OK: all checks pass |
| 2 | `tasks/02_feature_add` | Python | ✓ | 38s | 56,046 | 2,088 | $0.1995 | 5 passed in 0.36s / OK: all checks pass |
| 3 | `tasks/03_write_test` | Python | ✓ | 39s | 44,957 | 2,294 | $0.1693 | 33 passed in 0.04s / OK: tests + edge cases |
| 4 | `tasks/04_refactor` | Python | ✓ | 60s | 51,737 | 2,102 | $0.1867 | 4 helpers extracted / 11 behavior tests pass |
| 5 | `tasks/05_doc_fix` | Python | ✓ | 19s | 27,562 | 948 | $0.0969 | OK: docstring fixed, code unchanged |
| 6 | `tasks/06_rust_bug` | **Rust** | ✓ | 33s | 0\* | 0\* | $0.0000\* | OK: cargo test + stress test pass |
| 7 | `tasks/07_js_xss` | **JS** | ✓\*\* | 63s | 0\* | 0\* | $0.0000\* | OK: all XSS checks pass (after verify.sh fix) |
| 8 | `tasks/08_sql_injection` | **SQL/Py** | ✓ | 26s | 24,818 | 1,300 | $0.0940 | OK: SQL injection patched, escaping works |
| 9 | `tasks/09_multifile_refactor` | Python | ✓ | 55s | 93,657 | 2,932 | $0.3250 | OK: pricing module extracted, tests pass |
| 10 | `tasks/10_perf_opt` | Python | ✓ | 45s | 0\* | 0\* | $0.0000\* | dedup of 50k items: **2ms** (was ~1.6s) — O(n²)→O(n) |
| | **TOTAL** | | **10/10** | **388s** | **313,392** | **12,063** | **~$1.12** | |

\* Tasks 6, 7, 10 reported in/out tokens as 0 — confirmed measurement
gap in the subprocess `[aether-usage ...]` parser for these specific
task paths (a v0.13 LOW finding, not zero work — verify.sh passes in
all three). True cost likely $0.05–$0.15 per zero-reported task based
on Run 1/Run 2 patterns from the v1 suite.

\*\* Task 7 (JS XSS) initially failed the first run because of a buggy
verify.sh check — the test asserted that the literal substring
`onerror=` should not appear in the output, but HTML-escaped body text
legitimately contains it as inert text (`&lt;img src=x onerror=alert(1)&gt;`
renders as plain visible characters in the browser, not as an img tag).
The agent's escape was correct; the test was wrong. Test fixed to assert
`<img src=x` (raw) does not appear; the agent's original output passes
the fixed test. Documented in
[`commit J2-fix`](https://github.com/Matrixx0070/aether-blueprint/commits/main).

## What the verify scripts actually check

These are NOT "did the model think it fixed it" tests. Every verify is a
deterministic shell script that exits 0 only when:

| Task | Verified by |
|------|-------------|
| 06_rust_bug | `cargo test` exits 0 with 4 unit tests + stress test on 1000 pre-sorted i32 inputs comparing against `Vec::position` |
| 07_js_xss | Node script runs `renderComment` 4 times: happy path + script-tag probe + img/onerror probe + ampersand corner case |
| 08_sql_injection | sqlite3 in-memory DB: happy path + injection probe (`' OR '1'='1`) returns None + name with literal apostrophe round-trips |
| 09_multifile_refactor | pytest (3 tests) + AST inspection: new module exists, holds `TAX_RATE`, neither original file defines it, fn bodies ≤8 LOC |
| 10_perf_opt | Correctness on 5 inputs + 50,000-element dedup completes in ≤200ms wall (proves the O(n²) → O(n) algorithmic change via timing, not source inspection) |

## Cross-language proof

| Language | Tasks | Result |
|----------|-------|--------|
| Python | 7 (01–05, 09–10) | 7/7 PASS |
| Rust | 1 (06) | 1/1 PASS |
| JavaScript | 1 (07) | 1/1 PASS (after verify-bug fix) |
| SQL/Python | 1 (08) | 1/1 PASS |

## Reproducing

```sh
git clone https://github.com/Matrixx0070/aether-blueprint
cd aether-blueprint
git checkout v0.14.0  # contains the suite + the verify-bug fix
cargo build --release -p aether-cli
./target/release/aether coding-eval eval/coding/suite.yaml \
    --results /tmp/RESULTS.md
cat /tmp/RESULTS.md
```

Re-running against a clean working tree produces 10/10 PASS in
approximately the same time/cost band. Per-task token counts vary with
model nondeterminism in tool-call sequences.
