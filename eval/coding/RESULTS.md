# Coding-Eval Results: aether-coding-eval-v1

Model: `claude-sonnet-4-6`  ·  Tasks: 5  ·  **Stability across 2 independent runs: 10/10 task completions, 0 failures**.

## Run 1 (183s wall, ~$0.5810)

| # | Task | Pass | Agent wall | In tok | Out tok | Cost USD | Note |
|---|------|------|------------|--------|---------|----------|------|
| 1 | `tasks/01_bug_fix` | ✓ | 29s | 37,181 | 981 | $0.1263 | OK: all checks pass |
| 2 | `tasks/02_feature_add` | ✓ | 55s | 70,539 | 2,243 | $0.2453 | 5 passed in 0.11s / OK: all checks pass |
| 3 | `tasks/03_write_test` | ✓ | 30s | 27,373 | 2,008 | $0.1122 | 32 passed in 0.02s / OK: tests + edge cases |
| 4 | `tasks/04_refactor` | ✓ | 47s | 0\* | 0\* | $0.0000\* | 3 helpers extracted / OK: behavior preserved |
| 5 | `tasks/05_doc_fix` | ✓ | 20s | 27,531 | 977 | $0.0972 | OK: docstring fixed, code unchanged |
| | **TOTAL** | **5/5** | **183s** | **162,624** | **6,209** | **$0.5810** | |

## Run 2 (158s wall, ~$0.4851)

| # | Task | Pass | Agent wall | In tok | Out tok | Cost USD | Note |
|---|------|------|------------|--------|---------|----------|------|
| 1 | `tasks/01_bug_fix` | ✓ | 12s | 14,600 | 396 | $0.0497 | OK: all checks pass |
| 2 | `tasks/02_feature_add` | ✓ | 49s | 64,846 | 2,348 | $0.2298 | 6 passed in 0.14s / OK: all checks pass |
| 3 | `tasks/03_write_test` | ✓ | 27s | 27,023 | 1,797 | $0.1080 | 31 passed in 0.01s / OK: tests + edge cases |
| 4 | `tasks/04_refactor` | ✓ | 46s | 0\* | 0\* | $0.0000\* | 4 helpers extracted / OK: behavior preserved |
| 5 | `tasks/05_doc_fix` | ✓ | 22s | 27,563 | 995 | $0.0976 | OK: docstring fixed, code unchanged |
| | **TOTAL** | **5/5** | **158s** | **134,032** | **5,536** | **$0.4851** | |

## Stability summary

| Metric | Run 1 | Run 2 | Notes |
|--------|-------|-------|-------|
| Pass rate | 5/5 | 5/5 | **Cumulative 10/10 task completions** |
| Total wall | 183s | 158s | Run 2 ~14% faster (cache warmup) |
| Total cost | $0.5810 | $0.4851 | Run 2 ~17% cheaper |
| Task 04 helpers | 3 | 4 | Different valid refactors (both pass behavior tests) |
| Task 03 tests written | 32 | 31 | Both pass + cover ZeroDivisionError + ValueError |

\* Task 04 reported usage as 0/0 in BOTH runs — confirmed measurement
gap in our subprocess `[aether-usage ...]` parser for that specific
task shape, NOT zero actual work (verify.sh passes both runs; helpers
were genuinely extracted). Documented as a v0.13 LOW finding in
[`COMPARISON.md`](COMPARISON.md). Real cost for task 04 estimated at
$0.05–$0.10 per run based on Run 1 vs Run 2 totals.

## Reproducing

```sh
git clone https://github.com/Matrixx0070/aether-blueprint
cd aether-blueprint
git checkout v0.13.0  # or download the prebuilt binary from the GitHub release
cargo build --release -p aether-cli
./target/release/aether coding-eval eval/coding/suite.yaml \
    --results /tmp/RESULTS.md
cat /tmp/RESULTS.md
```

Requires:
- Valid Anthropic credentials (`ANTHROPIC_API_KEY`, OAuth token, or
  Claude Code credentials file — `aether doctor` confirms availability).
- python3 + pytest (auto-installed by `verify.sh` if missing on a system
  with `pip` reachable; offline-hermetic environments need pytest
  preinstalled).
- git working tree must be clean for the per-task `git checkout HEAD --`
  reset to behave as expected.

Re-running against a clean working tree produces 5/5 PASS in
approximately the same time/cost band. Per-task token counts vary with
model nondeterminism in tool-call sequences.
