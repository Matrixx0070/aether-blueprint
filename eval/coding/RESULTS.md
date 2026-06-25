# Coding-Eval Results: aether-coding-eval-v1

Model: `claude-sonnet-4-6`  ·  Tasks: 5  ·  Passed: 5  ·  Failed: 0

| # | Task | Pass | Agent wall | In tok | Out tok | Cost USD | Note |
|---|------|------|------------|--------|---------|----------|------|
| 1 | `tasks/01_bug_fix` | ✓ | 29s | 37181 | 981 | $0.1263 | OK: all checks pass /  |
| 2 | `tasks/02_feature_add` | ✓ | 55s | 70539 | 2243 | $0.2453 | 5 passed in 0.11s / OK: all checks pass /  |
| 3 | `tasks/03_write_test` | ✓ | 30s | 27373 | 2008 | $0.1122 | 32 passed in 0.02s / OK: tests written + passing + cover edge cases /  |
| 4 | `tasks/04_refactor` | ✓ | 47s | 0 | 0 | $0.0000 | extracted helper functions: 3 / OK: refactor done, behavior preserved /  |
| 5 | `tasks/05_doc_fix` | ✓ | 20s | 27531 | 977 | $0.0972 | OK: docstring fixed, code unchanged /  |

**Totals**: 183s agent wall · in=162624 · out=6209 · ~$0.5810
