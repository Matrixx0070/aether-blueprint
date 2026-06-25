# aether vs Claude Code — coding-task comparison

**Honest framing first**: aether and Claude Code use the same Anthropic
models (Sonnet 4.6 / Opus 4.7 / Haiku 4.5) via the same Messages API.
Model quality is identical. Differences live in the harness — context
assembly, tool design, verifier gate, retry policy, parallel execution,
specialised commands.

This document is split into three parts:

1. **Verified live**: numbers aether produced on real coding tasks in
   this repo, captured with `aether coding-eval` against `Matrixx0070/
   aether-blueprint @ v0.12.0+`.
2. **Documented behavior**: feature-level differences pulled from
   Claude Code's public docs / shipping CLI surface as of 2026-06-25.
3. **UNVERIFIED**: items I cannot compare head-to-head because the
   benchmark harness cannot run Claude Code side-by-side in this env.

---

## 1. Verified live (aether on 5 real coding tasks, Sonnet 4.6)

Run command:

```
./target/release/aether coding-eval eval/coding/suite.yaml \
    --results eval/coding/RESULTS.md
```

Result (see [RESULTS.md](RESULTS.md) for the per-task table):

| Metric | v1 (5 tasks, Python) | v2 (10 tasks, multi-lang) |
|--------|----------------------|---------------------------|
| Tasks attempted | 5 | 10 |
| Tasks passed | **5/5 (100%)** | **10/10 (100%)\*** |
| Total agent wall-clock | 184s | 388s |
| Total input tokens | 162,624 | 313,392 |
| Total output tokens | 6,209 | 12,063 |
| Total cost | ~$0.58 USD | ~$1.12 USD |

\* Initial v2 run was 9/10; the 1 failure was a buggy verify.sh (asserted
the literal substring `onerror=` should be absent, but escaped-as-text
`onerror=` is harmless — only raw `<img` is dangerous). Test fixed to
check `<img src=x` is absent; the agent's original output passes the
fixed test. Documented in RESULTS.md.

Languages covered: Python (7 tasks), Rust (1), JavaScript (1), SQL+Python (1).

Each "pass" means a bash `verify.sh` script (NOT model judgment) checked
observable behavior of the resulting code:

| # | Task | What it required | Verification |
|---|------|------------------|--------------|
| 1 | `01_bug_fix` | Fix `count_words` (was counting chars, not words) | 5 input/output pairs |
| 2 | `02_feature_add` | Add `--reverse` flag + extend test suite | CLI runs both ways + pytest + grep "reverse" in test file |
| 3 | `03_write_test` | Write complete pytest file covering 5 functions + 2 edge cases | grep coverage by name + pytest pass + ZeroDivisionError + ValueError tests |
| 4 | `04_refactor` | Extract helpers from a 32-LOC function while preserving all 11 behavior tests | AST-counted body LOC ≤20 + ≥2 helpers + 11 tests pass |
| 5 | `05_doc_fix` | Correct a docstring that misdescribed the code (claimed `ValueError`/`KeyError`/`created_at`, code does none) | code unchanged + docstring no longer makes false claims |

The 5 verify scripts each tested a STARTING state (all 5 fail before the
agent runs) and an EXPECTED state (all 5 pass after the agent runs).
Verification is binary: exit 0 = pass, exit 1 = fail. No partial credit.

The benchmark itself is reproducible — `cargo build --release -p aether-cli`,
then `./target/release/aether coding-eval eval/coding/suite.yaml` against
a clean working tree.

---

## 2. Documented behavior — feature-by-feature

### Features aether ships, Claude Code does NOT (as of CC v2.x, 2026-06-25)

| Feature | aether command | Notes |
|---------|----------------|-------|
| **Coding-eval benchmark** | `aether coding-eval` | This document is the artifact; Claude Code has no equivalent reproducible coding-task suite. |
| **Security-eval suite** | `aether security-eval` | 23 OWASP-class fixtures across Python/Java/C++/Go/SQL with CWE+severity matching. v0.7.3 result: 23/23 at threshold 1.0 across 3 runs on Sonnet 4.6. |
| **Structured security review** | `aether review --kind security` | Single-turn critic producing `SEVERITY / CWE / LOCATION / SUMMARY / WHY / FIX` blocks per issue. Language-specific focus lists for Rust / Python / JS / Go / Java / C / C++ / SQL. |
| **STRIDE threat modeling** | `aether threat-model` | Trust boundaries, data classes, per-category threats with mitigations + residual risk. |
| **Scope-gated network tools** | `aether scope add-host/add-range` | Hosts / CIDR ranges / repos declared up front with `--authorized-by` + `--ticket-id` + expiry. CIDR /16+ refused. NetworkScan / WebProbe / DnsLookup auto-register iff a scope file is present. |
| **Tamper-evident audit log** | `aether audit verify` | `prev_hash`-chained JSONL at `~/.aether/audit.jsonl`. Every scope-gated tool call (allowed or refused) logs to the chain. |
| **CTF runner** | `aether ctf` | Bubblewrap-sandboxed challenge runner with file mounts + agent loop. |
| **Cross-provider sweep** | `aether security-eval --provider anthropic,bedrock,vertex,azure` | Run the same fixture suite through 4 cloud providers, comparison table. |
| **Provider health probe** | `aether doctor --probe --json` | Opt-in 1-token round-trip + latency + JSON output for CI. |
| **Compaction kill-switch** | `AETHER_NO_COMPACT=1` | aether's auto-compaction triggers at 80% of model window; this env disables. |
| **Retry kill-switch** | `AETHER_NO_RETRY=1` | aether's RetryingProvider wraps every provider; this env disables for test harnesses. |

### Features at parity (both ship them)

| Feature | aether | Claude Code |
|---------|--------|-------------|
| Anthropic Messages API | yes | yes |
| OAuth Bearer + API-key auth | yes | yes |
| Streaming REPL output | yes (v0.9, kill-switch `AETHER_NO_STREAM=1`) | yes |
| Read / Glob / Grep / Edit / Write / Bash / WebFetch tools | yes | yes |
| MCP stdio transport | yes | yes |
| MCP SSE transport | yes | partial |
| MCP WebSocket transport | yes (v0.11) | not in CLI surface |
| Parallel safe-tool execution | yes (v0.9, Read/Glob/Grep/MemoryRead concurrent) | yes |
| Context compaction at 80% window | yes (v0.9) | yes |
| `/usage` token + cost tracking | yes | yes |
| Plan mode (no-mutate) | yes | yes |
| Bedrock provider | yes (v0.8) | yes |
| Vertex provider | yes (v0.8) | yes |
| Azure Foundry provider | yes (v0.10) | UNVERIFIED |

### Features Claude Code ships, aether does NOT yet

| Feature | Status in aether |
|---------|------------------|
| VS Code extension | planned for v0.13+ |
| JetBrains plugin | planned for v0.13+ |
| Apple-notarized macOS binary | not signed (released unsigned in v0.12.0; users get "untrusted developer" warning) |
| Windows binary | not built — `aether-cli` is cross-compile-able but the v0.12 release workflow targets Linux + macOS only |
| Wider community plugin ecosystem | aether is new |
| Native /think extended-thinking integration | not exposed yet |

---

## 3. UNVERIFIED — items I cannot directly compare

This benchmark harness runs aether against its own fixtures and verifies
observable behavior. It cannot run Claude Code on the same fixtures
because:

- Claude Code is not installed in this environment.
- Even if it were, the verify.sh scripts only test the resulting file
  state — a Claude Code run would also leave behavior-equivalent edits,
  but without instrumenting both binaries to emit usage in the same
  format, per-task token/cost comparison would be apples-to-oranges.

**What I am NOT claiming**:

- That aether is faster than Claude Code on these tasks. UNVERIFIED.
- That aether produces "better" code than Claude Code. UNVERIFIED —
  both call the same model.
- That aether's parallel-tool-execution speedup translates to faster
  end-to-end task completion. UNVERIFIED — the 184s total above
  includes serial inter-turn latency that dominates over per-turn
  tool fan-out.
- That aether's compaction trigger is "more efficient" than CC's.
  UNVERIFIED — no head-to-head measurement.

**What I AM claiming** (with citations):

- aether achieves **5/5 PASS on these 5 real coding tasks** for
  **~$0.58 USD on Sonnet 4.6** — verified live in this session.
- aether ships **`security-eval`, `threat-model`, `scope`, `audit`,
  `ctf`, `coding-eval`, cross-provider sweep, doctor `--probe --json`**
  commands that Claude Code's shipping CLI does NOT have as of
  2026-06-25 — verified by inspection of CC's documented command
  surface.
- aether and Claude Code call the same Anthropic Messages API, so
  **model quality is identical** — there is no model-side win for
  either.

---

## Reproducing this

```sh
git clone https://github.com/Matrixx0070/aether-blueprint
cd aether-blueprint
cargo build --release -p aether-cli
# Requires a valid Anthropic credential — see INSTALL.md "After install".
./target/release/aether coding-eval eval/coding/suite.yaml \
    --results eval/coding/RESULTS.md
cat eval/coding/RESULTS.md
```

Re-running against a clean working tree should produce 5/5 PASS again;
token counts will vary slightly due to model nondeterminism in choice
of tool sequences. Cost has been observed in the $0.45 — $0.75 range
across runs.
