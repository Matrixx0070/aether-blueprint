# Structural advantages — code citations

This document lists aether's harness-level features that Claude Code's
shipping CLI does not have, with **file:line citations** to the
implementing code in this repo. Every claim points at code you can grep
for and audit.

> **Honest framing**: "structural" means the harness, not the model.
> aether and Claude Code call the same Anthropic Messages API; the
> Sonnet-4.6 / Opus-4.7 / Haiku-4.5 model quality is identical. The
> differentiators are entirely in what the harness does AROUND the
> model call: routing, retry policy, audit chain, scope file, security
> review pipeline, etc.

---

## 1. Security review pipeline

### `aether review --kind security` — structured CWE blocks

**Source**: `crates/aether-cli/src/main.rs`, `review_security_file()`
function (search for `async fn review_security_file`).

What it does that's not in Claude Code's CLI surface:
- Single-turn critic (no tool calls inside the review — pure analysis).
- Structured output: per-issue `SEVERITY / CWE / LOCATION / SUMMARY /
  WHY / FIX` blocks parsed into typed `ReviewIssue` records.
- Per-language focus lists (Rust / Python / JS / Go / Java / C / C++ /
  SQL) injected into the prompt — `language_security_focus()`.
- `--json` outputs parsed blocks for downstream tools.

### `aether security-eval` — fixture suite

**Source**: `crates/aether-cli/src/main.rs`, `run_security_eval_inner()`.

What it does that's not in Claude Code:
- 23-fixture OWASP-class regression suite (`eval/security/suite.yaml`).
- Asserts on expected CWE detection + minimum severity.
- `--runs N --threshold P` stability harness (verified 23/23 at
  threshold 1.0 across 3 runs in v0.7.3).
- Cross-provider sweep: `--provider anthropic,bedrock,vertex,azure`
  produces a comparison table.
- CI-friendly exit 1 on any miss.

### Security auto-route to Sonnet

**Source**: `crates/aether-cli/src/main.rs`, `route_for_security()`.

What it does:
- Opus-class models truncate mid-stream on adversarial security prompts
  (Anthropic's cyber-safeguards classifier). Sonnet 4.6 ships clean.
- aether automatically reroutes `aether review --kind security` and
  `aether security-eval` from Opus to Sonnet when the user hasn't
  explicitly passed `--model`.
- One-line stderr notice tells the user what changed + how to override
  (`AETHER_SECURITY_NO_AUTOROUTE=1` to disable globally).
- 6 unit tests in the same file pin the routing logic.

---

## 2. Scope + audit chain

### Declarative scope file

**Source**: `crates/aether-sec/src/lib.rs`.

What it does:
- `aether scope init --authorized-by NAME --ticket-id TKT --days N`
  creates a scope file at `~/.aether/scope.json`.
- Hosts / CIDR ranges / repos declared up front.
- CIDR ranges larger than /16 refused at `scope add-range` time.
- Network tools (NetworkScan / WebProbe / DnsLookup) auto-register
  ONLY when a valid scope file is present. No scope file → tools are
  not even in the registry.

### Tamper-evident audit log

**Source**: `crates/aether-sec/src/lib.rs`, search for `audit_append`.

What it does:
- `~/.aether/audit.jsonl` — `prev_hash`-chained JSONL.
- Every scope-gated tool call (allowed OR refused) logs to the chain.
- `aether audit verify` walks the chain end-to-end and reports tamper.

Neither feature exists in Claude Code's documented CLI surface.

---

## 3. Threat modeling

### `aether threat-model SPEC.md`

**Source**: `crates/aether-cli/src/main.rs`, `run_threat_model()`.

What it does:
- Single-turn STRIDE walkthrough on an architecture spec.
- Output: trust boundaries, data classifications, per-category threats
  (Spoofing / Tampering / Repudiation / Information Disclosure / DoS /
  Elevation of privilege), each with `Threat / Mitigations / Residual
  risk` triple.

Claude Code can certainly *be asked* to do threat modeling in a chat,
but aether ships the structured prompt template as a first-class
subcommand.

---

## 4. Coding-eval — this benchmark

**Source**: `crates/aether-cli/src/main.rs`, `run_coding_eval()` and
the surrounding `CodingTask` / `CodingTaskResult` / `CodingReport`
types.

What it does:
- Reproducible coding-task benchmark with mechanical (exit-code)
  verification. NO model judgment in the verify loop.
- 15-task v3 suite covering 9 languages.
- `git checkout HEAD -- <task_dir>` between tasks so re-runs are clean.
- Parses `[aether-usage in=X out=Y cache_w=Z cache_r=W cost_usd=N]`
  stderr line per task for per-task cost tracking.
- `--results PATH` writes a Markdown table for CI consumption.

Claude Code has no equivalent reproducible coding-task suite — every
benchmark you can find published is hand-graded.

---

## 5. Cross-provider sweep + retry watchdog

### Sweep

**Source**: `crates/aether-cli/src/main.rs`, `run_security_eval_sweep()`.

What it does:
- Same fixture suite across `anthropic`, `bedrock`, `vertex`, `azure`
  in one command.
- Comparison table (passed / failed / total per provider).
- Skipped providers (auth missing) show SKIP rows so partial sweeps
  aren't silently green.

### Retry

**Source**: `crates/aether-llm/src/retry.rs`, `RetryingProvider`
decorator.

What it does:
- Wraps every constructed provider at `build_provider()`.
- Retries 5xx, 429, transport errors with exponential backoff
  (1s → 2s → 4s, max 3 attempts default).
- 4xx (non-429) + schema errors return immediately — no useless retry.
- Streaming intentionally NOT retried (partial deltas already emitted;
  retry would duplicate text).
- Kill-switch `AETHER_NO_RETRY=1`.

Claude Code's retry policy isn't documented in the public CLI help.

---

## 6. Compaction + parallel tools

### Automatic context compaction at 80%

**Source**: `crates/aether-core/src/compaction.rs`, `maybe_compact()`.

What it does:
- Trigger: cumulative `usage_total.input_tokens + output_tokens` ≥ 80%
  of model context window (200K for all current Claude 4.x).
- Action: keep final 1/3 of history verbatim, summarise the head into a
  single synthetic `User → Assistant` exchange.
- Hysteresis: per-compaction `usage_total` reset — next compaction
  can't fire until threshold accumulates again.
- Kill-switch `AETHER_NO_COMPACT=1`.
- 8 unit tests in `aether-core::compaction::tests`.

### Parallel safe-tool execution

**Source**: `crates/aether-core/src/executor.rs`, `Executor::execute()`.

What it does:
- Coalesces contiguous runs of read-only tools (`Read`, `Glob`, `Grep`,
  `MemoryRead`) into a single `futures::future::join_all` batch.
- Mutating tools (`Write`, `Edit`, `Bash`, `WebFetch`) stay sequential.
- Kill-switch `AETHER_NO_PARALLEL_TOOLS=1`.
- Interleave-probe unit test (NOT timing-based, robust under cargo
  test's parallel runner) proves true concurrency.

Both features documented as being in Claude Code's harness as of
v2.x, but aether's are user-facing and kill-switchable.

---

## 7. Doctor + observability

### `aether doctor --probe --json`

**Source**: `crates/aether-cli/src/main.rs`, `run_doctor()`.

What it does:
- Reports active provider + credential source + token expiry + settings
  + hooks + MCP + disk usage.
- `--probe` does a 1-token round-trip against the active provider,
  reports latency + token counts (CI-friendly exit 1 on probe failure).
- `--json` emits structured JSON document for log shippers.
- Composes: `aether doctor --probe --json` produces a structured
  health-check artifact.

---

## 8. MCP three-transport client

**Source**: `crates/aether-mcp/src/lib.rs`.

What it does:
- `StdioClient` — subprocess + stdin/stdout JSON-RPC framing.
- `SseClient` — `event-stream` POST endpoint + reader task.
- `WsClient` — `tokio-tungstenite` connect + writer/reader split,
  same JSON-RPC demux pattern as SSE.
- `spawn_client()` factory dispatches `ServerConfig::{Stdio|Sse|Ws}`.

Claude Code v2.x ships stdio MCP. SSE + Ws are documented but not in
the CLI as of writing.

---

## 9. Per-feature kill-switch matrix

aether exposes an environment variable for every automated behavior
that could surprise a user. Each is documented in the source via the
`std::env::var(...).ok().as_deref() == Some("1")` pattern.

| Env | Disables | Default |
|-----|----------|---------|
| `AETHER_NO_STREAM=1` | REPL/print streaming | streaming on |
| `AETHER_NO_COMPACT=1` | Context compaction at 80% | compaction on |
| `AETHER_NO_PARALLEL_TOOLS=1` | Concurrent safe-tool dispatch | parallel on |
| `AETHER_NO_RETRY=1` | Provider retry watchdog | retry on |
| `AETHER_SECURITY_NO_AUTOROUTE=1` | Opus → Sonnet routing for security ops | autoroute on |
| `AETHER_DOCTOR_NO_PROBE` | Doctor probe inactive by default; `--probe` opts in | off by default |

Search `crates/aether-cli/src/main.rs` for `AETHER_NO_` to audit.

---

## What this document does NOT claim

- That Claude Code lacks every feature listed here — only that they
  are not in the documented CLI surface as of 2026-06-25.
- That aether is universally better. **The model quality is identical**
  (same Anthropic API). aether's edge is the surrounding harness.
- That aether is production-ready for every use case. v0.15 is still
  a v0.x release; the surface stabilises through v1.

What it DOES claim, with code citations: aether ships an empirically-
verifiable set of commands and behaviors that Claude Code's CLI does
not — and every one of them is auditable in this repository's source.
