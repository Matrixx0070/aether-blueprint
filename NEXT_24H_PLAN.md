# Next 24-hour autonomous plan — Plan N

Drafted at end of Plan M (v0.16 → v0.17). Picks up the v0.18+ scope items
listed in `ROADMAP.md` and the LOW findings from M7 self-audit.

---

## Plan N — production posture + plugin marketplace

**MISSION**: Move aether from "single-user CLI / dev IDE" → "multi-user
production posture" with rate limiting, audit-log forwarding, per-org
policy enforcement, and asymmetric plugin signing (so a marketplace
becomes feasible).

**DONE MEANS** (6 criteria):

1. **Asymmetric plugin signing (ed25519)** alongside the M5 HMAC path.
   Manifests gain an `algorithm` field — `"hmac-sha256"` (the v0.17
   default) or `"ed25519"`. New `aether plugin keypair` subcommand
   produces a fresh ed25519 keypair PEM. `aether plugin sign` accepts
   `--key <PEM>` and `aether plugin verify` accepts `--public-key
   <PEM>`. 4 unit tests including a cross-keypair tamper-detect case.
2. **Rate limit on `aether serve`**. Configurable via env:
   `AETHER_SERVE_RATE_LIMIT_RPM` (per-IP requests per minute, default
   60). Token-bucket implementation, in-memory. 429 with
   `Retry-After: <seconds>` on exhaustion. Live-verified with a hammer
   loop.
3. **Audit-log forwarding** — `~/.aether/audit.jsonl` lines optionally
   tee'd to syslog (Unix `LOG_USER`) when `AETHER_AUDIT_SYSLOG=1` is
   set. New `aether audit tail --follow` companion to `aether audit
   verify` so operators can watch live.
4. **Per-org policy file enforcement** at `build_provider()`. New
   `~/.aether/policy.json` schema with `model_allowlist`,
   `tool_blocklist`, `max_tokens_per_turn`. Refusal at boot if config
   conflicts with policy; live error on tool call if policy changed
   mid-session. 4 unit tests.
5. **Concurrent-session cap on `aether serve`** via
   `AETHER_SERVE_MAX_SESSIONS` (default 32). 503 with
   `Retry-After: 5` past the cap.
6. **v0.18.0 binary release** shipped + verified, all 4 platforms.

**ASSUMPTIONS** (defaults picked):

- ed25519 via `ed25519-dalek` (the standard pure-Rust impl, already
  battle-tested in the rustls ecosystem).
- Token-bucket rate limit is per-IP (`X-Forwarded-For` honoured when
  present; raw socket addr otherwise). No distributed rate-limit
  state — fits the single-process posture; multi-replica is N+1.
- Policy file is JSON, NOT YAML, for parser uniformity with the rest
  of `~/.aether/`.
- Audit-syslog forwarding uses the `syslog` crate (Unix only).
  Windows users get a no-op + warning.

**NON-GOALS** (explicitly out):

- Plugin marketplace UI itself (just the signing primitive that
  makes one possible).
- Federation / multi-server orchestration.
- mTLS on `aether serve` (TLS termination belongs at a reverse proxy).
- Hardware-key signing (yubikey, etc.).
- Apple notarization.

**Phase breakdown** (~24h):

| Phase | Time | Slices |
|-------|------|--------|
| **N1**: asymmetric plugin signing | 6h | ed25519-dalek dep, algorithm-field on manifest, keypair subcommand, sign/verify accept `--key/--public-key`, 4 unit tests, cross-keypair tamper case |
| **N2**: rate limit | 3h | token-bucket implementation, X-Forwarded-For parse, axum middleware integration, 429 + Retry-After, hammer-loop smoke test |
| **N3**: audit-log syslog tee | 3h | syslog crate dep, optional tee on audit_append, `aether audit tail --follow` for live viewing, smoke test on a Linux box |
| **N4**: per-org policy file | 5h | ~/.aether/policy.json schema (model_allowlist + tool_blocklist + max_tokens_per_turn), parse at build_provider, refuse boot on conflict, live-error on cross-session policy change, 4 unit tests |
| **N5**: concurrent-session cap | 2h | atomic counter on /v1/messages and /ws/chat, 503 with Retry-After, smoke test |
| **N6**: ship v0.18.0 | 2h | bump + tag + autobuild + install verify |
| **N7**: self-audit + Plan O | 3h | LOW/MEDIUM scan, M-style honest report, Plan O draft |

**API budget**: ~$2-5 for live verification round-trips. Hammer
loops use Haiku.

**WEAKEST POINT**:

N4 — policy file enforcement. The line between "block tool X" and
"the agent picks a different valid path around tool X" is fuzzy.
Honest framing: refuse the call at the executor; let the agent loop
retry / replan if it can. Tests will pin both the refusal-on-call
side AND the "agent gets a `refused: policy` ToolError back into
context" side so behavior is observable.

**Failure modes to catch via self-audit**:

- Rate limiter that double-counts retries (RetryingProvider →
  same logical "request" → 5 rapid retries → 429 spuriously).
- Audit-syslog that buffers forever when syslog is unreachable —
  silently drop after a configurable backlog.
- Policy file that allows the model to bypass via a sub-agent
  (AgentTool inheriting the parent's permissions). Audit the
  AgentTool registration path.
- ed25519 verifier that returns ok on absent signature when
  `algorithm` was set — must fail-closed.

---

## Pre-flight checklist (run at next-session start)

1. `git -C /root/aether-blueprint status` — clean tree?
2. `git -C /root/aether-blueprint log -5 --oneline` — last commit
   is v0.17.0 docs?
3. `cargo test --workspace --release` — all green before adding new
   code (note: the `prune_window_perf_at_realistic_scale` test is
   `#[ignore]`'d and only runs under `-- --ignored`)
4. `gh release view v0.17.0` — confirm v0.17.0 binary is live
5. Read this file + the previous session's `wiki/hot.md` entry

---

## Candidate plans for 24h after Plan N

- **Plan O** (cost optimization): cache-aware retry, partial-stream
  resume, sub-agent fan-out for parallel codebase analysis.
- **Plan P** (research artifact): a real SWE-Bench-Lite submission
  with aether's numbers + harness description published as a
  technical report.
- **Plan Q** (mantle BYOC + JetBrains): finally close the
  cross-IDE matrix and the cross-provider matrix to "all the big
  ones."
