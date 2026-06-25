# Roadmap

## v0.7 — Security Edge — shipped 2026-06-25 (this release)

A self-contained surface for authorized security work, end-to-end:

- **Scope file** (`~/.aether/scope.json`): hosts / CIDR ranges / repos
  declared up front, with `--authorized-by` + `--ticket-id` + expiry.
  CIDR ranges larger than /16 refused at `scope add-range` time.
- **Tamper-evident audit log** (`~/.aether/audit.jsonl`): `prev_hash`-
  chained JSONL, `aether audit verify` walks the chain end-to-end.
- **Scope-gated network tools**: `NetworkScan` (nmap), `WebProbe` (curl),
  `DnsLookup` (dig). Auto-registered ONLY when the scope file loads;
  every call (allowed OR refused) logs to the audit chain.
- **`aether review --kind security`**: single-turn critic, no tools.
  Structured `SEVERITY / CWE / LOCATION / SUMMARY / WHY / FIX` blocks
  per issue, language-specific focus lists for Rust / Python /
  JavaScript / Go / Java / C / C++ / SQL. `--json` returns parsed blocks.
- **STRIDE `aether threat-model <spec>`**: trust boundaries, data
  classes, per-category threats with mitigations + residual risk.
- **`aether ctf <dir>`**: bubblewrap-sandboxed challenge runner; mounts
  the challenge's listed files into `/work` and loops the agent until
  the expected flag is produced. Ships with an example XOR challenge.
- **Scanner tool wrappers**: gitleaks, cargo-audit, osv-scanner.
- **`Sandbox` tool**: bubblewrap-isolated command execution.
- **`aether security-eval <suite.yaml>`**: fixture-based OWASP-class
  regression. Seven Python fixtures (SQLi / path traversal /
  hard-coded creds / command injection / weak crypto / insecure
  deserialization / SSRF), each asserts the critic flags the expected
  CWE at the configured minimum severity. CI-friendly exit 1 on miss.

**Security Edge benchmark** — `aether security-eval eval/security/suite.yaml`:

- Sonnet 4.6: **7/7 (100%)** at correct CWE + severity, 110s total
- Opus 4.7: 2/7 (29%); 5 calls truncate mid-stream because Anthropic's
  cyber-safeguards classifier engages on adversarial-framing +
  structured-output + classic-injection-code combinations. Not a bug
  in aether; the same prompt clears on Sonnet 4.6. v0.7 docs
  recommend `AETHER_MODEL=claude-sonnet-4-6` for security review.

## v0.7.2 — shipped 2026-06-25 (patch)

- **Security eval suite expanded to 4 languages**: 9 new fixtures (Java
  ×3, C++ ×3, Go ×3) added to the 7 Python fixtures. Suite YAML and per-
  language README tables updated. Single autoroute run on Sonnet 4.6
  detects **16/16 at BLOCKER severity**, 5m21s wall-clock. No tooling
  changes — only fixtures + docs.

## v0.7.1 — shipped 2026-06-25 (patch)

- **Security auto-route**: `aether review --kind security` and `aether
  security-eval` auto-route Opus-class models (`claude-opus-*`) to Sonnet
  4.6 when `--model` was not passed explicitly. Pure-function router
  (`route_for_security`) covered by 6 unit tests. One-line stderr notice
  per invocation. Three override paths: explicit `--model X`,
  `AETHER_SECURITY_NO_AUTOROUTE=1`, or just call with Sonnet/Haiku
  directly. Closes the 5/7 Opus truncation reported in v0.7's BENCHMARK.

## v0.7.3 — shipped 2026-06-25 (patch)

- **7 new gap-filling fixtures** (→23 total): Python ReDoS (CWE-1333) +
  Jinja2 XSS (CWE-79), Java JNDI injection (CWE-917) + Jackson polymorphic
  deserialization (CWE-502), Go concurrent map race (CWE-362) + missing
  HTTP timeout (CWE-400), C++ use-after-free (CWE-416).
- **`aether security-eval --runs N --threshold P`**: repeat each fixture N
  times, assert pass_rate ≥ threshold. Four new unit tests
  (`compute_median_{odd,even}_count`, `meets_threshold_{above,below}`).
  `--runs 1` default preserves backward-compat. 15/15 unit tests passing.
- **Stability benchmark**: 23×3 run on Sonnet 4.6 — 23/23 at threshold 1.0.
  Per-fixture median/min/max ms table in `BENCHMARK.md`.

## v0.8 — BYOC provider parity — shipped 2026-06-25

- **Bedrock streaming** (B1): `invoke-with-response-stream` + AWS binary
  event-stream parser (total/headers_len + header type-7 extraction +
  base64 payload decode). No CRC dependency — TLS provides transport
  integrity. `complete_streamed()` live on `BedrockProvider`.
- **Vertex streaming** (B2): `:streamRawPredict` SSE endpoint + `parse_sse_data_events`
  line-by-line parser. `complete_streamed()` live on `VertexProvider`.
- **AWS credential provider chain** (B3): env vars → `~/.aws/credentials`
  INI → IMDSv2 (three-step: PUT token → GET role → GET creds) → ECS task
  role. `CredentialSource` enum reported by `aether doctor`. Pure
  `parse_credentials_file` covered by workspace tests.
- **GCP service-account JWT auto-refresh** (B4): RS256 JWT (iss/sub/aud/
  iat/exp/scope) via `jsonwebtoken = "9"`. Double-check `RwLock` pattern:
  fast read-lock check, write-lock mint only on miss/near-expiry (5 min
  buffer). `VertexProvider::from_service_account_file(path)` public API.
- **Cross-provider security-eval sweep** (B5): `aether security-eval
  --provider anthropic,bedrock,vertex` runs the same fixture suite through
  each provider and prints a comparison table. Human or `--json` output.
  `build_named_provider(name)` rejects unknown slugs with a clear error.
  3 new unit tests; 18/18 aether-cli tests green.

## v0.9 — REPL UX + session economics — shipped 2026-06-25

- **Print mode streaming** (D1): `run_print_agent` now calls `agent_turn_streamed`
  with an on_delta sink that writes deltas to stdout. REPL streaming (already
  in v0.7.x) gains `AETHER_NO_STREAM=1` kill-switch for buffered fallback.
- **Cost-estimator unit tests** (D2): 5 new tests pin per-model rates
  ($3/$15 Sonnet, $15/$75 Opus, $0.80/$4 Haiku) and cache multipliers
  (reads at 10%, writes at 125%); ordering invariants and unknown-model
  default-to-sonnet behaviour.
- **Automatic context compaction** (D3): new aether-core::compaction module
  + wire-in at the top of agent_turn_inner. Triggers when cumulative
  `usage_total.input_tokens + output_tokens` exceeds 80% of the model's
  context window. Keeps the final 1/3 of history verbatim; summarises the
  head into one synthetic User+Assistant pair. Per-compaction usage reset
  acts as hysteresis to prevent boundary oscillation. Kill-switch
  `AETHER_NO_COMPACT=1`. 8 unit tests.
- **Parallel safe-tool execution** (D4): partitions the per-turn tool_uses
  slice into runs of safe (read-only: Read/Glob/Grep/MemoryRead) and unsafe
  (mutating/unknown). Safe runs dispatch concurrently via
  `futures_util::future::join_all`; mutating tools keep sequential slots so
  file writes never race and interactive prompts can't double-fire. Result
  ordering matches model emission. Kill-switch `AETHER_NO_PARALLEL_TOOLS=1`.
  5 unit tests (interleave probe avoids fragile wall-clock assertions).
- **ENV_TEST_LOCK**: process-wide test mutex in aether-core::mock so kill-
  switch tests across compaction + executor don't race under cargo-test's
  parallel runner.

## v0.10 — reliability + Foundry — shipped 2026-06-25

- **Azure AI Foundry provider** (F1): new `aether-llm::azure` module.
  Anthropic Messages-API-compatible endpoints on Azure subscriptions
  via per-resource URL + `?api-version=...` query + `api-key` header.
  `AzureProvider::from_env()` reads `AZURE_AI_ENDPOINT` +
  `AZURE_AI_API_KEY` + optional `AZURE_AI_API_VERSION`. Slugs accepted
  by `build_named_provider`: `azure` / `azure-foundry` / `foundry`.
  4 unit tests (URL construction, trailing-slash strip, env validation,
  name stability). UNVERIFIED for live — no Azure subscription in env.
- **Unified retry watchdog** (F2): new `aether-llm::retry` module +
  `RetryingProvider` decorator wrapping any `LlmProvider`. Retries
  5xx / 429 / transport errors with exponential backoff (1s → 2s → 4s
  by default, 3 attempts). 4xx (non-429) and schema errors return
  immediately. `build_provider` + `build_named_provider` both wrap
  via `with_retry()` so REPL/print + sweep paths inherit retry. Streaming
  intentionally NOT retried (partial deltas already emitted; duplicate
  text on retry would corrupt the conversation). Kill-switch
  `AETHER_NO_RETRY=1`. 7 unit tests (classification, backoff math,
  retry-on-5xx, no-retry-on-4xx, max-attempts, kill-switch).
- **`aether doctor --probe`** (F3): opt-in 1-token round-trip against
  the active provider. Reports latency + token counts (from `usage`
  field) + provider name. Goes through retry wrapper so transient 5xx/429
  don't false-positive the health check. Exit 1 on probe failure.
  Default behavior (no flag) unchanged; emits "probe: skipped (pass
  `--probe` to make a 1-token round-trip)" so users discover the flag.

## v0.11 — cleanup + MCP WS + CI surface — shipped 2026-06-25

- **Stripped anthropic-internal retry** (G1): closes F2's weakest point.
  The v0.7-era `send_with_retries` in `anthropic.rs` (5 attempts +
  exponential backoff + jitter) was double-firing with v0.10's
  `RetryingProvider` wrapper, producing 3×5=15 worst-case attempts and
  minutes of cumulative sleep on real 5xx storms. Removed the inner
  loop (-43 LoC); `RetryingProvider` is now the single retry layer.
  Updated `LlmError::actionable()` text to match.
- **MCP WebSocket transport** (G2): new `WsClient` in aether-mcp alongside
  `StdioClient` + `SseClient`. Connects via `tokio-tungstenite::connect_async`,
  splits into writer (Mutex) + reader (spawn task), demuxes JSON-RPC
  responses by id. Implements the full `Client` trait. `spawn_client`
  factory now dispatches `ServerConfig::Ws` → `WsClient`. 4 new unit
  tests (URL scheme validation, wrong-config rejection, serde round-trip,
  factory dispatch). Live ws:// round-trip UNVERIFIED (no public test
  MCP-over-WS server).
- **`aether doctor --json`** (G3): structured output for CI consumers.
  Built progressively alongside the text path, same data fields, stable
  shape. Composes with `--probe`. Exit-code semantics preserved
  (0 on success, 1 on any failure).

## v0.12 — ship infrastructure — shipped 2026-06-25

- **GitHub Actions release workflow** (H1): new `.github/workflows/release.yml`
  triggers on `v*` tag push, builds release binaries for 4 platforms
  (linux-x86_64, linux-aarch64 via cross-rs, macos-x86_64, macos-aarch64)
  in parallel matrix, strips, tarballs with README + LICENSE files,
  generates per-tarball SHA256, concatenates into a single SHA256SUMS
  at the release root, and publishes a GitHub Release with all assets
  attached via softprops/action-gh-release@v2.
- **install.sh** (H2): one-liner install script. Detects OS (Linux/macOS)
  + arch (x86_64/aarch64) via uname, resolves "latest" via GitHub API,
  downloads tarball + SHA256SUMS, verifies hash, extracts to
  `$AETHER_PREFIX/bin` (default `~/.local/bin`). Refuses unsupported
  OS/arch with explicit source-build pointer. Uses curl or wget;
  sha256sum or shasum -a 256. Safe defaults: `set -euo pipefail`,
  tempdir cleanup trap, hash-mismatch abort.
- **LICENSE (Apache-2.0)**: workspace previously declared dual-license
  ("MIT OR Apache-2.0") but no LICENSE files were present. The user
  scoped this release to Apache-only — `Cargo.toml` license field
  updated, single `LICENSE` file at repo root with the full canonical
  Apache-2.0 text, bundled into every release tarball.
- **README install section + INSTALL.md** (H3): three install paths
  documented (one-liner, manual + verify, source-build) plus uninstall
  guidance.

## v0.13 — coding benchmark + comparison — shipped 2026-06-25

- **`aether coding-eval`** (I1+I2): new `eval/coding/` directory with
  5 bounded, verifiable tasks (bug fix, feature add, test write,
  refactor, doc fix). Each task has a starting state + a `verify.sh`
  that tests OBSERVABLE behavior via exit code — no model judgment in
  the verification loop. New `coding-eval` subcommand resets each
  task dir from git, spawns `aether -p` as a subprocess against the
  task dir, parses `[aether-usage ...]` stderr line for per-task
  tokens + cost, runs verify.sh, records pass/fail.
- **Live benchmark result** (I3): 5/5 PASS on Sonnet 4.6, ~$0.58 USD,
  184s total agent wall. Per-task table at `eval/coding/RESULTS.md`.
- **Honest comparison vs Claude Code** (I4) at
  `eval/coding/COMPARISON.md`. Three-part: (1) numbers aether produced
  live; (2) feature-by-feature inventory — features aether ships that
  CC does NOT (security-eval, threat-model, scope, audit chain, ctf,
  coding-eval itself, cross-provider sweep, doctor --probe --json),
  parity items, gaps aether has (VS Code ext, JetBrains, Windows
  binary); (3) UNVERIFIED items I cannot compare head-to-head because
  Claude Code isn't runnable in the test env.

## v0.14 — plugins + IDE surfaces (next)

- Plugin system via WASM modules registered as tools
- BYOC: Mantle
- VS Code extension, JetBrains plugin
- HTTP server WebSocket chat for browser clients

## v0.9 — enterprise

- SAML / OIDC federation
- Audit log forwarding to SIEM
- Per-org policy enforcement (tool blocklists, model restrictions)
- Trusted-device enrollment

## Explicit non-goals

- A drop-in `claude` binary replacement that spoofs Claude Code identity.
  aether's OAuth uses the SDK-agent identity prefix; we do not impersonate.
- Telemetry to a vendor endpoint. Hooks let operators export what they need.
- Auto-update.
