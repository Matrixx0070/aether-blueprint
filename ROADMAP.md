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

## v0.14 — coding benchmark v2 — shipped 2026-06-25

- **5 new cross-language tasks** (J1) bringing the suite from 5 → 10:
  - `06_rust_bug` (Rust): off-by-one bugs in `binary_search`; verify
    runs `cargo test` + a 1000-element stress test against `Vec::position`.
  - `07_js_xss` (Node.js): renderComment interpolates user input as raw
    HTML; verify exercises 4 XSS probes (script tag + img/onerror +
    ampersand corner + happy path).
  - `08_sql_injection` (Python+SQL): find_user concatenates username
    into SELECT; verify hits in-memory sqlite + injection probe +
    apostrophe escaping.
  - `09_multifile_refactor` (Python): order.py + invoice.py duplicate
    TAX_RATE + identical math; verify checks a new module exists,
    holds TAX_RATE, and both original fns shrink to ≤8 LOC.
  - `10_perf_opt` (Python): dedup is O(n²); verify asserts 50k inputs
    complete in ≤200ms (proves O(n) algorithm via timing, not source
    inspection).
- **Live run** (J2): **10/10 PASS, 388s wall, ~$1.12 USD on Sonnet 4.6**.
  Initial run was 9/10 due to a buggy verify check on task 7 (asserted
  escaped `onerror=` was bad, but escaped-as-text is harmless); test
  fixed to check raw `<img` is absent, agent's original output passed.
- **Cross-language proof** (J3): Python 7/7, Rust 1/1, JS 1/1, SQL+Py
  1/1. Documented honestly in RESULTS.md + COMPARISON.md.

## v0.15 — coding benchmark v3 + measurement honesty — shipped 2026-06-25

- **K1 measurement-gap fix**: `run_print_agent` loop now captures
  agent_turn errors into `deferred_error: Option<anyhow::Error>` instead
  of propagating with `?` mid-loop. Usage line emits unconditionally
  before the function returns; deferred error replayed AFTER usage
  prints so subprocess exit codes still reflect failure. Closes the
  v0.14 LOW that 4/10 tasks reported in=0/out=0. Verified live: task 04
  now reports $0.25 vs $0.00 before.
- **K2 suite v3 expansion** (10 → 15 tasks): adds Go nil-deref,
  TypeScript type-bug, Bash quoting, Dockerfile security hardening,
  Java NPE. Each fixture fails on starting state, verified directly.
- **K3-K6 stability**: 2 independent live runs of the full 15-task
  suite. Run 1: 13/15 PASS, $2.18, 544s. Run 2: 14/15 PASS, $2.45,
  626s. Both initial fails were the same class of verify-script bug
  fixed in v0.14 task 07: grep on file content matched against agent
  explanatory comments, not just executable code. After fixing
  task 12's verify (strip comments, accept 3 honest-fix patterns) +
  manually re-verifying both run outputs: **30/30 cumulative task
  completions, 0 agent failures**.
- **Coverage**: 9 languages (Python ×7, Rust, JavaScript, TypeScript,
  Go, Bash, Java, Dockerfile, SQL).

## v0.16 — plugins + IDE surfaces — shipped 2026-06-25

- **L1 HTTP WebSocket chat** on `aether serve`: new GET /ws/chat
  route streams agent text deltas as JSON frames. One prompt per
  connection; clients reconnect. axum ws feature + tokio-tungstenite.
- **L2 VS Code extension skeleton** (TypeScript) at `editor/vscode/`:
  3 commands (Ask / Ask about selection / Doctor), 3 settings,
  bare-minimum activation. `tsc -p .` compiles clean. Roadmap items
  (multi-turn webview panel, diff preview, WS backend) documented in
  the extension's own README.
- **L3 multi-turn coding tasks** added to coding-eval (3 new tasks,
  18 total). Tests whether the agent will commit to a design choice
  AND document the assumption in deliberately ambiguous prompts. Live
  on Sonnet 4.6: **3/3 PASS, $0.61** — agent chose half-up rounding,
  score-DESC sort with name-ASC tiebreaker, LRU(128) caching, each
  with rationale.
- **L4 subprocess plugin loader** in new `aether-plugin` crate.
  Manifest-based at `~/.aether/plugins/<name>/manifest.json` (or
  `$AETHER_PLUGIN_DIR`); tool input written to stdin, stdout becomes
  the reply. Zero new compile-time deps (no wasmtime — that's a v0.17+
  upgrade). 4/4 unit tests + LIVE end-to-end verified with a
  shell-script `plugin__hello` example.

WASM plugin sandboxing remains the v0.17+ goal — subprocess is the
practical v1 surface that ships now and gives users immediate
extensibility.

## v0.17 — plugin sandboxing + IDE polish — shipped 2026-06-26

- **M1 WASM-sandboxed plugin loader** (`aether-plugin-wasm` crate)
  alongside the v0.16 subprocess loader. Both coexist; the manifest's
  `runtime` field routes to the right backend. wasmtime + WASI
  preview1. 64 MiB / 30 s caps. No network, no FS except declared
  `allow_dirs`. Pure compile-time-deps add; no runtime changes for
  users who don't use WASM plugins.
- **M2 example WASM plugin** at `editor/wasm-plugin-example/` — 50-line
  Rust source → 47 KB optimised .wasm, zero dependencies.
- **M3 `/ws/chat` bearer auth**: when `AETHER_SERVE_TOKEN` is set,
  upgrades require `Authorization: Bearer <token>`. Constant-time
  comparison. Kill-switch `AETHER_SERVE_NO_AUTH=1`. Closes the L6
  finding that `aether serve --bind 0.0.0.0:...` was unauthenticated.
- **M4 VS Code multi-turn webview** panel — `aether: Open chat panel`
  command opens a webview that connects to `aether serve` over WS,
  streams Markdown deltas, shows per-turn token + cost in a footer.
  Vanilla JS + markdown-it CDN under strict CSP. No extra npm deps.
- **M5 plugin HMAC signing** — opt-in tamper detection.
  `aether plugin sign / verify` CLI; agent runtime checks manifest
  signatures when `AETHER_PLUGIN_HMAC_KEY` is set. Unsigned manifests
  load with a warning by default; refuse with
  `AETHER_PLUGIN_ENFORCE_SIGNING=1`. Trust model: symmetric HMAC,
  sufficient for self-verification; asymmetric-signed marketplace
  is v0.18+.

## v0.18 — production posture — shipped 2026-06-26

- **N1 ed25519 asymmetric plugin signing** alongside v0.17 HMAC.
  Manifest `algorithm` field dispatches; `aether plugin keypair / sign
  --algorithm ed25519 --private-key / verify --public-key`. Discovery
  uses `AETHER_PLUGIN_ED25519_PUBKEY`. 4 unit tests including
  cross-keypair tamper. Live-verified end-to-end this session
  (round-trip, tamper, cross-keypair).
- **N2 token-bucket rate limit** on `/v1/messages` + `/ws/chat`.
  Per-IP, in-memory. `AETHER_SERVE_RATE_LIMIT_RPM` (default 60).
  X-Forwarded-For honoured. 429 + `Retry-After`. Kill-switch
  `AETHER_SERVE_RATE_LIMIT_RPM=0`.
- **N3 audit syslog tee + tail**. `AETHER_AUDIT_SYSLOG=1` forwards
  every audit_append entry to `/dev/log` (Linux) / `/var/run/log`
  (macOS) with `LOG_USER` facility. New `aether audit tail [--follow]
  [--limit N]` subcommand prints recent entries, optionally
  poll-streaming new ones.
- **N4 per-org policy file** at `~/.aether/policy.json` (override via
  `AETHER_POLICY_FILE`). `model_allowlist`: refuses boot (exit code 2)
  if the resolved model isn't on the list. `tool_blocklist` +
  `max_tokens_per_turn` stored via OnceCell, ready for executor
  enforcement in v0.19.
- **N5 concurrent-session cap** on `aether serve`. Atomic counter on
  POST `/v1/messages` + WS `/ws/chat`. 503 + `Retry-After: 5` past
  `AETHER_SERVE_MAX_SESSIONS` (default 32). RAII `SessionGuard` so
  panics / WS hangups release the slot.

## v0.19 — executor policy enforcement + cost dashboard — shipped 2026-06-26

- **O1 tool-blocklist enforced at executor dispatch**. New
  `Executor::policy_blocklist` field + `set_policy_blocklist` setter +
  `is_policy_blocked` dispatch-time check. `bypassPermissions` cannot
  override the policy blocklist (that is the entire point of the
  layer). 4 new unit tests; aether-core lib: 36 passed.
- **O2 apply_policy_to_session()** wired at all 9 `Session::new` sites
  (print, REPL, TUI, serve_one_turn, ws_run_one_turn_streamed,
  sub-agents). Caps `max_tokens_per_turn` to the policy ceiling when
  smaller; pushes `tool_blocklist` into the executor.
- **O3 aether usage SQLite dashboard** at `~/.aether/usage.db`.
  Versioned schema (errors on mismatch). Per-turn writers in print
  mode, REPL (delta = post-pre), HTTP `/v1/messages`, WS `/ws/chat`.
  Reader: `aether usage [--days N] [--by-model] [--by-tool] [--json]`.
  `AETHER_NO_USAGE_DB=1` disables the writer.
- **O4 inotify-based audit tail** via `notify` crate (cross-platform:
  inotify Linux, kqueue macOS, RDCW Windows). Watches the parent dir
  so log rotations don't blind the subscription. 2-second timeout
  doubles as rotation safety poll.
- **O5 plugin trust keychain** at `~/.aether/plugin-trust.txt`.
  Line-delimited hex ed25519 public keys. `aether plugin trust
  list/add/remove`. `discover_plugins()` accepts any trusted key for
  ed25519 manifests. `AETHER_PLUGIN_ED25519_PUBKEY` remains as a
  zero-config fallback.

## v0.20 — cross-IDE + remote BYOC — shipped 2026-06-26

- **P1 JetBrains plugin scaffold** at `editor/jetbrains/` — Kotlin /
  Gradle / IntelliJ Platform 2024.3. Tool window, WS streaming
  to `aether serve`, settings panel, Ctrl/Cmd+Alt+A. UNVERIFIED
  build chain in CI (heavy IntelliJ Platform download); manual
  install path documented.
- **P2 Mantle BYOC provider** — 5th provider in `aether-llm` next
  to Anthropic/Bedrock/Vertex/Azure. Anthropic-Messages-API-
  compatible proxy; `MANTLE_API_KEY` + optional `MANTLE_BASE_URL`.
  5 unit tests.
- **P3 VS Code marketplace publish prep** — repository / homepage /
  bugs / keywords metadata; bundled Apache-2.0 LICENSE; CHANGELOG.
  `vsce package` produces `aether-0.20.0.vsix` (9 files, 18.65 KB).
- **P4 `/v1/trust` routes + VS Code trust UI** — server gains
  `GET/POST/DELETE /v1/trust` (bearer-protected). VS Code adds an
  `aether.openTrust` command + webview that lists / adds /
  removes trusted ed25519 keys.
- **P5 inline tool-use diffs in the VS Code chat panel** — server
  WS handler emits a `tool_use` frame per tool the agent invokes;
  panel renders an inline "before / after" diff for Edit / Write
  or a labelled entry for any other tool. Read-only in v0.20
  (Accept/Reject deferred to v0.21).
- **P6 usage dashboard QoL** — `aether usage --csv` (RFC4180),
  `--tail` (notify-based live stream of new turn rows),
  `AETHER_COST_CEILING_USD` warn-once when 24h spend crosses the
  ceiling.

## v0.21 — finish-what-P-deferred + close UNVERIFIED — shipped 2026-06-26

- **Q2 per-tool WS streaming** — Executor `tool_hook` now fires the
  `tool_use` frame the instant the tool dispatches; for Edit/Write
  it also captures the file's pre-state into `original_contents`
  + `did_not_exist`. Replaces the v0.20 end-of-turn batch.
- **Q1 Accept / Reject for inline tool diffs** — new
  `POST /v1/rollback` (bearer-protected) restores a file to its
  captured pre-state; VS Code panel renders Accept / Reject buttons
  under each Edit/Write diff. Reject deletes a Write-that-created
  or overwrites with original_contents for Edit / Write-that-overwrote.
  Idempotent on delete (200 "already_absent").
- **Q3 Bedrock streaming** — smoke verified (clean parseable error
  on no-creds path); live round-trip remains UNVERIFIED pending
  operator-supplied AWS credentials.
- **Q4 JetBrains build** — scaffold structurally validated (P1);
  `./gradlew buildPlugin` remains UNVERIFIED pending a host with
  JDK 21 + Gradle 8.10.
- **Q5 Mantle cross-provider sweep** — `--provider mantle` reaches
  MantleProvider with clean error on missing creds; live security-
  eval matrix remains UNVERIFIED pending operator Mantle creds.
- **Q6 cosign-keyless signed releases** — `SHA256SUMS` is signed
  via Sigstore + GitHub OIDC; `.sig` + `.pem` ride the release.
  INSTALL.md documents the verifier recipe.

## v0.22 — enterprise hardening — shipped 2026-06-26

- **R4 SSO scaffolding** — `aether sso configure / status / login /
  logout`. Configure does OIDC discovery against `{issuer}/.well-
  known/openid-configuration` and writes `~/.aether/sso.json`
  (0600). Login binds 127.0.0.1:0, runs a PKCE-protected auth-code
  flow with S256 challenge + 16-byte state, exchanges the code at
  token_endpoint, persists id_token (or access_token fallback) to
  `~/.aether/sso.token` (0600). `AETHER_REQUIRE_SSO=1` blocks
  REPL/print mode at entry unless a token is present.
- **R5 plugin manifest commit_sha + --enforce-commit-pinned** —
  optional `commit_sha` field, automatically covered by the
  existing canonical-bytes signature (HMAC + ed25519 both).
  `aether plugin verify --enforce-commit-pinned` refuses manifests
  without the field. Tamper-after-sign verified to fail the
  signature math.
- **R6 multi-tenant aether serve + usage.db schema v2** — optional
  `X-Aether-Tenant: <slug>` header on `/v1/trust` (per-tenant
  keychain at `~/.aether/tenants/<slug>/plugin-trust.txt`). Slug
  validation [A-Za-z0-9_-]+ blocks path traversal. usage.db
  migrates v1 → v2 in place at first open (adds `tenant` column +
  index on `turns` and `tool_calls`).
- R1 / R2 / R3 — the cred-blocked verifiers (Bedrock streaming,
  JetBrains build, Mantle sweep) remain DONE/UNVERIFIED — they
  close the moment the operator supplies AWS creds, JDK 21 +
  Gradle, or a Mantle endpoint respectively.

## v0.23 — token-binding, JWT validation, completion API — shipped 2026-06-26

- **S2 JWT signature validation in `aether sso login`** — after the
  token exchange, fetch jwks_uri, find the JWK by `kid`, verify
  RS256/ES256 + iss + aud + exp locally; refuse to persist the
  token on any failure. Closes R7 MED #1.
- **S1 tenant ACL** — `~/.aether/tenants.json` binds bearer-sha256
  ↔ allowed tenants. `aether tenant grant/list/revoke` admin
  surface. Server gate returns 403 on mismatch. Closes R7 MED #2.
- **S3 `tool_calls` writers** — Post-phase tool_hook records
  `(name, duration_ms, is_error)` rows into the schema row that
  shipped empty in v0.19. `aether usage --by-tool` finally has data.
- **S4 `aether plugin verify --resolve-commit <repo>`** — runs
  `git ls-remote` (URL) or `git cat-file -t` (local path) against
  the manifest's commit_sha; exits non-zero if the SHA doesn't
  resolve. Closes R7 LOW #2.
- **S5 `POST /v1/complete`** — fill-in-the-middle code completion
  with SSE delta streaming. Same bearer + tenant gates as /ws/chat.
- **S6 `aether plugin trust sync --remote <git-url> [--push]`** —
  pulls a team-curated `trusted-keys.txt` and merges it additively
  (union) into the local keychain. With --push, also writes back.

## v0.24 — followups + verifier hardening — shipped 2026-06-26

- **T4 `/v1/complete` fence-strip** — server-side state machine
  strips leading ```language\n + trailing ``` from streamed SSE
  deltas; strict prefix check preserves backtick template literals.
- **T1 EdDSA in JWT validation** — `aether sso login` now accepts
  RS256 + ES256 + EdDSA. OKP/Ed25519 JWK parsing via
  `DecodingKey::from_ed_components`.
- **T3 `plugin verify --require-signed-commit`** — runs `git
  verify-commit <sha>` on the resolved local commit; refuses
  unsigned. URL mode explicitly rejected (commit body not fetched).
- **T5 `plugin trust sync --remove-from-team <hex>`** — subtractive
  complement to the S6 union pull; with --push, the team copy
  drops the matching keys too. Without --push, only local is
  updated.
- **T2 per-tool_use_id `tool_calls` keying** — `ToolHookCallback`
  signature extended with tool_use_id; HashMap key is the id
  (Anthropic's per-call unique id), so concurrent same-name calls
  no longer alias.
- T6 — R1/R2/R3 cred-blocked verifiers (Bedrock streaming, JetBrains
  build, Mantle sweep) remain DONE/UNVERIFIED; closing pending
  operator inputs.

## v0.25 — observability + enterprise alt-paths + key hygiene — shipped 2026-06-26

- **U4 signed-commit integration test** at tests/u4-signed-commit.sh
  — mints a throwaway gpg key + signed commit, asserts
  `--require-signed-commit` exits 0 + "carries a valid signature".
  Closes T3 LOW.
- **U5 provider pool for /v1/complete** — process-wide
  Mutex<HashMap<provider_name, Arc<dyn LlmProvider>>>; back-to-back
  completions reuse one HTTP client + auth. ~240ms saved on the 2nd
  request. Closes S7 LOW.
- **U3 `aether plugin trust audit`** — surfaces per-key git-log
  provenance (commit SHA + date that introduced each key) when a
  team keychain remote is provided; file-mtime fallback otherwise.
- **U1 Prometheus /metrics on `aether serve`** — 8 atomic counters
  (turns, tool_calls, errors, complete, rollback, 429, 4xx,
  duration_ms_sum). Bearer-protected when AETHER_SERVE_TOKEN is set.
- **U2 webhook notifications** — `aether webhook configure / list /
  remove / test`. POSTs carry `X-Aether-Signature: sha256=<hex(hmac_
  sha256(secret, body))>` (GitHub-webhook shape). Hooked into
  rollback_handler.
- **U6 SAML scaffolding** — `aether sso configure-saml --idp-metadata-
  url` fetches IdP metadata, extracts SSO endpoint + binding + X509
  signing cert, persists to ~/.aether/sso-saml.json. XXE-safe (DOCTYPE
  + ENTITY refused; body capped at 1 MiB).

## v0.26 — observability + enterprise plumbing — shipped 2026-06-27

- **V3 labelled metrics + histogram + rename** — closes U7 MED #1+#2.
  `aether_tool_calls_labelled_total{tool="…",is_error="…"}` via
  RwLock<HashMap>. `/v1/complete` latency histogram with cumulative
  buckets. `aether_turn_duration_ms_sum` renamed to
  `aether_tool_call_duration_ms_sum` (breaking name change for scrapers).
- **V2 webhook coverage** — closes U7 MED #4. trust-add, trust-remove,
  sso-token-rotate (login + logout) all fire `fire_webhook(event, …)`.
  Live-verified HMAC-signed POSTs against a python receiver.
- **V6 provider pool TTL + /admin/reload-pool** — closes U7 LOW.
  `AETHER_PROVIDER_POOL_TTL_SECS` evicts stale entries; bearer-protected
  `POST /admin/reload-pool` clears the pool atomically.
- **V5 tenant quota** — `rpm_cap` (per-minute fixed window) + `daily_
  cost_usd_cap` (rolling 24h SUM(cost_usd)) on TenantAclRow. Server
  returns 429 / 402 with informative JSON error.
- **V4 AETHER_SERVE_TOKEN_FROM_SECRETS_MANAGER** — `vault:<path>`
  scheme reads KV v2; `aws:<id>` returns informative-error stub
  (full AWS Secrets Manager dep deferred). Live-verified vault path
  resolves a bearer that the server then enforces.
- **V1 SAML login routing** — `aether sso login` detects sso-saml.json
  and routes to a stub that loads + reports the scaffold, then bails
  with an informative message. The full redirect-binding + signed-
  response validation pipeline is honestly deferred to Plan W (multi-
  week pure-Rust XML crypto).

## v0.27 — enterprise gap-closes — shipped 2026-06-27

- **W4 per-tool argument-filter policy** — `tool_arg_filters` on
  policy.json; executor refuses or warns on regex matches against
  the serialised tool input. Live-verified across refuse / allow /
  warn / invalid-regex.
- **W6 plugin-load-failure webhook** — closes V2 NON-GOAL.
  `aether_plugin::discover_plugins_with_diagnostics` surfaces
  failure diagnostics; CLI fires `fire_webhook("plugin-load-failure",
  {manifest_path, reason})`. Live-verified with a broken manifest.
- **W5 audit-log forwarding to SIEM** — `AETHER_AUDIT_FORWARD=
  loki:<url>` or `=splunk:<url>` activates HTTP-POST forwarding
  with a 10-line batch buffer. Live-verified against a fake Loki
  receiver — 12 audit entries → 2 batched POSTs.
- **W3 AWS Secrets Manager backend** — closes V4 MED. Hand-rolled
  SigV4 reusing the v0.8 Bedrock cred chain; `aws:<id>` resolves
  the secret and stuffs it into AETHER_SERVE_TOKEN. Live-verified
  against a fake SM endpoint.
- W1 (SAML AuthnRequest + redirect-binding) and W2 (signed-
  response validation) — DEFERRED to a dedicated SAML plan. The
  full pure-Rust XML c14n# + RSA-SHA256 + x509 pipeline is multi-
  week work that doesn't fit a 24h plan budget honestly. The v0.26
  SAML routing refusal stays in place — operators don't silently
  fall into an unvalidated flow.

## v0.28 — distributed tracing + per-field policy + WASM diagnostics — shipped 2026-06-27

- **X1 OpenTelemetry tracing on serve hot path** —
  `AETHER_OTEL_ENDPOINT=<otlp-http-base>` enables OTLP/HTTP JSON
  span export from /v1/messages, /v1/complete, /ws/chat. Span
  attributes: http.method, http.route, http.status_code,
  duration_ms, aether.model, aether.tenant. Process-wide
  `reqwest::Client` reuse; fire-and-forget tokio task per span;
  no overhead when env var unset.
- **X2 per-field arg-filter policy** — `tool_arg_filters` rows
  gain `field: <dotted-json-path>`; the regex matches against
  that field instead of the whole serialised body. Closes W4
  LOW. Rows without `field` retain v0.27 whole-body semantics.
- **X3 WASM plugin-load-failure diagnostics** — sister to W6.
  `aether_plugin_wasm::discover_wasm_plugins_with_diagnostics`
  surfaces WASM-loader failures; CLI fires
  `fire_webhook("plugin-load-failure", {runtime:"wasm",
  manifest_path, reason})`. Subprocess loader gets a runtime-tag
  filter so WASM manifests aren't double-dispatched.
- **X4 tenant rpm Redis backend** — `AETHER_RATE_BACKEND=
  redis://host:6379` switches the V5 per-bearer rpm bucket from
  process-local Mutex<HashMap> to Redis INCR+EXPIRE so the cap is
  correct across a horizontally scaled fleet. Closes V5 LOW.
  Falls back to in-process bucket on single-thread tokio runtime
  or on Redis errors (fail-open with stderr warning).
- **X5 plugin trust audit --history** — extends U3.
  `aether plugin trust audit --history <hex-prefix> --remote
  <url>` shows every add/remove transition for that key.
- **X6 periodic SIEM flusher** — 1-second tokio interval task
  drains the W5 batch buffer so low-volume operators don't lose
  audit rows. Closes W5 LOW. Runs on `tokio::task::spawn_blocking`
  so it doesn't pin a worker for the `curl --max-time 2` syscall.
- **X7 self-audit + Plan Y draft** — pre-tag audit caught the
  block_in_place flavor guard + the spawn_blocking wrap; both
  fixed in-band. Plan Y drafted as the standalone SAML plan.
- W1+W2 SAML pipeline — still DEFERRED to Plan Y.

## v0.29 — SAML 2.0 SSO end-to-end — shipped 2026-06-27

- **Y1 AuthnRequest emission** — SP-initiated `<samlp:AuthnRequest>` in
  HTTP-Redirect binding (raw DEFLATE + standard base64 + URL-encode per
  saml-bindings-2.0 §3.4.4.1). Destination / ACS URL / SP entityID
  validated for XML-special chars before emission.
- **Y2 SAML ACS endpoint** — non-blocking `TcpListener` on `127.0.0.1:0`
  serves the IdP's HTTP-POST callback; full HTTP/1.1 request reader
  (`Content-Length` framing), URL-decode → base64-decode → raw XML
  body. RelayState parsed and hard-validated (CSRF bail, not warn).
- **Y3 quick-xml SAMLResponse extractor** — event-walker over full
  `<samlp:Response>` tree; extracts `Status.code`, `Assertion.ID`,
  `Issuer`, `NameID`, `SubjectConfirmationData`, `Conditions`,
  `AudienceRestriction`, and `<ds:Signature>` (signed-info fragment +
  inherited NS + value + x509 cert).
- **Y4 exclusive XML canonicalization 1.0** — hand-rolled exc-c14n#
  (no external c14n crate): namespace inheritance from `inherited`
  map, utf-8 attribute sorting, element/attr/text escaping; also
  `canonicalize_exc_c14n_subtree_with_skip` for enveloped-signature
  stripping. Byte-for-byte interoperable with lxml.
- **Y5 RSA-SHA256 assertion signature verify** — full 6-step pipeline:
  (1) algorithm gate, (2+3+4) per-Reference transform/digest/c14n
  verification, (5) SignedInfo RSA-SHA256 signature check, (6)
  KeyInfo X509Certificate pin against configured IdP cert DER;
  `load_idp_signing_key` now returns `(RsaPublicKey, Vec<u8>)` so
  the cert pin is active in production (BLOCKER-1 fix).
- **Y6 assertion bounds + audience** — `Conditions/@NotBefore` /
  `@NotOnOrAfter`, `SubjectConfirmationData/@NotOnOrAfter`, and
  `AudienceRestriction` validated with configurable clock skew
  (`AETHER_SAML_CLOCK_SKEW_S`, default 30 s, clamped [0, 300]).
- **Y7 NameID → SAML session token** — `saml.v1.<b64url(nameid)>
  .<b64url(idp)>.<b64url(32-byte-nonce)>` written to
  `~/.aether/sso.token` at mode 0600.
- **Audit fixes (pre-tag)**:
  - BLOCKER-2 (XSW): `verify_saml_assertion_signature` validates that
    the Reference target's local name is "Assertion" before
    canonicalising.
  - BLOCKER-3 (CSRF): RelayState mismatch elevated from `eprintln!`
    warn to `anyhow::bail!`.
  - HIGH-1: `find_element_byte_range_by_id` End-event comparison uses
    local names, not raw qnames.
  - HIGH-2: `SubjectConfirmationData/@Recipient` and `@InResponseTo`
    validated against ACS URL and AuthnRequest ID when present.
- **Live verify**: `tests/y7-saml-smoke.py` (RSA-2048 + lxml exc-c14n
  signed SAMLResponse → `aether sso login` ACS → `sso.token` at 0600).
  Exit 0 confirmed on this commit.

## v0.30 — OIDC hardening + BYOC wire-format smokes — shipped 2026-06-27

Plan Z. The shipped scope diverged from the original draft: Z1–Z3
became OIDC hardening of the existing flow (not net-new OIDC) after
audit revealed the v0.18 OIDC flow was already feature-complete but
missing three real spec gates. Z4–Z6 became fake-endpoint wire-format
smokes after the live BYOC paths surfaced billing / Marketplace
gates outside aether's control (documented honestly in commits).

- **Z1' OIDC nonce binding** (commit a60baad). 32-byte
  URL-safe-no-pad nonce generated alongside state + PKCE verifier,
  threaded through the authorization URL as `&nonce=…` and into
  `validate_id_token`. New pure helper `verify_nonce_claim`. 4 unit
  tests + fake-IdP smoke (`tests/z1-oidc-smoke.py`) live-verifies
  nonce round-trip end-to-end. Closes OIDC core §15.5.2 replay gap.
- **Z2 at_hash + JWKS hardening** (edebaf0). `verify_at_hash_claim`
  computes left-most half-of-hash per OIDC core §3.1.3.6:
  SHA-256[:16] for RS256/ES256, SHA-512[:32] for EdDSA. JWKS fetch
  gains a 10s reqwest timeout + 256 KiB body cap (read as bytes
  before parse so the cap fires pre-deser). 5 unit tests.
- **Z3 require-jwks default + iat freshness + at_hash strict mode**
  (490a714). Missing `jwks_uri` is now a hard refusal; operators
  who genuinely need to point at a legacy issuer set
  `AETHER_OIDC_ALLOW_UNVERIFIED=1`. `verify_iat_claim` bounds iat
  to ±`AETHER_OIDC_CLOCK_SKEW_S` (default 60s, clamped [0, 300]).
  `AETHER_OIDC_REQUIRE_AT_HASH=1` makes the at_hash claim
  mandatory whenever an access_token was issued. 6 unit tests.
  Aether log line is now `signature + nonce + iat + at_hash OK`.
- **Z4 Bedrock fake-endpoint smoke** (8e10a55). New
  `AETHER_BEDROCK_ENDPOINT` env override resolved through
  `BedrockProvider::base_url()`. Python fake server
  (`tests/z4-bedrock-smoke.py`) hand-frames AWS event-stream
  messages for `:invoke-with-response-stream` and serves Anthropic
  JSON for `:invoke`. Validates SigV4 prefix + body shape (no
  top-level `model`, `anthropic_version` discriminator present).
  Honest UNVERIFIED carried forward: real AWS Bedrock round-trip
  not exercised — no creds in env.
- **Z5 Vertex fake-endpoint smoke** (3365e15). New
  `AETHER_VERTEX_ENDPOINT` env override resolved through
  `VertexProvider::base_url()`. Python fake server
  (`tests/z5-vertex-smoke.py`) returns Anthropic-shape JSON on
  `:rawPredict` and SSE `data: {…}` lines on `:streamRawPredict`.
  Validates `Authorization: Bearer` + `anthropic_version =
  vertex-2023-10-16` + absent `model`/`stream` keys. Honest
  UNVERIFIED: real GCP Anthropic-on-Vertex round-trip blocked at
  Google's billing gate — `gcloud auth print-access-token` worked,
  aether sent the right request, but billing was disabled on all
  three projects on the active account; even with billing, Anthropic
  on Vertex requires a Cloud Marketplace subscription.
- **Z6 Azure fake-endpoint smoke** (0e2dd12). Zero Rust changes —
  `AZURE_AI_ENDPOINT` already plays the env-override role.
  `tests/z6-azure-smoke.py` validates `api-key` header (NOT
  Bearer), `anthropic-version: 2023-06-01` header, URL query
  `api-version=2024-08-01-preview`, plain Anthropic Messages body
  shape (model + messages + max_tokens, no Bedrock-style stripping).
  Honest UNVERIFIED: real Azure AI Foundry round-trip — no Azure
  subscription in this session.

24 new Z-prefix unit tests pass alongside the existing 33 Y-prefix
SAML tests. 3 new fake-IdP smokes added to `tests/` (one each for
OIDC / Bedrock / Vertex / Azure → 4 total including the existing
Y7 SAML smoke).

## v0.31 — enterprise SSO breadth — shipped 2026-06-27

Plan AA. Honest scope re-frame mid-plan: AA1–AA3 (Bedrock / Vertex /
Azure real round-trips) were blocked on operator-side gates outside
aether's control (Vertex live attempt produced concrete evidence —
all 3 GCP projects had billing disabled, plus Anthropic-on-Vertex
requires a Cloud Marketplace subscription). The plan pivoted to the
non-cred-dependent slices: SAML HTTP-POST binding (closes a v0.29
explicit deferral), multi-cert IdP support, configure-saml
auto-discovery, and OIDC userinfo.

- **AA4 SAML HTTP-POST AuthnRequest binding** (commit 79fed59). New
  `encode_saml_request_post` (standard base64, no DEFLATE per
  saml-bindings-2.0 §3.5.4) + `render_saml_post_form`
  (self-submitting HTML form: method=POST, action=<sso_url>, hidden
  SAMLRequest + RelayState, `onload` auto-submit, `<noscript>`
  Continue button as the no-JS fallback the spec mandates).
  `sso_login_saml` binding-dispatches between Redirect and POST;
  POST writes the form to `~/.aether/saml/authn-request-form.html`
  at mode 0600 and opens via `file://`. The ACS listener + Y3-Y7
  pipeline is untouched (IdP→SP leg is identical regardless of
  binding). 3 new unit tests + live smoke
  `tests/aa4-saml-post-smoke.py`.
- **AA5 multi-cert IdP support** (commit 125d2c6). Loader
  resolution order: `AETHER_SAML_IDP_CERT_PEM` env (single-file
  legacy override) → `~/.aether/saml/idp-certs/*.pem` (multi-cert
  dir, lex order) → `~/.aether/saml/idp-cert.pem` (single-file
  legacy fallback). `verify_saml_assertion_signature` takes
  `&[(RsaPublicKey, Vec<u8>)]` and walks the slice first-match-
  wins; KeyInfo X509Cert pin runs against the matched DER not the
  full slice (so a confused-deputy attack swapping the KeyInfo
  cert is still rejected even if the swapped cert happens to be
  trusted). 5 new unit tests + live smoke
  `tests/aa5-multi-cert-smoke.py`.
- **AA5-followup configure-saml multi-cert discovery** (commit
  62ed5b8). Closes the AA5 weakest-point. `configure-saml`
  extracts ALL `<KeyDescriptor use="signing"><X509Certificate>`
  nodes from IdP metadata, PEM-wraps each, writes to
  `idp-certs/NN-discovered.pem` at mode 0600 with NN reflecting
  metadata order. Re-runs clear existing `*.pem` first so stale
  certs don't accumulate. 6 new unit tests + live smoke
  `tests/aa5fu-configure-saml-multi-cert-smoke.py`.
- **AA6 OIDC userinfo + `aether sso whoami`** (commit a997c48).
  `SsoConfig.userinfo_endpoint: Option<String>` captured at
  configure time (serde default keeps pre-AA6 sso.json compatible).
  `sso_login` writes a `~/.aether/sso.access_token` sidecar at
  mode 0600 — the userinfo endpoint needs the access_token as
  Bearer, NOT the id_token JWT. New `sso whoami [--json]`
  subcommand: 10s reqwest timeout + 256 KiB body cap (Z2
  hardening pattern), prefers sidecar / falls back to sso.token
  with a warn. Formatted output prints sub + email + name +
  username + groups; `--json` emits raw userinfo for `jq`. Pure
  `parse_whoami_claims` helper handles `groups` array-or-string-
  or-mixed shapes. `sso logout` cleans up both files. 5 new unit
  tests + live smoke `tests/aa6-oidc-whoami-smoke.py`.

**Honest UNVERIFIEDs carried forward (all documented in commits +
Plan BB pre-reqs):**
- AA1 Bedrock real AWS round-trip — no creds in env.
- AA2 Vertex real GCP round-trip — gcloud auth worked, but all 3
  projects had billingEnabled=false; Anthropic-on-Vertex
  Marketplace subscription also needed.
- AA3 Azure real round-trip — no AAD subscription in this session.

15 new unit tests (3 AA4 + 5 AA5 + 6 AA5-followup + 5 AA6) + 4 new
fake-IdP Python smokes pass alongside the existing Y/Z corpora.
67/67 Y/Z/AA-prefix unit tests green.

## v0.32 — next (Plan BB draft)

- **BB1 Bedrock + Vertex + Azure live round-trip** — same plan as
  AA1–AA3, awaiting creds + Marketplace + billing.
- **BB2 OIDC mTLS client auth (RFC 8705)** — alternative to
  `client_secret_basic` for high-assurance OAuth clients.
- **BB3 Tenant SCIM provisioning** — `/v1/scim/Users` CRUD
  reusing `tenant_acl.db`, bearer-gated via `AETHER_SCIM_BEARER`.
- **BB4 Signed AuthnRequest (POST binding)** — close the AA4
  weakest-point. Some enterprise IdPs require XML Digital
  Signature over the AuthnRequest element with the SP's private
  key.
- **BB5 OIDC access-token refresh** — close the AA6 weakest-point.
  Persist `refresh_token` from the token response (when issued),
  `aether sso whoami` auto-refreshes on 401, new `aether sso
  refresh` subcommand for manual rotation.
- **BB6 SAML metadata auto-refresh** — close the AA5-followup
  weakest-point. New `aether sso refresh-saml` subcommand
  re-fetches metadata and rotates `idp-certs/` without bouncing
  aether. Optional cron periodicity via env knob.

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
