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

## v0.32 — close every AA weakest-point — shipped 2026-06-27

Plan BB. 3 shipped + 3 cred-blocked carried forward to Plan CC.
The shipped trio specifically closes the three weakest-points Plan
AA's self-audit documented — each was queued with a concrete
remediation, and each got delivered without operator-side gates.

- **BB4 Signed AuthnRequest (POST binding)** (commit 25301f0).
  Closes AA4 weakest-point. `AETHER_SAML_SP_PRIVATE_KEY_PEM=path`
  makes aether splice a `<ds:Signature>` block into the
  AuthnRequest right after `</saml:Issuer>` (schema-mandated
  position per saml-core-2.0 §3.2.1), using the same algorithm
  pipeline the Y5 verifier accepts on the IdP→SP side: RSA-SHA256
  + SHA-256 digest + [enveloped-signature, exc-c14n#] transforms.
  `load_sp_signing_key_from_pem` accepts both PKCS#8 + PKCS#1 PEM
  (openssl-3 default + legacy fallback). `sign_authn_request_xml`
  reuses Y4 `canonicalize_exc_c14n_subtree` + Y5 algorithm
  constants. Cargo: enabled `pem` feature on the rsa crate. 3
  unit tests + live smoke `tests/bb4-signed-authn-request-smoke.py`
  drives full spec-path verify with lxml (Signature placement /
  Reference URI / DigestValue against c14n-of-unsigned / RSA
  SignatureValue verify).
- **BB5 OIDC access-token refresh** (commit 49b0b1a). Closes AA6
  weakest-point. `sso_login` persists the `refresh_token` to
  `~/.aether/sso.refresh_token` (mode 0600, write_sso_sidecar
  helper extracted). New `aether sso refresh` subcommand for
  manual rotation. `sso_whoami` auto-refreshes ONCE on userinfo
  401 when the refresh sidecar exists; `--no-refresh` opts out.
  Pure `parse_token_response` helper (RFC 6749 §5.1: access_token
  REQUIRED; refresh/id/expires optional) + async
  `refresh_oauth_access_token` helper used by both manual and
  auto-refresh paths. Handles refresh-token rotation per RFC 6749
  §6 (when IdP returns a new RT alongside the new AT, both
  sidecars overwritten). `sso_logout` cleans up all three files.
  5 unit tests + live smoke `tests/bb5-oidc-refresh-smoke.py`
  (six-step chain: login → whoami → invalidate AT → auto-refresh
  + retry → manual refresh → --no-refresh opt-out → logout cleanup).
- **BB6 SAML metadata auto-refresh** (commit edc7328). Closes
  AA5-followup weakest-point. configure-saml persists
  `idp_metadata_url` in sso-saml.json. New `aether sso
  refresh-saml [--watch]` subcommand: one-shot re-runs the AA5-
  followup multi-cert layout against the persisted URL; `--watch`
  runs a foreground daemon refreshing every
  `AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS` (default 3600s,
  clamped [60, 86400]). Refactor extracted
  `fetch_saml_metadata_xml` (HTTP + XXE/size validation) and
  `apply_saml_idp_metadata` (pure layout) helpers shared between
  configure-saml and refresh-saml. Tick errors logged + swallowed
  in watch mode so a transient IdP 5xx doesn't kill the daemon.
  3 unit tests + live smoke
  `tests/bb6-saml-refresh-metadata-smoke.py` (seven-step chain:
  configure-saml v1 → flip server to v2 → refresh-saml rotates
  idp-certs/ → SAML login signed with v2-only key verifies via
  AA5 first-match-wins → --watch banner emission). Caught
  mid-development: refactor accidentally changed configure-saml
  stderr wording and broke the AA5fu smoke's grep; original
  wording restored.

**Honest UNVERIFIEDs carried forward to Plan CC:**
- BB1 Bedrock real AWS round-trip — no creds in env.
- BB2 Vertex real GCP round-trip — billing + Marketplace gates
  outside aether's control.
- BB3 Azure real round-trip — no Foundry resource in this session.

11 new BB-prefix unit tests (3 BB4 + 5 BB5 + 3 BB6) + 3 new Python
fake-IdP smokes. 78/78 Y/Z/AA/BB-prefix unit tests pass.

## v0.33 — every AA + BB weakest-point closed — shipped 2026-06-27

Plan CC. 3 shipped + 3 cred-blocked carried forward. The shipped
trio closed the LAST documented weakest-points across both Plan AA
and Plan BB — every gap the self-audits flagged across the enterprise
SSO surface (SAML + OIDC) now has a delivered remediation.

- **CC4 SAML metadata drift detection** (commit b3e334b). Closes
  BB6 weakest-point. `apply_saml_idp_metadata` now extracts the
  trust-relevant fields (`idp_entity_id` + `sso_url` + `binding` +
  sorted signing-cert set) into a new `ParsedSamlMetadata` struct
  and persists a sha256 fingerprint over them in sso-saml.json.
  `sso refresh-saml` ticks compare the new fingerprint to the
  persisted one and skip the layout rewrite when they match. Sorted
  certs make the hash order-insensitive against IdPs that
  rearrange `<KeyDescriptor>` blocks; NUL separators between
  fields defeat concatenation collisions. Hash covers the EXTRACTED
  trust fields, not the raw XML — defeats timestamp / contact-info
  attribute churn some IdPs include on every fetch. 6 unit tests
  + live smoke `tests/cc4-saml-drift-detection-smoke.py` (five-step
  chain: configure-v1 → fingerprint persisted → refresh-on-v1 →
  "no drift, skipping layout rewrite" + pem mtime unchanged → flip
  to v2 → drift-triggered rewrite + post-rewrite fingerprint
  stable).
- **CC5 OIDC proactive access-token refresh** (commit 6e73b97).
  Closes BB5 weakest-point. `sso_login` + `sso_refresh` persist
  `expires_at = now + expires_in` to a new sidecar
  (`~/.aether/sso.access_token.expires_at`, mode 0600, RFC 3339
  UTC). `sso whoami` reads the sidecar before the userinfo call;
  if inside the AETHER_OIDC_REFRESH_LEAD_SECS window (default 300s,
  clamped [60, 3600]) AND the refresh sidecar exists AND
  `!no_refresh`, refreshes BEFORE the userinfo call. Pure
  `is_access_token_expiring(expires_at, now, lead)` helper +
  `oidc_refresh_lead_secs` env helper. `--no-refresh` opts out of
  BOTH proactive (CC5) and reactive (BB5). Malformed sidecar
  logged + skipped (falls through to BB5 reactive path). 4 unit
  tests + live smoke `tests/cc5-oidc-proactive-refresh-smoke.py`
  (four-step chain: expires_at sidecar at 0600 → outside-window
  skip → inside-window proactive refresh hits /token BEFORE
  /userinfo → --no-refresh opt-out). BB5 smoke pinned to lead=60s
  so its 300s expires_in stays outside the window and the BB5
  reactive path is exercised, not bypassed.
- **CC6 EdDSA AuthnRequest signing** (commit 963a0f5). Closes BB4
  weakest-point. New `SpSigningKey { Rsa, Ed25519 }` enum.
  `load_sp_signing_key_from_pem` tries Ed25519 PKCS#8 first
  (tightest discriminator — OID 1.3.101.112), then RSA PKCS#8,
  then RSA PKCS#1; garbage PEM bails citing all three formats.
  `sign_authn_request_xml` dispatches on the variant: RSA path
  unchanged (RSA-SHA256), Ed25519 path uses SignatureMethod URI
  `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519` (per
  draft-jones-eddsa-xml-signature) and signs the canonical
  SignedInfo BYTES directly — no separate hash. ed25519-dalek
  features bumped (`pkcs8` + `pem`) and added as a direct
  aether-cli dep (previously workspace-only). 3 BB4 tests
  migrated to wrap RSA keys in `SpSigningKey::Rsa(_)`; 3 new CC6
  tests (Ed25519 PEM load + EdDSA URI dispatch + end-to-end
  round-trip with `ed25519_dalek::Verifier`). Live smoke
  `tests/cc6-eddsa-authn-request-smoke.py` (five-step chain
  mirroring BB4 with Ed25519 key + Python `cryptography` Ed25519
  verify + Y3-Y7 IdP→SP regression).

**Honest UNVERIFIEDs carried forward to Plan DD:**
- CC1 Bedrock real AWS round-trip — no creds in env.
- CC2 Vertex real GCP round-trip — billing + Marketplace gates.
- CC3 Azure real round-trip — no Foundry resource.

13 new CC-prefix unit tests (6 CC4 + 4 CC5 + 3 CC6) + 3 new Python
fake-IdP smokes. 91/91 Y/Z/AA/BB/CC-prefix unit tests pass.

**Closure milestone:** every documented weakest-point from Plan AA
and Plan BB has now landed. The AA→BB→CC remediation chain:
  - AA4 unsigned AuthnRequest → BB4 RSA signing → CC6 EdDSA signing
  - AA5-followup discovery → BB6 refresh-saml → CC4 drift detection
  - AA6 no userinfo → BB5 reactive refresh → CC5 proactive refresh

## v0.34 — close every CC weakest-point — shipped 2026-06-27

Plan DD. 3 shipped + 3 cred-blocked carried forward. The shipped
trio closed the LAST documented weakest-points from Plan CC, which
themselves closed every Plan BB weakest-point, which closed every
Plan AA weakest-point. The full AA→BB→CC→DD remediation chain for
the enterprise SSO surface is now complete on three orthogonal
lanes (AuthnRequest signing + algorithm verification, SAML
metadata lifecycle, OIDC token refresh).

- **DD4 Y5 EdDSA assertion verifier** (commit d9b95b5). Closes
  CC6 weakest-point. CC6 made the SP signer Ed25519-aware on the
  AuthnRequest leg; DD4 makes the inbound Y5 verifier accept
  Ed25519-signed SAMLResponses on the IdP→SP leg. New `enum
  IdpVerifyingKey { Rsa, Ed25519 }`. `rsa_pubkey_from_pem_cert`
  renamed to `idp_verifying_key_from_pem_cert` with SPKI OID
  dispatch (1.2.840.113549.1.1.1 → RSA, 1.3.101.112 → Ed25519 per
  RFC 8410). `verify_saml_assertion_signature` algorithm gate
  accepts both URIs; per-key dispatch SKIPS wrong-algorithm keys
  to defend against confused-deputy where cert and sig
  algorithms diverge (risk-register requirement). 5 unit tests
  (happy path + 2 algorithm-mismatch defenses + algorithm-gate
  reject + SPKI byte round-trip) + live smoke
  `tests/dd4-ed25519-assertion-verify-smoke.py` runs the IdP→SP
  leg with an Ed25519-signed SAMLResponse through Y3-Y7
  end-to-end.
- **DD5 SAML metadata validUntil staleness check** (commit
  4a25cac). Closes CC4 follow-up gap. CC4's fingerprint covered
  the trust fields but not the metadata's `validUntil` attribute;
  an IdP that let metadata officially expire without rotating
  certs would still trigger "no drift". `ParsedSamlMetadata`
  gains `valid_until: Option<DateTime<Utc>>`. `parse_saml_metadata`
  extracts the attribute via regex + RFC 3339 parse. New env
  helper `saml_metadata_staleness_warn_secs` (default 86400s = 24h,
  clamped [3600, 2592000]) and pure helpers
  `is_metadata_expired` + `is_metadata_near_expiry`. `apply_saml_
  idp_metadata` bails on expired metadata BEFORE any filesystem
  mutation (defense-in-depth for configure-saml + refresh-saml
  rewrite paths). `sso_refresh_saml` tick: past → bail; near-
  expiry → WARN with remaining seconds; absent → advisory. 6
  unit tests + live smoke `tests/dd5-saml-validuntil-staleness-
  smoke.py` six-step chain covering far-future + near-expiry +
  past-expiry + no-validUntil + custom env knob.
- **DD6 OIDC system-clock-skew detection** (commit 9b29306).
  Closes CC5 weakest-point. CC5's proactive refresh trusted the
  local clock — broken NTP would defeat the window math. After
  every successful POST to /token, aether reads the HTTP `Date:`
  header, computes `local_now - server_date`, persists signed
  seconds to `~/.aether/sso.clock_skew_secs`. `sso whoami` reads
  the sidecar at the top and emits a WARN line when |skew|
  exceeds `AETHER_OIDC_CLOCK_SKEW_WARN_SECS` (default 60s,
  clamped [10, 3600]). Advisory only — whoami doesn't refuse.
  Pure helpers `parse_http_date` (RFC 7231 IMF-fixdate via
  chrono's RFC 2822 parser) + `compute_clock_skew_secs`. Recorder
  wired into both `sso_login` and `refresh_oauth_access_token`
  so every successful token exchange refreshes the skew. 3 unit
  tests + live smoke `tests/dd6-oidc-clock-skew-smoke.py`
  five-step chain (in-sync + server-past + server-future via
  manual refresh + custom env knob + logout cleanup). Caught
  mid-development: Python's http.server auto-adds its own `Date:`
  header in `send_response` which shadowed the fake's offset
  injection; fixed by overriding `date_time_string()` on the
  smoke's handler so the framework's emission carries the
  configured offset.

**Honest UNVERIFIEDs carried forward to Plan EE:**
- DD1 Bedrock real AWS round-trip — no creds in env. Fifth plan
  in a row carrying this forward.
- DD2 Vertex real GCP round-trip — billing + Marketplace gates.
- DD3 Azure real round-trip — no Foundry resource.

14 new DD-prefix unit tests (5 DD4 + 6 DD5 + 3 DD6) + 3 new
fake-IdP Python smokes. 105/105 Y/Z/AA/BB/CC/DD-prefix unit tests
pass. 14 SAML+OIDC live smokes all pass as regression.

**Closure-chain status — ALL THREE LANES NOW COMPLETE:**
- AA4 unsigned AuthnRequest → BB4 RSA sign → CC6 EdDSA sign →
  **DD4 EdDSA verify** ✓
- AA5-followup discovery → BB6 refresh-saml → CC4 drift detection →
  **DD5 validUntil staleness** ✓
- AA6 no userinfo → BB5 reactive refresh → CC5 proactive refresh →
  **DD6 clock-skew detection** ✓

## v0.35 — hygiene + close DD weakest-points — shipped 2026-06-27

Plan EE recalibrated after the AA→BB→CC→DD closure-chain landed in
DD: the "close every documented weakest-point" phase ended at DD, so
EE picked up the chronic four-plan deferrals (mTLS + SCIM), a CI
hygiene gate that closes the recurring STATUS-row placeholder
pattern, and two smaller DD weakest-point fillers. 3 shipped + 3
cred/scope-blocked carry-forward.

- **EE4 (5e89e8f) pre-tag CI placeholder check** — closes the chronic
  STATUS-row `(this commit)` pattern that hit six successive ships
  (Y7 / Z7 / AA7 / BB7 / CC7 / DD7), each needing a follow-up
  backfill commit. New `tests/check-status-no-placeholders.sh`:
  `set -euo pipefail` + `grep -Fn` so parentheses are literal not
  regex; exit 0 clean / 1 if placeholder present / 2 if STATUS.md
  missing. Escape hatch via `AETHER_SKIP_STATUS_PLACEHOLDER_CHECK=1`
  per risk register §EE4. Wired into release.yml as a new
  `prerelease-checks` job with `build: needs: prerelease-checks` so
  a tag push with a placeholder never even starts the 4-platform
  build. The script's first run on main caught a real historical
  Y-audit row placeholder that had never been backfilled (SHA
  `9d474b8`) — backfilled in the same commit.
- **EE5 (034e1f7) SAML metadata cacheDuration support** — closes the
  DD5 weakest-point. New pure helper `parse_xsd_duration_secs`
  accepts the subset of xsd:duration used by SAML cacheDuration
  (`P1D`, `PT1H`, `PT30M`, `PT1H30M`, `P1Y6M`, `P1DT12H`, etc.) with
  365d/30d year/month approximation. `ParsedSamlMetadata.
  cache_duration_secs: Option<u64>` extracted via regex from
  `<md:EntityDescriptor cacheDuration="…">` per saml-metadata-2.0
  §2.3.2 and persisted in sso-saml.json.
  `saml_metadata_refresh_interval_secs` now returns
  `(u64, &'static str)` — interval AND source ("env" / "cacheDuration"
  / "default"), refactored from two-decision into one so the watch
  banner can't lie about where the interval came from (caught
  mid-development by S5 of the smoke). Priority: env > hint > 3600s
  default; garbage env falls through to hint, NOT silently to
  default, so an IdP-stated value still wins over a typo.
- **EE6 (d4ed0ef) Ed448 SAML verify path** — closes the DD4 weakest-
  point. `IdpVerifyingKey::Ed448(ed448_goldilocks::VerifyingKey)`
  variant + OID `1.3.101.113` (id-Ed448 per RFC 8410) dispatch in
  `idp_verifying_key_from_pem_cert`. RFC 8410 §4 raw 57-byte BIT
  STRING SPKI shape (same as Ed25519 just with different length).
  New `SAML_SIG_METHOD_EDDSA_ED448` const for the xmldsig-more URI
  `eddsa-ed448`; algorithm gate now accepts all three URIs. Per-key
  dispatch arm verifies 114B signature via
  `ed448_goldilocks::VerifyingKey::verify_raw` (RFC 8032 §5.2
  PureEdDSA, same "no separate hash step" shape as Ed25519). Wrong-
  algorithm keys still SKIP per the DD4 risk register (confused-
  deputy defense). Crate: `ed448-goldilocks` v0.14.0-pre.15 from
  the RustCrypto org. Trust assumption: Ed448 is far less battle-
  tested than Ed25519 (audit gap per Plan EE risk register §EE6) —
  documented inline at the verify call-site.

**Cred/scope-blocked carry-forward to Plan FF:**

- **EE1 Bedrock LIVE round-trip** — seventh-plan cred-blocked.
  RETIRED by FF1 (2026-07-01): env vars + cred-acquisition
  checklists now live in `docs/byoc-setup.md`; the Z4/Z5/Z6
  fake-endpoint smokes remain the CI-enforced wire-format
  contract. Carry-forward list is now 2 (mTLS + SCIM).
- **EE2 OIDC mTLS client auth (RFC 8705)** — still deferred since
  Plan BB. Plan FF re-frames this as its main theme (mTLS-dedicated
  plan, mirroring Plan Y's SAML-dedicated approach).
- **EE3 Tenant SCIM** — still deferred since Plan BB. Re-queued
  for Plan GG or later as a similar dedicated-plan candidate.

**v0.35.0 ship metadata:** see Plan FF's STATUS row backfill + tag
v0.35.0.

## v0.36 — security-crate tiers 31-45 + mock→real sweep — shipped 2026-07-01

Shipped OUTSIDE the plan-letter cadence as an autonomous tiers build
(run 28548024257 green, release published + cosign-verified):

- 14 new production crates (aether-deps-reach / taint / triage /
  patch / ebpf / netwatch / drift / semgrep-gen / explain / baseline
  / pr-bot / policy / report / license) wired into aether-cli; 115
  new tests. Live-verified: `aether license` (58 packages) and
  `aether taint` (5 CWE flows).
- Post-tag commit cfc2673: mock threat-intel feeds → real
  VirusTotal/URLHaus/ThreatFox/Shodan/CIRCL APIs; fake TPM
  attestation → real tpm2-tools invocation (ships in v0.37).

## v0.37 — dedicated OIDC mTLS plan (Plan FF) — shipped 2026-07-01

Plan FF re-frames as a dedicated **OIDC mTLS plan** (mirroring Plan
Y's dedicated-SAML approach that successfully landed the full SAML
pipeline in one 24h budget). One main theme + small filler.
Shipped-as-built notes: FF3 uses rustls `Identity::from_pem`
(key+cert one buffer) — `from_pkcs8_pem` is a native-tls-only API
and this workspace pins rustls; there is no introspection endpoint
in the codebase (the draft's mention was aspirational), so the two
wired POST paths are token exchange + refresh grant (×3 call
sites). New env knobs: `AETHER_OIDC_REQUIRE_CNF_X5T_S256=1`
(advisory→hard cnf binding), `AETHER_OIDC_EXTRA_ROOT_CA_PEM`
(private-CA trust without disabling verification). FF7's fix is a
pre-flight sanitize-or-refuse pairing guard in agent_turn_inner —
production self-heals (drop orphan tool_results / synthesize
missing ones, stderr WARN per repair), `AETHER_DEBUG=1` hard-fails
via the new `AgentError::Internal`. See STATUS FF1–FF8 rows for
per-slice live-verify evidence.

- **FF1 BYOC carry-forward retirement** — six plans of Bedrock+Vertex+
  Azure deferral is enough. Document the env vars + the
  cred-acquisition path in `docs/byoc-setup.md` and remove from the
  carry-forward list. The fake-endpoint smokes (Z4/Z5/Z6) stay; real
  live-call work returns when an operator with creds arrives.
- **FF2 `aether sso configure-mtls`** — new subcommand. `--cert <pem>
  + --key <pem>` paths persist in sso.json under a new `mtls`
  block. Loader reads cert+key into memory at every token POST
  invocation time (atomic-rename convention — risk register §EE2).
- **FF3 reqwest client mTLS wiring** — modify the shared reqwest
  client in `sso_login` + `refresh_oauth_access_token` to load the
  cert+key via `Identity::from_pkcs8_pem` when the `mtls` block is
  present in sso.json. Same path for token endpoint and
  introspection. No state-machine changes — mTLS is layered on top
  of the existing OIDC PKCE flow.
- **FF4 `cnf.x5t#S256` claim verification** — optional id_token
  claim binding per RFC 8705 §3.1. When the client presented a cert
  on the token endpoint, the issued id_token can carry a
  `cnf.x5t#S256` claim with the SHA-256 fingerprint of the leaf
  cert. Verify it matches the configured cert; reject if it
  doesn't.
- **FF5 live smoke** — fake IdP that REJECTS token endpoint calls
  without a client cert; aether's configured cert is required for
  success. End-to-end chain: configure-mtls → sso login → token
  POST carries cert → id_token verifies → optional cnf claim
  matches.
- **FF6 Ed448 stable bump (if available)** — `ed448-goldilocks`
  v0.14.0-pre.15 → v0.14.0 stable when the RustCrypto org cuts
  it. Otherwise add a one-line note in the trust-assumption comment
  pointing at the audit-gap risk register. Documentation-only if
  no stable bump exists.
- **FF7 parallel sub-agent orchestration fix** — HIGH, filed
  against `docs/bugs/orchestration-tool-use-id-mismatch.md` from a
  2026-06-27 real-user session (Frank/CEO auditing sudo-ai-v4). When
  parallel sub-agents are dispatched and one exhausts turn budget /
  errors out, the orchestrator emits `tool_result` blocks whose
  `tool_use_id` references INTERNAL sub-agent ids that never made
  it into the parent thread → Anthropic HTTP 400 → REPL main loop
  wedges silently. Three changes: pre-flight pairing check before
  every API call (debug-gated), sub-agent result mapping (parent
  dispatch id, not internal), balanced tool_result on every
  termination path. Live smoke reruns the failing audit in REPL
  mode against the same codebase.
- **FF8 wrap-up** — version bump + ROADMAP + STATUS + Plan GG draft
  + tag + ship. The pre-tag placeholder check (EE4) gates this.

## v0.38 — daily-driver readiness gauntlet — shipped 2026-07-02

User directive: "continue fully autonomous until you're fully
satisfied Aether is ready for regular use like Claude Code." Rather
than more enterprise plumbing (SCIM stayed queued as Plan GG), this
plan ran Aether's own 18-task real-coding benchmark plus a set of
manual REPL lifecycle probes against the v0.37.0 binary and fixed
every real gap found.

- **Coding-eval baseline**: `aether coding-eval eval/coding/suite.yaml`
  — 18/18 passed (Python/Rust/JS/Go/TS/SQL/Bash/Docker/Java), 589s
  agent wall, ~$2.21 total. No regressions to fix here — recorded as
  the readiness floor.
- **G1 — assumption-first law**: told to "fix it yourself until it
  runs" against an ambiguous-but-reversible failure (a script
  importing a genuinely nonexistent module), the agent diagnosed
  correctly but then STOPPED and asked the user to pick between 3
  options instead of acting. New ASSUMPTION-FIRST LAW in
  KERNEL_SYSTEM_PROMPT: pick the reasonable default and act, label it
  ASSUMED, only ask first when a wrong guess destroys data / costs
  money / touches prod. Live-reverified post-fix: same scenario now
  gets a working shim + a labeled assumption instead of a stall.
- **G2 — compaction EVIDENCE section**: after `/compact`, the agent
  under-reported its own verified work (claimed "never verified with
  a tool call" for something it HAD verified pre-compaction). The
  6-section compaction summary_prompt gains a 7th EVIDENCE section
  listing which claims were verified by which tool calls.
- **G3 — resume tool-history reconstruction (the real bug)**: found
  while testing G2 — `load_session_history` only replayed `user` and
  `assistant` records, silently dropping every `tool_use`/
  `tool_result`. A resumed session had ZERO memory of tool calls the
  original session made. Manually confirmed: resuming and asking
  "did you verify X with a tool call" got a false "no tool calls in
  this session" for a session that had run the exact verifying
  command. Fixed by reconstructing `tool_use` (attached to the
  preceding Assistant, or a synthesized carrier) and `tool_result`
  (coalesced into the following ToolResults) on load, plus dropping
  a trailing unanswered Assistant so resume starts from a balanced
  boundary. Live-reverified: resumed session correctly recalled exact
  tool names + arguments + results, including the distinction between
  "read source" and "executed and observed" — the precise nuance the
  bug used to erase. 2 new tests (full-turn reconstruction, dangling
  tool_use dropped).
- Tests: aether-core 65+14, aether-cli 155 — all pass (was 153; +2
  for G3).

## v0.39 — SCIM 2.0 provisioning (Plan GG) — shipped 2026-07-02

Dedicated SCIM plan (mirroring Plan Y's SAML and Plan FF's mTLS
dedicated-plan pattern). Closes EE3, the sole carry-forward left
after Plan FF — deferred since Plan BB.

- **GG1 routes**: `GET/POST /scim/v2/Users`, `PATCH/DELETE
  /scim/v2/Users/:id`, `GET /scim/v2/Groups` (read-only — tenant
  slugs rendered as SCIM Groups, membership managed only via the
  Users resource). axum gained the `query` feature for `?filter`.
- **GG2 dedicated bearer**: new `~/.aether/scim.json`
  (`aether scim configure/status/remove`) checked by
  `check_scim_bearer` — a store and function entirely separate from
  `tenants.json`/`check_tenant_acl`. Absent config is 501, not an
  ambiguous 401/403. All SCIM error bodies use the RFC 7644 §3.12
  shape.
- **GG3 lifecycle → ACL mapping**: shipped-as-built deviates from the
  original draft's implicit username/password model — aether's ACL
  is bearer-token identity, so POST carries the IdP-provisioned
  bearer in a new `urn:ietf:params:scim:schemas:extension:aether:1.0:User`
  attribute (`{bearer, tenant, global}`); `userName` is a human label
  used only for filter/display. New `TenantAclRow.active` field
  (default true, back-compat via serde default) is enforced by
  `check_tenant_acl` on every gated route — a SCIM
  `PATCH .../active false` locks the bearer out of `/v1/messages`
  and `/v1/trust` immediately, not just SCIM's own routes. DELETE
  removes the row outright. Every mutation appends to
  `~/.aether/scim_audit.jsonl` (0600).
- **GG4 filter**: minimal RFC 7644 §3.4.2.2 `userName eq "..."`
  subset; any other operator or attribute is a 400 citing the
  supported subset (never a silent empty result).
- **GG5 live smoke**: `tests/gg5-scim-smoke.py` drives a real
  `aether serve` instance through the full lifecycle — unauthed
  POST → 401; create → 201 + on-disk `tenants.json` row confirmed;
  filter lookup; Groups membership; privilege separation (the
  just-created tenant bearer rejected by `/scim/v2/Users`, 401);
  deactivate → on-disk `active=false` + unsupported PATCH op → 501;
  delete → on-disk row gone + repeat delete → 404; audit trail
  `[create, deactivate, delete]`. All 10 steps LIVE-VERIFIED.
- 9 unit tests (filter parser × 5, User-resource shape × 2, GG2
  privilege separation, GG3 deactivation lockout). aether-core
  65+14, aether-cli 164 pass (was 155).

## v0.40 — real distributed scanning (Plan HH-A) — shipped 2026-07-02

User directive (2026-07-02, still standing): "100 times better than
Claude Code, ready for regular use, don't stop until fully
satisfied." With Plan GG closing the last cred-blocked carry-forward,
HH-A tackled the other kind of debt: a completely disconnected stub
crate.

- **Real multi-process fan-out**: pre-HH-A, `aether-distrib` was an
  18-line stub with NO callers anywhere in the workspace — the
  `aether distributed` CLI command printed hardcoded
  "Peers: (connecting...)" with zero connection to the crate. Now
  `aether distributed --target <dir> [--workers N] [--json]` shards
  a directory's files round-robin across N REAL child OS processes
  (each re-execs `current_exe distributed --worker`, piped
  stdin/stdout), each running the existing `aether-secrets::scan_file`
  primitive, aggregated by the coordinator. Per the risk register:
  `tokio::spawn`/thread concurrency would NOT have closed this gap —
  this codebase already has plenty of that; "distributed" had to mean
  distinct OS-level PIDs, which the integration test asserts directly.
- **Critical perf bug found + fixed as a byproduct of testing it for
  real**: the live smoke against a real ~200-file target hung a
  worker at high CPU. Root cause: `aether-secrets::rules()` rebuilt
  and recompiled ~30 regexes on EVERY call, and `scan_line` calls it
  once per LINE — scanning aether-cli's own 70K-line `main.rs`
  recompiled the whole ruleset ~70,000 times. Fixed with a
  `Lazy<Vec<...>>` static (same pattern already used for
  `ALLOWLIST_PATTERNS` in the same file, just never applied to the
  rule table). `main.rs` now scans in ~70ms — was hanging for
  minutes. This bug had been latent since aether-secrets shipped;
  nobody had pointed a full-content scan at a file that large before.
- **Latent test-isolation flake fixed**: `cargo test --workspace`
  under full parallelism surfaced a race — 11 test functions (this
  session's FF2/G3/GG additions plus some pre-existing ones) mutate
  the global `HOME` env var with no synchronization. Added a shared
  mutex so they serialize. Confirmed clean across 3 consecutive full
  workspace runs (0 failures, 772 tests).
- Tests: 4 aether-distrib unit tests + 1 integration test (spawns a
  real separate `fake_worker` binary, asserts distinct PIDs) + 1
  aether-secrets perf-regression guard (20K-line synthetic scan must
  complete under 2s). Live smoke `tests/hh-a-distributed-smoke.sh`:
  6 workers → 6 distinct real PIDs against a 198-file target,
  0.25s wall time; `--workers 1` edge case; legacy `--node`
  back-compat path.
- Also ran a second readiness-gauntlet round (HH-C, no ship needed):
  live REPL multi-file refactor, git commit workflow (with the
  correct `--permission-mode bypassPermissions` flag), and a
  long-running background task — all three passed clean on the
  v0.39.0 binary. Two apparent failures during testing turned out to
  be test-methodology mistakes (a git-fixture set up post-refactor,
  and a missing bypass flag for a piped non-interactive session), not
  product defects — both correctly-refused-to-fabricate and
  correctly-denied-on-no-answer behaviors were the RIGHT call.

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
