# aether-blueprint — autonomous run log

This file is the resumable session log for the 24h autonomous plan
(A1 → C3). One line per slice. Newest at the bottom. Restart-safe.

## Plan reference

- Phase A — v0.7.3 security hardening (4 slices, ~6h)
- Phase B — v0.8.0 BYOC streaming + creds (5 slices + bump, ~12h)
- Phase C — buffer + harden (3 slices, ~4h)

DONE MEANS (all five):
1. v0.7.3 + v0.8.0 tags on origin/main at Matrixx0070/aether-blueprint
2. security-eval --runs 3 ≥ 95% per-fixture pass rate on ≥22 fixtures
3. cargo test --workspace --release exit 0 at each tag boundary
4. Bedrock + Vertex streaming live-verified or UNVERIFIED-labelled honestly
5. STATUS.md complete one-line-per-slice log (this file)

Banned vocabulary: "should work" / "probably" / "likely fixed" / "seems fine".
Every "works" claim cites command + exit code or output excerpt.

## Slice log

format: `[slice] [status] [commit] [verifier] [live-check] note`
- status ∈ {DONE, UNVERIFIED, BRANCHED, BLOCKED}
- verifier ∈ {SHIP, SHIP+LOW, SHIP+MED, FIXED-IN-COMMIT, n/a}
- live-check is the literal exit-code + output excerpt, not a claim

| Slice | Status | Commit | Verifier | Live check | Note |
|-------|--------|--------|----------|------------|------|
| A1 | DONE | dc4db46 | n/a | exit 0 · 23/23 passed | 7 gap-fill fixtures; autoroute fired once; Sonnet 4.6 |
| A2 | DONE | 18408a2 | n/a | 15/15 tests passing | `--runs N --threshold P`; 4 new unit tests |
| A3 | DONE | a04e340 | n/a | exit 0 · 23/23 @ threshold 1.0 × 3 runs | 0 flaky fixtures; per-fixture median/min/max in BENCHMARK.md |
| A4 | DONE | 535ab5b | n/a | exit 0 · pushed origin/main · tag v0.7.3 live | Bump 0.7.3, docs, tag, push |
| B1 | DONE/UNVERIFIED | (bedrock.rs rewrite) | n/a | build exit 0 · no AWS creds in env | Bedrock streaming: event-stream binary parser, SigV4 signing |
| B2 | DONE/UNVERIFIED | (vertex.rs rewrite) | n/a | build exit 0 · no GCP creds in env | Vertex streaming: SSE `:streamRawPredict` parser |
| B3 | DONE/UNVERIFIED | (bedrock.rs cred chain) | n/a | build exit 0 · no IMDS in env | AWS cred provider chain: env→credentials file→IMDSv2→ECS |
| B4 | DONE/UNVERIFIED | (vertex.rs JWT refresh) | n/a | build exit 0 · no GCP SA JSON in env | GCP SA JSON → RS256 JWT → Bearer, auto-refresh 5min buffer |
| B5 | DONE | 825ae5a | SHIP | 18/18 tests · `--provider` in --help | Cross-provider sweep; `build_named_provider`; 3 new tests |
| B6 | DONE | f89605e | n/a | exit 0 · pushed origin/main · tag v0.8.0 live | Bump 0.8.0, docs, tag, push |
| C1 | DONE | n/a | n/a | release build exit 0 · `--provider` in --help | Regression: binary at v0.8.0 compiles clean, help correct |
| D1 | DONE | d5d010c | n/a | exit 0 · workspace tests green | Print mode streaming + AETHER_NO_STREAM kill-switch |
| D2 | DONE | 651b302 | n/a | exit 0 · 24/24 aether-cli (+5) | 5 cost-estimator tests (cost calc + /usage cmd existed already) |
| D3 | DONE | 76c125e | n/a | exit 0 · 28/28 aether-core (+8) | Context compaction at 80% window + AETHER_NO_COMPACT + 8 tests |
| D4 | DONE | fe36c89,1fb51cd | n/a | exit 0 · 33/33 aether-core (+5) | Parallel safe-tool execution + AETHER_NO_PARALLEL_TOOLS + 5 tests |
| D5 | DONE | 01f9e83 | n/a | exit 0 · pushed · tag v0.9.0 live | Bump 0.9.0, docs, tag, push |
| E1 | DONE | 602fad9 | n/a | exit 0 · 2 MED closed | ENV_TEST_LOCK coverage gap + compaction fail-soft |
| F1 | DONE | af8ed8a | n/a | 4/4 azure tests · 57 aether-llm total | Azure Foundry provider (UNVERIFIED — no Azure creds) |
| F2 | DONE | 55ddff3 | n/a | 7/7 retry tests · workspace green | Unified retry watchdog + AETHER_NO_RETRY |
| F3 | DONE | 3d432bf | n/a | doctor --help shows --probe · workspace green | aether doctor --probe (latency + token counts) |
| F4 | DONE | b52373f | n/a | exit 0 · pushed · tag v0.10.0 live | Bump 0.10.0, docs, tag, push |
| F5 | DONE | 20ce322 | n/a | exit 0 · 1 MED closed (Azure env-lock) | Self-audit + lock-gap fix |
| G1 | DONE | c14455b | n/a | -43 LoC in anthropic.rs · workspace green | Stripped anthropic-internal retry (F2 follow-up) |
| G2 | DONE | 2b5ec01 | n/a | 8/8 aether-mcp (+4) · workspace green | MCP WebSocket transport (UNVERIFIED for live ws://) |
| G3 | DONE | 878b034 | n/a | --json + text output verified · workspace green | aether doctor --json for CI consumers |
| G4 | DONE | c2e4583 | n/a | exit 0 · pushed · tag v0.11.0 live | Bump 0.11.0, docs, tag, push |
| G5 | DONE | n/a | n/a | self-audit · 0 BLOCKER/HIGH/MED · 4 LOW noted | Self-audit on G1-G3 |
| H1 | DONE | 26c184a | n/a | YAML valid · LICENSE files added | GitHub Actions release workflow (4 platforms) |
| H2 | DONE | 639105f | n/a | bash -n OK · platform-detect OK | install.sh (one-liner with checksum verify) |
| H3 | DONE | 9fee0e8 | n/a | README + INSTALL.md authored | Install docs (one-liner + manual + source-build) |
| H4 | DONE | f477508,743632a | n/a | release v0.12.0 LIVE · 4 platforms · single Apache LICENSE | Apache-only ship + private-repo install caveat |
| H5 | DONE | n/a | n/a | end-to-end verified · `./aether --version` prints `aether 0.12.0` | binary install + sha256 + ./aether --version |
| I1 | DONE | df4b34d | n/a | 5/5 verify.sh scripts fail on starting state | 5 coding-task fixtures + suite.yaml |
| I2 | DONE | 6fdbbd3 | n/a | `aether coding-eval --help` lists options | coding-eval command + verify harness |
| I3 | DONE | 7083bea | n/a | **5/5 PASS · 184s · $0.58 on Sonnet 4.6** | live benchmark run |
| I4 | DONE | 7083bea | n/a | RESULTS.md + COMPARISON.md authored | honest comparison vs Claude Code |
| I5 | DONE | dcb9f6f | n/a | v0.13.0 binary release LIVE on GitHub (4 platforms) | bump 0.13.0 + tag autotrigger working |
| I6 | DONE | d11aa9d | n/a | stability 5/5 + 5/5 = 10/10 cumulative | 2nd run verification |
| J1 | DONE | 4a21b62 | n/a | 5 new verify.sh scripts fail on starting state | Rust + JS + SQL + multi-file + perf tasks |
| J2 | DONE | 53637bf | n/a | **10/10 PASS · 388s · $1.12 on Sonnet 4.6** | live multi-language run |
| J3 | DONE | 53637bf | n/a | RESULTS.md v2 + COMPARISON.md updated | cross-language proof |
| J4 | DONE | 8cfab9d | n/a | exit 0 · v0.14.0 binary release LIVE on 4 platforms | bump 0.14.0 + ./aether --version 0.14.0 confirmed |
| K1 | DONE | 32d27a3 | n/a | task 4 now reports $0.25 (was $0.00) | [aether-usage] emits even when agent_turn errors |
| K2 | DONE | 365aaed | n/a | 5/5 new verify.sh fail on starting state | suite v3: Go/TS/Bash/Docker/Java |
| K3-K6 | DONE | bcdab8e | n/a | **30/30 cumulative across 2 runs · $4.63 total** | stability + verify-bug class closed |
| K10 | DONE | e8347cd | n/a | v0.15.0 binary release LIVE (4 platforms) | bump 0.15.0 |
| K11-12 | DONE | 60fd992 | n/a | STRUCTURAL_ADVANTAGES.md with file:line citations | 9-category catalogue vs CC |
| K13 | DONE | 469212f | n/a | zero workspace warnings (was 2) | dead-code cleanup |
| L1 | DONE | 0461332 | n/a | live ws://127.0.0.1:7779/ws/chat → Pong, $0.0025 | WebSocket chat endpoint |
| L2 | DONE | (commit) | n/a | tsc -p . clean, 211-line extension.js | VS Code skeleton |
| L3 | DONE | 8bbdf9e | n/a | **3/3 PASS, $0.61, agent committed+rationaled** | 3 multi-turn design-decision tasks |
| L4 | DONE | (commit) | n/a | 4/4 plugin tests + live end-to-end echo | subprocess plugin loader |
| L5 | DONE | ccab63a | n/a | v0.16.0 binary release LIVE on 4 platforms | bump 0.16.0 |
| L6 | DONE | 03f4f89 | n/a | 0 BLOCKER/HIGH · 2 MED (auth + plugin signing → Plan M) | self-audit + Plan M draft |
| CI-fix | DONE | 9bdb7b7 | n/a | linux-aarch64 cross-compile via apt toolchain (was: cross/Docker fallback) | release workflow fix |
| M1 | DONE | (next) | n/a | wasmtime workspace compile + 47KB example .wasm built | WASM-sandboxed plugin loader |
| M2 | DONE | (next) | n/a | editor/wasm-plugin-example/ ready (50 LoC Rust → wasm32-wasip1) | example WASM plugin |
| M3 | DONE | 52c2a4d | n/a | constant-time bearer compare + 401 on mismatch | /ws/chat bearer auth |
| M4 | DONE | 52c2a4d | n/a | tsc clean: extension.js 8KB + panel.js 11KB | VS Code multi-turn webview |
| M5 | DONE | 0b83a7a | n/a | 7/7 aether-plugin tests (+3 HMAC: round-trip / tamper / unsigned) | plugin HMAC signing + CLI |
| M5-fix | DONE | ba822da | n/a | live: WASM-manifest verify passed | runtime-agnostic plugin verify |
| M6 | DONE | d45b0e4,d3f4… | n/a | v0.17.0 binary release LIVE (4 platforms, $0.0025 test cost) | bump 0.17.0 |
| N1 | DONE | 1495bb8,8cabdce | n/a | 11/11 aether-plugin tests (+4 ed25519) · live keypair + sign + verify + tamper + cross-keypair | ed25519 asymmetric plugin signing |
| N2-N5 | DONE | af17fd4 | n/a | workspace tests green; live rate-limit/policy/tail verification pending v0.18 binary | rate limit + audit syslog + audit tail + policy file + session cap |
| N6+N7 | DONE | 8399387 | n/a | v0.18.0 workspace bump · Plan O drafted | bump 0.18.0, docs refresh, Plan O draft |
| O1+O2 | DONE | ae5df73 | n/a | 36/36 aether-core (+4 policy_blocklist tests) | executor enforces policy tool-blocklist + token cap primitive |
| O2+O3 | DONE | 89ccb2e | n/a | live: `aether usage --days 7 --by-model` → 1 row · in=3332 out=5 $0.0027 | apply_policy_to_session + aether usage SQLite dashboard |
| O4+O5 | DONE | 29b1fbf | n/a | live: wrong-key keychain rejects ed25519 plugin · right-key loads (TrustTest) | inotify audit tail (notify crate) + plugin trust keychain |
| O6+O7 | DONE | 21da008,bfdc79f | n/a | v0.19.0 release LIVE (4 platforms, run 28220631082, SHA256SUMS OK, ./aether --version 0.19.0) | v0.19.0 ship + Plan P draft |
| P1 | DONE | d6a0ef3 | n/a | UNVERIFIED build chain (no JDK21+gradle in env); scaffold structurally complete | JetBrains plugin scaffold (Kotlin, IntelliJ Platform 2024.3) |
| P2 | DONE | 2ebb946 | n/a | 5/5 mantle tests · `--provider mantle` lists in error · `mantle` provider builds | Mantle BYOC provider (Anthropic-compatible) |
| P3 | DONE | 712ddbe | n/a | aether-0.20.0.vsix built (9 files, 18.65 KB, LICENSE bundled) | VS Code marketplace prep (metadata + bundled LICENSE) |
| P4 | DONE | dd14915 | n/a | live: 6 trust-route paths + bearer 401 + correct 200 verified via curl | /v1/trust routes + VS Code trust panel |
| P5 | DONE | 9220af3 | n/a | live: WS probe → tool_use:1 + Edit input visible + /tmp/p5-ws.txt edited | inline tool-use diff in VS Code chat panel |
| P6 | DONE | 43dbf51 | n/a | live: --csv, --tail (live row capture), AETHER_COST_CEILING_USD warn all verified | usage --csv / --tail / cost ceiling |
| P7 | DONE | 836df9c | n/a | v0.20.0 release LIVE (4 platforms, run 28224477135, SHA256SUMS OK, ./aether --version 0.20.0) | v0.20.0 ship + Plan Q draft |
| Q2 | DONE | 0f794de | n/a | live: WS probe → per-tool tool_use frame with original_contents="old marker\n" + did_not_exist=true on Write | per-tool WS streaming + pre-state capture |
| Q1 | DONE | 891dd7e | n/a | live: 5 rollback paths verified (restored / removed / 400 abs-path / 400 missing-original / 200 idempotent-absent) | Accept/Reject UI + /v1/rollback |
| Q3 | DONE/UNVERIFIED | n/a | smoke OK: no-creds → "no AWS credentials found" (no panic) | Bedrock streaming UNVERIFIED in this env; live-verify pending operator AWS creds |
| Q4 | DONE/UNVERIFIED | n/a | scaffold structurally complete (P1); no JDK21+gradle in env | JetBrains build UNVERIFIED; live-verify pending JDK21+gradle host |
| Q5 | DONE/UNVERIFIED | n/a | smoke OK: no-creds → "MANTLE_API_KEY not set" (no panic) | Mantle cross-provider sweep UNVERIFIED; live-verify pending operator Mantle creds |
| Q6 | DONE | 853685c | n/a | YAML valid; OIDC sign-blob path runs only on GHA — live-verify pending tag push | cosign-keyless sign SHA256SUMS in release workflow |
| Q7 | DONE | 89bf565 | n/a | v0.21.0 release LIVE on 4 platforms; cosign verify-blob → "Verified OK" against published SHA256SUMS | v0.21.0 ship + Plan R draft + cosign live-proof |
| R4 | DONE | eb57ae7 | n/a | live: discovery against Google → sso.json mode 0600; AETHER_REQUIRE_SSO=1 blocks print mode | SSO scaffolding (OIDC discovery + PKCE auth-code login) |
| R5 | DONE | de2a60f | n/a | live: --enforce-commit-pinned rejects missing field; tamper-after-sign → ed25519 verify fail | plugin manifest commit_sha + --enforce-commit-pinned |
| R6 | DONE | d5b1273 | n/a | live: tenant=acme/beta keychains isolated; path traversal 400'd; v1→v2 ALTER TABLE migration confirmed | multi-tenant aether serve + usage.db schema v2 |
| R1 | DONE/UNVERIFIED | n/a | smoke OK from Q3; full live verify still pending operator AWS creds | Bedrock streaming live verify (carried from Q3) |
| R2 | DONE/UNVERIFIED | n/a | scaffold validated from P1; build still pending JDK21+gradle host | JetBrains build live verify (carried from Q4) |
| R3 | DONE/UNVERIFIED | n/a | smoke OK from Q5; full live sweep still pending operator Mantle creds | Mantle cross-provider security-eval matrix (carried from Q5) |
| R7 | DONE | 267ed43 | n/a | v0.22.0 release LIVE (4 platforms, run 28265454848); cosign verify-blob → "Verified OK"; sha256sum -c → OK | v0.22.0 ship + Plan S draft + cosign live-verify |
| S2 | DONE | 5188b92 | n/a | build clean; jsonwebtoken@9 in scope; RS256+ES256 accepted, iss+aud+exp validated | JWT signature validation in `aether sso login` |
| S1 | DONE | 0d4c034 | n/a | 7 live cases: alpha+acme/beta/charlie/none + bravo+acme/beta/none → 200/200/403/200/200/403/403 | tenant ACL (bearer-sha256 ↔ allowed-tenants) |
| S3 | DONE | 1b6fd21 | n/a | live: Edit (0ms) + Bash (312ms) rows in tool_calls; `aether usage --by-tool` shows real columns | tool_calls table writers (per-tool latency + is_error) |
| S4 | DONE | e6373bd | n/a | 5 live cases: real-local-OK, fake-local-FAIL, unpushed-URL-FAIL, pushed-URL-OK, missing-field-FAIL | `aether plugin verify --resolve-commit <repo>` |
| S5 | DONE | b16e552 | n/a | live SSE: `def fibonacci(n)...` → `fibonacci(n-1)+fibonacci(n-2)` streamed in 2 deltas + done frame ($0.0002) | POST /v1/complete SSE code-completion endpoint |
| S6 | DONE | 2fdcaee | n/a | 4 live cases: pull-merges-2-keys, push-confirmed-by-fresh-clone, idempotent-noop-on-second-push, local-bare-remote works | `aether plugin trust sync --remote <git-url> [--push]` |
| S7 | DONE | 8532ab0 | n/a | v0.23.0 release LIVE on 4 platforms; cosign verify-blob → "Verified OK"; sha256sum -c → OK | v0.23.0 ship + Plan T draft + cosign live-verify |
| T4 | DONE | 320e005 | n/a | 3 live language probes (Python/Rust/TypeScript), template literal preserved after fence-detection fix | /v1/complete server-side fence-strip |
| T1 | DONE | 27af402 | n/a | build clean + accepted-set message updated to (RS256, ES256, EdDSA); JWK kty=OKP/crv=Ed25519 parsing wired | EdDSA in `aether sso login` JWT validation |
| T3 | DONE | 8ae397b | n/a | 4 live cases: unsigned-local FAIL, pushed-URL refused-by-helper, missing --resolve-commit clap-rejected | `plugin verify --require-signed-commit` |
| T5 | DONE | a1eb994 | n/a | 4 live cases: --remove-from-team without/with --push round-trip + non-matching prefix error | `trust sync --remove-from-team <hex>` |
| T2 | DONE | 40a608a | n/a | live: 2 Edits (13ms, 2ms) + 1 Bash (81ms) — no aliasing under per-tool_use_id keying | per-tool_use_id keying in tool_calls |
| T6 | DONE/UNVERIFIED | n/a | R1 Bedrock streaming, R2 JetBrains build, R3 Mantle sweep all carry forward — no operator AWS/JDK21/Mantle inputs supplied this run | R1/R2/R3 cred-blocked verifiers carried to Plan U |
| T7 | DONE | a018deb | n/a | v0.24.0 release LIVE (4 platforms, run 28270037477); cosign verify-blob → "Verified OK" against published artifact | v0.24.0 ship + Plan U draft + cosign live-verify |
| U4 | DONE | 4217c06 | n/a | tests/u4-signed-commit.sh: gpg key + signed commit + ed25519 manifest → "carries a valid signature" + exit 0 | signed-commit success-path integration test (closes T3 LOW) |
| U5 | DONE | 8abb89a | n/a | 2 back-to-back /v1/complete requests: req1=1.647s, req2=1.408s (~240ms saved on pool hit) | /v1/complete provider pool (closes S7 LOW) |
| U3 | DONE | d251d29 | n/a | trust audit --remote: 3 keys shown with distinct SHAs + dates (53cc4ec/81abd45/cae68f1); CAUGHT-FIX --diff-filter=A→pickaxe | aether plugin trust audit (key age + git-log provenance) |
| U1 | DONE | b6cacc0 | n/a | /metrics exposes 8 counters; live: turns=2, complete=2, rollback=1, 4xx=1 after live traffic | Prometheus /metrics endpoint |
| U2 | DONE | 991d854 | n/a | configure/list/test fired 2 webhooks; HMAC over body byte-perfect match (a722e89958cb...) | webhook notifications (HMAC-SHA256 signed POST) |
| U6 | DONE | 21ba787 | n/a | configure-saml: spec-conforming metadata → sso-saml.json with IdP+SP+SSO+cert; DOCTYPE/ENTITY metadata → XXE-bait refused | SAML scaffolding (alt-path to OIDC) |
| U7 | DONE | 06f0669 | n/a | v0.25.0 release LIVE on 4 platforms (run 28271620497); cosign verify-blob → "Verified OK" against published artifact | v0.25.0 ship + Plan V draft + cosign live-verify |
| V3 | DONE | dd21264 | n/a | /metrics: histogram fired le="5000"=1 / count=1 / sum=3071ms; rename to aether_tool_call_duration_ms_sum confirmed | labelled Prometheus metrics + histogram + rename |
| V2 | DONE | 1370e41 | n/a | python receiver: 3 events fired live (trust-add{key,tenant,path} / trust-remove{prefix,counts} / sso-token-rotate{action:logout}) | webhook coverage for trust-add/remove + sso-rotate |
| V6 | DONE | 875ba19 | n/a | reload-pool: req1=3.0s build, req2=2.4s pool-hit, req3=5.3s rebuild after reload (pool cleared) | provider pool TTL + POST /admin/reload-pool |
| V5 | DONE | 465d191 | n/a | rpm_cap=3 against 5 reqs → first 3 HTTP 200, last 2 HTTP 429 "tenant rpm_cap exceeded" | tenant quota (rpm_cap + daily_cost_usd_cap) |
| V4 | DONE | 9270464 | n/a | vault: scheme resolved bearer "vault-resolved-bearer-XYZ"; 401 without bearer / 200 with resolved bearer; aws scheme returns informative error | secrets manager (vault path + aws stub) |
| V1 | DONE | d10e51b | n/a | SAML scaffold present → detection + informative refusal; scaffold absent → routes to OIDC | SAML login routing (full flow deferred to Plan W) |
| V7 | DONE | 3ab3727 | n/a | v0.26.0 release LIVE (4 platforms, run 28272975315); cosign verify-blob → "Verified OK" against published artifact | v0.26.0 ship + Plan W draft + cosign live-verify |
| W4 | DONE | 69cf598 | n/a | 4 live cases: refuse / allow / warn / invalid-regex; agent reported policy refusal back to user | per-tool argument-filter policy on policy.json |
| W6 | DONE | 6c0b3c0 | n/a | broken plugin manifest → discover_plugins_with_diagnostics → fire_webhook → POST /plugin-fail with reason+manifest_path | plugin-load-failure webhook (closes V2 NON-GOAL) |
| W5 | DONE | 327e49a | n/a | 12 audit entries → 2 Loki POSTs (batch of 10 + flush of 2); body shape valid {streams:[{stream,values}]} | audit-log forwarding to SIEM (loki/splunk HEC) |
| W3 | DONE | 87e0b03 | n/a | fake SM endpoint validated SigV4 + X-Amz-Target; resolved bearer → 401/200 round-trip via aether serve | AWS Secrets Manager backend (closes V4 MED) |
| W1+W2 | DEFERRED | n/a | dedicated SAML plan — full pipeline is multi-week pure-Rust XML crypto, outside Plan W's 24h budget | SAML AuthnRequest + signed-response validation deferred |

| X2 | DONE | 1d48646 | n/a | tool_arg_filter with field:"command" → matches `bash -lc "rm -rf /tmp/x"` (denied), passes benign body content with same regex literal in non-command field | per-field arg-filter (dotted JSON path) |
| X3 | DONE | d7ae0dd | n/a | broken WASM manifest → discover_wasm_plugins_with_diagnostics → fire_webhook("plugin-load-failure",{runtime:"wasm"}) hit Python receiver | WASM plugin-load-failure diagnostics (closes W6 LOW) |
| X5 | DONE | 80e17c6 | n/a | synthesized 3-transition local repo: trust audit --history showed `added/removed/added` rows with the 3 expected SHAs + dates | trust audit --history (full key timeline) |
| X6 | DONE | 7956cc4 | n/a | AETHER_AUDIT_FORWARD=loki + audit_emit() of 1 row → flusher posted within ~1s (under 10-line batch threshold) | periodic SIEM flusher (1s tokio interval task) |
| X4 | DONE | 7a1359b | n/a | redis-server :6399, rpm_cap=3, 5 reqs → 200/200/200/429/429; AETHER_RATE_BACKEND=redis://:9999 (down) → 3×200 fail-open | tenant rpm Redis backend (AETHER_RATE_BACKEND) |
| X1 | DONE | 520e5b4 | n/a | python OTLP sink :4318: /v1/messages span status=500 model=haiku, /ws/chat span status=101, /v1/complete span status=500 tenant=acme duration_ms=761 | OpenTelemetry tracing on serve hot path |
| Y1 | DONE | 5724bfb | n/a | AuthnRequest XML built + DEFLATE+b64+URL-encode roundtrip; redirect URL emits `?SAMLRequest=…&RelayState=…` | SAML AuthnRequest + HTTP-Redirect binding |
| Y2 | DONE | dc1ca90 | n/a | ACS POST round-trip via smoke: port bound, SAMLResponse decoded, Status=Success extracted | SAML ACS endpoint + SAMLResponse decode |
| Y3 | DONE | 726b063 | n/a | 33 quick-xml test cases (status / issuer / nameid / conditions / sig fragments / encrypted-rejection) all pass | SAMLResponse quick-xml extractor |
| Y4 | DONE | 6f223bc | n/a | exc-c14n byte-stable across attr reorder; lxml interop confirmed in live smoke (digest byte-match) | exclusive XML canonicalization 1.0 |
| Y5 | DONE | 61334c3 | n/a | RSA-2048 end-to-end verify passes; flipped SignatureValue → "RSA-SHA256 verify failed"; flipped DigestValue → "Reference digest mismatch" | RSA-SHA256 SAML assertion signature verify |
| Y6 | DONE | bb595db | n/a | 8 Y6-prefix tests: NotBefore/NotOnOrAfter/SubjectConf/Audience/clock-skew all pass (exit 0) | SAML Conditions + AudienceRestriction validation |
| Y7 | DONE | 571111f | n/a | live smoke: sso.token written (116 B, mode 0600, saml.v1. prefix); [smoke] Y7 LIVE-VERIFIED OK | NameID → SAML session token (sso_login_saml end-to-end) |
| Y-audit | DONE | (this commit) | FIXED | 33/33 Y-tests pass after B1+B2+B3+H1+H2 audit fixes; live smoke re-run → Y7 LIVE-VERIFIED OK | pre-tag audit: cert-pin + XSW + RelayState-bail + local-name + Recipient/InResponseTo |
| Z1' | DONE | a60baad | n/a | live smoke: nonce= j65aso4… in auth URL → echoed in id_token → persisted JWT carries matching nonce; 4 unit tests | OIDC nonce binding (replay defense per OIDC core §15.5.2) |
| Z2 | DONE | edebaf0 | n/a | live smoke: aether log "id_token signature + nonce + at_hash OK"; sso.token at_hash byte-matches SHA-256(access_token)[:16]; 5 unit tests | OIDC at_hash binding + JWKS 10s timeout + 256 KiB body cap |
| Z3 | DONE | 490a714 | n/a | live smoke: aether log line updated to "signature + nonce + iat + at_hash OK"; 6 unit tests cover iat-within-skew + too-far-past + too-far-future + missing + clamp env knob + strict at_hash | OIDC require-jwks default + iat freshness ±AETHER_OIDC_CLOCK_SKEW_S + AETHER_OIDC_REQUIRE_AT_HASH=1 strict mode |
| Z4 | DONE | 8e10a55 | n/a | live smoke: AWS4-HMAC-SHA256 + body shape OK on /invoke; "bedrock responded in 1ms (in=7 out=1)"; print mode emitted stream delta "hi-from-z4" via 3 hand-framed event-stream messages on /invoke-with-response-stream; 1 unit test | Bedrock fake-endpoint wire-format smoke + AETHER_BEDROCK_ENDPOINT env override |
| Z5 | DONE | 3365e15 | n/a | live smoke: Bearer + anthropic_version=vertex-2023-10-16 + no top-level model on :rawPredict; "vertex responded in 1ms (in=5 out=1)"; SSE data: events parsed → delta "hi-from-z5" reached stdout; 1 unit test. Honest UNVERIFIED: real GCP attempted with user gcloud auth, blocked by Google billing gate on all 3 projects | Vertex fake-endpoint wire-format smoke + AETHER_VERTEX_ENDPOINT env override |
| Z6 | DONE | 0e2dd12 | n/a | live smoke: api-key header byte-match + anthropic-version: 2023-06-01 header + ?api-version=2024-08-01-preview query + body has model+messages+max_tokens; "azure-foundry responded in 1ms (in=9 out=4)"; print mode emitted "hi-from-z6" via default complete_streamed → complete() fallback. Zero Rust changes (AZURE_AI_ENDPOINT already plays env-override role) | Azure AI Foundry fake-endpoint wire-format smoke |
| Z7 | DONE | dfab6c1 | n/a | v0.30.0 ship: workspace bump + 15 internal dep pins + ROADMAP + STATUS + Plan AA draft + tag + push; run 28283072232 4-platform autobuild green ~7m27s; cosign verify-blob → "Verified OK"; ./aether --version → aether 0.30.0 from published artifact | Plan Z wrap-up + v0.30.0 ship |
| AA4 | DONE | 79fed59 | n/a | live smoke: aether wrote authn-request-form.html at 0600 with method=POST + action=https://idp.test/saml/sso + hidden SAMLRequest+RelayState + onload auto-submit + <noscript> fallback; SAMLRequest b64 round-trips byte-for-byte to AuthnRequest XML embedding the ACS URL; IdP→SP leg signed via lxml exc-c14n still passes Y3→Y5→Y6→Y7 → sso.token at 0600. Y7 Redirect smoke re-run confirmed no regression. 3 unit tests | SAML HTTP-POST AuthnRequest binding (closes v0.29 explicit deferral) |
| AA5 | DONE | 125d2c6 | n/a | live smoke: 2 unrelated RSA-2048 IdP certs written to ~/.aether/saml/idp-certs/{00-old,10-new}.pem; SAMLResponse signed by OLD key verifies (slot 0 match); SAMLResponse signed by NEW key also verifies (verifier walks past slot 0 to find slot 1); both runs log "against 2 configured IdP cert(s)". 5 unit tests cover enumerate dir/env/legacy/empty + first-match-wins | Multi-cert IdP support — idp-certs/*.pem + first-match-wins |
| AA6 | DONE | a997c48 | n/a | live smoke: sso configure captured userinfo_endpoint into sso.json; sso login wrote ~/.aether/sso.access_token sidecar at 0600 with the access_token bytes; sso whoami formatted printed sub+email(verified)+name+username+groups; sso whoami --json emitted byte-for-byte userinfo JSON; sso logout removed BOTH sso.token + sso.access_token. Userinfo call carried Bearer access_token (not id_token JWT). 5 unit tests for parse_whoami_claims | OIDC userinfo + `aether sso whoami` |
| AA5-fu | DONE | 62ed5b8 | n/a | live smoke: fake metadata with 2 md:KeyDescriptor use="signing" blocks; configure-saml extracted both, wrote idp-certs/00-discovered.pem + 01-discovered.pem at 0600, each round-trips byte-for-byte to source DER; subsequent SAML login signed by slot-1 key verified via AA5 first-match-wins → sso.token at 0600. 6 unit tests cover order + encryption-filter + fallback + md/ds prefixes + empty + PEM wrap | configure-saml multi-cert discovery (closes AA5 weakest-point) |
| AA7 | DONE | 297788f | n/a | v0.31.0 ship: workspace bump + 15 internal dep pins + ROADMAP + STATUS + Plan BB draft + tag + push; run 28284401156 4-platform autobuild green (~8m23s longest leg); cosign verify-blob → "Verified OK"; ./aether --version → aether 0.31.0 from published artifact | Plan AA wrap-up + v0.31.0 ship |
| BB4 | DONE | 25301f0 | n/a | live smoke: AETHER_SAML_SP_PRIVATE_KEY_PEM=path spliced <ds:Signature> after </saml:Issuer> per saml-core §3.2.1; lxml round-trip verify confirmed Signature placement + Reference URI=#<authn_request_id> + DigestValue==sha256(exc-c14n(unsigned)) + RSA-SHA256 SignatureValue verifies under SP public key. PKCS#8+PKCS#1 PEM both load. IdP→SP leg passes Y3-Y7 unchanged. 3 unit tests | signed AuthnRequest (closes AA4 weakest-point) |
| BB5 | DONE | 49b0b1a | n/a | live smoke 6-step chain: login → sso.refresh_token at 0600; whoami succeeds; invalidate AT at fake → auto-refresh on 401 ("auto-refreshing via <path> (BB5)") + retry succeeds; manual `sso refresh` rotates; --no-refresh opts out cleanly; logout removes all 3 files. Refresh-token rotation per RFC 6749 §6 handled. 5 unit tests (parser full/min/missing/rotated + sidecar writer) | OIDC access-token refresh (closes AA6 weakest-point) |
| BB6 | DONE | edc7328 | n/a | live smoke 7-step chain: configure-saml v1 → sso-saml.json captures idp_metadata_url; flip server to v2 → refresh-saml writes 2 PEMs (v1 cleared); subsequent SAML login signed by v2-only cert B verified via AA5 first-match-wins; --watch banner emitted with AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS=60. Caught mid-development: refactor changed configure-saml wording; restored. 3 unit tests | SAML metadata auto-refresh (closes AA5-followup weakest-point) |
| BB7 | DONE | 96f8081 | n/a | v0.32.0 ship: workspace bump + 15 internal dep pins + ROADMAP + STATUS + Plan CC draft + tag + push; run 28285426700 4-platform autobuild green (~8m16s longest leg); cosign verify-blob → "Verified OK"; ./aether --version → aether 0.32.0 from published artifact | Plan BB wrap-up + v0.32.0 ship |
