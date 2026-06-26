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

