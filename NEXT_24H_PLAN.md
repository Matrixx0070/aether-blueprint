# Next 24-hour autonomous plan — Plan M

Drafted at end of Plan L (v0.15 → v0.16). Picks up the v0.17+ scope items
listed in `ROADMAP.md` and the LOW/MEDIUM findings from L6 self-audit.

---

## Plan M — sandbox + IDE polish + production hardening

**MISSION**: Close the L4-deferred safety gap (WASM sandbox for plugins),
upgrade the VS Code extension from skeleton to functional dev UI, and
add WS authentication so `aether serve --bind 0.0.0.0:...` is safe.

**DONE MEANS** (5 criteria):

1. **WASM-sandboxed plugin loader** in a NEW crate `aether-plugin-wasm`
   (does NOT replace L4 subprocess plugins — both ship; users pick).
   Uses `wasmtime` with WASI preview1. Same manifest format as L4 plus
   a `runtime: "wasm"` field. Example plugin: an `echo.wasm` built from
   a 20-LoC Rust source via `rustup target add wasm32-wasi-preview1 &&
   cargo build --target wasm32-wasi-preview1 --release`. Live-verified
   end-to-end (sandboxed plugin echoes input).
2. **WS bearer-token auth** on `aether serve /ws/chat`. New
   `AETHER_SERVE_TOKEN` env var; if set, the WS handler refuses
   connections without a matching `Authorization: Bearer <token>`
   header. Documented in the existing serve startup message. Live-
   verified: connection without token → 401; with correct token → OK.
3. **VS Code extension multi-turn webview panel** replacing the
   one-shot output-channel UI from L2. New `panel.html` + `panel.ts`
   that connect to a long-lived `aether serve` over `/ws/chat` and
   render streamed deltas in a Markdown-rendered view. UNVERIFIED for
   actual VS Code launch (still no headless harness in this env) but
   compiles + the webview HTML renders in isolated browser test.
4. **Plugin manifest signing** (HMAC-SHA256). Optional `signature`
   field in `manifest.json` matched against `$AETHER_PLUGIN_HMAC_KEY`.
   Unsigned plugins still load (warning printed) — opt-in trust model.
   3 unit tests including a tamper-detection case.
5. **v0.17.0 binary release** shipped + verified, all 4 platforms.

**ASSUMPTIONS** (defaults picked):

- WASM runtime: `wasmtime` ≥ 25, `wasi-preview1` enabled (matches the
  stable WASI surface most language toolchains target as of 2026-06).
- Resource limits per WASM plugin: 64 MB memory, 10s wall-clock. No
  per-instruction fuel metering in v1 (too coarse a tradeoff).
- WS auth: simple shared-secret bearer. JWT / OAuth flows are out of
  scope (separate slice).
- VS Code panel: client-side Markdown rendering via `markdown-it`
  (single CDN script, not bundled). Avoids the npm build complexity.

**NON-GOALS** (explicitly out):

- JetBrains plugin (Kotlin language stack; M+1 candidate).
- Apple notarization (paid Developer ID required).
- Plugin marketplace + per-plugin reputation system.
- WASM gas/fuel metering (planned for v0.18+).
- Mantle BYOC provider.

**Phase breakdown** (~24h):

| Phase | Time | Slices |
|-------|------|--------|
| **M1**: `aether-plugin-wasm` crate | 7h | wasmtime workspace dep, ManifestRuntime enum, WasmPluginTool adapter, resource limits, `runtime: "wasm"` discovery branch, 4 unit tests |
| **M2**: example WASM plugin | 2h | minimal Rust source compiled to wasm32-wasi-preview1, manifest, live verification |
| **M3**: WS bearer-token auth | 3h | extract token from upgrade headers, refuse on mismatch, kill-switch `AETHER_SERVE_NO_AUTH=1`, smoke test both branches |
| **M4**: VS Code webview panel | 6h | panel.html + panel.ts, WS connection state machine, streamed-delta rendering, smoke test via `code --extensionDevelopmentPath` if available; UNVERIFIED otherwise |
| **M5**: plugin HMAC signing | 3h | sign / verify helpers, optional manifest field, 3 unit tests, smoke verify with a tampered manifest |
| **M6**: ship v0.17.0 | 1h | bump + tag + autobuild + install verify |
| **M7**: self-audit + Plan N | 2h | LOW/MEDIUM scan + draft |

**API budget**: $5-10 for live verification round-trips. Negligible
otherwise.

**WEAKEST POINT**:

M4 — VS Code webview panel. Without `code` on the path, the actual UI
rendering can't be confirmed; smoke tests stop at "page HTML parses
and the JS bundle compiles." Honest label in commit + README.

**Failure modes to catch via self-audit**:

- WASM plugin that exhausts memory limit → wasmtime aborts; check
  ToolError surface is informative, not a panic.
- WS handler that accepts a partial-bearer or wrong-prefix token →
  ensure the comparison is constant-time AND scheme-strict.
- VS Code panel that streams correctly but never closes the WS → leak
  on multiple panel opens.
- Plugin HMAC verifier that returns ok on absent signature (forgetting
  to fail-closed when signing is mandatory in CI mode).

---

## Pre-flight checklist (run at next-session start)

1. `git -C /root/aether-blueprint status` — clean tree?
2. `git -C /root/aether-blueprint log -5 --oneline` — last commit is v0.16.0 docs?
3. `cargo test --workspace --release` — all green before adding new code
4. `gh release view v0.16.0` — confirm v0.16.0 binary is live
5. `wasmtime --version` — wasmtime CLI optional but useful for plugin debugging
6. `rustup target list --installed | grep wasm32-wasi-preview1` — target installed?

---

## Candidate plans for 24h after Plan M

- **Plan N** (production posture): rate limit + concurrent-session cap
  on `aether serve`, audit-log forwarding to syslog/SIEM, per-org
  policy file enforcement at provider construction.
- **Plan O** (cost optimization): cache-aware retry, partial-stream
  resume, sub-agent fan-out for parallel codebase analysis.
- **Plan P** (research artifact): a real SWE-Bench-Lite submission
  with aether's numbers + harness description published as a
  technical report.
