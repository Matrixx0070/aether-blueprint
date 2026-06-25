# Next 24-hour autonomous plan

Drafted at end of Plan K (v0.14 → v0.15) with empirical observations
folded in. Pick up here on resume.

---

## Plan L — IDE surface + multi-turn benchmark + plugin loader

**MISSION**: Move aether from "CLI + auditable harness" → "embeddable
into editor surfaces and richer task shapes," with empirical proof at
each step.

**DONE MEANS** (5 criteria):

1. **HTTP WebSocket chat endpoint** — `aether serve --bind ...` already
   exists; add a `/ws/chat` route that streams JSON-RPC-style messages
   for browser clients. Verified by a minimal HTML page that
   connects + sends a prompt + renders streamed deltas.
2. **VS Code extension skeleton** in a new `crates/aether-vscode/`
   directory (TypeScript inside, compile via `tsc`). Bare-minimum:
   command palette entry "aether: ask" that spawns `aether -p` via
   child_process and streams stdout into the active editor's bottom
   panel. Builds cleanly with `npm install && npm run compile`.
3. **Multi-turn benchmark tasks** — extend coding-eval with 3 tasks
   that REQUIRE clarification before fixing. Each task's `prompt:`
   field is deliberately underspecified; the task `verify.sh` accepts
   either a clarification-then-fix sequence OR a sensible default
   assumption that gets disclosed in the resulting code. Tests the
   agent's ability to handle ambiguity.
4. **WASM plugin loader (smallest viable)** — `wasmtime` crate as a
   workspace dep; new `aether-plugin` crate that loads `.wasm` files
   from `~/.aether/plugins/` and exposes them as tools through the
   existing `ToolRegistry`. Single example plugin (`echo.wasm`) that
   compiles from a 20-LoC Rust source.
5. **v0.16.0 binary release shipped + verified** — 4-platform tarballs
   + SHA256SUMS attached + `./aether --version` confirms.

**ASSUMPTIONS** (defaults picked):

- WebSocket transport: `tokio-tungstenite` (already a dep from G2 MCP
  work). No auth on the WS endpoint by default — bind defaults to
  127.0.0.1 like the existing HTTP server.
- VS Code extension: TypeScript, single source file, `vscode` engine
  ^1.85.0, packages with `vsce`. Marketplace publish is out of scope.
- Plugin manifest: minimal JSON sidecar (`echo.wasm.json`) declaring
  `name + description + input_schema`. No signing or sandbox escape
  protections in v1 — plugins run with full WASI capabilities.
- Multi-turn tasks: agent's response counts as a clarification if it
  contains a `?` in the first assistant text block AND no tool calls.

**NON-GOALS** (explicitly out):

- JetBrains plugin (separate language stack + ecosystem; 8h+ alone).
- Apple notarization (paid Developer ID required).
- Plugin marketplace + signature verification.
- Multi-user / collaborative session sharing.
- Mantle BYOC provider (uncertain API shape — defer).

**Phase breakdown** (~24h):

| Phase | Time | Slices |
|-------|------|--------|
| **L1**: HTTP WS chat endpoint | 4h | tokio-tungstenite route on `aether serve` + minimal HTML test page + smoke-test |
| **L2**: VS Code ext skeleton | 5h | new dir, package.json, single TS extension file, child_process spawn of `aether -p`, deltas to output channel, README, .vsix build |
| **L3**: Multi-turn coding tasks | 4h | 3 new fixtures (ambiguous bug fix, "which approach do you want" feature, design-tradeoff refactor) + verify scripts that accept clarification-first OR sensible-default; live run |
| **L4**: WASM plugin loader | 6h | wasmtime workspace dep, new `aether-plugin` crate, plugin manifest schema, `~/.aether/plugins/` discovery, `Tool` adapter, one example echo plugin, 3-4 unit tests |
| **L5**: Ship v0.16.0 | 2h | bump, tag, push, autobuild verify, install test |
| **L6**: Self-audit + next plan | 3h | verifier pass, M-plan draft |

**API budget**: $5-10 for L3 multi-turn live runs. Negligible for L1/L2/L4.

**WEAKEST POINT**:

L3 multi-turn tasks. Defining "what counts as a clarification vs a
default-assumed answer" is itself a research question. Backup: skip
L3, replace with **3-run stability matrix on the v3 15-task suite**
(15 × 3 = 45 runs, ~$6.50, ~30 min, produces a mean ± stddev cost
table per task — directly useful for cost-modelling consumers).

**Failure modes to catch via self-audit**:

- L1 WS endpoint that silently buffers instead of streaming → log
  visible per-chunk write times.
- L2 VS Code extension that compiles but doesn't actually load in VS
  Code → manual smoke test with `code --extensionDevelopmentPath` if
  VS Code is reachable; else mark UNVERIFIED.
- L4 plugin loader that runs but doesn't sandbox — be honest in docs.
- Token budget overrun: cap at $15 and stop.

---

## Pre-flight checklist (run at session start)

1. `git -C /root/aether-blueprint status` — clean tree?
2. `git -C /root/aether-blueprint log -5 --oneline` — verify last commit is v0.15.0 docs
3. `cargo test --workspace --release` — all green before adding new code
4. `gh release view v0.15.0` — confirm v0.15.0 binary release is live
5. Re-read this plan + the previous session's `wiki/hot.md` entry

If any precheck fails: stop and ask. Don't paper over.

---

## After this 24h: candidate plans for the NEXT 24h

- **Plan M** (productization): JetBrains plugin, Apple notarization
  (if user has Developer ID), GitHub Marketplace presence
- **Plan N** (cost optimization): cache-aware retry, partial-stream
  resume, sub-agent fan-out for parallel codebase analysis
- **Plan O** (research): a real SWE-Bench-Lite submission with aether's
  numbers + harness description published as a technical report

These are user-direction items, not autonomous defaults.
