# Roadmap

## v0.5 — shipped 2026-06-25 (this release)

Phase 1 — TUI polish:
- Markdown rendering in assistant chat lines (**bold**, `inline code`,
  ```code-block``` cyan, `#` headings magenta+bold) with structural-fallback
- Bracketed paste: multi-line paste arrives as one input edit

Phase 2 — Internal cleanup (placeholder crates become real):
- `aether-store` owns Settings + load/apply_env/set/append_always_allow
- `aether-skill` owns LoadedSkill + load_skills + SkillTool (with 4 unit tests)
- `aether-mem` owns memory_dir + memory_index + MemoryRead/Write tools
  (D5 MemoryPolicyStore retained for future fully-managed memory)
- `aether-cli` re-uses via thin `use crate::*` lines; behavior unchanged

Phase 3 — FleetView (parallel sub-agent visualization):
- Process-global `FleetRegistry` (once_cell) tracks every AgentTool call
- TUI grows a 4th pane (right-bottom) when any sub-agents exist:
  ◌ (running) / ✓ (done) / ⊘ (cancelled) / ✗ (error) + preview snippet
- `/fleet` REPL slash command lists tasks; `/fleet cancel <id>` flips the
  per-task cancel flag (sub-agent checks each turn and exits cleanly)

Phase 4 — Eval harness:
- `aether eval <suite.yaml>` runs a YAML test suite of cases
- Criteria: `expected_contains[]`, `forbidden_strings[]`,
  `expected_tool_used[]`, `max_turns`
- Human report (default) or `--json` machine-readable EvalReport
- Process exits 1 when any case fails (CI-friendly)
- Ships `eval/example.yaml` smoke (2 cases)

Phase 5 — Session admin:
- `aether session export <id>` prints a clean markdown transcript
- `aether session branch <id> --at-turn N` forks at exchange N into a
  new session id (writes to ~/.aether/sessions/, returns id on stdout)

## v0.5.1 — patch (next)

- MCP SSE end-to-end live smoke against a real server
- HTTP server SSE streaming response variant
- `aether eval` parallel runs with `--concurrency N`
- Permission prompt UX: show input summary by tool category (file path
  for Read/Write/Edit, command line for Bash, etc.)

## v0.6 — TUI + integration surfaces

- Plugin system via WASM modules registered as tools
- BYOC providers: Bedrock, Vertex, Foundry, Mantle
- VS Code extension, JetBrains plugin
- MCP websocket transport
- HTTP server WebSocket chat for browser clients
- Real `aether-mcp` server-side (host MCP servers from `aether` itself)

## v0.7 — enterprise

- SAML / OIDC federation
- Audit log forwarding to SIEM
- Per-org policy enforcement (tool blocklists, model restrictions)
- Trusted-device enrollment

## Explicit non-goals

- A drop-in `claude` binary replacement that spoofs Claude Code identity.
  aether's OAuth uses the SDK-agent identity prefix; we do not impersonate.
- Telemetry to a vendor endpoint. Hooks let operators export what they need.
- Auto-update.
