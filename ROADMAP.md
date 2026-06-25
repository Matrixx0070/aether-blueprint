# Roadmap

## v0.4 — shipped 2026-06-25 (this release)

Phase 1 — v0.3.1 patches:
- D7 rule 06 (`lyrics_and_poems`): `applies_when: not_creative_writing_context`
  predicate; agent_turn detects creative-writing requests via substring
  scan; structural-line guard from v0.3 kept as belt-and-suspenders
- Persistent always-allow: answering `a` at the permission prompt writes
  to `~/.aether/settings.json` so subsequent sessions inherit
- `aether mcp test NAME` probes a configured server (spawn + initialize
  + list_tools + shutdown, reports tool count + names)
- `/usage` now estimates USD cost per session using a per-model price
  table (Haiku / Sonnet / Opus / Fable), with cache write 1.25× and
  cache read 0.10× multipliers

Phase 2 — Ratatui TUI (`aether tui`):
- 3 panes: chat (70%, scrollable), tools (30%, live status icons),
  status bar (model · session · perm · tokens · cost), input (5 rows)
- Streaming SSE tokens flow into the chat pane in real time
- Tool calls show ◌ (running) → ✓ (ok) / ✗ (err)
- Enter sends, Shift+Enter newline, Esc/Ctrl-Q exit, Ctrl-C clears input
- PgUp/PgDn scrolls the chat pane
- TerminalGuard RAII restores cooked-mode on panic

Phase 3 — Network surfaces:
- `aether serve` HTTP API: `POST /v1/messages`, `GET /healthz`; axum
  with minimal feature set; loopback-only by default (`127.0.0.1:7777`)
- MCP SSE transport: `Client` trait abstracts stdio + SSE; `SseClient`
  follows the older `event: endpoint` flow (GET /sse for response
  stream, POST to the advertised endpoint for requests); `spawn_client`
  factory picks the right transport from the config variant

Phase 4 — Reliability:
- `send_with_retries` in aether-llm: exp backoff (base 500ms, doubling,
  cap 30s, full-jitter, max 5 attempts) on transport errors + HTTP 5xx
  (incl. 529 overloaded); does NOT retry 4xx or successful 2xx
- `LlmError::actionable()` returns user-readable explanations with
  suggested fixes; CLI surfaces via `explain_agent_error`
- Streaming tool cancel: global `CANCEL_FLAG` in aether-tools::builtin;
  Bash tool's wait loop select!s timeout vs cancel-flag poll; CLI
  installs a tokio::signal::ctrl_c handler that flips the flag

## v0.4.1 — patch (next)

- MCP SSE end-to-end smoke against a real server (currently transport
  compiles + StdioClient still verified live; live SSE test deferred
  because no sandbox public MCP SSE server was handy)
- HTTP server streaming response (SSE flavor of POST /v1/messages)
- TUI: bracketed-paste support; rendering markdown inline (bold, code)
- More retry-watchdog telemetry (`/retries` slash command)

## v0.5 — feature parity push

- FleetView TUI for parallel sub-agents
- Plugin system via WASM modules registered as tools
- BYOC providers: Bedrock, Vertex, Foundry, Mantle
- MCP websocket transport
- Real `aether-mem` crate (lift from aether-cli)
- Real `aether-store` crate (lift settings from aether-cli)
- Real `aether-skill` crate (lift skill loader from aether-cli)

## v0.6 — surfaces

- IDE integrations: VS Code extension, JetBrains plugin
- Enterprise gateway: SAML/OIDC federation, audit log forwarding
- Trusted-device enrollment

## Explicit non-goals

- A drop-in `claude` binary replacement that spoofs Claude Code identity.
  aether's OAuth uses the SDK-agent identity prefix; we do not impersonate.
- Telemetry to a vendor endpoint. Hooks let operators export what they need.
- Auto-update.
