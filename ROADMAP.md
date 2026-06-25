# Roadmap

## v0.3 — shipped 2026-06-25 (this release)

Phase 1 — v0.2.1 patches:
- D7 rule 06 (`lyrics_and_poems`) tuning: skips markdown structural lines
  (bullets, ordered lists, headings, block quotes, tables, code fences)
- PreToolUse / PostToolUse hooks (Executor gains ToolHookCallback +
  drain_pending_reminders)
- `aether config set` writes atomically to settings.json (recognised:
  default_model, permission_mode, always_allow_tools, env.KEY)
- `aether resume` with no id shows interactive picker

Phase 2 — MCP client:
- Real `aether-mcp` crate: stdio transport, JSON-RPC 2.0 codec, multiplexed
  reader task, initialize handshake at protocolVersion 2024-11-05
- tools/list, tools/call, resources/list, read_resource, prompts/list
- `McpToolAdapter` mounts MCP tools as `mcp__<server>__<tool>`
- `aether mcp add/list/remove` subcommands → `~/.aether/mcp.json`

Phase 3 — Skills + memory:
- `Skill` tool loads `~/.aether/skills/*.md` with YAML frontmatter
- `MemoryRead` + `MemoryWrite` tools backed by `~/.aether/memory/*.md`
- `<memory-index>` reminder auto-injected at session start (compounding
  context across sessions without inlining every file)
- `/memory` slash command lists entries

Phase 4 — Polish:
- `aether doctor` health check (auth, settings, hooks, mcp, disk)
- Inline diff preview (red/green) when Edit runs
- Token tracking: MessagesResponse gains `usage`; SSE parses
  message_start + message_delta; Session accumulates totals; `/usage`
  slash command
- Tab completion in REPL for slash commands (built-in + custom)

## v0.3.1 — patch (next)

- D7 rule 06: add `applies_when: creative_writing_context` predicate using
  user-input introspection (rather than the current structural-only fix)
- Persistent always-allow tools list from settings (already wired at startup,
  but `a` answer at prompt currently only updates in-memory; persist back)
- `aether mcp test NAME` to probe a server without entering a session
- Per-model cost estimation in `/usage` (Haiku / Sonnet / Opus pricing table)

## v0.4 — TUI + surfaces

- Ink-style TUI: split panes (chat / tool log / diff viewer / status bar)
- FleetView for parallel sub-agents
- Plugin system via WASM modules registered as tools
- BYOC providers: Bedrock, Vertex, Foundry, Mantle (each ~3h slice)
- HTTP API server mode (`aether serve`) for remote consumption
- VS Code extension, JetBrains plugin
- MCP SSE + websocket transports

## v0.5 — enterprise

- SAML / OIDC federation
- Audit log forwarding to standard SIEM
- Per-org policy enforcement (tool blocklists, model restrictions)
- Trusted-device enrollment

## Explicit non-goals

- A drop-in `claude` binary replacement that spoofs Claude Code identity.
  aether's OAuth uses the SDK-agent identity prefix; we do not impersonate.
- Telemetry to a vendor endpoint. Hooks let operators export what they need.
- Auto-update.
