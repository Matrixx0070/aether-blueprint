# Roadmap

## v0.2 — shipped 2026-06-25 (this release)

- Streaming SSE (text deltas progressive in REPL)
- Bundled D7 self-check rule library (14 rules, was empty in v0.1)
- AETHER.md / CLAUDE.md auto-load (cwd ancestry + `~/.aether/CLAUDE.md`)
- WebFetch, NotebookEdit, TodoWrite, Agent tools (11 total)
- Tool output safety (binary detection via NUL-byte heuristic)
- Interactive permission prompts (`y/n/a` per mutating call in default mode)
- Hooks system: SessionStart + UserPromptSubmit
- Settings file `~/.aether/settings.json`
- Custom slash commands from `~/.aether/commands/*.md`
- rustyline REPL: history, arrow keys, multi-line, Ctrl-C handling
- `aether list` recent sessions

## v0.2.1 — patch (next)

- D7 rule 06 (`lyrics_and_poems`) over-aggressive on short bullets — tune
  thresholds or add an `applies_when` predicate that suppresses on
  non-creative-writing contexts.
- PreToolUse / PostToolUse hooks (needs Executor changes to thread the
  hook list).
- `config set` actually writes settings.json (currently requires manual edit).
- Interactive resume picker (`aether resume` with no id shows a fuzzy
  picker over `aether list` output).

## v0.3 — feature parity push

- MCP client (real protocol: tools + resources + prompts; OAuth flow per server)
- Sub-agent FleetView (TUI for visualising parallel sub-agents)
- Ink-style TUI: split panes, inline diff viewer for Edit/Write, live tool
  status panel
- Plugin system: external Rust dylibs or WASM modules registered as tools
- BYOC providers: Bedrock, Vertex, Foundry, Mantle
- Aether-specific memory store with semantic recall (the `aether-mem` placeholder
  crate becomes real)
- Skill loader (the `aether-skill` placeholder becomes real — markdown skills
  that compile into available capabilities at session start)

## v0.4 — surfaces

- IDE integrations: VS Code extension, JetBrains plugin
- HTTP API server mode (`aether serve`) for remote consumption
- Enterprise gateway: SAML / OIDC federation, audit log forwarding

## Explicit non-goals

- A drop-in `claude` binary replacement that spoofs Claude Code identity.
  aether's OAuth gate uses the SDK-agent identity prefix (`"You are a Claude
  agent, built on Anthropic's Claude Agent SDK."`), which is the documented
  third-party path. We do not impersonate.
- Telemetry to a vendor endpoint. Hooks let operators export what they need.
- Auto-update (the binary is small enough to rebuild from source).
