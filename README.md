# aether — agentic CLI

`aether` is a code-editing agent built on Anthropic's Claude Agent SDK and the
Anthropic Messages API. It runs an explicit perceive → plan → tool-select →
execute → observe → verify loop with a built-in self-check gate and reminder
tamper-test — pipeline scaffolding most agents don't ship.

## Status: v0.5

Adds: **FleetView** for parallel sub-agents (TUI pane + `/fleet` command +
cancellation), **`aether eval`** harness for YAML test suites (CI-friendly
exit codes + JSON output), **`aether session export/branch`** for transcript
dump + session forking, **TUI markdown rendering** (bold / inline code /
code blocks / headings) + **bracketed paste**, and internal cleanup
(settings → `aether-store`, skills → `aether-skill`, memory → `aether-mem`).

End-to-end working: MCP client (stdio + SSE), sub-agent delegation with
FleetView, persistent memory, markdown skills, 4-event hooks, interactive
permission prompts, token tracking + cost, streaming SSE, rustyline REPL
with tab completion, `aether doctor`, full TUI with up-to-4 panes (chat /
tools / fleet / status / input), HTTP API, eval harness, session export/
branch.
13 built-in tools + every MCP server's tools auto-mounted. Verified live
against Opus 4.7 / 4.8 / Sonnet 4.6 / Haiku 4.5.

## Install

```bash
cd aether-blueprint
./bin/install.sh                  # builds + installs to ~/.local/bin/aether
aether --version
aether doctor                     # health check
```

## Auth

`aether` auto-detects credentials in this order:

1. `ANTHROPIC_API_KEY` env var
2. `CLAUDE_CODE_OAUTH_TOKEN` env var (raw Bearer)
3. `~/.claude/.credentials.json` (Claude Code OAuth, Max subscription)

OAuth tokens auto-refresh within 10 min of expiry. 401 → forced refresh +
retry. Atomic write back (`.tmp` + rename, mode 0600).

## Usage

```bash
# Interactive REPL (rustyline: history, arrow keys, Ctrl-R, multi-line, tab)
aether
aether --model claude-opus-4-8
aether --permission-mode bypassPermissions

# Full TUI (chat + tool log + status + multi-line input)
aether tui

# HTTP API (loopback only by default)
aether serve --bind 127.0.0.1:7777
# then:  curl -X POST http://127.0.0.1:7777/v1/messages -d '{"prompt":"..."}'

# One-shot
aether --print "Write hello world in Rust to /tmp/hello.rs and run it"

# Sessions
aether --continue                          # latest session
aether resume                              # interactive picker (recent 20)
aether resume <id>                         # specific session
aether list --limit 20                     # show recent sessions

# Setup + introspection
aether init                                # creates AETHER.md scaffold
aether doctor                              # health check
aether config show                         # print resolved settings
aether config set default_model claude-opus-4-8
aether config set always_allow_tools "Bash,Edit,Write"
aether config set env.AETHER_DEBUG 1

# MCP servers
aether mcp add fs -- npx -y @modelcontextprotocol/server-filesystem /tmp
aether mcp list
aether mcp test fs
aether mcp remove fs

# Eval harness (CI-friendly; exit 1 on any case failure)
aether eval eval/example.yaml
aether eval eval/example.yaml --json

# Session admin
aether session export <id>                 # markdown transcript on stdout
aether session branch <id> --at-turn 3     # fork at exchange 3, prints new id
```

### Slash commands (in REPL)

| Command | Action |
|---|---|
| `/help` | List built-in + custom commands |
| `/clear` | Wipe in-memory history |
| `/model NAME` | Switch active model |
| `/tools` | List registered tools |
| `/memory` | List `~/.aether/memory/` entries |
| `/usage` | Show token totals for the session |
| `/fleet` | List sub-agents (use `/fleet cancel <id>` to signal cancel) |
| `/commands` | List custom commands |
| `/<custom>` | Run a `~/.aether/commands/<custom>.md` template |
| `/quit` | Exit |

Tab cycles candidates. Trailing backslash continues input on next line.
First Ctrl-C clears, second exits.

### Built-in tools (13)

| Tool | Purpose |
|---|---|
| `Bash` | Run shell command (`/bin/bash -c`, 120s default, 600s max) |
| `Read` | Read file with line numbers; refuses binaries (NUL detection) |
| `Write` | Create/overwrite (absolute paths only) |
| `Edit` | Exact string-replace with uniqueness check |
| `Grep` | ripgrep wrapper |
| `Glob` | Path matching, sorted by mtime |
| `LS` | Directory listing |
| `WebFetch` | HTTP GET, HTML stripped to text |
| `NotebookEdit` | `.ipynb` cell-level edit |
| `TodoWrite` | In-process task tracker |
| `Agent` | Spawn sub-session for delegated work |
| `MemoryRead` | Read `~/.aether/memory/<name>.md` |
| `MemoryWrite` | Save `~/.aether/memory/<name>.md` |
| `Skill` | Invoke `~/.aether/skills/<name>.md` (only when any skills are present) |

Plus every connected MCP server's tools, namespaced `mcp__<server>__<tool>`.

### Permission modes

| Mode | Behavior |
|---|---|
| `default` | Read-only allowed; mutating tools prompt `y/n/a` |
| `acceptEdits` | Read-only + file mutators allowed; Bash/network refused |
| `plan` | Read-only only |
| `bypassPermissions` | Everything allowed |

Answering `a` adds the tool to the session's always-allow set. Persistent
allowlist via `aether config set always_allow_tools ...`.

### MCP (Model Context Protocol)

JSON-RPC 2.0 over stdio. Add a server, its tools become `mcp__<name>__<tool>`
in the registry; the model calls them like any built-in:

```bash
aether mcp add fs -- npx -y @modelcontextprotocol/server-filesystem /tmp
# Then in aether:
#   "Use the mcp__fs__read_file tool to read /tmp/notes.md"
```

Configuration persisted at `~/.aether/mcp.json`. Spawned + initialized at
session start; killed on session end.

### Hooks (`~/.aether/hooks.json`)

```json
{
  "SessionStart":     [{"command": "echo 'Repo:' $(basename $(pwd))"}],
  "UserPromptSubmit": [{"command": "./bin/safety-check.sh"}],
  "PreToolUse":       [{"command": "echo 'about to run' $(jq -r .tool)", "tool_matcher": "Bash"}],
  "PostToolUse":      [{"command": "logger -t aether 'tool done'"}]
}
```

Each hook is `/bin/bash -c <command>` with the event payload as JSON on
stdin. Stdout (≤ 64 KiB, 30s timeout) becomes a kernel reminder. PreToolUse
and PostToolUse can filter by `tool_matcher` substring.

### Memory (`~/.aether/memory/*.md`)

Cross-session compounding. At session start, aether injects a `<memory-index>`
reminder listing every memory file's name + first line. The model calls
`MemoryRead` on demand and `MemoryWrite` to save new facts.

```bash
# Model can: MemoryWrite{name:"project-codename", content:"Lighthouse"}
# Next session: model sees memory-index, can MemoryRead it back.
```

### Skills (`~/.aether/skills/*.md`)

Each `.md` file becomes a callable skill via the `Skill` tool. YAML
frontmatter declares name + description; body is the skill prompt.

```markdown
---
name: code-review
description: Audit staged git diff and produce a punch list
---
Review the staged diff. Produce BLOCKER/HIGH/MEDIUM/LOW sections...
```

### Custom slash commands (`~/.aether/commands/*.md`)

Each `.md` becomes a `/name` command. `$ARGS`, `$1`, `$2`, … substitute
the rest of the line.

### Project context auto-load

At session start aether walks cwd up to root and reads any `AETHER.md` or
`CLAUDE.md`, plus `~/.aether/CLAUDE.md` as a global baseline. The combined
content is injected as a kernel-source reminder.

### Settings (`~/.aether/settings.json`)

```json
{
  "default_model": "claude-opus-4-8",
  "permission_mode": "default",
  "always_allow_tools": ["Bash", "Write", "Edit"],
  "env": { "AETHER_LOG_LEVEL": "info" }
}
```

CLI flag > env var > settings > built-in default. Edit via `aether config set`.

### Session persistence

`~/.aether/sessions/<id>.jsonl` per session, one entry per turn.
`~/.aether/sessions/latest` points to the most-recent id for `--continue`.

### Streaming

Assistant text streams via SSE. Tool calls are accumulated before dispatch
(the agent loop needs the complete `input` JSON before it can run a tool).

### Token tracking

Each response's `usage` field is added to a session-wide counter. `/usage`
prints `in / out / cache_create / cache_read / total`. Works for both
streaming (parsed from `message_delta`) and non-streaming paths.

## Architecture

```
crates/
├── aether-cli          Binary; REPL + agent-print + session lifecycle
├── aether-core         Agent loop (Session, agent_turn, ContextAssembler, Verifier)
├── aether-llm          LlmProvider trait + Anthropic Messages + OAuth + SSE + Usage
├── aether-tools        Tool trait + 11 standard built-ins (memory/skill/agent live in aether-cli)
├── aether-mcp          MCP 2024-11-05 client (stdio transport)
├── aether-hook         D1 reminder tamper-test (34-signal classifier)
├── aether-selfcheck    D7 pre-emission self-check gate (14-rule YAML library, structural-line aware)
├── aether-overlay      D1–D7 activation predicates
├── aether-perm         Permission mode enum
├── aether-mem          Reserved (memory store currently in aether-cli)
├── aether-store        Reserved (settings store currently in aether-cli)
├── aether-skill        Reserved (skill loader currently in aether-cli)
└── aether-render       Reserved for v0.4 Ink-style TUI
```

## aether vs claude-code

| Capability | Claude Code | aether (v0.4) |
|---|:---:|:---:|
| Single-binary CLI | ✅ | ✅ |
| OAuth + Max-subscription auth + auto-refresh | ✅ | ✅ |
| Streaming SSE | ✅ | ✅ |
| Bash / Read / Write / Edit / Grep / Glob / LS | ✅ | ✅ |
| WebFetch / NotebookEdit / TodoWrite | ✅ | ✅ |
| Sub-agent (Agent tool) | ✅ | ✅ |
| Memory (cross-session) | ✅ | ✅ |
| Skills | ✅ | ✅ |
| MCP client (stdio) | ✅ | ✅ |
| MCP client (SSE) | ✅ | ✅ |
| Hooks (SessionStart, UserPromptSubmit, PreToolUse, PostToolUse) | ✅ | ✅ |
| Interactive permission prompts (with persistent always-allow) | ✅ | ✅ |
| Settings file + `config set` | ✅ | ✅ |
| Custom slash commands | ✅ | ✅ |
| Project context auto-load | ✅ | ✅ |
| Token / cost tracking ($) | ✅ | ✅ |
| REPL: history, arrow keys, multi-line, Ctrl-C, tab completion | ✅ | ✅ |
| Session list + resume picker | ✅ | ✅ |
| `aether doctor` health check | ✅ | ✅ |
| **Ink-style TUI (split panes, live tool log)** | ✅ | ✅ |
| **HTTP API server (`aether serve`)** | ⬜ | ✅ |
| **Retry watchdog (exp-backoff on 5xx)** | ✅ | ✅ |
| **Actionable error messages** | ✅ | ✅ |
| **Streaming tool cancel (Ctrl-C)** | ✅ | ✅ |
| **FleetView (parallel sub-agent TUI pane + /fleet)** | ✅ | ✅ |
| **`aether eval` harness (YAML suites + JSON output)** | ⬜ | ✅ |
| **`aether session export/branch`** | ✅ | ✅ |
| **TUI markdown rendering + bracketed paste** | ✅ | ✅ |
| Plugin system (dylib / WASM) | ✅ | ⬜ (v0.6) |
| BYOC providers (Bedrock / Vertex / Foundry) | ✅ | ⬜ (v0.6) |
| IDE integrations | ✅ | ⬜ (v0.6) |
| **D1 reminder tamper-test (34-signal classifier)** | ⬜ | ✅ |
| **D7 self-check gate (14 rules, structural-line aware)** | ⬜ | ✅ |
| **Deterministic first-match routing (D3)** | ⬜ | ✅ |

aether ships the three Fable-5 deltas Claude Code doesn't (D1 prompt-injection
filter, D7 pre-emission gate, D3 deterministic routing). For everything else,
v0.3 is at functional parity on the core agent loop; v0.4 picks up TUI +
plugin surfaces.

## Performance

See [`BENCHMARK.md`](BENCHMARK.md). aether is consistently 2–3× faster at p50
and 2–4× faster at p95 than `claude` for the agent-loop+IO axis, across v0.1
through v0.3.

## License

MIT OR Apache-2.0.
