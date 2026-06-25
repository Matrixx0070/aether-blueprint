# aether — agentic CLI

`aether` is a code-editing agent built on Anthropic's Claude Agent SDK and the
Anthropic Messages API. It runs an explicit perceive → plan → tool-select →
execute → observe → verify loop with a built-in self-check gate and reminder
tamper-test — pipeline scaffolding most agents don't ship.

## Status

This is **v0** of a Rust workspace under active development. Auth flow, agent
loop, seven built-in tools, REPL, session persistence, and OAuth token refresh
are wired end-to-end and verified live against Claude Opus 4.7 / Opus 4.8 /
Sonnet 4.6 / Haiku 4.5.

## Install

```bash
cd aether-blueprint
cargo build --release
# binary is at target/release/aether
install -m 0755 target/release/aether ~/.local/bin/aether
aether --version
```

Or run `bin/install.sh` from the repo root.

## Auth

`aether` auto-detects credentials in this order:

1. `ANTHROPIC_API_KEY` env var (Console API key path, billed against Console)
2. `CLAUDE_CODE_OAUTH_TOKEN` env var (raw Bearer)
3. `~/.claude/.credentials.json` (Claude Code OAuth, billed against the Max
   subscription)

OAuth tokens are auto-refreshed when within 10 minutes of expiry. A 401
triggers a forced refresh + single retry. The refreshed token is persisted
back to the credentials file atomically (write to `.tmp` + rename).

## Usage

```bash
# Interactive REPL
aether
aether --model claude-opus-4-8
aether --permission-mode bypassPermissions       # skip per-tool confirmation
aether --cwd ~/my/project                        # set working directory

# One-shot agent call (uses tools)
aether --print "Write a hello world in Rust at /tmp/hello.rs and run it"

# Resume sessions
aether --continue                                # latest session
aether resume <session-id>                       # specific session

# Scaffold a project context file
aether init                                       # creates AETHER.md
```

### Slash commands (in REPL)

| Command | Action |
|---|---|
| `/help` | List commands |
| `/clear` | Wipe in-memory history (session file kept) |
| `/model NAME` | Switch active model |
| `/tools` | List registered tools |
| `/quit` | Exit |

### Built-in tools

| Tool | Purpose |
|---|---|
| `Bash` | Run shell command via `/bin/bash -c` (default 120s timeout, max 600s) |
| `Read` | Read file with line numbers; supports offset/limit |
| `Write` | Create/overwrite a file (absolute paths only) |
| `Edit` | Exact string-replace with uniqueness check |
| `Grep` | ripgrep wrapper; content / files_with_matches / count modes |
| `Glob` | Path-pattern matching; sorted by mtime, newest first |
| `LS` | List directory contents one level deep |

### Permission modes

| Mode | Behavior |
|---|---|
| `default` | Read-only allowed; mutating tools (Bash, Write, Edit) refused |
| `acceptEdits` | Read-only and file mutators allowed; Bash/network refused |
| `plan` | Read-only only; all mutators refused |
| `bypassPermissions` | Everything allowed (operator opt-in) |

### Session persistence

Each session writes to `~/.aether/sessions/<id>.jsonl`, one entry per turn.
The pointer `~/.aether/sessions/latest` holds the most-recent id so
`aether --continue` works without flags.

## Architecture

```
crates/
├── aether-cli          Binary; argument parsing + REPL + session lifecycle
├── aether-core         Agent loop (Session, agent_turn, ContextAssembler, Verifier)
├── aether-llm          LlmProvider trait + Anthropic Messages API client + OAuth
├── aether-tools        Tool trait + Bash/Read/Write/Edit/Grep/Glob/LS
├── aether-hook         D1 reminder tamper-test pipeline (kernel rules + telemetry)
├── aether-selfcheck    D7 pre-emission self-check gate (YAML-loaded rule library)
├── aether-overlay      D1–D7 activation predicates (Fable5Overlay)
├── aether-perm         Permission mode enum
├── aether-mcp          MCP client (placeholder for v0.2)
├── aether-mem          Memory store (placeholder for v0.2)
├── aether-store        Settings store (placeholder for v0.2)
├── aether-skill        Skill loader (placeholder for v0.2)
└── aether-render       TUI rendering (placeholder for v0.2)
```

The agent loop runs six phases per turn:

1. **perceive** — assemble system prompt + messages via `ContextAssembler`
   (D1 reminder filter + D6 long-conversation injection)
2. **plan** — refresh the active plan if dirty (L1 plan-critic)
3. **tool-select** — single LLM call; returned `tool_uses` drive execute
4. **execute** — per tool_use: permission decide → run → capture
5. **observe** — append the assistant turn + any tool results
6. **verify** — D7 self-check on the assistant text; block or rewrite

## aether vs claude-code

Honest comparison, no hand-waving:

| Capability | Claude Code | aether (v0) |
|---|:---:|:---:|
| Single-binary CLI | ✅ | ✅ |
| OAuth + Max-subscription auth | ✅ | ✅ |
| Token auto-refresh + 401 retry | ✅ | ✅ |
| Bash / Read / Write / Edit / Grep / Glob / LS | ✅ | ✅ |
| Permission modes (default / acceptEdits / plan / bypass) | ✅ | ✅ |
| Interactive REPL | ✅ | ✅ (plain readline) |
| Session persistence + resume | ✅ | ✅ |
| Slash commands | ✅ | ✅ (subset: help/clear/model/tools) |
| Streaming SSE | ✅ | ⬜ (non-streaming for v0, SSE in v0.1) |
| Ink-style TUI | ✅ | ⬜ (plain text REPL in v0, Ink in v0.2) |
| MCP client | ✅ | ⬜ (v0.2) |
| Sub-agents / FleetView | ✅ | ⬜ (v0.3) |
| IDE integrations | ✅ | ⬜ |
| Plugin system | ✅ | ⬜ |
| **D1 reminder tamper-test** | ⬜ | ✅ |
| **D7 self-check gate w/ rewrite + block** | ⬜ | ✅ |
| **First-match deterministic tool routing (D3)** | ⬜ | ✅ |

`aether` ships the three Fable-5 deltas the public Claude Code build doesn't:
D1 (reminder filtering against prompt-injection), D7 (pre-emission self-check
with rewrite/block), and D3 (deterministic routing). Everything else is
explicit roadmap.

## Verifying the install

```bash
# Should print: pong
aether --model claude-haiku-4-5-20251001 --print "Reply with the single word: pong"

# Should create the file, then read it back
aether --permission-mode bypassPermissions --print \
  "Use Write to put 'aether works' in /tmp/aether-check.txt, then Read it back"
cat /tmp/aether-check.txt
```

## License

MIT OR Apache-2.0.
