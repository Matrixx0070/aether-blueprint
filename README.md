# aether — agentic CLI

`aether` is a code-editing agent built on Anthropic's Claude Agent SDK and the
Anthropic Messages API. It runs an explicit perceive → plan → tool-select →
execute → observe → verify loop with a built-in self-check gate and reminder
tamper-test — pipeline scaffolding most agents don't ship.

## Status: v0.2

11 built-in tools, REPL with rustyline (history + arrow keys + multi-line),
streaming SSE, OAuth token auto-refresh, sub-agent delegation, custom slash
commands, project context auto-loading, settings file, hooks system, session
list. End-to-end verified against Opus 4.7 / Opus 4.8 / Sonnet 4.6 / Haiku 4.5.

## Install

```bash
cd aether-blueprint
./bin/install.sh                  # builds + installs to ~/.local/bin/aether
aether --version
```

## Auth

`aether` auto-detects credentials in this order:

1. `ANTHROPIC_API_KEY` env var (Console API key path, billed against Console)
2. `CLAUDE_CODE_OAUTH_TOKEN` env var (raw Bearer)
3. `~/.claude/.credentials.json` (Claude Code OAuth, billed against Max)

OAuth tokens are auto-refreshed within 10 minutes of expiry. A 401 triggers a
forced refresh + retry. The refreshed token is atomically written back
(`.tmp` + rename, mode 0600).

## Usage

```bash
# Interactive REPL with streaming
aether
aether --model claude-opus-4-8
aether --permission-mode bypassPermissions       # skip per-tool confirmation
aether --cwd ~/my/project                        # set working directory

# One-shot agent call (uses tools)
aether --print "Write a hello world in Rust at /tmp/hello.rs and run it"

# Resume sessions
aether --continue                                # latest session
aether resume <session-id>                       # specific session
aether list --limit 20                           # show recent sessions

# Scaffold + config
aether init                                       # creates AETHER.md
aether config show                                # show resolved settings
```

### Slash commands (in REPL)

| Command | Action |
|---|---|
| `/help` | List built-in + custom commands |
| `/clear` | Wipe in-memory history |
| `/model NAME` | Switch active model |
| `/tools` | List registered tools |
| `/commands` | List custom commands |
| `/<custom>` | Run a `~/.aether/commands/<custom>.md` template |
| `/quit` | Exit (also Ctrl-D, or double Ctrl-C) |

REPL input supports arrow keys, Ctrl-R history search, trailing-backslash
multi-line continuation, persistent history at `~/.aether/history`.

### Built-in tools (11)

| Tool | Purpose |
|---|---|
| `Bash` | Run shell command via `/bin/bash -c` (120s default timeout, max 600s) |
| `Read` | Read file; refuses binaries (NUL-byte heuristic); supports offset/limit |
| `Write` | Create / overwrite a file (absolute paths only) |
| `Edit` | Exact string-replace with uniqueness check |
| `Grep` | ripgrep wrapper; content / files_with_matches / count modes |
| `Glob` | Pattern matching; sorted by mtime, newest first |
| `LS` | List directory one level deep |
| `WebFetch` | HTTP GET; strips HTML to text; 30s timeout; 5 MiB max |
| `NotebookEdit` | `.ipynb` cell-level edit (replace / insert / delete) |
| `TodoWrite` | In-process task tracker the model uses to break work down |
| `Agent` | Spawn a fresh sub-session for a self-contained delegated task |

### Permission modes

| Mode | Behavior |
|---|---|
| `default` | Read-only allowed; mutating tools prompt for `y/n/a` (Allow/Deny/Always-for-tool) |
| `acceptEdits` | Read-only and file mutators allowed; Bash/network refused |
| `plan` | Read-only only; all mutators refused |
| `bypassPermissions` | Everything allowed (operator opt-in) |

In `default` mode the REPL surfaces an interactive prompt per mutating tool.
Answering `a` adds that tool to the session's always-allow set.

### Project context auto-load

At session start, aether walks the cwd up to root and reads any `AETHER.md`
or `CLAUDE.md` found, plus `~/.aether/CLAUDE.md` as a global baseline. The
combined content is injected as a kernel-source reminder so the model has
project context without a hand-curated system prompt.

### Settings (`~/.aether/settings.json`)

```json
{
  "default_model": "claude-opus-4-8",
  "permission_mode": "default",
  "always_allow_tools": ["Bash", "Write", "Edit"],
  "env": {
    "AETHER_LOG_LEVEL": "info"
  }
}
```

Resolution: CLI flag > env var > settings > built-in default.

### Hooks (`~/.aether/hooks.json`)

```json
{
  "SessionStart": [
    {"command": "echo 'Repo:' $(basename $(pwd))"}
  ],
  "UserPromptSubmit": [
    {"command": "./bin/safety-check.sh"}
  ]
}
```

Each hook is `/bin/bash -c <command>`. The event payload arrives on stdin as
JSON. Stdout (≤ 64 KiB, 30s timeout) becomes a kernel reminder for the next
LLM call. `PreToolUse` / `PostToolUse` planned for v0.2.1.

### Custom slash commands (`~/.aether/commands/*.md`)

Files in this directory become `/<filename>` commands at the REPL. `$ARGS`,
`$1`, `$2`, … are substituted from whatever follows the command.

```markdown
# ~/.aether/commands/calc.md
Compute the following and reply with just the numeric answer:
$ARGS
```

`/calc 12*7+3` → sends the substituted prompt to the model.

### Session persistence

Each session writes to `~/.aether/sessions/<id>.jsonl`, one entry per turn.
`~/.aether/sessions/latest` holds the most-recent id for `--continue`. List
recent sessions with `aether list`.

### Streaming

Assistant text streams progressively to stdout as Anthropic delivers SSE
deltas. Tool calls remain fully buffered (the agent loop needs the complete
`input` JSON before it can run the tool).

## Architecture

```
crates/
├── aether-cli          Binary; REPL + agent-print + session lifecycle
├── aether-core         Agent loop (Session, agent_turn, ContextAssembler, Verifier)
├── aether-llm          LlmProvider trait + Anthropic Messages + OAuth + SSE
├── aether-tools        Tool trait + 11 built-ins
├── aether-hook         D1 reminder tamper-test (34-signal classifier)
├── aether-selfcheck    D7 pre-emission self-check gate (14-rule YAML library)
├── aether-overlay      D1–D7 activation predicates
├── aether-perm         Permission mode enum
├── aether-mcp          MCP client (placeholder for v0.3)
├── aether-mem          Memory store (placeholder for v0.3)
├── aether-store        Settings store (placeholder for v0.3)
├── aether-skill        Skill loader (placeholder for v0.3)
└── aether-render       TUI rendering (placeholder for v0.3)
```

Agent loop phases:

1. **perceive** — assemble system prompt + messages (D1 reminder filter, D6
   long-conversation injection, AETHER.md inclusion)
2. **plan** — refresh active plan if dirty (L1 plan critic)
3. **tool-select** — single LLM call (streamed); returned tool_uses drive execute
4. **execute** — per tool_use: permission decide (with optional interactive
   prompt) → run → capture
5. **observe** — append assistant turn + tool results
6. **verify** — D7 self-check on assistant text; rewrite or block

## aether vs claude-code

| Capability | Claude Code | aether (v0.2) |
|---|:---:|:---:|
| Single-binary CLI | ✅ | ✅ |
| OAuth + Max-subscription auth | ✅ | ✅ |
| Token auto-refresh + 401 retry | ✅ | ✅ |
| Streaming SSE | ✅ | ✅ |
| Read / Write / Edit / Bash / Grep / Glob / LS | ✅ | ✅ |
| WebFetch | ✅ | ✅ |
| NotebookEdit | ✅ | ✅ |
| TodoWrite | ✅ | ✅ |
| Agent (sub-loop) | ✅ | ✅ |
| Interactive REPL with history + arrow keys + Ctrl-R | ✅ | ✅ |
| Multi-line input | ✅ | ✅ (trailing backslash) |
| Ctrl-C handling | ✅ | ✅ (first clears, second exits) |
| Session persistence + resume | ✅ | ✅ |
| `--list` recent sessions | ✅ | ✅ |
| Slash commands | ✅ | ✅ |
| Custom slash commands | ✅ | ✅ |
| Project context auto-load (CLAUDE.md / AETHER.md) | ✅ | ✅ |
| Settings file | ✅ | ✅ |
| Hooks (SessionStart, UserPromptSubmit) | ✅ | ✅ |
| Interactive permission prompts | ✅ | ✅ (y/n/a) |
| PreToolUse / PostToolUse hooks | ✅ | ⬜ (v0.2.1) |
| Ink-style TUI (split panes, diff viewer) | ✅ | ⬜ (v0.3) |
| MCP client | ✅ | ⬜ (v0.3) |
| FleetView (sub-agent UI) | ✅ | ⬜ (v0.3) |
| IDE integrations | ✅ | ⬜ |
| BYOC providers (Bedrock / Vertex / Foundry) | ✅ | ⬜ |
| **D1 reminder tamper-test (34-signal classifier)** | ⬜ | ✅ |
| **D7 self-check gate (14-rule library)** | ⬜ | ✅ |
| **Deterministic first-match tool routing (D3)** | ⬜ | ✅ |

aether ships the three Fable-5 deltas the public Claude Code build doesn't:
D1 (reminder filtering against prompt-injection), D7 (pre-emission self-check
with rewrite/block), and D3 (deterministic first-match routing). Everything
else is explicit roadmap.

## Performance

See [`BENCHMARK.md`](BENCHMARK.md). n=20 head-to-head on Haiku 4.5: aether is
roughly **2–3× faster at p50** and tighter at p95 than `claude` for the
"spin up agent → do tools → return" loop.

## Verifying the install

```bash
# Should print: pong
aether --model claude-haiku-4-5-20251001 --print "Reply with the single word: pong"

# Should create the file, then read it back
aether --permission-mode bypassPermissions --print \
  "Use Write to put 'aether works' in /tmp/aether-check.txt, then Read it back"
cat /tmp/aether-check.txt
```

## Known issues

- D7 rule 06 (`lyrics_and_poems`) is over-aggressive on short-bulleted output;
  the verifier may block harmless lists. Logged for a v0.2.1 rule tuning pass.

## License

MIT OR Apache-2.0.
