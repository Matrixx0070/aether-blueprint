# aether — agentic CLI

`aether` is a code-editing agent built on Anthropic's Claude Agent SDK and the
Anthropic Messages API. It runs an explicit perceive → plan → tool-select →
execute → observe → verify loop with a built-in self-check gate and reminder
tamper-test — pipeline scaffolding most agents don't ship.

## Status: v0.11.0

Cleanup + new transport + CI surface:
- **Stripped anthropic-internal retry** (G1) — the v0.7-era 5-attempt
  retry loop inside `anthropic.rs` was double-firing with v0.10's
  canonical `RetryingProvider` wrapper (3×5 = 15 worst-case attempts).
  Removed; `RetryingProvider` is now the single retry layer.
- **MCP WebSocket transport** (G2) — `ServerConfig::Ws { url }` is no
  longer "not implemented". Connects via `tokio-tungstenite`, demuxes
  JSON-RPC responses by id like the existing SSE client. Live ws://
  round-trip UNVERIFIED (no public test MCP-over-WS server).
- **`aether doctor --json`** (G3) — structured output for CI consumers.
  Same data as the text path, stable JSON shape. Composes with `--probe`.

v0.10.0 patch:

Adds reliability + fourth cloud provider:
- **Azure AI Foundry provider** — Claude on Azure via `AZURE_AI_ENDPOINT` +
  `AZURE_AI_API_KEY`. Slugs: `azure` / `azure-foundry` / `foundry`. UNVERIFIED
  for live (no Azure creds in test env); 4 unit tests pin URL + auth shape.
- **Unified retry watchdog** — exponential backoff (1s → 2s → 4s) on 5xx /
  429 / transport errors, applied to every provider via `RetryingProvider`
  decorator at `build_provider`. Streaming intentionally NOT retried
  (partial output already emitted). Kill-switch `AETHER_NO_RETRY=1`.
- **`aether doctor --probe`** — opt-in 1-token round-trip to the active
  provider; reports latency + token counts + auth source. CI-friendly
  exit 1 on failure. Default behavior (no flag) unchanged.

v0.9.0 patch:

Closes the biggest user-visible UX gaps vs Claude Code:
- **Print mode streaming** — `aether -p` writes tokens to stdout as the model
  produces them (the REPL already streamed in v0.7.x; print mode joins it).
  `AETHER_NO_STREAM=1` falls back to buffered output for CI logs.
- **Automatic context compaction** at 80% of model window. Long sessions
  summarise the oldest history into one synthetic exchange so the next
  request fits; per-compaction usage reset acts as hysteresis. Kill-switch
  `AETHER_NO_COMPACT=1`.
- **Parallel safe-tool execution** — `Read` + `Glob` + `Grep` + `MemoryRead`
  emitted in the same turn dispatch concurrently via `join_all`. Mutating
  tools keep their original sequential slot for safety. Kill-switch
  `AETHER_NO_PARALLEL_TOOLS=1`.
- **5 new cost-estimator tests** pin `/usage` arithmetic that already
  shipped (cache reads at 10%, cache writes at 125%, per-family rates).

v0.8.0 patch: **Bedrock streaming** (AWS event-stream binary parser),
**Vertex streaming** (SSE via `:streamRawPredict`), **AWS credential provider
chain** (env → shared credentials file → IMDSv2 → ECS task role), **GCP
service-account JWT auto-refresh**, and **cross-provider security-eval sweep**
(`--provider anthropic,bedrock,vertex` comparison table).

v0.7.3 patch: **7 new gap-filling fixtures (→23 total), stability
harness (`--runs N --threshold P`), and benchmark verification.**

New fixtures cover: Python ReDoS (CWE-1333) and Jinja2 XSS (CWE-79); Java
JNDI injection (CWE-917) and Jackson polymorphic deserialization (CWE-502);
Go concurrent map race (CWE-362) and missing HTTP timeout (CWE-400); C++
use-after-free (CWE-416). `aether security-eval` gains `--runs N` (repeat
each fixture N times) and `--threshold P` (minimum pass fraction, default
1.0). Stability run: **23/23 at threshold 1.0 across 3 runs** — no flaky
fixtures; see `BENCHMARK.md` v0.7.3 section.

v0.7.2: security eval suite expanded from 7 Python fixtures to
16 across 4 languages — Java (SQLi via Statement, XXE in DocumentBuilder,
DES/ECB crypto), C++ (`strcpy` buffer overflow, format string in `printf`,
integer overflow in `malloc`), and Go (`exec.Command` injection,
`filepath.Join` traversal, HMAC signing key in source). Sonnet 4.6 detects
**16/16 at BLOCKER severity**, 5m21s total wall-clock.

v0.7.1: `aether review --kind security` and `aether security-eval` auto-route
Opus-class models (`claude-opus-*`) to Sonnet 4.6 when `--model` was not
passed explicitly. A one-line stderr notice tells the user what changed and
how to opt out (`--model claude-opus-4-7` overrides;
`AETHER_SECURITY_NO_AUTOROUTE=1` disables globally). Reason: the Anthropic
cyber-safeguards classifier truncates Opus mid-stream on the
adversarial-framing + structured-finding + classic-injection-pattern shape; on
Sonnet 4.6 the same prompt ships clean. 6 new unit tests pin the pure-function
router.

v0.7: **Security Edge** — scope-gated network tools (NetworkScan / WebProbe /
DnsLookup) for authorized engagements, tamper-evident audit log
(`~/.aether/audit.jsonl`, `prev_hash`-chained), the `aether review --kind
security` critic with structured (CWE / severity / location / why / fix)
output, STRIDE `aether threat-model`, `aether ctf` sandboxed challenge
runner, bubblewrap-backed `Sandbox` tool, and `aether security-eval` — a YAML
regression suite of seven Python fixtures (one OWASP class each: SQLi, path
traversal, hard-coded secrets, command injection, weak crypto, insecure
deserialization, SSRF). On Sonnet 4.6 the suite detects 7/7 with correct CWE
+ severity; see `BENCHMARK.md` for the head-to-head with Opus 4.7.

(v0.6: BYOC providers — AWS Bedrock SigV4 + GCP Vertex AI Bearer; `aether
doctor` per-provider auth checks. v0.5: FleetView, eval harness, session
export/branch, TUI markdown + bracketed paste, placeholder-crate cleanup.)

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

`aether` picks a provider in this order: `AETHER_PROVIDER` env, then
`settings.provider`, then `anthropic` by default.

### Anthropic (default)

1. `ANTHROPIC_API_KEY` env var
2. `CLAUDE_CODE_OAUTH_TOKEN` env var (raw Bearer)
3. `~/.claude/.credentials.json` (Claude Code OAuth, Max subscription)

OAuth tokens auto-refresh within 10 min of expiry. 401 → forced refresh +
retry. Atomic write back (`.tmp` + rename, mode 0600).

### AWS Bedrock (`AETHER_PROVIDER=bedrock`)

- `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ optional `AWS_SESSION_TOKEN`)
- `AWS_REGION` (default `us-east-1`)
- Model id is auto-translated: `claude-haiku-4-5-20251001` →
  `anthropic.claude-haiku-4-5-20251001-v1:0`. Pass-through when you already
  give a Bedrock id.
- Hand-rolled SigV4 signing (verified against AWS-published test vector)
- Non-streaming for v0.6; SSE event-stream variant in v0.6.1.

### GCP Vertex AI (`AETHER_PROVIDER=vertex`)

- `VERTEX_ACCESS_TOKEN` — get one via `gcloud auth print-access-token`
- `VERTEX_PROJECT` (or `GCLOUD_PROJECT` or `GOOGLE_CLOUD_PROJECT`)
- `VERTEX_REGION` (default `us-central1`)
- Model id is auto-translated: `claude-haiku-4-5-20251001` →
  `claude-haiku-4-5@20251001`.
- ADC / service-account auto-rotation deferred to v0.6.1 (we don't pull
  the heavy `gcp_auth` crate yet).

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

# Security edge (v0.7)
aether scope init --authorized-by alice --ticket-id ENG-123 --days 14
aether scope add-host example.com
aether scope show
aether audit show --limit 50
aether audit verify                                # hash-chain integrity
aether review --kind security path/to/file.py      # structured critic, --json for parsed
aether threat-model docs/architecture.md           # STRIDE walkthrough
aether ctf eval/security/ctf/example/              # solve a challenge in sandbox
aether security-eval eval/security/suite.yaml      # 7-fixture OWASP regression
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

### Security Edge (v0.7)

A self-contained surface for authorized security work:

- **Scope file** (`~/.aether/scope.json`) — declares hosts, CIDR ranges,
  and repos this aether process may act against. `aether scope init`
  requires `--authorized-by` + `--ticket-id` and an expiry. No scope file
  ⇒ the three scope-gated tools (`NetworkScan`, `WebProbe`, `DnsLookup`)
  do not appear in the tool registry at all. The surface stays honest.
- **Tamper-evident audit log** (`~/.aether/audit.jsonl`) — every
  scope-gated call writes a JSONL entry with `prev_hash` chaining. `aether
  audit verify` walks the chain and reports the first break, if any.
  CIDR ranges larger than /16 are rejected at `scope add-range` time.
- **`aether review --kind security`** — single-turn critic, no tools.
  Emits structured `SEVERITY / CWE / LOCATION / SUMMARY / WHY / FIX` blocks
  per issue, plus a `TOTAL:` summary line. `--json` gives parsed blocks.
  Language-specific focus lists for Rust / Python / JavaScript / Go / Java
  / C / C++ / SQL bias the critic's attention.
- **`aether threat-model`** — STRIDE walkthrough over an architecture
  spec: trust boundaries, data classes, assumptions, per-category threats
  with mitigations + residual risk, open questions.
- **`aether ctf <dir>`** — challenge runner. Reads `challenge.yaml`, mounts
  the listed files into the sandbox, and runs the agent until the model
  produces the expected flag. Sandbox uses bubblewrap (`bwrap`) with a
  read-only root and only `/work` writable.
- **`aether security-eval`** — fixture-based regression. The seven
  `eval/security/fixtures/*.py` files each plant one OWASP-class bug; the
  suite passes only if `review --kind security` flags the expected CWE at
  or above the configured minimum severity. CI-friendly: exit 1 on miss.
- **Security auto-route (v0.7.1)** — both `aether review --kind security`
  and `aether security-eval` auto-route Opus-class models to Sonnet 4.6
  when `--model` is not on the command line. The Anthropic cyber-safeguards
  classifier truncates Opus mid-stream on the structured-finding-output +
  classic-injection-code shape (see `BENCHMARK.md`); the same prompt ships
  clean on Sonnet 4.6. A one-line stderr notice fires per invocation;
  override with explicit `--model claude-opus-4-7`, disable globally with
  `AETHER_SECURITY_NO_AUTOROUTE=1`.

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

| Capability | Claude Code | aether (v0.7) |
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
| **BYOC: AWS Bedrock** | ✅ | ✅ |
| **BYOC: GCP Vertex AI** | ✅ | ✅ |
| BYOC: Foundry / Mantle | ✅ | ⬜ (v0.8) |
| Plugin system (dylib / WASM) | ✅ | ⬜ (v0.8) |
| IDE integrations | ✅ | ⬜ (v0.8) |
| **D1 reminder tamper-test (34-signal classifier)** | ⬜ | ✅ |
| **D7 self-check gate (14 rules, structural-line aware)** | ⬜ | ✅ |
| **Deterministic first-match routing (D3)** | ⬜ | ✅ |
| **Scope file + tamper-evident audit log (v0.7)** | ⬜ | ✅ |
| **`aether review --kind security` structured critic (v0.7)** | ⬜ | ✅ |
| **STRIDE `aether threat-model` (v0.7)** | ⬜ | ✅ |
| **`aether ctf` bubblewrap-sandboxed runner (v0.7)** | ⬜ | ✅ |
| **Scope-gated network tools (NetworkScan/WebProbe/DnsLookup, v0.7)** | ⬜ | ✅ |
| **`aether security-eval` OWASP-class regression (v0.7)** | ⬜ | ✅ |
| **Scanner wrappers (gitleaks / cargo-audit / osv-scanner, v0.7)** | ⬜ | ✅ |

aether ships the three Fable-5 deltas Claude Code doesn't (D1 prompt-injection
filter, D7 pre-emission gate, D3 deterministic routing) plus the entire v0.7
Security Edge surface (scope + audit + critic + STRIDE + CTF + scope-gated
network tools + OWASP regression). For everything else, v0.6 is at functional
parity on the core agent loop; v0.7 adds the security column.

## Performance

See [`BENCHMARK.md`](BENCHMARK.md). aether is consistently 2–3× faster at p50
and 2–4× faster at p95 than `claude` for the agent-loop+IO axis, across v0.1
through v0.5. v0.7 adds a new axis — the Security Edge benchmark on the
seven-fixture OWASP regression: **7/7 on Sonnet 4.6**, 2/7 on Opus 4.7
(Anthropic's cyber-safeguards classifier interferes with the latter; see
BENCHMARK.md).

## License

MIT OR Apache-2.0.
