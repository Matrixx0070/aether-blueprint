# aether — agentic CLI

`aether` is a code-editing agent built on Anthropic's Claude Agent SDK and the
Anthropic Messages API. It runs an explicit perceive → plan → tool-select →
execute → observe → verify loop with a built-in self-check gate and reminder
tamper-test — pipeline scaffolding most agents don't ship.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Matrixx0070/aether-blueprint/main/install.sh | bash
```

Pin a version or install location:

```sh
AETHER_VERSION=v0.12.0 AETHER_PREFIX=/usr/local \
  curl -fsSL https://raw.githubusercontent.com/Matrixx0070/aether-blueprint/main/install.sh | bash
```

Supported platforms: Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64.
Each tarball ships with a SHA256 the script verifies before extraction. See
`INSTALL.md` for the manual download + verify path and the source-build
fallback.

## Status: v0.21.0

Plan Q shipped six finish-what-P-deferred features + cosign signing (24h autonomous run):

- **Q2 per-tool WS streaming** — the chat panel sees a `tool_use`
  frame the instant the agent dispatches each tool, with the
  file's pre-state captured for Edit/Write. Replaces the v0.20
  end-of-turn batch.
- **Q1 Accept / Reject for inline tool diffs** — new
  `POST /v1/rollback` route + VS Code Accept / Reject buttons
  under each Edit/Write diff. Reject deletes new files or
  overwrites with the captured pre-state.
- **Q3 Bedrock streaming** — smoke verified; live round-trip
  remains UNVERIFIED pending operator AWS credentials.
- **Q4 JetBrains build** — scaffold validated; `./gradlew
  buildPlugin` remains UNVERIFIED pending JDK 21 + Gradle host.
- **Q5 Mantle cross-provider sweep** — smoke verified; live
  security-eval matrix remains UNVERIFIED pending Mantle creds.
- **Q6 cosign-keyless signed releases** — `SHA256SUMS` is signed
  via Sigstore + GitHub OIDC; `.sig` + `.pem` ride each release.
  `cosign verify-blob` recipe in INSTALL.md.

Plan P shipped six cross-IDE + remote-BYOC features (24h autonomous run):

- **P1 JetBrains plugin scaffold** at `editor/jetbrains/` — Kotlin /
  Gradle / IntelliJ Platform 2024.3. Tool window, WS streaming to
  `aether serve`, settings panel, Ctrl/Cmd+Alt+A keymap.
- **P2 Mantle BYOC provider** — 5th LLM provider in `aether-llm`.
  Anthropic-Messages-API-compatible HTTP proxy; `MANTLE_API_KEY`
  + optional `MANTLE_BASE_URL`. 5 unit tests.
- **P3 VS Code marketplace publish prep** — `editor/vscode/` gains
  the marketplace metadata (repository / homepage / bugs / keywords),
  bundled Apache LICENSE, CHANGELOG. `vsce package` produces a clean
  `aether-0.20.0.vsix` (9 files, 18.65 KB).
- **P4 `/v1/trust` routes + VS Code trust UI** — server-side
  bearer-protected REST CRUD for the ed25519 plugin trust keychain;
  client-side webview that lists / adds / removes keys.
- **P5 inline tool-use diffs in the VS Code chat panel** — server
  WS handler emits a `tool_use` frame per tool the agent invokes;
  panel renders an inline two-pane "before / after" diff for Edit /
  Write or a labelled entry for any other tool.
- **P6 usage dashboard QoL** — `aether usage --csv` (RFC4180), `--tail`
  (live stream of new turn rows via notify), `AETHER_COST_CEILING_USD`
  warn-once when 24h cumulative cost crosses a threshold.

Plan O shipped five executor-policy + cost-transparency features (24h autonomous run):

- **O1 tool-blocklist enforced at executor dispatch** — `Executor`
  carries the policy blocklist; the dispatch path returns a structured
  refusal BEFORE the permission check fires, so `bypassPermissions`
  cannot override the operator policy.
- **O2 apply_policy_to_session()** — every `Session::new` site (print,
  REPL, TUI, HTTP `/v1/messages`, WS `/ws/chat`, sub-agents) pulls
  `tool_blocklist` and `max_tokens_per_turn` from `~/.aether/policy.json`
  and applies them at construction time.
- **O3 `aether usage` cost dashboard** — SQLite-backed,
  `~/.aether/usage.db`. Versioned schema; informative version-mismatch
  error on binary/db skew. Reader:
  `aether usage [--days N] [--by-model] [--by-tool] [--json]`.
  Writers fire in every agent path; `AETHER_NO_USAGE_DB=1` opts out.
- **O4 inotify-based audit tail** — `audit tail --follow` now uses
  the `notify` crate (inotify Linux, kqueue macOS, RDCW Windows).
  Watches the parent dir so log rotations don't lose the subscription;
  2-second timeout doubles as rotation safety.
- **O5 plugin trust keychain** — `~/.aether/plugin-trust.txt` holds
  one hex ed25519 public key per line. `aether plugin trust
  list/add/remove`. `discover_plugins()` accepts any listed key for
  ed25519 manifests; `AETHER_PLUGIN_ED25519_PUBKEY` still works.

Plan N shipped five production-posture features (24h autonomous run):

- **N1 ed25519 asymmetric plugin signing** — sister to the v0.17 HMAC
  path; manifest `algorithm` field dispatches between them. New
  `aether plugin keypair` generates an ed25519 keypair pair; `sign`
  accepts `--algorithm ed25519 --private-key <FILE>`; `verify` accepts
  `--public-key <FILE>`. Discovery checks against
  `AETHER_PLUGIN_ED25519_PUBKEY`. Trust model uplift: plugin marketplaces
  are now feasible (publisher signs with private key, consumers verify
  with public key alone).
- **N2 token-bucket rate limit** on `/v1/messages` + `/ws/chat`. Per-IP,
  in-memory; `AETHER_SERVE_RATE_LIMIT_RPM` (default 60). 429 with
  `Retry-After`. `X-Forwarded-For` honoured.
- **N3 audit-log syslog forwarding** + `aether audit tail [--follow]`.
  When `AETHER_AUDIT_SYSLOG=1`, each JSONL entry tees to syslog with
  facility LOG_USER. `aether audit tail` is operator-friendly with
  poll-based follow.
- **N4 per-org policy file** at `~/.aether/policy.json`.
  `model_allowlist` enforced at boot; `tool_blocklist` +
  `max_tokens_per_turn` stored for v0.19 enforcement. Path overridable
  via `AETHER_POLICY_FILE`.
- **N5 concurrent-session cap** on `aether serve` via
  `AETHER_SERVE_MAX_SESSIONS` (default 32). 503 with `Retry-After: 5`
  past the cap. RAII guards so panics still release slots.

Plan M shipped five hardening / surface upgrades (24h autonomous run):

- **M1 WASM-sandboxed plugin loader** — new `aether-plugin-wasm` crate
  via wasmtime + WASI preview1. Sister loader to the v0.16 subprocess
  plugins; both coexist via the manifest `runtime` field. 64 MiB memory
  cap, 30 s wall-clock timeout, no network, no filesystem except
  manifest-declared `allow_dirs`.
- **M2 Example WASM plugin** at `editor/wasm-plugin-example/` — 50-line
  Rust source → 47 KB optimised .wasm, zero deps.
- **M3 WS bearer-token auth** on `/ws/chat` — `AETHER_SERVE_TOKEN`
  required; constant-time comparison; 401 on mismatch. Kill-switch
  `AETHER_SERVE_NO_AUTH=1`.
- **M4 VS Code multi-turn webview panel** — `aether: Open chat panel`
  command connects to `aether serve` over WS, renders streamed deltas
  as Markdown, shows per-turn token + cost. Vanilla JS + markdown-it
  from CDN under a strict CSP.
- **M5 Plugin HMAC-SHA256 signing** — opt-in tamper detection for
  plugin manifests. `aether plugin sign / verify` subcommands; agent
  startup verifies signatures against `AETHER_PLUGIN_HMAC_KEY` when
  set; unsigned plugins still load by default (warning) or refuse
  loading with `AETHER_PLUGIN_ENFORCE_SIGNING=1`.

Plan L shipped four new surfaces (24h autonomous run):

- **L1 WebSocket chat endpoint** on `aether serve` — `GET /ws/chat`
  streams agent text deltas as JSON frames; live-verified Haiku
  round-trip (`Pong`, $0.0025).
- **L2 VS Code extension skeleton** in `editor/vscode/` — 3 commands
  (Ask / Ask about selection / Doctor), 3 settings, compiles clean
  (`tsc -p .`).
- **L3 Multi-turn coding tasks** — 3 new fixtures with deliberately
  ambiguous prompts; agent must commit to a design choice AND
  document the assumption. Live: **3/3 PASS, $0.61** on Sonnet 4.6
  (chose half-up rounding, score-DESC sort, LRU caching — each with
  rationale).
- **L4 Subprocess plugin loader** in a new `aether-plugin` crate —
  manifests at `~/.aether/plugins/<name>/manifest.json` expose
  user-supplied tools to the LLM. Live end-to-end verified: agent
  called a shell-script plugin and quoted its output back.

**Coding benchmark v3**: `aether coding-eval` produces **30/30 PASS
across 2 independent runs** on **15 real coding tasks across 9
languages** (Python, Rust, JavaScript, TypeScript, Go, Bash, Java,
Dockerfile, SQL). Task categories: bug fix, feature add, write tests,
refactor, doc fix, security patch (XSS+SQLi), perf optimization,
multi-file dedup, type honesty, nil-deref hardening, container
hardening. Each run ~$2.18-$2.45 on Sonnet 4.6, ~9-10 min wall.

**K1 measurement-gap fix** (v0.15): `aether -p` now emits the
`[aether-usage ...]` line even when the agent loop errors mid-run.
Previously 4/10 tasks reported in=0/out=0 — verified resolved
(task 04 now reports $0.25 vs $0.00 before).

v0.14.0 — coding benchmark v2 (10 tasks, 4 languages).

**Coding benchmark v2**: `aether coding-eval` produces **10/10 PASS** on
10 real coding tasks across **4 languages** (Python ×7 + Rust ×1 +
JavaScript ×1 + SQL+Python ×1) for ~$1.12 USD on Sonnet 4.6, 388s total
agent wall. Tasks include: binary-search bug fix in Rust, HTML-escape
XSS fix in Node.js, parameterized-query SQL injection patch, multi-file
duplication refactor extracting a shared `pricing` module, and an
O(n²) → O(n) `dedup` perf optimization verified by 50k-element timing
assertion.

v0.13.0 — initial 5-task coding benchmark. Full per-task table
and honest comparison vs Claude Code at
[`eval/coding/RESULTS.md`](eval/coding/RESULTS.md) and
[`eval/coding/COMPARISON.md`](eval/coding/COMPARISON.md).

The benchmark is reproducible: `cargo build --release -p aether-cli`,
then `./target/release/aether coding-eval eval/coding/suite.yaml`.
Each verify.sh tests observable behavior via exit code — no model
judgment in the verification loop.

v0.12.0 patch:

Ship-ready release infrastructure:
- **GitHub Actions release workflow** (H1) — tag a `v*` to autobuild release
  binaries for 4 platforms (linux-x86_64, linux-aarch64, macos-x86_64,
  macos-aarch64). Tarballs + SHA256SUMS attached to the matching GitHub
  Release automatically.
- **One-liner install** (H2) — `install.sh` detects platform, downloads
  from latest release, verifies SHA256, installs to `~/.local/bin/aether`
  (or `$AETHER_PREFIX/bin`). See `INSTALL.md` for the manual + source-build
  paths.
- **LICENSE (Apache-2.0)** — single canonical `LICENSE` at repo root,
  bundled into every release tarball. (Earlier dual-license declaration
  in `Cargo.toml` was narrowed to `Apache-2.0` only for shipping.)

v0.11.0 patch:

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
