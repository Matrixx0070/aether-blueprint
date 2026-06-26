# Next 24-hour autonomous plan — Plan O

Drafted at end of Plan N (v0.17 → v0.18). Picks up the v0.19+ scope items
in `ROADMAP.md` and the LOW findings from N7 self-audit.

---

## Plan O — executor-level policy enforcement + cost transparency

**MISSION**: Close the v0.18 gap that `tool_blocklist` /
`max_tokens_per_turn` are parsed-but-not-enforced. Ship a real cost
dashboard so operators can answer "what did we spend last week, on
what models, on what tools?" without grepping JSONL by hand.

**DONE MEANS** (6 criteria):

1. **Tool-blocklist enforced at executor dispatch**. Every tool call
   passes through `policy_allows_tool(name)` before reaching the
   registry. A blocked tool returns `ToolError::PermissionDenied(...)`
   with the policy file's path in the message. Audit chain records
   the refusal as a separate entry kind. 4 unit tests including
   "agent calls blocked tool then routes around it".
2. **`max_tokens_per_turn` enforced** at `Session::new` — cap kicks
   in before the LLM call, not after. Live-verified against a long
   prompt that would otherwise exceed.
3. **`aether usage` command** with three flag families:
   - `--days N`: filter to the last N days (default 7)
   - `--by-model`: group cost by `session.usage_total.model`
   - `--by-tool`: group invocations by tool name
   Sources data from a new SQLite at `~/.aether/usage.db` populated
   by a hook on every agent_turn finish.
4. **inotify-based audit tail** replaces the 500ms poll on Linux
   (poll fallback on macOS / where `inotify_init` isn't available).
5. **Asymmetric plugin keychain** — `aether plugin trust <pub>`
   appends to `~/.aether/plugin-trust.txt`; `discover_plugins()`
   accepts a manifest signed by ANY listed pubkey, not just one
   `$AETHER_PLUGIN_ED25519_PUBKEY`. v0.19 = poor-man's
   marketplace.
6. **v0.19.0 binary release** shipped + verified, all 4 platforms.

**ASSUMPTIONS** (defaults picked):

- SQLite via `rusqlite` (bundled feature). Adds ~1.5MB binary but
  is the standard Rust stdlib for embedded analytics. Live cost
  dashboard wouldn't be sane without indexed queries.
- inotify via `notify` crate, Linux only; macOS falls back to the
  existing poll loop without a separate code path.
- `~/.aether/usage.db` schema is internal — operators query via
  `aether usage`, not direct SQL. Schema can change between minor
  versions without notice.
- Plugin trust file is line-delimited hex pubkeys. Comments allowed
  with `#`. No revocation list yet.

**NON-GOALS** (explicitly out):

- Distributed audit forwarding (kafka, kinesis). Per-host syslog
  already shipped in N3.
- Cost dashboard web UI. CLI table output is the v0.19 surface.
- Plugin marketplace UI / hosting (just the trust primitive).
- JetBrains plugin (still slated for Plan P).
- Mantle BYOC (slated for Plan P).

**Phase breakdown** (~24h):

| Phase | Time | Slices |
|-------|------|--------|
| **O1**: tool-blocklist in executor | 4h | wire `policy_allows_tool` into `Executor::execute_call`, refuse-error variant, audit entry, 4 unit tests + agent-loop integration test |
| **O2**: max_tokens_per_turn cap | 2h | apply at Session::new, live verify with a 100k-char prompt that gets truncated to the cap |
| **O3**: usage SQLite + `aether usage` | 8h | rusqlite dep, schema (`turns(ts, model, in, out, cache_w, cache_r, cost, session_id)`, `tool_calls(ts, tool, dur_ms, session_id)`), per-turn writer hook, `usage` subcommand with three group-by modes, 5 unit tests |
| **O4**: inotify audit tail | 3h | notify crate dep, Linux backend, macOS poll fallback, smoke test |
| **O5**: plugin trust keychain | 3h | trust file at `~/.aether/plugin-trust.txt`, `aether plugin trust` subcommand, `discover_plugins` accepts ANY listed pubkey, 3 unit tests |
| **O6**: ship v0.19.0 | 2h | bump + tag + autobuild + install verify |
| **O7**: self-audit + Plan P | 2h | LOW/MEDIUM scan, Plan P draft (JetBrains + Mantle + something) |

**API budget**: $2-3 for live verification round-trips. Most slices
have no LLM cost.

**WEAKEST POINT**:

O3 — SQLite schema design. Once shipped, schema changes are user-
breaking. Mitigation: ship `~/.aether/usage.db` as v1 with a
`schema_version` row that future versions check; `aether usage` errors
informatively on schema mismatch instead of silently misreading.

**Failure modes to catch via self-audit**:

- Tool-blocklist that the agent can bypass via `AgentTool` (sub-agent
  inherits parent's tool registry). Wire blocklist into
  AgentTool::new's registry filter.
- `max_tokens_per_turn` cap that breaks streaming mid-response
  (cap should refuse before LLM call, not truncate mid-stream).
- Usage writer that blocks the agent loop on disk I/O. Use a
  channel + background thread.
- inotify on a path that doesn't exist yet (first audit entry).
  Watch the dir, not the file.
- Plugin trust file with embedded newlines / non-hex content —
  reject with line number in error message.

---

## Pre-flight checklist

1. `git status` — clean tree?
2. `git log -5 --oneline` — last commit is v0.18.0 docs?
3. `cargo test --workspace` — green (1 #[ignore]'d perf microbench)
4. `gh release view v0.18.0` — confirm binary live
5. Re-read this file + the previous session's `wiki/hot.md` entry

---

## Candidate plans for 24h after Plan O

- **Plan P** (cross-IDE matrix): JetBrains plugin (Kotlin), Mantle
  BYOC provider, VS Code marketplace publish.
- **Plan Q** (research artifact): SWE-Bench-Lite submission with
  aether's numbers + harness description published as a technical
  report.
- **Plan R** (cost optimization): cache-aware retry, partial-stream
  resume, sub-agent fan-out for parallel codebase analysis.
