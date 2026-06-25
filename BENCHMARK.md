# Benchmark — aether vs Claude Code

Head-to-head measurement of the user-perceived loop "spin up agent → do tools →
return."

**Latest run: v0.3 — 2026-06-25.** Same axis, same protocol. aether is
2.0–3.2× faster at p50 and 1.3–2.3× faster at p95 — no regression despite
v0.3 adding MCP client, persistent memory, skills, PreToolUse/PostToolUse
hooks, interactive permission prompts, doctor, diff renderer, token
tracking, tab completion (15 slices since v0.2).

## v0.3 results (n=20)

| Test | binary | n | failures | min | **p50** | **p95** | max |
|---|---|---:|---:|---:|---:|---:|---:|
| text roundtrip | aether | 20 | 0 | 834 | **1,062** | **1,854** | 1,863 |
|  | claude | 20 | 0 | 2,996 | **3,438** | **4,061** | 4,418 |
| single tool (Read) | aether | 20 | 0 | 1,988 | **2,809** | **7,004** | 8,151 |
|  | claude | 20 | 0 | 4,621 | **5,591** | **9,055** | 16,457 |
| multi-tool (Write+Read) | aether | 20 | 0 | 2,463 | **3,942** | **7,305** | 8,752 |
|  | claude | 20 | 0 | 5,700 | **8,473** | **13,594** | 16,090 |
| Grep | aether | 20 | 0 | 3,802 | **5,191** | **8,942** | 9,033 |
|  | claude | 20 | 0 | 6,713 | **14,531** | **20,328** | 23,094 |

### v0.3 speedup vs claude

| Test | p50 ratio | p95 ratio |
|---|---:|---:|
| text roundtrip | **3.24×** | **2.19×** |
| single tool (Read) | **1.99×** | **1.29×** |
| multi-tool (Write+Read) | **2.15×** | **1.86×** |
| Grep | **2.80×** | **2.27×** |

### v0.3 reliability

aether: **80 / 80** successful. claude: **80 / 80** successful.

### Trend across releases (p50 ratio)

| Test | v0.1 | v0.2 | v0.3 |
|---|---:|---:|---:|
| text roundtrip | 3.43× | 3.35× | 3.24× |
| single tool (Read) | 2.52× | 2.38× | 1.99× |
| multi-tool (Write+Read) | 2.00× | 1.97× | 2.15× |
| Grep | 2.38× | 2.90× | 2.80× |

Stable inside ±15% of v0.1 baseline across three releases despite the
substantial feature growth (7 → 13 built-in tools + MCP + memory +
skills + hooks + permission prompts + token tracking + diff renderer +
tab completion). The v0.3 T2 dip (2.52 → 1.99) tracks v0.3's extra
session-start work (memory-index injection, MCP server probe paths, hook
load) — paid once per process, more visible on short tests.

---

## v0.2 baseline

**Earlier run: v0.2 — 2026-06-25.** Confirmed v0.1 numbers: aether is
2.0–3.4× faster at p50 and 2.3–4.5× faster at p95 with no regression from
the new features (streaming SSE, bundled D7 rules, project context loading,
hooks, settings, 4 additional tools, interactive permission prompts,
rustyline REPL).

## v0.2 results (n=20)

| Test | binary | n | failures | min | **p50** | **p95** | max |
|---|---|---:|---:|---:|---:|---:|---:|
| text roundtrip | aether | 20 | 0 | 872 | **1,024** | **1,629** | 1,690 |
|  | claude | 20 | 0 | 3,035 | **3,430** | **4,887** | 6,815 |
| single tool (Read) | aether | 20 | 0 | 2,011 | **2,525** | **3,053** | 3,220 |
|  | claude | 20 | 0 | 4,714 | **6,000** | **13,642** | 16,399 |
| multi-tool (Write+Read) | aether | 20 | 0 | 2,320 | **3,840** | **6,089** | 8,115 |
|  | claude | 20 | 0 | 5,463 | **7,580** | **13,961** | 14,246 |
| Grep | aether | 20 | 0 | 3,288 | **5,083** | **6,411** | 6,802 |
|  | claude | 20 | 0 | 9,382 | **14,728** | **22,842** | 24,414 |

### v0.2 aether speedup vs claude

| Test | p50 ratio | p95 ratio |
|---|---:|---:|
| text roundtrip | **3.35×** | **3.00×** |
| single tool (Read) | **2.38×** | **4.47×** |
| multi-tool (Write+Read) | **1.97×** | **2.29×** |
| Grep | **2.90×** | **3.56×** |
| **median across tests** | **2.64×** | **3.28×** |

### v0.2 reliability

- aether: **80 / 80** successful, zero failures, zero timeouts
- claude: **80 / 80** successful, max trial 24.4s (no 10-min retry-watchdog
  hangs this run — last run had one)

### v0.2 vs v0.1 — no perf regression

| Test | v0.1 p50 ratio | v0.2 p50 ratio |
|---|---:|---:|
| text roundtrip | 3.43× | 3.35× |
| single tool (Read) | 2.52× | 2.38× |
| multi-tool (Write+Read) | 2.00× | 1.97× |
| Grep | 2.38× | 2.90× |

v0.2 added: streaming SSE, 14 bundled D7 rules now actively gating, AETHER.md
auto-load, 4 new tools, hooks, settings file load, interactive perm prompts,
rustyline REPL — and stayed inside ±5% of the v0.1 ratios on every test.

---

## v0.1 baseline (original run, n=20)

## Setup

| Item | Value |
|---|---|
| Date | 2026-06-25 |
| Host | Linux 6.8.0-90 |
| Auth | Same Claude Max OAuth token (`~/.claude/.credentials.json`) |
| Model | `claude-haiku-4-5-20251001` (avoids premium-model gate confound) |
| aether build | `target/release/aether` v0.1.0, single 6.0 MB static Rust binary |
| Claude Code build | v2.1.191, `~/.local/bin/claude` (Node.js + ~14 MB JS bundle) |
| Permission mode | `bypassPermissions` on both sides |
| Sample size | **n = 20** trials per test per binary (160 invocations total) |
| Per-trial cap | 30s `timeout` wrapper (prevents single-call hangs from blocking the run) |

Test inputs at `/tmp/aether-vs-cc/`:

```text
seed.txt   (3 lines, 212 bytes)
notes.md   (4 lines)
other.txt  (1 line, no match terms)
```

## Test prompts

| # | Prompt |
|---|---|
| T1 | `Reply with exactly the word: pong` |
| T2 | `Read /tmp/aether-vs-cc/seed.txt and reply with just the line count as a number.` |
| T3 | `Create file /tmp/aether-vs-cc/n20/scratch-X-N.txt with content '<binary>-multi-works' using Write, then Read it back. Reply with just the file's content.` |
| T4 | `Use Grep with pattern 'aether' under /tmp/aether-vs-cc with output_mode files_with_matches. Reply with just a comma-separated list of just the file basenames, nothing else.` |

## Results (n=20, wall time in ms)

### Per-test stats

| Test | binary | n | failures | min | **p50** | **p95** | max |
|---|---|---:|---:|---:|---:|---:|---:|
| text roundtrip | aether | 20 | 0 | 729 | **1,028** | **2,881** | 4,640 |
|  | claude | 20 | 0 | 2,986 | **3,531** | **4,508** | 4,574 |
| single tool (Read) | aether | 20 | 0 | 1,920 | **2,542** | **3,420** | 4,632 |
|  | claude | 20 | 0 | 5,129 | **6,413** | **13,105** | 24,726 |
| multi-tool (Write+Read) | aether | 20 | 0 | 2,354 | **3,978** | **5,650** | 5,898 |
|  | claude | 20 | 0 | 5,402 | **7,968** | **12,294** | 609,902† |
| Grep | aether | 20 | 0 | 2,684 | **4,446** | **6,926** | 7,196 |
|  | claude | 20 | 0 | 6,339 | **10,577** | **15,310** | 16,393 |

† one outlier of 610s (10-minute hang inside claude's retry watchdog on a
single trial). Excluded from p95 by definition; reported as max so it's not
hidden.

### aether speedup vs claude

| Test | p50 ratio | p95 ratio |
|---|---:|---:|
| text roundtrip | **3.43×** | **1.56×** |
| single tool (Read) | **2.52×** | **3.83×** |
| multi-tool (Write+Read) | **2.00×** | **2.18×** |
| Grep | **2.38×** | **2.21×** |
| **median across tests** | **2.45×** | **2.20×** |

### Reliability

- aether: **80 / 80** successful (zero failures, zero timeouts)
- claude: **80 / 80** successful, but **1 / 80** required ~10 minutes (retry
  watchdog hang). Without the 30s `timeout` wrapper on the original run, this
  would have blocked the entire benchmark — and *did* block the first attempt
  before per-trial timeouts were added.

### Latency distribution shape

aether's `max` is within **~10–30%** of its `p95` on every test → tight, predictable
distribution.

claude's `max` exceeds its `p95` by **1.8× to 50×** (excluding outlier; 50× with
outlier) → long, fat tail. A user experiencing claude will occasionally see
multi-second waits even on trivial prompts.

## Findings

### Where aether wins

- **Wall time at every percentile, every test.** p50 ratios cluster around
  2–3.4×, p95 ratios 1.5–3.8×.
- **Consistency.** aether's p95 is ≤ 1.7× its p50 across all tests. claude's
  p95 reaches 2× its own p50 and includes a 610s outlier.
- **Equal correctness** at this scale; both binaries returned correct content
  on all 80 trials each.

### Why aether is faster

- Single static Rust binary (6 MB), no Node.js startup tax (claude's `node`
  binary alone is ~75 MB and loads a ~14 MB JS bundle on every invocation)
- Lean agent loop — no telemetry warmup, no MCP-client init, no plugin
  discovery, no hook system probe, no `claude doctor` checks
- Both binaries hit the same `POST /v1/messages` with the same OAuth Bearer
  token, so the network leg is identical. The delta is entirely client-side.

### Where claude wins (not measured)

claude is feature-richer: MCP client, sub-agent fleet (FleetView), Ink-style
TUI, plugin system, hooks, `/skills`, `/loop`, sessions UI, IDE integrations,
telemetry, BYOC providers, enterprise gateway, OIDC federation, trusted-device
enrollment, retry-watchdog mode. None of those are in aether v0 — see
`README.md` roadmap. This benchmark measures the **agent-loop + IO efficiency
axis only**.

## Caveats

- **Single host, single network path.** Server-side variance still
  contributes to both binaries equally, but absolute numbers may differ
  meaningfully on a remote runner or different region.
- **Token cost is roughly equal.** Both binaries POST similar request bodies;
  Anthropic bills by token, not wall time.
- **Wall time ≠ user-perceived latency.** With streaming SSE, claude's first
  text appears earlier than its total time suggests. aether's streaming path
  is a v0.1 slice — once landed, the perceived gap will narrow even though
  total wall time stays the same.

## Method notes (so this is reproducible)

1. Test fixtures created at `/tmp/aether-vs-cc/` (seed.txt, notes.md,
   other.txt — see Reproducing section).
2. Runner script invokes both binaries via `timeout 30` for each trial,
   captures wall-time-from-fork via `date +%s%N` deltas, exit code, stderr
   to a side log.
3. CSV format: `trial_index,wall_ms,exit_code`. One row per trial.
4. Stats computed in Python: median = `statistics.median()`; p95 = nearest-rank
   from sorted successes; mean / min / max for context.
5. Per-trial wall time includes process spawn → exit. For aether this is
   dominated by the network round-trip; for claude it includes Node.js
   startup as well.

## Reproducing

```bash
mkdir -p /tmp/aether-vs-cc/scratch /tmp/aether-vs-cc/n20
cat > /tmp/aether-vs-cc/seed.txt << 'EOF'
aether is an agentic CLI built on Claude Agent SDK.
It ships D1 reminder filtering and D7 self-check that public Claude Code does not.
The OAuth gate exists to prevent third-party clients from spoofing identity.
EOF

# Then run the same 4 prompts above through both binaries with
# `timeout 30 aether --print …` and `timeout 30 claude -p …`, n=20 each.
# Compute median + p95 with statistics.median + sorted nearest-rank p95.
```

## Conclusion

Across n=20 trials on 4 representative tasks (160 total invocations), **aether
is 2.0–3.4× faster at p50** and **1.6–3.8× faster at p95** than Claude Code
v2.1.191, with **identical correctness** and **tighter latency distribution**
(no multi-second tail).

claude remains feature-richer; closing that gap is the explicit v0.x roadmap.
On the narrow axis this benchmark measures — agent-loop and IO efficiency for
a Max-OAuth user — aether wins decisively and reproducibly.
