# BUG: parallel sub-agent dispatch leaves stale tool_result blocks → Anthropic 400

**Discovered:** 2026-06-27 during a real-user session (Frank, CEO)
auditing the 1153-file / 265K-LOC `sudo-ai-v4` codebase with
`aether` REPL on v0.35.0-source / v0.34.0-binary.
**Affected versions:** v0.34.0 (current published) + v0.35.0
(tag-only, unpublished). Almost certainly any version with parallel
sub-agent dispatch — feature has been in aether since at least v0.20
(IDE Task agent).
**Severity:** HIGH — makes aether unusable for any non-trivial task
that triggers parallel sub-agent dispatch (audits, refactors,
multi-file research). REPL session wedges and the only recovery is
to kill the process.

## Symptoms

1. User issues a prompt that the main agent decides to delegate to
   parallel sub-agents (typically: "audit this codebase",
   "refactor across these files", multi-area research questions).
2. Main agent emits one `tool_use` block per sub-agent dispatch.
3. Sub-agents run independently; one or more either:
   - exhausts its turn budget without producing a final reply, OR
   - errors out mid-run (network blip, model error, oom).
4. When aether's orchestration assembles the next message to send
   back to Anthropic, one or more `tool_result` blocks reference
   `tool_use_id`s that are NOT in the previous assistant message.
5. Anthropic returns HTTP 400 with:
   ```
   messages.2.content.0: unexpected `tool_use_id` found in
   `tool_result` blocks: toolu_XXX. Each `tool_result` block must
   have a corresponding `tool_use` block in the previous message.
   ```
6. REPL stays alive but the main loop wedges — the upstream error
   isn't surfaced to the user as actionable; CPU drops to 0%.
7. Process must be killed to free the terminal.

## Concrete evidence — session capture

Session file:
`/root/.aether/sessions/19f09433ecd-9b68.jsonl` (48 lines, 100KB).
Stuck REPL was PID 1591894 on pts/0, started 13:27, killed 13:54.

Three `tool_result` records at the same `ts=1782567940153`:

```jsonl
{"ts":"1782567940153","kind":"tool_result",
 "output":"(sub-agent exhausted turn budget without final reply)",
 "tool_use_id":"toolu_019qkXroMvEipJBvyinpsnJW"}

{"ts":"1782567940153","kind":"tool_result",
 "output":"tool error: io: sub-agent: llm: upstream 400: {
   \"type\":\"error\",
   \"error\":{
     \"type\":\"invalid_request_error\",
     \"message\":\"messages.2.content.0: unexpected `tool_use_id`
       found in `tool_result` blocks: toolu_01CeMEvJjrNqt18JA3eANNAY.
       Each `tool_result` block must have a corresponding
       `tool_use` block in the previous message.\"},
   \"request_id\":\"req_011CcTs3J9KNSxBpcVcauAP8\"}",
 "tool_use_id":"toolu_013mhWcpZwqi84MS6pLSb8T4","is_error":true}

{"ts":"1782567940153","kind":"tool_result",
 "output":"All evidence verified. Writing the report.\n\n# Release
 & Operational Audit — `sudo-ai-v4` ...","tool_use_id":"toolu_01CEXZDn5nxhe54uncUzj8Vi"}
```

The middle record is the upstream-API failure. The two flanking
records are the OTHER two sub-agents: one exhausted budget, one
succeeded with a 9.1KB structured audit report.

Note `toolu_01CeMEvJjrNqt18JA3eANNAY` (cited in the 400) does NOT
match any of the three top-level `tool_use_id`s — it appears to be
a sub-agent's INTERNAL tool_use that leaked into the parent thread.

## Root-cause hypothesis

When sub-agent dispatch interleaves with sub-agent INTERNAL tool
use, aether's main-loop message assembler is splicing the
sub-agent's internal `tool_result` blocks into the parent thread
without the matching `tool_use` blocks. Specifically:

- Parent message N: `assistant` with 3 `tool_use` blocks (one per
  sub-agent dispatch).
- Sub-agent A runs N tool calls internally. Sub-agent A's last
  message is a `tool_result` for ITS OWN final tool_use.
- Aether returns sub-agent A's last message AS the parent's
  tool_result for the dispatch. But the message's `tool_use_id`
  field has been replaced with sub-agent A's internal id, NOT the
  parent's dispatch id.
- Parent message N+1 sends `tool_result(tool_use_id=internal_id)`
  back to Anthropic. Anthropic checks the previous assistant
  message: no matching `tool_use` block (the parent emitted
  dispatch_id, not internal_id). 400.

The "sub-agent exhausted turn budget" path likely makes this worse
by not even producing a clean final message — aether may be
fabricating a synthetic tool_result whose tool_use_id is wrong.

## Repro recipe

1. `aether --permission-mode bypassPermissions` in a directory
   with >500 files (or pass `--cwd /path/to/large/repo`).
2. Prompt: `"Audit this codebase for the top 10 release-blocking
   issues. Cover dependencies, build config, CI, runtime behavior,
   schema migrations, observability, and error handling. Be
   thorough."`
3. Watch for the assistant to dispatch parallel sub-agents (usually
   2-4 of them).
4. Wait for the main loop to wedge. The session JSONL will contain
   the same 3-records-with-identical-ts pattern.

`--print` one-shot mode AVOIDS the bug if the prompt is tight
enough to NOT trigger sub-agent dispatch. The same audit task with
the prompt `"Find findings 6-10 in apps/ core/ ops/ only. Stay in
main loop. At most 1 sub-agent."` ran clean end-to-end —
confirmed in /tmp/sudo-ai-audit-6-10.md from this session.

## Proposed fix (Plan FF7 slice)

Three changes in `aether-cli/src/main.rs` (or wherever sub-agent
dispatch and message assembly live):

### Pre-flight validation before every Anthropic API call

Walk the message list. For every `tool_result` block in message N,
assert there's a matching `tool_use` block (same `tool_use_id`) in
message N-1. If not, BAIL with a structured error before the wire
call — don't make Anthropic catch our bug.

```rust
fn assert_tool_use_result_pairing(messages: &[Message]) -> Result<()> {
    for (i, m) in messages.iter().enumerate().skip(1) {
        let tool_use_ids_in_prev: HashSet<&str> = messages[i - 1]
            .content
            .iter()
            .filter_map(|b| match b {
                Block::ToolUse { id, .. } => Some(id.as_str()),
                _ => None,
            })
            .collect();
        for b in &m.content {
            if let Block::ToolResult { tool_use_id, .. } = b {
                if !tool_use_ids_in_prev.contains(tool_use_id.as_str()) {
                    anyhow::bail!(
                        "internal bug: tool_result block at message {} \
                         cites tool_use_id={} but previous message has \
                         no matching tool_use (ids: {:?})",
                        i, tool_use_id, tool_use_ids_in_prev
                    );
                }
            }
        }
    }
    Ok(())
}
```

### Sub-agent result mapping

When a sub-agent dispatch finishes (success or fail), aether's
orchestrator MUST construct exactly one `tool_result` block whose
`tool_use_id` equals the PARENT's dispatch tool_use_id, NOT any
sub-agent-internal id. The sub-agent's final message text becomes
the result content; the sub-agent's internal tool_use/tool_result
history stays inside the sub-agent and never leaks to the parent
thread.

### Sub-agent failure path

When a sub-agent exhausts its turn budget or errors out, the
orchestrator MUST still emit a `tool_result(tool_use_id=parent_id,
is_error=true, content="<reason>")` so the parent thread has a
balanced message. The current code path appears to either:
- emit nothing (parent has an unanswered tool_use → next API call
  errors on shape), OR
- emit a synthetic tool_result with the wrong tool_use_id (parent
  has an orphan tool_result → 400 as seen).

The dispatch tool_use_id MUST be tracked through every code path
that can terminate a sub-agent — happy path, budget exhaustion,
internal error, timeout, user cancel.

## Acceptance criteria

- Pre-flight assertion lands as a debug-only check (or as a hard
  check gated behind `AETHER_DEBUG=1`) so production runs aren't
  taxed by the walk.
- Unit tests for the three sub-agent termination paths (happy
  path / budget exhausted / internal error) all produce balanced
  message threads.
- Live smoke: rerun the same audit-large-codebase prompt against
  `/root/sudo-ai-v4` in REPL mode and confirm parallel sub-agent
  dispatch composes without 400.

## Banned phrases

This document does not use "should work" / "probably" / "likely
fixed" / "seems fine". Every claim is either an observed log
extract, a code citation, or a hypothesis labeled as such.

## Related

- Plan FF main theme: dedicated OIDC mTLS plan (NEXT_24H_PLAN.md).
- This bug becomes Plan FF slice FF7 (orchestration fix); the
  v0.36 ship slice renumbers to FF8.
- Original session file:
  `/root/.aether/sessions/19f09433ecd-9b68.jsonl`
- Successful audit (the part that survived):
  `/tmp/sudo-ai-audit-report.md` (findings 1-5)
  `/tmp/sudo-ai-audit-6-10.md` (findings 6-10, run in --print mode)
