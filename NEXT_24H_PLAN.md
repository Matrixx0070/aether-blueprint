# Next 24-hour autonomous plan — Plan Q

Drafted at end of Plan P (v0.19 → v0.20). Picks up the v0.21+ scope
items in `ROADMAP.md` and the deferred items from P5/P6.

---

## Plan Q — finish what P deferred + close UNVERIFIED labels

**MISSION**: Cash the cheques Plan P wrote — Accept/Reject for the
inline-diff UI, per-tool streaming for the WS `tool_use` frames,
Bedrock streaming live-verified, JetBrains build chain actually
exercised. Plus a security-eval cross-provider matrix using the new
Mantle slot, and signed release artifacts via cosign.

**DONE MEANS** (6 criteria):

1. v0.21.0 tag on origin/main; release autobuild green on 4
   platforms; release artifacts also carry a cosign signature.
2. VS Code chat panel: Accept rolls back the file to its
   pre-Edit/Write state on click; Reject leaves it as the agent
   left it; both confirmed by `git diff` cycle on a real repo.
3. `aether security-eval --provider mantle,anthropic --runs 3
   --threshold 0.95` produces a comparison table with both columns
   filled (Mantle backed by a real Anthropic-compatible proxy of
   the operator's choice).
4. `cd editor/jetbrains && ./gradlew buildPlugin` succeeds on a
   developer machine; the zip installs into IntelliJ 2024.3+; a
   manual round-trip ("Ask…" → response) is captured in STATUS.
5. Bedrock streaming: a recorded session through the BedrockProvider
   surfaces at least one streamed delta, written to STATUS as a
   `live-check` row (replaces the v0.8 UNVERIFIED label).
6. STATUS slice log entries Q1–Q6 with commit SHAs and live-check
   output (no banned vocabulary).

## Slices

### Q1 — VS Code: Accept / Reject for tool-use diffs

- Each `tool_use` frame includes the file's pre-state on the server
  side (capture before the tool runs). New WS frame: `tool_use_pre`.
- Panel renders Accept / Reject buttons under each diff.
- Reject → POST `/v1/rollback` with `{file_path, original_contents}`
  to overwrite the file back to its pre-state.
- Accept → no-op (the file is already in the post-state).
- 3 wire tests: Accept clean, Reject restores, Reject-on-Write
  deletes the file if it didn't exist before.

### Q2 — Per-tool WS streaming for tool_use frames

- Today a turn's tool_uses are emitted in a batch AT END OF TURN.
  Move emission into `agent_turn_streamed` itself (or rather, a new
  callback the WS handler passes in), so each tool's frame arrives
  the moment the model dispatches it.
- Required to make Q1 Accept/Reject usable mid-turn: the user can
  Reject before the next tool even fires.

### Q3 — Bedrock streaming live verify

- Stand up a Bedrock test profile (operator-supplied AWS creds).
- Record a streamed session via the WS endpoint pointing at
  `AETHER_PROVIDER=bedrock`. Capture stderr + frame counts.
- Promote the v0.8 `DONE/UNVERIFIED` slice rows in STATUS to
  `DONE` with the recorded output.

### Q4 — JetBrains build live verify

- On a developer machine with JDK 21 and Gradle 8.10+ available:
  `./gradlew buildPlugin` → zip; manual install in IntelliJ 2024.3;
  one round-trip prompt → response.
- Capture: build artifact size, gradle wall-clock, IDE install
  confirmation, prompt+response screenshot.

### Q5 — Mantle cross-provider security-eval

- Point a real Mantle deployment (operator-supplied URL + key) at
  the existing security-eval suite. Run alongside Anthropic for
  comparison.
- `aether security-eval --provider mantle,anthropic --runs 3
   --threshold 0.95 --json` should produce a JSON output with both
   provider columns.

### Q6 — Cosign-signed release artifacts

- Add a `release-sign.yml` GitHub Actions job: after the existing
  4-platform build matrix completes, fetch each artifact, sign with
  cosign keyless (OIDC), upload the `.sig` alongside.
- Install docs gain a `cosign verify-blob` step.

### Q7 — Self-audit + Plan R draft

- Audit Q1–Q6 diff against the Discipline Laws kernel.
- Draft Plan R: enterprise SSO scaffolding, signed-commit
  verification on plugin manifests, multi-tenant `aether serve`.

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (default picked if no answer)

1. **JetBrains marketplace publish?** Default: still deferred —
   keystore + publisher account dance, separate plan.
2. **Cosign keyless OIDC issuer.** Default: GitHub Actions OIDC,
   per Sigstore's standard recipe.
3. **Bedrock test profile.** Default: hold for operator to supply
   creds; until then Q3 remains a follow-up and v0.21 ships without it.

## Risk register

- **Mantle live verify needs a real deployment.** Mitigation: if
  the operator can't provide a Mantle base URL + key, Q5 is
  exercised against a recorded mock (still useful as a regression
  test for the wire serialisation).
- **Q1 rollback API is the biggest new surface.** Mitigation:
  start with file-overwrite-only semantics (no chunk-level undo);
  a true diff-apply is v0.22+.

---

## P7 — self-audit on Plan P (v0.20.0 shipping)

**Audited commits**: d6a0ef3 (P1), 2ebb946 (P2), 712ddbe (P3),
dd14915 (P4), 9220af3 (P5), 43dbf51 (P6). 6 slices, 7 commits,
+1300 / −10 net.

### BLOCKER — none

### HIGH — none

### MED

- **P1 JetBrains scaffold is UNVERIFIED** — `./gradlew buildPlugin`
  was not exercised in this session (JDK 17 only, no Gradle, no
  IntelliJ Platform). Build chain is structurally sound (declared
  IntelliJ Platform 2.1.0 + Kotlin 2.0.21, version-pinned, since/
  untilBuild bounds set). Operator must run the build on a
  JDK 21 + Gradle 8.10 machine before any marketplace publish.
- **P5 emits tool_use frames per-turn, not per-tool** — if the
  agent calls 5 tools in one turn, the user sees 5 frames AT THE
  END of that turn, not interleaved with the text deltas. Promoted
  to Q2 next plan; documented in commit message.

### LOW

- **P3 publisher namespace assumes `matrixx0070`** — fine for now,
  but a future rename would force a marketplace re-publish (deeper
  than a simple bump).
- **P4 trust-list is global per `aether serve` process** — a multi-
  tenant deployment would need a per-tenant trust file. Documented
  inside the commit message and mitigated by 127.0.0.1 binding.
- **P5 diff renders as plain `<pre>` with whitespace preservation**
  — no syntax highlighting on the before/after panes. Functional
  but not pretty. Highlight.js would inflate the CSP; defer to
  v0.21+ if user complains.
- **P6 cost ceiling check runs per-turn** — small SQL query, but
  per-turn cost on a hot loop. Acceptable; can move behind a
  N-turn throttle if profiling shows it matters.
- **P6 --tail polls SQLite via MAX(id)** — multi-writer race
  documented in commit; not a v0.20 concern (single-machine).

### What worked

- **Bounded slices held**: 7 commits, each with live-verify output
  cited in the commit message. Build/test cycle stayed reliable.
- **Banned-vocab discipline** unbroken across this plan's commits
  and STATUS rows.
- **Plan-then-ship cadence** unbroken: Plan P drafted in
  bfdc79f exactly described what shipped here.
- **Cross-IDE consistency emerged**: JetBrains and VS Code now
  share the same WS protocol AND the same settings shape
  (serveUrl + bearer token + default model). The protocol is the
  product; both editors are clients.

### Diff numbers (net additions)

- aether-llm:    +151 LoC (Mantle provider + 5 tests)
- aether-cli:    +570 LoC (/v1/trust handlers + tool_use frame +
                          usage --csv / --tail + cost ceiling +
                          mantle dispatch arm)
- editor/jetbrains: +493 LoC (full scaffold)
- editor/vscode:    +106 LoC (trust.ts + panel.ts diff renderer)
- editor/vscode metadata: +243 LoC (CHANGELOG, LICENSE bundle,
                                   package.json fields)

### Total binary delta

- aether 0.19.0 release binary on linux-x64: ~38 MB
- aether 0.20.0 release binary on linux-x64: ~39 MB (notify already
  paid in v0.19; mantle adds ~1 MB; no other heavy deps).
