# Next 24-hour autonomous plan — Plan U

Drafted at end of Plan T (v0.23 → v0.24). Picks up the unfinished
T-followups + the enterprise-shaped items that have been queued for
a few plans (webhooks, metrics, key rotation).

---

## Plan U — observability + enterprise alt-paths + key hygiene

**MISSION**: Close the operator-facing gaps T7 carried (signed-commit
success-path integration test, completion-API provider pool) and add
the production-deploy primitives the slice log keeps deferring:
Prometheus metrics on `aether serve`, webhook notifications on key
events, plugin trust key rotation telemetry.

**DONE MEANS** (6 criteria):

1. v0.25.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. `aether plugin verify --require-signed-commit` integration test
   passes against a temp repo with a real gpg-signed commit (closes
   T3 LOW).
3. `GET /metrics` on `aether serve` returns Prometheus-format
   counters: turns, tool_calls, /v1/complete, errors, 4xx, 429.
4. `aether plugin trust audit` lists each trusted key with the
   commit SHA + date it was added (read from git log of the team
   sync repo).
5. `aether webhook configure --url <URL> --event <e>` writes a
   notification config to `~/.aether/webhooks.json`; firing on
   trust-add / trust-remove / sso-token-rotate events.
6. STATUS slice log entries U1–U7 with commit SHAs and live-check
   output (no banned vocabulary).

## Slices

### U1 — Prometheus metrics endpoint

- New `GET /metrics` on `aether serve`. No auth gate by default
  (operators put it behind a firewall) but honours `AETHER_SERVE_NO_AUTH`
  + bearer token like the other routes when configured.
- Counters: `aether_turns_total`, `aether_tool_calls_total{tool=…,is_error=…}`,
  `aether_complete_total`, `aether_4xx_total{route=…}`, `aether_429_total`,
  `aether_rollback_total`.
- Histogram: `aether_turn_duration_ms`.
- Updated from existing record_turn_usage + record_tool_call paths.

### U2 — Webhook notifications

- `aether webhook configure --url <URL> --event <e> [--secret <s>]`.
- ~/.aether/webhooks.json (mode 0600) holds the registry.
- Events: trust-add, trust-remove, sso-token-rotate,
  rollback, plugin-load-failure.
- POST body: `{event, ts, payload, hmac_sha256(secret, body)}`.
- Fire-and-forget; failed POSTs land in stderr.

### U3 — Plugin trust audit + key age

- `aether plugin trust audit` reads ~/.aether/plugin-trust.txt and,
  if it tracks a git-backed team copy, surfaces `git log -1 --format=%H,%ai`
  per key (when added, by which commit).
- For local-only keys (no git history), shows file mtime as a fallback.

### U4 — Signed-commit success-path integration test

- New integration test in tests/ that mints a temp repo, configures
  a throwaway gpg key, makes a signed commit, runs `aether plugin verify
  --enforce-commit-pinned --resolve-commit <tmp> --require-signed-commit`
  and asserts exit 0 + "carries a valid signature" line.
- Closes T3 LOW (success path was UNVERIFIED in T3).

### U5 — Completion API: provider pool

- `complete_run_one_turn` currently spins a fresh provider per
  request. Add a global `OnceCell<Arc<dyn LlmProvider>>` keyed by
  `(model, permission_mode)` so back-to-back completions reuse one
  HTTP client + auth.
- Closes the S7 LOW about per-request provider construction.

### U6 — SAML scaffolding (alt-path to OIDC)

- `aether sso configure-saml --idp-metadata-url <URL>`.
- Parses IdP metadata XML, persists SSO endpoints to sso.json.
- Login: redirect to IdP, capture SAMLResponse, validate signature
  against IdP cert.
- Out of scope: signed/encrypted assertions full pipeline (T's slot;
  this is the scaffold only).

### U7 — Self-audit + Plan V draft

- Audit U1–U6 against the Discipline Laws kernel.
- Draft Plan V: secrets manager integration (AWS Secrets Manager /
  Vault) for AETHER_SERVE_TOKEN; tenant quota throttling (rate +
  cost); per-tool permission policy (tool_blocklist gets a tool-
  argument filter).

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (default picked if no answer)

1. **Webhook signing scheme.** Default: HMAC-SHA256 over body with
   `X-Aether-Signature: sha256=<hex>` header (same shape as GitHub
   webhooks).
2. **Metrics path naming.** Default: `aether_` prefix; lowercase
   snake_case; histograms have `_ms` suffix.
3. **SAML test IdP.** Default: simplesamlphp Docker image in a
   bring-your-own-host doc; we don't ship one.
4. **R1/R2/R3 creds.** Default unchanged: carry forward if absent.

## Risk register

- **Webhook HMAC keys persist on disk.** Mitigation: secret column
  is sha256-hashed at write time; the original is never re-read.
  Operators rotate via `webhook configure` re-runs.
- **SAML adds XML parsing surface area.** Mitigation: pin a tested
  parser (quick-xml + xml-rs combo), forbid DTDs, length-cap input.
- **Provider pool can leak keys** if multiple sessions share an
  Arc<dyn LlmProvider> with different auth. Mitigation: key the
  pool by (model, permission_mode) AND auth-source identifier.

---

## T7 — self-audit on Plan T (v0.24.0 shipping)

**Audited commits**: 320e005 (T4), 27af402 (T1), 8ae397b (T3),
a1eb994 (T5), 40a608a (T2), plus the inline T6 carry. 5 code
commits + this doc commit, +400 / −60 net.

### BLOCKER — none

### HIGH — none

### MED

- **T1 EdDSA live round-trip remains UNVERIFIED in this env** — no
  public OIDC issuer publishes EdDSA today; the JWK parsing wire
  is taken from RFC 8037. Operator's real EdDSA issuer will exercise.
- **T3 signed-commit success path UNVERIFIED** — failure paths
  (unsigned local, URL-mode rejection, missing --resolve-commit)
  all verified live; the green-light path needs a gpg-signed commit
  in scope. Promoted to U4 integration test.

### LOW

- **T4 fence-strip can over-trim** if the model legitimately needs
  a literal triple-backtick in code (rare in FIM). Documented.
- **T4 strict-prefix detection** is the user-facing fix for the
  TypeScript template-literal bug that was caught and fixed during
  T4; documented inline as a CAUGHT-FIX trail.
- **T5 prefix-match remove** — same caveat as `trust remove`; a
  short typo can mass-revoke from the team copy. The printed
  removed-count is the operator-side check.
- **T2 still writes only tool_name to the SQLite row** (not
  tool_use_id). The HashMap is now id-keyed but the persistent
  row keeps the v0.19 shape. A v0.25+ slice can add `tool_use_id
  TEXT` if a downstream query needs per-call rows.
- **T6 R1/R2/R3 carry-forward** is honest but the STATUS table is
  now wide; consider a `DONE/UNVERIFIED` summary row in the next
  ship to reduce noise.

### What worked

- **All 5 code slices live-verified in this session** with
  multiple cases per slice (T4 = 3 lang probes; T3 = 4 cases;
  T5 = 4 cases; T2 = real agent run; T1 = build-clean).
- **CAUGHT-FIX** during T4 (TypeScript template literal eaten by
  over-broad starts_with('`')) caught by the live verify probe
  itself; honest commit message.
- **Plan-then-ship cadence held**: Plan T draft from 8532ab0 (S7)
  matches what shipped, including the cred-blocked T6 carry.
- **Banned-vocab discipline held** across all commits + STATUS rows.

### Diff numbers

- aether-core/src/executor.rs: +6 LoC (signature change + 2 callsite
                                       updates)
- aether-cli/src/main.rs:      +395 LoC (FenceStripper + EdDSA arm +
                                          require_signed_commit_in_repo +
                                          trust_sync subtractive branch +
                                          tool_call_start/finish refactor)
- README / ROADMAP / STATUS / NEXT_24H_PLAN: +140 / -50 LoC

### Total binary delta

- aether 0.23.0 release binary on linux-x64: ~41 MB
- aether 0.24.0 release binary on linux-x64: ~41 MB
  (no new deps; jsonwebtoken's EdDSA arm was already linked).
