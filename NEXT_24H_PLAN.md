# Next 24-hour autonomous plan — Plan R

Drafted at end of Plan Q (v0.20 → v0.21). Picks up the deferred items
the build env can't exercise (creds, JDK21, JetBrains marketplace),
plus the v0.22 scope items in ROADMAP.md.

---

## Plan R — enterprise hardening + close the credential-blocked UNVERIFIEDs

**MISSION**: Close the credential-shaped UNVERIFIED rows Q3/Q4/Q5 left
behind (Bedrock streaming live, JetBrains build live, Mantle sweep
live), and add the enterprise-shaped features the slice log has
flagged for a while: SSO scaffolding, signed-commit verification on
plugin manifests, multi-tenant `aether serve`.

**DONE MEANS** (6 criteria):

1. v0.22.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. Bedrock streaming UNVERIFIED row in STATUS replaced with recorded
   delta output from a real AWS profile (operator-supplied).
3. `./gradlew buildPlugin` on a host with JDK 21 + Gradle 8.10
   produces `aether-jetbrains-0.22.0.zip` that installs in IntelliJ
   2024.3+; a manual prompt→response round-trip captured in STATUS.
4. `aether security-eval --provider mantle,anthropic --runs 3
   --threshold 0.95 --json` produces a matrix JSON with both columns
   populated (operator-supplied Mantle creds).
5. New CLI `aether sso configure` writes an OIDC discovery URL +
   client_id to `~/.aether/sso.json`; `aether sso login` opens a
   browser-flow and persists a token to `~/.aether/sso.token`.
6. STATUS slice log entries R1–R6 with commit SHAs and live-check
   output (no banned vocabulary).

## Slices

### R1 — Close Q3 (Bedrock streaming live verify)

- Operator supplies AWS profile via `~/.aws/credentials`.
- Start `aether serve` with `AETHER_PROVIDER=bedrock`.
- Run the python ws-probe against the model id Bedrock's catalog
  exposes; capture frame counts.
- Promote the v0.8 + Q3 UNVERIFIED labels in STATUS to DONE.

### R2 — Close Q4 (JetBrains build live verify)

- On a JDK 21 + Gradle 8.10 host: `./gradlew buildPlugin`.
- Manual install in IntelliJ Community 2024.3.
- Round-trip an "Ask… → response" via the tool window; capture
  the panel content.

### R3 — Close Q5 (Mantle cross-provider sweep)

- Operator supplies `MANTLE_API_KEY` + `MANTLE_BASE_URL`.
- `aether security-eval --provider mantle,anthropic --runs 3
   --threshold 0.95 --json` produces a JSON matrix.

### R4 — SSO scaffolding (SAML/OIDC discovery)

- `aether sso configure` writes `~/.aether/sso.json`:
  `{ issuer, client_id, scopes?, redirect_uri }`.
- `aether sso login` opens the system browser at the OIDC
  authorization endpoint, runs a short-lived local HTTP server on
  127.0.0.1:<random> as the redirect_uri, exchanges the code for
  a token, persists it to `~/.aether/sso.token` (mode 0600).
- New env var `AETHER_REQUIRE_SSO=1` blocks REPL / print mode at
  startup unless a valid SSO token is present.
- Out of scope: actual SAML (defer to a follow-up if requested);
  OIDC is the v0.22 ship.

### R5 — Signed-commit verification on plugin manifests

- New manifest field: `commit_sha` (the git commit that built the
  plugin) + a separate detached signature over `(canonical_manifest
  ‖ commit_sha)`.
- `aether plugin verify` learns `--enforce-commit-pinned`: refuses
  the manifest if `commit_sha` is missing OR if the signature
  doesn't cover both.
- Backward compat: manifests without `commit_sha` continue to load
  in non-strict mode (warning only).

### R6 — Multi-tenant `aether serve`

- Optional tenant header `X-Aether-Tenant: <slug>` on `/ws/chat`
  + `/v1/messages` + `/v1/trust` + `/v1/rollback`.
- Trust keychain becomes per-tenant under
  `~/.aether/tenants/<slug>/plugin-trust.txt`; usage.db gets a
  `tenant` column on the `turns` and `tool_calls` tables (schema
  v2 with migration).
- Bearer-protected as today; the tenant header is informational
  only — multi-tenant ACLs are a v0.23 add.

### R7 — Self-audit + Plan S draft

- Audit R1–R6 diff against the Discipline Laws kernel.
- Draft Plan S: code-completion API endpoint, completion telemetry,
  team-shared trust keychain, security-eval coverage matrix CI gate.

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (default picked if no answer)

1. **OIDC default issuer.** Default: none — operator picks at
   `sso configure` time. Common defaults (Auth0, Okta, Google,
   Microsoft) all work; we don't bake one in.
2. **Bedrock test model id.** Default: `anthropic.claude-sonnet-4-6`
   (pick from `aws bedrock list-foundation-models`).
3. **Mantle endpoint.** Default: same as Plan P — operator overrides
   via `MANTLE_BASE_URL`.

## Risk register

- **OIDC redirect flow needs a short-lived local server.** Mitigation:
  bind 127.0.0.1:0 (kernel picks a free port); accept exactly one
  request, then shutdown.
- **Schema v2 migration for multi-tenant usage.db.** Mitigation: the
  USAGE_SCHEMA_VERSION check (introduced in O3) blocks silent
  corruption; v2 binary on v1 db = informative error, not silent
  rewrite.
- **JetBrains marketplace publish is STILL deferred.** Mitigation:
  R2 only proves the build chain works; marketplace upload is its
  own keystore dance.

---

## Q7 — self-audit on Plan Q (v0.21.0 shipping)

**Audited commits**: 0f794de (Q2), 891dd7e (Q1), 853685c (Q6), plus
the inline Q3+Q4+Q5 UNVERIFIED rows in STATUS. 3 code commits +
1 docs commit, +280 / −33 net.

### BLOCKER — none

### HIGH — none

### MED

- **Q1 rollback POST has no per-session scope** — anyone with the
  bearer token can roll back any absolute file path. Documented as
  the intended v0.21 semantic (single-machine operator); tenant
  isolation arrives in R6.
- **Q2 original_contents captured at PreToolUse phase** — a tool
  whose internal flow re-reads the file between the hook and the
  mutation could race. Edit/Write don't do that today; flagged for
  Plan S if a fancier file tool ships.
- **Q3/Q4/Q5 live verification is BLOCKED on creds/JDK21** — Plan R
  closes these the moment the operator supplies what's needed.
  Documented honestly in STATUS as DONE/UNVERIFIED.

### LOW

- **Q1 rollback path overwrite is full-file, not chunk-level** — if
  the agent's tool already moved the file (rename + edit), the
  overwrite no longer matches. Edit/Write are atomic today.
- **Q1 panel CSP widened from `connect-src ws: wss:` to also allow
  `http: https:`** — needed for the rollback fetch(). Acceptable
  for a localhost-binding `aether serve`; a multi-tenant deployment
  would tighten this back to the specific host.
- **Q2 hook fires per-tool but blocks on the executor's tx send** —
  if the receiver (WS handler) is slow, the executor stalls. The
  channel is unbounded so this is theoretical, but worth noting.
- **Q6 cosign sign-blob path is verified only when the workflow
  actually runs on GHA** — local YAML lint is necessary but not
  sufficient; the first v0.21+ release tag is the real proof.

### What worked

- **Bounded slices**: 3 code commits, each with a live-verify block
  in the commit message. Q3/Q4/Q5 explicitly documented as
  UNVERIFIED in STATUS rather than silently optimistic.
- **Plan-then-ship cadence held**: Plan Q draft from bfdc79f (P7)
  matches what shipped here, with the Q3/Q4/Q5 cred-blockers
  honestly flagged.
- **Banned-vocab discipline held** through all commits.
- **Cross-IDE protocol unification continued**: tool_use frame is
  now the same shape across the WS handler regardless of which
  editor's client consumes it.

### Diff numbers

- aether-cli:           +220 LoC (rollback handler + tool_hook
                                   refactor + listening banner)
- editor/vscode panel:   +130 LoC (Accept/Reject + postRollback
                                   + CSS + CSP widening)
- .github/workflows:     +32 LoC (cosign step + id-token perm)
- INSTALL.md:            +30 LoC (cosign verifier recipe)
- STATUS / ROADMAP / README / NEXT_24H_PLAN: +120 / -30 LoC

### Total binary delta

- aether 0.20.0 release binary on linux-x64: ~39 MB
- aether 0.21.0 release binary on linux-x64: ~39 MB (no new deps;
  only existing code paths reorganised + new HTTP handlers).
