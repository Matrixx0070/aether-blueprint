# Next 24-hour autonomous plan — Plan S

Drafted at end of Plan R (v0.21 → v0.22). Picks up the token-binding
follow-up R6 needs to be production-grade, plus the v0.23+ scope items
the team will want once enterprise hardening lands.

---

## Plan S — token-binding, JWT validation, tool-call telemetry

**MISSION**: Make the Plan R enterprise primitives cryptographically
enforceable. Tenants today are informational; bind each bearer to a
set of allowed tenants. SSO tokens today are presence-only; validate
the id_token signature against the issuer's jwks_uri. Push the
existing tool_calls table to actually receive data.

**DONE MEANS** (6 criteria):

1. v0.23.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. `aether serve` reads a tenant ACL file (`~/.aether/tenants.json`)
   that binds bearer → allowed tenants; a request with a tenant not
   in the bearer's set returns 403 (not 200).
3. `aether sso login` validates the returned id_token's signature
   against the discovered jwks_uri; an unsigned or wrong-key token
   refuses to persist.
4. Tool calls populate the `tool_calls` table with name + duration_ms
   + is_error per dispatch; `aether usage --by-tool` shows real
   numbers in addition to the existing turns-only stats.
5. `aether plugin verify --enforce-commit-pinned --resolve-commit
   <repo-url>` clones the repo, asserts the SHA exists, and returns
   non-zero if not.
6. STATUS slice log entries S1–S7 with commit SHAs and live-check
   output (no banned vocabulary).

## Slices

### S1 — Tenant ACL: bearer ↔ allowed-tenants

- New file `~/.aether/tenants.json` (mode 0600). Shape:
  `[ { "bearer_prefix_or_hash": "...", "allowed_tenants": ["acme", "beta"], "global": false } ]`
- The server middleware resolves the request's bearer → ACL row →
  allowed-tenants set; the X-Aether-Tenant must be in that set or
  `global=true` permits the no-tenant fallback.
- 403 with informative detail on mismatch.
- Bearer compared via constant-time eq against the configured
  prefix (avoid logging long tokens).

### S2 — JWT signature validation in `aether sso login`

- After token exchange, fetch jwks_uri (discovered in R4).
- Find the JWK matching the id_token's `kid` header.
- Verify the RS256/ES256/EdDSA signature locally; refuse to persist
  if it fails.
- Surface `iss`, `aud`, `exp` claims in `aether sso status`.

### S3 — `tool_calls` table writers

- Hook a `Post`-phase tool_hook in the print/REPL/serve paths
  that captures `(name, duration_ms, is_error)` and inserts into
  the v0.22 `tool_calls` table. Tenant column populated from
  X-Aether-Tenant on serve paths.
- `aether usage --by-tool` is already wired; it'll start emitting
  real columns the moment data lands.

### S4 — `aether plugin verify --resolve-commit <repo>`

- Operator passes a repo URL (or local path); CLI shallow-clones
  with `git fetch <sha>` and exits non-zero if the SHA doesn't
  resolve.
- Out of scope: full clone (the SHA-only fetch is enough for proof);
  signature on the commit itself (Plan T).

### S5 — Code-completion API endpoint

- New `POST /v1/complete` taking `{file_path, cursor_offset, ...}`,
  forwarding to the agent loop with a tightly-scoped prompt, and
  returning completion deltas as Server-Sent Events.
- Same bearer + tenant gates as /ws/chat.

### S6 — Team-shared trust keychain (git-backed)

- `aether plugin trust sync --remote <git-url>` pulls a
  team-curated keychain to the local trust list (additive only).
- `--push` requires write access to the remote; uses git's normal
  identity. No new secret storage.

### S7 — Self-audit + Plan T draft

- Audit S1–S6 against the Discipline Laws kernel.
- Draft Plan T: signed-commit on plugin manifests (commit signature
  via cosign), security-eval cross-provider CI gate (Mantle + Bedrock
  + Anthropic), VS Code marketplace publish.

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (default picked if no answer)

1. **Tenant ACL bearer match — prefix or hash?** Default: hash
   (sha256 of the bearer) to avoid storing the full secret on disk.
2. **JWT signature algorithms supported.** Default: RS256 + ES256;
   EdDSA added if a real issuer demands it.
3. **Bedrock / JetBrains / Mantle creds.** Default unchanged: carry
   the R1/R2/R3 UNVERIFIED labels into Plan T if not supplied.

## Risk register

- **Tenant ACL format change.** Mitigation: prefix the JSON with a
  `version` field so a v2 format can ship without silent breakage;
  the file is small (~tens of entries), not a SQLite table.
- **JWT validation pulls a new dependency** (`jsonwebtoken` is
  already in workspace deps from the v0.7 cred-chain work — confirm
  this in S2). Mitigation: reuse the existing dep.
- **Code-completion API** broadens the agent attack surface. Mitigation:
  shape the prompt server-side so the LLM treats input as inert
  context, never as instructions.

---

## R7 — self-audit on Plan R (v0.22.0 shipping)

**Audited commits**: eb57ae7 (R4), de2a60f (R5), d5b1273 (R6), plus
the inline R1/R2/R3 carries in STATUS. 3 code commits + this doc
update, +617 / −29 net.

### BLOCKER — none

### HIGH — none

### MED

- **R4 token presence-only gate** — `AETHER_REQUIRE_SSO=1` blocks
  on the FILE existing + non-empty, not on cryptographic validity.
  A user could write any non-empty file to ~/.aether/sso.token
  and pass the gate. Documented as the v0.22 contract; JWT
  validation lands in Plan S2.
- **R6 tenant-id is informational** — the bearer token isn't bound
  to a tenant set. Anyone with the global bearer can address any
  tenant's keychain. Documented; bearer ↔ tenants binding is
  Plan S1.

### LOW

- **R4 token persistence is unencrypted at rest** — relies on
  Unix mode 0600 + filesystem isolation. Acceptable for v0.22's
  single-machine operator; a future slice could wrap with the OS
  keystore (macOS Keychain, gnome-keyring, DPAPI). Linux servers
  generally don't have a desktop keystore — file mode is the
  pragmatic floor.
- **R5 commit_sha is opaque to the verifier** — it isn't validated
  against an actual repo. Promoted to Plan S4 with `--resolve-commit`.
- **R6 schema v1 → v2 migration is non-reversible** — operators
  downgrading to v0.21- after running v0.22 will hit the
  newer-than-binary error from O3. Documented in the commit
  message; not a concern in normal upgrade flow.
- **R6 tenant_idx covers `tenant` only** — a per-tenant per-day
  rollup query won't hit a composite index. Acceptable for the
  v0.22 row volumes; revisit if a fleet deployment makes it hot.

### What worked

- **Bounded slices held**: 3 code commits, each live-verified.
- **Banned-vocab discipline held** through commit messages and
  STATUS rows.
- **Honest UNVERIFIED labelling**: Q3/Q4/Q5 → R1/R2/R3 carried
  forward with no false claims of progress.
- **Plan-then-ship cadence held**: Plan R draft from 89bf565 (Q7)
  matches what shipped.

### Diff numbers

- aether-cli:        +470 LoC (SSO + sso_cmd + extract_tenant +
                                tenant-aware trust handlers +
                                schema v2 migration with PRAGMA-
                                aware ALTER TABLE)
- aether-plugin:     +50 LoC (trust_keychain_path_for +
                              load_trust_keychain_for + slug
                              validation)
- aether-plugin (manifest): +9 LoC (commit_sha field)
- README / ROADMAP / STATUS / NEXT_24H_PLAN: +130 / -30 LoC

### Total binary delta

- aether 0.21.0 release binary on linux-x64: ~39 MB
- aether 0.22.0 release binary on linux-x64: ~40 MB (reqwest +
  base64 + sha2 + rand_core were already workspace deps used
  elsewhere; the SSO code adds ~500 KB of monomorphisation).
