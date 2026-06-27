# Next 24-hour autonomous plan — Plan EE

Drafted at end of Plan DD (v0.33 → v0.34). Plan DD closed the LAST
documented Plan-CC weakest-points: DD4 EdDSA SAML verifier (closes
CC6), DD5 SAML validUntil staleness (closes CC4 follow-up), DD6
OIDC clock-skew detection (closes CC5). The full AA→BB→CC→DD
remediation chain across the three orthogonal SSO lanes
(AuthnRequest signing+verify, SAML metadata lifecycle, OIDC token
refresh) is now complete.

**Closure-chain status:**
  - AA4 unsigned AuthnRequest → BB4 RSA sign → CC6 EdDSA sign →
    **DD4 EdDSA verify** ✓
  - AA5-followup discovery → BB6 refresh-saml → CC4 drift detection →
    **DD5 validUntil staleness** ✓
  - AA6 no userinfo → BB5 reactive refresh → CC5 proactive refresh →
    **DD6 clock-skew detection** ✓

Plan EE recalibrates. The "close every documented weakest-point"
phase ended at DD. The chronic four-plan deferrals (OIDC mTLS +
tenant SCIM) become the natural next scope. Cred-blocked BYOC work
continues to carry forward.

---

## Plan EE — long-deferred enterprise plumbing + housekeeping

**MISSION**: Land the chronic four-plan deferrals (mTLS + SCIM),
close the recurring STATUS-row placeholder pattern with a pre-tag
CI check, and pick up two of the DD weakest-points
(cacheDuration + Ed448) as smaller fillers.

**DONE MEANS** (8 criteria):

1. v0.35.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. EE1 Bedrock LIVE round-trip — real AWS creds, single 1-token
   call returns `usage > 0`.
3. EE2 OIDC mTLS client auth wired into `sso configure` + `sso
   login`; live smoke against an mTLS-requiring fake IdP.
4. EE3 `/v1/scim/Users` CRUD endpoints reusing `tenant_acl.db`;
   `aether tenant scim-grant` + bearer-protected serve route.
5. EE4 `tests/check-status-no-placeholders.sh` invoked from a
   pre-tag CI step; the script refuses tag-push when STATUS.md
   contains the `(this commit)` literal.
6. EE5 `cacheDuration` parsed from metadata and used as the
   refresh-interval default when `AETHER_SAML_METADATA_REFRESH_
   INTERVAL_SECS` is unset.
7. EE6 Ed448 verify path added alongside Ed25519 in DD4's algorithm
   dispatch.
8. STATUS slice rows EE1–EE7 with commit SHAs + live-verify
   excerpts. No banned vocabulary.

## Slices

### EE1 — Bedrock live round-trip (cred-blocked, sixth-plan
carry-forward)

- User provides real AWS creds + region. Unset
  `AETHER_BEDROCK_ENDPOINT`. Run `aether doctor --probe --provider
  bedrock`.

### EE2 — OIDC mTLS client auth (RFC 8705)

- Deferred since Plan BB. Some high-assurance OAuth deployments
  (financial-grade, banking APIs) require the client to present a
  TLS certificate on every token endpoint POST. The cert is bound
  to the issued tokens via the `cnf.x5t#S256` claim.
- New `sso configure-mtls --cert <pem> --key <pem>` subcommand;
  persists paths in sso.json.
- Modify the reqwest client in `sso_login` + `refresh_oauth_
  access_token` to load the cert+key via `Identity::from_pkcs8_pem`
  when configured. Same path for token endpoint and introspection.
- Optional `cnf.x5t#S256` claim verification on the id_token.
- Live smoke: fake IdP that rejects token endpoint calls without
  the client cert; aether's configured cert is required for
  success.

### EE3 — Tenant SCIM provisioning

- Deferred since Plan BB. SCIM 2.0 `/v1/scim/Users` CRUD reusing
  `tenant_acl.db` so SCIM users are real bearer-holders.
- New CLI: `aether tenant scim-grant --bearer <token>` + the
  existing `tenant grant` flow.
- New serve routes: GET / POST / PATCH / DELETE `/v1/scim/Users`,
  gated by `AETHER_SCIM_BEARER` (separate from
  `AETHER_SERVE_TOKEN` so SCIM operations can be granted to a
  different identity than agent operations).
- Live smoke: fake SCIM client provisions a user → aether grants
  the bearer; deprovisions → bearer revoked.

### EE4 — Pre-tag CI placeholder check

- Closes the chronic STATUS-row pattern that's appeared in Y7 /
  Z7 / AA7 / BB7 / CC7 / DD7 (six successive ship slices needing
  a follow-up backfill commit because the SHA didn't exist at
  commit time).
- New `tests/check-status-no-placeholders.sh`: greps STATUS.md
  for the literal `(this commit)`, exits 1 when found.
- Wired into the GitHub Actions release workflow as a job that
  runs before tag-validation. Refuses to publish a release if
  STATUS.md still has placeholders.

### EE5 — SAML metadata cacheDuration support

- Closes the DD5 weakest-point. Honor `<md:EntityDescriptor
  cacheDuration="P1D" validUntil="…">` per saml-metadata-2.0
  §2.3.2 as the default refresh-interval hint.
- Parse the xsd:duration attribute (P1D = 1 day, PT1H = 1 hour,
  etc.) into seconds.
- When `AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS` is unset AND
  cacheDuration is present, use it instead of the 3600s default.
  Env var still wins when set.

### EE6 — Ed448 SAML verify path

- Closes the DD4 weakest-point. Add OID 1.3.101.113 + 57-byte
  SPKI + Ed448 verify primitive.
- Likely via `ed448-goldilocks` crate (or a similar pure-Rust
  Ed448 implementation).
- Live smoke extension.

### EE7 — Plan EE wrap-up

- Version bump + ROADMAP + STATUS + Plan FF draft + tag + ship.
- The pre-tag placeholder check (EE4) MUST be installed before
  this slice runs, so EE7 is the first ship where STATUS.md
  cannot land with the chicken-and-egg placeholder.

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (defaults picked)

1. **EE2 token-binding scope.** Default: persist cert path in
   sso.json; aether reloads on every token POST so cert rotation
   without re-running `sso configure-mtls`.
2. **EE3 SCIM bearer vs serve token.** Default: separate env vars
   so SCIM admin can be distinct from agent operator.
3. **EE6 Ed448 crate selection.** Default: try
   `ed448-goldilocks` first; fall back to whatever pure-Rust
   implementation has the most stars + active maintenance.

## Risk register

- **Marketplace activation latency** — EE1 may carry forward
  again. After six plans, candidate to retire from the carry-
  forward and just document the env vars needed.
- **EE2 cert rotation race** — if the operator rotates the cert
  on disk while a refresh is in flight, the next call could pick
  up a half-written cert. Mitigation: read cert into memory at
  invocation time; document atomic-rename convention.
- **EE4 false positives** — a commit message that legitimately
  uses the string `(this commit)` would trigger the script.
  Acceptable: that string is rare outside the placeholder pattern,
  and the script can be skipped with an env var if needed.
- **EE6 ed448-goldilocks audit gap** — Ed448 is far less battle-
  tested than Ed25519. Document the trust assumption explicitly.

---

## Pre-EE context — Plan DD self-audit (v0.34.0 shipping)

**Audited commits**: d9b95b5 (DD4), 4a25cac (DD5), 9b29306 (DD6),
plus this version-bump commit.

### Closure milestone — complete

The AA→BB→CC→DD chain is now fully closed across all three lanes
(see ROADMAP entry). Any remaining work is recalibrated scope
(deferred plumbing, smaller hygiene), not weakest-point closure.

### BLOCKERs — none

All three shipped Plan DD slices ship with all spec gates closed.

### HIGHs — none

### MEDs — documented and carried

- DD4 SP signer supports Ed25519 but not Ed448. Real-world EdDSA
  AuthnRequest usage is overwhelmingly Ed25519; Ed448 deferred to
  EE6.
- DD5 cacheDuration not parsed. EE5 honors it as the
  refresh-interval hint when present.
- DD6 skew recorded at /token POST time, not refreshed on every
  whoami. A future slice could add a HEAD-against-token_endpoint
  refresh path; not currently planned.

### LOWs — knowingly carried

- DD4 algorithm gate is RSA-SHA256 OR EdDSA only. RSA-PSS,
  ECDSA-with-SHA-2 not accepted. Real-world IdP usage of these
  for SAML signing is essentially nonexistent.
- DD5 validity-check uses `>=` for the boundary instant (expired
  at exactly valid_until). Conservative; the spec leaves the
  inclusive-vs-exclusive interpretation up to deployments.
- DD6 sidecar is single ASCII integer. Could be a JSON-typed
  structure with timestamp + skew but the simpler form is
  greppable.

### What worked

- **All 3 shipped Plan DD slices live-verified end-to-end** in
  this session. Each with a dedicated Python fake-IdP smoke that
  walks the new code path 5-6 steps deep.
- **DD6 mid-development Python `http.server` Date-header bug
  caught by the smoke** — the framework's auto-added Date was
  shadowing the offset injection. The bug-and-fix is exactly the
  reason this pattern keeps catching real issues.
- **The closure milestone is real and complete.** Every documented
  weakest-point Plan AA through Plan CC raised now has a delivered
  remediation, audited by both unit tests and a live smoke.

### Diff numbers (approximate)

- aether-cli/src/main.rs: +500 LoC across DD4 + DD5 + DD6
  (IdpVerifyingKey enum + EdDSA verify path + validUntil parse +
  staleness helpers + Date-header parser + skew recorder + whoami
  WARN).
- Cargo.toml: 0 net change (ed25519-dalek + chrono already in use).
- tests/ python smokes: +1700 LoC across 3 new files.
- ROADMAP / STATUS / NEXT_24H_PLAN: +300 LoC (closure milestone
  framing + Plan EE recalibration).

### Total binary delta

- aether 0.33.0 release binary on linux-x64: ~44 MB
- aether 0.34.0 release binary on linux-x64: ~44 MB (no new code
  paths — just helpers + algorithm dispatch + new sidecars +
  warning emission)
