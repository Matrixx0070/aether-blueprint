# Next 24-hour autonomous plan — Plan BB

Drafted at end of Plan AA (v0.30 → v0.31). Plan AA shipped 4 of 6
drafted slices honestly: AA1–AA3 (real Bedrock / Vertex / Azure
round-trips) were blocked at billing + Marketplace + subscription
gates outside aether's control, so the plan pivoted to AA4 SAML
HTTP-POST + AA5 multi-cert IdP support + AA5-followup configure-saml
auto-discovery + AA6 OIDC userinfo + sso whoami.

Plan BB carries forward the cred-blocked AA1–AA3 work and closes
each of Plan AA's documented weakest-points.

---

## Plan BB — close AA weakest-points + cred-unblock when ready

**MISSION**: Flip Plan AA's UNVERIFIED labels to LIVE-VERIFIED when
creds become available; close every weakest-point Plan AA explicitly
documented (signed AuthnRequest, access-token refresh, metadata
auto-refresh).

**DONE MEANS** (7 criteria):

1. v0.32.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. AA1 Bedrock LIVE round-trip — real AWS creds, real
   `bedrock-runtime.<region>.amazonaws.com`, single 1-token call
   returns `usage > 0`.
3. AA2 Vertex LIVE round-trip — billing-enabled GCP project +
   Anthropic-on-Vertex Marketplace subscription + access token,
   single 1-token call returns `usage > 0`.
4. AA3 Azure LIVE round-trip — Azure AI Foundry resource + Claude
   deployment + api-key, single 1-token call returns `usage > 0`.
5. BB4 Signed AuthnRequest (POST binding) accepted by `aether sso
   login` end-to-end (smoke updated to verify the
   `<ds:Signature>` element on the AuthnRequest).
6. BB5 OIDC access-token refresh wired into `aether sso whoami`
   (401 → use refresh_token → retry).
7. BB6 SAML metadata auto-refresh subcommand documented.
8. STATUS slice rows BB1–BB6 with commit SHAs + live-verify
   excerpts. No banned vocabulary.

## Slices

### BB1 — Bedrock live round-trip (cred-blocked)

- User provides real `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
  (+ optional `AWS_SESSION_TOKEN`) + `AWS_REGION`.
- Unset `AETHER_BEDROCK_ENDPOINT` (so it falls back to AWS default).
- Run `aether doctor --probe --provider bedrock`.

### BB2 — Vertex live round-trip (cred-blocked + Marketplace)

- Pre-req on user's side: enable billing on a GCP project +
  subscribe to "Claude on Vertex AI" via Cloud Marketplace.
- `VERTEX_ACCESS_TOKEN=$(gcloud auth print-access-token)` +
  `VERTEX_PROJECT=<enabled-project>`.
- Unset `AETHER_VERTEX_ENDPOINT`.
- Run `aether doctor --probe --provider vertex`.

### BB3 — Azure live round-trip (cred-blocked)

- Pre-req: Azure AI Foundry resource + Claude deployment.
- `AZURE_AI_ENDPOINT=https://<resource>.services.ai.azure.com` +
  `AZURE_AI_API_KEY=<resource-scoped-key>`.
- Run `aether doctor --probe --provider azure`.

### BB4 — Signed AuthnRequest (POST binding)

- Closes AA4 weakest-point. Some enterprise IdPs require XML
  Digital Signature over the AuthnRequest with the SP's private
  key (rsa-sha256, enveloped, exc-c14n#).
- New helper `sign_authn_request_xml(xml, sp_priv_key) ->
  signed_xml` that splices a `<ds:Signature>` block into the
  AuthnRequest. Reuses the Y4 exc-c14n machinery.
- New env knob `AETHER_SAML_SP_PRIVATE_KEY_PEM=path` switches
  AuthnRequest emission to signed mode when set.
- Unit tests: build → sign → c14n SignedInfo → RSA verify with
  the public key recovered from the keypair.
- Live smoke extension: drive the fake IdP through a signed POST
  AuthnRequest path; assert the IdP receives a verifiable
  `<ds:Signature>` element.

### BB5 — OIDC access-token refresh

- Closes AA6 weakest-point. When the token response includes
  `refresh_token`, persist it at `~/.aether/sso.refresh_token`
  (mode 0600).
- `sso whoami` on userinfo 401: use the refresh_token to mint a
  fresh access_token (POST to token_endpoint with
  `grant_type=refresh_token`), rewrite the sidecar, retry the
  userinfo call once.
- New `aether sso refresh` subcommand for manual rotation.
- Unit tests for the refresh response parser; live smoke
  extension on the fake IdP.

### BB6 — SAML metadata auto-refresh

- Closes AA5-followup weakest-point. New `aether sso refresh-saml`
  subcommand re-fetches the metadata URL persisted at
  configure-saml time and re-runs the multi-cert layout.
- New optional env `AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS`
  spawns a background tokio task that runs the refresh on the
  given cadence — useful for IdP cert rotation without bouncing
  aether.

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (defaults picked)

1. **BB1 model id.** Default: `anthropic.claude-haiku-4-5-v1:0` —
   cheapest live Bedrock Anthropic call.
2. **BB2 region.** Default: `us-central1` — matches Plan Z evidence
   the user's account is provisioned there.
3. **BB4 signed-AuthnRequest scope.** Default: rsa-sha256 only
   (the Y5 verifier already understands this algorithm); RSA-PSS
   and EdDSA in a follow-up.
4. **BB5 refresh-on-401 retries.** Default: ONE retry. Repeated
   401 → bail (avoid loops on stale refresh tokens).

## Risk register

- **Marketplace activation latency** — Vertex Marketplace
  subscription can take hours; BB2 may have to defer.
- **AWS cred exposure** — never commit AWS keys to the repo;
  env-only.
- **BB5 refresh-token theft scope** — refresh tokens live longer
  than access tokens; the sidecar at mode 0600 is the same
  defense as the existing token sidecars.

---

## Pre-BB context — Plan AA self-audit (v0.31.0 shipping)

**Audited commits**: 79fed59 (AA4), 125d2c6 (AA5), a997c48 (AA6),
62ed5b8 (AA5-followup), plus this version-bump commit.

### Honest scope re-frame mid-plan

Plan AA was drafted assuming AA1–AA3 (real Bedrock / Vertex / Azure
round-trips) would be runnable as the first three slices. The user
provided their gcloud auth in good faith; live attempt revealed all
3 GCP projects had billing disabled and Anthropic-on-Vertex requires
a Cloud Marketplace subscription. Plan pivoted to the non-cred-
dependent slices. AA1–AA3 carry forward to Plan BB1–BB3.

### BLOCKERs — none

All four shipped Plan AA slices ship with all spec gates closed at
the unit-test level. No BLOCKER findings carried into the version
bump.

### HIGHs — one caught + fixed mid-slice

- AA5-followup mid-development bug: refactor briefly moved
  `sso-saml.json` from `~/.aether/sso-saml.json` to
  `~/.aether/saml/sso-saml.json`, breaking the SAML routing branch
  (`sso_cmd::Login` looks for the legacy path). Caught by the live
  smoke when login fell through to OIDC. Fixed by separating the
  config path (kept at legacy) from the certs dir (new location).

### MEDs — documented and carried

- AA6 streaming dimension untouched. `validate_id_token` runs once
  at login; userinfo runs synchronously. No streaming protocols
  involved.
- AA5 verifier reconstructs `Pkcs1v15Sign` per iteration because
  it takes `self` by value. Zero-size marker struct so the cost is
  nil — documented in code.

### LOWs — knowingly carried

- AA4 POST binding emits an UNSIGNED AuthnRequest. Some enterprise
  IdPs require XML-signed AuthnRequest; deferred to BB4.
- AA5-followup: metadata re-fetch isn't automated. Operators must
  re-run `configure-saml` to pick up rotated certs. Deferred to
  BB6.
- AA6: access-token expiry isn't refreshed. `sso whoami` 401s
  silently when the token expires. Deferred to BB5.
- AA6: groups normalisation drops non-string entries silently —
  IdP-specific extension shapes vary too widely to be strict.

### What worked

- **All 4 shipped Plan AA slices live-verified end-to-end** in
  this session. Each has a dedicated Python fake-IdP smoke that
  drives the new code path through `aether sso login` /
  `configure-saml` / `whoami` to the success-case stdout assertion.
- **Self-audit caught the routing bug** during AA5-followup live
  smoke — the unit tests passed but the integration revealed the
  path mismatch. The smoke is what protected the production code.
- **Real Vertex live attempt produced actionable evidence**: not
  a hand-waved "untested", but a concrete 403 PERMISSION_DENIED
  with the exact missing capability (project billing). That
  evidence is carried into BB2's pre-reqs verbatim.

### Diff numbers (approximate)

- aether-cli/src/main.rs: +600 LoC across AA4 + AA5 + AA5-followup
  + AA6 (helpers, refactored verify, new subcommand, sidecar
  writes, metadata multi-cert extraction)
- aether-llm/: 0 LoC (no changes — Plan AA scope is SAML+OIDC)
- tests/ python smokes: +1100 LoC across 4 new files
- ROADMAP / STATUS / NEXT_24H_PLAN: +250 LoC

### Total binary delta

- aether 0.30.0 release binary on linux-x64: ~43 MB
- aether 0.31.0 release binary on linux-x64: ~43 MB (no new code
  paths — just helpers + new subcommand entry)
