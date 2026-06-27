# Next 24-hour autonomous plan — Plan CC

Drafted at end of Plan BB (v0.31 → v0.32). Plan BB shipped 3 of 6
drafted slices honestly: BB1–BB3 (real Bedrock / Vertex / Azure
round-trips) remained cred-blocked exactly as in Plan AA — billing
+ Marketplace + subscription gates outside aether's control. The
plan delivered the three non-cred-dependent slices that closed every
Plan AA documented weakest-point:

  - BB4 closed AA4 (signed AuthnRequest).
  - BB5 closed AA6 (OIDC access-token refresh).
  - BB6 closed AA5-followup (SAML metadata auto-refresh).

Plan CC continues to carry forward CC1–CC3 (the cred-blocked work)
until creds become available, and adds CC4–CC6 to close each of
Plan BB's documented weakest-points.

---

## Plan CC — close every BB weakest-point + cred-unblock when ready

**MISSION**: Flip Plan BB's UNVERIFIED labels to LIVE-VERIFIED when
creds become available; close every weakest-point Plan BB explicitly
documented (metadata drift detection, proactive token refresh,
EdDSA AuthnRequest signing).

**DONE MEANS** (7 criteria):

1. v0.33.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. CC1 Bedrock LIVE round-trip — real AWS creds, real
   `bedrock-runtime.<region>.amazonaws.com`, single 1-token call
   returns `usage > 0`.
3. CC2 Vertex LIVE round-trip — billing-enabled GCP project +
   Anthropic-on-Vertex Marketplace subscription + access token,
   single 1-token call returns `usage > 0`.
4. CC3 Azure LIVE round-trip — Azure AI Foundry resource + Claude
   deployment + api-key, single 1-token call returns `usage > 0`.
5. CC4 SAML metadata drift detection: refresh-saml --watch skips
   the rewrite when the metadata response hash matches the
   previous tick.
6. CC5 OIDC proactive refresh: aether refreshes the access_token
   ahead of `expires_in` (e.g. 5 min before) rather than on 401.
7. CC6 EdDSA AuthnRequest signing accepted by `aether sso login`
   with an Ed25519 SP key.
8. STATUS slice rows CC1–CC6 with commit SHAs + live-verify
   excerpts. No banned vocabulary.

## Slices

### CC1 — Bedrock live round-trip (cred-blocked)

- User provides real `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
  (+ optional `AWS_SESSION_TOKEN`) + `AWS_REGION`.
- Unset `AETHER_BEDROCK_ENDPOINT` (so it falls back to AWS default).
- Run `aether doctor --probe --provider bedrock`.

### CC2 — Vertex live round-trip (cred-blocked + Marketplace)

- Pre-req on user's side: enable billing on a GCP project +
  subscribe to "Claude on Vertex AI" via Cloud Marketplace.
- `VERTEX_ACCESS_TOKEN=$(gcloud auth print-access-token)` +
  `VERTEX_PROJECT=<enabled-project>`.
- Unset `AETHER_VERTEX_ENDPOINT`.
- Run `aether doctor --probe --provider vertex`.

### CC3 — Azure live round-trip (cred-blocked)

- Pre-req: Azure AI Foundry resource + Claude deployment.
- `AZURE_AI_ENDPOINT=https://<resource>.services.ai.azure.com` +
  `AZURE_AI_API_KEY=<resource-scoped-key>`.
- Run `aether doctor --probe --provider azure`.

### CC4 — SAML metadata drift detection

- Closes BB6 weakest-point. Hash the metadata response (sha256
  of bytes); persist the hash in sso-saml.json as
  `metadata_xml_sha256`.
- On refresh-saml tick: if response hash matches the persisted
  value, skip the layout rewrite + log "no drift, skipping
  rewrite"; bump a `last_checked_at` timestamp regardless.
- Unit tests for the hash equality + persistence path; live smoke
  extension on the BB6 mutable metadata server.

### CC5 — OIDC proactive refresh

- Closes BB5 weakest-point. Read `expires_in` from the token
  response; persist `~/.aether/sso.access_token.expires_at`
  alongside the sidecar.
- `sso whoami` computes `now < expires_at - 5 minutes`; refresh
  preemptively when the window has been crossed, BEFORE calling
  userinfo. Falls back to the existing reactive 401 path on
  refresh failure.
- New env knob `AETHER_OIDC_REFRESH_LEAD_SECS` (default 300,
  clamped [60, 3600]) for the lead-time window.
- Unit tests for the expiry math; live smoke extension on the
  BB5 fake IdP.

### CC6 — EdDSA AuthnRequest signing

- Closes BB4 weakest-point. BB4 supports only RSA-SHA256; some
  modern IdPs (FIDO2-adjacent, Auth0 paths using Ed25519 keys)
  advertise EdDSA on the AuthnRequest binding.
- `load_sp_signing_key_from_pem` already accepts Ed25519 PKCS#8.
- `sign_authn_request_xml` dispatches on key type: RSA → existing
  RSA-SHA256; Ed25519 → eddsa-2022 SignatureMethod URI.
- Unit tests for the Ed25519 round-trip; live smoke extension on
  BB4's fake IdP with an Ed25519 SP key.

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (defaults picked)

1. **CC4 hash persistence location.** Default: as a new field
   `metadata_xml_sha256` in sso-saml.json. Backward-compat: pre-CC4
   files just trigger a "first refresh" rewrite on the next tick.
2. **CC5 lead-time default.** Default: 300 seconds (5 minutes).
   Same window the Z2 JWKS timeout + AA6 reqwest timeout use.
3. **CC6 EdDSA SignatureMethod URI.** Default:
   `http://www.w3.org/2021/04/xmldsig-more#eddsa-2022` per the
   XML-DSig EdDSA registration. Verifiable against the existing Y5
   verifier when extended.

## Risk register

- **Marketplace activation latency** — Vertex Marketplace
  subscription can take hours; CC2 may have to defer again.
- **AWS cred exposure** — never commit AWS keys to the repo;
  env-only.
- **CC4 hash false positive** — some IdPs include a timestamp
  attribute in the metadata document that changes per-fetch even
  when the certs / endpoints don't. May need to hash a normalized
  subset of the document rather than the raw bytes. Investigate
  before shipping.
- **CC6 EdDSA verifier impact** — Y5 currently rejects EdDSA in
  `verify_saml_assertion_signature` (Algorithm gate). Extending
  the sender doesn't require extending the verifier, but operators
  with a self-loop test would need both. Plan CC scope is sender-
  side only; verifier extension in a follow-up.

---

## Pre-CC context — Plan BB self-audit (v0.32.0 shipping)

**Audited commits**: 25301f0 (BB4), 49b0b1a (BB5), edc7328 (BB6),
plus this version-bump commit.

### Honest scope re-frame mid-plan

Plan BB was drafted with the same shape as Plan AA: 3 cred-
dependent slices (BB1–BB3) + 3 non-cred-dependent slices (BB4–BB6
closing AA weakest-points). The cred-blocked slices remained
cred-blocked exactly as in Plan AA — no GCP billing came on, no AWS
creds arrived, no Azure Foundry resource was provisioned. The
non-cred-dependent slices shipped 100%.

### BLOCKERs — none

All three shipped Plan BB slices have all spec gates closed at the
unit-test level. No BLOCKER findings carried into the version bump.

### HIGHs — one caught + fixed mid-slice

- BB6 mid-development bug: refactor extracted
  `apply_saml_idp_metadata` from `sso_configure_saml`, accidentally
  changed the stderr line from "discovered, written to" to "laid
  out under". AA5fu live smoke greps the old string; the regression
  surfaced immediately during regression-sweep. Fixed by restoring
  the original wording (BB6 doesn't need to change it). The smoke
  is what protected the production message contract.

### MEDs — documented and carried

- BB5 auto-refresh attempts ONCE per `whoami` invocation. A
  rotated refresh_token that also fails would not loop. Documented
  in Plan BB risk register.
- BB6 `--watch` is a foreground daemon, not a tokio::spawn from
  `aether serve`. Operators that want systemd-style supervision
  wrap it themselves.

### LOWs — knowingly carried

- BB4 signature algorithm is RSA-SHA256 only. EdDSA AuthnRequest
  signing deferred to CC6.
- BB5 no proactive refresh based on `expires_in`. Deferred to CC5.
- BB6 no drift detection — refresh-saml rewrites unconditionally.
  Wasteful in --watch mode against a stable IdP. Deferred to CC4.
- BB6 `parse_token_response` was named after the OAuth concept
  but used by BB5; could rename to `parse_token_endpoint_response`
  for clarity. Cosmetic.

### What worked

- **All 3 shipped Plan BB slices live-verified end-to-end** in
  this session, each with a dedicated Python fake-IdP smoke that
  walks the new code path 5-7 steps deep.
- **The regression sweep caught the BB6 wording change**
  immediately — without the AA5fu smoke, a working code change
  would have broken a downstream test that nobody re-ran.
- **The wrap-up commit-message convention captured the
  cred-blocked carry-forward honestly** — operators reading the
  ROADMAP can see the exact gate that's blocking each slice and the
  env vars they'd need to unblock it.

### Diff numbers (approximate)

- aether-cli/src/main.rs: +600 LoC across BB4 + BB5 + BB6 (helpers,
  new subcommands, sidecar persistence, metadata helpers,
  binding-aware SP signing).
- aether-llm/: 0 LoC (no changes — Plan BB scope is SAML + OIDC).
- Cargo.toml: +1 word (rsa `pem` feature enabled for BB4 PEM
  loading).
- tests/ python smokes: +1100 LoC across 3 new files.
- ROADMAP / STATUS / NEXT_24H_PLAN: +250 LoC.

### Total binary delta

- aether 0.31.0 release binary on linux-x64: ~43 MB
- aether 0.32.0 release binary on linux-x64: ~43 MB (no new code
  paths — just helpers + new subcommand entries)
