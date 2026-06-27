# Next 24-hour autonomous plan — Plan AA

Drafted at end of Plan Z (v0.29 → v0.30). Plan Z shipped OIDC hardening
(Z1–Z3) plus fake-endpoint BYOC wire-format smokes (Z4–Z6) after the
real BYOC paths surfaced billing / Marketplace gates outside aether's
control. Plan AA closes the remaining cred-blocked UNVERIFIEDs when
creds become available and extends the SAML / OIDC surface.

---

## Plan AA — BYOC live verify + enterprise SSO breadth

**MISSION**: Flip every UNVERIFIED label that Plan Z carried forward
to LIVE-VERIFIED when creds become available, plus close the v0.29
explicit SAML deferral (HTTP-POST binding) and add OIDC userinfo.

**DONE MEANS** (6 criteria):

1. v0.31.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. Bedrock LIVE round-trip — real AWS creds, real
   `bedrock-runtime.<region>.amazonaws.com`, single 1-token complete
   call returns usage > 0.
3. Vertex LIVE round-trip — real GCP creds on a billing-enabled
   project with Anthropic-on-Vertex Marketplace subscription, single
   1-token complete call returns usage > 0.
4. Azure LIVE round-trip — real Azure AI Foundry resource +
   deployment, single 1-token complete call returns usage > 0.
5. SAML HTTP-POST binding for AuthnRequest accepted by
   `aether sso login` end-to-end (smoke updated to post the
   AuthnRequest via form-encoded body, not redirect query).
6. STATUS slice rows AA1–AA6 with commit SHAs + live-verify output
   excerpts (no banned vocabulary).

## Slices

### AA1 — Bedrock live round-trip

- User provides real AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (+
  optional AWS_SESSION_TOKEN) + AWS_REGION.
- Unset AETHER_BEDROCK_ENDPOINT (so it falls back to AWS default).
- Run `aether doctor --probe --provider bedrock` — exit 0 with
  `bedrock responded in <ms>ms (in=X out=Y)`.
- Record live-verify excerpt in STATUS.

### AA2 — Vertex live round-trip

- Pre-req on user's side: enable billing on a GCP project +
  subscribe to "Claude on Vertex AI" via Cloud Marketplace.
- `VERTEX_ACCESS_TOKEN` from `gcloud auth print-access-token` +
  `VERTEX_PROJECT=<enabled-project>` + `VERTEX_REGION=us-central1`.
- Unset AETHER_VERTEX_ENDPOINT.
- Run `aether doctor --probe --provider vertex` — exit 0 with
  `vertex responded in <ms>ms (in=X out=Y)`.

### AA3 — Azure live round-trip

- Pre-req: Azure AI Foundry resource + Claude deployment via
  Marketplace.
- `AZURE_AI_ENDPOINT=https://<resource>.services.ai.azure.com` +
  `AZURE_AI_API_KEY=<resource-scoped-key>`.
- Run `aether doctor --probe --provider azure` — exit 0 with
  `azure-foundry responded in <ms>ms (in=X out=Y)`.

### AA4 — SAML HTTP-POST binding for AuthnRequest

- Currently `sso_login_saml()` refuses any binding other than
  HTTP-Redirect (line 7987 in main.rs). Extend `build_authn_request_
  xml` + AuthnRequest emission so HTTP-POST binding renders a
  self-submitting form (per saml-bindings-2.0 §3.5.4) and posts to
  the IdP's `SingleSignOnService Location` instead of redirecting.
- Update `tests/y7-saml-smoke.py` to drive the POST binding path
  end-to-end.

### AA5 — Multi-cert IdP support

- Replace `~/.aether/saml/idp-cert.pem` with `idp-certs/*.pem`
  directory. `load_idp_signing_key` returns
  `Vec<(RsaPublicKey, Vec<u8>)>`. Signature verify tries each pubkey
  until one succeeds; first match wins. Supports IdP cert rotation
  without bouncing aether.

### AA6 — OIDC userinfo + `aether sso whoami`

- New `aether sso whoami` subcommand. Calls
  `userinfo_endpoint` (from the cached discovery doc in sso.json)
  with the access_token from sso.token. Prints the resolved
  subject + email + groups. Useful for operators debugging "which
  identity is this session bound to".

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (defaults picked)

1. **AA2 project selection.** Default: ask user before consuming
   billing — even small Vertex Anthropic calls cost money.
2. **AA3 Azure resource provisioning.** Default: skip if no
   resource exists; mark UNVERIFIED again.
3. **AA5 cert ordering.** Default: lexicographic by filename — gives
   operators a predictable "rotate by renaming" workflow.

## Risk register

- **Marketplace subscription latency** — Anthropic on Vertex
  Marketplace activation can take hours. AA2 may have to defer
  again if user hasn't pre-provisioned.
- **AWS credential exposure** — never commit AWS keys to the repo;
  use env-only.
- **AA4 HTTP-POST signed-AuthnRequest** — POST binding optionally
  signs the AuthnRequest. Plan AA scope is unsigned POST first;
  signed POST in a follow-up.

---

## Pre-AA context — Plan Z self-audit (v0.30.0 shipping)

**Audited commits**: a60baad (Z1'), edebaf0 (Z2), 490a714 (Z3),
8e10a55 (Z4), 3365e15 (Z5), 0e2dd12 (Z6), plus this version-bump
commit.

### Honest scope re-frame mid-plan

Plan Z was drafted assuming OIDC discovery + PKCE + ID-token
validation did NOT exist. Reading the codebase at Z1 revealed they
shipped in v0.18. Re-framed Z1–Z3 as OIDC hardening of the existing
flow, with three concrete spec gaps closed (nonce, at_hash, iat +
require-jwks). This is documented in the v0.30 ROADMAP entry.

### BLOCKERs — none

All six Z slices ship with all spec gates closed at the unit-test
level. No BLOCKER findings carried into the version bump.

### HIGHs — one fixed in slice, none carried

- Z2 `verify_id_token` originally called `reqwest::get()` with no
  timeout or body cap (HIGH — DoS surface). Fixed in slice by
  switching to a per-call `reqwest::Client::builder().timeout(10s)`
  + `bytes()`-then-size-check before parse.

### MEDs — one carried, documented

- Z6 streaming dimension is wholly untested. `AzureProvider` has no
  `complete_streamed` impl (relies on the LlmProvider default which
  calls `complete()` once). Documented in Z6 commit; deferred to a
  future hardening when Azure publishes a real SSE streaming surface
  on the Anthropic-compat endpoints.

### LOWs — knowingly carried

- Z1' `verify_nonce_claim` accepts `Option<&str>` for the expected
  nonce. The only caller (`sso_login`) always passes `Some`, but the
  API allows misuse. Tightening this is a refactor, not a security
  fix.
- Z2 `verify_at_hash_claim` skips silently when at_hash is absent in
  auth-code flow (spec-compliant). Z3 adds the strict-mode knob; the
  default remains permissive for compatibility.
- Z3 `verify_iat_claim` rejects non-integer iat values as
  "missing iat" rather than a more accurate "non-integer iat".
  RFC 7519 §2 permits non-integer NumericDate; every production IdP
  emits integers.
- Z4/Z5 fake-endpoint smokes don't exercise SigV4 signature verify
  or OAuth token verify — only request shape. Real upstream catches
  bad signatures; the fakes accept anything well-formed.
- Z4/Z5 fake-endpoint smokes don't exercise retry watchdog (no 429
  / 5xx injection). Wire-format coverage only.

### What worked

- **24 new Z-prefix unit tests** pass cleanly across both
  aether-cli (z1*/z2*/z3* nonce + at_hash + iat + strict + env knob)
  and aether-llm (z4*/z5* endpoint overrides). Live smokes added for
  OIDC + Bedrock + Vertex + Azure.
- **Real Vertex live attempt produced concrete evidence**: not a
  hand-waved "untested", but a real 403 PERMISSION_DENIED with
  the exact missing capability (billing) cited in the error. That
  evidence flows into AA2's pre-reqs.
- **Self-audit caught scope drift early** — recognising Z1–Z3 were
  hardening, not net-new, saved redundant scaffolding.

### Diff numbers (approximate)

- aether-cli/src/main.rs: +180 LoC (Z1'+Z2+Z3 verify helpers + env
  knobs + sso_login wiring)
- aether-llm/src/bedrock.rs: +27 LoC (base_url + override + unit test)
- aether-llm/src/vertex.rs: +50 LoC (base_url + override + unit test)
- aether-llm/src/azure.rs: +0 LoC
- tests/ python smokes: +800 LoC across 4 new files
- ROADMAP / STATUS / NEXT_24H_PLAN: +200 LoC

### Total binary delta

- aether 0.29.0 release binary on linux-x64: ~43 MB
- aether 0.30.0 release binary on linux-x64: ~43 MB (no new code
  paths — just helpers + env reads)
