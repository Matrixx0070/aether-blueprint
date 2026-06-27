# Next 24-hour autonomous plan — Plan Z

Drafted at end of Plan Y (v0.28 → v0.29). Plan Y shipped the full SAML
2.0 SSO pipeline; Plan Z closes the remaining cred-blocked UNVERIFIEDs
and adds OIDC federation.

---

## Plan Z — OIDC federation + cred-unblock

**MISSION**: Add PKCE-based OIDC SSO (browser round-trip → ID-token →
session token) and live-verify the three BYOC providers that have been
UNVERIFIED since v0.8 due to missing creds (Bedrock, Vertex, Azure).

**DONE MEANS** (6 criteria):

1. v0.30.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. `aether sso configure-oidc` + `aether sso login` complete a PKCE
   browser round-trip against a local fake OIDC server (RS256 ID token
   validated, `sso.token` written at 0600).
3. Bedrock streaming live-verified (real AWS creds, at least 1 token
   returned from `invoke-with-response-stream`).
4. Vertex streaming live-verified (real GCP SA JSON, at least 1 delta
   from `:streamRawPredict`).
5. Azure AI Foundry live-verified (real endpoint + api-key, `--probe`
   round-trip returns `usage.input_tokens > 0`).
6. ROADMAP / STATUS / NEXT_24H_PLAN updated. No banned vocabulary in
   any new commit.

## Slices

### Z1 — OIDC discovery + configure-oidc

- `aether sso configure-oidc --issuer <url>` fetches
  `<issuer>/.well-known/openid-configuration`, extracts
  `authorization_endpoint`, `token_endpoint`, `jwks_uri`, and writes
  `~/.aether/sso-oidc.json`.

### Z2 — PKCE browser round-trip

- `aether sso login` (when `sso-oidc.json` present) generates
  `code_verifier` + `code_challenge` (S256), binds `127.0.0.1:0`
  callback, emits the authorization URL, waits for the code, POSTs
  to `token_endpoint` for `access_token` + `id_token`.

### Z3 — RS256 / ES256 ID-token validation

- Fetch `jwks_uri`, select the matching `kid`; verify RS256 or ES256
  `id_token` signature + `iss` / `aud` / `exp` claims. Write
  `~/.aether/sso.token` at 0600.

### Z4 — Bedrock live-verify

- Run `aether doctor --probe --provider bedrock` against real AWS
  creds (env vars `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`).
  Record exit 0 + usage fields.

### Z5 — Vertex live-verify

- Run `aether doctor --probe --provider vertex` against real GCP SA
  JSON (env `GOOGLE_APPLICATION_CREDENTIALS`). Record exit 0 + delta.

### Z6 — Azure live-verify + ship v0.30.0

- Run `aether doctor --probe --provider azure` against real Azure
  endpoint. Bump Cargo.toml. Tag, push, watch autobuild, cosign
  verify-blob.

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (defaults picked)

1. **OIDC nonce + at_hash.** Default: validate `nonce` round-trip
   (anti-replay); skip `at_hash` (access-token hash, optional in spec).
2. **Multi-IdP OIDC.** Default: single configured issuer per install.
3. **Cred unblock order.** Default: Bedrock → Vertex → Azure (matches
   ROADMAP order).

## Risk register

- **JWKS caching** — don't cache without a TTL; stale JWKS causes
  false-negative sig failures on key rotation. Use a 5-min in-memory
  TTL.
- **Live-verify creds** — if creds aren't in env, mark UNVERIFIED
  honestly and document the exact env vars needed.
- **OIDC scope** — Z1–Z3 is significant; don't let scope creep from
  Z4–Z6 compress the OIDC time budget.

---

## Pre-Z context — Plan Y self-audit (v0.29.0 shipping)

**Audited commits**: 5724bfb (Y1), dc1ca90 (Y2), 726b063 (Y3),
6f223bc (Y4), 61334c3 (Y5), bb595db (Y6), 571111f (Y7), plus audit
fix commit on this plan boundary.

### BLOCKERs — fixed before tag

- **BLOCKER-1 (cert-pin bypass)** — `load_idp_signing_key` returned
  only `RsaPublicKey`, causing the KeyInfo X509Certificate pin check
  in `verify_saml_assertion_signature` to be skipped in production
  (caller passed `&[]`). Fixed: function now returns
  `(RsaPublicKey, Vec<u8>)` (key + cert DER); call site passes real
  DER bytes.
- **BLOCKER-2 (XSW first-match)** — `verify_saml_assertion_signature`
  called `find_element_byte_range_by_id` without verifying the matched
  element's local name is "Assertion". An XSW attacker could prefix
  the document with `<outer ID="_assertion-id">` to redirect
  canonicalisation to unsigned content. Fixed: after resolving the byte
  range, the local name of the opening tag is extracted and asserted
  equal to "Assertion".
- **BLOCKER-3 (RelayState CSRF)** — RelayState mismatch was an
  `eprintln!` warning, not a hard error. Fixed: elevated to
  `anyhow::bail!`.

### HIGHs — fixed before tag

- **HIGH-1 (End local-name)** — `find_element_byte_range_by_id` End
  arm compared full qnames (`saml:Assertion` vs `saml:Assertion`).
  Harmless in practice (same prefix) but semantically wrong. Fixed:
  extract local names from both sides before comparing.
- **HIGH-2 (Recipient + InResponseTo)** — `SubjectConfirmationData/
  @Recipient` and `@InResponseTo` were not validated. Fixed: generate
  `authn_request_id` before calling `build_authn_request_xml` (passing
  it via `Some(&id)`); after Y6 bounds check, validate Recipient ==
  acs_url and InResponseTo == authn_request_id when present.

### What worked

- **33/33 Y-prefix unit tests** pass after all audit fixes (exit 0,
  `cargo test --release -p aether-cli -- tests::y`).
- **Y7 live smoke** (`tests/y7-saml-smoke.py`) passes end-to-end:
  RSA-2048 keygen + lxml exc-c14n sign → `aether sso login` ACS →
  `sso.token` written at 0600 with `saml.v1.` prefix.
- **Dead-code warning** on `load_idp_signing_key` (present during Y5
  development) cleared by the BLOCKER-1 fix that wires the return
  value through.
