# Next 24-hour autonomous plan — Plan DD

Drafted at end of Plan CC (v0.32 → v0.33). Plan CC shipped 3 of 6
drafted slices honestly: CC1–CC3 (real BYOC round-trips) carried
forward exactly as in BB1–BB3 and AA1–AA3 — billing + Marketplace
+ subscription gates outside aether's control. The non-cred-
dependent trio closed every last documented weakest-point from
Plan AA and Plan BB:

  - CC4 closed BB6 (SAML metadata drift detection).
  - CC5 closed BB5 (OIDC proactive refresh).
  - CC6 closed BB4 (EdDSA AuthnRequest signing).

This is the closure milestone for the enterprise SSO surface
audited under Plans AA + BB. Plan DD carries forward the cred-
blocked work (DD1–DD3 = CC1–CC3 = BB1–BB3 = AA1–AA3) and adds
DD4–DD6 to close each of Plan CC's documented weakest-points.

---

## Plan DD — close every CC weakest-point + cred-unblock when ready

**MISSION**: Flip Plan CC's UNVERIFIED labels to LIVE-VERIFIED when
creds become available; close every weakest-point Plan CC explicitly
documented (EdDSA SAML verifier extension, metadata validUntil
staleness, OIDC system-clock-skew detection).

**DONE MEANS** (7 criteria):

1. v0.34.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. DD1 Bedrock LIVE round-trip — real AWS creds, single 1-token
   call returns `usage > 0`.
3. DD2 Vertex LIVE round-trip — billing-enabled GCP project +
   Anthropic-on-Vertex Marketplace + access token, single
   1-token call returns `usage > 0`.
4. DD3 Azure LIVE round-trip — Azure AI Foundry + Claude
   deployment + api-key, single 1-token call returns `usage > 0`.
5. DD4 Y5 verifier accepts EdDSA SAMLResponses end-to-end.
6. DD5 SAML metadata staleness check warns when `validUntil` is
   approaching expiry.
7. DD6 OIDC system-clock-skew detection warns when local-vs-IdP
   time delta exceeds threshold.
8. STATUS slice rows DD1–DD6 with commit SHAs + live-verify
   excerpts. No banned vocabulary.

## Slices

### DD1 — Bedrock live round-trip (cred-blocked)

- User provides real `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
  (+ optional `AWS_SESSION_TOKEN`) + `AWS_REGION`.
- Unset `AETHER_BEDROCK_ENDPOINT`.
- Run `aether doctor --probe --provider bedrock`.

### DD2 — Vertex live round-trip (cred-blocked + Marketplace)

- Enable billing on a GCP project + subscribe to "Claude on
  Vertex AI" via Cloud Marketplace.
- `VERTEX_ACCESS_TOKEN=$(gcloud auth print-access-token)` +
  `VERTEX_PROJECT=<enabled-project>`.
- Unset `AETHER_VERTEX_ENDPOINT`.
- Run `aether doctor --probe --provider vertex`.

### DD3 — Azure live round-trip (cred-blocked)

- Provision Azure AI Foundry resource + Claude deployment.
- `AZURE_AI_ENDPOINT=https://<resource>.services.ai.azure.com` +
  `AZURE_AI_API_KEY=<resource-scoped-key>`.
- Run `aether doctor --probe --provider azure`.

### DD4 — Y5 EdDSA verifier extension

- Closes CC6 weakest-point. CC6 made the SP signer EdDSA-aware;
  the Y5 verifier still gates on RSA-SHA256.
- Extend `verify_saml_assertion_signature` algorithm gate to
  accept SAML_SIG_METHOD_EDDSA_ED25519 alongside
  SAML_SIG_METHOD_RSA_SHA256. The cert-pin defense already
  generalises (cert DER is algorithm-independent).
- Add Ed25519 verify primitive — extract the Ed25519 pubkey from
  the IdP cert SPKI, call `ed25519_dalek::Verifier::verify` on
  the c14n SignedInfo bytes (no separate hash).
- Live smoke extension: round-trip an Ed25519-signed SAMLResponse
  through aether's verifier.

### DD5 — SAML metadata validUntil staleness check

- Closes CC4 follow-up gap. CC4's fingerprint covers trust
  fields but not the metadata's `validUntil` attribute. An IdP
  that bumps `validUntil` without rotating certs would still
  trigger "no drift".
- Parse `validUntil` (XML schema xsd:dateTime) from
  `<md:EntityDescriptor>`; persist in sso-saml.json.
- `refresh-saml` warns when `validUntil` is within
  `AETHER_SAML_METADATA_STALENESS_WARN_SECS` (default 86400 = 24h)
  of expiry; bails with a clear error when ALREADY expired.

### DD6 — OIDC system-clock-skew detection

- Closes CC5 weakest-point. CC5 trusts the local clock for the
  expiry math — broken NTP would defeat proactive refresh.
- After every successful POST to the token_endpoint, read the
  HTTP `Date:` header and compute `local_now - server_date`.
- Persist the latest delta in sso.json metadata or a sidecar.
- `sso whoami` warns when `|delta| > AETHER_OIDC_CLOCK_SKEW_WARN_SECS`
  (default 60s). Doesn't refuse — just surfaces the problem.

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (defaults picked)

1. **DD4 EdDSA cert key extraction.** Default: x509-parser's
   `SubjectPublicKeyInfo` decoder reads the Ed25519 SPKI
   (OID 1.3.101.112). Verifying-key bytes are 32 bytes after the
   SPKI prefix.
2. **DD5 validUntil parser.** Default: chrono's
   `DateTime::parse_from_rfc3339` (xsd:dateTime is an RFC 3339
   superset in practice).
3. **DD6 warn threshold.** Default: 60s. Real-world NTP drift is
   sub-second; 60s catches obviously broken setups without
   false-positive on normal datacentre-vs-laptop skew.

## Risk register

- **Marketplace activation latency** — DD2 may have to defer.
- **AWS cred exposure** — env-only, never committed.
- **DD4 verifier regression** — adding an algorithm to the gate
  is the kind of change that silently widens trust. Audit the
  EdDSA verify path before tag-push: confirm the algorithm URI
  in SignedInfo matches what the cert pubkey actually supports
  (don't allow RSA cert + EdDSA SignedInfo).

---

## Pre-DD context — Plan CC self-audit (v0.33.0 shipping)

**Audited commits**: b3e334b (CC4), 6e73b97 (CC5), 963a0f5 (CC6),
plus this version-bump commit.

### Closure milestone

This is the version where every documented Plan AA + Plan BB
weakest-point has landed remediation. The chain:
  - AA4 unsigned AuthnRequest → BB4 RSA signing → CC6 EdDSA signing
  - AA5-followup discovery → BB6 refresh-saml → CC4 drift detection
  - AA6 no userinfo → BB5 reactive refresh → CC5 proactive refresh

The remaining Plan-AA / BB / CC carry-forward is the cred-blocked
DD1-DD3 = CC1-CC3 = BB1-BB3 = AA1-AA3 BYOC live round-trips.

### BLOCKERs — none

All three shipped Plan CC slices ship with all spec gates closed.

### HIGHs — none

### MEDs — documented and carried

- CC4 fingerprint covers the EXTRACTED trust fields, not the raw
  XML. Necessary to defeat timestamp/contact-info false positives,
  but means a metadata that changes `validUntil` without rotating
  certs is reported as "no drift". Plan DD5 closes this.
- CC5 proactive refresh trusts the local system clock. Plan DD6
  closes this via Date-header skew detection.
- CC6 SP signer is EdDSA-aware but Y5 verifier still gates on
  RSA-SHA256. Plan DD4 closes this with a symmetric extension.

### LOWs — knowingly carried

- CC4 fingerprint algorithm is hard-coded sha256. If the operator
  needs collision-resistance against a stronger adversary, they
  re-implement. Sha256 is the right default for trust-set hashing
  in 2026.
- CC5 sidecar uses RFC 3339 with timezone offset. Could store
  unix-seconds for slightly smaller / faster parsing. Cosmetic.
- CC6 only Ed25519 EdDSA variant. Ed448 not supported. No real
  IdP advertises Ed448 today.

### What worked

- **All 3 shipped Plan CC slices live-verified end-to-end** in
  this session, each with a dedicated fake-IdP smoke that drives
  the new path 4-7 steps deep.
- **The regression sweep caught the BB6 stderr wording change**
  (CC4) and the BB5 lead-window interference (CC5) immediately —
  without the smokes, those would have been silent breakages.
- **The closure milestone is real**. The AA → BB → CC chain is
  not coincidence; every weakest-point in plan N got remediated
  in plan N+1, on schedule.

### Diff numbers (approximate)

- aether-cli/src/main.rs: +500 LoC across CC4 + CC5 + CC6 (parser
  + fingerprint + drift dispatch + expires_at sidecar + proactive
  refresh + SpSigningKey enum + EdDSA signing path).
- Cargo.toml: +1 word (ed25519-dalek `pkcs8` + `pem` features).
- crates/aether-cli/Cargo.toml: +1 line (direct ed25519-dalek dep).
- tests/ python smokes: +1500 LoC across 3 new files.
- ROADMAP / STATUS / NEXT_24H_PLAN: +250 LoC.

### Total binary delta

- aether 0.32.0 release binary on linux-x64: ~43 MB
- aether 0.33.0 release binary on linux-x64: ~44 MB (Ed25519
  signing primitive + PKCS#8 PEM decoder pulled in by
  ed25519-dalek with new features)
