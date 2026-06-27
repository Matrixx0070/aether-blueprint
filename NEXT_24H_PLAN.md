# Next 24-hour autonomous plan — Plan Y

Drafted at end of Plan X (v0.27 → v0.28). The dedicated SAML pipeline
that Plan W deferred and Plan X intentionally kept out of scope.

---

## Plan Y — SAML 2.0 SSO end-to-end

**MISSION**: Convert the v0.25 SAML scaffolding (metadata endpoint +
routing refusal) into a real SP-initiated SSO flow: AuthnRequest →
IdP redirect → SAMLResponse capture → signature verify → audience &
time bounds → NameID persistence. Standalone work, one plan, one tag.

**DONE MEANS** (8 criteria):

1. v0.29.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. `POST /sso/saml/login` 302-redirects with a valid
   AuthnRequest in the `SAMLRequest` query param (DEFLATE +
   base64 + URL-encode per HTTP-Redirect binding §3.4 of saml-bindings-2.0).
3. `POST /sso/saml/acs` (assertion-consumer service) accepts a
   base64-encoded SAMLResponse POST, decodes, parses via quick-xml
   (replacing the v0.25 regex extractor).
4. Exclusive XML canonicalisation 1.0 (xml-c14n#exc-c14n) on the
   <ds:SignedInfo> envelope.
5. RSA-SHA256 signature verify against the IdP's x509 cert
   configured in `~/.aether/saml/idp-cert.pem`. Live verify against
   a fake IdP that signs a deterministic response.
6. <Conditions NotBefore> / <Conditions NotOnOrAfter> /
   <AudienceRestriction><Audience> validated; clock-skew tolerance
   = 30 seconds (configurable via `AETHER_SAML_CLOCK_SKEW_S`).
7. NameID persisted to `aether sso` session storage (sqlite row
   in tenant_acl.db), reusing the existing tenant bearer issuance
   path so a SAML-logged-in user gets the same tenant bearer the
   `aether sso login` flow already issues.
8. STATUS slice rows Y1–Y7 with commit SHAs + live-verify output
   against the fake IdP (no banned vocabulary).

## Slices

### Y1 — AuthnRequest emission + HTTP-Redirect binding

- Build minimal AuthnRequest XML (`<samlp:AuthnRequest>` with
  `ID`, `IssueInstant`, `Destination`, `<saml:Issuer>`,
  `ProtocolBinding`, `AssertionConsumerServiceURL`).
- DEFLATE (raw, no zlib wrapper), base64, URL-encode.
- 302 to `${idp_sso_url}?SAMLRequest=…&RelayState=…`.

### Y2 — ACS endpoint + SAMLResponse decode

- `POST /sso/saml/acs` accepts form-encoded SAMLResponse.
- base64 decode → UTF-8 XML.
- Initial sanity parse: extract response status code +
  optional StatusMessage. Reject anything that isn't
  `urn:oasis:names:tc:SAML:2.0:status:Success`.

### Y3 — quick-xml extractor

- Pull quick-xml into aether-sec. Walk events to extract:
    Issuer, NameID, Subject/SubjectConfirmationData,
    Conditions/AudienceRestriction, AuthnStatement,
    ds:Signature/ds:SignedInfo/ds:SignatureValue,
    ds:KeyInfo/ds:X509Data/ds:X509Certificate.
- Replaces the v0.25 regex extractor at the call site.

### Y4 — exclusive canonicalisation 1.0

- Implement xml-c14n#exc-c14n over the <ds:SignedInfo> subtree:
  sorted attrs, no comments, namespace inclusivity per XML-EXC-C14N
  §2.4. Hand-rolled — no new c14n dep.
- Smoke against the OASIS test vector
  (xml-c14n-20020615/in/exc-doc-subset.xml).

### Y5 — RSA-SHA256 verify

- Pull `rsa` 0.9 + `rsa::Pkcs1v15Sign` for sha256 verify.
- Extract x509 modulus + exponent from the PEM in
  `~/.aether/saml/idp-cert.pem` (or `AETHER_SAML_IDP_CERT_PEM`).
- Verify `ds:SignatureValue` (base64-decoded) against the c14n
  digest of <ds:SignedInfo>.

### Y6 — assertion-validity bounds

- `Conditions/@NotBefore`, `Conditions/@NotOnOrAfter`:
  reject if `now() < NotBefore - skew` or `now() > NotOnOrAfter + skew`.
- `<AudienceRestriction><Audience>`: must contain our SP entityID
  (read from `~/.aether/saml/sp-config.yaml` `entity_id` field).

### Y7 — NameID → tenant bearer + ship v0.29.0

- On Subject + Signature + Conditions all green: look up tenant by
  IdP entity ID in the existing tenant_acl.db, issue a bearer via
  the same path `aether sso login` uses, set as session cookie,
  302 back to RelayState (or `/` if empty).
- Self-audit on Y1–Y7. Tag, push, watch autobuild, verify cosign.

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (default picked if no answer)

1. **HTTP-POST vs HTTP-Redirect binding.** Default: Redirect for
   AuthnRequest, POST for SAMLResponse (industry-standard).
2. **Encrypted assertions (<EncryptedAssertion>).** Default: REJECT
   for now; document in Plan Z (Y has enough scope).
3. **SLO (single logout).** Default: out of scope for Y. Logout is
   local-session-clear only.
4. **Per-IdP cert rotation.** Default: single static IdP cert file
   path. Multi-cert + cert-rotation in a follow-up.

## Risk register

- **c14n is fiddly** — the OASIS test vectors are not optional.
  Y4 lives or dies on those smokes.
- **rsa crate is large** — 200KB+ binary delta. Acceptable given
  SAML is the enterprise auth story.
- **Clock skew on dev machines** — give operators a clear knob via
  `AETHER_SAML_CLOCK_SKEW_S` (default 30s).
- **No real IdP in CI** — Y5 + Y7 must verify against a hand-built
  fake-IdP test fixture (deterministic AuthnResponse with known
  cert + signature). Otherwise we're flying blind.

---

## Pre-Y context — Plan X self-audit (v0.28.0 shipping)

**Audited commits**: 1d48646 (X2), d7ae0dd (X3), 80e17c6 (X5),
7956cc4 (X6), 7a1359b (X4), 520e5b4 (X1), plus this audit/version
commit. 6 code commits + this docs commit.

### BLOCKER — none after fixes

- **block_in_place flavor guard** — X4's
  `bearer_rpm_admit_dispatch` previously called `block_in_place +
  Handle::current().block_on` unconditionally. Single-thread
  runtimes (e.g. `#[tokio::test]`) would panic. Fixed by adding a
  `runtime_flavor() == MultiThread` guard with fail-open fallback
  to the in-process bucket. Verified by re-reading the dispatch
  function post-fix.

### HIGH — none after fixes

- **X5 git argument injection vector** — the `--history` SHA from
  `git log --format=%h` is git-controlled, but defensive hex
  validation now rejects anything outside [0-9a-fA-F] before it
  reaches `git show <sha>:…` argument splicing. Same hex
  validation applied to the user-supplied `--history <prefix>`.
- **X6 SIEM flusher blocking on tokio worker** — the inner
  `audit_siem_flush()` calls `child.wait()` synchronously and
  could pin a worker for the `curl --max-time 2` syscall. Fixed
  by wrapping in `tokio::task::spawn_blocking`.
- **X1 reqwest::Client per span** — was constructing a new
  connection pool on every request. Fixed by hoisting to a
  process-wide `OTEL_HTTP: Lazy<reqwest::Client>`.

### MED

- **OTLP intValue spec compliance** — moved from quoted string to
  bare integer per OTLP/HTTP proto-JSON.

### LOW (knowingly carried)

- **X6 flusher task panic recovery** — if `audit_siem_flush`
  panics inside the spawn_blocking, the join handle is dropped
  and the next tick proceeds. Acceptable: SIEM flush is
  best-effort and operator-observable via the audit-log file.
- **X1 chat-session lifetime not spanned** — only the WS upgrade
  decision (status 101) gets a span. The chat conversation is
  intentionally separate — admission cost is what /ws/chat
  contributes to OTel.

### What worked

- **All 6 shipped slices live-verified end-to-end** in this
  session:
    X1: 3-handler OTel emit verified against a Python OTLP sink
        (matching the OTLP/HTTP JSON spec, with real durations
        for /v1/complete + real `aether.tenant: acme` attribute).
    X2: per-field arg-filter verified by running the agent with
        a Bash arg-filter rule targeted at the `command` field
        (denies `rm -rf` without matching benign code review
        body content).
    X3: WASM diagnostics verified by registering a broken WASM
        manifest and watching the webhook receiver fire with
        `runtime: wasm` + `reason`.
    X4: Redis backend verified against a local Redis on :6399
        (rpm_cap=3 → 200/200/200/429/429; fail-open on
        unreachable redis:// URL → 3 × 200).
    X5: trust audit --history verified against a synthesized
        local clone with 3 add/remove transitions.
    X6: SIEM flusher verified by inserting a single audit row
        under threshold and watching the periodic flusher drain
        it within ~1s.
- **Self-audit caught real issues** before tagging — the
  block_in_place flavor guard and the spawn_blocking wrap for
  X6 were not in the initial implementation.

### Diff numbers (approximate)

- aether-cli:    +500 LoC across X1–X6
- aether-core:   +75 LoC (X2 dotted-path resolver + per-field match)
- aether-plugin: +9 LoC (runtime-tag filter in subprocess loader)
- aether-plugin-wasm: +35 LoC (WasmPluginLoadFailure +
                                discover_with_diagnostics)
- Cargo.lock / Cargo.toml: +47 LoC (redis + once_cell uses)

### Total binary delta

- aether 0.27.0 release binary on linux-x64: ~41 MB
- aether 0.28.0 release binary on linux-x64: ~43 MB (redis +
  multi-handler OTel infra)
