# Next 24-hour autonomous plan — Plan W

Drafted at end of Plan V (v0.25 → v0.26). Picks up the V follow-ups
(full SAML signed-response validation, AWS Secrets Manager,
plugin-load-failure webhook) plus the per-tool argument-filter and
SIEM-forwarding items the slice log has been deferring.

---

## Plan W — finish SAML, AWS secrets, argument-filter policy, SIEM

**MISSION**: Cash the cheques V1 + V4 wrote — ship the full SAML
pipeline (the multi-week pure-Rust XML crypto work, broken across
the 24h budget into the parts that fit) and the AWS Secrets Manager
backend. Add per-tool argument-filter policy so an operator can block
not just a tool by name but a specific input pattern. Forward the
audit log to a SIEM.

**DONE MEANS** (6 criteria):

1. v0.27.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. `aether sso login` against a configured SAML IdP completes the
   AuthnRequest emission + redirect-binding + SAMLResponse capture
   + signed-response validation (RSA-SHA256 over canonicalised
   SignedInfo).
3. `AETHER_SERVE_TOKEN_FROM_SECRETS_MANAGER=aws:<id>` resolves
   against AWS Secrets Manager via the existing Bedrock cred chain.
4. `~/.aether/policy.json` gains a `tool_arg_filters: [{tool,
   regex}]` field; the executor refuses any tool call whose
   `serde_json::to_string(input)` matches the regex.
5. `AETHER_AUDIT_FORWARD=<scheme>:<url>` ships audit log lines to
   Loki / Splunk HEC; HTTP POSTs with a small batch buffer.
6. STATUS slice log entries W1–W7 with commit SHAs and live-check
   output (no banned vocabulary).

## Slices

### W1 — SAML AuthnRequest + redirect-binding (V1 follow-up part 1)

- Build the `<samlp:AuthnRequest>` XML using a hand-rolled minimal
  XML writer (no quick-xml dep churn).
- Deflate + base64-encode per the HTTP-Redirect binding spec.
- Open the browser at `sso_url?SAMLRequest=…&RelayState=…`.
- Spin up the local listener (same pattern as U7 OIDC PKCE) to
  capture the POST'd or GET'd SAMLResponse.

### W2 — SAML signed-response validation (V1 follow-up part 2)

- Pure-Rust XML c14n# (exclusive canonicalisation 1.0).
- Walk the `<ds:Signature>` element; extract `SignedInfo`,
  `SignatureValue`, `Reference URI`, `DigestValue`.
- Verify the digest of the canonicalised referenced element.
- Verify RSA-SHA256 over the canonicalised `SignedInfo` against
  the x509 cert from sso-saml.json.
- Validate NotBefore / NotOnOrAfter on the assertion.
- Extract NameID + claimed AudienceRestriction; persist to sso.token.

### W3 — AWS Secrets Manager backend (V4 follow-up)

- Build a `BedrockCredChain`-style helper in aether-llm exposed as
  `pub fn aws_signed_secrets_get(secret_id) -> Result<String>`.
- Wire into `resolve_serve_token_from_secrets_manager` so the
  `aws:<id>` scheme stops returning the informative-error stub.
- Auth path: SigV4-sign a POST to `secretsmanager.<region>.amazonaws.com`
  with body `{"SecretId": "<id>"}`.

### W4 — per-tool argument-filter policy

- New `tool_arg_filters: [{tool: String, regex: String, action:
  "refuse"|"warn"}]` field on the Plan N policy.json.
- Executor pre-dispatch: compile each regex, match against the
  serialised input JSON, refuse if any matches at `refuse`-action.
- Closes a gap operators have asked about: "block Bash when the
  command contains `curl evil.com`".

### W5 — Audit-log forwarding to SIEM (Loki / Splunk HEC)

- `AETHER_AUDIT_FORWARD=loki:<URL>` or `=splunk:<URL>` activates
  HTTP-POST forwarding of each newly-appended audit line.
- Small in-memory batch buffer (10 lines / 1 second) so a high-
  volume server doesn't melt the SIEM.
- Reuses the v0.18 N3 audit-syslog tee architecture (sister sink).

### W6 — plugin-load-failure webhook event

- aether_plugin::discover_plugins() returns `(Vec<PluginTool>,
  Vec<PluginError>)`.
- aether-cli's register_subprocess_plugins fires
  `fire_webhook("plugin-load-failure", {error, manifest_path})`
  for each error.
- Closes the V2 NON-GOAL.

### W7 — Self-audit + Plan X draft

- Audit W1–W6 against the Discipline Laws kernel.
- Draft Plan X: distributed tracing hooks (OpenTelemetry), tenant
  ACL with key rotation (RFC 8555-style), MCP transport
  improvements (HTTP/2 streaming).

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (default picked if no answer)

1. **SAML XML c14n library.** Default: hand-rolled minimal c14n#.
   xmlsec-c is the reference impl but it's C; Rust ports are
   immature. Hand-roll only what the SAML AuthnResponse needs.
2. **AWS region for Secrets Manager.** Default: read from `AWS_REGION`,
   fall back to `us-east-1`.
3. **Tool arg-filter action default.** Default: `refuse` (deny by
   match). `warn` is opt-in.
4. **R1/R2/R3 creds.** Default unchanged: carry forward if absent.

## Risk register

- **SAML signed-response validation** — pure-Rust c14n# + x509
  signature verification is genuinely hard. Mitigation: ship W1
  + W2 as TWO commits so reviewers can audit each step; explicitly
  document the algorithm choices.
- **AWS SDK dep tree** — using the official sdk-rust would balloon
  the binary by ~20MB. Mitigation: hand-roll SigV4 like W3
  describes; reuses primitives already in aether-llm.
- **Tool arg-filter regex DOS** — a malicious policy could ship a
  catastrophic regex. Mitigation: compile-time only (the regex is
  loaded at startup); use the `regex` crate's `regex::Regex::new`
  which already enforces a safety bound.

---

## V7 — self-audit on Plan V (v0.26.0 shipping)

**Audited commits**: dd21264 (V3), 1370e41 (V2), 875ba19 (V6),
465d191 (V5), 9270464 (V4), d10e51b (V1). 6 code commits + this
docs commit, +500 / −20 net.

### BLOCKER — none

### HIGH — none

### MED

- **V1 SAML login is DETECTION-ONLY** — the actual signed-response
  validation pipeline is honestly deferred. Operators who configure
  SAML get a clear refusal, not a silent unvalidated flow. Promoted
  to Plan W1+W2.
- **V4 AWS scheme is an informative-error stub** — vault path works,
  aws path bails. Promoted to Plan W3.

### LOW

- **V3 labelled tool_calls_total empty in serve** — install_tool_hook
  isn't wired into the serve paths; the labelled view is currently
  populated only by print/REPL/TUI sessions. Documented; the
  schema + plumbing are correct; population is a 1-commit follow-up.
- **V5 rpm bucket is process-local** — horizontal scaling needs an
  external rate backend (Redis, etc.). Documented; not a v0.26
  blocker for the single-machine operator model.
- **V5 daily_cost_usd_cap reads usage.db per request** — small
  table, single query, but on the hot path. v0.27+ can cache.
- **V2 plugin-load-failure event NOT WIRED** — needs an
  aether_plugin API change. Promoted to W6.
- **V4 secret persisted via env::set_var** — inherited by forks/exec.
  Acceptable for single-process model.
- **V6 reload-pool endpoint has no separate admin role** — same
  bearer as /v1/messages. Operators behind a reverse proxy.

### What worked

- **All 6 slices live-verified end-to-end** with multiple cases:
  V3 histogram bucketing, V2 HMAC byte-perfect, V6 reload timing
  diff, V5 5-request rpm probe, V4 vault round-trip, V1 detection
  dispatch.
- **Honest UNVERIFIED labelling** held through V1's "scope is
  detection only" and V4's AWS stub — no security pretence.
- **Plan-then-ship cadence held**: Plan V draft from 06f0669 (U7)
  matches what shipped, with V1+V4 honestly scoped to "ship the
  detection layer; defer the crypto/dep work".
- **Banned-vocab discipline held** through all commits + STATUS rows.

### Diff numbers

- aether-cli:  +500 LoC (labelled metrics + histogram + webhook
                         coverage + provider pool TTL + tenant
                         quota + secrets manager + SAML dispatch)
- README / ROADMAP / STATUS / NEXT_24H_PLAN: +160 / -40 LoC

### Total binary delta

- aether 0.25.0 release binary on linux-x64: ~41 MB
- aether 0.26.0 release binary on linux-x64: ~41 MB (no new
  deps; all V slices used primitives already in the workspace).
