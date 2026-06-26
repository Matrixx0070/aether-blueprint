# Next 24-hour autonomous plan — Plan V

Drafted at end of Plan U (v0.24 → v0.25). Picks up the U-followups
(webhook hook coverage, labelled metrics, SAML login flow) plus the
secrets-manager + tenant-quota items the slice log has been deferring.

---

## Plan V — SAML login flow + secrets manager + labelled metrics

**MISSION**: Cash the cheques Plan U wrote — wire the remaining
webhook events, ship the SAML login flow that consumes U6's
scaffold, finish the Prometheus labelling pass, and add the
secrets-manager + tenant-quota primitives that production deploys
have been blocked on.

**DONE MEANS** (6 criteria):

1. v0.26.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. `aether sso login` against a configured SAML IdP completes the
   redirect-binding flow + persists an asserted attribute set to
   ~/.aether/sso.token.
3. Webhook events fire for trust-add, trust-remove, sso-token-rotate,
   plugin-load-failure — each live-verified via the Python receiver
   pattern U2 introduced.
4. `aether_tool_calls_total{tool=…,is_error=…}` labelled metrics
   exposed; histogram for /v1/complete latency added.
5. `AETHER_SERVE_TOKEN_FROM_SECRETS_MANAGER=aws:secret-id` or
   `=vault:path/to/secret` reads at startup; otherwise the raw env
   var continues to work.
6. STATUS slice log entries V1–V7 with commit SHAs and live-check
   output (no banned vocabulary).

## Slices

### V1 — SAML login flow consumes U6's sso-saml.json

- `aether sso login` detects sso-saml.json (in addition to sso.json)
  and routes to the SAML redirect-binding path.
- Swap U6's regex parsing for quick-xml; walk the metadata
  properly (forbid DTD/ENTITY at parser level).
- Signed SAML response validation against x509_signing_cert_b64.
- Persist asserted attributes (NameID, common ones) to sso.token.

### V2 — Webhook hook coverage for the remaining events

- trust-add        → fire from trust_add_handler + `plugin trust add`
- trust-remove     → fire from trust_remove_handler + `plugin trust remove`
- sso-token-rotate → fire from sso_login + sso_logout
- plugin-load-failure → fire from discover_plugins / register_*
- Each verified by spinning up the Python receiver pattern from U2.

### V3 — Labelled Prometheus metrics

- Replace static AtomicU64 with `HashMap<label_set, AtomicU64>`
  wrapped in `RwLock`. Helpers `bump_labelled(name, labels)`.
- `aether_tool_calls_total{tool="Edit",is_error="false"}` shape.
- Add histogram for /v1/complete request latency.
- Rename `aether_turn_duration_ms_sum` → `aether_tool_call_duration_ms_sum`
  (the v0.25 name was wrong; documented as WEAKEST POINT in U1).

### V4 — Secrets manager integration

- New env `AETHER_SERVE_TOKEN_FROM_SECRETS_MANAGER=<scheme>:<id>`.
- Schemes: aws (AWS Secrets Manager), vault (HashiCorp Vault).
- Resolved at `aether serve` startup; cached for the process lifetime
  (provider pool semantics from U5).
- AWS path reuses the v0.8 Bedrock cred chain; Vault path adds a
  thin HTTP client to /v1/kv-v2/data/<id>.

### V5 — Tenant quota throttling

- Per-tenant rate-limit + cost ceiling, in addition to the per-IP
  limit S1's ACL already informs.
- ~/.aether/tenants.json gains optional `rpm_cap` and `daily_cost_usd_cap`
  per row.
- Server reads usage.db per request to assess remaining budget.

### V6 — Provider pool TTL / `aether serve reload-pool`

- New env `AETHER_PROVIDER_POOL_TTL_SECS` (default: unbounded).
- Plus a `POST /admin/reload-pool` endpoint (bearer-protected) that
  clears the pool — useful after `aether sso login` rotates a token.

### V7 — Self-audit + Plan W draft

- Audit V1–V6 against the Discipline Laws kernel.
- Draft Plan W: per-tool argument-filter policy (tool_blocklist
  gets a regex-on-input matcher), audit-log forwarding to SIEM
  (LokiAggregator / Splunk HEC), distributed tracing hooks.

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (default picked if no answer)

1. **SAML signed-response validation library.** Default: pure-Rust
   `x509-cert` + manual canonical XML signing path (no openssl).
2. **Secrets manager backend.** Default: AWS Secrets Manager first;
   Vault second; no shipped Azure Key Vault until v0.27+.
3. **Tenant quota refresh window.** Default: rolling 24h on
   daily_cost_usd_cap; per-minute fixed window on rpm_cap.
4. **R1/R2/R3 creds.** Default unchanged: carry forward if absent.

## Risk register

- **SAML signed-response validation** is the highest-CVE-density
  area in the plan. Mitigation: pin a canonical-form parser, refuse
  external entity references, require explicit cert configuration
  (no auto-trust on first see).
- **Labelled metrics RwLock contention** under high QPS. Mitigation:
  per-label-set atomic + read-lock-free fast path; benchmark
  before/after in V3.
- **Secrets-manager dep tree growth** — AWS SDK is heavy.
  Mitigation: feature-gate `secrets-aws` so the binary stays small
  when not enabled.

---

## U7 — self-audit on Plan U (v0.25.0 shipping)

**Audited commits**: 4217c06 (U4), 8abb89a (U5), d251d29 (U3),
b6cacc0 (U1), 991d854 (U2), 21ba787 (U6). 6 code commits +
this doc commit, +900 / −40 net.

### BLOCKER — none

### HIGH — none

### MED

- **U1 metrics are unlabelled** — `aether_tool_calls_total` is a
  single counter, not `{tool="…",is_error="…"}` broken-down.
  Documented as WEAKEST POINT in the commit; promoted to V3.
- **U1 `aether_turn_duration_ms_sum` misnamed** — it tracks
  tool-call duration, not turn duration. Plan V will rename in
  V3 alongside labelling. Misnamed metric is worse than no metric;
  this is a real LOW-to-MED until V ships.
- **U6 SAML scaffold doesn't yet have a LOGIN flow** — `aether sso
  login` continues to do PKCE/OIDC. Documented inline as "scaffold
  only"; promoted to V1.
- **U2 webhook coverage is rollback-only** — trust-add /
  trust-remove / sso-token-rotate / plugin-load-failure plumbing
  is in place but not yet wired. Promoted to V2.

### LOW

- **U3 trust audit pickaxe finds FIRST add** — if the same key was
  removed and re-added, only the original commit is reported. Plan
  V key-rotation slice can extend.
- **U5 provider pool retains stale auth on credential rotation** —
  caller must restart the process to refresh. Promoted to V6.
- **U6 regex-only metadata parsing chokes on non-canonical
  namespaces.** quick-xml swap is V1's job.
- **U2 secret stored RAW on disk** (mode 0600 only). Plan V or
  Plan W can integrate OS keystore.
- **U4 integration test requires gpg in PATH** — fine on Ubuntu
  CI runners; macOS doesn't ship gpg by default. Skip-on-no-gpg
  guard is a future refinement.
- **Bash CWD reset between turns** caused 2 build-skipped false
  positives during this run (same recurring papercut from Plan O+).

### What worked

- **All 6 slices live-verified end-to-end** with the receiver
  pattern (Python for webhooks, http.server for SAML metadata,
  curl matrix for /metrics, real gpg for U4, fresh-clone for U3).
- **CAUGHT-FIX** during U3 (`--diff-filter=A` only matched the
  first key) caught by the live verify probe itself and fixed
  with a comment trail.
- **Plan-then-ship cadence held**: Plan U draft from a018deb (T7)
  matches what shipped, including the U6 scaffold-only framing.
- **Banned-vocab discipline held** across all commits + STATUS rows.

### Diff numbers

- aether-cli:           +900 LoC (metrics counters + handler,
                                   webhook config + fire_webhook,
                                   SAML configure-saml + XXE guards,
                                   trust audit, provider pool,
                                   plugin verify --require integration
                                   test scaffolding inline)
- aether-cli/Cargo.toml + workspace: +4 LoC (hmac, regex,
                                              tokio-stream already there)
- tests/u4-signed-commit.sh: +106 LoC (new shell integration test)
- README / ROADMAP / STATUS / NEXT_24H_PLAN: +180 / -50 LoC

### Total binary delta

- aether 0.24.0 release binary on linux-x64: ~41 MB
- aether 0.25.0 release binary on linux-x64: ~41 MB (no new
  major deps; regex + hmac were already linked elsewhere).
