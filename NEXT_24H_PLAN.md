# Next 24-hour autonomous plan — Plan X

Drafted at end of Plan W (v0.26 → v0.27). Picks up the deferred SAML
pipeline (the multi-week item), plus the v0.28+ scope from ROADMAP.md.

---

## Plan X — distributed tracing + per-field policy + WASM diagnostics

**MISSION**: Ship operational tooling that v0.27's primitives now make
useful (distributed tracing, per-field arg-filter). Wire the WASM
loader's diagnostics. The dedicated SAML pipeline is its OWN plan (Y
or later) — too big for a 24h budget honestly.

**DONE MEANS** (6 criteria):

1. v0.28.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. OpenTelemetry-compatible spans emitted from `aether serve`'s hot
   path: /v1/messages, /v1/complete, /ws/chat — exported to a
   configurable OTLP endpoint.
3. `tool_arg_filters` rows gain `field: "command"` so the regex
   matches against `input.command` (or whatever field), not the
   whole serialised body. Backward compat: rows without `field`
   match the whole body (v0.27 semantics).
4. `aether_plugin_wasm` exposes `discover_wasm_plugins_with_diagnostics`,
   mirroring W6 in subprocess loader.
5. Plan Y drafted as the SAML-dedicated plan (a SINGLE 24h budget
   targeting the AuthnRequest + signed-response pipeline).
6. STATUS slice log entries X1–X7 with commit SHAs and live-check
   output (no banned vocabulary).

## Slices

### X1 — OpenTelemetry tracing in serve hot path

- Add `tracing` + `tracing-subscriber` + `opentelemetry-otlp` deps.
- Span per request: /v1/messages, /v1/complete, /ws/chat each get
  a root span with model, tenant, status_code, duration_ms.
- Export to `AETHER_OTEL_ENDPOINT=http://collector:4317`.
- Smoke against Jaeger-via-Docker.

### X2 — Per-field arg-filter policy

- `tool_arg_filters: [{tool, field, regex, action}]`.
- `field` is a dotted JSON path (`command`, `file_path`, `args.0`).
- Existing rows without `field` → match against whole serialised
  body (v0.27 semantics).
- Live-verify with a Bash + field=command policy that catches
  `rm -rf` without false-positive matches on benign code review
  inputs.

### X3 — WASM plugin-load-failure diagnostics

- aether_plugin_wasm gains discover_wasm_plugins_with_diagnostics.
- Same PluginLoadFailure struct (reason: String, manifest_path).
- aether-cli's register_wasm_plugins fires the same
  fire_webhook("plugin-load-failure") for WASM failures.

### X4 — Tenant quota Redis backend (rpm_cap)

- `AETHER_RATE_BACKEND=redis://host:6379` switches the V5 rpm bucket
  from process-local Mutex<HashMap> to Redis INCR-with-EXPIRE.
- Closes V7 LOW (rpm bucket is process-local).
- Out of scope: cost-cap Redis cache (cost is already in usage.db).

### X5 — Plugin trust audit: full key history

- U3 reports the FIRST commit each key was added. X5 extends to
  show every add/remove transition (key rotation use case).
- `aether plugin trust audit --history <key>` outputs the full
  timeline.

### X6 — Periodic SIEM flusher

- W5 ships a 10-line batch threshold + explicit `audit_siem_flush`.
- X6 adds a 1-second periodic tokio task that runs
  `audit_siem_flush` so low-volume operators don't lose entries
  to the buffer.

### X7 — Self-audit + Plan Y draft (the SAML plan)

- Audit X1–X6 against the Discipline Laws kernel.
- Draft Plan Y as a SINGLE 24h budget on SAML:
    Y1 AuthnRequest emission + redirect-binding
    Y2 SAMLResponse capture + base64 decode + initial parse
    Y3 quick-xml swap (replaces v0.25 regex extractor)
    Y4 c14n# (exclusive canonicalisation 1.0)
    Y5 RSA-SHA256 signature verify against x509 cert
    Y6 NotBefore/NotOnOrAfter + AudienceRestriction
    Y7 NameID persistence + ship v0.29.0

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (default picked if no answer)

1. **OTLP gRPC vs HTTP.** Default: HTTP — simpler dep tree.
2. **Field-path syntax for X2.** Default: dotted JSON path (no
   JSONPath complexity).
3. **R1/R2/R3 creds.** Default unchanged: carry forward if absent.

## Risk register

- **OTEL deps are heavy** — opentelemetry-otlp + tracing pulls a
  lot. Mitigation: feature-gate the OTEL exporter so non-OTEL
  operators still see a small binary.
- **X4 Redis is a new external dep** — add the `redis` crate +
  document that AETHER_RATE_BACKEND defaults to in-process when
  unset (V5 behaviour unchanged).

---

## W7 — self-audit on Plan W (v0.27.0 shipping)

**Audited commits**: 69cf598 (W4), 6c0b3c0 (W6), 327e49a (W5),
87e0b03 (W3), plus the W1+W2 honest deferral. 4 code commits + this
docs commit, +430 / −20 net.

### BLOCKER — none

### HIGH — none

### MED

- **W1+W2 SAML pipeline DEFERRED** — the plan-drafted scope of
  "AuthnRequest + c14n# + RSA-SHA256 + x509 + assertion bounds"
  is genuinely multi-week work. Plan W shipped the 4 code-bounded
  slices (W3/W4/W5/W6) and explicitly deferred SAML to a dedicated
  plan rather than ship a half-implemented signature check (which
  is worse than the v0.26 routing refusal). Plan X7 drafts a
  SAML-dedicated Plan Y.

### LOW

- **W4 regex matches whole serialised JSON** — operators must
  anchor patterns carefully to avoid catching benign fields. Plan
  X2 adds per-field arg-filter.
- **W5 1-second flush cadence not implemented** — only the 10-line
  threshold + explicit `audit_siem_flush()`. Low-volume servers
  could lose entries to the buffer. Plan X6 adds a periodic
  flusher.
- **W5 uses curl as transport** — no HTTP client in aether-sec.
  Plan X+ can pull reqwest in.
- **W3 SecretBinary not supported** — only SecretString. Operator
  picks at secret-creation time; error message is informative.
- **W6 WASM plugin loader doesn't have the diagnostic variant** —
  only the subprocess loader was wired. Plan X3.

### What worked

- **All 4 shipped slices live-verified end-to-end** with real
  receiver patterns: W4 across 4 cases against actual agent runs,
  W6 with a broken manifest + python receiver, W5 with a fake
  Loki + JSON-body byte verification, W3 with a fake SM endpoint
  that validated SigV4 + X-Amz-Target.
- **Honest scope-reduction on W1+W2** — refused to ship a half-
  implemented signature check; the v0.26 routing refusal stays.
- **Plan-then-ship cadence held**: Plan W draft from 3ab3727 (V7)
  matches what shipped, with the explicit W1+W2 deferral noted
  in the risk register at draft time.
- **Banned-vocab discipline held** across commits + STATUS rows.

### Diff numbers

- aether-cli:    +260 LoC (W4 arg-filter wire-in + W6 webhook fire
                          + W3 AWS Secrets Manager hand-rolled
                          SigV4 + apply_policy_to_session compile)
- aether-core:   +60 LoC (ToolArgFilter + ArgFilterAction +
                          set_arg_filters + dispatch-time check)
- aether-plugin: +30 LoC (PluginLoadFailure +
                          discover_plugins_with_diagnostics)
- aether-llm:    +4 LoC (pub on derive_signing_key + hmac_sha256)
- aether-sec:    +140 LoC (W5 SIEM forwarder + batch buffer +
                          curl transport)
- aether-sec/examples: +20 LoC (w5_smoke.rs live-verify helper)
- README / ROADMAP / STATUS / NEXT_24H_PLAN: +150 / -50 LoC

### Total binary delta

- aether 0.26.0 release binary on linux-x64: ~41 MB
- aether 0.27.0 release binary on linux-x64: ~41 MB (no new
  major deps; W5 uses curl-via-Command instead of pulling reqwest
  into aether-sec).
