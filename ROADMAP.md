# Roadmap

## v0.7 — Security Edge — shipped 2026-06-25 (this release)

A self-contained surface for authorized security work, end-to-end:

- **Scope file** (`~/.aether/scope.json`): hosts / CIDR ranges / repos
  declared up front, with `--authorized-by` + `--ticket-id` + expiry.
  CIDR ranges larger than /16 refused at `scope add-range` time.
- **Tamper-evident audit log** (`~/.aether/audit.jsonl`): `prev_hash`-
  chained JSONL, `aether audit verify` walks the chain end-to-end.
- **Scope-gated network tools**: `NetworkScan` (nmap), `WebProbe` (curl),
  `DnsLookup` (dig). Auto-registered ONLY when the scope file loads;
  every call (allowed OR refused) logs to the audit chain.
- **`aether review --kind security`**: single-turn critic, no tools.
  Structured `SEVERITY / CWE / LOCATION / SUMMARY / WHY / FIX` blocks
  per issue, language-specific focus lists for Rust / Python /
  JavaScript / Go / Java / C / C++ / SQL. `--json` returns parsed blocks.
- **STRIDE `aether threat-model <spec>`**: trust boundaries, data
  classes, per-category threats with mitigations + residual risk.
- **`aether ctf <dir>`**: bubblewrap-sandboxed challenge runner; mounts
  the challenge's listed files into `/work` and loops the agent until
  the expected flag is produced. Ships with an example XOR challenge.
- **Scanner tool wrappers**: gitleaks, cargo-audit, osv-scanner.
- **`Sandbox` tool**: bubblewrap-isolated command execution.
- **`aether security-eval <suite.yaml>`**: fixture-based OWASP-class
  regression. Seven Python fixtures (SQLi / path traversal /
  hard-coded creds / command injection / weak crypto / insecure
  deserialization / SSRF), each asserts the critic flags the expected
  CWE at the configured minimum severity. CI-friendly exit 1 on miss.

**Security Edge benchmark** — `aether security-eval eval/security/suite.yaml`:

- Sonnet 4.6: **7/7 (100%)** at correct CWE + severity, 110s total
- Opus 4.7: 2/7 (29%); 5 calls truncate mid-stream because Anthropic's
  cyber-safeguards classifier engages on adversarial-framing +
  structured-output + classic-injection-code combinations. Not a bug
  in aether; the same prompt clears on Sonnet 4.6. v0.7 docs
  recommend `AETHER_MODEL=claude-sonnet-4-6` for security review.

## v0.7.2 — shipped 2026-06-25 (patch)

- **Security eval suite expanded to 4 languages**: 9 new fixtures (Java
  ×3, C++ ×3, Go ×3) added to the 7 Python fixtures. Suite YAML and per-
  language README tables updated. Single autoroute run on Sonnet 4.6
  detects **16/16 at BLOCKER severity**, 5m21s wall-clock. No tooling
  changes — only fixtures + docs.

## v0.7.1 — shipped 2026-06-25 (patch)

- **Security auto-route**: `aether review --kind security` and `aether
  security-eval` auto-route Opus-class models (`claude-opus-*`) to Sonnet
  4.6 when `--model` was not passed explicitly. Pure-function router
  (`route_for_security`) covered by 6 unit tests. One-line stderr notice
  per invocation. Three override paths: explicit `--model X`,
  `AETHER_SECURITY_NO_AUTOROUTE=1`, or just call with Sonnet/Haiku
  directly. Closes the 5/7 Opus truncation reported in v0.7's BENCHMARK.

## v0.7.2 — patch (next)

- Bedrock streaming via `invoke-with-response-stream` (AWS event-stream)
- Vertex streaming via `:streamRawPredict` (SSE)
- AWS credential provider chain: profile file at `~/.aws/credentials`,
  IMDS, ECS task role
- GCP credential auto-rotation via `gcp_auth` crate (ADC + service-account
  JSON file)
- BYOC retry watchdog parity (Bedrock 5xx + 429 retry-after parsing,
  Vertex 5xx retry)
- `aether eval --provider <name>` to run the same suite across providers

## v0.8 — plugins + IDE surfaces

- Plugin system via WASM modules registered as tools
- BYOC: Foundry (Azure) + Mantle
- VS Code extension, JetBrains plugin
- MCP websocket transport
- HTTP server WebSocket chat for browser clients

## v0.9 — enterprise

- SAML / OIDC federation
- Audit log forwarding to SIEM
- Per-org policy enforcement (tool blocklists, model restrictions)
- Trusted-device enrollment

## Explicit non-goals

- A drop-in `claude` binary replacement that spoofs Claude Code identity.
  aether's OAuth uses the SDK-agent identity prefix; we do not impersonate.
- Telemetry to a vendor endpoint. Hooks let operators export what they need.
- Auto-update.
