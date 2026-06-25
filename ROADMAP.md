# Roadmap

## v0.6 — shipped 2026-06-25 (this release)

BYOC providers — AWS Bedrock + GCP Vertex AI:

- `aether-llm::bedrock::BedrockProvider`: hand-rolled SigV4 against the
  AWS-published test vector, model-id translation
  (`claude-haiku-4-5-20251001` → `anthropic.claude-haiku-4-5-20251001-v1:0`),
  reads `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`
  / `AWS_REGION` from env. Non-streaming for v0.6.
- `aether-llm::vertex::VertexProvider`: Bearer-token auth from
  `VERTEX_ACCESS_TOKEN`, model-id translation
  (`claude-haiku-4-5-20251001` → `claude-haiku-4-5@20251001`), reads
  `VERTEX_PROJECT` / `VERTEX_REGION` from env. Non-streaming for v0.6.
- Provider selection: `AETHER_PROVIDER` env > `settings.provider` >
  `anthropic` default. `aether config set provider bedrock` persists.
- `aether doctor` reports the active provider and runs the right per-
  provider auth check (AWS env vars / Vertex token / Anthropic creds).
- `aether-cli`'s 6 LLM construction sites refactored to a central
  `build_provider() -> Arc<dyn LlmProvider>` factory.

29 aether-llm unit tests (up from 18 in v0.5): includes SigV4 signing
math (AWS published test vector), model-id mapping, body-shape
verification per provider.

## v0.6.1 — patch (next)

- Bedrock streaming via `invoke-with-response-stream` (AWS event-stream framing)
- Vertex streaming via `:streamRawPredict` (SSE)
- AWS credential provider chain: profile file at `~/.aws/credentials`,
  IMDS, ECS task role
- GCP credential auto-rotation via `gcp_auth` crate (ADC + service-account
  JSON file)
- BYOC retry watchdog parity (Bedrock 5xx + 429 retry-after parsing,
  Vertex 5xx retry)
- `aether eval --provider <name>` to run the same suite across providers

## v0.7 — TUI + integration surfaces

- Plugin system via WASM modules registered as tools
- BYOC: Foundry (Azure) + Mantle
- VS Code extension, JetBrains plugin
- MCP websocket transport
- HTTP server WebSocket chat for browser clients

## v0.8 — enterprise

- SAML / OIDC federation
- Audit log forwarding to SIEM
- Per-org policy enforcement (tool blocklists, model restrictions)
- Trusted-device enrollment

## Explicit non-goals

- A drop-in `claude` binary replacement that spoofs Claude Code identity.
  aether's OAuth uses the SDK-agent identity prefix; we do not impersonate.
- Telemetry to a vendor endpoint. Hooks let operators export what they need.
- Auto-update.
