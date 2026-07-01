# BYOC setup — Bedrock / Vertex / Azure live credentials

Status: **documentation, FF1**. This page retires the long-running
"Bedrock LIVE round-trip" carry-forward (EE1, deferred across seven
plans) to docs. The wire-format fake-endpoint smokes (Z4 Bedrock /
Z5 Vertex / Z6 Azure, see `tests/z*-smoke.py`) exercise every
request/response shape end-to-end and stay in CI; the only thing NOT
verified is a real cloud round-trip, which requires an operator with
billing-enabled credentials. This page is the checklist that operator
follows.

All env-var names below are the ones the code actually reads
(`crates/aether-llm/src/{bedrock,vertex,azure}.rs`), not aspirational.

---

## AWS Bedrock

Provider slug: `bedrock` (`BedrockProvider::from_credential_chain`).

Credential resolution order (v0.8 chain, `bedrock.rs`):

1. Static env: `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`
   (+ optional `AWS_SESSION_TOKEN`)
2. Shared credentials file `~/.aws/credentials`
   (profile from `AWS_PROFILE`, default `default`;
   file path override via `AWS_SHARED_CREDENTIALS_FILE`)
3. Container credentials
   (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` /
   `AWS_CONTAINER_CREDENTIALS_FULL_URI` +
   `AWS_CONTAINER_AUTHORIZATION_TOKEN`)

Also set:

- `AWS_REGION` — region hosting the Anthropic models
  (e.g. `us-east-1`, `us-west-2`)
- `AETHER_BEDROCK_ENDPOINT` — test/override endpoint only; unset for
  real AWS

Cred-acquisition checklist:

1. AWS account with billing enabled.
2. In the target region, open Bedrock console → **Model access** →
   request access to the Anthropic Claude models you need (per-model
   opt-in; usually instant for Claude).
3. IAM principal needs `bedrock:InvokeModel` +
   `bedrock:InvokeModelWithResponseStream` on the model ARNs.
4. Verify: `aether ask --provider bedrock "ping"` — success proves
   SigV4 signing + event-stream decode against real AWS (closes the
   Z4 UNVERIFIED).

## GCP Vertex AI (Anthropic on Vertex)

Provider slug: `vertex` (`VertexProvider::from_env`).

Env (static-token mode, what `from_env` reads):

- `VERTEX_ACCESS_TOKEN` (fallback `GCP_ACCESS_TOKEN`) — from
  `gcloud auth print-access-token`
- `VERTEX_PROJECT` (fallbacks `GCLOUD_PROJECT`,
  `GOOGLE_CLOUD_PROJECT`) — billing-enabled project id
- `VERTEX_REGION` — default `us-central1`
- `AETHER_VERTEX_ENDPOINT` — test/override endpoint only; unset for
  real GCP

Service-account mode (long-lived, auto-refreshing RS256 JWT
exchange): construct via
`VertexProvider::from_service_account_file(path)` with a
service-account JSON key file.

Cred-acquisition checklist — Plan Z's live attempt (2026-06-27)
proved BOTH gates below are real and outside aether's control:
`gcloud auth print-access-token` worked and aether sent a correct
request, but got 403 because:

1. **Billing** must be enabled on the project (it was disabled on
   all three projects tested).
2. **Cloud Marketplace subscription**: Anthropic on Vertex requires
   subscribing via GCP Marketplace ("Claude on Vertex AI") even with
   billing on.
3. Enable the Vertex AI API (`aiplatform.googleapis.com`).
4. Principal needs `roles/aiplatform.user` on the project.
5. Verify: `aether ask --provider vertex "ping"` — success closes
   the Z5 UNVERIFIED.

## Azure AI Foundry

Provider slugs: `azure`, `azure-foundry`, `foundry`
(`AzureProvider::from_env`).

Env:

- `AZURE_AI_ENDPOINT` — required, resource endpoint, e.g.
  `https://<resource>.services.ai.azure.com`
- `AZURE_AI_API_KEY` — required, resource-scoped key
- `AZURE_AI_API_VERSION` — default `2024-08-01-preview`

Cred-acquisition checklist:

1. Azure subscription with billing enabled.
2. Create an **AI Foundry** resource; deploy an Anthropic Claude
   model from the model catalog (Marketplace terms acceptance
   required on first deploy).
3. Copy endpoint + key from the resource's Keys and Endpoint blade.
4. Verify: `aether ask --provider azure "ping"` — success closes the
   Z6 UNVERIFIED.

---

## What "retired to docs" means

- ROADMAP's cred/scope-blocked carry-forward list no longer tracks
  BYOC live round-trips plan-over-plan.
- The Z4/Z5/Z6 fake-endpoint smokes remain the CI-enforced contract
  for wire-format correctness.
- When an operator with real creds runs any checklist above, file the
  output in STATUS as the closing evidence for that provider's
  UNVERIFIED row.
