# Next 24-hour autonomous plan — Plan GG

Drafted at end of Plan FF (v0.36 → v0.37). Plan FF shipped all 7
engineering slices (FF1 BYOC-docs retirement, FF2–FF5 full RFC 8705
mTLS pipeline with live smoke, FF6 Ed448 pre-release note, FF7
orchestration pairing guard) — the first plan since Z with zero
cred-blocked deferrals of its own.

**Carry-forward status at end of FF:**

- EE2 OIDC mTLS — CLOSED by FF2–FF5.
- EE1 Bedrock LIVE — RETIRED to `docs/byoc-setup.md` by FF1.
- EE3 Tenant SCIM — sole remaining carry-forward (deferred since
  Plan BB). Plan GG re-frames it as the main theme, mirroring the
  dedicated-plan pattern that worked for SAML (Y) and mTLS (FF).

**Non-plan debt (from the v0.36 tiers build):**

- TIER 24 distributed scanning is still a stub (aether-distrib).
- No real ZK-SNARK circuits behind aether-zk.
Both are candidates for GG filler or a dedicated Plan HH.

---

## Plan GG — dedicated tenant SCIM plan

**MISSION**: Land SCIM 2.0 (RFC 7643/7644) user + group provisioning
against aether's multi-tenant ACL store so an enterprise IdP can
push/deprovision users instead of operators hand-running
`aether tenant grant/revoke`.

**DONE MEANS** (7 criteria):

1. v0.37.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms; EE4 prerelease-checks pass.
2. GG1 `aether scim serve` (or `/scim/v2` routes on the existing
   multi-tenant server): `/Users` GET/POST/DELETE + `/Groups` GET
   with SCIM-shaped JSON (schemas, resourceType, meta) per RFC 7643.
3. GG2 SCIM bearer auth: a dedicated provisioning bearer (hashed at
   rest like tenant ACL bearers) distinct from tenant bearers;
   401/403 with SCIM error bodies per RFC 7644 §3.12.
4. GG3 user lifecycle → ACL mapping: POST /Users with a tenant-slug
   attribute grants; DELETE (or active=false PATCH) revokes; audit
   rows written (reuse trust-audit history table pattern).
5. GG4 filter support: `GET /Users?filter=userName eq "..."` (eq
   only — the minimal subset real IdPs use for lookup-before-create).
6. GG5 live smoke: fake Okta-style SCIM client drives
   create → lookup → deactivate against a running serve instance;
   tenant ACL rows observed changing on disk.
7. STATUS GG rows with commit SHAs + live-verify excerpts; ROADMAP
   updated; Plan HH draft (distributed scanning or ZK-real).

## Risk register

- §GG2: provisioning bearer must never be usable as a tenant bearer
  (privilege separation) — test both directions.
- §GG3: PATCH semantics are where SCIM implementations rot; support
  the Okta/Azure-AD `active=false` replace op minimally and refuse
  loudly otherwise.
- §GG5: the smoke must assert on-disk ACL change, not just HTTP 200
  (an accepted-but-ignored provision is worse than a 501).
