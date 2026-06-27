# Next 24-hour autonomous plan — Plan FF

Drafted at end of Plan EE (v0.34 → v0.35). Plan EE shipped 3 slices
(EE4 pre-tag placeholder check, EE5 cacheDuration, EE6 Ed448) and
carried 3 deferrals forward. Both DD weakest-points (DD4 → EE6 Ed448
verify; DD5 → EE5 cacheDuration) are now closed; the pre-tag CI gate
ends the chronic Y7→DD7 STATUS-row placeholder pattern.

**Carry-forward status at end of EE:**

  - EE1 Bedrock LIVE — SEVENTH plan of carry-forward → Plan FF
    retires this to docs.
  - EE2 OIDC mTLS (RFC 8705) — FIFTH plan of deferral → Plan FF
    re-frames as the main theme (dedicated-plan approach, mirroring
    Plan Y's successful dedicated-SAML pattern).
  - EE3 Tenant SCIM — FIFTH plan of deferral → re-queued for Plan
    GG as another dedicated-plan candidate.

---

## Plan FF — dedicated OIDC mTLS plan

**MISSION**: Land RFC 8705 mTLS client authentication end-to-end for
the OIDC token endpoint, retire the long-running BYOC carry-forward
to docs, and close the EE6 trust-assumption follow-through if a
stable ed448-goldilocks ships.

**DONE MEANS** (8 criteria):

1. v0.36.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms; pre-tag prerelease-checks job (EE4) passes.
2. FF1 `docs/byoc-setup.md` lands with env vars + GCP/AWS/Azure
   cred-acquisition checklists; ROADMAP carry-forward list shrinks
   from 3 to 2.
3. FF2 `aether sso configure-mtls --cert <pem> --key <pem>` persists
   paths in sso.json `mtls` block at 0600; reload-on-invocation per
   risk register §EE2 cert-rotation race.
4. FF3 reqwest client in `sso_login` + `refresh_oauth_access_token`
   loads the cert+key via `Identity::from_pkcs8_pem` when `mtls` is
   configured; cert+key read into memory at invocation time
   (atomic-rename convention).
5. FF4 `cnf.x5t#S256` id_token claim verification: when configured,
   the claim MUST be present and match the SHA-256 fingerprint of
   the leaf cert; reject mismatch.
6. FF5 live smoke against fake IdP that rejects token endpoint POSTs
   without a client cert; aether's configured cert is required for
   success.
7. FF6 ed448-goldilocks v0.14 stable bump if available, otherwise
   one-line trust-assumption note in the EE6 comment.
8. STATUS slice rows FF1–FF7 with commit SHAs + live-verify
   excerpts. EE4's pre-tag check passes. No banned vocabulary.

## Slices

### FF1 — BYOC carry-forward retirement

- Six plans of Bedrock+Vertex+Azure deferral is enough. Plan EE's
  risk register flagged this as candidate to retire after the
  sixth plan; that bar is met.
- New `docs/byoc-setup.md` covers env-var setup (AWS_PROFILE +
  AWS_REGION for Bedrock; GOOGLE_APPLICATION_CREDENTIALS +
  AETHER_VERTEX_PROJECT for Vertex; AZURE_AI_ENDPOINT +
  AZURE_AI_API_KEY for Foundry) + the cred-acquisition checklist
  (billing-enabled project, Marketplace subscription) per Plan Z's
  Vertex 403 evidence.
- ROADMAP "Cred/scope-blocked carry-forward" list shrinks from 3
  to 2 (mTLS + SCIM remain; BYOC retired to docs).
- Fake-endpoint smokes (Z4 Bedrock / Z5 Vertex / Z6 Azure) stay —
  they exercise the wire-format end-to-end. Real live-call work
  returns when an operator with creds arrives.

### FF2 — `aether sso configure-mtls`

- New CLI subcommand: `aether sso configure-mtls --cert <pem> --key
  <pem>`. Validates the PEM files parse + match (cert pubkey matches
  key pubkey) before writing.
- Persists `{mtls: {cert_path: "...", key_path: "..."}}` block in
  sso.json. Existing sso.json files (no `mtls` block) keep working —
  `serde` default keeps backwards-compat.
- Paths persisted; cert+key NOT cached in memory at config time —
  loaded on every token POST per risk register §EE2.

### FF3 — reqwest client mTLS wiring

- Modify shared reqwest client construction in `sso_login` +
  `refresh_oauth_access_token` to load the cert+key via
  `Identity::from_pkcs8_pem` when sso.json `mtls` block is present.
- Read cert+key from disk fresh per invocation (mitigates the
  cert-rotation race documented in EE2 risk register — operator
  rotates cert on disk, next refresh picks up new value).
- Document atomic-rename convention in the configure-mtls
  subcommand's help text.
- Same path for token endpoint POST and introspection POST.
- Errors (cert/key parse failure, mismatch) surface loudly — don't
  silently fall back to non-mTLS.

### FF4 — `cnf.x5t#S256` id_token claim verification

- Per RFC 8705 §3.1 token binding. When the client presented a cert
  on the token endpoint, the issued id_token MAY carry a
  `cnf.x5t#S256` claim with the SHA-256 fingerprint (43-char URL-
  safe-no-pad base64) of the leaf cert DER.
- New env knob: `AETHER_OIDC_REQUIRE_CNF_X5T_S256=1` flips
  verification from advisory (warn-on-mismatch) to hard-reject.
- Compute the SHA-256 fingerprint of the configured leaf cert DER at
  verify time; compare to the persisted id_token claim. Mismatch =
  reject with informative error.
- 3 unit tests: claim present + matches → ok; claim present + mismatch
  → reject (or warn under default); claim absent + require=1 → reject.

### FF5 — live smoke (mTLS end-to-end)

- Fake IdP that:
  - Issues a server cert + a client-CA cert.
  - Token endpoint REJECTS POSTs without a client cert that chains
    to the CA (HTTP 400 + json error).
  - When the client cert IS valid, issues an id_token with
    `cnf.x5t#S256` = SHA-256 of the presented leaf cert.
- Smoke chain:
  1. configure-mtls with the client cert+key.
  2. configure-oidc against the fake IdP.
  3. sso login → token POST carries the client cert → id_token
     returned with cnf claim.
  4. cnf claim verifies against the configured cert.
  5. Refresh path also carries the client cert.
  6. Remove the cert from configure-mtls → next refresh fails with
     a token-endpoint refusal (not a silent fallback).

### FF6 — Ed448 stable bump (if available)

- Check crates.io for `ed448-goldilocks` v0.14.0 stable.
- If available: bump Cargo.toml + Cargo.lock; re-run EE6 unit tests
  + smoke to confirm no API drift.
- If not available: add a one-line note in the EE6 trust-assumption
  comment pointing at the risk register §EE6 audit gap and the
  pre-release dependency state.
- Documentation-only if no stable bump exists.

### FF7 — Plan FF wrap-up

- Version bump 0.35 → 0.36 + ROADMAP + STATUS + Plan GG draft +
  tag + ship.
- EE4's pre-tag placeholder check gates the tag push; STATUS.md
  must not contain `(this commit)` literals.
- Same post-ship pattern Plan EE established: ship commit lands
  STATUS rows for FF1-FF6 only; FF7 row backfilled in a SINGLE
  follow-up commit with commit SHA + run ID + cosign result. This
  is structurally cleaner than the Y7→DD7 placeholder-then-backfill
  pattern that needed two commits to roundtrip.

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (defaults picked)

1. **FF3 cert+key reload cadence.** Default: every token POST
   reloads from disk. Avoids the rotation race; minor performance
   cost is acceptable since token-endpoint hits are infrequent.
2. **FF4 cnf verification default.** Default: advisory (warn-on-
   mismatch) without `AETHER_OIDC_REQUIRE_CNF_X5T_S256=1`. Matches
   the Plan Z pattern where strict-mode is opt-in.
3. **FF5 client-CA chain depth.** Default: leaf + 1 CA (no
   intermediates). RFC 8705 doesn't require chain depth ≥ 2;
   keeps the smoke focused on the binding semantic.

## Risk register

- **FF3 cert reload race** — operator atomic-renames the cert on
  disk mid-refresh; the disk read sees the rename. PEM is a
  text format so partial reads would produce parse-fail (loud,
  not silent). Mitigation: parse failure surfaces as a token-POST
  error, not a silent fallback.
- **FF4 cnf claim defaults** — accepting cnf-absent silently is a
  policy choice that some operators will dislike. Mitigation: env
  knob flips advisory → hard-reject.
- **FF5 fake IdP TLS setup complexity** — generating a fake CA +
  serving HTTPS in a Python smoke is more setup than the existing
  HTTP smokes. Mitigation: use cryptography library + the
  ssl.create_default_context pattern; reuse helpers from BB4/CC6
  smokes where possible.

---

## Pre-FF context — Plan EE self-audit (v0.35.0 shipping)

**Audited commits**: 5e89e8f (EE4), 034e1f7 (EE5), d4ed0ef (EE6),
plus this version-bump commit.

### BLOCKERs — none

All three shipped Plan EE slices ship with their spec gates closed.
The pre-tag prerelease-checks job (new this plan) passes on the
v0.35 ship commit — no STATUS.md placeholders.

### HIGHs — none

### MEDs — documented and carried

- EE6 ed448-goldilocks v0.14.0-pre.15 is a pre-release dependency.
  Pinning + a trust-assumption inline comment is the v0.35 posture.
  FF6 bumps to stable when the RustCrypto org cuts v0.14.0.

### LOWs — knowingly carried

- EE4 `AETHER_SKIP_STATUS_PLACEHOLDER_CHECK=1` env escape is honored
  by the script but the workflow step has no `env:` block surface
  to set it from the workflow side. An operator hitting the rare
  legitimate-quote case would have to edit the workflow YAML
  temporarily. Acceptable: the legitimate-quote case is rare and
  the workflow file is operator-owned.
- EE5 garbage env value falls through silently (warn on parse fail
  is logged but no loud "ignored" line). Acceptable per risk-
  register §EE4 pattern.
- EE6 Ed448 sign path NOT implemented (verify-only). Real-world
  Ed448 SAML SP-signing is essentially nonexistent; verify-only
  matches the interop-not-issuance scope of EE6.

### What worked

- **EE4 caught a real historical placeholder on its first run.**
  The Y-audit row (line 168) had had `(this commit)` since v0.29
  ship and never been backfilled. The script surfaced it as part of
  its own clean-state check, and the backfill landed in the same
  commit. That single artifact validates the design: the gate
  CATCHES real placeholders, not just hypothetical future ones.
- **EE5 source-string refactor caught a real divergence by S5 of
  the smoke.** Two-decision picker (interval + source separately
  computed) said `source: env` when the actual interval came from
  the hint. Refactor to one-decision tuple eliminated the
  divergence by construction. The test now pins this against
  future regressions.
- **EE6 ed448-goldilocks API matched what we needed first try.**
  `SigningKey::generate()` + `sign_raw(msg)` + `verifying_key()` +
  `VerifyingKey::verify_raw(&sig, msg)` mirror the ed25519-dalek
  surface 1:1, so the EE6 dispatch arm was structurally identical
  to DD4's Ed25519 arm. Crate selection paid off.

### Diff numbers (approximate)

- aether-cli/src/main.rs: +300 LoC across EE4 (none — script + YAML
  only) + EE5 (helpers + parser + persist + picker) + EE6 (enum +
  OID dispatch + URI const + per-key arm + 5 unit tests).
- tests/check-status-no-placeholders.sh: +60 LoC.
- .github/workflows/release.yml: +28 LoC (prerelease-checks job).
- tests/ee5-saml-cache-duration-smoke.py: +250 LoC.
- tests/ee6-ed448-assertion-verify-smoke.py: +250 LoC.
- ROADMAP / STATUS / NEXT_24H_PLAN: +400 LoC (v0.35 entry + Plan
  FF draft + STATUS rows for EE4/EE5/EE6).

### Total binary delta

- aether 0.34.0 release binary on linux-x64: ~44 MB
- aether 0.35.0 release binary on linux-x64: ~44 MB (Ed448
  primitive + new helpers — no large new code paths)
