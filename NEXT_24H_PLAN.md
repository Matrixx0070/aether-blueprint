# Next 24-hour autonomous plan — Plan T

Drafted at end of Plan S (v0.22 → v0.23). Picks up the follow-up
items from S2/S3/S4/S5/S6 plus the v0.24+ scope items in ROADMAP.md.

---

## Plan T — followups + verifier hardening + close cred-blockers

**MISSION**: Promote the Plan S primitives from "shipped + reviewable"
to "operationally rich". Each S slice opened a follow-up; T closes
the most useful of them, adds verifier-side hardening (gpg-on-commit,
fence-strip on completion), and (if creds appear) closes R1/R2/R3.

**DONE MEANS** (6 criteria):

1. v0.24.0 tag on origin/main; cosign-signed autobuild green on 4
   platforms.
2. `aether sso login` accepts EdDSA-signed id_tokens against a
   live issuer that publishes one.
3. `aether usage --by-tool` shows per-tool-use-id rows (no more
   process-wide same-name aliasing).
4. `aether plugin verify --require-signed-commit` runs `git
   verify-commit` on the resolved SHA and refuses unsigned commits.
5. `POST /v1/complete` returns clean code (no triple-backtick fences,
   no language preamble) for at least 3 distinct language probes.
6. STATUS slice log entries T1–T7 with commit SHAs and live-check
   output (no banned vocabulary).

## Slices

### T1 — EdDSA support in JWT validation (S2 follow-up)

- Add `Algorithm::EdDSA` to the accepted set in `validate_id_token`.
- JWK shape: `kty=OKP, crv=Ed25519, x=<base64url>`.
- Live verify against a JWT minted with an Ed25519 key + a JWKS that
  exposes the OKP key.

### T2 — Per-tool_use_id tool_calls keying (S3 follow-up)

- Replace `Mutex<HashMap<tool_name, Instant>>` with
  `Mutex<HashMap<tool_use_id, (tool_name, Instant)>>`.
- Plumb tool_use_id through the Executor's tool_hook signature
  (Pre AND Post phases).
- Concurrent same-name calls now record independently.

### T3 — `--require-signed-commit` on plugin verify (S4 follow-up)

- New flag that runs `git verify-commit <sha>` on the resolved
  commit AND parses the output for "Good signature".
- Local-path mode: requires `git -C` to have gpg / ssh key access.
- URL mode: extends the shallow fetch from S4 to also fetch the
  notes/refs that carry the signature.

### T4 — Code-completion polish: fence-strip + language-aware trim (S5 follow-up)

- Server-side post-process inside `/v1/complete` that strips a
  leading ```language\n fence and a trailing ``` fence before
  emitting the delta.
- Buffer until first newline + check for fence start; if present,
  begin streaming from after the fence.
- Live verify with 3 language probes (Python, Rust, TypeScript).

### T5 — Team trust keychain rotation / revocation (S6 follow-up)

- New `aether plugin trust sync --remove-from-team <hex>` mode
  that removes a key from the team copy (subtractive). Requires
  --push to take effect.
- Local removals via `aether plugin trust remove` continue to
  apply locally only.
- Combined: an operator can yank a compromised key from the team
  copy AND from their local cache in one workflow.

### T6 — Close R1/R2/R3 if creds appear

- R1 Bedrock streaming: AWS profile from operator → live WS probe
- R2 JetBrains build: JDK 21 + Gradle host → `./gradlew buildPlugin`
- R3 Mantle sweep: MANTLE_API_KEY from operator → security-eval
  --provider mantle,anthropic --json

Each remains UNVERIFIED if no input arrives in this run.

### T7 — Self-audit + Plan U draft

- Audit T1–T6 against the Discipline Laws kernel.
- Draft Plan U: SAML support (alternative to OIDC for enterprises
  that still demand it), notification webhooks, secret rotation
  policy on plugin trust keychain, Prometheus metrics endpoint.

## Banned vocabulary

"should work" / "probably" / "likely fixed" / "seems fine" do not
appear in commit messages, STATUS rows, or end-of-turn reports.

## Open questions (default picked if no answer)

1. **EdDSA test issuer.** Default: spin up a local JWT + JWKS in
   Python (cryptography lib supports Ed25519) so the live verify
   doesn't need a public issuer that publishes EdDSA today.
2. **`--require-signed-commit` failure mode for unsigned commits
   in `cat-file -t` paths.** Default: emit clear error
   "commit_sha resolves but commit is unsigned"; non-zero exit.
3. **R1/R2/R3 creds.** Default unchanged: carry forward if absent.

## Risk register

- **EdDSA JWK parsing differs from RSA/EC** (uses OKP curve).
  jsonwebtoken crate supports this; verify the API surface in T1.
- **T2 ToolHookCallback signature change** ripples through every
  callsite. Mitigation: add tool_use_id as a new param with default
  empty string at the boundary so existing hooks compile cleanly
  during the transition.
- **T4 fence-strip can over-trim** if the model legitimately needs
  triple-backticks in its output. Mitigation: only strip ON THE
  FIRST line; preserve in-stream backticks.

---

## S7 — self-audit on Plan S (v0.23.0 shipping)

**Audited commits**: 5188b92 (S2), 0d4c034 (S1), 1b6fd21 (S3),
e6373bd (S4), b16e552 (S5), 2fdcaee (S6). 6 code commits + this
docs commit, +850 / -50 net.

### BLOCKER — none

### HIGH — none

### MED

- **S2 live round-trip remains UNVERIFIED in this session** — the
  full browser → token-endpoint → JWT-validate path needs a real
  OIDC client_id pre-registered against the issuer. Build is clean
  and the code path is short; operator's actual login is where this
  gets fully exercised. Carried as DONE/UNVERIFIED.
- **S5 model can emit triple-backtick fences** despite the "no
  fences, no preamble" prompt. Streaming output passes through
  verbatim; client must defensively strip. Promoted to T4.

### LOW

- **S1 ACL is read on every request** (no cache). Acceptable for
  v0.23 (dozens of rows max); fleet-scale would want a notify-
  watched cache.
- **S3 process-wide HashMap keys by tool_name**, so concurrent same-
  name calls alias. Promoted to T2.
- **S4 resolves SHA existence but not signature** (no gpg/ssh
  verify on the commit). Promoted to T3.
- **S5 spins a fresh provider per request** (no connection pool).
  Acceptable at v0.23 traffic; if completion becomes a hot path, a
  pool is a future slice.
- **S6 trust sync is unauthenticated at the application level** —
  trust flows entirely from git's auth. Documented as deliberate.
- **Bash CWD reset between turns** caused two build-skipped false
  positives during this plan. Mitigation in personal practice: always
  `cd /root/aether-blueprint &&` cargo invocations.

### What worked

- **All 6 code slices live-verified in this session** (S2 build-
  only, the other 5 with real curl / agent / sqlite probes).
- **Bounded slices held**: 6 commits, each with proof in the
  commit message body.
- **R7 MED #1 + MED #2 both closed** (S2 + S1).
- **Plan-then-ship cadence held**: Plan S draft from 267ed43 (R7)
  matches what shipped.
- **Banned-vocab discipline held** across all commits + STATUS rows.

### Diff numbers

- aether-cli:   +780 LoC (sso_cmd JWT path, tenant_cmd + ACL gate,
                          tool_call telemetry, resolve_commit,
                          complete_handler + SSE, trust_sync)
- aether-cli/Cargo.toml + workspace: +6 LoC (tokio-stream dep,
                                              jsonwebtoken pin)
- aether-plugin: 0 (S2-S6 didn't touch it — the v0.22 surface was
                    enough)
- README / ROADMAP / STATUS / NEXT_24H_PLAN: +140 / -30 LoC

### Total binary delta

- aether 0.22.0 release binary on linux-x64: ~40 MB
- aether 0.23.0 release binary on linux-x64: ~41 MB
  (tokio-stream tiny; jsonwebtoken brings in ring-style RSA/EC code
  that monomorphises to ~700 KB).
