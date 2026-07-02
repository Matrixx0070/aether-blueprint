# Next 24-hour autonomous plan — Plan HH (2/3 complete)

Drafted at end of Plan GG (v0.38 → v0.39). Plan GG shipped all 5
engineering slices (GG1-GG5 SCIM), closing EE3 — the last
cred-blocked carry-forward. Plan HH offered three options; two are
now DONE:

- **HH-C (DONE, no ship needed)**: second readiness-gauntlet round
  (live REPL multi-file refactor, git commit workflow, long-running
  background task) — all 3 passed clean against v0.39.0. Zero
  product defects; two apparent test failures were methodology
  mistakes on the tester's side, and the agent's refusals in both
  cases were the objectively correct behavior.
- **HH-A (DONE, shipped as v0.40.0)**: `aether-distrib` rebuilt from
  a disconnected 18-line stub into real multi-process fan-out
  (`aether distributed --target <dir> --workers N`), live-verified
  with distinct real OS pids. Surfaced and fixed a critical
  pre-existing perf bug (regex ruleset recompiled per-line in
  aether-secrets — 70K-line files took minutes, now 70ms) and a
  latent HOME-env test-isolation flake.
- **HH-B (NEXT)**: land a real ZK-SNARK circuit behind `aether-zk`,
  currently zero real circuits. Minimal real prove/verify round-trip
  using an existing Rust ZK crate (arkworks or halo2) — e.g. "prove I
  know a preimage of this hash" (Groth16 or PLONK). Live-verified
  prove+verify, not just that the crate compiles.

## Risk register carried forward

- §HH-B: a ZK crate landing in pre-1.0/pre-release state (the EE6
  Ed448 pattern repeating) should be documented as a trust
  assumption, same as ed448-goldilocks.
- §HH-B: "real circuit" means an actual constraint system that proves
  a genuine relation and a verifier that rejects a forged proof —
  not a toy that always returns true. The live smoke must include a
  NEGATIVE case (wrong witness / tampered proof → verify fails).

## After HH-B

No forced next step — Plan GG left the cred-blocked carry-forward
list empty and HH-A/HH-C closed the two known non-plan debt items.
Once HH-B ships, do a final holistic satisfaction pass: rerun
`aether coding-eval` once more end-to-end, confirm `cargo test
--workspace` is green + non-flaky, and write an honest closing
assessment of what "ready for regular use, better than Claude Code"
does and doesn't mean at that point — including anything still
UNVERIFIED (macOS/Windows binaries only smoke-tested via cosign, not
run; real enterprise IdP integrations for SAML/mTLS/SCIM only
fake-client-tested).
