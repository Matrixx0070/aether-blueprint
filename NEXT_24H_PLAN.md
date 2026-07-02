# Next 24-hour autonomous plan — Plan HH

Drafted at end of Plan GG (v0.38 → v0.39). Plan GG shipped all 5
engineering slices (GG1-GG4 SCIM routes/auth/lifecycle/filter in one
commit, GG5 live smoke) — closes EE3, the last carry-forward from
the AA→BB→CC→DD→EE→FF chain. Every enterprise-auth deferral opened
since Plan Y (SAML) is now closed: SAML (Y), mTLS (FF), SCIM (GG).

**Carry-forward status at end of GG:** none. This is the first plan
boundary with an EMPTY cred/scope-blocked carry-forward list.

**Non-plan debt (still open, from the v0.36 tiers build):**

- TIER 24 distributed scanning is still a stub (aether-distrib).
- No real ZK-SNARK circuits behind aether-zk.

**User directive (2026-07-02, still standing):** "fully autonomous
until you're fully satisfied Aether is ready for regular use like
Claude Code... 100 times better." The v0.38 readiness gauntlet
(G0-G3) covered coding tasks + REPL lifecycle. Plan HH extends that
mandate into the two areas that most affect daily "is this better
than Claude Code" perception: MCP/tool ecosystem breadth and
IDE-adjacent workflows, alongside closing the TIER 24 / ZK debt.

---

## Plan HH — options for next session

Two roughly-equal-weight candidates; pick based on what's cheapest
to make real progress on without new external creds:

**HH-A: TIER 24 distributed scanning, made real.** aether-distrib is
a stub. Land an actual distributed-analysis primitive: fan out a
scan (e.g. secrets-scan or crypto-audit) across N local worker
processes coordinated via a simple work-queue, live-verified against
a real multi-hundred-file target. Closes a concrete "stub" gap
flagged since the v0.36 tiers build.

**HH-B: real ZK-SNARK circuit behind aether-zk.** Currently
aether-zk has no real ZK-SNARK circuits. Land one minimal real
circuit (e.g. a Groth16/PLONK "prove I know a preimage of this
hash" or "prove a file matches a committed hash without revealing
it" circuit) using an existing Rust ZK crate (arkworks or halo2),
live-verified prove+verify round-trip. Closes the other v0.36 stub
gap.

**HH-C (readiness-gauntlet extension, cross-cutting):** run a second
gauntlet round per the G0-G3 template, covering scenarios not yet
exercised: multi-file refactor driven live through the REPL (not
just via coding-eval), a full git commit/PR workflow, and a
long-running background-task scenario (start something slow, do
other work, check back). Any new gap found gets fixed + tested the
same way G1-G3 were.

Recommended default if the user just says "continue": HH-C first
(cheapest, directly serves the standing "ready for regular use"
mandate), then HH-A or HH-B as a dedicated plan.

## Risk register

- §HH-A: a fake/simulated "distributed" primitive (e.g. spawning
  threads instead of real separate processes/workers) would not
  actually close the stub gap — the live-verify must show real
  process-level parallelism, not just async concurrency already
  present elsewhere in the codebase.
- §HH-B: an ZK crate landing in pre-1.0/pre-release state (the EE6
  Ed448 pattern repeating) should be documented as a trust
  assumption, same as ed448-goldilocks.
