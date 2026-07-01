//! AetherCode differential fuzzer.
//!
//! Runs two implementations of the same interface with mutated inputs and
//! surfaces any inputs where they disagree (divergences).
//!
//! ## Quick start
//!
//! ```rust
//! use aether_difffuzz::{DiffTarget, DiffOutput, FuzzSession};
//!
//! struct RevA;
//! impl DiffTarget for RevA {
//!     fn name(&self) -> &str { "rev_a" }
//!     fn run(&self, input: &[u8]) -> DiffOutput {
//!         let mut v = input.to_vec();
//!         v.reverse();
//!         DiffOutput::Ok(v)
//!     }
//! }
//!
//! struct RevB;
//! impl DiffTarget for RevB {
//!     fn name(&self) -> &str { "rev_b" }
//!     fn run(&self, input: &[u8]) -> DiffOutput {
//!         // Same as A — no divergences expected
//!         let mut v = input.to_vec();
//!         v.reverse();
//!         DiffOutput::Ok(v)
//!     }
//! }
//!
//! let mut session = FuzzSession::new(RevA, RevB, 42);
//! session.add_seed(b"hello world".to_vec());
//! let found = session.run(200);
//! assert_eq!(found.len(), 0, "identical impls should never diverge");
//! ```

pub mod mutator;
pub mod runner;
pub mod session;

pub use mutator::{Mutator, MutationOp, Xorshift64};
pub use runner::{DiffOutput, DiffTarget, DiffRunner, Divergence, DivergenceKind, RunnerConfig};
pub use session::{FuzzSession, FuzzStats};

#[cfg(test)]
mod tests {
    use super::*;

    // ── Targets for tests ──────────────────────────────────────────────────

    struct UpperA;
    impl DiffTarget for UpperA {
        fn name(&self) -> &str { "upper_a" }
        fn run(&self, input: &[u8]) -> DiffOutput {
            DiffOutput::Ok(input.to_ascii_uppercase())
        }
    }

    struct UpperB;
    impl DiffTarget for UpperB {
        fn name(&self) -> &str { "upper_b" }
        fn run(&self, input: &[u8]) -> DiffOutput {
            // Identical implementation — should never diverge
            DiffOutput::Ok(input.to_ascii_uppercase())
        }
    }

    struct BuggyUpper;
    impl DiffTarget for BuggyUpper {
        fn name(&self) -> &str { "buggy" }
        fn run(&self, input: &[u8]) -> DiffOutput {
            // Bug: capitalise only first byte
            let mut out = input.to_vec();
            if let Some(b) = out.first_mut() {
                *b = b.to_ascii_uppercase();
            }
            DiffOutput::Ok(out)
        }
    }

    struct PanicOnNul;
    impl DiffTarget for PanicOnNul {
        fn name(&self) -> &str { "panic_on_nul" }
        fn run(&self, input: &[u8]) -> DiffOutput {
            if input.contains(&0) {
                DiffOutput::Panic("contains NUL".into())
            } else {
                DiffOutput::Ok(input.to_vec())
            }
        }
    }

    // ── Tests ──────────────────────────────────────────────────────────────

    #[test]
    fn identical_impls_never_diverge() {
        let mut session = FuzzSession::new(UpperA, UpperB, 1337);
        session.add_seed(b"Hello World".to_vec());
        let found = session.run(500);
        assert!(found.is_empty(), "identical impls should never diverge, got: {found:?}");
    }

    #[test]
    fn buggy_impl_diverges() {
        let mut session = FuzzSession::new(UpperA, BuggyUpper, 99);
        session.add_seed(b"hello".to_vec());
        let found = session.run(1000);
        assert!(
            !found.is_empty(),
            "buggy impl should diverge on multi-char input"
        );
        assert!(found.iter().all(|d| d.kind == DivergenceKind::OutputMismatch));
    }

    #[test]
    fn panic_mismatch_detected() {
        let runner = DiffRunner::new(UpperA, PanicOnNul);
        // Input with NUL byte
        let div = runner.compare(&[b'a', 0, b'b'], 0);
        assert!(div.is_some());
        assert_eq!(div.unwrap().kind, DivergenceKind::PanicMismatch);
    }

    #[test]
    fn replay_reproduces_divergence() {
        let mut session = FuzzSession::new(UpperA, BuggyUpper, 42);
        session.add_seed(b"abc".to_vec());
        let found = session.run(500);
        // Take the first diverging input and replay it
        if let Some(div) = found.first() {
            let replay = session.replay(&div.input);
            assert!(replay.is_some(), "replay must reproduce the divergence");
        }
    }

    #[test]
    fn xorshift_rng_is_deterministic() {
        let mut a = Xorshift64::new(42);
        let mut b = Xorshift64::new(42);
        for _ in 0..100 {
            assert_eq!(a.next(), b.next());
        }
    }

    #[test]
    fn mutator_generates_varied_inputs() {
        let mut m = Mutator::new(7);
        let inputs: Vec<Vec<u8>> = (0..50).map(|_| m.next_input().0).collect();
        // Not all inputs should be identical
        let unique: std::collections::HashSet<Vec<u8>> = inputs.into_iter().collect();
        assert!(unique.len() > 1, "mutator should produce varied inputs");
    }

    #[test]
    fn stats_track_correctly() {
        let mut session = FuzzSession::new(UpperA, BuggyUpper, 11);
        session.add_seed(b"hello world".to_vec());
        session.run(100);
        assert_eq!(session.stats.iterations, 100);
        // divergences counter should match divergences vec length
        assert_eq!(session.stats.divergences, session.divergences.len() as u64);
    }

    #[test]
    fn length_mismatch_detected() {
        struct LongOut;
        impl DiffTarget for LongOut {
            fn name(&self) -> &str { "long" }
            fn run(&self, input: &[u8]) -> DiffOutput {
                // Returns 3× the input
                DiffOutput::Ok(input.repeat(3))
            }
        }
        let runner = DiffRunner::new(UpperA, LongOut);
        // For input with len > 2, ratio > 3.0 → LengthMismatch
        let div = runner.compare(b"hello", 0);
        assert!(div.is_some());
        assert_eq!(div.unwrap().kind, DivergenceKind::LengthMismatch);
    }
}
