//! AetherCode invariant miner (Daikon-style).
//!
//! Observes program values across multiple runs and infers likely invariants:
//!   - `x > 0` (lower bound)
//!   - `x <= 100` (upper bound)
//!   - `y == 2 * x` (linear relationship)
//!   - `z in {0, 1}` (enumerable set)
//!   - `x == y` (equality)
//!   - `x != 0` (non-zero)
//!   - `x >= 0` (non-negative)
//!
//! ## Workflow
//!
//! ```rust
//! use aether_invariant::{InvariantMiner, Observation};
//!
//! let mut miner = InvariantMiner::new();
//! miner.observe("x", 5);
//! miner.observe("x", 10);
//! miner.observe("x", 3);
//! miner.observe("y", 10);
//! miner.observe("y", 20);
//! miner.observe("y", 6);
//!
//! let report = miner.mine();
//! // Likely finds: x > 0, y > 0, y == 2*x
//! println!("{}", report.summary());
//! ```

pub mod candidate;
pub mod miner;
pub mod report;

pub use candidate::{Invariant, InvariantKind};
pub use miner::InvariantMiner;
pub use report::InvariantReport;

/// A single observed value for a named variable.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Observation {
    pub variable: String,
    pub value: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mines_positive_bound() {
        let mut m = InvariantMiner::new();
        for v in [1, 5, 10, 3, 7] {
            m.observe("x", v);
        }
        let report = m.mine();
        let found = report.invariants.iter().any(|inv| {
            matches!(inv.kind, InvariantKind::Gt | InvariantKind::Ge)
                && inv.lhs == "x"
                && inv.rhs_int == Some(0)
        });
        assert!(found, "should find x > 0, got: {:?}", report.invariants);
    }

    #[test]
    fn mines_upper_bound() {
        let mut m = InvariantMiner::new();
        for v in [10, 20, 30, 15, 5] {
            m.observe("x", v);
        }
        let report = m.mine();
        let found = report.invariants.iter().any(|inv| {
            matches!(inv.kind, InvariantKind::Le | InvariantKind::Lt)
                && inv.lhs == "x"
        });
        assert!(found, "should find upper bound for x");
    }

    #[test]
    fn mines_linear_relation() {
        let mut m = InvariantMiner::new();
        for (x, y) in [(1, 2), (3, 6), (5, 10), (7, 14)] {
            m.observe("x", x);
            m.observe("y", y);
            m.observe_pair("y", "x", y, x);
        }
        let report = m.mine();
        let found = report.invariants.iter().any(|inv| {
            matches!(inv.kind, InvariantKind::LinearMul { multiplier: 2 })
                && inv.lhs == "y"
        });
        assert!(found, "should find y == 2*x, got: {:?}", report.invariants);
    }

    #[test]
    fn mines_enum_set() {
        let mut m = InvariantMiner::new();
        for v in [0, 1, 0, 1, 0, 1] {
            m.observe("flag", v);
        }
        let report = m.mine();
        let found = report.invariants.iter().any(|inv| {
            matches!(inv.kind, InvariantKind::InSet(_)) && inv.lhs == "flag"
        });
        assert!(found, "should find flag in {{0, 1}}, got: {:?}", report.invariants);
    }

    #[test]
    fn mines_non_zero() {
        let mut m = InvariantMiner::new();
        for v in [1, 2, 3, -1, 5] {
            m.observe("x", v);
        }
        let report = m.mine();
        let found = report.invariants.iter().any(|inv| {
            inv.lhs == "x" && inv.kind == InvariantKind::Ne && inv.rhs_int == Some(0)
        });
        assert!(found, "should find x != 0, got: {:?}", report.invariants);
    }

    #[test]
    fn mines_equality_between_vars() {
        let mut m = InvariantMiner::new();
        for v in [5, 10, 3] {
            m.observe("a", v);
            m.observe("b", v);
            m.observe_pair("a", "b", v, v);
        }
        let report = m.mine();
        let found = report.invariants.iter().any(|inv| {
            inv.kind == InvariantKind::EqVar && inv.lhs == "a" && inv.rhs_sym.as_deref() == Some("b")
        });
        assert!(found, "should find a == b, got: {:?}", report.invariants);
    }

    #[test]
    fn confidence_below_threshold_not_reported() {
        let mut m = InvariantMiner::new();
        // Only 1 observation — too few to be confident
        m.observe("x", 42);
        let report = m.mine();
        // Bounds should be omitted when fewer than 2 obs
        assert!(
            report.invariants.iter().all(|inv| inv.lhs != "x")
                || report.invariants.iter().all(|inv| inv.confidence < 0.99),
            "should not report high-confidence invariants from 1 sample"
        );
    }

    #[test]
    fn report_summary_not_empty() {
        let mut m = InvariantMiner::new();
        for v in [1, 2, 3] {
            m.observe("n", v);
        }
        let report = m.mine();
        let s = report.summary();
        assert!(!s.is_empty());
    }
}
