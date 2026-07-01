//! AetherCode concolic unit test replay.
//!
//! Concolic = concrete + symbolic. This crate provides:
//!
//! 1. **PathRecord** — records the branch decisions made during a concrete run.
//! 2. **ConstraintSet** — the conjunction of symbolic constraints along that path.
//! 3. **InputGenerator** — negates one constraint at a time to generate new
//!    test inputs that explore alternative paths (the "concolic flip").
//! 4. **TestExtractor** — scans Rust test files and extracts concrete input
//!    values (literals in assert_eq!/assert! calls) as seed points.
//!
//! The approach is lightweight and does not require compiler instrumentation:
//! it works at the value level, with the user populating PathRecord via a
//! thin recording API.

pub mod constraint;
pub mod extractor;
pub mod generator;
pub mod record;

pub use constraint::{Constraint, ConstraintKind, ConstraintSet};
pub use extractor::{extract_test_inputs, TestInput};
pub use generator::{flip_constraints, generate_inputs, InputCandidate};
pub use record::{BranchDecision, PathRecord};

#[cfg(test)]
mod tests {
    use super::*;
    use constraint::{Constraint, ConstraintKind};
    use record::BranchDecision;

    fn sample_path() -> PathRecord {
        let mut path = PathRecord::new("test_add");
        path.record(BranchDecision {
            site_id: "add::check_overflow".into(),
            condition: Constraint {
                kind: ConstraintKind::Lt,
                lhs: "a".into(),
                rhs_int: Some(100),
                rhs_sym: None,
            },
            taken: true,
        });
        path.record(BranchDecision {
            site_id: "add::check_positive".into(),
            condition: Constraint {
                kind: ConstraintKind::Ge,
                lhs: "b".into(),
                rhs_int: Some(0),
                rhs_sym: None,
            },
            taken: true,
        });
        path
    }

    #[test]
    fn path_record_stores_decisions() {
        let path = sample_path();
        assert_eq!(path.decisions.len(), 2);
        assert_eq!(path.function_name, "test_add");
    }

    #[test]
    fn constraint_set_from_path() {
        let path = sample_path();
        let cs = ConstraintSet::from_path(&path);
        assert_eq!(cs.constraints.len(), 2);
    }

    #[test]
    fn flip_generates_negations() {
        let path = sample_path();
        let cs = ConstraintSet::from_path(&path);
        let candidates = flip_constraints(&cs);
        // One flip per constraint
        assert_eq!(candidates.len(), 2);
        // Each candidate has one negated constraint
        for (i, cand) in candidates.iter().enumerate() {
            let orig = &cs.constraints[i];
            let negated = &cand.constraints[i];
            assert_ne!(orig.kind, negated.kind, "flip[{i}] should negate kind");
        }
    }

    #[test]
    fn input_candidates_have_variables() {
        let path = sample_path();
        let inputs = generate_inputs(&path, 10);
        assert!(!inputs.is_empty());
        for inp in &inputs {
            assert!(!inp.assignments.is_empty());
        }
    }

    #[test]
    fn extract_test_inputs_finds_literals() {
        let source = r#"
        #[test]
        fn test_add() {
            assert_eq!(add(3, 4), 7);
            assert_eq!(add(0, 100), 100);
        }
        "#;
        let inputs = extract_test_inputs(source);
        assert!(!inputs.is_empty(), "should find literal values in assert_eq!");
    }

    #[test]
    fn constraint_negate_covers_all_kinds() {
        use ConstraintKind::*;
        let pairs = [(Eq, Ne), (Ne, Eq), (Lt, Ge), (Le, Gt), (Gt, Le), (Ge, Lt)];
        for (orig, expected) in pairs {
            let c = Constraint { kind: orig, lhs: "x".into(), rhs_int: Some(0), rhs_sym: None };
            let neg = c.negate();
            assert_eq!(neg.kind, expected, "{orig:?} should negate to {expected:?}");
        }
    }

    #[test]
    fn constraint_set_is_satisfiable_true_for_non_contradictory() {
        let mut cs = ConstraintSet::default();
        cs.add(Constraint { kind: ConstraintKind::Gt, lhs: "x".into(), rhs_int: Some(0), rhs_sym: None });
        cs.add(Constraint { kind: ConstraintKind::Lt, lhs: "x".into(), rhs_int: Some(100), rhs_sym: None });
        assert!(cs.is_trivially_satisfiable());
    }

    #[test]
    fn constraint_set_contradictory_detected() {
        let mut cs = ConstraintSet::default();
        cs.add(Constraint { kind: ConstraintKind::Gt, lhs: "x".into(), rhs_int: Some(10), rhs_sym: None });
        cs.add(Constraint { kind: ConstraintKind::Lt, lhs: "x".into(), rhs_int: Some(5), rhs_sym: None });
        assert!(!cs.is_trivially_satisfiable());
    }
}
