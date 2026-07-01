//! AetherCode mutation testing gate.
//!
//! Applies source-level mutations (operator substitution, literal perturbation,
//! condition negation, etc.) to Rust source files and verifies that the test
//! suite kills each mutant. Survived mutants identify test gaps.
//!
//! ## Gate usage (CI integration)
//!
//! ```no_run
//! use aether_muttest::{generator, MuttestConfig, MuttestReport, run_mutations};
//! use std::path::Path;
//!
//! let source = std::fs::read_to_string("src/lib.rs").unwrap();
//! let mutations = generator::generate_mutations("src/lib.rs", &source);
//! let applicable = generator::filter_applicable(mutations, &source);
//! let cfg = MuttestConfig { max_mutants: Some(50), ..Default::default() };
//! let report = run_mutations(&applicable, Path::new("."), &cfg).unwrap();
//! assert!(report.score >= 0.80, "mutation score below 80%: {}", report.summary());
//! ```

pub mod generator;
pub mod mutation;
pub mod runner;

pub use mutation::{MutantOutcome, MutantResult, Mutation, MutationKind};
pub use runner::{run_mutations, MuttestConfig, MuttestReport};

#[cfg(test)]
mod tests {
    use super::*;
    use generator::{filter_applicable, generate_mutations};

    const SAMPLE: &str = r#"
fn add(a: i32, b: i32) -> i32 {
    if a == 0 {
        return 0;
    }
    a + b
}

fn is_positive(x: i32) -> bool {
    x > 0
}

fn safe_div(a: f64, b: f64) -> Option<f64> {
    if b != 0.0 {
        Some(a / b)
    } else {
        None
    }
}
"#;

    #[test]
    fn generates_mutations_for_sample() {
        let muts = generate_mutations("src/lib.rs", SAMPLE);
        assert!(!muts.is_empty(), "should generate mutations");
    }

    #[test]
    fn eq_to_ne_generated() {
        let muts = generate_mutations("src/lib.rs", SAMPLE);
        assert!(
            muts.iter().any(|m| m.kind == MutationKind::EqToNe),
            "should find == → != mutation"
        );
    }

    #[test]
    fn arith_add_sub_generated() {
        let muts = generate_mutations("src/lib.rs", SAMPLE);
        assert!(
            muts.iter().any(|m| m.kind == MutationKind::ArithAddSub),
            "should find + → - mutation"
        );
    }

    #[test]
    fn relational_invert_generated() {
        let muts = generate_mutations("src/lib.rs", SAMPLE);
        assert!(
            muts.iter().any(|m| m.kind == MutationKind::RelationalInvert),
            "should find > → <= mutation"
        );
    }

    #[test]
    fn int_literal_perturb_generated() {
        let muts = generate_mutations("src/lib.rs", SAMPLE);
        assert!(
            muts.iter().any(|m| matches!(m.kind, MutationKind::IntLiteralPerturb { .. })),
            "should find integer literal mutations"
        );
    }

    #[test]
    fn filter_removes_inapplicable() {
        let muts = generate_mutations("src/lib.rs", SAMPLE);
        let before = muts.len();
        let after = filter_applicable(muts, SAMPLE);
        // All should be applicable since we generated from the same source
        assert_eq!(after.len(), before, "all mutations should be applicable");
    }

    #[test]
    fn mutation_apply_changes_source() {
        let source = "let x = a + b;";
        let muts = generate_mutations("test.rs", source);
        let addsub = muts.iter().find(|m| m.kind == MutationKind::ArithAddSub);
        if let Some(m) = addsub {
            let mutated = m.apply(source);
            assert_ne!(mutated, source, "mutated source should differ");
            assert!(mutated.contains('-'), "should replace + with -");
        }
    }

    #[test]
    fn mutation_apply_is_reversible() {
        let source = "if x == 0 { return true; }";
        let muts = generate_mutations("test.rs", source);
        let eq_mut = muts.iter().find(|m| m.kind == MutationKind::EqToNe);
        if let Some(m) = eq_mut {
            let mutated = m.apply(source);
            // Build a reverse mutation
            let reverse = Mutation {
                id: 0,
                kind: MutationKind::EqToNe,
                file: m.file.clone(),
                line: m.line,
                col: m.col,
                original: m.replacement.clone(),
                replacement: m.original.clone(),
            };
            let restored = reverse.apply(&mutated);
            assert_eq!(restored, source, "should restore original");
        }
    }

    #[test]
    fn report_score_calculation() {
        use mutation::{MutantOutcome, MutantResult};
        let results = vec![
            MutantResult {
                mutation: Mutation {
                    id: 1, kind: MutationKind::EqToNe, file: "f".into(),
                    line: 1, col: 0, original: "==".into(), replacement: "!=".into(),
                },
                outcome: MutantOutcome::Killed,
                duration_ms: 100,
                output_snippet: String::new(),
            },
            MutantResult {
                mutation: Mutation {
                    id: 2, kind: MutationKind::ArithAddSub, file: "f".into(),
                    line: 2, col: 0, original: "+".into(), replacement: "-".into(),
                },
                outcome: MutantOutcome::Survived,
                duration_ms: 50,
                output_snippet: String::new(),
            },
        ];
        let report = MuttestReport::from_results(results);
        assert_eq!(report.killed, 1);
        assert_eq!(report.survived, 1);
        assert!((report.score - 0.5).abs() < 0.001);
    }
}
