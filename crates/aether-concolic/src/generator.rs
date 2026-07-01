//! Concolic input generator — flips one branch constraint at a time.

use crate::constraint::{Constraint, ConstraintKind, ConstraintSet};
use crate::record::PathRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A candidate test input derived by flipping a constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputCandidate {
    /// Which branch index was flipped (0-based into the original PathRecord).
    pub flipped_idx: usize,
    /// The modified constraint set with the flipped constraint.
    pub constraints: Vec<Constraint>,
    /// Best-effort concrete assignments satisfying the flipped constraint set.
    pub assignments: HashMap<String, i64>,
    /// True if our solver found a satisfying assignment.
    pub is_feasible: bool,
}

/// Produce one InputCandidate per constraint in the set (each with one flip).
pub fn flip_constraints(cs: &ConstraintSet) -> Vec<InputCandidate> {
    (0..cs.constraints.len())
        .map(|i| {
            let flipped = cs.with_flip(i);
            let feasible = flipped.is_trivially_satisfiable();
            let assignments = if feasible {
                solve_assignments(&flipped)
            } else {
                HashMap::new()
            };
            InputCandidate {
                flipped_idx: i,
                constraints: flipped.constraints,
                assignments,
                is_feasible: feasible,
            }
        })
        .collect()
}

/// Generate up to `max` InputCandidates from a concrete PathRecord.
pub fn generate_inputs(path: &PathRecord, max: usize) -> Vec<InputCandidate> {
    let cs = ConstraintSet::from_path(path);
    let mut candidates = flip_constraints(&cs);
    candidates.retain(|c| c.is_feasible);

    // Merge entry values into assignments
    for cand in &mut candidates {
        for (k, v) in &path.entry_values {
            cand.assignments.entry(k.clone()).or_insert(*v);
        }
    }

    candidates.truncate(max);
    candidates
}

/// Lightweight constraint solver: assign values satisfying a ConstraintSet.
/// Only handles integer constraints with literal RHS.
fn solve_assignments(cs: &ConstraintSet) -> HashMap<String, i64> {
    let vars = cs.variables();
    let mut assignments: HashMap<String, i64> = HashMap::new();

    // Initial guess: all variables = 0
    for v in &vars {
        assignments.insert(v.clone(), 0);
    }

    // Iterate to satisfy each constraint (simple push)
    for _ in 0..64 {
        let mut changed = false;
        for c in &cs.constraints {
            let rhs = match c.rhs_int {
                Some(n) => n,
                None => continue,
            };
            let current = *assignments.get(&c.lhs).unwrap_or(&0);
            let needed = satisfy_value(c.kind, current, rhs);
            if needed != current {
                assignments.insert(c.lhs.clone(), needed);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    assignments
}

/// Return a value for `lhs` that satisfies `lhs <kind> rhs`, starting from `current`.
fn satisfy_value(kind: ConstraintKind, current: i64, rhs: i64) -> i64 {
    match kind {
        ConstraintKind::Eq => rhs,
        ConstraintKind::Ne => {
            if current == rhs {
                rhs.wrapping_add(1)
            } else {
                current
            }
        }
        ConstraintKind::Lt => {
            if current < rhs {
                current
            } else {
                rhs.saturating_sub(1)
            }
        }
        ConstraintKind::Le => {
            if current <= rhs {
                current
            } else {
                rhs
            }
        }
        ConstraintKind::Gt => {
            if current > rhs {
                current
            } else {
                rhs.saturating_add(1)
            }
        }
        ConstraintKind::Ge => {
            if current >= rhs {
                current
            } else {
                rhs
            }
        }
    }
}
