//! InvariantMiner: collects observations and infers invariants.

use crate::candidate::{Invariant, InvariantKind};
use crate::report::InvariantReport;
use std::collections::{HashMap, HashSet};

const MIN_SUPPORT: usize = 2;
const CONFIDENCE_THRESHOLD: f64 = 0.95;
/// Max cardinality for InSet invariant
const MAX_SET_SIZE: usize = 8;

/// Pairs of (var_a_value, var_b_value) observed together in the same run.
pub struct PairObs {
    pub a: String,
    pub b: String,
    pub pairs: Vec<(i64, i64)>,
}

pub struct InvariantMiner {
    /// Per-variable observations.
    pub obs: HashMap<String, Vec<i64>>,
    /// Cross-variable paired observations (for linear relations).
    pub pairs: Vec<PairObs>,
}

impl InvariantMiner {
    pub fn new() -> Self {
        InvariantMiner {
            obs: HashMap::new(),
            pairs: Vec::new(),
        }
    }

    pub fn observe(&mut self, var: impl Into<String>, value: i64) {
        self.obs.entry(var.into()).or_default().push(value);
    }

    pub fn observe_pair(&mut self, a: impl Into<String>, b: impl Into<String>, val_a: i64, val_b: i64) {
        let a = a.into();
        let b = b.into();
        if let Some(existing) = self.pairs.iter_mut().find(|p| p.a == a && p.b == b) {
            existing.pairs.push((val_a, val_b));
        } else {
            self.pairs.push(PairObs { a, b, pairs: vec![(val_a, val_b)] });
        }
    }

    /// Mine invariants from all observations. Returns an InvariantReport.
    pub fn mine(&self) -> InvariantReport {
        let mut invariants = Vec::new();

        for (var, values) in &self.obs {
            if values.len() < MIN_SUPPORT {
                continue;
            }
            mine_single_var(var, values, &mut invariants);
        }

        for pair in &self.pairs {
            if pair.pairs.len() < MIN_SUPPORT {
                continue;
            }
            mine_pair(&pair.a, &pair.b, &pair.pairs, &mut invariants);
        }

        // Deduplicate
        invariants.dedup_by(|a, b| a.lhs == b.lhs && a.kind == b.kind && a.rhs_int == b.rhs_int);
        InvariantReport { invariants }
    }
}

impl Default for InvariantMiner {
    fn default() -> Self {
        Self::new()
    }
}

fn mine_single_var(var: &str, values: &[i64], out: &mut Vec<Invariant>) {
    let n = values.len();
    let min = *values.iter().min().unwrap();
    let max = *values.iter().max().unwrap();

    // Constant: all equal
    if min == max {
        out.push(Invariant {
            lhs: var.to_string(),
            kind: InvariantKind::Eq,
            rhs_int: Some(min),
            rhs_sym: None,
            confidence: 1.0,
            support: n,
        });
        return; // subsumes all other single-var invariants
    }

    // Lower bound: x > 0
    if min > 0 {
        out.push(Invariant {
            lhs: var.to_string(),
            kind: InvariantKind::Gt,
            rhs_int: Some(0),
            rhs_sym: None,
            confidence: 1.0,
            support: n,
        });
    } else if min >= 0 {
        out.push(Invariant {
            lhs: var.to_string(),
            kind: InvariantKind::Ge,
            rhs_int: Some(0),
            rhs_sym: None,
            confidence: 1.0,
            support: n,
        });
    }

    // Non-zero: x != 0
    if !values.iter().any(|&v| v == 0) {
        out.push(Invariant {
            lhs: var.to_string(),
            kind: InvariantKind::Ne,
            rhs_int: Some(0),
            rhs_sym: None,
            confidence: 1.0,
            support: n,
        });
    }

    // Upper bound: x <= max observed
    out.push(Invariant {
        lhs: var.to_string(),
        kind: InvariantKind::Le,
        rhs_int: Some(max),
        rhs_sym: None,
        confidence: CONFIDENCE_THRESHOLD,
        support: n,
    });

    // InSet: if cardinality is small
    let unique: HashSet<i64> = values.iter().copied().collect();
    if unique.len() <= MAX_SET_SIZE && unique.len() < n {
        let mut set_vals: Vec<i64> = unique.into_iter().collect();
        set_vals.sort();
        out.push(Invariant {
            lhs: var.to_string(),
            kind: InvariantKind::InSet(set_vals),
            rhs_int: None,
            rhs_sym: None,
            confidence: 1.0,
            support: n,
        });
    }
}

fn mine_pair(a: &str, b: &str, pairs: &[(i64, i64)], out: &mut Vec<Invariant>) {
    let n = pairs.len();

    // Equality: a == b for all pairs
    if pairs.iter().all(|(va, vb)| va == vb) {
        out.push(Invariant {
            lhs: a.to_string(),
            kind: InvariantKind::EqVar,
            rhs_int: None,
            rhs_sym: Some(b.to_string()),
            confidence: 1.0,
            support: n,
        });
        return;
    }

    // Linear: a == k * b for small k in {2,3,4,5,-1,-2}
    for &k in &[2i64, 3, 4, 5, -1, -2] {
        if pairs.iter().all(|(va, vb)| *va == k * vb) {
            out.push(Invariant {
                lhs: a.to_string(),
                kind: InvariantKind::LinearMul { multiplier: k },
                rhs_int: None,
                rhs_sym: Some(b.to_string()),
                confidence: 1.0,
                support: n,
            });
        }
    }
}
