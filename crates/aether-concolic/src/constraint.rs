//! Symbolic constraints and constraint sets.

use crate::record::PathRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintKind {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl ConstraintKind {
    pub fn negate(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::Lt => Self::Ge,
            Self::Le => Self::Gt,
            Self::Gt => Self::Le,
            Self::Ge => Self::Lt,
        }
    }
}

impl std::fmt::Display for ConstraintKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Eq => "==",
                Self::Ne => "!=",
                Self::Lt => "<",
                Self::Le => "<=",
                Self::Gt => ">",
                Self::Ge => ">=",
            }
        )
    }
}

/// A single symbolic constraint: `lhs <op> rhs_int` or `lhs <op> rhs_sym`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub kind: ConstraintKind,
    pub lhs: String,
    pub rhs_int: Option<i64>,
    pub rhs_sym: Option<String>,
}

impl Constraint {
    pub fn negate(&self) -> Self {
        Constraint {
            kind: self.kind.negate(),
            lhs: self.lhs.clone(),
            rhs_int: self.rhs_int,
            rhs_sym: self.rhs_sym.clone(),
        }
    }

    /// Try to evaluate this constraint with a concrete value assignment.
    pub fn evaluate(&self, env: &HashMap<String, i64>) -> Option<bool> {
        let lhs_val = env.get(&self.lhs)?;
        let rhs_val = if let Some(n) = self.rhs_int {
            n
        } else if let Some(s) = &self.rhs_sym {
            *env.get(s)?
        } else {
            return None;
        };
        Some(match self.kind {
            ConstraintKind::Eq => lhs_val == &rhs_val,
            ConstraintKind::Ne => lhs_val != &rhs_val,
            ConstraintKind::Lt => lhs_val < &rhs_val,
            ConstraintKind::Le => lhs_val <= &rhs_val,
            ConstraintKind::Gt => lhs_val > &rhs_val,
            ConstraintKind::Ge => lhs_val >= &rhs_val,
        })
    }
}

impl std::fmt::Display for Constraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(n) = self.rhs_int {
            write!(f, "{} {} {}", self.lhs, self.kind, n)
        } else if let Some(s) = &self.rhs_sym {
            write!(f, "{} {} {}", self.lhs, self.kind, s)
        } else {
            write!(f, "{} {} ?", self.lhs, self.kind)
        }
    }
}

/// A conjunction of constraints along a path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstraintSet {
    pub constraints: Vec<Constraint>,
}

impl ConstraintSet {
    pub fn add(&mut self, c: Constraint) {
        self.constraints.push(c);
    }

    /// Build a ConstraintSet from the taken-branch constraints in a PathRecord.
    pub fn from_path(path: &PathRecord) -> Self {
        let mut cs = ConstraintSet::default();
        for decision in &path.decisions {
            let c = if decision.taken {
                decision.condition.clone()
            } else {
                decision.condition.negate()
            };
            cs.add(c);
        }
        cs
    }

    /// Produce a copy with constraint[idx] negated.
    pub fn with_flip(&self, idx: usize) -> Self {
        let mut new = self.clone();
        if idx < new.constraints.len() {
            new.constraints[idx] = new.constraints[idx].negate();
        }
        new
    }

    /// Conservative satisfiability check for integer constraints on a single variable.
    /// If we have `x > a` and `x < b` with `a >= b` → unsatisfiable.
    pub fn is_trivially_satisfiable(&self) -> bool {
        let mut lower: HashMap<String, i64> = HashMap::new();
        let mut upper: HashMap<String, i64> = HashMap::new();

        for c in &self.constraints {
            let rhs = match c.rhs_int {
                Some(n) => n,
                None => continue,
            };
            match c.kind {
                ConstraintKind::Gt | ConstraintKind::Ge => {
                    let lb = if c.kind == ConstraintKind::Gt { rhs + 1 } else { rhs };
                    let e = lower.entry(c.lhs.clone()).or_insert(i64::MIN);
                    *e = (*e).max(lb);
                }
                ConstraintKind::Lt | ConstraintKind::Le => {
                    let ub = if c.kind == ConstraintKind::Lt { rhs - 1 } else { rhs };
                    let e = upper.entry(c.lhs.clone()).or_insert(i64::MAX);
                    *e = (*e).min(ub);
                }
                ConstraintKind::Eq => {
                    lower.insert(c.lhs.clone(), rhs);
                    upper.insert(c.lhs.clone(), rhs);
                }
                ConstraintKind::Ne => {} // can't easily prove contradiction
            }
        }
        for (var, &lb) in &lower {
            if let Some(&ub) = upper.get(var) {
                if lb > ub {
                    return false;
                }
            }
        }
        true
    }

    /// All free symbolic variable names referenced in this set.
    pub fn variables(&self) -> Vec<String> {
        let mut vars: Vec<String> = self
            .constraints
            .iter()
            .flat_map(|c| {
                let mut v = vec![c.lhs.clone()];
                if let Some(s) = &c.rhs_sym {
                    v.push(s.clone());
                }
                v
            })
            .collect();
        vars.sort();
        vars.dedup();
        vars
    }
}
