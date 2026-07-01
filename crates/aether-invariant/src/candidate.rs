//! Invariant types.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvariantKind {
    /// lhs == rhs_int (constant)
    Eq,
    /// lhs != rhs_int
    Ne,
    /// lhs > rhs_int
    Gt,
    /// lhs >= rhs_int
    Ge,
    /// lhs < rhs_int
    Lt,
    /// lhs <= rhs_int
    Le,
    /// lhs == multiplier * rhs_sym (linear)
    LinearMul { multiplier: i64 },
    /// lhs == rhs_sym (variable equality)
    EqVar,
    /// lhs in a finite set of values
    InSet(Vec<i64>),
}

impl std::fmt::Display for InvariantKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvariantKind::Eq => write!(f, "=="),
            InvariantKind::Ne => write!(f, "!="),
            InvariantKind::Gt => write!(f, ">"),
            InvariantKind::Ge => write!(f, ">="),
            InvariantKind::Lt => write!(f, "<"),
            InvariantKind::Le => write!(f, "<="),
            InvariantKind::LinearMul { multiplier } => write!(f, "== {multiplier}*"),
            InvariantKind::EqVar => write!(f, "=="),
            InvariantKind::InSet(s) => {
                let vals: Vec<_> = s.iter().map(|n| n.to_string()).collect();
                write!(f, "in {{{}}}", vals.join(","))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invariant {
    pub lhs: String,
    pub kind: InvariantKind,
    pub rhs_int: Option<i64>,
    pub rhs_sym: Option<String>,
    /// Fraction of observations consistent with this invariant (0–1).
    pub confidence: f64,
    /// Number of observations used.
    pub support: usize,
}

impl std::fmt::Display for Invariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            InvariantKind::InSet(_) | InvariantKind::Eq | InvariantKind::Ne
            | InvariantKind::Gt | InvariantKind::Ge | InvariantKind::Lt | InvariantKind::Le => {
                if let Some(n) = self.rhs_int {
                    write!(f, "{} {} {} [conf={:.2} n={}]", self.lhs, self.kind, n, self.confidence, self.support)
                } else {
                    write!(f, "{} {} [conf={:.2} n={}]", self.lhs, self.kind, self.confidence, self.support)
                }
            }
            InvariantKind::LinearMul { multiplier } => {
                let rhs = self.rhs_sym.as_deref().unwrap_or("?");
                write!(f, "{} == {}*{} [conf={:.2} n={}]", self.lhs, multiplier, rhs, self.confidence, self.support)
            }
            InvariantKind::EqVar => {
                let rhs = self.rhs_sym.as_deref().unwrap_or("?");
                write!(f, "{} == {} [conf={:.2} n={}]", self.lhs, rhs, self.confidence, self.support)
            }
        }
    }
}
