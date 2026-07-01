//! InvariantReport: the output of InvariantMiner::mine().

use crate::candidate::Invariant;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct InvariantReport {
    pub invariants: Vec<Invariant>,
}

impl InvariantReport {
    pub fn summary(&self) -> String {
        if self.invariants.is_empty() {
            return "no invariants found".to_string();
        }
        let lines: Vec<String> = self.invariants.iter().map(|i| i.to_string()).collect();
        lines.join("\n")
    }

    pub fn by_variable(&self, var: &str) -> Vec<&Invariant> {
        self.invariants.iter().filter(|i| i.lhs == var).collect()
    }

    pub fn high_confidence(&self, threshold: f64) -> Vec<&Invariant> {
        self.invariants
            .iter()
            .filter(|i| i.confidence >= threshold)
            .collect()
    }
}
