//! PathRecord: records branch decisions during a concrete run.

use crate::constraint::Constraint;
use serde::{Deserialize, Serialize};

/// A single branch decision observed during a concrete run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchDecision {
    /// Source-location label for the branch (e.g. "fn::if_condition_name").
    pub site_id: String,
    /// The symbolic condition evaluated at this branch.
    pub condition: Constraint,
    /// True if the branch was taken, false if the else-branch was taken.
    pub taken: bool,
}

/// Records the path taken during a single concrete execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathRecord {
    pub function_name: String,
    pub decisions: Vec<BranchDecision>,
    /// Optional concrete input values bound at function entry.
    pub entry_values: std::collections::HashMap<String, i64>,
}

impl PathRecord {
    pub fn new(function_name: impl Into<String>) -> Self {
        PathRecord {
            function_name: function_name.into(),
            decisions: Vec::new(),
            entry_values: std::collections::HashMap::new(),
        }
    }

    pub fn record(&mut self, decision: BranchDecision) {
        self.decisions.push(decision);
    }

    pub fn bind(&mut self, var: impl Into<String>, value: i64) {
        self.entry_values.insert(var.into(), value);
    }

    /// The path identifier: stable hash of site_ids + taken booleans.
    pub fn path_id(&self) -> String {
        let parts: Vec<String> = self
            .decisions
            .iter()
            .map(|d| format!("{}:{}", d.site_id, if d.taken { "T" } else { "F" }))
            .collect();
        parts.join("|")
    }
}
