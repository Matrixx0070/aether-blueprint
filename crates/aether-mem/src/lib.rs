//! Memory orchestrator.
//!
//! Skeleton: hit type + `MemoryPolicyStore` (D5 user-editable edit log).
//! Episodic / semantic / procedural backends, the hybrid retriever, and the
//! local embedding pipeline land in feature-gated submodules once a target
//! vector backend is chosen (likely `lancedb`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryHit {
    pub doc_id: String,
    pub chunk_id: String,
    pub score: f32,
    pub text: String,
}

/// D5 — user-editable memory edit log.
///
/// Mirrors the Fable-5 `memory_user_edits` tool: view/add/remove/replace
/// operations on a numbered list of edits that constrain what the memory
/// writer is allowed to record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryPolicyStore {
    pub edits: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("edit count cap of 30 exceeded")]
    CountCap,
    #[error("edit length cap of 100000 chars exceeded")]
    LengthCap,
    #[error("invalid line number {0}")]
    InvalidLine(usize),
}

impl MemoryPolicyStore {
    pub const MAX_EDITS: usize = 30;
    pub const MAX_CHARS: usize = 100_000;

    pub fn view(&self) -> &[String] {
        &self.edits
    }

    pub fn add(&mut self, edit: impl Into<String>) -> Result<usize, PolicyError> {
        let s = edit.into();
        if s.len() > Self::MAX_CHARS {
            return Err(PolicyError::LengthCap);
        }
        if self.edits.len() >= Self::MAX_EDITS {
            return Err(PolicyError::CountCap);
        }
        self.edits.push(s);
        Ok(self.edits.len())
    }

    pub fn remove(&mut self, line: usize) -> Result<String, PolicyError> {
        if line == 0 || line > self.edits.len() {
            return Err(PolicyError::InvalidLine(line));
        }
        Ok(self.edits.remove(line - 1))
    }

    pub fn replace(
        &mut self,
        line: usize,
        new_text: impl Into<String>,
    ) -> Result<(), PolicyError> {
        let s = new_text.into();
        if s.len() > Self::MAX_CHARS {
            return Err(PolicyError::LengthCap);
        }
        if line == 0 || line > self.edits.len() {
            return Err(PolicyError::InvalidLine(line));
        }
        self.edits[line - 1] = s;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_remove_replace_round_trip() {
        let mut s = MemoryPolicyStore::default();
        assert_eq!(s.add("works at Anthropic").unwrap(), 1);
        assert_eq!(s.add("two cats").unwrap(), 2);
        s.replace(1, "no longer works at Anthropic").unwrap();
        assert_eq!(s.view()[0], "no longer works at Anthropic");
        let removed = s.remove(2).unwrap();
        assert_eq!(removed, "two cats");
        assert_eq!(s.view().len(), 1);
    }

    #[test]
    fn count_cap_enforced() {
        let mut s = MemoryPolicyStore::default();
        for i in 0..MemoryPolicyStore::MAX_EDITS {
            s.add(format!("edit {i}")).unwrap();
        }
        assert!(matches!(s.add("one more"), Err(PolicyError::CountCap)));
    }

    #[test]
    fn remove_invalid_line_errors() {
        let mut s = MemoryPolicyStore::default();
        s.add("only edit").unwrap();
        assert!(matches!(s.remove(0), Err(PolicyError::InvalidLine(0))));
        assert!(matches!(s.remove(5), Err(PolicyError::InvalidLine(5))));
    }
}
