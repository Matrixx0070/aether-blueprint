//! Memory orchestrator + on-disk file store.
//!
//! Today: file-backed memory at `~/.aether/memory/<name>.md` plus the
//! `MemoryRead` / `MemoryWrite` tools and the index-builder consumed at
//! session start. The `MemoryPolicyStore` is the D5 user-editable edit log
//! (kept as a future hook for fully-managed memory semantics).
//!
//! Future: episodic / semantic / procedural backends + hybrid retrieval
//! land here once a vector backend is chosen (likely lancedb).

use aether_tools::{Tool, ToolError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const MEMORY_REL_PATH: &str = ".aether/memory";

pub fn memory_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(MEMORY_REL_PATH)
}

/// Return (file_name_stem, first_line) for every *.md in the memory dir,
/// sorted by name. Used by both `/memory` and the index reminder builder.
pub fn memory_index() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let dir = memory_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let stem = match p.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let first = std::fs::read_to_string(&p)
            .ok()
            .and_then(|s| {
                s.lines()
                    .next()
                    .map(|l| l.trim_start_matches('#').trim().to_string())
            })
            .unwrap_or_default();
        out.push((stem, first));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Compose the `<memory-index>` kernel reminder. None when nothing's there.
pub fn memory_index_reminder() -> Option<String> {
    let idx = memory_index();
    if idx.is_empty() {
        return None;
    }
    let mut body = String::from("<memory-index>\n");
    for (name, hint) in idx {
        body.push_str(&format!("- {name}"));
        if !hint.is_empty() {
            body.push_str(&format!(" — {hint}"));
        }
        body.push('\n');
    }
    body.push_str("</memory-index>");
    Some(body)
}

/// `MemoryRead` tool — reads a single named memory file.
pub struct MemoryReadTool;

#[derive(Debug, Deserialize)]
struct MemoryReadInput {
    name: String,
}

#[async_trait]
impl Tool for MemoryReadTool {
    fn name(&self) -> &str {
        "MemoryRead"
    }
    fn description(&self) -> &str {
        "Read a named memory file from ~/.aether/memory/. Use the memory-index \
         system reminder to discover available names. Returns the file contents \
         verbatim."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": { "name": {"type": "string", "description": "Memory name (filename stem, no .md)"} },
            "required": ["name"]
        })
    }
    async fn run(&self, input: serde_json::Value) -> Result<String, ToolError> {
        let inp: MemoryReadInput =
            serde_json::from_value(input).map_err(|e| ToolError::Schema(e.to_string()))?;
        if inp.name.contains('/') || inp.name.contains("..") {
            return Err(ToolError::Schema("invalid memory name".into()));
        }
        let p = memory_dir().join(format!("{}.md", inp.name));
        tokio::fs::read_to_string(&p)
            .await
            .map_err(|e| ToolError::Io(format!("{}: {e}", p.display())))
    }
}

/// `MemoryWrite` tool — save or overwrite a named memory file.
pub struct MemoryWriteTool;

#[derive(Debug, Deserialize)]
struct MemoryWriteInput {
    name: String,
    content: String,
}

#[async_trait]
impl Tool for MemoryWriteTool {
    fn name(&self) -> &str {
        "MemoryWrite"
    }
    fn description(&self) -> &str {
        "Save or overwrite a memory file at ~/.aether/memory/<name>.md. Use \
         for facts you want to remember across sessions (project conventions, \
         user preferences, decisions). Content should be self-contained — \
         future sessions read it without context."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "name":    {"type": "string", "description": "Short slug, [a-z0-9-]"},
                "content": {"type": "string", "description": "Markdown body of the memory"}
            },
            "required": ["name", "content"]
        })
    }
    async fn run(&self, input: serde_json::Value) -> Result<String, ToolError> {
        let inp: MemoryWriteInput =
            serde_json::from_value(input).map_err(|e| ToolError::Schema(e.to_string()))?;
        if inp.name.is_empty()
            || inp.name.contains('/')
            || inp.name.contains("..")
            || inp.name.contains(' ')
        {
            return Err(ToolError::Schema(
                "invalid memory name (no /, .., or spaces)".into(),
            ));
        }
        let dir = memory_dir();
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| ToolError::Io(format!("mkdir: {e}")))?;
        let p = dir.join(format!("{}.md", inp.name));
        tokio::fs::write(&p, &inp.content)
            .await
            .map_err(|e| ToolError::Io(format!("{}: {e}", p.display())))?;
        Ok(format!(
            "saved {} bytes to {}",
            inp.content.len(),
            p.display()
        ))
    }
}

// ── Below: the D5 user-editable memory edit log (kept from skeleton) ──

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
