//! Executor (execute + observe phase).
//!
//! Iterates the model's `tool_uses`, applies a permission decision per
//! tool, dispatches to the registered `Tool` impl, and packages each
//! outcome as a `RecordedToolResult` that the observe step appends to
//! history.
//!
//! v1 permission policy is deliberately blunt:
//!   - `BypassPermissions` → allow everything (operator opt-in only).
//!   - `Plan`              → allow read-only tools, refuse mutators.
//!   - `AcceptEdits`       → allow read-only and file mutators
//!                           (Edit/Write/NotebookEdit); deny shell/network.
//!   - `Default`           → allow read-only, deny mutators. No interactive
//!                           prompt is wired yet, so "ask" effectively
//!                           degrades to "deny" for mutating tools.
//!
//! A real `aether-perm` engine with allow/deny/ask rules is a follow-up;
//! this version makes the loop testable end-to-end without an interactive
//! permission UI.

use aether_perm::PermissionMode;
use aether_tools::ToolRegistry;

use crate::context::{RecordedToolResult, RecordedToolUse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionOutcome {
    Allowed,
    Refused(String),
}

pub fn is_mutating(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "Write" | "Edit" | "NotebookEdit" | "Bash" | "WebFetch" | "WebSearch"
    )
}

pub fn is_file_mutator(tool_name: &str) -> bool {
    matches!(tool_name, "Write" | "Edit" | "NotebookEdit")
}

pub fn decide(mode: PermissionMode, tool_name: &str) -> PermissionOutcome {
    use PermissionMode::*;
    use PermissionOutcome::*;
    let mutating = is_mutating(tool_name);
    match mode {
        BypassPermissions => Allowed,
        Plan if mutating => Refused("plan mode forbids mutating tools".into()),
        Plan => Allowed,
        AcceptEdits if !mutating || is_file_mutator(tool_name) => Allowed,
        AcceptEdits => Refused("acceptEdits mode allows file mutators only".into()),
        Default if mutating => Refused("default mode requires an explicit allow rule".into()),
        Default => Allowed,
    }
}

pub struct Executor {
    pub mode: PermissionMode,
}

impl Executor {
    pub fn new(mode: PermissionMode) -> Self {
        Self { mode }
    }

    pub async fn execute(
        &self,
        registry: &ToolRegistry,
        uses: &[RecordedToolUse],
    ) -> Vec<RecordedToolResult> {
        let mut out = Vec::with_capacity(uses.len());
        for tu in uses {
            let (content, is_error) = match decide(self.mode, &tu.name) {
                PermissionOutcome::Allowed => match registry.get(&tu.name) {
                    Some(tool) => match tool.run(tu.input.clone()).await {
                        Ok(s) => (s, false),
                        Err(e) => (format!("tool error: {e}"), true),
                    },
                    None => (format!("unknown tool: {}", tu.name), true),
                },
                PermissionOutcome::Refused(why) => (format!("refused: {why}"), true),
            };
            out.push(RecordedToolResult {
                tool_use_id: tu.id.clone(),
                content,
                is_error,
            });
        }
        out
    }
}
