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

/// Answer to an interactive permission prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionAnswer {
    Allow,
    Deny,
    AllowAlwaysForTool,
}

/// Prompter signature: given the tool name + a short summary of the call,
/// return an answer. Called inside `Executor::execute` only when the
/// permission mode is `Default` and the tool is mutating. Synchronous so
/// callers can read from stdin without spawning a task.
pub type PermissionPrompter = Box<dyn Fn(&str, &str) -> PermissionAnswer + Send + Sync>;

/// Phase of a tool-hook call.
#[derive(Debug, Clone, Copy)]
pub enum ToolHookPhase {
    Pre,
    Post,
}

/// Tool-hook callback: receives the phase, tool name, input JSON value, and
/// (post-phase only) the captured tool output + is_error flag. Returns a
/// list of strings to be injected as kernel reminders before the next LLM
/// call. Synchronous so the callback can use blocking `std::process` to
/// invoke shell hooks.
pub type ToolHookCallback = Box<
    dyn Fn(ToolHookPhase, &str, &serde_json::Value, Option<&str>, bool) -> Vec<String>
        + Send
        + Sync,
>;

pub struct Executor {
    pub mode: PermissionMode,
    prompter: Option<PermissionPrompter>,
    tool_hook: Option<ToolHookCallback>,
    /// Collected hook outputs to be drained by `agent_turn` and pushed as
    /// reminders for the next turn.
    pending_reminders: std::sync::Mutex<Vec<String>>,
    always_allowed: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl Executor {
    pub fn new(mode: PermissionMode) -> Self {
        Self {
            mode,
            prompter: None,
            tool_hook: None,
            pending_reminders: std::sync::Mutex::new(Vec::new()),
            always_allowed: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Install a prompter that's consulted when running in `Default` mode
    /// before invoking a mutating tool. Without a prompter, mutating tools
    /// are refused in `Default` mode (current behavior).
    pub fn set_prompter(&mut self, p: PermissionPrompter) {
        self.prompter = Some(p);
    }

    /// Install a tool-hook callback that's invoked Pre and Post each tool
    /// call. Stdout from each hook is collected via `pending_reminders` and
    /// drained by the next `agent_turn`.
    pub fn set_tool_hook(&mut self, h: ToolHookCallback) {
        self.tool_hook = Some(h);
    }

    /// Drain any reminders the tool hooks emitted during the most recent
    /// `execute()` call. Cleared on each `agent_turn`.
    pub fn drain_pending_reminders(&self) -> Vec<String> {
        let mut g = self.pending_reminders.lock().expect("hook reminders mutex");
        std::mem::take(&mut *g)
    }

    /// Pre-populate the in-session "always allow" set (e.g. from settings.json).
    pub fn allow_tools(&mut self, names: impl IntoIterator<Item = String>) {
        let mut g = self.always_allowed.lock().expect("always-allow mutex");
        for n in names {
            g.insert(n);
        }
    }

    fn is_always_allowed(&self, name: &str) -> bool {
        self.always_allowed
            .lock()
            .expect("always-allow mutex")
            .contains(name)
    }

    fn mark_always_allowed(&self, name: &str) {
        self.always_allowed
            .lock()
            .expect("always-allow mutex")
            .insert(name.to_string());
    }

    fn summarize(input: &serde_json::Value) -> String {
        if let Some(s) = input.get("command").and_then(|v| v.as_str()) {
            return s.lines().next().unwrap_or("").chars().take(120).collect();
        }
        if let Some(s) = input.get("file_path").and_then(|v| v.as_str()) {
            return s.to_string();
        }
        if let Some(s) = input.get("url").and_then(|v| v.as_str()) {
            return s.to_string();
        }
        String::new()
    }

    pub async fn execute(
        &self,
        registry: &ToolRegistry,
        uses: &[RecordedToolUse],
    ) -> Vec<RecordedToolResult> {
        let mut out = Vec::with_capacity(uses.len());
        for tu in uses {
            // Static policy
            let mut decision = decide(self.mode, &tu.name);
            // Interactive escalation: in Default mode, a refusal can be
            // upgraded to Allowed if the user explicitly says yes.
            if matches!(decision, PermissionOutcome::Refused(_))
                && matches!(self.mode, PermissionMode::Default)
                && is_mutating(&tu.name)
            {
                if self.is_always_allowed(&tu.name) {
                    decision = PermissionOutcome::Allowed;
                } else if let Some(p) = &self.prompter {
                    let summary = Self::summarize(&tu.input);
                    match p(&tu.name, &summary) {
                        PermissionAnswer::Allow => decision = PermissionOutcome::Allowed,
                        PermissionAnswer::AllowAlwaysForTool => {
                            self.mark_always_allowed(&tu.name);
                            decision = PermissionOutcome::Allowed;
                        }
                        PermissionAnswer::Deny => {
                            decision =
                                PermissionOutcome::Refused("user denied at prompt".into());
                        }
                    }
                }
            }

            // PreToolUse hook: only fires if the call is going to actually run
            // (Allowed). Hook outputs accumulate as reminders for the next turn.
            if matches!(decision, PermissionOutcome::Allowed) {
                if let Some(h) = &self.tool_hook {
                    let outs = h(ToolHookPhase::Pre, &tu.name, &tu.input, None, false);
                    if !outs.is_empty() {
                        let mut g = self
                            .pending_reminders
                            .lock()
                            .expect("hook reminders mutex");
                        for s in outs {
                            g.push(s);
                        }
                    }
                }
            }

            let (content, is_error) = match decision {
                PermissionOutcome::Allowed => match registry.get(&tu.name) {
                    Some(tool) => match tool.run(tu.input.clone()).await {
                        Ok(s) => (s, false),
                        Err(e) => (format!("tool error: {e}"), true),
                    },
                    None => (format!("unknown tool: {}", tu.name), true),
                },
                PermissionOutcome::Refused(why) => (format!("refused: {why}"), true),
            };

            // PostToolUse hook: always fires after a call attempt (even
            // refused ones) so operators can audit failed permission decisions.
            if let Some(h) = &self.tool_hook {
                let outs = h(
                    ToolHookPhase::Post,
                    &tu.name,
                    &tu.input,
                    Some(&content),
                    is_error,
                );
                if !outs.is_empty() {
                    let mut g = self
                        .pending_reminders
                        .lock()
                        .expect("hook reminders mutex");
                    for s in outs {
                        g.push(s);
                    }
                }
            }

            out.push(RecordedToolResult {
                tool_use_id: tu.id.clone(),
                content,
                is_error,
            });
        }
        out
    }
}
