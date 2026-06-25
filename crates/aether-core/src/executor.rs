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

/// Tools that are safe to run concurrently within a single turn. Strictly
/// read-only and side-effect-free at the local-filesystem boundary. Any
/// tool not on this list runs in its original sequential slot — preserves
/// ordering for mutating tools, prompt-driven approval (Default mode),
/// and any external system that expects serial calls.
pub fn is_parallel_safe(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "Read" | "Glob" | "Grep" | "MemoryRead"
    )
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

    /// Run one tool use end-to-end: permission decide, optional prompt,
    /// Pre hook, dispatch, Post hook. Same body as the v0.8 sequential
    /// loop — extracted so both the sequential and parallel paths share it.
    async fn run_one(
        &self,
        registry: &ToolRegistry,
        tu: &RecordedToolUse,
    ) -> RecordedToolResult {
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

        RecordedToolResult {
            tool_use_id: tu.id.clone(),
            content,
            is_error,
        }
    }

    pub async fn execute(
        &self,
        registry: &ToolRegistry,
        uses: &[RecordedToolUse],
    ) -> Vec<RecordedToolResult> {
        let parallel_disabled =
            std::env::var("AETHER_NO_PARALLEL_TOOLS").ok().as_deref() == Some("1");

        // Output is allocated in advance so we can place each result at its
        // original index — preserves the model-emitted tool_use ordering
        // that downstream code expects when matching tool_use_id pairs.
        let mut results: Vec<Option<RecordedToolResult>> = (0..uses.len()).map(|_| None).collect();

        // Walk uses left-to-right. Coalesce contiguous runs of parallel-safe
        // tool_uses into a single join_all batch; mutating / interactive /
        // unknown tools run in their original sequential slot.
        let mut i = 0;
        while i < uses.len() {
            if !parallel_disabled && is_parallel_safe(&uses[i].name) {
                // Find the end of the safe run.
                let mut j = i + 1;
                while j < uses.len() && is_parallel_safe(&uses[j].name) {
                    j += 1;
                }
                // Single safe call: no point spawning a join_all.
                if j - i == 1 {
                    results[i] = Some(self.run_one(registry, &uses[i]).await);
                } else {
                    // Collect into a Vec FIRST: join_all polls in iteration
                    // order, and a lazy `.iter().map(...)` adapter ends up
                    // constructing futures one-at-a-time as poll progresses,
                    // which can serialize the calls in practice. An eager
                    // Vec materialises all futures so the first poll round
                    // registers all timers in parallel.
                    let futs: Vec<_> =
                        uses[i..j].iter().map(|tu| self.run_one(registry, tu)).collect();
                    let batch = futures_util::future::join_all(futs).await;
                    for (k, r) in batch.into_iter().enumerate() {
                        results[i + k] = Some(r);
                    }
                }
                i = j;
            } else {
                results[i] = Some(self.run_one(registry, &uses[i]).await);
                i += 1;
            }
        }

        results.into_iter().map(|r| r.expect("filled")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_tools::{Tool, ToolError, ToolRegistry};
    use async_trait::async_trait;
    use serde_json::Value;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// Mock that simulates a slow read by sleeping `sleep_ms` before returning.
    struct SleepyTool {
        name: &'static str,
        sleep_ms: u64,
    }

    #[async_trait]
    impl Tool for SleepyTool {
        fn name(&self) -> &str {
            self.name
        }
        fn description(&self) -> &str {
            "sleepy mock"
        }
        fn input_schema(&self) -> Value {
            serde_json::json!({"type": "object"})
        }
        async fn run(&self, _input: Value) -> Result<String, ToolError> {
            tokio::time::sleep(Duration::from_millis(self.sleep_ms)).await;
            Ok(self.name.to_string())
        }
    }

    /// Mock that increments a counter when called — verifies dispatch hit.
    struct CountTool {
        name: &'static str,
        calls: Arc<AtomicU64>,
    }

    #[async_trait]
    impl Tool for CountTool {
        fn name(&self) -> &str {
            self.name
        }
        fn description(&self) -> &str {
            "counter mock"
        }
        fn input_schema(&self) -> Value {
            serde_json::json!({"type": "object"})
        }
        async fn run(&self, _input: Value) -> Result<String, ToolError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.name.to_string())
        }
    }

    fn use_call(id: &str, name: &str) -> RecordedToolUse {
        RecordedToolUse {
            id: id.into(),
            name: name.into(),
            input: serde_json::json!({}),
        }
    }

    #[test]
    fn is_parallel_safe_covers_read_only_only() {
        assert!(is_parallel_safe("Read"));
        assert!(is_parallel_safe("Glob"));
        assert!(is_parallel_safe("Grep"));
        assert!(is_parallel_safe("MemoryRead"));
        // Mutating tools must NEVER be flagged safe — a parallel write
        // would race file state, an interactive prompt can't run twice.
        assert!(!is_parallel_safe("Write"));
        assert!(!is_parallel_safe("Edit"));
        assert!(!is_parallel_safe("Bash"));
        // Unknown tools must default to sequential.
        assert!(!is_parallel_safe("RandomFutureTool"));
    }

    /// Tool that records (start_marker, finish_marker) on a shared event
    /// log. With true concurrency the log should contain interleaved
    /// starts (e.g. "Read:start", "Glob:start", "Grep:start", then the
    /// finishes); strict sequential dispatch would produce
    /// (start, finish, start, finish, start, finish).
    struct InterleaveTool {
        name: &'static str,
        log: Arc<tokio::sync::Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl Tool for InterleaveTool {
        fn name(&self) -> &str {
            self.name
        }
        fn description(&self) -> &str {
            "interleave probe"
        }
        fn input_schema(&self) -> Value {
            serde_json::json!({"type": "object"})
        }
        async fn run(&self, _input: Value) -> Result<String, ToolError> {
            {
                let mut g = self.log.lock().await;
                g.push(format!("{}:start", self.name));
            }
            // Yield to the executor multiple times so other concurrent
            // futures get a chance to enter `run` between our start and
            // finish markers. tokio::task::yield_now is cooperative and
            // works on both current_thread and multi_thread runtimes.
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            {
                let mut g = self.log.lock().await;
                g.push(format!("{}:finish", self.name));
            }
            Ok(self.name.to_string())
        }
    }

    #[tokio::test]
    async fn parallel_safe_tools_interleave_not_serialize() {
        // True parallel dispatch interleaves start markers before any
        // finish marker. Strict sequential would produce
        // "Read:start, Read:finish, Glob:start, Glob:finish, ...".
        let log = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(InterleaveTool {
            name: "Read",
            log: log.clone(),
        }));
        reg.register(Box::new(InterleaveTool {
            name: "Glob",
            log: log.clone(),
        }));
        reg.register(Box::new(InterleaveTool {
            name: "Grep",
            log: log.clone(),
        }));

        let exec = Executor::new(PermissionMode::BypassPermissions);
        let uses = vec![
            use_call("t1", "Read"),
            use_call("t2", "Glob"),
            use_call("t3", "Grep"),
        ];
        let out = exec.execute(&reg, &uses).await;

        assert_eq!(out.len(), 3);
        assert_eq!(out[0].tool_use_id, "t1");
        assert_eq!(out[1].tool_use_id, "t2");
        assert_eq!(out[2].tool_use_id, "t3");

        let g = log.lock().await;
        // First three entries should all be starts — proves the executor
        // dispatched all three before any of them completed. Sequential
        // execution would produce start,finish,start,finish,start,finish.
        let first_three: Vec<&str> = g.iter().take(3).map(|s| s.as_str()).collect();
        let all_starts = first_three.iter().all(|s| s.ends_with(":start"));
        assert!(
            all_starts,
            "expected first 3 log entries to all be starts (parallel dispatch); \
             got {first_three:?} (full log: {:?})",
            *g
        );
    }

    #[tokio::test]
    async fn mutating_tools_break_parallel_batch_and_preserve_order() {
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(SleepyTool {
            name: "Read",
            sleep_ms: 50,
        }));
        reg.register(Box::new(SleepyTool {
            name: "Write",
            sleep_ms: 50,
        }));
        reg.register(Box::new(SleepyTool {
            name: "Grep",
            sleep_ms: 50,
        }));

        let exec = Executor::new(PermissionMode::BypassPermissions);
        let uses = vec![
            use_call("a", "Read"),
            use_call("b", "Write"),
            use_call("c", "Grep"),
        ];
        let out = exec.execute(&reg, &uses).await;
        // Order preserved across mixed safe/mutating batches.
        assert_eq!(out[0].tool_use_id, "a");
        assert_eq!(out[1].tool_use_id, "b");
        assert_eq!(out[2].tool_use_id, "c");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallel_kill_switch_falls_back_to_sequential() {
        use crate::mock::ENV_TEST_LOCK;
        let _guard = ENV_TEST_LOCK.lock().expect("env lock");
        std::env::set_var("AETHER_NO_PARALLEL_TOOLS", "1");
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(SleepyTool {
            name: "Read",
            sleep_ms: 200,
        }));
        reg.register(Box::new(SleepyTool {
            name: "Glob",
            sleep_ms: 200,
        }));

        let exec = Executor::new(PermissionMode::BypassPermissions);
        let uses = vec![use_call("t1", "Read"), use_call("t2", "Glob")];
        let started = std::time::Instant::now();
        let _ = exec.execute(&reg, &uses).await;
        let elapsed_ms = started.elapsed().as_millis();
        std::env::remove_var("AETHER_NO_PARALLEL_TOOLS");

        // With kill-switch active, two 200ms sleeps serialize ≥ 400ms.
        assert!(
            elapsed_ms >= 380,
            "kill-switch should force sequential (≥380ms), got {elapsed_ms}ms"
        );
    }

    #[tokio::test]
    async fn all_tools_actually_dispatch_in_parallel_batch() {
        // Counts must hit each tool exactly once even when batched.
        let counter = Arc::new(AtomicU64::new(0));
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(CountTool {
            name: "Read",
            calls: counter.clone(),
        }));
        reg.register(Box::new(CountTool {
            name: "Glob",
            calls: counter.clone(),
        }));
        reg.register(Box::new(CountTool {
            name: "Grep",
            calls: counter.clone(),
        }));

        let exec = Executor::new(PermissionMode::BypassPermissions);
        let uses = vec![
            use_call("a", "Read"),
            use_call("b", "Glob"),
            use_call("c", "Grep"),
        ];
        let out = exec.execute(&reg, &uses).await;
        assert_eq!(out.len(), 3);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }
}
