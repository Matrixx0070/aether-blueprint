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
        "Write" | "Edit" | "NotebookEdit" | "Bash" | "WebFetch" | "WebSearch" | "MemoryWrite"
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
        "Read" | "Glob" | "Grep" | "MemoryRead" | "WebFetch" | "WebSearch"
    )
}

/// Conservative allowlist of Unix binaries whose normal operation is
/// unconditionally read-only (no flag changes that). Excludes `find`,
/// `sed -i`, `awk` (can write via redirection or `-i`), `xargs` (chains
/// to arbitrary commands), and `tee` (writes).
const SAFE_BASH_BINARIES: &[&str] = &[
    "cat", "ls", "head", "tail", "wc", "stat", "file", "echo", "pwd",
    "which", "type", "du", "df", "ps", "env", "printenv", "uname",
    "date", "id", "whoami", "hostname", "uptime", "diff", "sort",
    "uniq", "cut", "tr", "basename", "dirname", "realpath", "readlink",
    "grep", "rg",
];

/// Shell metacharacters that indicate output side-effects or command
/// chaining. We scan the raw command string without parsing quoting —
/// a conservative false-negative (falls back to sequential) is
/// acceptable; a false-positive (parallelises a mutating command) is not.
const SHELL_SIDE_EFFECT_CHARS: &[char] = &['>', '|', ';', '`', '&', '\n'];

/// Return true when a `Bash` tool call looks like a single, read-only
/// invocation with no shell chaining or output redirection.
///
/// Only inspects the `command` field of the tool input JSON. The check
/// is deliberately conservative: any unrecognised binary or any shell
/// metacharacter forces the call back to the sequential slot.
pub fn bash_command_is_readonly(input: &serde_json::Value) -> bool {
    let cmd = match input.get("command").and_then(|v| v.as_str()) {
        Some(s) => s.trim(),
        None => return false,
    };

    // Fast-reject on side-effect characters anywhere in the command.
    if cmd.chars().any(|c| SHELL_SIDE_EFFECT_CHARS.contains(&c)) {
        return false;
    }
    // Command substitution via $()
    if cmd.contains("$(") {
        return false;
    }

    // Extract the binary name. Strip a leading path so `/usr/bin/cat`
    // matches the same as plain `cat`.
    let first_word = cmd.split_ascii_whitespace().next().unwrap_or("");
    let binary = first_word.rsplit('/').next().unwrap_or(first_word);

    SAFE_BASH_BINARIES.contains(&binary)
}

/// True if `tool_name`+`input` can safely run concurrently with other
/// calls in the same batch. Named tools are checked by `is_parallel_safe`;
/// `Bash` calls are additionally inspected to allow read-only invocations.
pub fn can_run_parallel(tool_name: &str, input: &serde_json::Value) -> bool {
    is_parallel_safe(tool_name)
        || (tool_name == "Bash" && bash_command_is_readonly(input))
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

/// Tool-hook callback: receives the phase, tool_use_id (the per-call
/// id Anthropic emits in the ToolUse block; uniquely keys Pre→Post
/// pairs even when the agent invokes the same tool name concurrently),
/// tool name, input JSON value, and (post-phase only) the captured
/// tool output + is_error flag. Returns a list of strings to be
/// injected as kernel reminders before the next LLM call.
/// Synchronous so the callback can use blocking `std::process` to
/// invoke shell hooks.
pub type ToolHookCallback = Box<
    dyn Fn(ToolHookPhase, &str, &str, &serde_json::Value, Option<&str>, bool) -> Vec<String>
        + Send
        + Sync,
>;

/// Callback for streaming tool output lines (BashTool). Receives the
/// tool_use_id and the text line. Called from inside `run_one` as each
/// line arrives. Must be `Send + Sync` because the Executor is used
/// inside a Tokio task.
pub type ToolStreamCallback = std::sync::Arc<dyn Fn(String, String) + Send + Sync>;

/// W4 + X2: per-tool argument-filter row. Matches a regex against
/// either a specific input JSON field (dotted path) OR the whole
/// serialised input JSON. Loaded from policy.json via
/// apply_policy_to_session.
pub struct ToolArgFilter {
    pub tool: String,
    pub regex: regex::Regex,
    pub action: ArgFilterAction,
    /// X2: dotted JSON path. None ⇒ match against whole serialised
    /// input JSON (W4 v0.27 semantics).
    pub field: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum ArgFilterAction {
    Refuse,
    Warn,
}

pub struct Executor {
    pub mode: PermissionMode,
    prompter: Option<PermissionPrompter>,
    tool_hook: Option<ToolHookCallback>,
    /// Optional sink for streaming Bash output lines to the UI.
    /// Receives (tool_use_id, line) for each line emitted by a streaming tool.
    stream_callback: Option<ToolStreamCallback>,
    /// Collected hook outputs to be drained by `agent_turn` and pushed as
    /// reminders for the next turn.
    pending_reminders: std::sync::Mutex<Vec<String>>,
    always_allowed: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Per-org policy: tool names in this list are refused at dispatch
    /// time with `PermissionOutcome::Refused`, independent of the
    /// permission mode. Empty list = no policy enforcement.
    /// Populated at session bootstrap from `~/.aether/policy.json`.
    policy_blocklist: Vec<String>,
    /// W4: per-tool argument-filter rules. Evaluated AFTER the
    /// tool_blocklist check; matches against the serialised input JSON.
    arg_filters: Vec<ToolArgFilter>,
}

impl Executor {
    pub fn new(mode: PermissionMode) -> Self {
        Self {
            mode,
            prompter: None,
            tool_hook: None,
            stream_callback: None,
            pending_reminders: std::sync::Mutex::new(Vec::new()),
            always_allowed: std::sync::Mutex::new(std::collections::HashSet::new()),
            policy_blocklist: Vec::new(),
            arg_filters: Vec::new(),
        }
    }

    /// Install a streaming-output callback. Each line emitted by a streaming
    /// tool (currently only BashTool) is forwarded to this callback as
    /// (tool_use_id, line). Used by the TUI driver to show live Bash output.
    pub fn set_stream_callback(&mut self, cb: ToolStreamCallback) {
        self.stream_callback = Some(cb);
    }

    /// Replace the policy tool-blocklist. Tool names matching any entry
    /// are refused at dispatch (before permission decide).
    pub fn set_policy_blocklist(&mut self, names: Vec<String>) {
        self.policy_blocklist = names;
    }

    /// W4: replace the per-tool argument-filter rules.
    pub fn set_arg_filters(&mut self, filters: Vec<ToolArgFilter>) {
        self.arg_filters = filters;
    }

    fn is_policy_blocked(&self, name: &str) -> bool {
        self.policy_blocklist.iter().any(|n| n == name)
    }

    /// W4 + X2: return Some(arg_filter) if any rule matches.
    /// Matching target:
    ///   - filter.field == None        → whole serialised input JSON
    ///   - filter.field == Some(path)  → value at dotted JSON path,
    ///                                    string-converted (skipped
    ///                                    when path resolves to null
    ///                                    or missing)
    fn match_arg_filter(&self, name: &str, input: &serde_json::Value) -> Option<&ToolArgFilter> {
        if self.arg_filters.is_empty() {
            return None;
        }
        let whole = serde_json::to_string(input).unwrap_or_default();
        for f in &self.arg_filters {
            if f.tool != name {
                continue;
            }
            let target: std::borrow::Cow<str> = match &f.field {
                None => std::borrow::Cow::Borrowed(whole.as_str()),
                Some(path) => match resolve_dotted_path(input, path) {
                    Some(v) => std::borrow::Cow::Owned(json_to_match_string(&v)),
                    None => continue, // field absent → no match
                },
            };
            if f.regex.is_match(&target) {
                return Some(f);
            }
        }
        None
    }
}

/// X2: walk a dotted JSON path. `command` → object key, `args.0` →
/// object key then array index. Returns None when any segment is
/// missing or a type mismatch occurs.
fn resolve_dotted_path<'a>(v: &'a serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let mut cur: &serde_json::Value = v;
    for seg in path.split('.') {
        if seg.is_empty() {
            return None;
        }
        if let Ok(idx) = seg.parse::<usize>() {
            cur = cur.as_array()?.get(idx)?;
        } else {
            cur = cur.as_object()?.get(seg)?;
        }
    }
    Some(cur.clone())
}

/// X2: convert a JSON value to the string the regex matches against.
/// Strings are unwrapped (no JSON quotes); everything else uses the
/// canonical JSON encoding so e.g. integers, arrays, nested objects
/// can still be pattern-matched.
fn json_to_match_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Prepend a structured recovery header to failed tool output so the agent
/// sees an actionable hint exactly at the point of failure — not buried in
/// the system prompt. Keeps the hint terse (2 lines) to avoid burning tokens.
fn enrich_error_content(tool_name: &str, raw: String) -> String {
    format!(
        "[TOOL ERROR: {tool_name}]\n\
         [Recovery hint: read the FULL message below; look for file:line patterns; \
         try a more targeted call or smaller input rather than repeating verbatim]\n\
         {raw}"
    )
}

impl Executor {

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
        // Per-org policy blocklist runs BEFORE the static permission
        // check. A blocked tool cannot be upgraded by a prompter — the
        // policy is an organisational decision, not a per-call one.
        if self.is_policy_blocked(&tu.name) {
            return RecordedToolResult {
                tool_use_id: tu.id.clone(),
                content: format!(
                    "refused: policy: tool `{}` is in tool_blocklist (see ~/.aether/policy.json)",
                    tu.name
                ),
                is_error: true,
            };
        }
        // W4: per-tool argument-filter policy. Refuse-action filters
        // block dispatch outright; warn-action filters log to stderr
        // and pass through.
        if let Some(filter) = self.match_arg_filter(&tu.name, &tu.input) {
            match filter.action {
                ArgFilterAction::Refuse => {
                    return RecordedToolResult {
                        tool_use_id: tu.id.clone(),
                        content: format!(
                            "refused: policy: tool `{}` input matched arg-filter pattern `{}` \
                             (see tool_arg_filters in ~/.aether/policy.json)",
                            tu.name,
                            filter.regex.as_str()
                        ),
                        is_error: true,
                    };
                }
                ArgFilterAction::Warn => {
                    eprintln!(
                        "[policy] WARN tool `{}` input matched arg-filter `{}` (action=warn; not blocked)",
                        tu.name,
                        filter.regex.as_str()
                    );
                }
            }
        }
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
                let outs = h(ToolHookPhase::Pre, &tu.id, &tu.name, &tu.input, None, false);
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
                Some(tool) => {
                    if tool.supports_streaming() {
                        if let Some(cb) = &self.stream_callback {
                            let cb = cb.clone();
                            let id = tu.id.clone();
                            let (tx, mut rx) =
                                tokio::sync::mpsc::channel::<String>(256);
                            let forward = tokio::spawn(async move {
                                while let Some(line) = rx.recv().await {
                                    cb(id.clone(), line);
                                }
                            });
                            let result = tool.run_streamed(tu.input.clone(), &tx).await;
                            drop(tx);
                            let _ = forward.await;
                            match result {
                                Ok(s) => (s, false),
                                Err(e) => (format!("tool error: {e}"), true),
                            }
                        } else {
                            match tool.run(tu.input.clone()).await {
                                Ok(s) => (s, false),
                                Err(e) => (format!("tool error: {e}"), true),
                            }
                        }
                    } else {
                        match tool.run(tu.input.clone()).await {
                            Ok(s) => (s, false),
                            Err(e) => (format!("tool error: {e}"), true),
                        }
                    }
                }
                None => (format!("unknown tool: {}", tu.name), true),
            },
            PermissionOutcome::Refused(why) => (format!("refused: {why}"), true),
        };

        // Enrich failed results with a structured recovery header so the
        // agent sees actionable guidance inline with the error content.
        let (content, is_error) = if is_error {
            (enrich_error_content(&tu.name, content), true)
        } else {
            (content, false)
        };

        // PostToolUse hook: always fires after a call attempt (even
        // refused ones) so operators can audit failed permission decisions.
        if let Some(h) = &self.tool_hook {
            let outs = h(
                ToolHookPhase::Post,
                &tu.id,
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
            if !parallel_disabled && can_run_parallel(&uses[i].name, &uses[i].input) {
                // Find the end of the safe run.
                let mut j = i + 1;
                while j < uses.len() && can_run_parallel(&uses[j].name, &uses[j].input) {
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

    #[test]
    fn enrich_error_content_includes_tool_name_and_hint() {
        let enriched = super::enrich_error_content("Bash", "exit status 1: make: *** [all] Error 1".into());
        assert!(enriched.contains("[TOOL ERROR: Bash]"), "missing header: {enriched}");
        assert!(enriched.contains("Recovery hint:"), "missing hint: {enriched}");
        assert!(enriched.contains("exit status 1"), "missing original error: {enriched}");
    }

    fn use_call(id: &str, name: &str) -> RecordedToolUse {
        RecordedToolUse {
            id: id.into(),
            name: name.into(),
            input: serde_json::json!({}),
        }
    }

    #[tokio::test]
    async fn policy_blocklist_refuses_blocked_tool() {
        let counter = Arc::new(AtomicU64::new(0));
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(CountTool {
            name: "Bash",
            calls: counter.clone(),
        }));
        let mut exec = Executor::new(PermissionMode::BypassPermissions);
        exec.set_policy_blocklist(vec!["Bash".into()]);
        let uses = vec![use_call("t1", "Bash")];
        let out = exec.execute(&reg, &uses).await;
        assert_eq!(out.len(), 1);
        assert!(out[0].is_error);
        assert!(
            out[0].content.contains("policy: tool `Bash` is in tool_blocklist"),
            "expected policy refusal, got: {}",
            out[0].content
        );
        // The actual tool MUST NOT have run.
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "blocked tool was dispatched anyway"
        );
    }

    #[tokio::test]
    async fn policy_blocklist_allows_unlisted_tool() {
        let counter = Arc::new(AtomicU64::new(0));
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(CountTool {
            name: "Read",
            calls: counter.clone(),
        }));
        let mut exec = Executor::new(PermissionMode::BypassPermissions);
        exec.set_policy_blocklist(vec!["Bash".into(), "Write".into()]);
        let uses = vec![use_call("t1", "Read")];
        let out = exec.execute(&reg, &uses).await;
        assert!(!out[0].is_error);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn policy_blocklist_overrides_bypass_permissions() {
        // Even with BypassPermissions (which would normally allow anything),
        // the policy blocklist still refuses. Policy is org-level, mode is
        // session-level — policy wins.
        let counter = Arc::new(AtomicU64::new(0));
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(CountTool {
            name: "WebFetch",
            calls: counter.clone(),
        }));
        let mut exec = Executor::new(PermissionMode::BypassPermissions);
        exec.set_policy_blocklist(vec!["WebFetch".into()]);
        let out = exec.execute(&reg, &[use_call("t1", "WebFetch")]).await;
        assert!(out[0].is_error);
        assert!(out[0].content.contains("policy"));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_blocklist_empty_is_no_op() {
        let counter = Arc::new(AtomicU64::new(0));
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(CountTool {
            name: "Bash",
            calls: counter.clone(),
        }));
        // Note: no set_policy_blocklist call → empty blocklist → no-op
        let exec = Executor::new(PermissionMode::BypassPermissions);
        let out = exec.execute(&reg, &[use_call("t1", "Bash")]).await;
        assert!(!out[0].is_error);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // ── bash_command_is_readonly / can_run_parallel ───────────────────────

    fn bash_input(cmd: &str) -> serde_json::Value {
        serde_json::json!({ "command": cmd })
    }

    #[test]
    fn bash_readonly_allows_safe_binaries() {
        for cmd in &[
            "cat file.txt",
            "ls -la /tmp",
            "head -n 20 src/main.rs",
            "tail -f /var/log/syslog",
            "wc -l *.rs",
            "stat /etc/hostname",
            "echo hello",
            "pwd",
            "which cargo",
            "du -sh .",
            "df -h",
            "ps aux",
            "uname -a",
            "date +%Y-%m-%d",
            "id",
            "whoami",
            "hostname",
            "diff a.txt b.txt",
            "sort -u list.txt",
            "uniq -c words.txt",
            "cut -d, -f1 data.csv",
            "grep -r TODO src/",
            "rg 'fn main' --type rust",
            "/usr/bin/cat /etc/os-release",
        ] {
            assert!(
                bash_command_is_readonly(&bash_input(cmd)),
                "expected readonly for: {cmd}"
            );
        }
    }

    #[test]
    fn bash_readonly_rejects_mutating_binaries() {
        for cmd in &[
            "rm -rf /tmp/test",
            "mv src dst",
            "cp a b",
            "mkdir newdir",
            "touch file.txt",
            "chmod 755 script.sh",
            "chown root file",
            "dd if=/dev/zero of=disk",
            "tee output.txt",
            "find . -exec rm {} \\;",
            "sed -i 's/a/b/' file",
            "awk '{print > \"out\"}' file",
            "xargs rm",
            "curl https://example.com",
            "wget https://example.com",
        ] {
            assert!(
                !bash_command_is_readonly(&bash_input(cmd)),
                "expected NOT readonly for: {cmd}"
            );
        }
    }

    #[test]
    fn bash_readonly_rejects_shell_operators() {
        // Output redirect
        assert!(!bash_command_is_readonly(&bash_input("ls > out.txt")));
        assert!(!bash_command_is_readonly(&bash_input("echo hi >> file")));
        // Pipe (could chain to a mutating command)
        assert!(!bash_command_is_readonly(&bash_input("cat file | rm -f")));
        assert!(!bash_command_is_readonly(&bash_input("ls | grep foo")));
        // Semicolon chaining
        assert!(!bash_command_is_readonly(&bash_input("ls; rm -rf /")));
        // Background
        assert!(!bash_command_is_readonly(&bash_input("ls &")));
        // Command substitution via $()
        assert!(!bash_command_is_readonly(&bash_input("echo $(rm -rf /)")));
        // Backtick substitution
        assert!(!bash_command_is_readonly(&bash_input("echo `id`")));
        // Newline command separator
        assert!(!bash_command_is_readonly(&bash_input("ls\nrm -rf /")));
        // Logical AND/OR chaining
        assert!(!bash_command_is_readonly(&bash_input("ls && rm file")));
        assert!(!bash_command_is_readonly(&bash_input("ls || rm file")));
    }

    #[test]
    fn bash_readonly_rejects_missing_or_empty_command() {
        assert!(!bash_command_is_readonly(&serde_json::json!({})));
        assert!(!bash_command_is_readonly(&serde_json::json!({"command": ""})));
        assert!(!bash_command_is_readonly(&serde_json::json!({"command": "   "})));
    }

    #[test]
    fn can_run_parallel_combines_named_tools_and_bash() {
        // Named parallel-safe tools still work
        assert!(can_run_parallel("Read", &serde_json::json!({})));
        assert!(can_run_parallel("Glob", &serde_json::json!({})));
        assert!(can_run_parallel("WebFetch", &serde_json::json!({})));
        // Bash with read-only command
        assert!(can_run_parallel("Bash", &bash_input("cat README.md")));
        assert!(can_run_parallel("Bash", &bash_input("ls -la")));
        // Bash with mutating command
        assert!(!can_run_parallel("Bash", &bash_input("rm -rf /")));
        assert!(!can_run_parallel("Bash", &bash_input("cat a | tee b")));
        // Non-Bash mutating tools never parallel
        assert!(!can_run_parallel("Write", &serde_json::json!({})));
        assert!(!can_run_parallel("Edit", &serde_json::json!({})));
    }

    #[tokio::test]
    async fn readonly_bash_calls_run_in_parallel() {
        let _guard = crate::mock::ENV_TEST_LOCK.lock().expect("env lock");
        let log = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let mut reg = ToolRegistry::new();
        // Register a "Bash" mock that records start/finish with yields.
        reg.register(Box::new(InterleaveTool {
            name: "Bash",
            log: log.clone(),
        }));

        let exec = Executor::new(PermissionMode::BypassPermissions);
        let uses = vec![
            RecordedToolUse {
                id: "b1".into(),
                name: "Bash".into(),
                input: bash_input("cat a.txt"),
            },
            RecordedToolUse {
                id: "b2".into(),
                name: "Bash".into(),
                input: bash_input("ls -la"),
            },
            RecordedToolUse {
                id: "b3".into(),
                name: "Bash".into(),
                input: bash_input("head -5 README.md"),
            },
        ];
        let out = exec.execute(&reg, &uses).await;

        // Results back in input order
        assert_eq!(out[0].tool_use_id, "b1");
        assert_eq!(out[1].tool_use_id, "b2");
        assert_eq!(out[2].tool_use_id, "b3");

        // First three log entries should all be starts — parallel dispatch
        let g = log.lock().await;
        let first_three: Vec<&str> = g.iter().take(3).map(|s| s.as_str()).collect();
        assert!(
            first_three.iter().all(|s| s.ends_with(":start")),
            "expected 3 parallel starts, got {first_three:?} (full: {g:?})"
        );
    }

    #[tokio::test]
    async fn mutating_bash_breaks_parallel_batch() {
        let _guard = crate::mock::ENV_TEST_LOCK.lock().expect("env lock");
        // [cat, rm, cat] → cat runs alone, rm runs alone, cat runs alone.
        // If rm were batched with either cat, the log would show 2+ starts
        // before any finish on the first batch (or 3 starts total).
        // Sequential dispatch gives start,finish,start,finish,start,finish.
        let counter = Arc::new(AtomicU64::new(0));
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(CountTool {
            name: "Bash",
            calls: counter.clone(),
        }));

        let exec = Executor::new(PermissionMode::BypassPermissions);
        let uses = vec![
            RecordedToolUse {
                id: "b1".into(),
                name: "Bash".into(),
                input: bash_input("cat a.txt"),
            },
            RecordedToolUse {
                id: "b2".into(),
                name: "Bash".into(),
                input: bash_input("rm -rf /tmp/test"),
            },
            RecordedToolUse {
                id: "b3".into(),
                name: "Bash".into(),
                input: bash_input("ls -la"),
            },
        ];
        let out = exec.execute(&reg, &uses).await;
        assert_eq!(out.len(), 3);
        // All three must have run exactly once
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn is_parallel_safe_covers_read_only_only() {
        assert!(is_parallel_safe("Read"));
        assert!(is_parallel_safe("Glob"));
        assert!(is_parallel_safe("Grep"));
        assert!(is_parallel_safe("MemoryRead"));
        assert!(is_parallel_safe("WebFetch"));
        assert!(is_parallel_safe("WebSearch"));
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
        // Hold ENV_TEST_LOCK so the kill-switch test cannot race
        // AETHER_NO_PARALLEL_TOOLS=1 into our environment.
        let _guard = crate::mock::ENV_TEST_LOCK.lock().expect("env lock");
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
        // Hold the lock so AETHER_NO_PARALLEL_TOOLS cannot flip mid-test.
        let _guard = crate::mock::ENV_TEST_LOCK.lock().expect("env lock");
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
        // Hold the lock so AETHER_NO_PARALLEL_TOOLS cannot flip mid-test.
        let _guard = crate::mock::ENV_TEST_LOCK.lock().expect("env lock");
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
