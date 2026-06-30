//! Agent loop + `Session` orchestrator.
//!
//! Six phases per turn:
//!   1. perceive — assemble system prompt + messages via `ContextAssembler`.
//!                 D1 (reminder tamper-test) and D6 (long-conversation
//!                 reminder) fire here.
//!   2. plan     — refresh the active plan if it's dirty (L1 plan-critic).
//!   3. tool-sel — single LLM call. Returned `tool_uses` drive execute.
//!   4. execute  — for each tool_use: permission decide → run → capture.
//!   5. observe  — append the assistant turn + any tool results to history.
//!   6. verify   — D7 self-check gate on the assistant text. On Pass, the
//!                 (possibly rewritten) text is emitted. On Blocked, the
//!                 turn returns ContinueImmediately with `plan.dirty = true`.

pub mod compaction;
pub mod context;
pub mod executor;
pub mod mock;
pub mod planner;
pub mod verifier;

use aether_hook::{KernelRules, Reminder, ReminderKind, Source};
use aether_llm::{ContentBlock, LlmError, LlmProvider, StopReason, ToolDef};
use aether_overlay::{ActivationContext, Fable5Overlay};
use aether_perm::PermissionMode;
use aether_selfcheck::{Gate, SessionContext as SelfCheckCtx};
use aether_tools::ToolRegistry;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use context::{
    AssemblyTelemetry, ContextAssembler, ConversationItem, RecordedToolResult, RecordedToolUse,
};
use executor::Executor;
use planner::{Plan, Planner};
use verifier::{VerificationResult, Verifier};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub model: String,
    pub permission_mode: PermissionMode,
    pub max_tokens_per_turn: u32,
    /// When Some, enables extended thinking with this token budget (Opus 4+ only).
    /// Tools are auto-disabled when thinking is active.
    #[serde(default)]
    pub thinking_budget: Option<u32>,
    /// Sampling temperature injected into every request. None → API default (1.0).
    #[serde(default)]
    pub temperature: Option<f32>,
    /// When > 0 the tool registry is cleared for this many upcoming turns,
    /// then the counter resets to 0. Set by `/notool [N]`.
    #[serde(default)]
    pub tools_disabled_turns: usize,
    /// Optional user-defined suffix appended to the kernel system prompt.
    /// Injected after all kernel rules so it can specialize or constrain the AI persona.
    /// Set via `/persona <text>`, cleared with `/persona off`.
    #[serde(default)]
    pub system_suffix: Option<String>,
    /// Maximum tool calls allowed per turn. When the model emits more than
    /// this many tool_use blocks in a single response, the excess are dropped
    /// and a warning reminder is pushed for the next turn. 0 = unlimited.
    /// Default: 20 (same as Claude Code's internal limit).
    #[serde(default = "default_max_tool_calls_per_turn")]
    pub max_tool_calls_per_turn: usize,
}

fn default_max_tool_calls_per_turn() -> usize { 20 }

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            model: "claude-opus-4-7".into(),
            permission_mode: PermissionMode::Default,
            max_tokens_per_turn: 8_192,
            thinking_budget: None,
            temperature: None,
            tools_disabled_turns: 0,
            system_suffix: None,
            max_tool_calls_per_turn: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnOutcome {
    AwaitUser,
    ContinueImmediately,
    Sleep { seconds: u64 },
    Exit,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("llm: {0}")]
    Llm(#[from] LlmError),
}

pub struct Session {
    pub config: SessionConfig,
    pub overlay: Fable5Overlay,
    pub assembler: ContextAssembler,
    pub planner: Planner,
    pub executor: Executor,
    pub verifier: Verifier,
    pub llm: Arc<dyn LlmProvider>,
    pub tools: ToolRegistry,

    pub history: Vec<ConversationItem>,
    pub plan: Plan,
    pub turn_index: usize,

    pub last_verification: Option<VerificationResult>,
    pub last_assembly_telemetry: Option<AssemblyTelemetry>,
    pub pending_reminders: Vec<Reminder>,
    pub selfcheck_ctx: SelfCheckCtx,
    /// Running token totals across the session — accumulated from each
    /// model response's `usage` field. None on responses where the model
    /// didn't return usage.
    pub usage_total: aether_llm::Usage,

    /// Cumulative wall-clock time spent waiting for LLM responses (ms).
    /// Incremented per turn in `agent_turn_inner`. Does not include
    /// time spent executing tools or rendering the TUI.
    pub llm_ms_total: u64,

    /// Wall-clock time of the most recent LLM call (ms).
    pub llm_ms_last: u64,

    /// Session start timestamp (seconds since UNIX epoch).
    pub started_at: u64,

    /// Set to true by `compact_inner` when compaction fires this turn.
    /// The TUI driver reads this after each agent turn and resets it to false,
    /// then shows a SystemNote so the user knows compaction happened.
    pub compaction_happened: bool,

    /// Maximum autonomous turns before the agent pauses and awaits user input.
    /// 0 = unlimited (default). Set via `/max-turns N` at runtime.
    pub max_turns: usize,

    /// Standing instructions that re-inject themselves as reminders at the
    /// start of every turn. Set via `/remind <text>`, cleared via `/remind clear`.
    /// Injected after the stuck-tool check and before assembly so they always
    /// appear in the system prompt alongside other kernel reminders.
    pub persistent_reminders: Vec<String>,

    /// Custom compaction threshold (0.0–1.0). When > 0.0, overrides the
    /// default COMPACTION_THRESHOLD_PCT (0.80). The stuck-tool deduction
    /// (−0.10) still applies on top of this value.
    pub compaction_threshold_pct: f64,

    /// Total session token budget (input + output combined). When > 0 and
    /// cumulative token usage exceeds this value, a SystemNote warning is
    /// pushed so the user knows they're over budget. 0 = unlimited.
    pub token_budget: u64,

    /// Per-turn LLM call timeout in seconds. When > 0, the complete/complete_streamed
    /// call is wrapped in tokio::time::timeout. On expiry, a synthetic error
    /// is injected and the turn returns ContinueImmediately with guidance.
    pub llm_timeout_secs: u64,

    /// Set to true when cumulative context usage first exceeds 60%.
    /// The TUI driver reads this flag, emits a SystemNote, and clears it.
    pub context_warned_60pct: bool,

    /// When false, the D7 self-check verifier is skipped entirely, trading
    /// safety for speed. Default: true. Toggle via `/verify on|off`.
    pub verify_enabled: bool,

    /// When > 0, the session goal is re-injected as a reminder every N turns.
    /// Keeps long autonomous runs from drifting off-target. 0 = off.
    pub turn_reminder_every: usize,

    /// When > 0, the agent pauses for user review after every N total tool calls.
    /// Prevents runaway automation. 0 = off.
    pub checkpoint_every_tools: usize,

    /// File paths that are re-injected as user context after each compaction event.
    /// Keeps key project files visible to the model even after history is summarised.
    pub warmup_files: Vec<String>,

    /// In-session progress tracker: (description, done).
    /// When non-empty, injected as a reminder every turn so the agent sees current status.
    pub progress_items: Vec<(String, bool)>,

    /// Per-tool output character limits. When a tool's output exceeds the
    /// configured cap it is truncated before being stored in history.
    /// Complements the global 50k cap in the executor.
    pub tool_output_limits: std::collections::HashMap<String, usize>,

    /// When true, detect consecutive identical tool calls (same name+args) and
    /// inject a deduplication warning so the agent tries different arguments.
    pub dedup_tool_calls: bool,

    /// Signature (name, args_json) of tool calls from the most recent tool
    /// execution batch. Used by the dedup detector above.
    pub last_tool_signatures: Vec<(String, String)>,

    /// When true, automatically raise thinking budget to 8 192 tokens when
    /// the agent is detected as stuck (consecutive tool errors ≥ threshold).
    pub auto_think_on_stuck: bool,

    /// In-memory named snapshots of (history, plan). Allows branching and
    /// backtracking without writing files or touching git.
    pub saved_snapshots: std::collections::HashMap<String, (Vec<context::ConversationItem>, planner::Plan)>,

    /// When true, automatically trigger context compaction when the agent
    /// is stuck (any tool at TOOL_ERROR_THRESHOLD consecutive errors).
    pub auto_compact_on_stuck: bool,

    /// When > 0, the agent pauses after this many total tool errors accumulate
    /// across the session. Prevents wasting tokens/money on a broken run. 0 = off.
    pub fail_fast_errors: usize,
}

impl Session {
    pub fn new(
        config: SessionConfig,
        overlay: Fable5Overlay,
        llm: Arc<dyn LlmProvider>,
        gate: Gate,
        tools: ToolRegistry,
    ) -> Self {
        let executor = Executor::new(config.permission_mode);
        let started_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            assembler: ContextAssembler::new(KernelRules::default()),
            planner: Planner::new(),
            executor,
            verifier: Verifier::new(gate),
            config,
            overlay,
            llm,
            tools,
            history: Vec::new(),
            plan: Plan::default(),
            turn_index: 0,
            last_verification: None,
            last_assembly_telemetry: None,
            pending_reminders: Vec::new(),
            selfcheck_ctx: SelfCheckCtx::default(),
            usage_total: aether_llm::Usage::default(),
            llm_ms_total: 0,
            llm_ms_last: 0,
            started_at,
            compaction_happened: false,
            max_turns: 0,
            persistent_reminders: Vec::new(),
            compaction_threshold_pct: 0.0,
            token_budget: 0,
            llm_timeout_secs: 0,
            context_warned_60pct: false,
            verify_enabled: true,
            turn_reminder_every: 0,
            checkpoint_every_tools: 0,
            warmup_files: Vec::new(),
            progress_items: Vec::new(),
            tool_output_limits: std::collections::HashMap::new(),
            dedup_tool_calls: false,
            last_tool_signatures: Vec::new(),
            auto_think_on_stuck: false,
            saved_snapshots: std::collections::HashMap::new(),
            auto_compact_on_stuck: false,
            fail_fast_errors: 0,
        }
    }

    pub fn activation_context(&self) -> ActivationContext {
        // Compute the current context fill ratio from cumulative token usage.
        // This was previously hardcoded to 0.0, so overlays with ctx_size_ratio
        // predicates never activated — now they see the real fill level.
        let used = self.usage_total.input_tokens + self.usage_total.output_tokens;
        let window = compaction::context_window_for_model(&self.config.model);
        let ctx_size_ratio = if window > 0 {
            ((used as f64 / window as f64).min(1.0)) as f32
        } else {
            0.0f32
        };
        ActivationContext {
            turn_index: self.turn_index,
            ctx_size_ratio,
            plan_active: self.plan.is_active(),
            task_expected_hours: 0.0,
            verifier_flagged: self
                .last_verification
                .as_ref()
                .map(|v| !v.findings.is_empty() || v.is_blocked())
                .unwrap_or(false),
            tool_metadata_third_party: false,
            memory_write_attempted: false,
            user_requests_memory_change: false,
            output_contains_quoted_text: false,
            output_contains_external_claim: false,
            persona_refusal_active: false,
        }
    }

    pub fn push_reminder(&mut self, r: Reminder) {
        self.pending_reminders.push(r);
    }
}

pub async fn agent_turn(
    session: &mut Session,
    user_input: Option<String>,
) -> Result<TurnOutcome, AgentError> {
    agent_turn_inner(session, user_input, None).await
}

/// Conservative substring detector. Triggers when the user message contains
/// one of a small set of creative-writing terms. False positives are okay
/// here — the worst case is that rule 06 stops gating one turn that didn't
/// actually need gating; that's an acceptable trade.
fn looks_like_creative_writing_request(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    const TRIGGERS: &[&str] = &[
        "poem", "poetry", "haiku", "sonnet", "limerick", "verse", "ballad",
        "song lyric", "lyrics for", "write a song", "write me a song",
        "rap lyrics", "rhyme", "couplet",
    ];
    TRIGGERS.iter().any(|t| lower.contains(t))
}

/// Streaming variant — text deltas are emitted via the callback as the
/// model produces them. The full assistant response is still recorded into
/// session history after the stream completes. Pass the same callback you
/// would for printing tokens to stdout in a REPL.
pub async fn agent_turn_streamed(
    session: &mut Session,
    user_input: Option<String>,
    on_delta: aether_llm::TextDeltaSink,
) -> Result<TurnOutcome, AgentError> {
    agent_turn_inner(session, user_input, Some(on_delta)).await
}

async fn agent_turn_inner(
    session: &mut Session,
    user_input: Option<String>,
    on_delta: Option<aether_llm::TextDeltaSink>,
) -> Result<TurnOutcome, AgentError> {
    // ── perceive (input) ──────────────────────────────────────────────
    if let Some(s) = user_input {
        // Update selfcheck context flags from the latest user turn so
        // rules with applies_when predicates see fresh state.
        session.selfcheck_ctx.user_asked_for_creative_writing =
            looks_like_creative_writing_request(&s);
        session.history.push(ConversationItem::User(s));
    }

    // ── turn budget ──────────────────────────────────────────────────
    // When max_turns > 0, stop the agent loop before calling the LLM so
    // the user can review progress and decide whether to continue.
    if session.max_turns > 0 && session.turn_index >= session.max_turns {
        session.pending_reminders.push(Reminder::new(
            ReminderKind::SystemWarning,
            Source::Kernel,
            format!(
                "Turn budget reached ({}/{} turns). Awaiting user instruction. \
                 Use /max-turns to raise the limit or just send a new message.",
                session.turn_index, session.max_turns
            ),
        ));
        return Ok(TurnOutcome::AwaitUser);
    }

    // ── compact — run BEFORE assembly so the next LLM call sees the
    // shortened history. Fires only when cumulative usage > 80% of the
    // model's context window AND history has at least 4 items.
    //
    // Fail-soft: a transient provider error during the summary call
    // shouldn't kill the user's turn. Skip compaction silently and
    // let the regular call attempt proceed — if context is genuinely
    // full, the model will return its own 400 and the user sees that. ─
    if let Err(e) = compaction::maybe_compact(session).await {
        eprintln!("[compaction] skipped this turn: {e}");
    }

    // ── plan ─────────────────────────────────────────────────────────
    // Always call refresh so the sliding-window prune runs even on clean
    // turns. In monotonic mode (window=None) this is a cheap no-op when
    // the plan is empty and idempotent when it isn't.
    session.planner.refresh(&mut session.plan, session.turn_index);

    // Auto-inject targeted recovery reminder when tools are stuck. This
    // produces a system-prompt-level signal ("you are stuck on tool X")
    // in addition to the plan-text signal — two injection points means
    // the guidance shows up even when the plan text is truncated.
    {
        let mut stuck_names: Vec<String> = session
            .plan
            .tool_error_counts
            .iter()
            .filter(|(_, &n)| n >= planner::TOOL_ERROR_THRESHOLD)
            .map(|(name, _)| name.clone())
            .collect();
        stuck_names.sort();
        if !stuck_names.is_empty() {
            let names = stuck_names.join(", ");
            session.pending_reminders.push(Reminder::new(
                ReminderKind::SystemWarning,
                Source::Kernel,
                format!(
                    "You are currently stuck: tool(s) [{names}] have failed 3+ times consecutively. \
                     Do NOT repeat the same call. Instead: (1) re-read the FULL error output from \
                     the last failure; (2) try a more targeted variant (smaller scope, different \
                     arguments, or a different tool entirely); (3) if blocked by permissions, \
                     report it rather than retrying."
                ),
            ));
        }
    }

    let ctx = session.activation_context();

    // Re-inject persistent (standing) reminders set by the user via
    // `/remind`. These fire every turn and survive compaction — they're
    // an always-on addition to the system prompt outside the context window.
    for body in &session.persistent_reminders {
        session.pending_reminders.push(Reminder::new(
            ReminderKind::SystemWarning,
            Source::Kernel,
            format!("[Standing instruction] {body}"),
        ));
    }

    // Progress tracker: re-inject the current task list every turn when non-empty.
    if !session.progress_items.is_empty() {
        let items: Vec<String> = session.progress_items.iter()
            .enumerate()
            .map(|(i, (text, done))| {
                format!("[{}] {} {}", i, if *done { "DONE" } else { "TODO" }, text)
            })
            .collect();
        session.pending_reminders.push(Reminder::new(
            ReminderKind::SystemWarning,
            Source::Kernel,
            format!("[Progress tracker]\n{}", items.join("\n")),
        ));
    }

    // Periodic goal re-injection: if turn_reminder_every > 0 and the current
    // turn index is a multiple of it, re-surface the session goal so long
    // autonomous runs stay on track.
    if session.turn_reminder_every > 0
        && session.turn_index > 0
        && session.turn_index % session.turn_reminder_every == 0
    {
        if let Some(ref goal) = session.plan.goal {
            session.pending_reminders.push(Reminder::new(
                ReminderKind::SystemWarning,
                Source::Kernel,
                format!(
                    "[Turn-{} goal reminder] {}",
                    session.turn_index, goal
                ),
            ));
        }
    }

    // ── perceive (assemble) — D1 + D6 fire here ──────────────────────
    // Deduplicate pending_reminders by body text before draining so
    // identical warnings (e.g. stuck-tool repeated injection) don't
    // pile up into the system prompt across back-to-back agent turns.
    {
        let mut seen = std::collections::HashSet::new();
        session.pending_reminders.retain(|r| seen.insert(r.body.clone()));
    }
    let candidate_reminders = std::mem::take(&mut session.pending_reminders);
    let tool_defs: Vec<ToolDef> = session
        .tools
        .names()
        .iter()
        .filter_map(|n| {
            session.tools.get(n).map(|t| ToolDef {
                name: t.name().to_string(),
                description: t.description().to_string(),
                input_schema: t.input_schema(),
            })
        })
        .collect();
    let plan_text = if session.plan.is_active() {
        Some(session.plan.text.clone())
    } else {
        None
    };
    let (mut req, telemetry) = session.assembler.build(
        &session.history,
        &session.config,
        &session.overlay,
        &ctx,
        candidate_reminders,
        tool_defs,
        plan_text.as_deref(),
    );
    session.last_assembly_telemetry = Some(telemetry);

    // Inject extended thinking config when enabled. Tools must be empty while
    // thinking is active — the model cannot mix thinking + tool_use.
    if let Some(budget) = session.config.thinking_budget {
        req.thinking = Some(aether_llm::ThinkingConfig::enabled(budget));
        req.tools.clear(); // required by the API
        // max_tokens must exceed budget_tokens.
        if req.max_tokens <= budget {
            req.max_tokens = budget + 16_384;
        }
    }

    // Sampling temperature override (None → let the API use its default of 1.0).
    req.temperature = session.config.temperature;

    // /notool — clear tools for this turn and decrement the counter.
    if session.config.tools_disabled_turns > 0 {
        req.tools.clear();
        session.config.tools_disabled_turns -= 1;
    }

    // ── tool-sel (LLM call) ──────────────────────────────────────────
    let llm_start = std::time::Instant::now();
    let timeout_dur = if session.llm_timeout_secs > 0 {
        Some(std::time::Duration::from_secs(session.llm_timeout_secs))
    } else {
        None
    };
    let llm_result = match (timeout_dur, on_delta) {
        (Some(dur), None) => {
            match tokio::time::timeout(dur, session.llm.complete(req)).await {
                Ok(r) => r,
                Err(_) => Err(aether_llm::LlmError::Transport(
                    format!("LLM call timed out after {}s (set by /timeout)", dur.as_secs())
                )),
            }
        }
        (Some(dur), Some(cb)) => {
            match tokio::time::timeout(dur, session.llm.complete_streamed(req, cb)).await {
                Ok(r) => r,
                Err(_) => Err(aether_llm::LlmError::Transport(
                    format!("LLM call timed out after {}s (set by /timeout)", dur.as_secs())
                )),
            }
        }
        (None, None) => session.llm.complete(req).await,
        (None, Some(cb)) => session.llm.complete_streamed(req, cb).await,
    };
    let resp = llm_result?;
    let llm_elapsed_ms = llm_start.elapsed().as_millis() as u64;
    session.llm_ms_last = llm_elapsed_ms;
    session.llm_ms_total += llm_elapsed_ms;
    if let Some(u) = &resp.usage {
        session.usage_total.add(u);
    }

    // Context 60% early-warning: set a flag the TUI driver will convert to a
    // SystemNote. Fires at most once per session so it doesn't spam the user.
    if !session.context_warned_60pct {
        let used = session.usage_total.input_tokens + session.usage_total.output_tokens;
        let window = compaction::context_window_for_model(&session.config.model);
        if window > 0 && (used as f64 / window as f64) >= 0.60 {
            session.context_warned_60pct = true;
        }
    }

    // Token budget check — warn the user when total usage exceeds the budget.
    if session.token_budget > 0 {
        let used = session.usage_total.input_tokens + session.usage_total.output_tokens;
        if used >= session.token_budget {
            session.pending_reminders.push(Reminder::new(
                ReminderKind::SystemWarning,
                Source::Kernel,
                format!(
                    "Token budget exceeded: {used} / {} tokens used. \
                     Consider running /compact or /trim-history to reduce context, \
                     or raise the budget with /token-budget.",
                    session.token_budget
                ),
            ));
        }
    }

    let mut text_parts: Vec<String> = Vec::new();
    let mut tool_uses: Vec<RecordedToolUse> = Vec::new();
    for block in &resp.content {
        match block {
            ContentBlock::Text { text } => text_parts.push(text.clone()),
            ContentBlock::ToolUse { id, name, input } => tool_uses.push(RecordedToolUse {
                id: id.clone(),
                name: name.clone(),
                input: input.clone(),
            }),
            ContentBlock::ToolResult { .. } => {
                // never emitted by a model in assistant role; drop silently
            }
            ContentBlock::Thinking { .. } => {
                // Already streamed to the user via on_delta; skip from text_parts.
            }
            ContentBlock::Image { .. } => {
                // Models never emit images in their assistant responses; drop silently.
            }
        }
    }
    let raw_assistant_text = if text_parts.is_empty() {
        None
    } else {
        Some(text_parts.join("\n"))
    };

    // Tool-call budget: drop excess tool_uses beyond the per-turn cap.
    // A reminder is queued so the next LLM call sees explicit guidance
    // about why some of its requested tool calls were dropped.
    let cap = session.config.max_tool_calls_per_turn;
    if cap > 0 && tool_uses.len() > cap {
        let dropped = tool_uses.len() - cap;
        tool_uses.truncate(cap);
        session.pending_reminders.push(Reminder::new(
            ReminderKind::SystemWarning,
            Source::Kernel,
            format!(
                "Tool-call budget exceeded: {dropped} tool call(s) were dropped this turn \
                 (limit = {cap} per turn). Request fewer tool calls per response or \
                 increase the limit with /set-max-tools."
            ),
        ));
    }

    // ── verify — D7 runs BEFORE we commit anything to history so a
    // rewrite lands in history correctly and a block can choose not to
    // execute the model's tool_uses. When verify_enabled is false, skip
    // entirely (speed mode). ────────────────────────────────────────────
    let mut final_text = raw_assistant_text.clone();
    let mut blocked = false;
    if session.verify_enabled {
        if let Some(t) = &raw_assistant_text {
            let v = session.verifier.check_before_emit(t, &session.selfcheck_ctx);
            if v.is_blocked() {
                blocked = true;
            } else {
                final_text = Some(v.message.clone());
            }
            session.last_verification = Some(v);
        }
    }

    // ── block handler — keep the original blocked text out of history,
    // record the block in the plan, and queue a kernel reminder so the
    // next LLM call sees concrete routing-around guidance instead of
    // re-emitting the same pattern. ────────────────────────────────────
    if blocked {
        let v = session.last_verification.as_ref().unwrap();
        let ids: Vec<String> = v
            .blocked_reasons
            .iter()
            .map(|f| f.rule_id.clone())
            .collect();
        let mut unique_ids = ids.clone();
        unique_ids.sort();
        unique_ids.dedup();
        let id_list = unique_ids.join(",");

        // Sentinel replaces the original text in history — the raw blocked
        // content never gets stored in-band.
        final_text = Some(format!("[BLOCKED BY VERIFIER: rules={id_list}]"));

        // Drop the model's tool_uses too. Execute was already going to skip,
        // but we don't want them sitting in history pointing at calls that
        // never ran.
        tool_uses.clear();

        session.plan.record_block(session.turn_index, &ids);

        // The reminder lands in `pending_reminders`; it gets drained at the
        // top of the next agent_turn call. Source::Kernel so D1 always
        // admits it even when the overlay is on.
        session.pending_reminders.push(Reminder::new(
            ReminderKind::SystemWarning,
            Source::Kernel,
            format!(
                "Previous emission was blocked by the self-check gate (rules={id_list}). \
                 Do not repeat the blocked content. Refer to the active plan."
            ),
        ));
    }

    // ── dedup detector — warn when agent repeats identical tool+args ────
    // Fires only when dedup_tool_calls is enabled. Injects a reminder so
    // the model tries different arguments on the next turn instead of looping.
    if session.dedup_tool_calls && !tool_uses.is_empty() {
        let current_sigs: Vec<(String, String)> = tool_uses.iter()
            .map(|tu| (tu.name.clone(), tu.input.to_string()))
            .collect();
        let dups: Vec<&str> = current_sigs.iter()
            .filter(|sig| session.last_tool_signatures.contains(sig))
            .map(|(name, _)| name.as_str())
            .collect();
        if !dups.is_empty() {
            session.pending_reminders.push(Reminder::new(
                ReminderKind::SystemWarning,
                Source::Kernel,
                format!(
                    "[Duplicate tool call detected: {}] You called these tools with identical \
                     arguments last turn. Use different parameters, a different tool, or \
                     reconsider the approach.",
                    dups.join(", ")
                ),
            ));
        }
        session.last_tool_signatures = current_sigs;
    }

    // ── auto-think-on-stuck — raise thinking budget when stuck ──────────
    // When enabled and any tool has hit the consecutive-error threshold,
    // temporarily enable extended thinking (8 192 tokens) to help the model
    // reason its way out of the stuck state.
    if session.auto_think_on_stuck && session.config.thinking_budget.is_none() {
        let is_stuck = session.plan.tool_call_stats.values()
            .any(|(_, err)| *err >= planner::TOOL_ERROR_THRESHOLD);
        if is_stuck {
            session.config.thinking_budget = Some(8_192);
            session.pending_reminders.push(Reminder::new(
                ReminderKind::SystemWarning,
                Source::Kernel,
                "[Auto-think activated] Extended thinking enabled due to repeated errors. \
                 Reason carefully before your next tool call."
                    .to_string(),
            ));
        }
    }

    // ── execute — skip tool dispatch when blocked (tool_uses is now
    // empty so this short-circuits naturally) so we don't run side
    // effects for output the user will never see. ─────────────────────
    let tool_results: Vec<RecordedToolResult> = if tool_uses.is_empty() {
        Vec::new()
    } else {
        session.executor.execute(&session.tools, &tool_uses).await
    };

    // Apply per-tool output character limits when configured. Per-tool caps
    // are tighter than the global 50k executor cap and let users silence
    // verbose tools (e.g. cargo test, grep) without a global truncation.
    let tool_results: Vec<context::RecordedToolResult> = if session.tool_output_limits.is_empty() {
        tool_results
    } else {
        tool_results
            .into_iter()
            .map(|mut r| {
                let tool_name = tool_uses.iter()
                    .find(|tu| tu.id == r.tool_use_id)
                    .map(|tu| tu.name.as_str())
                    .unwrap_or("");
                if let Some(&cap) = session.tool_output_limits.get(tool_name) {
                    if r.content.len() > cap {
                        let dropped = r.content.len() - cap;
                        let head: String = r.content.chars().take(cap).collect();
                        r.content = format!(
                            "{head}\n\n[PER-TOOL LIMIT ({tool_name}): {dropped} chars dropped — \
                             use a more specific query or raise with /tool-output-max {tool_name} <N>]"
                        );
                    }
                }
                r
            })
            .collect()
    };

    // Drain any reminders the PreToolUse / PostToolUse hooks emitted
    // during execute() and queue them for the NEXT turn so the model
    // sees the hook commentary on its next call.
    let hook_reminders = session.executor.drain_pending_reminders();
    for body in hook_reminders {
        session.pending_reminders.push(Reminder::new(
            ReminderKind::SystemWarning,
            Source::Kernel,
            body,
        ));
    }

    // Feed tool outcomes into the planner's consecutive-error tracker.
    // Consecutive failures accumulate; a success resets the counter for
    // that tool. When a tool hits TOOL_ERROR_THRESHOLD consecutive errors
    // the next refresh() injects a stuck-guidance note into the system prompt.
    for r in &tool_results {
        if let Some(tu) = tool_uses.iter().find(|tu| tu.id == r.tool_use_id) {
            if r.is_error {
                session.plan.record_tool_error(&tu.name);
                session.plan.record_tool_error_text(&tu.name, &r.content);
            } else {
                session.plan.record_tool_success(&tu.name);
            }
        }
    }

    // ── observe — record the turn ────────────────────────────────────
    session.history.push(ConversationItem::Assistant {
        text: final_text,
        tool_uses: tool_uses.clone(),
    });
    if !tool_results.is_empty() {
        session
            .history
            .push(ConversationItem::ToolResults(tool_results));
    }

    session.turn_index += 1;

    // ── decide next outcome ──────────────────────────────────────────
    if blocked {
        // History now ends with the blocked Assistant sentinel. Without a
        // following User message the next API call would send assistant-prefill
        // and Anthropic returns 400. Push a synthetic User acknowledgment so
        // the alternation is restored before ContinueImmediately fires.
        session.history.push(ConversationItem::User(
            "[SYSTEM] Your previous response was blocked by the content-safety \
             verifier. Please revise your answer without repeating the blocked content."
                .into(),
        ));
        return Ok(TurnOutcome::ContinueImmediately);
    }
    Ok(match resp.stop_reason {
        StopReason::EndTurn => TurnOutcome::AwaitUser,
        StopReason::ToolUse => TurnOutcome::ContinueImmediately,
        StopReason::MaxTokens => {
            // When there were no tool_uses, history ends with a partial
            // Assistant turn and no ToolResults follow. The next API call
            // would send assistant-prefill → Anthropic 400. Insert a
            // synthetic User continuation so the U/A/U alternation holds.
            if tool_uses.is_empty() {
                session.history.push(ConversationItem::User(
                    "[SYSTEM] Your response was cut off by the token limit. \
                     Please continue seamlessly from where you left off."
                        .into(),
                ));
            }
            TurnOutcome::ContinueImmediately
        }
        StopReason::Refusal => TurnOutcome::AwaitUser,
        // A configured stop sequence hit — model's "natural" end.
        StopReason::StopSequence => TurnOutcome::AwaitUser,
        // Server-side pause (extended-thinking style); resume immediately.
        StopReason::PauseTurn => TurnOutcome::ContinueImmediately,
    })
}
