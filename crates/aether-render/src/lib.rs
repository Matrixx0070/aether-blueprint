//! Ratatui-based TUI for aether — Claude Code-inspired visual design.
//!
//! Layout (top → bottom):
//!   1. Header bar  (1 line):  ◆ Aether · model · cwd · perm
//!   2. Main area   (flex):    chat (left ~70%) | tools panel (right ~30%)
//!   3. Input area  (4 lines): "> " prompt with typed message
//!   4. Hints bar   (1 line):  key shortcuts + session cost
//!
//! Chat messages use CC-style prefix glyphs ("> " user, "◆ " aether) with
//! no surrounding box borders — the conversation flows cleanly down the left
//! pane. The right panel keeps a subtle border to delineate tool activity.
//! A live spinner animates when the agent is thinking.

use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap};
use ratatui::Terminal;
use std::io::{self, Stdout};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

// ── colour palette (TrueColor) ────────────────────────────────────────────────

const C_BRAND: Color = Color::Rgb(99, 179, 237); // sky-300   — ◆ brand glyph
const C_HDR_BG: Color = Color::Rgb(15, 23, 42); // slate-950 — header / hints bg
const C_USER_PFX: Color = Color::Rgb(148, 163, 184); // slate-400 — ">" user prefix
const C_ASST_PFX: Color = Color::Rgb(129, 140, 248); // indigo-400— "◆" aether prefix
const C_BODY: Color = Color::Rgb(226, 232, 240); // slate-200 — body text
const C_DIM: Color = Color::Rgb(100, 116, 139); // slate-500 — dim / secondary
const C_CODE_FG: Color = Color::Rgb(125, 211, 252); // sky-300   — inline `code`
const C_CODE_BG: Color = Color::Rgb(30, 41, 59); // slate-800 — inline code bg
const C_HEAD_FG: Color = Color::Rgb(192, 132, 252); // purple-400— ## headings
const C_OK: Color = Color::Rgb(74, 222, 128); // green-400 — tool success
const C_WARN: Color = Color::Rgb(251, 191, 36); // amber-400 — running / warn
const C_ERR: Color = Color::Rgb(248, 113, 113); // red-400   — error
const C_BORDER: Color = Color::Rgb(51, 65, 85); // slate-700 — panel border

// Syntax-highlighting palette (inside fenced code blocks)
const C_SYN_KW:  Color = Color::Rgb(196, 181, 253); // violet-300 — keywords
const C_SYN_STR: Color = Color::Rgb(110, 231, 183); // emerald-300 — strings
const C_SYN_NUM: Color = Color::Rgb(253, 186, 116); // orange-300  — numbers
const C_SYN_CMT: Color = Color::Rgb(100, 116, 139); // slate-500   — comments

// Eight-frame braille spinner; advances at ~8 fps (125 ms / frame).
const SPINNER_FRAMES: &[&str] = &["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"];

fn spinner_frame() -> &'static str {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_millis();
    SPINNER_FRAMES[(ms / 125) as usize % SPINNER_FRAMES.len()]
}

// ── headless renderer (kept for tests / non-TTY usage) ───────────────────────

pub trait Renderer: Send {
    fn write_text(&mut self, s: &str);
    fn write_diff(&mut self, before: &str, after: &str);
    fn flush(&mut self);
}

#[derive(Default)]
pub struct PlainRenderer {
    pub buf: String,
}

impl Renderer for PlainRenderer {
    fn write_text(&mut self, s: &str) {
        self.buf.push_str(s);
    }
    fn write_diff(&mut self, before: &str, after: &str) {
        for line in before.lines() {
            self.buf.push_str("- ");
            self.buf.push_str(line);
            self.buf.push('\n');
        }
        for line in after.lines() {
            self.buf.push_str("+ ");
            self.buf.push_str(line);
            self.buf.push('\n');
        }
    }
    fn flush(&mut self) {}
}

// ── TUI event / command types ─────────────────────────────────────────────────

/// Events pushed by the session-driver task into the UI event loop.
#[derive(Debug, Clone)]
pub enum UiEvent {
    AssistantDelta(String),
    AssistantDone(String),
    ToolStart {
        name: String,
        summary: String,
    },
    ToolDone {
        name: String,
        summary: String,
        is_error: bool,
        preview: String,
    },
    Usage {
        input: u64,
        output: u64,
        total: u64,
        cost_usd: f64,
    },
    Error(String),
    AwaitUser,
    /// Informational note sent from the agent driver to the UI (no error state).
    SystemNote(String),
    /// Response to QueryTools: list of (name, description) pairs.
    ToolList(Vec<(String, String)>),
    /// Response to QueryToolSchema: full JSON schema for one tool.
    ToolSchemaResult { name: String, description: String, schema: String },
    /// A single line of streaming output from a running Bash tool call.
    /// `id` is the tool_use_id; `line` is the text (may start with "[err] ").
    ToolOutputLine { id: String, line: String },
}

/// Commands sent from the UI back to the session driver.
#[derive(Debug, Clone)]
pub enum UiCommand {
    UserMessage(String),
    Cancel,
    Quit,
    /// Directly set the agent session's active plan text.
    SetPlan(String),
    /// Clear the agent session's active plan.
    ClearPlan,
    /// Request the driver to respond with the registered tool list (filtered by substring).
    QueryTools(String),
    /// Return the full input_schema JSON for a specific tool by name.
    QueryToolSchema(String),
    /// Set session thinking budget. None = off, Some(n) = n tokens.
    SetThinking(Option<u32>),
    /// Inject an environment variable into the driver's process env (inherited by Bash tool).
    SetEnvVar(String, String),
    /// Remove an environment variable from the driver's process env.
    UnsetEnvVar(String),
    /// Force context-history compaction regardless of usage threshold.
    ForceCompact,
    /// Inject a message into session history as a User turn (AI sees it as context, no LLM call).
    InjectContext(String),
    /// Set session sampling temperature. None = API default (1.0).
    SetTemperature(Option<f32>),
    /// Set per-turn max_tokens cap.
    SetMaxTokens(u32),
    /// Set/clear the user-defined system prompt suffix (`/persona`).
    /// None clears the suffix; Some(text) replaces it.
    SetPersona(Option<String>),
    /// Clear the session's conversation history (AI memory) without touching
    /// the TUI chat display. The AI starts fresh; the user sees all prior output.
    ClearHistory,
    /// Set tools_disabled_turns on SessionConfig. 0 = re-enable tools immediately.
    SetToolsDisabled(usize),
    /// Query the active plan text; driver replies with UiEvent::SystemNote.
    QueryPlan,
    /// Query per-tool consecutive error counts; driver replies with UiEvent::SystemNote.
    QueryStuck,
    /// Reset all tool error counts in the plan to 0.
    ResetToolErrors,
    /// Set or clear the session goal (None = clear).
    SetGoal(Option<String>),
    /// Query context window usage; driver replies with UiEvent::SystemNote.
    QueryContextInfo,
    /// Query session statistics (turns, tokens, cost, wall time, LLM latency).
    QuerySessionStats,
    /// Show the most recent tool error text + tool name.
    QueryLastError,
    /// Set max tool calls per turn (0 = unlimited).
    SetMaxToolsPerTurn(usize),
    /// Full diagnostic dump of session state.
    QueryDebugSession,
    /// Set autonomous turn budget (0 = unlimited).
    SetMaxTurns(usize),
    /// Show last N history items as a SystemNote (0 = all).
    QueryHistory(usize),
    /// List all registered tools with their descriptions (alias for QueryTools with empty filter).
    QueryToolsList,
    /// Drop all but the last N conversation history items (0 = keep all, 1 = keep last pair).
    TrimHistory(usize),
    /// Change the session model mid-flight.
    SetModel(String),
    /// Serialize session history to a JSON file at the given path.
    SaveSession(String),
    /// Load history from a previously saved JSON session file.
    LoadSession(String),
    /// Show detailed token cost breakdown for this session.
    QueryCostEstimate,
    /// Add a standing instruction reminder (re-injected every turn).
    AddPersistentReminder(String),
    /// Clear all standing instructions.
    ClearPersistentReminders,
    /// List all standing instructions.
    QueryPersistentReminders,
    /// Pop the last user+assistant turn pair from history (undo).
    UndoLastTurn,
    /// Search conversation history for messages containing the given substring.
    FindInHistory(String),
    /// Save the current active plan text to a file.
    SavePlan(String),
    /// Replace the active plan text with content from a file.
    LoadPlan(String),
    /// Reset per-session LLM timing and token counters.
    ResetStats,
    /// Show per-tool lifetime call statistics (successes, failures, error rate).
    QueryToolStats,
    /// Configure the planner sliding-window size (0 = monotonic/no window).
    SetPlanWindow(usize),
    /// Set the compaction threshold (1–99 percent; 0 = use default 80%).
    SetCompactionThreshold(u8),
    /// Set the total session token budget (0 = unlimited).
    SetTokenBudget(u64),
    /// Set the per-turn LLM timeout in seconds (0 = no timeout).
    SetLlmTimeout(u64),
    /// Clear lifetime tool call statistics (tool_call_stats).
    WipeToolStats,
    /// Enable or disable the D7 self-check verifier (true = enabled).
    SetVerifyEnabled(bool),
    /// Append text to the system prompt suffix (does not replace existing suffix).
    AppendSystemSuffix(String),
    /// Reset everything: history, plan, errors, stats, persistent reminders.
    ClearAll,
    /// Pause autonomous agent at next AwaitUser by setting max_turns to turn_index.
    PauseAtNext,
    /// Read a file and inject its content as user context into session history.
    AttachFile(String),
    /// Run a shell command and inject its output as user context.
    ShellInject(String),
    /// Pin a history item (by 0-based index) so its content persists across compaction.
    PinHistoryItem(usize),
    /// Remove a previously pinned history item by index.
    UnpinHistoryItem(usize),
    /// List all currently pinned history items.
    QueryPins,
    /// Remove the last assistant turn (and any trailing tool results), re-extract the last
    /// user message, and re-run the agent — effectively retrying the previous prompt.
    RetryLast,
    /// Serialise the conversation history to a Markdown file at the given path.
    ExportSession(String),
    /// Ask the agent to rewrite its last response with additional instructions.
    RewriteLast(String),
    /// Set the periodic goal-reminder interval (0 = off).
    SetTurnReminderEvery(usize),
    /// Show a breakdown of context usage by history item type.
    QueryContextHealth,
    /// Set the tool-call checkpoint interval (0 = off).
    SetCheckpointEveryTools(usize),
    /// Show the tools called in the most recent agent turn.
    QueryLastTools,
    /// Show total tool call counts across the session.
    QueryToolCallCount,
    /// Add a file path to the warmup list (re-injected as context after compaction).
    AddWarmupFile(String),
    /// Remove a file path from the warmup list.
    RemoveWarmupFile(String),
    /// List all warmup files.
    QueryWarmupFiles,
    /// Set a per-tool output character cap (0 = remove cap for that tool).
    SetToolOutputMax(String, usize),
    /// List all per-tool output limits.
    QueryToolOutputLimits,
    /// Enable or disable consecutive duplicate tool call detection.
    SetDedupToolCalls(bool),
    /// Enable or disable auto-thinking when the agent is stuck.
    SetAutoThinkOnStuck(bool),
    /// Enable or disable auto-compaction when the agent is stuck.
    SetAutoCompactOnStuck(bool),
    /// Remove ToolResults items from history (keeps User+Assistant turns).
    SmartTrimHistory,
    /// Set the total tool-error fail-fast threshold (0 = off).
    SetFailFast(usize),
    /// Query session elapsed wall time.
    QueryElapsed,
    /// Enable or disable the auto-status summary after each agent cycle.
    SetAutoStatus(bool),
    /// Show all active budget/limit configurations and current usage.
    QueryBudgetCheck,
    /// Add a (pattern, hint) entry to the error playbook.
    AddPlaybookEntry(String, String),
    /// Remove a playbook entry by 0-based index.
    RemovePlaybookEntry(usize),
    /// List all error playbook entries.
    QueryPlaybook,
    /// Set a named session variable (name, value).
    SetSessionVar(String, String),
    /// Delete a named session variable.
    DeleteSessionVar(String),
    /// List all session variables.
    QuerySessionVars,
    /// Set a file scope guard pattern (None = off).
    SetScopeGuard(Option<String>),
    /// Show the current scope guard.
    QueryScopeGuard,
    /// Set the agent persona (None = off).
    SetAgentPersona(Option<String>),
    /// Show the current agent persona.
    QueryAgentPersona,
    /// Show a line-diff between the last two outputs of a named tool.
    QueryToolDiff(String),
    /// Compute and show a composite session health score.
    QuerySessionHealth,
    /// Configure auto-retry: (error_threshold, max_retries). 0,0 = off.
    SetRetryOnError(usize, usize),
    /// Show current auto-retry configuration.
    QueryRetryOnError,
    /// Annotate the current turn with a label (turn_index, label).
    LabelTurn(usize, String),
    /// List all labeled turns.
    QueryTurnLabels,
    /// Remove a turn label by 0-based index in the label list.
    RemoveTurnLabel(usize),
    /// Add a snippet to the sticky context list (prepended to system prompt every turn).
    AddStickyContext(String),
    /// Remove a sticky context entry by 0-based index.
    RemoveStickyContext(usize),
    /// List all sticky context entries.
    QueryStickyContext,
    /// Clear all sticky context entries.
    ClearStickyContext,
    /// Export the full session turn log to a file (path, format: "json"|"md").
    ExportTurns(String, String),
    /// Set the preferred response format ("json", "markdown", "plain", or custom).
    SetResponseFormat(Option<String>),
    /// Show the current response format constraint.
    QueryResponseFormat,
    /// Set a session-scoped environment variable (KEY, VALUE).
    SetSessionEnv(String, String),
    /// Remove a session-scoped environment variable by key.
    UnsetSessionEnv(String),
    /// Show all session-scoped environment variables.
    QuerySessionEnv,
    /// Add a tool name to the allow-list (empty = allow all).
    AllowTool(String),
    /// Add a tool name to the deny-list.
    DenyTool(String),
    /// Clear both allow and deny tool filter lists.
    ClearToolFilter,
    /// Show current tool allow/deny filter configuration.
    QueryToolFilter,
    /// Enable or disable auto git-commit after each tool-using turn.
    SetAutoCommit(bool),
    /// Set the commit message template (supports {turn} placeholder).
    SetAutoCommitTemplate(String),
    /// Show current auto-commit config.
    QueryAutoCommit,
    /// Show the most recent N per-turn cost entries (default 10).
    QueryCostPerTurn(usize),
    /// Show a full per-turn cost report for the session.
    QueryCostReport,
    /// Set a fallback LLM model to retry with on primary model failure (None = off).
    SetLlmFallback(Option<String>),
    /// Show the current fallback model and invocation count.
    QueryLlmFallback,
    /// Set a hard cost cap in USD (0.0 = off). Agent stops when exceeded.
    SetCostCap(f64),
    /// Show current cost cap and cumulative cost.
    QueryCostCap,
    /// Show token consumption rate (tokens/sec) and estimated time to fill.
    QueryTokenRate,
    /// Define a slash-command alias: (name, expansion).
    SetAlias(String, String),
    /// Remove a slash-command alias by name.
    RemoveAlias(String),
    /// List all defined aliases.
    QueryAliases,
    /// Set a shell command to auto-run after each tool-using agent turn.
    SetPostTurnHook(Option<String>),
    /// Show the current post-turn hook command.
    QueryPostTurnHook,
    /// Add a task string to the sequential task queue.
    AddTask(String),
    /// List all queued tasks (index + text).
    QueryTasks,
    /// Remove all tasks from the queue.
    ClearTasks,
    /// Skip the next queued task (pop without executing).
    SkipTask,
    /// Save current history+plan under a named in-memory snapshot.
    SaveSnapshot(String),
    /// Restore history+plan from a named in-memory snapshot.
    LoadSnapshot(String),
    /// List all saved in-memory snapshots.
    ListSnapshots,
    /// Delete all in-memory snapshots.
    ClearSnapshots,
    /// Add an item to the in-session progress tracker.
    AddProgressItem(String),
    /// Mark a progress item (by 0-based index) as done.
    DoneProgressItem(usize),
    /// Clear all progress items.
    ClearProgressItems,
    /// List current progress items.
    QueryProgressItems,
    /// Start capturing agent output (user + assistant turns) to a file (path).
    StartCapture(String),
    /// Stop the current output capture and close the file.
    StopCapture,
    /// Show current capture state: active path and bytes written.
    QueryCapture,
    /// Re-send the Nth past user message (0-based index) as a new turn.
    ReplayTurn(usize),
    /// Re-send the most recent user message as a new turn.
    ReplayLast,
    /// List past user messages with their indices.
    QueryReplayList,
    /// Add a bookmark at the current turn (optional label).
    AddBookmark(String),
    /// List all bookmarks with indices, labels, and turn/history info.
    QueryBookmarks,
    /// Show the assistant response at the bookmarked position (0-based index).
    JumpBookmark(usize),
    /// Delete a bookmark by 0-based index.
    DeleteBookmark(usize),
    /// Extract TODO/FIXME/HACK/NOTE comments from code blocks in all responses.
    QueryFindTodos,
    /// Export turn_cost_log + wall times as a CSV file.
    ExportCsv(String),
    /// Show cost/tokens for a specific turn by 0-based turn index.
    QueryTurnCost(usize),
    /// Show cumulative cost growth turn by turn as a mini bar chart.
    QueryCostTimeline,
    /// Show average/min/max response times from turn_wall_ms.
    QueryAvgResponseTime,
    /// Save the last assistant response text to the given file path.
    SaveLastResponse(String),
    /// Show turns/hour, cost/hour, tokens/hour for the session.
    QuerySessionVelocity,
    /// Show input vs output token split as percentage and absolute counts.
    QueryTokenBreakdown,
    /// Show the last N history items in compact form.
    QueryHistoryTail(usize),
    /// Set auto-bookmark interval: add a bookmark every N turns automatically.
    SetAutoBookmarkEvery(usize),
    /// Clear the auto-bookmark interval (disable auto-bookmarks).
    ClearAutoBookmarkEvery,
    /// Show current auto-bookmark setting.
    QueryAutoBookmarkEvery,
    /// Clear all session bookmarks.
    ClearAllBookmarks,
    /// Find and list all code blocks across all assistant responses, optionally filtered by language.
    QueryFindCodeBlocks(String),
    /// Show remaining tokens before context compaction threshold is hit.
    QueryContextHeadroom,
    /// List all assistant responses longer than N characters with their history indices.
    QueryFindLongResponses(usize),
    /// Show a compact summary of the Nth user exchange (0-based exchange index).
    QueryTurnSummary(usize),
    /// Compute and show a quality score for the last assistant response.
    QueryResponseQuality,
    /// Show a line-diff between two history items by 0-based history index.
    QueryDiffHistory(usize, usize),
    /// Set minimum milliseconds between auto-continue ticks (0 = off).
    SetCooldown(u64),
    /// Clear the auto-continue cooldown.
    ClearCooldown,
    /// Show current cooldown setting.
    QueryCooldown,
    /// Show tokens-per-second and tokens-per-minute for the session.
    QueryTokenVelocity,
    /// Set a pattern that pauses the agent when found in an assistant response.
    SetSmartPause(String),
    /// Clear the smart-pause pattern.
    ClearSmartPause,
    /// Show the current smart-pause pattern and status.
    QuerySmartPause,
    /// Show full input/output of every tool call from the last assistant turn.
    QueryDebugTools,
    /// Show a comprehensive end-of-session report.
    QuerySessionReport,
    /// Export the conversation history as a markdown file to the given path.
    ExportMarkdown(String),
    /// Show a per-turn token-usage chart (mini bar chart of tokens in+out per turn).
    QueryContextMap,
    /// Clear all session notes (session_notes Vec).
    ClearNotes,
    /// Project future cost: given N more turns at current avg burn rate, show total projected cost.
    QueryCostProjection(usize),
    /// Show a compact one-line status: turn, cost, context-fill, tool errors.
    QueryQuickStatus,
    /// Show estimated size of history in bytes and items.
    QueryHistorySize,
    /// Display a comprehensive active-modes summary for this session.
    QueryModeReport,
    /// Show the last user message from history.
    QueryLastUser,
    /// Show the per-turn model history (which model was used for each turn).
    QueryModelHistory,
    /// Compute and display a 0–100 context health score.
    QueryContextHealthScore,
    /// Dump session.history as JSON to the given file path.
    DumpHistory(String),
    /// Add a user-defined tag/label to the current session.
    AddSessionTag(String),
    /// Remove a session tag by 0-based index.
    DelSessionTag(usize),
    /// List all session tags.
    QuerySessionTags,
    /// Show per-tool success rate (ok / total) from session tool call stats.
    QueryToolSuccessRate,
    /// Set a soft cost alert threshold in USD (fires a note once, does not stop agent).
    SetCostAlert(f64),
    /// Clear the cost alert threshold.
    ClearCostAlert,
    /// Show the current cost alert threshold and whether it has fired.
    QueryCostAlert,
    /// Show how long the current session has been running (wall clock).
    QuerySessionDuration,
    /// Search all assistant responses for a substring pattern (case-insensitive).
    QueryResponseGrep(String),
    /// Add an auto-tag rule: (pattern, label) — bookmark added when response matches.
    AddAutoTag(String, String),
    /// Remove an auto-tag rule by 0-based index.
    DelAutoTag(usize),
    /// List all auto-tag rules.
    QueryAutoTags,
    /// Resend the last user message as a new user turn.
    RepeatLast,
    /// Extract and display all fenced code blocks from the last assistant response.
    QueryShowCode,
    /// Extract and display all URLs from the last assistant response.
    QueryShowUrls,
    /// Show cost and token totals accumulated since (and including) turn N.
    QueryCostSince(usize),
    /// Show min/avg/max length stats for all assistant responses in history.
    QueryResponseStats,
    /// Show count of each ConversationItem type in history (User/Assistant/ToolResult).
    QueryHistoryStats,
    /// Show the index and first 200 chars of the longest assistant response.
    QueryLongestResponse,
    /// Show per-turn cost/token/latency log. 0 = all turns; N = last N turns.
    QueryTurnLog(usize),
    /// Show session-level efficiency metrics: tokens/dollar, avg cost, peak turn.
    QuerySessionEfficiency,
    /// Set a text prefix prepended to every user message before AI dispatch.
    SetRequestPrefix(String),
    /// Clear the per-request prefix.
    ClearRequestPrefix,
    /// Set a text suffix appended to every user message before AI dispatch.
    SetRequestSuffix(String),
    /// Clear the per-request suffix.
    ClearRequestSuffix,
    /// Show current request prefix and suffix settings.
    QueryRequestWrap,
    /// Remove the last N items from conversation history — alias for the existing TrimHistory variant.
    TrimLastN(usize),
    /// Remove all User items from conversation history.
    TrimUserHistory,
    /// Remove all Assistant items from conversation history.
    TrimAssistantHistory,
    /// Enable or disable think-aloud mode (bool). When enabling with a custom preamble, see SetThinkAloudPrompt.
    SetThinkAloud(bool),
    /// Set a custom think-aloud preamble (empty = use default).
    SetThinkAloudPrompt(String),
    /// Show current think-aloud mode and preamble.
    QueryThinkAloud,
    /// Use a specific model for the next turn only, then revert.
    SetNextTurnModel(String),
    /// Clear any pending next-turn model override.
    ClearNextTurnModel,
    /// Show current next-turn model override (if any).
    QueryNextTurnModel,
    /// Show a line-diff between two assistant turns by 0-based index.
    QueryTurnDiff(usize, usize),
    /// Show total word count in conversation history by role.
    QueryWordCount,
    /// Show total character count in conversation history by role.
    QueryCharCount,
    /// Show a comprehensive session volume report (words, chars, tokens, items).
    QuerySessionVolume,
    /// Set a total tool-call budget for the session (0 = unlimited).
    SetToolBudget(usize),
    /// Show current tool-call budget and usage.
    QueryToolBudget,
    /// Search the user input history for a substring (case-insensitive).
    SearchInputHistory(String),
    /// Show the last N user inputs from the input history buffer.
    QueryInputHistory(usize),
    /// Clear the user input history buffer.
    ClearInputHistory,
    /// Add a note to the in-session notepad (text).
    AddNote(String),
    /// Remove a note by 0-based index.
    DeleteNote(usize),
    /// List all session notes.
    QueryNotes,
    /// Show detailed per-tool breakdown: ok/err counts and call order.
    QueryToolStatsDetail,
    /// Show the top N tools by total call count.
    QueryToolTop(usize),
    /// List only tools that had at least one error this session.
    QueryToolErrors,
    /// Full-text search across conversation history items (returns matches).
    SearchHistory(String),
    /// Full-text search across tool output history (tool_output_history values).
    SearchToolOutputs(String),
    /// Schedule a pause after N more autonomous turns (0 = clear).
    SetPauseAfter(usize),
    /// Pause the agent after the current turn completes.
    SetPauseNow,
    /// Clear all pending pause signals.
    ClearPause,
    /// Show current pause configuration.
    QueryPauseStatus,
    /// Show elapsed time for the last agent turn.
    QueryTurnTime,
    /// Show average elapsed time across all agent turns this session.
    QueryTurnTimeAvg,
    /// Show full per-turn wall-clock latency history.
    QueryLatencyLog,
    /// Save a named prompt macro (name, text).
    SaveMacro(String, String),
    /// Delete a named prompt macro by name.
    DeleteMacro(String),
    /// Run a named prompt macro (sends its text as a user message).
    RunMacro(String),
    /// List all saved prompt macros.
    QueryMacros,
    /// Set context-fill warn threshold (0.0=off, e.g. 0.70 for 70%).
    SetTokenBudgetWarn(f64),
    /// Set context-fill hard-stop threshold (0.0=off).
    SetTokenBudgetHard(f64),
    /// Show current token budget thresholds and fill level.
    QueryTokenBudgetStatus,
    /// Inject a User message into history without triggering an agent turn.
    InjectUser(String),
    /// Inject an Assistant message into history (as if the agent said it).
    InjectAssistant(String),
    /// Remove the most recent history item (undo last injection or turn).
    PopHistory,
    /// Show the number of items in the conversation history.
    QueryHistoryLen,
    /// Reset session metrics (turn_cost_log, turn_wall_ms, turn_models) without clearing history.
    ResetSessionMetrics,
    /// OR-search across conversation history for any of the given pipe-separated patterns.
    QueryMultiSearch(String),
    /// Show a chronological log of all tool calls grouped by turn index.
    QueryToolTimeline,
    /// Find-and-replace text in the last User history item (old, new).
    HistoryGrepReplace(String, String),
    /// Show what a named alias expands to, or note if it doesn't exist.
    QueryAliasExpand(String),
    /// Analyse gaps between turns: show per-turn wall-time deltas and flag long pauses.
    QueryTurnGapAnalysis,
    /// Inject a timestamped annotation as a SystemNote into the chat log.
    SessionAnnotate(String),
    /// Show each history item as a single-line type:length:preview summary.
    QueryHistoryCompact,
    /// Given N more turns at current avg token burn, forecast context exhaustion.
    QueryTokenForecast(usize),
    /// Scan all ToolResults in history and report entries with is_error=true.
    QueryFindErrors,
    /// Show estimated cost attribution by tool name (avg cost/call × call count).
    QueryCostPerTool,
    /// List all User turns in history with their index and a text preview.
    QueryUserTurnList,
    /// Extract all JSON code blocks from assistant responses in history.
    QueryExtractJson,
    /// Detailed efficiency report: tokens/dollar, cost/hr, turns/hr, avg tools/turn.
    QueryEfficiencyReport,
    /// Show tool-calls-per-turn as a mini histogram.
    QueryToolCallDensity,
    /// Show assistant response lengths turn-by-turn with a trend indicator.
    QueryResponseLengthTrend,
    /// Show only history items matching a given type (user/asst/tool).
    QueryHistoryTypeFilter(String),
    /// Set a hard cost ceiling in USD; agent stops when exceeded (0.0 = off).
    SetCostCeiling(f64),
    /// Show current cost ceiling and cumulative cost.
    QueryCostCeiling,
    /// Search session notes for a case-insensitive pattern.
    QueryNoteSearch(String),
    /// Export all session variables to a JSON file at the given path.
    ExportSessionVars(String),
    /// Count words and lines in the current active plan text.
    QueryPlanWordCount,
    /// Show per-history-item type breakdown with rough token estimates.
    QueryCompactHistoryStats,
    /// Export all session bookmarks to a JSON file.
    ExportBookmarks(String),
    /// Show top N most frequent words across all assistant responses.
    QueryResponseWordFreq(usize),
    /// Show the value of a specific named session variable.
    QuerySessionVar(String),
    /// Find-and-replace text across ALL User history items (not just the last).
    HistorySearchReplaceAll(String, String),
    /// Estimate what the session would have cost on a different model.
    QueryModelCompareCost(String),
    /// Search all tool_output_history entries for a pattern (case-insensitive).
    QueryToolOutputSearch(String),
    /// Show history items in reverse order (newest first) as compact previews.
    QueryHistoryReverse(usize),
    /// Detect turns with more than N tool calls (burst detection). 0 = auto threshold.
    QuerySessionBurstDetect(usize),
    /// Search history for pattern, return N context lines around each match.
    QueryResponseSearchContext(String, usize),
    /// Combined per-turn table: turn#, model, cost, wall_ms, tool count.
    QuerySessionTimeline,
    /// Save the active plan text to a file at the given path.
    ExportPlan(String),
    /// Run multiple named macros in sequence, joined by newline, as one agent message.
    RunMacroChain(Vec<String>),
    /// Remove all ToolResults items from history (alias for SmartTrimHistory).
    StripToolResults,
    /// Show cost grouped by model when multiple models were used in a session.
    QueryCostBreakdownByModel,
    /// Show the Nth User turn and its immediately following Assistant response.
    QueryUserContext(usize),
    /// Append a response-length hint to the system suffix (short/medium/long).
    SetResponseLengthHint(String),
    /// Show a delta summary of context stats vs what they were N turns ago.
    QueryContextStatsDiff(usize),
    /// Set a focus topic appended to every system prompt as a sticky reminder (None = clear).
    SetFocusMode(Option<String>),
    /// Show the current focus mode topic if set.
    QueryFocusMode,
    /// Show per-tool error breakdown combining error_counts and tool_call_stats.
    QueryToolErrorSummary,
    /// Hard-truncate history to keep only the last N items (drop from head).
    HistoryTruncateTo(usize),
    /// Show all pending_reminders that will be injected into the next turn.
    QueryPendingReminders,
    /// Merge two consecutive User history items (by index) into one concatenated message.
    HistoryMergeUser(usize, usize),
    /// Show count and summary of tools currently in the deny list.
    QueryDenyList,
    /// Compute and show a composite session quality score (0-100).
    QuerySessionScore,
    /// Estimate how many history items fit within the model's context window.
    QueryHistoryContextWindowEstimate,
    /// Show full input + output of the Nth tool call in the last assistant turn.
    QueryToolCallTrace(usize),
    /// List all saved snapshots with their history size.
    QuerySnapshotList,
    /// Grade the Nth assistant response on length, tool use, and clarity.
    QueryResponseGrade(usize),
    /// Set a soft warning when estimated history size exceeds N bytes (0 = off).
    SetHistorySizeWarn(usize),
    /// Show the current history size warning threshold.
    QueryHistorySizeWarn,
    /// Append a max word count constraint to the system suffix.
    SetMaxResponseLength(usize),
    /// Export conversation history as JSONL (one object per line).
    ExportHistoryJsonl(String),
    /// Set a high-level session intent string (shown in reports).
    SetSessionIntent(String),
    /// Show the current session intent.
    QuerySessionIntent,
    /// Add an annotation note to a specific history item by index.
    AnnotateHistory(usize, String),
    /// List all history annotations.
    QueryHistoryAnnotations,
    /// Show cost accumulated since last /session-reset-metrics call.
    QueryCostSinceReset,
    /// Set a per-tool-call execution timeout in seconds (0 = off).
    SetToolTimeout(u64),
    /// Show the current tool timeout setting.
    QueryToolTimeout,
    /// Remove consecutive duplicate User messages from conversation history.
    HistoryDedup,
    /// Show top N most expensive turns by token cost.
    QueryTopCostTurns(usize),
    /// Show the first user message in conversation history.
    QueryHistoryFirstUser,
    /// Show min/max/avg turn cost from the turn cost log.
    QueryTurnCostStats,
    /// Show estimated context fill percentage vs model window.
    QueryContextFillPct,
    /// Show the last assistant response text from history.
    QueryHistoryLastAssistant,
    /// Show total input and output tokens summed across all turns.
    QueryTurnTokensTotal,
    /// Count of User-role items in conversation history.
    QueryHistoryUserCount,
    /// Show line count of the active plan.
    QueryPlanLines,
    /// Export session notes to a file path.
    ExportSessionNotes(String),
    /// Show total tool calls used vs budget this session.
    QueryToolBudgetRemaining,
    /// Count tool-use entries across all history items.
    QueryHistoryToolCount,
    /// Show count of active sticky context entries.
    QueryStickyCount,
    /// Export session notes as a markdown file.
    ExportNotesMd(String),
    /// Count Assistant-role items in conversation history.
    QueryHistoryAssistantCount,
    /// Count in-memory named snapshots.
    QuerySnapshotCount,
    /// Show which model was used for a specific turn index.
    QueryTurnModelShow(usize),
    /// Count defined aliases.
    QueryAliasCount,
    /// Show history size in megabytes.
    QueryHistorySizeMb,
    /// Show cost per session note as a rough efficiency metric.
    QueryCostPerNote,
    /// Show history items in a specific index range (from, to inclusive).
    QueryHistoryItemsRange(usize, usize),
    /// Count session environment variables.
    QuerySessionEnvCount,
    /// Count user-defined turn labels.
    QueryLabelCount,
    /// Count defined prompt macros.
    QueryMacroCount,
    /// Count history items matching a grep pattern.
    QueryHistoryGrepCount(String),
    /// Count files in the warmup-files list.
    QueryWarmupCount,
    /// Count progress items (total, done, pending).
    QueryProgressCount,
    /// Remove the last item from conversation history.
    HistoryDropLast,
    /// Show cumulative cost and total tokens together.
    QueryCostTotalTokens,
    /// Remove the first N items from conversation history.
    HistoryTruncateHead(usize),
    /// Count error playbook entries.
    QueryErrorPlaybookCount,
    /// List session notes briefly (index + first 60 chars).
    QuerySessionNotesList,
    /// Find history items containing a specific tool name in tool_uses.
    QueryHistoryFindTool(String),
    /// Count auto-tag rules.
    QueryAutoTagCount,
    /// Show cost ceiling status: current spend vs ceiling.
    QueryCostCeilingStatus,
    /// Show breakdown of history items by type (User/Assistant/ToolResults).
    QueryHistorySummaryStats,
    /// Show current task queue depth and next task.
    QueryTaskCount,
    /// Count conversation bookmarks.
    QueryBookmarkCount,
    /// Count session tags.
    QuerySessionTagsCount,
    /// Count tools in the allow-list.
    QueryToolAllowCount,
    /// Show the current preferred response format setting.
    QueryResponseFormatShow,
    /// Show the active scope guard pattern.
    QueryScopeGuardShow,
    /// Show current think-aloud setting and prompt.
    QueryThinkAloudShow,
    /// Show the configured LLM fallback model.
    QueryFallbackModelShow,
    /// Show whether auto-status is enabled.
    QueryAutoStatusShow,
    /// Show the max-turns limit for this session.
    QueryMaxTurnsShow,
    /// Show the fail-fast error threshold setting.
    QueryFailFastShow,
    /// Show whether consecutive-tool dedup is enabled.
    QueryDedupToolsShow,
    /// Show the checkpoint-every-tools setting.
    QueryCheckpointEveryShow,
    /// Show the auto-think-on-stuck setting.
    QueryAutoThinkShow,
    /// Show the auto-compact-on-stuck setting.
    QueryAutoCompactShow,
    /// Show the LLM call timeout setting.
    QueryLlmTimeoutShow,
    /// Show whether the D7 verifier is enabled.
    QueryVerifyShow,
    /// Show the turn-reminder-every frequency setting.
    QueryTurnReminderShow,
    /// Show the context compaction threshold percentage.
    QueryCompactionThresholdShow,
    /// Show the auto-commit setting and template.
    QueryAutoCommitShow,
    /// Show the token-budget warn threshold.
    QueryTokenBudgetWarnShow,
    /// Show the token-budget hard-stop threshold.
    QueryTokenBudgetHardShow,
    /// Show the configured post-turn hook command.
    QueryPostTurnHookShow,
    /// Show the current request prefix injected before every user message.
    QueryRequestPrefixShow,
    /// Show the current request suffix appended after every user message.
    QueryRequestSuffixShow,
    /// Show all entries in the tool deny list.
    QueryToolDenyShow,
    /// Show all entries in the tool allow list.
    QueryToolAllowShow,
    /// Show all current session variables (key=value pairs).
    QuerySessionVarsShow,
    /// Show the pause-after-turns setting.
    QueryPauseAfterShow,
    /// List all session tags.
    QuerySessionTagsList,
    /// List all error-playbook entries.
    QueryErrorPlaybookList,
    /// List all queued tasks.
    QueryTaskList,
    /// List all bookmarks with labels.
    QueryBookmarkList,
    /// List all session aliases.
    QueryAliasList,
    /// Show average wall-clock time per turn.
    QueryTurnWallAvg,
    /// Show the top 5 most expensive turns by cost.
    QueryTurnCostTop,
    /// Show plan tool-call success/error stats.
    QueryPlanStats,
    /// List models used across all turns.
    QueryTurnModelList,
    /// List all turn labels.
    QueryLabelList,
    /// Show last known output of a named tool.
    QueryToolOutputShow(String),
    /// Show session start time and elapsed duration.
    QueryStartTime,
    /// List all auto-tag rules (pattern → tag).
    QueryAutoTagRulesList,
    /// List all persistent reminders.
    QueryPersistentRemindersList,
    /// List all sticky-context entries.
    QueryStickyContextList,
    /// Count session notes.
    QuerySessionNotesCount,
    /// Show raw token budget (in tokens).
    QueryTokenBudgetRaw,
    /// List distinct tool names used in history.
    QueryHistoryToolNames,
    /// Show total token usage for this session.
    QueryUsageTotal,
    /// Show total and last-turn LLM latency.
    QueryLlmMsTotal,
    /// Show max-tool-calls-per-turn config.
    QueryMaxToolCallsShow,
    /// Show whether compaction has happened in this session.
    QueryCompactionHappened,
    /// Show configured thinking budget.
    QueryThinkingBudgetShow,
    /// Show configured LLM temperature.
    QueryTemperatureShow,
    /// Show the active permission mode.
    QueryPermissionMode,
    /// Show max-tokens-per-turn config.
    QueryMaxTokensPerTurn,
    /// Show whether the 60% context-fill warning has fired.
    QueryContextWarn60,
    /// Show current retry-on-error count and config.
    QueryRetryCountShow,
    /// Show total LLM fallback trigger count.
    QueryLlmFallbackTotal,
    /// Show cost cap (hard ceiling) setting.
    QueryCostCapShow,
    /// Show how many turns tools remain disabled.
    QueryToolsDisabledTurns,
    /// Show the system suffix / persona text.
    QuerySystemSuffixShow,
    /// Show whether the cost alert has fired.
    QueryCostAlertFired,
    /// List all session environment variables.
    QuerySessionEnvList,
    /// List all prompt macros.
    QueryPromptMacrosList,
    /// Show current turn index.
    QueryTurnIndexShow,
    /// List all history annotations.
    QueryHistoryAnnotationList,
    /// Show auto-continue cooldown configuration.
    QueryAutoContinueCooldown,
    /// Show last tool call signatures (dedup detection).
    QueryLastToolSigs,
    /// Show the current active model name.
    QueryCurrentModel,
    /// Show the full current plan text.
    QueryPlanTextShow,
    /// Show the active plan goal line.
    QueryPlanGoal,
    /// Show per-rule verifier block counts from the plan.
    QueryPlanBlockCounts,
    /// Show the last error text and tool name from the plan.
    QueryPlanLastError,
    /// Show per-tool consecutive error counts from the plan.
    QueryPlanToolErrors,
    /// Show the plan sliding-window size.
    QueryPlanWindowShow,
    /// Show total verifier blocks recorded in this plan.
    QueryPlanBlocksRecorded,
    /// Show the last verification result (blocked / passed / findings).
    QueryVerifierLastShow,
    /// Show last context-assembly telemetry.
    QueryAssemblyTeleShow,
    /// Show admitted and dropped reminder counts from last assembly.
    QueryRemindersShow,
    /// Show D1 (reminder tamper-test overlay) active status.
    QueryD1Status,
    /// Show D6 (long-conversation overlay) active status from last assembly.
    QueryD6Status,
    /// Show per-session tool call budget.
    QueryToolCallBudgetShow,
    /// Show whether long-conversation digest was injected last assembly.
    QueryLongConvStatus,
    /// Show whether plan text was included in last assembly's system prompt.
    QueryPlanIncludedShow,
    /// Count pending reminders in the queue.
    QueryPendingRemindersCount,
    /// Show the turn index at which metrics were last reset.
    QueryMetricResetTurn,
    /// Show average cost per completed turn.
    QueryCostPerTurnAvg,
    /// Show history byte size in memory.
    QueryHistorySizeBytes,
    /// Show the active focus mode.
    QueryFocusModeShow,
    /// Show whether the token-budget warn threshold has already fired.
    QueryTokenBudgetFired,
    /// List all saved snapshot keys.
    QuerySnapshotKeys,
    /// List all progress items with their completion status.
    QueryProgressItemsList,
    /// Show tool output character limit for a named tool.
    QueryToolOutputLimitShow(String),
    /// Show the wall-clock time of the most recent turn.
    QueryTurnWallLast,
    /// Get a single session variable by key.
    QuerySessionVarGet(String),
    /// Get the expansion of a named session alias.
    QueryAliasGet(String),
    /// Show the most recent session note.
    QueryNoteLatest,
    /// List all tool output char limits.
    QueryToolOutputLimitsList,
    /// Show which turns a specific verifier rule blocked.
    QueryPlanBlockTurns(String),
    /// Get the expansion of a named prompt macro.
    QueryMacroGet(String),
    /// Get a specific session environment variable by key.
    QueryEnvGet(String),
    /// Get a specific sticky-context entry by index.
    QueryStickyGet(usize),
    /// Get a specific warmup file path by index.
    QueryWarmupGet(usize),
    /// Show a concise plan health summary.
    QueryPlanSummary,
    /// Show a specific history item by index.
    QueryHistoryItemShow(usize),
    /// Count the number of verifier rules loaded.
    QueryVerifierRulesCount,
    /// Show top 5 tools by total call count.
    QueryToolStatsTop,
    /// Show error rate for a specific tool by name.
    QueryToolErrorRate(String),
    /// Show elapsed time since session start.
    QuerySessionAge,
    /// Show the last tool call found in conversation history.
    QueryHistoryLastTool,
    /// Count total plan steps (block entries) recorded.
    QueryPlanStepCount,
    /// Count how many verifier findings are blockers.
    QueryVerifierBlockedCount,
    /// Show tool-call budget usage (used / max).
    QueryToolCallBudgetUsed,
    /// Show ok-call count for a specific tool from plan stats.
    QueryPlanToolOkCount(String),
    /// Show reminders admitted count from last assembly telemetry.
    QueryRemindersAdmitted,
    /// Show last verifier result summary message.
    QueryVerifierMessage,
    /// Show whether the plan is currently marked dirty.
    QueryPlanDirty,
    /// Show estimated total byte size of conversation history.
    QueryHistoryByteSize,
    /// Show average cost per turn for this session.
    QuerySessionCostPerTurn,
    /// Count session notes stored.
    QueryNoteCount,
    /// Count session tags assigned.
    QuerySessionTagCount,
    /// Count tool output history entries.
    QueryToolOutputCount,
    /// Show total call count for a specific tool from plan stats.
    QueryPlanToolTotalCalls(String),
    /// Show cost of the most recent turn.
    QueryLastTurnCost,
    /// Show the last user message in history.
    QueryHistoryUserLast,
    /// Show total LLM fallback count for this session.
    QueryLlmFallbackCount,
    /// Show the byte length of the current system suffix.
    QuerySystemSuffixLen,
    /// Show the last assistant message text in history.
    QueryHistoryAssistantLast,
    /// Count session variables set.
    QuerySessionVarCount,
    /// List plan block type names.
    QueryPlanBlockList,
    /// Show diff (prev vs current) for a specific tool output.
    QueryToolOutputDiff(String),
    /// Show whether pause-now flag is active.
    QueryPauseNowShow,
    /// Show character length of current plan goal.
    QueryPlanGoalLen,
    /// Show whether the 60% context warning has fired.
    QueryContextWarnPct,
    /// Count ToolResults items in conversation history.
    QueryHistoryToolResultCount,
    /// Count pending reminders queued for injection.
    QueryPendingReminderCount,
    /// List all tool names tracked in plan call stats.
    QueryPlanToolNames,
    /// Show cost alert threshold and whether it has fired.
    QuerySessionCostAlert,
    /// Show the number of turn entries in the plan block_turns map for a block type.
    QueryPlanBlockTurnsLen(String),
    /// Show current turn index for this session.
    QueryHistoryTurnCount,
    /// Show total input tokens used this session.
    QuerySessionTokenIn,
    /// Show total output tokens used this session.
    QuerySessionTokenOut,
    /// List all verifier findings from last check.
    QueryVerifierFindingsList,
    /// Show whether D1 (deep context injection) was active in last assembly.
    QueryAssemblyD1,
    /// Show reminders dropped count from last assembly telemetry.
    QueryReminderDropped,
    /// Show top tools by error count from plan stats.
    QueryPlanToolErrTop,
    /// Show token budget used as a percentage of configured limit.
    QueryTokenBudgetPct,
    /// Show total count of all history items (user+assistant+tool results).
    QueryHistoryItemCount,
    /// Get a specific session env variable by name.
    QuerySessionEnvGet(String),
    /// Show whether token budget warn has fired this session.
    QueryTokenBudgetWarnFired,
    /// Show compaction status (happened flag + threshold).
    QueryCompactionStatus,
    /// Count total tool_uses entries across all assistant history items.
    QueryHistoryToolUseCount,
    /// Show whether auto-compact-on-stuck is enabled.
    QueryAutoCompactEnabled,
    /// List rule IDs from the verifier gate.
    QueryVerifierRulesList,
    /// Show block_turns for a specific plan block type (by name).
    QueryPlanToolBlockTurns(String),
    /// List names of all saved session snapshots.
    QuerySavedSnapshotList,
    /// Show average cost per turn (alias for session-cost-per-turn with turn breakdown).
    QueryTurnCostAvg,
    /// Show which tool triggered last plan error.
    QueryPlanErrorTool,
    /// Show session uptime in human-readable form.
    QuerySessionUptime,
    /// Show a preview of a specific history item by index.
    QueryHistoryPreviewAt(usize),
    /// Show consecutive error counts per tool from plan.
    QueryPlanConsecErrors,
    /// Show the full text of the last plan error.
    QueryPlanLastErrorText,
    /// Show total session cost (sum of all turn costs).
    QuerySessionCostTotal,
    /// Show configured token budget hard-stop percentage.
    QueryTokenBudgetHardPct,
    /// Search history for messages containing a substring.
    QueryHistorySearchText(String),
    /// Show which turns are included in the current plan window.
    QueryPlanWindowTurns,
    /// Show configured max tool calls per turn.
    QueryToolBudgetMax,
    /// Show last LLM call latency in milliseconds.
    QueryLlmMsLast,
    /// Show total character count of all sticky context entries.
    QueryStickyContextLen,
    /// Show tool uses at a specific history index.
    QueryHistoryToolUseAt(usize),
    /// Show input/output token ratio for this session.
    QuerySessionTokenRatio,
    /// Show character count of the current plan text.
    QueryPlanTextLen,
    /// Show bookmark details at a specific index.
    QueryBookmarkAt(usize),
    /// Show session note at a specific index.
    QuerySessionNoteAt(usize),
    /// Show turn label at a specific index.
    QueryTurnLabelAt(usize),
    /// Show previous output for a specific tool from output history.
    QueryToolOutputPrev(String),
    /// Show word count of the current plan goal.
    QueryPlanGoalWords,
    /// Show the second-to-last user message in history.
    QueryHistoryUserLast2,
    /// Show whether long-conversation digest was injected in last assembly.
    QueryAssemblyLongConv,
    /// Count how many turns a specific plan block type appears in.
    QueryPlanBlockTurnCount(String),
    /// Show the tool-results at a specific history index.
    QueryHistoryToolResultAt(usize),
    /// Show whether the verifier gate is enabled.
    QueryVerifierGateEnabled,
    /// List pending reminder bodies (up to 5).
    QueryPendingReminderList,
    /// Show the plan goal from a named snapshot.
    QuerySnapshotPlanGoal(String),
    /// Show count of error-result items in history.
    QueryHistoryErrorResultCount,
    /// Show configured token budget warn percentage.
    QueryTokenBudgetWarnPct,
    /// Show a 100-char preview of the current plan goal.
    QueryPlanGoalPreview,
    /// Show history length from a named snapshot.
    QuerySavedSnapshotAt(String),
    /// Show the most expensive turn from the cost log.
    QueryTurnCostMax,
    /// Show the cheapest turn from the cost log.
    QueryTurnCostMin,
    /// Show the plan blocks_recorded count as a proxy for plan age.
    QueryPlanAgeTurns,
    /// Show how many tool calls have been made this turn.
    QueryToolCallsThisTurn,
    /// Show the first tool use in conversation history.
    QueryHistoryFirstTool,
    /// Show the 5 most recently recorded plan block types.
    QueryPlanRecentBlocks,
    /// Show model context window size in tokens.
    QueryContextWindowSize,
    /// Show total byte size of all history text content.
    QueryHistoryTotalBytes,
    /// Show the first sticky context entry.
    QueryStickyContextTop,
    /// Show auto-tag rule at a specific index (pattern, tag).
    QueryAutoTagRuleAt(usize),
    /// Find bookmark(s) matching a label substring.
    QueryBookmarkByLabel(String),
    /// Show count of recorded turns for a specific plan block type.
    QueryPlanBlockAt(String),
    /// Show average LLM call latency in milliseconds across session.
    QueryLlmMsAvg,
    /// Show a 150-char preview of the current plan text.
    QueryPlanTextPreview,
    /// Show the rule ID of the first blocking verifier finding.
    QueryVerifierLastRule,
    /// Show error playbook entry at a specific index.
    QueryErrorPlaybookAt(usize),
    /// Show persistent reminder at a specific index.
    QueryPersistentReminderAt(usize),
    /// Show session variable entry at index.
    QuerySessionVarAt(usize),
    /// Show sum of all plan block counts.
    QueryPlanBlockCountTotal,
    /// Show prompt macro at a given sorted index.
    QueryPromptMacroAt(usize),
    /// Show warmup file path at a given index.
    QueryWarmupFileAt(usize),
    /// Count of turn labels defined in the session.
    QueryTurnLabelCount,
    /// Count of session notes stored.
    QuerySessionNoteCount,
    /// Count of last-tool-call signatures tracked for dedup.
    QueryToolSigCount,
    /// Show auto-commit message template.
    QueryAutoCommitTemplateShow,
    /// Count sticky context entries.
    QueryStickyCtxCount,
    /// Count history annotations.
    QueryHistoryAnnCount,
    /// Show total char count of all user messages in history.
    QueryHistoryUserLen,
    /// Show count of tools with non-zero consecutive errors in the plan.
    QueryPlanRecentErrors,
    /// List all auto-tag rules.
    QueryAutoTagRuleList,
    /// List all tools with non-zero error counts in the plan.
    QueryPlanToolErrList,
    /// List all session tags.
    QuerySessionTagList,
    /// Show total char count of all assistant text in history.
    QueryHistoryAssistantLen,
    /// Count of tools tracked in tool-output history.
    QueryToolOutputCountTotal,
    /// Total char count of all tool results in history.
    QueryHistoryToolResultLen,
    /// Count of total verifier findings in last verification.
    QueryVerifierFindingCount,
    /// Show overall tool ok-rate across all plan stats.
    QueryPlanOkRate,
    /// Show average session cost per turn (burn rate).
    QuerySessionCostBurn,
    /// Show ratio of user chars to assistant chars in history.
    QueryHistoryRatio,
    /// Show tool with highest ok count in plan stats.
    QueryPlanToolOkTop,
    /// Show average message length across all history items.
    QueryHistoryItemAvgLen,
    /// Show most recent session note.
    QuerySessionNoteLatest,
    /// Show tool with highest total block count in plan.
    QueryPlanBlockTop,
    /// Show most recently added bookmark.
    QueryBookmarkLatest,
    /// Show ratio of tool calls to user messages in history.
    QueryHistoryToolUseRate,
    /// Show tool with highest consecutive error count.
    QueryToolErrRateTop,
    /// Show session var with lexicographically last key.
    QuerySessionVarTop,
    /// Show the latest user message text from history.
    QueryHistoryUserLatest,
    /// Show ratio of error tool results to total tool results in history.
    QueryHistoryErrorRate,
    /// Show the first verifier rule ID and description.
    QueryVerifierRuleTop,
    /// List names of all saved snapshots.
    QuerySnapshotNameList,
    /// Show total tool calls (ok + err) across all plan stats.
    QueryPlanToolCallTotal,
    /// Show session uptime in hours.
    QuerySessionUptimeHrs,
    /// Count distinct back-and-forth exchanges in history.
    QueryHistoryTurnDepth,
    /// Show USD cost per token for this session.
    QueryCostPerToken,
    /// Show first sticky context entry preview.
    QueryStickyCtxPreview,
    /// List all tool names tracked in plan stats.
    QueryPlanToolList,
    /// List all session env variable keys.
    QueryEnvKeyList,
    /// List all tool names in tool-output history.
    QueryToolOutputKeyList,
    /// List all prompt macro keys.
    QueryMacroKeyList,
    /// Show session tag at a specific index.
    QuerySessionTagAt(usize),
    /// List all alias keys.
    QueryAliasKeyList,
    /// List all bookmark labels.
    QueryBookmarkLabelList,
    /// Show maximum wall-clock time across all turns.
    QueryTurnWallMax,
    /// Show minimum wall-clock time across all turns.
    QueryTurnWallMin,
    /// Preview the most recent tool result from history.
    QueryHistoryResultPreview,
    /// Count of warmup files configured.
    QueryWarmupFileCount,
    /// Count of auto-tag rules defined.
    QueryAutoTagRuleCount,
    /// Count of distinct tool names in plan block_counts.
    QueryPlanBlockListLen,
    /// Show average cost per turn from turn cost log.
    QuerySessionCostAvgTurn,
    /// Show remaining token budget (budget - used).
    QueryTokenBudgetRemaining,
    /// Show whether the plan has been modified (dirty).
    QueryPlanDirtyShow,
    /// Preview the most recent assistant text from history.
    QueryHistoryAssistantPreview,
    /// Show whether the plan has a goal set.
    QueryPlanGoalSet,
    /// Show first key=value pair in session env.
    QuerySessionEnvPreview,
    /// Show alias at a specific sorted index.
    QueryAliasAt(usize),
    /// Show total count of session vars.
    QuerySessionVarCountTotal,
    /// Show median (p50) wall-clock time across all turns.
    QueryTurnWallP50,
    /// Show whether last verification was blocked.
    QueryVerifierBlockedShow,
    /// Show error count for a specific tool in plan.
    QueryPlanToolErrAt(String),
    /// Show session intent if set.
    QuerySessionIntentPreview,
    /// Show turn-reminder-every setting (0 = off).
    QueryTurnReminderEveryShow,
    /// Show retry-on-error threshold, max, and current count.
    QueryRetryOnErrorShow,
    /// Show history annotation at a specific index.
    QueryHistoryAnnotationAt(usize),
    /// Show count of done vs total progress items.
    QueryProgressItemsDone,
    /// Show the next queued task (peek without removing).
    QueryTaskQueueNext,
    /// Show the focus_mode text if set.
    QueryFocusModeText,
    /// Show the scope guard pattern if set.
    QueryScopeGuardText,
    /// Show the agent persona if set.
    QueryAgentPersonaText,
    /// Show the request prefix if set.
    QueryRequestPrefixText,
    /// Show the request suffix if set.
    QueryRequestSuffixText,
    /// Show the smart-pause pattern if set.
    QuerySmartPausePat,
    /// Count of tool-deny entries.
    QueryToolDenyCount,
    /// Show auto-continue cooldown in ms.
    QueryCooldownMsShow,
    /// Count of history annotations.
    QueryHistoryAnnotCount,
    /// Show a specific progress item by index.
    QueryProgressItemAt(usize),
}

/// Style for the info column of a [`ChatLine::SplashRow`].
#[derive(Debug, Clone)]
pub enum SplashStyle {
    Brand,  // sky-300 BOLD    — "Aether" hero title
    Title,  // slate-200 bold  — version number
    Accent, // indigo-400      — model name
    Ok,     // green-400       — auto-edit perm
    Warn,   // amber-400       — bypass perm
    Dim,    // slate-500       — cwd / hints
}

#[derive(Debug, Clone)]
pub enum ChatLine {
    /// User message. Second field is Unix timestamp (0 = unknown, from loaded sessions).
    User(String, u64),
    /// Completed assistant message. Second = response wall-clock seconds, third = cost delta USD (0.0 = unknown).
    Assistant(String, f64, f64),
    AssistantPartial(String),
    SystemNote(String),
    /// Startup splash row: `logo` in brand-blue bold, `info` in `style`-determined colour.
    SplashRow { logo: String, info: String, style: SplashStyle },
}

#[derive(Debug, Clone)]
pub struct ToolEntry {
    pub name: String,
    pub summary: String,
    pub status: ToolStatus,
    /// Wall time from ToolStart to ToolDone (None while still Running).
    pub elapsed_ms: Option<u64>,
    /// Instant when this tool started (used to compute elapsed_ms).
    pub start: std::time::Instant,
}

#[derive(Debug, Clone)]
pub enum ToolStatus {
    Running,
    Ok(String),
    Err(String),
}

#[derive(Debug, Clone)]
pub struct FleetEntry {
    pub id: u64,
    pub description: String,
    pub status: FleetStatus,
    pub preview: Option<String>,
}

#[derive(Debug, Clone)]
pub enum FleetStatus {
    Running,
    Done,
    Cancelled,
    Error,
}

// ── UI state ──────────────────────────────────────────────────────────────────

pub struct UiState {
    pub model: String,
    pub session_id: String,
    pub perm_mode: String,
    pub cwd: String,
    /// Current git branch, if we're inside a git repo (None otherwise).
    pub git_branch: Option<String>,
    pub chat_lines: Vec<ChatLine>,
    pub tool_log: Vec<ToolEntry>,
    pub fleet: Vec<FleetEntry>,
    pub input_buffer: String,
    /// Byte offset of the insertion cursor within `input_buffer`.
    pub input_cursor: usize,
    pub status_running: bool,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub tokens_total: u64,
    pub cost_usd: f64,
    pub chat_scroll: u16,
    pub last_error: Option<String>,
    /// When the TUI session started (for elapsed-time display).
    pub session_start: std::time::Instant,
    /// Submitted message history for Up/Down recall.
    pub input_history: Vec<String>,
    /// Index into `input_history` while navigating (None = live buffer).
    pub history_idx: Option<usize>,
    /// True while the user hasn't manually scrolled up (auto-follow the tail).
    pub follow_tail: bool,
    /// Cycles through Tab-completions for slash commands.
    pub tab_cycle: usize,
    /// Instant when the first streaming delta arrived for the current response.
    pub stream_start: Option<std::time::Instant>,
    /// Tokens/second for the last completed response.
    pub last_tps: f64,
    /// Ring-buffer of the last 8 t/s readings for the sparkline in the hints bar.
    pub tps_history: Vec<f64>,
    /// Total tool ok/err counts for the side-panel title.
    pub tools_ok: u32,
    pub tools_err: u32,
    /// Character count of the in-progress response (for live streaming display).
    pub stream_chars: u32,
    /// Wallclock seconds when each User message was submitted (for /stats).
    pub msg_times_secs: Vec<u64>,
    /// Cost snapshot at each AssistantDone (cumulative USD, for per-message delta).
    pub msg_cost_snapshots: Vec<f64>,
    /// Response durations in seconds for each completed exchange.
    pub response_durations: Vec<f64>,
    /// Response start instant for current in-flight request.
    pub response_start: Option<std::time::Instant>,
    /// True after AssistantDone — take cost snapshot on next Usage event.
    pending_cost_snap: bool,
    /// Pinned note shown at top of chat — set by /pin command.
    pub pinned_note: Option<String>,
    /// When true, the side panel (tools/fleet) is hidden — F2 to toggle.
    pub side_panel_hidden: bool,
    /// Non-None while user is in reverse-i-search mode (Ctrl+R).
    /// Contains the current search query string.
    pub history_search: Option<String>,
    /// Saved input buffer before entering search mode (restored on Escape).
    pub history_presearch_buf: String,
    /// Count of assistant messages received while the user was manually scrolled up.
    /// Shown as "↓ N new" in the hints bar. Reset when the user returns to tail.
    pub new_msgs_while_scrolled: u32,
    /// Instant when the last AssistantDone arrived — used to flash input border for ~1.2s.
    pub response_done_at: Option<std::time::Instant>,
    /// Instant when the current request was submitted — cleared on first delta received.
    pub waiting_since: Option<std::time::Instant>,
    /// Named scroll-position bookmarks: (name, scroll_line).
    pub bookmarks: Vec<(String, u16)>,
    /// When the session was last auto-saved.
    pub last_autosave: Option<std::time::Instant>,
    /// When true, show [N] exchange numbers before user messages.
    pub show_msg_numbers: bool,
    /// When true, the next keypress is interpreted as the Ctrl+X chord target.
    pub ctrl_x_pending: bool,
    /// Session-local command aliases: (alias_prefix, expansion).
    pub aliases: Vec<(String, String)>,
    /// When true, chat pane renders without word-wrap (useful for wide code).
    pub wrap_disabled: bool,
    /// When true, full timestamps are shown on each message header.
    pub show_timestamps: bool,
    /// Auto-extracted from the first user message (first 5 words, up to 40 chars).
    /// Shown in the header bar so each session feels named.
    pub session_title: Option<String>,
    /// When set, this term is highlighted in cyan+bold within rendered chat messages.
    /// Set by /search, cleared on /clear or next user message.
    pub search_highlight: Option<String>,
    /// One-level undo buffer for the input box: (saved_text, saved_cursor).
    pub input_undo: Option<(String, usize)>,
    /// When true, assistant messages render as plain text (no markdown).
    /// Toggled by /format command.
    pub raw_mode: bool,
    /// When true, code blocks show line numbers on the left margin.
    /// Toggled by /linenums command.
    pub show_line_numbers: bool,
    /// Ghost-text suggestion shown in dim after the cursor (first history match).
    /// Populated by the event loop; accepted with Right/End when cursor is at end.
    pub input_ghost: Option<String>,
    /// Active colour-theme index (0=sky, 1=emerald, 2=rose).
    /// Affects brand + accent colours. Cycled by /theme command.
    pub theme: u8,
    /// When true, hints bar is hidden — maximises chat height (zen/focus mode).
    /// Toggled by /focus command or Ctrl+F.
    pub focus_mode: bool,
    /// When set, this string is prepended to every AI request (silent system prefix).
    /// Shown as a badge in the input title; cleared with /pin-cmd clear.
    pub prompt_prefix: Option<String>,
    /// Word and char count of the last completed AI response (for tools panel badge).
    pub last_response_words: u32,
    pub last_response_chars: u32,
    /// Persistent file-context list: paths added with /add whose contents
    /// are injected at the top of every AI request.
    pub context_files: Vec<String>,
    /// Ring-buffer of the last 50 streaming output lines from the running
    /// Bash tool. Cleared on ToolDone. Shown in the tool panel while running.
    pub tool_stream_lines: Vec<String>,
    /// When set, a new AI call is blocked if `cost_usd >= cost_limit_usd`.
    /// Cleared with `/set-cost-limit off`.
    pub cost_limit_usd: Option<f64>,
    /// When true, `git diff --stat HEAD` is injected as a SystemNote after
    /// every AI turn that invoked at least one tool. Toggled by /auto-diff.
    pub auto_diff_enabled: bool,
    /// Env vars set in this session via /setenv (key, value pairs).
    /// Mirrored here for display by /env-list; authoritative copy is process env.
    pub session_env_vars: Vec<(String, String)>,
    /// Persistent session goal set by /goal. When Some, prepended to every
    /// AI request as `[GOAL]: {text}` so the AI always knows the objective.
    pub session_goal: Option<String>,
}

impl UiState {
    pub fn new(model: String, session_id: String, perm_mode: String, cwd: String) -> Self {
        let model_display = model_display_name(&model);
        let version = env!("CARGO_PKG_VERSION");
        let perm = perm_label(&perm_mode);
        let perm_style = match perm {
            "bypass"    => SplashStyle::Warn,
            "auto-edit" => SplashStyle::Ok,
            _           => SplashStyle::Accent,
        };
        // Startup splash: 13-row SOLID filled diamond.
        // Diamond grows +4 ◆ per row then shrinks; all rows padded to 28 chars.
        // Info appears on rows 2–6 (right of the logo column).
        //
        //   Row 1 (cap):  "           ◆◆           "  — no info
        //   Row 2:        "         ◆◆◆◆◆◆         "  — "Aether"   (Brand)
        //   Row 3:        "       ◆◆◆◆◆◆◆◆◆◆       "  — "v{version}" (Title)
        //   Row 4:        "     ◆◆◆◆◆◆◆◆◆◆◆◆◆◆     "  — model     (Accent)
        //   Row 5:        "   ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆   "  — perm mode  (Warn/Ok/Dim)
        //   Row 6:        "  ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆  "  — cwd       (Dim)
        //   Row 7 (wide): " ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆ "  — no info
        //   Rows 8–13:    mirror rows 6–1            — no info
        let chat_lines = vec![
            ChatLine::SplashRow { logo: "           ◆◆           ".to_string(), info: String::new(),                    style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "         ◆◆◆◆◆◆         ".to_string(), info: "Aether".to_string(),             style: SplashStyle::Brand },
            ChatLine::SplashRow { logo: "       ◆◆◆◆◆◆◆◆◆◆       ".to_string(), info: format!("v{version}"),           style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "     ◆◆◆◆◆◆◆◆◆◆◆◆◆◆     ".to_string(), info: model_display.clone(),           style: SplashStyle::Accent },
            ChatLine::SplashRow { logo: "   ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆   ".to_string(), info: format!("{perm} mode"),          style: perm_style },
            ChatLine::SplashRow { logo: "  ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆  ".to_string(), info: cwd.clone(),                    style: SplashStyle::Dim },
            ChatLine::SplashRow { logo: " ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆ ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "  ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆  ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "   ◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆◆   ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "     ◆◆◆◆◆◆◆◆◆◆◆◆◆◆     ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "       ◆◆◆◆◆◆◆◆◆◆       ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "         ◆◆◆◆◆◆         ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: "           ◆◆           ".to_string(), info: String::new(),                  style: SplashStyle::Title },
            ChatLine::SplashRow { logo: String::new(), info: "/help  ·  /help power  ·  F7 theme  ·  Ctrl+G find  ·  /model switch  ·  /cost  ·  /version".to_string(), style: SplashStyle::Dim },
            ChatLine::SplashRow { logo: String::new(), info: "150+ commands — /dashboard  /scan  /secrets  /jwt-decode  /k8s  /docker  /git-log  /todo-scan  /brainstorm  /json".to_string(), style: SplashStyle::Ok },
            {
                let tips: &[&str] = &[
                    "Tip: /copy all — copies the full conversation to clipboard",
                    "Tip: Ctrl+S — quick-save chat to /tmp as Markdown",
                    "Tip: /outline — see a TOC of headings in AI responses",
                    "Tip: F6 — focus mode hides the hints bar for more chat space",
                    "Tip: /extract — writes all code blocks to /tmp files by language",
                    "Tip: /speed — sparkline of token throughput across responses",
                    "Tip: /todo + <task> — built-in todo tracker with progress bar",
                    "Tip: Ctrl+G — find text using your current input buffer as pattern",
                    "Tip: /bm — bookmark the current position; /bookmarks to list",
                    "Tip: Alt+. — insert the last word from the AI response into input",
                    "Tip: /wc — word count + reading time + sentence stats",
                    "Tip: /replay — replay the last session step by step",
                    "Tip: /pin <note> — pin a sticky note visible in the tools panel",
                    "Tip: /goto N — jump to the Nth user/AI exchange",
                    "Tip: Ctrl+B — wrap the word at cursor in **bold** markdown",
                    "Tip: /ask-code <file> [q] — inject a file and ask AI about it",
                    "Tip: /grep-code <pattern> — regex search across all source files",
                    "Tip: /secrets [dir] — scan for hardcoded credentials (14 patterns)",
                    "Tip: /pr-review staged — AI reviews your staged git changes",
                    "Tip: /gen-tests <file> — AI generates full test suite for a file",
                    "Tip: /heatmap — visual git change-frequency map of your files",
                    "Tip: /explain-error — AI explains the last error + how to fix it",
                    "Tip: /translate-code <file> <lang> — port code to another language",
                    "Tip: /arch-review — full architecture audit: risks + roadmap + grade",
                    "Tip: /flow <file> — static call-flow outline for any source file",
                    "Tip: /metrics — LoC breakdown by language with percentage bar chart",
                    "Tip: /changelog — AI generates CHANGELOG from your recent commits",
                    "Tip: /status — project dashboard: git + tests + env + session cost",
                    "Tip: /bench — smart benchmark runner (cargo/jest/go/pytest)",
                    "Tip: /format-code — auto-format with the right tool for any language",
                ];
                let tip_idx = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as usize / 86400 % tips.len();
                ChatLine::SplashRow { logo: String::new(), info: tips[tip_idx].to_string(), style: SplashStyle::Accent }
            },
        ];
        Self {
            model,
            session_id,
            perm_mode,
            cwd,
            git_branch: None,
            chat_lines,
            tool_log: Vec::new(),
            fleet: Vec::new(),
            input_buffer: String::new(),
            input_cursor: 0,
            status_running: false,
            tokens_in: 0,
            tokens_out: 0,
            tokens_total: 0,
            cost_usd: 0.0,
            chat_scroll: 0,
            last_error: None,
            session_start: std::time::Instant::now(),
            input_history: Vec::new(),
            history_idx: None,
            follow_tail: true,
            tab_cycle: 0,
            stream_start: None,
            last_tps: 0.0,
            tps_history: Vec::new(),
            tools_ok: 0,
            tools_err: 0,
            stream_chars: 0,
            msg_times_secs: Vec::new(),
            msg_cost_snapshots: Vec::new(),
            response_durations: Vec::new(),
            response_start: None,
            pending_cost_snap: false,
            pinned_note: None,
            side_panel_hidden: false,
            history_search: None,
            history_presearch_buf: String::new(),
            new_msgs_while_scrolled: 0,
            response_done_at: None,
            waiting_since: None,
            bookmarks: Vec::new(),
            last_autosave: None,
            show_msg_numbers: false,
            ctrl_x_pending: false,
            aliases: Vec::new(),
            wrap_disabled: false,
            show_timestamps: false,
            session_title: None,
            search_highlight: None,
            input_undo: None,
            raw_mode: false,
            show_line_numbers: false,
            input_ghost: None,
            theme: 0,
            focus_mode: false,
            prompt_prefix: None,
            last_response_words: 0,
            last_response_chars: 0,
            context_files: Vec::new(),
            tool_stream_lines: Vec::new(),
            cost_limit_usd: None,
            auto_diff_enabled: false,
            session_env_vars: Vec::new(),
            session_goal: None,
        }
    }

    pub fn apply(&mut self, ev: UiEvent) {
        match ev {
            UiEvent::AssistantDelta(d) => {
                if self.stream_start.is_none() {
                    self.stream_start = Some(std::time::Instant::now());
                    self.waiting_since = None; // first token received — TTFT elapsed
                }
                if self.response_start.is_none() {
                    self.response_start = Some(std::time::Instant::now());
                }
                self.stream_chars += d.chars().count() as u32;
                match self.chat_lines.last_mut() {
                    Some(ChatLine::AssistantPartial(s)) => s.push_str(&d),
                    _ => self.chat_lines.push(ChatLine::AssistantPartial(d)),
                }
                // follow_tail scrolling is handled in draw_frame() using real line counts
            }
            UiEvent::AssistantDone(final_text) => {
                // Compute tokens/second from stream duration and output tokens.
                // Use max(0.01) floor so very fast responses still get a t/s reading.
                if let Some(t0) = self.stream_start.take() {
                    let secs = t0.elapsed().as_secs_f64().max(0.01);
                    if self.tokens_out > 0 {
                        self.last_tps = self.tokens_out as f64 / secs;
                        self.tps_history.push(self.last_tps);
                        if self.tps_history.len() > 8 {
                            self.tps_history.remove(0);
                        }
                    }
                }
                self.stream_chars = 0;
                // Record last response size for tools panel badge
                self.last_response_words = final_text.split_whitespace().count() as u32;
                self.last_response_chars = final_text.chars().count() as u32;
                // Record response duration (used both for /stats and per-message badge)
                let response_dur = self.response_start.take().map(|t0| {
                    let d = t0.elapsed().as_secs_f64();
                    self.response_durations.push(d);
                    d
                }).unwrap_or(0.0);
                // Schedule cost snapshot on next Usage event (which arrives after AssistantDone)
                self.pending_cost_snap = true;
                if matches!(self.chat_lines.last(), Some(ChatLine::AssistantPartial(_))) {
                    if let Some(last) = self.chat_lines.last_mut() {
                        *last = ChatLine::Assistant(final_text, response_dur, 0.0);
                    }
                } else {
                    self.chat_lines.push(ChatLine::Assistant(final_text, response_dur, 0.0));
                }
                // Track new messages while user is scrolled up
                if !self.follow_tail {
                    self.new_msgs_while_scrolled += 1;
                }
                // Stamp completion time so draw_frame can flash the input border
                self.response_done_at = Some(std::time::Instant::now());
                // Auto-bookmark long responses (> 400 words) so they're easy to find
                if self.last_response_words > 400 {
                    let idx = self.chat_lines.len().saturating_sub(1) as u16;
                    let bm_name = format!("long-{}", self.bookmarks.len() + 1);
                    self.bookmarks.push((bm_name, idx));
                }
            }
            UiEvent::ToolStart { name, summary } => {
                self.tool_log.push(ToolEntry {
                    name,
                    summary,
                    status: ToolStatus::Running,
                    elapsed_ms: None,
                    start: std::time::Instant::now(),
                });
            }
            UiEvent::ToolDone {
                name,
                summary: _,
                is_error,
                preview,
            } => {
                self.tool_stream_lines.clear();
                for entry in self.tool_log.iter_mut().rev() {
                    if entry.name == name && matches!(entry.status, ToolStatus::Running) {
                        entry.elapsed_ms = Some(entry.start.elapsed().as_millis() as u64);
                        if is_error {
                            entry.status = ToolStatus::Err(preview.clone());
                            self.tools_err += 1;
                        } else {
                            entry.status = ToolStatus::Ok(preview.clone());
                            self.tools_ok += 1;
                        }
                        break;
                    }
                }
            }
            UiEvent::ToolOutputLine { id: _, line } => {
                self.tool_stream_lines.push(line);
                if self.tool_stream_lines.len() > 50 {
                    self.tool_stream_lines.remove(0);
                }
                // Mirror latest line into the running tool entry's summary so
                // the tool panel shows live progress without render changes.
                for entry in self.tool_log.iter_mut().rev() {
                    if matches!(entry.status, ToolStatus::Running) {
                        let last = self.tool_stream_lines.last().map(|s| s.as_str()).unwrap_or("");
                        entry.summary = last.chars().take(80).collect();
                        break;
                    }
                }
            }
            UiEvent::Usage {
                input,
                output,
                total,
                cost_usd,
            } => {
                self.tokens_in = input;
                self.tokens_out = output;
                self.tokens_total = total;
                self.cost_usd = cost_usd;
                // Snapshot cost after AssistantDone (Usage arrives last in the event sequence)
                if self.pending_cost_snap {
                    self.pending_cost_snap = false;
                    let prev = self.msg_cost_snapshots.last().copied().unwrap_or(0.0);
                    let delta = (cost_usd - prev).max(0.0);
                    self.msg_cost_snapshots.push(cost_usd);
                    // Backfill cost_delta into the last completed Assistant message
                    for line in self.chat_lines.iter_mut().rev() {
                        if let ChatLine::Assistant(_, _, ref mut cost_field) = line {
                            *cost_field = delta;
                            break;
                        }
                    }
                }
            }
            UiEvent::Error(e) => {
                self.last_error = Some(e.clone());
                self.chat_lines
                    .push(ChatLine::SystemNote(format!("⚠  {}", clean_error_message(&e))));
                self.status_running = false;
            }
            UiEvent::AwaitUser => {
                self.status_running = false;
            }
            UiEvent::SystemNote(note) => {
                self.chat_lines.push(ChatLine::SystemNote(note));
            }
            UiEvent::ToolList(tools) => {
                if tools.is_empty() {
                    self.chat_lines.push(ChatLine::SystemNote("No matching tools.".into()));
                } else {
                    let mut msg = format!("Registered tools ({}):\n", tools.len());
                    msg.push_str("─────────────────────────────────────────────\n");
                    for (name, desc) in &tools {
                        msg.push_str(&format!("  {name}\n    {desc}\n"));
                    }
                    self.chat_lines.push(ChatLine::SystemNote(msg));
                }
            }
            UiEvent::ToolSchemaResult { name, description, schema } => {
                let msg = format!(
                    "Tool: {name}\n  {description}\n\n  Input schema:\n  {schema}",
                    schema = schema.replace('\n', "\n  ")
                );
                self.chat_lines.push(ChatLine::SystemNote(msg));
            }
        }
    }
}

// ── terminal lifecycle ────────────────────────────────────────────────────────

pub fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    use crossterm::{event::EnableBracketedPaste, execute, terminal};
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        terminal::EnterAlternateScreen,
        EnableBracketedPaste,
        crossterm::cursor::Hide
    )?;
    Terminal::new(CrosstermBackend::new(stdout))
}

pub fn teardown_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
    use crossterm::{event::DisableBracketedPaste, execute, terminal};
    terminal::disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableBracketedPaste,
        terminal::LeaveAlternateScreen,
        crossterm::cursor::Show
    )?;
    terminal.show_cursor()?;
    Ok(())
}

/// RAII guard: restores the terminal even on panic.
pub struct TerminalGuard {
    terminal: Option<Terminal<CrosstermBackend<Stdout>>>,
}

impl TerminalGuard {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            terminal: Some(setup_terminal()?),
        })
    }
    pub fn terminal(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        self.terminal.as_mut().expect("terminal already dropped")
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if let Some(mut t) = self.terminal.take() {
            let _ = teardown_terminal(&mut t);
        }
    }
}

// ── frame renderer ────────────────────────────────────────────────────────────

pub fn draw_frame(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &UiState,
) -> io::Result<()> {
    // Build enriched spinner string: plain frame when idle, live stats during streaming.
    // Uses owned String so we don't need Box::leak (the trailing format! creates Cow::Owned).
    let spin_owned: String = {
        let base = spinner_frame();
        if state.status_running && state.stream_chars == 0 {
            // Connecting phase (awaiting first token): slow pulse dots
            let ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let dot_count = ((ms / 600) % 4) as usize;
            let dots: String = "●".repeat(dot_count + 1)
                + &"○".repeat(3usize.saturating_sub(dot_count));
            format!("{dots} connecting")
        } else if state.status_running && state.stream_chars > 0 {
            let words = (state.stream_chars / 5).max(1);
            let tps_str = if state.last_tps > 1.0 {
                format!(" · {:.0}t/s", state.last_tps)
            } else {
                String::new()
            };
            format!("{base} ~{words}w{tps_str}")
        } else {
            base.to_string()
        }
    };
    let spin = spin_owned.as_str();

    terminal.draw(|f| {
        // Theme accent override — only brand glyph + input cursor use t_brand.
        // Rest of the palette stays constant so the chat is readable across themes.
        let t_brand: Color = match state.theme {
            1 => Color::Rgb(52, 211, 153),  // emerald-400
            2 => Color::Rgb(251, 113, 133), // rose-400
            _ => C_BRAND,                   // default sky-300
        };
        let t_accent: Color = match state.theme {
            1 => Color::Rgb(167, 243, 208), // emerald-200
            2 => Color::Rgb(253, 164, 175), // rose-300
            _ => C_ASST_PFX,               // default indigo-400
        };

        // Precompute message count (used in side panel + hints bar)
        let msg_count = state.chat_lines.iter()
            .filter(|cl| matches!(cl, ChatLine::User(_, _)))
            .count();

        // Context window usage — computed once, reused in input border + hints bar
        let ctx_max = model_context_window(&state.model);
        let ctx_pct = if ctx_max > 0 && state.tokens_total > 0 {
            (state.tokens_total as f64 / ctx_max as f64).min(1.0)
        } else {
            0.0
        };

        // Dynamic input height: 1 border + content lines, clamped 2..=8
        let input_content_lines = state.input_buffer.lines().count().max(1);
        let input_height = (input_content_lines + 1).min(8) as u16;

        // Outer vertical split: header | main | input | hints
        // hints bar is collapsed to 0 in focus mode to maximise chat height.
        let hints_height: u16 = if state.focus_mode { 0 } else { 1 };
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),            // header bar
                Constraint::Min(5),               // chat + tools
                Constraint::Length(input_height), // input (dynamic)
                Constraint::Length(hints_height), // hints bar (0 in focus mode)
            ])
            .split(f.area());

        // ── 1. Header bar ─────────────────────────────────────────────
        {
            let model_display = model_display_name(&state.model);
            let cwd = shorten_path(&state.cwd, 36);
            let perm = perm_label(&state.perm_mode);
            let (perm_hdr_color, perm_sym) = match perm {
                "bypass"    => (C_WARN, "⚡"),
                "auto-edit" => (C_OK,   "✓"),
                _           => (C_DIM,  "◆"),
            };

            let mut hdr_spans: Vec<Span<'static>> = vec![
                Span::raw("  "),
                Span::styled(
                    "◆ Aether",
                    Style::default()
                        .fg(t_brand)
                        .bg(C_HDR_BG)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("  ·  ", Style::default().fg(C_DIM).bg(C_HDR_BG)),
                Span::styled(
                    // Model family icon: ⊕ Opus · ◈ Sonnet · ◇ Haiku
                    if model_display.contains("opus") { "⊕ " }
                    else if model_display.contains("haiku") { "◇ " }
                    else { "◈ " },
                    Style::default().fg(
                        if model_display.contains("opus") { C_WARN }
                        else if model_display.contains("haiku") { C_OK }
                        else { t_brand }
                    ).bg(C_HDR_BG),
                ),
                Span::styled(
                    model_display.clone(),
                    // Opus = amber, Sonnet = brand, Haiku = green
                    Style::default().fg(
                        if model_display.contains("opus") { C_WARN }
                        else if model_display.contains("haiku") { C_OK }
                        else { t_brand }
                    ).bg(C_HDR_BG).add_modifier(Modifier::BOLD),
                ),
                Span::styled("  ·  ", Style::default().fg(C_DIM).bg(C_HDR_BG)),
                Span::styled(cwd, Style::default().fg(C_DIM).bg(C_HDR_BG)),
            ];
            if let Some(branch) = &state.git_branch {
                hdr_spans.push(Span::styled("  ", Style::default().bg(C_HDR_BG)));
                hdr_spans.push(Span::styled(
                    format!("⎇ {branch}"),
                    Style::default().fg(t_accent).bg(C_HDR_BG),
                ));
            }
            // Session title (auto-extracted from first user message)
            if let Some(ref title) = state.session_title {
                hdr_spans.push(Span::styled("  ·  ", Style::default().fg(C_DIM).bg(C_HDR_BG)));
                hdr_spans.push(Span::styled(
                    title.clone(),
                    Style::default().fg(C_BODY).bg(C_HDR_BG).add_modifier(Modifier::ITALIC),
                ));
            }
            // Wall clock HH:MM + session uptime +Nm/+Hh
            let wall_clock = {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let h = (ts % 86400) / 3600;
                let m = (ts % 3600) / 60;
                format!("{:02}:{:02}", h, m)
            };
            let uptime_badge = {
                let secs = state.session_start.elapsed().as_secs();
                if secs < 60 {
                    format!("+{secs}s")
                } else if secs < 3600 {
                    format!("+{}m", secs / 60)
                } else {
                    format!("+{}h{}m", secs / 3600, (secs % 3600) / 60)
                }
            };
            // Exchange counter badge (only when conversation has started)
            let exchange_count = state.chat_lines.iter()
                .filter(|cl| matches!(cl, ChatLine::User(_, _)))
                .count();
            if exchange_count > 0 {
                hdr_spans.push(Span::styled("  ·  ", Style::default().fg(C_DIM).bg(C_HDR_BG)));
                hdr_spans.push(Span::styled(
                    format!("{exchange_count}↵"),
                    Style::default().fg(C_DIM).bg(C_HDR_BG),
                ));
            }
            // Focus mode indicator
            if state.focus_mode {
                hdr_spans.push(Span::styled("  ·  ", Style::default().fg(C_DIM).bg(C_HDR_BG)));
                hdr_spans.push(Span::styled(
                    "[focus]",
                    Style::default().fg(t_accent).bg(C_HDR_BG),
                ));
            }
            hdr_spans.extend([
                Span::styled("  ·  ", Style::default().fg(C_DIM).bg(C_HDR_BG)),
                Span::styled(wall_clock, Style::default().fg(C_DIM).bg(C_HDR_BG)),
                Span::raw(" "),
                Span::styled(uptime_badge, Style::default().fg(Color::Rgb(51, 65, 85)).bg(C_HDR_BG)),
                Span::styled("  ·  ", Style::default().fg(C_DIM).bg(C_HDR_BG)),
                Span::styled(
                    format!("{perm_sym} {perm}"),
                    Style::default().fg(perm_hdr_color).bg(C_HDR_BG),
                ),
            ]);
            let hdr = Line::from(hdr_spans);
            f.render_widget(
                Paragraph::new(hdr).style(Style::default().bg(C_HDR_BG)),
                outer[0],
            );
        }

        // ── 2. Main area: chat + side panel ─────────────────────────────
        // Side panel shows Tools when active, cheat-sheet when in convo but idle,
        // or nothing (100% chat) on the pre-convo splash screen.
        let has_tools = !state.tool_log.is_empty() || !state.fleet.is_empty();
        let has_convo_for_layout = state.chat_lines.iter().any(|cl| {
            matches!(cl, ChatLine::User(_, _) | ChatLine::Assistant(_, _, _) | ChatLine::AssistantPartial(_))
        });
        let has_side = (has_tools || has_convo_for_layout) && !state.side_panel_hidden;
        let main = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(if has_side {
                vec![Constraint::Percentage(70), Constraint::Percentage(30)]
            } else {
                vec![Constraint::Percentage(100)]
            })
            .split(outer[1]);

        // Chat — no border, clean message flow with prefix glyphs
        {
            // Once a real conversation starts, hide the splash card (CC behaviour).
            let has_convo = state.chat_lines.iter().any(|cl| {
                matches!(
                    cl,
                    ChatLine::User(_, _) | ChatLine::Assistant(_, _, _) | ChatLine::AssistantPartial(_)
                )
            });

            // Pinned note: rendered as a sticky strip at the very top of the chat widget.
            let pin_lines: Vec<Line<'static>> = if let Some(note) = &state.pinned_note {
                let mut pl = vec![
                    Line::from(Span::styled(
                        format!("  ★  {}", note),
                        Style::default().fg(C_WARN).add_modifier(Modifier::BOLD),
                    )),
                    Line::from(Span::styled(
                        "  ─────────────────────────────",
                        Style::default().fg(C_DIM),
                    )),
                ];
                pl.push(Line::from(""));
                pl
            } else {
                vec![]
            };

            let total = state.chat_lines.len();
            let mut user_msg_counter: u32 = 0;
            let mut chat: Vec<Line> = state
                .chat_lines
                .iter()
                .enumerate()
                .flat_map(|(i, cl)| {
                    // Hide splash rows once conversation begins
                    if has_convo && matches!(cl, ChatLine::SplashRow { .. }) {
                        return vec![];
                    }
                    // Show spinner after the last in-flight partial only
                    let trail_spin = i + 1 == total
                        && state.status_running
                        && matches!(cl, ChatLine::AssistantPartial(_));
                    // Exchange number for message numbering mode
                    let msg_num = if state.show_msg_numbers && matches!(cl, ChatLine::User(_, _)) {
                        user_msg_counter += 1;
                        user_msg_counter
                    } else {
                        0
                    };
                    chat_line_to_lines(cl, trail_spin, spin, state.show_timestamps, state.search_highlight.as_deref(), state.raw_mode, state.show_line_numbers, msg_num)
                })
                .collect();

            // Prepend the pinned note strip
            let mut chat = {
                let mut v = pin_lines;
                v.extend(chat);
                v
            };

            // When running but no partial response yet, show a "thinking" line in chat.
            if state.status_running
                && !matches!(state.chat_lines.last(), Some(ChatLine::AssistantPartial(_)))
            {
                let wait_timer = if let Some(t0) = state.stream_start {
                    let secs = t0.elapsed().as_secs_f64();
                    if secs >= 0.5 { format!("  ⏱{:.1}s", secs) } else { String::new() }
                } else {
                    String::new()
                };
                chat.push(Line::from(vec![
                    Span::styled(
                        "  ◆  ",
                        Style::default().fg(C_ASST_PFX).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{spin}  thinking…{wait_timer}"),
                        Style::default().fg(C_DIM),
                    ),
                ]));
            }

            // Compute scroll: when follow_tail is set, scroll so the last line is visible.
            // We know how many rendered lines there are and the viewport height.
            let viewport_h = main[0].height as usize;
            let effective_scroll = if state.follow_tail {
                chat.len().saturating_sub(viewport_h) as u16
            } else {
                state.chat_scroll
            };

            let chat_para = {
                let p = Paragraph::new(chat.clone()).scroll((effective_scroll, 0));
                if state.wrap_disabled { p } else { p.wrap(Wrap { trim: false }) }
            };
            f.render_widget(chat_para, main[0]);

            // Vertical scrollbar on the right edge of the chat pane.
            let total_chat_lines = chat.len();
            if total_chat_lines > viewport_h {
                let scroll_range = total_chat_lines.saturating_sub(viewport_h);
                let mut sb_state = ScrollbarState::new(scroll_range)
                    .position(effective_scroll as usize);
                f.render_stateful_widget(
                    Scrollbar::new(ScrollbarOrientation::VerticalRight)
                        .begin_symbol(None)
                        .end_symbol(None)
                        .track_symbol(Some("│"))
                        .thumb_symbol("█"),
                    main[0],
                    &mut sb_state,
                );
            }

            // Scroll-back indicator: when user has scrolled up, show lines-below count.
            if !state.follow_tail {
                let lines_below = chat.len()
                    .saturating_sub(effective_scroll as usize + viewport_h);
                if lines_below > 0 {
                    let label = format!("  ↓  {} more below  (End to resume tail)  ", lines_below);
                    let ind_rect = ratatui::layout::Rect {
                        x: main[0].x,
                        y: main[0].y + main[0].height.saturating_sub(1),
                        width: main[0].width,
                        height: 1,
                    };
                    f.render_widget(
                        Paragraph::new(Line::from(Span::styled(
                            label,
                            Style::default().fg(C_HDR_BG).bg(C_WARN),
                        ))),
                        ind_rect,
                    );
                }
            }
        }

        // Side panel: tools+fleet when active, keyboard cheat-sheet when idle.
        if has_side {
            let border_style = Style::default().fg(C_BORDER);
            let title_style = Style::default().fg(C_DIM).add_modifier(Modifier::BOLD);

            // When no tool activity, render session stats + keyboard cheat sheet.
            if !has_tools {
                // Session stats summary (shown when conversation is active)
                let stats_row = if msg_count > 0 {
                    let msg_label = format!("  {} msg{}", msg_count, if msg_count == 1 { "" } else { "s" });
                    let cost_part = if state.cost_usd > 0.0 { format!("  ·  ${:.4}", state.cost_usd) } else { String::new() };
                    let dur_part = if !state.response_durations.is_empty() {
                        let avg = state.response_durations.iter().sum::<f64>() / state.response_durations.len() as f64;
                        format!("  ·  {:.1}s avg", avg)
                    } else { String::new() };
                    let tps_part = if state.last_tps > 0.5 { format!("  ·  {:.0}t/s", state.last_tps) } else { String::new() };
                    Some(Line::from(Span::styled(
                        format!("{msg_label}{cost_part}{dur_part}{tps_part}"),
                        Style::default().fg(C_DIM),
                    )))
                } else { None };

                let mut km_lines: Vec<Line<'static>> = Vec::new();
                if let Some(sr) = stats_row {
                    km_lines.push(sr);
                    km_lines.push(Line::from(Span::styled("  ─────────────────────────", Style::default().fg(Color::Rgb(30, 41, 59)))));
                    km_lines.push(Line::from(""));
                }
                let kh = |key: &'static str, desc: &'static str| -> Line<'static> {
                    Line::from(vec![
                        Span::styled(format!("  {key} "), Style::default().fg(C_DIM)),
                        Span::styled(desc, Style::default().fg(C_BODY)),
                    ])
                };
                km_lines.extend(vec![
                    Line::from(Span::styled("  Input", Style::default().fg(C_BRAND).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    kh("↵", "send message"),
                    kh("⇧↵", "newline"),
                    kh("↑↓", "history recall"),
                    kh("^R", "reverse-i-search"),
                    kh("^Y", "yank last response"),
                    kh("⇥", "tab complete /cmd"),
                    kh("^`", "insert code fence"),
                    kh("^A/E", "start / end of line"),
                    kh("^W", "delete word back"),
                    kh("^K/U", "kill to end / start"),
                    kh("^C", "cancel / clear / quit"),
                    Line::from(""),
                    Line::from(Span::styled("  Navigation", Style::default().fg(C_BRAND).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    kh("Pg↑↓", "scroll chat"),
                    kh("End", "jump to latest"),
                    kh("^H", "jump to oldest"),
                    kh("F2", "toggle side panel"),
                    kh("F3", "toggle timestamps"),
                    kh("F4", "open notes"),
                    kh("^L", "clear display"),
                    kh("^N", "new session"),
                    kh("^P", "pin last response"),
                    Line::from(""),
                    Line::from(Span::styled("  Commands", Style::default().fg(C_BRAND).add_modifier(Modifier::BOLD))),
                    Line::from(""),
                    kh("/help", "all commands"),
                    kh("/search", "<term>"),
                    kh("/retry", "resend last msg"),
                    kh("/copy", "clipboard copy"),
                    kh("/cost", "usage stats"),
                    kh("/compact", "[N] compress"),
                    kh("/doctor", "health check"),
                    kh("/sessions", "list sessions"),
                    kh("/export", "save transcript"),
                    kh("/note", "<text> save note"),
                    kh("/model", "<name>"),
                    kh("/clear", "clear display"),
                ]);
                f.render_widget(
                    Paragraph::new(km_lines)
                        .block(
                            Block::default()
                                .borders(Borders::LEFT)
                                .border_style(Style::default().fg(Color::Rgb(30, 41, 59))),
                        )
                        .wrap(Wrap { trim: false }),
                    main[1],
                );
            } else {

            let (tools_area, fleet_area) = if !state.fleet.is_empty() {
                let split = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(main[1]);
                (split[0], Some(split[1]))
            } else {
                (main[1], None)
            };

            const MAX_TOOL_SHOW: usize = 15;
            let total_tools = state.tool_log.len();
            let skip = total_tools.saturating_sub(MAX_TOOL_SHOW);
            let mut tool_lines: Vec<Line> = Vec::new();
            if skip > 0 {
                tool_lines.push(Line::from(Span::styled(
                    format!("  ── {skip} earlier ──"),
                    Style::default().fg(C_DIM),
                )));
            }
            let sep_line = Line::from(Span::styled(
                "  ─────────────────────────────".to_string(),
                Style::default().fg(Color::Rgb(30, 41, 59)), // nearly-black: very subtle
            ));
            for (idx, t) in state.tool_log[skip..].iter().enumerate() {
                if idx > 0 {
                    tool_lines.push(sep_line.clone());
                }
                tool_lines.extend(tool_entry_to_lines(t, spin));
            }
            let tps_part = if state.status_running && state.last_tps > 0.5 {
                format!("  {:.0}t/s", state.last_tps)
            } else {
                String::new()
            };
            let tools_title = {
                let ok = state.tools_ok;
                let err = state.tools_err;
                let resp_badge = if state.last_response_words > 0 && !state.status_running {
                    format!("  ·  {}w", state.last_response_words)
                } else {
                    String::new()
                };
                let pin_badge = if let Some(ref note) = state.pinned_note {
                    let preview: String = note.chars().take(18).collect();
                    let ellipsis = if note.chars().count() > 18 { "…" } else { "" };
                    format!("  ★ {}{}", preview, ellipsis)
                } else {
                    String::new()
                };
                if err > 0 {
                    format!(" Tools  {}✓  {}✗{}{}{} ", ok, err, tps_part, resp_badge, pin_badge)
                } else if ok > 0 {
                    format!(" Tools  {}✓{}{}{} ", ok, tps_part, resp_badge, pin_badge)
                } else {
                    format!(" Tools{}{}{} ", tps_part, resp_badge, pin_badge)
                }
            };
            let tools_title_color = if state.tools_err > 0 { C_ERR } else if state.tools_ok > 0 { C_OK } else { C_DIM };
            f.render_widget(
                Paragraph::new(tool_lines)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(border_style)
                            .title(Span::styled(tools_title, Style::default().fg(tools_title_color).add_modifier(Modifier::BOLD))),
                    )
                    .wrap(Wrap { trim: false }),
                tools_area,
            );

            if let Some(area) = fleet_area {
                let fleet_lines: Vec<Line> =
                    state.fleet.iter().map(fleet_entry_to_line).collect();
                f.render_widget(
                    Paragraph::new(fleet_lines)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_style(border_style)
                                .title(Span::styled(" Fleet ", title_style)),
                        )
                        .wrap(Wrap { trim: false }),
                    area,
                );
            }

            } // end else has_tools
        }

        // ── 3. Input area ─────────────────────────────────────────────
        {
            let (pfx, pfx_color) = if state.status_running {
                (spin, C_WARN)
            } else {
                (">", C_USER_PFX)
            };

            // Blinking cursor: 500ms on / 500ms off, disabled while thinking
            let cursor_on = {
                let ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                !state.status_running && (ms / 500) % 2 == 0
            };

            const SUGGESTIONS: &[&str] = &[
                "Try \"summarize this codebase\"",
                "Try \"find all TODO comments\"",
                "Try \"explain the main entry point\"",
                "Try \"what does this project do?\"",
                "Try \"find potential bugs in this code\"",
                "Try \"write tests for the core logic\"",
                "Try \"what's the architecture here?\"",
                "Try \"show me the most complex file\"",
                "Try \"list all public API endpoints\"",
                "Try \"where should I add error handling?\"",
            ];
            let sugg_idx = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                / 8;
            let placeholder: String = if state.status_running {
                "thinking…".to_string()
            } else {
                SUGGESTIONS[sugg_idx as usize % SUGGESTIONS.len()].to_string()
            };

            // Show char count when buffer has content
            let char_hint = if !state.input_buffer.is_empty() {
                let chars = state.input_buffer.chars().count();
                let lines = state.input_buffer.lines().count().max(1);
                if lines > 1 { format!("  [{chars}c {lines}L]") } else { format!("  [{chars}c]") }
            } else {
                String::new()
            };

            let input_content: Vec<Line> = if state.input_buffer.is_empty() {
                let cursor = if cursor_on { "│" } else { " " };
                vec![Line::from(vec![
                    Span::styled(
                        format!("  {pfx}  "),
                        Style::default()
                            .fg(pfx_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(cursor.to_string(), Style::default().fg(t_brand).add_modifier(Modifier::BOLD)),
                    Span::styled(placeholder, Style::default().fg(C_DIM)),
                ])]
            } else {
                let buf_lines: Vec<&str> = state.input_buffer.lines().collect();
                let total = buf_lines.len();
                buf_lines
                    .into_iter()
                    .enumerate()
                    .map(|(i, line)| {
                        let is_last = i + 1 == total;
                        let prefix_span = if i == 0 {
                            Span::styled(
                                format!("  {pfx}  "),
                                Style::default()
                                    .fg(pfx_color)
                                    .add_modifier(Modifier::BOLD),
                            )
                        } else {
                            Span::raw("       ")
                        };
                        // Slash command coloring: /word in accent, rest in body
                        let content_spans: Vec<Span<'static>> = if i == 0 && line.starts_with('/') {
                            let split = line.find(' ').unwrap_or(line.len());
                            let cmd = line[..split].to_string();
                            let rest = line[split..].to_string();
                            let mut cs = vec![Span::styled(cmd, Style::default().fg(C_ASST_PFX).add_modifier(Modifier::BOLD))];
                            if !rest.is_empty() {
                                cs.push(Span::styled(rest, Style::default().fg(C_BODY)));
                            }
                            cs
                        } else {
                            vec![Span::styled(line.to_string(), Style::default().fg(C_BODY))]
                        };
                        if is_last {
                            // Compute cursor position within this line's text
                            let line_start: usize = state.input_buffer
                                .lines()
                                .take(i)
                                .map(|l| l.len() + 1) // +1 for '\n'
                                .sum();
                            let cursor_in_line = state.input_cursor
                                .saturating_sub(line_start)
                                .min(line.len());

                            let mut spans = vec![prefix_span];
                            if cursor_in_line >= line.len() {
                                // Cursor at end — use pre-built slash-colored content_spans
                                spans.extend(content_spans);
                                let curs = if cursor_on { "│" } else { " " };
                                spans.push(Span::styled(
                                    curs.to_string(),
                                    Style::default().fg(t_brand).add_modifier(Modifier::BOLD),
                                ));
                                // Ghost-text suggestion (dim, only on last line when cursor is at end)
                                if is_last {
                                    if let Some(ref ghost) = state.input_ghost {
                                        spans.push(Span::styled(
                                            ghost.clone(),
                                            Style::default().fg(C_DIM),
                                        ));
                                    }
                                }
                            } else {
                                // Cursor inside text — block highlight at cursor char
                                let ch_end = line[cursor_in_line..].chars().next()
                                    .map(|c| cursor_in_line + c.len_utf8())
                                    .unwrap_or(line.len());
                                let before = line[..cursor_in_line].to_string();
                                let curs_ch = line[cursor_in_line..ch_end].to_string();
                                let after = line[ch_end..].to_string();
                                if !before.is_empty() {
                                    spans.push(Span::styled(before, Style::default().fg(C_BODY)));
                                }
                                let curs_style = if cursor_on {
                                    Style::default().fg(C_HDR_BG).bg(t_brand)
                                } else {
                                    Style::default().fg(C_BODY)
                                };
                                spans.push(Span::styled(curs_ch, curs_style));
                                if !after.is_empty() {
                                    spans.push(Span::styled(after, Style::default().fg(C_BODY)));
                                }
                            }
                            if !char_hint.is_empty() {
                                spans.push(Span::styled(
                                    char_hint.clone(),
                                    Style::default().fg(C_DIM),
                                ));
                            }
                            Line::from(spans)
                        } else {
                            let mut spans = vec![prefix_span];
                            spans.extend(content_spans);
                            Line::from(spans)
                        }
                    })
                    .collect()
            };

            let input_line_count = state.input_buffer.lines().count().max(1);
            let input_char_count = state.input_buffer.len();
            let input_token_est = input_char_count / 4; // standard chars/token heuristic
            // Compute cursor line:col (byte-safe — walk to cursor offset)
            let cursor_safe = state.input_cursor.min(state.input_buffer.len());
            let (cursor_line_num, cursor_col) = if input_line_count > 1 {
                let before_cursor = &state.input_buffer[..cursor_safe];
                let ln = before_cursor.lines().count().max(1);
                let col = before_cursor.lines().last().map_or(0, |l| l.len()) + 1;
                (ln, col)
            } else {
                // Single-line: col = char count before cursor
                let col = state.input_buffer[..cursor_safe].chars().count() + 1;
                (1, col)
            };
            let input_title = if ctx_pct > 0.75 {
                // Mini block-char progress bar: 8 cells, ██░░ style
                let pct = (ctx_pct * 100.0) as u8;
                let filled = (ctx_pct * 8.0).round() as usize;
                let bar: String = "█".repeat(filled) + &"░".repeat(8usize.saturating_sub(filled));
                let warn = if ctx_pct > 0.9 { "⚠ " } else { "" };
                format!(" {warn}[{bar}] {pct}% ctx ")
            } else if let Some(note) = &state.pinned_note {
                let preview: String = note.chars().take(40).collect();
                format!(" ★ {} ", preview)
            } else if let Some(ref pfx) = state.prompt_prefix {
                let preview: String = pfx.chars().take(30).collect();
                format!(" ⬡ prefix: {} ", preview)
            } else {
                let pos_part = if input_line_count > 1 {
                    format!("{}:{} ↵{}  ", cursor_line_num, cursor_col, input_line_count)
                } else if cursor_col > 40 {
                    format!("col {}  ", cursor_col)
                } else {
                    String::new()
                };
                let word_count = state.input_buffer.split_whitespace().count();
                let words_part = if word_count >= 20 {
                    format!("~{}w ", word_count)
                } else {
                    String::new()
                };
                let tokens_part = if input_token_est >= 50 {
                    format!("~{}t ", input_token_est)
                } else {
                    String::new()
                };
                let char_count = state.input_buffer.chars().count();
                let chars_part = if char_count > 200 {
                    format!("{}c ", char_count)
                } else {
                    String::new()
                };
                if pos_part.is_empty() && words_part.is_empty() && tokens_part.is_empty() && chars_part.is_empty() {
                    String::new()
                } else {
                    format!(" {}{}{}{}", pos_part, words_part, tokens_part, chars_part)
                }
            };
            // Flash bright brand-blue for 1.2s after a response completes
            let response_flash = state.response_done_at
                .map_or(false, |t| t.elapsed().as_millis() < 1200);
            let input_border_color = if ctx_pct > 0.9 {
                let ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                if (ms / 400) % 2 == 0 { C_ERR } else { C_WARN }
            } else if ctx_pct > 0.75 {
                C_WARN
            } else if state.pinned_note.is_some() {
                C_WARN // amber for pinned
            } else if response_flash {
                // Pulse brand/dim alternating to draw attention without being disruptive
                let ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                if (ms / 200) % 2 == 0 { C_BRAND } else { Color::Rgb(99, 102, 241) } // indigo-500
            } else {
                C_BORDER
            };
            let input_block = if input_title.is_empty() {
                Block::default()
                    .borders(Borders::TOP)
                    .border_style(Style::default().fg(input_border_color))
            } else {
                Block::default()
                    .borders(Borders::TOP)
                    .border_style(Style::default().fg(input_border_color))
                    .title(Span::styled(input_title, Style::default().fg(input_border_color).add_modifier(Modifier::BOLD)))
            };
            f.render_widget(
                Paragraph::new(input_content)
                    .block(input_block)
                    .wrap(Wrap { trim: false }),
                outer[2],
            );
        }

        // ── 4. Hints bar ──────────────────────────────────────────────
        {
            let perm = perm_label(&state.perm_mode);
            let (perm_color, perm_sym) = match perm {
                "bypass"    => (C_WARN, "⚡"),
                "auto-edit" => (C_OK,   "✓"),
                _           => (C_DIM,  "◆"),
            };
            // msg_count precomputed at top of draw_frame closure

            // Elapsed time
            let elapsed = state.session_start.elapsed().as_secs();
            let elapsed_str = if elapsed < 60 {
                format!("{elapsed}s")
            } else if elapsed < 3600 {
                format!("{}m{}s", elapsed / 60, elapsed % 60)
            } else {
                format!("{}h{}m", elapsed / 3600, (elapsed % 3600) / 60)
            };

            // Context window usage mini-bar (10 blocks) — ctx_pct precomputed at frame start
            let filled = (ctx_pct * 10.0).round() as usize;
            let ctx_bar: String = (0..10)
                .map(|i| if i < filled { '█' } else { '░' })
                .collect();
            let ctx_color = if ctx_pct > 0.85 {
                // Pulse red/amber when critically high context
                let ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                if (ms / 500) % 2 == 0 { C_ERR } else { C_WARN }
            } else if ctx_pct > 0.65 {
                C_WARN
            } else {
                Color::Rgb(51, 65, 85) // slate-700
            };

            // Right stats segment
            let thinking_part = if state.status_running {
                let (timer_str, cps_str) = if let Some(t0) = state.stream_start {
                    let secs = t0.elapsed().as_secs_f64();
                    let timer = if secs >= 1.0 { format!("  ⏱{:.1}s", secs) } else { String::new() };
                    let cps = if secs >= 0.5 && state.stream_chars > 0 {
                        format!("  {:.0}c/s", state.stream_chars as f64 / secs)
                    } else { String::new() };
                    (timer, cps)
                } else {
                    (String::new(), String::new())
                };
                if state.stream_chars > 0 {
                    let words = (state.stream_chars / 5).max(1);
                    format!("{spin}{timer_str}{cps_str}  ~{}w ~{}c  ", words, state.stream_chars)
                } else {
                    format!("{spin}{timer_str}  ")
                }
            } else {
                String::new()
            };

            let mut right_parts: Vec<String> = vec![elapsed_str];
            if state.tokens_in > 0 || state.tokens_out > 0 {
                right_parts.push(format!("↑{} ↓{}", fmt_tokens(state.tokens_in), fmt_tokens(state.tokens_out)));
            }
            if state.last_tps > 0.5 {
                right_parts.push(format!("{:.0} t/s", state.last_tps));
            }
            // t/s sparkline: build colored bar per reading (green=fast, amber=mid, red=slow)
            let sparkline_spans: Option<Vec<(char, Color)>> = if state.tps_history.len() >= 2 {
                let max_tps = state.tps_history.iter().cloned().fold(0.0_f64, f64::max).max(1.0);
                Some(state.tps_history.iter().map(|&v| {
                    let frac = v / max_tps;
                    let bar = match (frac * 7.0).round() as usize {
                        0 => '▁', 1 => '▂', 2 => '▃', 3 => '▄', 4 => '▅', 5 => '▆', 6 => '▇', _ => '█',
                    };
                    let color = if frac > 0.75 { C_OK } else if frac > 0.4 { C_WARN } else { C_ERR };
                    (bar, color)
                }).collect())
            } else { None };
            if state.cost_usd > 0.0 {
                right_parts.push(format!("${:.4}", state.cost_usd));
            }
            let right_str = right_parts.join("  ·  ");

            let msg_str = if msg_count > 0 {
                format!("  ·  msg {msg_count}")
            } else {
                String::new()
            };
            // Hints cycle every 8 s (6 groups: input / search / nav / commands / power-tools / ai-workflows)
            let hints_group = (elapsed / 8) % 6;
            let static_hints = match hints_group {
                0 => "↵ send  ⇧↵ newline  ↑↓ history  ←→ move  ^A/E line  ^W del-word  ^L clear  /help",
                1 => "^R reverse-i-search  ^Y yank last  ^K kill-end  ^U kill-start  ⇥ tab-complete  ^` code fence",
                2 => "Pg↑↓ scroll  End jump to tail  ^H top  F2 panel  F3 timestamps  F6 focus  F7 theme  ^G find  ^N new",
                3 => "/retry  /copy  /note  /compact  /export  /search  /cost  /model  /sessions  /undo  /pin",
                4 => "/scan  /secrets  /deps  /vulnscan  /owasp  /ctf-tools  /sbom  /blame  /grep-code  /heatmap",
                _ => "/ask-code  /gen-tests  /code-review  /pr-review  /refactor  /optimize  /arch-review  /ai-commit",
            };
            let mut hints_spans = vec![
                Span::styled(
                    format!("  {perm_sym} {perm}  ·  "),
                    Style::default().fg(perm_color).bg(C_HDR_BG),
                ),
                Span::styled(
                    format!("{}{}", thinking_part, static_hints),
                    Style::default().fg(C_DIM).bg(C_HDR_BG),
                ),
                Span::styled(
                    msg_str,
                    Style::default().fg(Color::Rgb(51, 65, 85)).bg(C_HDR_BG),
                ),
            ];
            if ctx_pct > 0.0 {
                hints_spans.push(Span::styled(
                    format!("  ·  {ctx_bar}"),
                    Style::default().fg(ctx_color).bg(C_HDR_BG),
                ));
                hints_spans.push(Span::styled(
                    format!("  {:.0}%", ctx_pct * 100.0),
                    Style::default().fg(ctx_color).bg(C_HDR_BG),
                ));
            }
            hints_spans.push(Span::styled(
                format!("  ·  {right_str}"),
                Style::default().fg(Color::Rgb(71, 85, 105)).bg(C_HDR_BG),
            ));
            // Colored t/s sparkline — each bar gets its own color span
            if let Some(bars) = sparkline_spans {
                hints_spans.push(Span::styled("  ·  ".to_string(), Style::default().fg(Color::Rgb(71, 85, 105)).bg(C_HDR_BG)));
                for (ch, color) in bars {
                    hints_spans.push(Span::styled(ch.to_string(), Style::default().fg(color).bg(C_HDR_BG)));
                }
            }
            // Scroll mode indicator: amber badge when user has scrolled up from tail
            if !state.follow_tail {
                let new_badge = if state.new_msgs_while_scrolled > 0 {
                    format!("  ↑SCROLL  ↓ {} new  (End to jump)", state.new_msgs_while_scrolled)
                } else {
                    "  ↑SCROLL  (End to resume)".to_string()
                };
                hints_spans.push(Span::styled(
                    new_badge,
                    Style::default().fg(C_WARN).bg(C_HDR_BG).add_modifier(Modifier::BOLD),
                ));
            }
            // F2 panel toggle badge
            if state.side_panel_hidden {
                hints_spans.push(Span::styled(
                    "  F2:panel".to_string(),
                    Style::default().fg(C_DIM).bg(C_HDR_BG),
                ));
            }
            // Active feature badges: TS / RAW / HL
            if state.show_timestamps {
                hints_spans.push(Span::styled("  [TS]".to_string(), Style::default().fg(C_BRAND).bg(C_HDR_BG)));
            }
            if state.raw_mode {
                hints_spans.push(Span::styled("  [RAW]".to_string(), Style::default().fg(C_WARN).bg(C_HDR_BG)));
            }
            if let Some(ref term) = state.search_highlight {
                let label: String = term.chars().take(8).collect();
                hints_spans.push(Span::styled(
                    format!("  [HL:{label}]"),
                    Style::default().fg(Color::Rgb(253, 224, 71)).bg(Color::Rgb(20, 14, 0)).add_modifier(Modifier::BOLD),
                ));
            }
            if state.show_line_numbers {
                hints_spans.push(Span::styled("  [LN]".to_string(), Style::default().fg(Color::Rgb(100, 116, 139)).bg(C_HDR_BG)));
            }
            // Context pressure warning: flashing badge at 85%+
            if ctx_pct >= 0.85 && !state.status_running {
                let ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                let visible = (ms / 800) % 2 == 0;
                if visible {
                    hints_spans.push(Span::styled(
                        "  ⚠ context full — /compact".to_string(),
                        Style::default().fg(C_ERR).bg(C_HDR_BG).add_modifier(Modifier::BOLD),
                    ));
                }
            }
            // "● live" tail indicator
            if state.follow_tail && !state.status_running {
                hints_spans.push(Span::styled(
                    "  ● live".to_string(),
                    Style::default().fg(C_OK).bg(C_HDR_BG),
                ));
            }
            // TTFT slow indicator: waiting >4s for first token
            if state.status_running && state.stream_chars == 0 {
                if let Some(t) = state.waiting_since {
                    let wait_secs = t.elapsed().as_secs();
                    if wait_secs >= 4 {
                        hints_spans.push(Span::styled(
                            format!("  [⧗ {}s slow]", wait_secs),
                            Style::default().fg(C_WARN).bg(C_HDR_BG),
                        ));
                    }
                }
            }
            // Live response timer: shows elapsed seconds once streaming starts
            if state.status_running && state.stream_chars > 0 {
                if let Some(t) = state.response_start {
                    let secs = t.elapsed().as_secs_f64();
                    hints_spans.push(Span::styled(
                        format!("  ⏱ {:.1}s", secs),
                        Style::default().fg(C_DIM).bg(C_HDR_BG),
                    ));
                }
            }
            // Reverse-i-search mode indicator overrides the right side of hints
            let hints_line = if let Some(ref q) = state.history_search {
                Line::from(vec![
                    Span::styled(
                        format!("  ⌕ reverse-i-search: {}█", q),
                        Style::default().fg(C_BRAND).bg(C_HDR_BG).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        "  ·  Ctrl+R: older  ·  Esc: cancel  ·  ↵: confirm".to_string(),
                        Style::default().fg(C_DIM).bg(C_HDR_BG),
                    ),
                ])
            } else {
                Line::from(hints_spans)
            };
            f.render_widget(
                Paragraph::new(hints_line).style(Style::default().bg(C_HDR_BG)),
                outer[3],
            );
        }
    })?;
    Ok(())
}

// ── search highlight post-processor ──────────────────────────────────────────

/// Walks rendered spans and splits any that contain `term` (case-insensitive),
/// inserting a yellow-bg highlight style around each match.
fn apply_search_highlight(mut lines: Vec<Line<'static>>, term: &str) -> Vec<Line<'static>> {
    if term.is_empty() { return lines; }
    let term_lower = term.to_lowercase();
    let hl_style = Style::default()
        .fg(Color::Rgb(0, 0, 0))
        .bg(Color::Rgb(253, 224, 71)) // amber-300 yellow
        .add_modifier(Modifier::BOLD);

    for line in &mut lines {
        let mut new_spans: Vec<Span<'static>> = Vec::new();
        for span in line.spans.drain(..) {
            let text = span.content.to_string();
            let base_style = span.style;
            let text_lower = text.to_lowercase();
            if text_lower.contains(&term_lower) {
                let mut rest: &str = &text;
                let mut rest_lower_start = 0usize;
                let text_bytes = text.as_bytes();
                let _ = text_bytes;
                // Walk through matches in the lowercased copy
                let mut pos_in_lower = 0usize;
                let mut pos_in_orig = 0usize;
                let lower_bytes = text_lower.as_bytes();
                while pos_in_lower + term_lower.len() <= lower_bytes.len() {
                    if lower_bytes[pos_in_lower..].starts_with(term_lower.as_bytes()) {
                        // Before the match
                        let before = &rest[..pos_in_orig - (rest.as_ptr() as usize - text.as_ptr() as usize)];
                        let _ = before;
                        break; // fall through to simpler split logic below
                    }
                    pos_in_lower += 1;
                    pos_in_orig += 1;
                }
                // Simpler: use find() on slices
                let mut remaining = text.as_str();
                loop {
                    let lower_remaining = remaining.to_lowercase();
                    match lower_remaining.find(&term_lower) {
                        None => {
                            if !remaining.is_empty() {
                                new_spans.push(Span::styled(remaining.to_string(), base_style));
                            }
                            break;
                        }
                        Some(byte_start) => {
                            let byte_end = (byte_start + term_lower.len()).min(remaining.len());
                            if byte_start > 0 {
                                new_spans.push(Span::styled(remaining[..byte_start].to_string(), base_style));
                            }
                            new_spans.push(Span::styled(remaining[byte_start..byte_end].to_string(), hl_style));
                            remaining = &remaining[byte_end..];
                        }
                    }
                }
                let _ = rest_lower_start;
            } else {
                new_spans.push(Span::styled(text, base_style));
            }
        }
        line.spans = new_spans;
    }
    lines
}

// ── chat line → ratatui Lines ─────────────────────────────────────────────────

fn chat_line_to_lines(cl: &ChatLine, trail_spin: bool, spin: &str, show_timestamps: bool, highlight: Option<&str>, raw_mode: bool, show_line_numbers: bool, msg_num: u32) -> Vec<Line<'static>> {
    match cl {
        ChatLine::User(body, ts) => {
            let mut lines: Vec<Line<'static>> = Vec::new();
            // Subtle top separator before each user turn, optionally with [N] exchange number
            let sep = if msg_num > 0 {
                format!("  [{msg_num}]─────────────────────────────────────────────────")
            } else {
                "  ·─────────────────────────────────────────────────────".to_string()
            };
            lines.push(Line::from(Span::styled(
                sep,
                Style::default().fg(Color::Rgb(30, 41, 59)),
            )));
            if *ts > 0 || show_timestamps {
                let ts_str = if *ts > 0 {
                    let h = (ts % 86400) / 3600;
                    let m = (ts % 3600) / 60;
                    let s = ts % 60;
                    format!("{:02}:{:02}:{:02}", h, m, s)
                } else {
                    "now".to_string()
                };
                lines.push(Line::from(vec![
                    Span::styled("  ·  ", Style::default().fg(Color::Rgb(30, 41, 59))),
                    Span::styled(
                        ts_str,
                        Style::default().fg(if show_timestamps { C_DIM } else { Color::Rgb(51, 65, 85) }),
                    ),
                ]));
            }
            let rendered = render_message("  >  ", C_USER_PFX, body, C_BODY, false, trail_spin, spin, 0.0, 0.0, false);
            lines.extend(if let Some(term) = highlight { apply_search_highlight(rendered, term) } else { rendered });
            lines
        }
        ChatLine::Assistant(body, dur, cost) => {
            // raw_mode disables markdown/syntax rendering — plain text only
            let rendered = render_message("  ◆  ", C_ASST_PFX, body, C_BODY, !raw_mode, false, spin, *dur, *cost, show_line_numbers);
            if let Some(term) = highlight { apply_search_highlight(rendered, term) } else { rendered }
        }
        ChatLine::AssistantPartial(body) => {
            let rendered = render_message("  ◆  ", C_ASST_PFX, body, C_BODY, !raw_mode, trail_spin, spin, 0.0, 0.0, show_line_numbers);
            if let Some(term) = highlight { apply_search_highlight(rendered, term) } else { rendered }
        }
        ChatLine::SystemNote(body) => {
            let rule = Line::from(Span::styled(
                "  ──────────────────────────────────────────────────────".to_string(),
                Style::default().fg(C_DIM),
            ));
            let mut lines: Vec<Line<'static>> = vec![rule.clone()];
            for raw_line in body.lines() {
                lines.push(Line::from(vec![
                    Span::styled("  ℹ  ".to_string(), Style::default().fg(C_ASST_PFX)),
                    Span::styled(raw_line.to_string(), Style::default().fg(Color::Rgb(148, 163, 184))),
                ]));
            }
            lines.push(rule);
            lines
        }
        ChatLine::SplashRow { logo, info, style } => {
            let (info_color, info_mod) = match style {
                SplashStyle::Brand  => (C_BRAND,    Modifier::BOLD),
                SplashStyle::Title  => (C_BODY,     Modifier::BOLD),
                SplashStyle::Accent => (C_ASST_PFX, Modifier::empty()),
                SplashStyle::Ok     => (C_OK,        Modifier::BOLD),
                SplashStyle::Warn   => (C_WARN,      Modifier::BOLD),
                SplashStyle::Dim    => (C_DIM,       Modifier::empty()),
            };
            let mut spans = vec![Span::styled(
                logo.clone(),
                Style::default().fg(C_BRAND).add_modifier(Modifier::BOLD),
            )];
            if !info.is_empty() {
                spans.push(Span::styled(
                    format!("  {}", info),
                    Style::default().fg(info_color).add_modifier(info_mod),
                ));
            }
            vec![Line::from(spans)]
        }
    }
}

/// Render one chat message as a sequence of styled `Line`s.
///
/// `prefix`      — 5-char glyph sequence (e.g. "  >  ") — must be `&'static str`
/// `prefix_color`— colour for the prefix glyph
/// `body`        — raw text of the message
/// `body_color`  — colour used for non-markdown-decorated body text
/// `is_assistant`— enables inline-markdown rendering and code-block colouring
/// `trail_spin`  — append the live spinner to the very last line
/// `spin`        — current spinner frame string
/// `duration_secs` — response wall-clock time (0.0 = no badge)
/// `cost_delta_usd` — cost for this message (0.0 = unknown, omit from badge)
fn render_message(
    prefix: &'static str,
    prefix_color: Color,
    body: &str,
    body_color: Color,
    is_assistant: bool,
    trail_spin: bool,
    spin: &str,
    duration_secs: f64,
    cost_delta_usd: f64,
    show_line_numbers: bool,
) -> Vec<Line<'static>> {
    let pfx_style = Style::default()
        .fg(prefix_color)
        .add_modifier(Modifier::BOLD);
    // Continuation indent — same visible width as prefix (5 chars).
    const CONT: &str = "     ";

    let mut out: Vec<Line<'static>> = Vec::new();
    let mut first = true;
    let mut in_code_block = false;
    let mut code_lang = String::new();
    // Track diff stats within fenced diff blocks (+/- line counts)
    let mut diff_plus: u32 = 0;
    let mut diff_minus: u32 = 0;
    let mut block_is_diff = false;
    // Line number counter within code blocks (reset per block)
    let mut code_line_num: u32 = 0;

    let raw_lines: Vec<&str> = body.lines().collect();
    let n = raw_lines.len();

    for (li, &line) in raw_lines.iter().enumerate() {
        let is_last = li + 1 == n;
        let trimmed = line.trim_start();

        if trimmed.starts_with("```") {
            if in_code_block {
                // Closing fence: emit diff stat line before the ruler
                if block_is_diff && (diff_plus + diff_minus) > 0 {
                    let stat_str = format!("  +{diff_plus} added  -{diff_minus} removed");
                    out.push(Line::from(vec![
                        Span::raw(CONT),
                        Span::styled(stat_str, Style::default().fg(C_DIM).bg(C_CODE_BG)),
                    ]));
                }
                diff_plus = 0;
                diff_minus = 0;
                block_is_diff = false;
                in_code_block = false;
                code_lang.clear();
            } else {
                in_code_block = true;
                code_lang = trimmed.trim_start_matches('`').trim().to_lowercase();
                block_is_diff = matches!(code_lang.as_str(), "diff" | "patch" | "udiff");
                code_line_num = 0; // reset line counter for new block
            }
        } else if in_code_block && block_is_diff {
            // Count meaningful diff lines (skip file headers +++ and ---)
            if trimmed.starts_with('+') && !trimmed.starts_with("+++") {
                diff_plus += 1;
            } else if trimmed.starts_with('-') && !trimmed.starts_with("---") {
                diff_minus += 1;
            }
        }

        let leader: Span<'static> = if first {
            first = false;
            Span::styled(prefix, pfx_style)
        } else {
            Span::raw(CONT)
        };

        let mut body_spans: Vec<Span<'static>> = if trimmed.starts_with("```") {
            // Fence delimiter: decorated ruler for assistant messages.
            // After the toggle above: in_code_block==true = opening fence, false = closing fence.
            if is_assistant {
                if in_code_block && !code_lang.is_empty() {
                    // Opening fence with colored language badge
                    let lang_color = match code_lang.as_str() {
                        "rust" | "rs"               => Color::Rgb(222, 165, 132), // rust orange
                        "python" | "py"             => Color::Rgb(52, 211, 153),  // emerald-400
                        "javascript" | "js" | "jsx" => Color::Rgb(250, 204, 21),  // yellow-400
                        "typescript" | "ts" | "tsx" => Color::Rgb(96, 165, 250),  // blue-400
                        "bash" | "sh" | "shell" | "zsh" => Color::Rgb(74, 222, 128), // green-400
                        "go"                        => Color::Rgb(99, 179, 237),  // sky-300
                        "c" | "cpp" | "c++"         => Color::Rgb(196, 181, 253), // purple-300
                        "java" | "kotlin"           => Color::Rgb(253, 186, 116), // orange-300
                        "diff" | "patch"            => Color::Rgb(248, 113, 113), // red-400
                        "json" | "yaml" | "toml"    => Color::Rgb(148, 163, 184), // slate-400
                        "sql"                       => Color::Rgb(216, 180, 254), // purple-300
                        "html" | "css" | "xml"      => Color::Rgb(249, 115, 22),  // orange-500
                        _                           => C_DIM,
                    };
                    // Show run hint for executable languages
                    let run_hint = match code_lang.as_str() {
                        "rust"|"rs" => "  /run",
                        "python"|"py" => "  /run",
                        "javascript"|"js" => "  /run",
                        "bash"|"sh"|"shell" => "  /run",
                        "diff"|"patch" => "  /patch",
                        _ => "",
                    };
                    let mut spans = vec![
                        Span::styled("  ─── ".to_string(), Style::default().fg(C_DIM).bg(C_CODE_BG)),
                        Span::styled(code_lang.to_uppercase(), Style::default().fg(lang_color).bg(C_CODE_BG).add_modifier(Modifier::BOLD)),
                        Span::styled(" ──────────────────────────".to_string(), Style::default().fg(C_DIM).bg(C_CODE_BG)),
                    ];
                    if !run_hint.is_empty() {
                        spans.push(Span::styled(run_hint.to_string(), Style::default().fg(C_DIM).bg(C_CODE_BG)));
                    }
                    spans
                } else if in_code_block {
                    // Opening fence no language
                    vec![Span::styled("  ──────────────────────────────────".to_string(), Style::default().fg(C_DIM).bg(C_CODE_BG))]
                } else {
                    // Closing fence: show line count + copy shortcut
                    let lines_label = if code_line_num > 0 {
                        format!("  ─── {} line{}  /copy code ────────────", code_line_num, if code_line_num == 1 { "" } else { "s" })
                    } else {
                        "  ──────────────────────────────────".to_string()
                    };
                    vec![Span::styled(lines_label, Style::default().fg(C_DIM).bg(C_CODE_BG))]
                }
            } else {
                vec![Span::styled(line.to_string(), Style::default().fg(C_DIM).bg(C_CODE_BG))]
            }
        } else if !is_assistant {
            // Non-assistant (user messages etc): plain dim
            vec![Span::styled(
                line.to_string(),
                Style::default().fg(C_DIM),
            )]
        } else if in_code_block {
            // Inside a fenced code block: syntax-highlighted spans (with optional line numbers)
            code_line_num += 1;
            let mut spans = if show_line_numbers {
                vec![Span::styled(
                    format!("{:3}│ ", code_line_num),
                    Style::default().fg(Color::Rgb(71, 85, 105)).bg(C_CODE_BG), // slate-600
                )]
            } else {
                Vec::new()
            };
            spans.extend(highlight_code_line(line, &code_lang));
            spans
        } else {
            // Normal assistant prose: check for block-level markdown patterns first.
            // Horizontal rule: --- / *** / ___
            if trimmed == "---" || trimmed == "***" || trimmed == "___" || trimmed.chars().all(|c| c == '-') && trimmed.len() >= 3 {
                vec![Span::styled(
                    "─────────────────────────────────────────────".to_string(),
                    Style::default().fg(C_DIM),
                )]
            // Blockquote: > text  — also handles GitHub/Obsidian callout >[!TYPE]
            } else if trimmed.starts_with("> ") || trimmed == ">" || trimmed.starts_with(">[!") {
                let content = trimmed.trim_start_matches('>').trim_start();
                if let Some(rest) = content.strip_prefix("[!") {
                    // Callout header: >[!NOTE], >[!WARNING], >[!TIP], >[!DANGER], >[!IMPORTANT]
                    let close = rest.find(']').unwrap_or(rest.len());
                    let kind = &rest[..close];
                    let title_after = rest.get(close + 1..).unwrap_or("").trim();
                    let kind_upper = kind.to_uppercase();
                    let (icon, color, label): (&str, Color, &str) = match kind_upper.as_str() {
                        "NOTE" | "INFO"               => ("ℹ  ", C_ASST_PFX,                       "NOTE"),
                        "WARNING" | "WARN"            => ("⚠  ", C_WARN,                           "WARNING"),
                        "TIP"                         => ("◈  ", C_OK,                             "TIP"),
                        "DANGER" | "ERROR"            => ("✕  ", C_ERR,                            "DANGER"),
                        "IMPORTANT"                   => ("★  ", Color::Rgb(167, 139, 250),         "IMPORTANT"),
                        "SUCCESS" | "CHECK"           => ("✓  ", C_OK,                             "SUCCESS"),
                        "QUESTION" | "HELP" | "FAQ"   => ("?  ", C_WARN,                           "QUESTION"),
                        "BUG"                         => ("⊗  ", C_ERR,                            "BUG"),
                        "EXAMPLE"                     => ("◉  ", Color::Rgb(139, 92, 246),          "EXAMPLE"),
                        "QUOTE" | "CITE"              => ("❝  ", Color::Rgb(148, 163, 184),         "QUOTE"),
                        _                             => ("│  ", C_ASST_PFX,                       kind),
                    };
                    let display = if title_after.is_empty() {
                        label.to_string()
                    } else {
                        format!("{label} — {title_after}")
                    };
                    vec![
                        Span::styled(icon.to_string(), Style::default().fg(color)),
                        Span::styled(display, Style::default().fg(color).add_modifier(Modifier::BOLD)),
                    ]
                } else {
                    let mut bq = vec![Span::styled("│ ".to_string(), Style::default().fg(C_ASST_PFX))];
                    bq.extend(inline_markdown_spans(content, Color::Rgb(148, 163, 184))); // slate-400
                    bq
                }
            // Task list item: - [ ] unchecked  /  - [x] or - [X] checked
            } else if trimmed.starts_with("- [ ] ") || trimmed.starts_with("- [x] ") || trimmed.starts_with("- [X] ") {
                let is_done = !trimmed.starts_with("- [ ]");
                let content = &trimmed[6..]; // skip "- [ ] " / "- [x] "
                let indent = line.len() - line.trim_start().len();
                let pad = " ".repeat(indent);
                let (check_glyph, check_color) = if is_done {
                    ("✓ ", C_OK)
                } else {
                    ("☐ ", C_DIM)
                };
                let text_color = if is_done { C_DIM } else { body_color };
                let mut li_spans = vec![Span::styled(format!("{pad}{check_glyph}"), Style::default().fg(check_color).add_modifier(if is_done { Modifier::empty() } else { Modifier::empty() }))];
                li_spans.extend(inline_markdown_spans(content, text_color));
                li_spans
            // Unordered list item: - / * / + (with nested bullet hierarchy)
            } else if (trimmed.starts_with("- ") || trimmed.starts_with("* ") || trimmed.starts_with("+ ")) && !in_code_block {
                let content = &trimmed[2..];
                let indent = line.len() - line.trim_start().len();
                let pad = " ".repeat(indent);
                // Bullet style: level 0 = •, level 1 (2–3 spaces) = ◦, level 2+ (4+ spaces) = ▪
                let (bullet, bullet_color) = if indent >= 4 {
                    ("▪ ", C_DIM)
                } else if indent >= 2 {
                    ("◦ ", Color::Rgb(100, 116, 139)) // slate-500
                } else {
                    ("• ", C_ASST_PFX)
                };
                let mut li_spans = vec![Span::styled(format!("{pad}{bullet}"), Style::default().fg(bullet_color))];
                li_spans.extend(inline_markdown_spans(content, body_color));
                li_spans
            // Ordered list item: 1. / 2. etc.
            } else if trimmed.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                let dot_pos = trimmed.find(". ");
                if let Some(pos) = dot_pos {
                    let num = &trimmed[..pos + 1];
                    let content = &trimmed[pos + 2..];
                    let indent = line.len() - line.trim_start().len();
                    let pad = " ".repeat(indent);
                    let mut li_spans = vec![Span::styled(format!("{pad}{num} "), Style::default().fg(C_ASST_PFX).add_modifier(Modifier::BOLD))];
                    li_spans.extend(inline_markdown_spans(content, body_color));
                    li_spans
                } else {
                    inline_markdown_spans(line, body_color)
                }
            // Markdown table row: | col | col | col |
            } else if trimmed.starts_with('|') {
                // Detect separator row: |---|---|  or  |:---:|---|
                let is_sep = trimmed.split('|').filter(|s| !s.is_empty()).all(|cell| {
                    cell.trim().chars().all(|c| c == '-' || c == ':' || c == ' ')
                });
                if is_sep {
                    vec![Span::styled(
                        "  ─────────────────────────────────────────────────".to_string(),
                        Style::default().fg(C_DIM),
                    )]
                } else {
                    // Data/header row: color pipe separators in accent, cells bold
                    let cells: Vec<&str> = trimmed.split('|').collect();
                    // cells[0] and cells[last] are empty (surrounding pipes) — skip them
                    let inner = if cells.first() == Some(&"") && cells.last() == Some(&"") {
                        &cells[1..cells.len() - 1]
                    } else {
                        &cells[..]
                    };
                    let mut spans: Vec<Span<'static>> = Vec::new();
                    for cell in inner {
                        spans.push(Span::styled(" │ ".to_string(), Style::default().fg(C_ASST_PFX)));
                        let trimmed_cell = cell.trim();
                        if !trimmed_cell.is_empty() {
                            // Apply inline markdown (bold, code, links) inside table cells
                            let cell_spans = inline_markdown_spans(trimmed_cell, C_BODY);
                            spans.extend(cell_spans);
                        }
                    }
                    spans.push(Span::styled(" │".to_string(), Style::default().fg(C_ASST_PFX)));
                    spans
                }
            } else {
                inline_markdown_spans(line, body_color)
            }
        };

        if trail_spin && is_last {
            body_spans.push(Span::styled(
                format!(" {spin}"),
                Style::default().fg(C_WARN),
            ));
        }

        let mut row = vec![leader];
        row.extend(body_spans);
        out.push(Line::from(row));
    }

    // Empty body: just the prefix glyph (possibly with spinner)
    if first {
        let mut row: Vec<Span<'static>> = vec![Span::styled(prefix, pfx_style)];
        if trail_spin {
            row.push(Span::styled(
                format!(" {spin}"),
                Style::default().fg(C_WARN),
            ));
        }
        out.push(Line::from(row));
    }

    // Separator line after each message: show response time + word count + cost.
    if duration_secs > 0.1 {
        let timing_str = if duration_secs >= 10.0 {
            format!("{:.0}s", duration_secs)
        } else {
            format!("{:.1}s", duration_secs)
        };
        let word_count = body.split_ascii_whitespace().count();
        let wc_str = if is_assistant && word_count > 5 {
            // Add "~N min read" for long responses (180 wpm reading speed)
            let read_min = word_count / 180;
            if read_min >= 1 {
                format!("  ·  ~{}w  ~{} min read", word_count, read_min)
            } else {
                format!("  ·  ~{}w", word_count)
            }
        } else {
            String::new()
        };
        let cost_str = if cost_delta_usd > 0.0 {
            format!("  ·  ${:.4}", cost_delta_usd)
        } else {
            String::new()
        };
        // Color timing badge by response speed: green (<5s) → amber (<15s) → red (≥15s)
        let timing_color = if !is_assistant {
            C_DIM
        } else if duration_secs < 5.0 {
            C_OK
        } else if duration_secs < 15.0 {
            C_WARN
        } else {
            C_ERR
        };
        out.push(Line::from(vec![
            Span::raw(CONT),
            Span::styled(
                format!("  ─  {timing_str}{wc_str}{cost_str}"),
                Style::default().fg(timing_color),
            ),
        ]));
    } else {
        out.push(Line::from(""));
    }
    out
}

// ── inline markdown spans ─────────────────────────────────────────────────────

/// Lightweight inline-markdown parser: headings, `inline code`, **bold**, *italic*.
///
/// Returns owned-string `Span<'static>` values so they can live in the
/// `Vec<Line<'static>>` that the renderer produces.
fn inline_markdown_spans(line: &str, body_color: Color) -> Vec<Span<'static>> {
    // Detect ATX heading: one-to-six '#' chars followed immediately by a space.
    let hash_count = line.len() - line.trim_start_matches('#').len();
    if hash_count >= 1 && hash_count <= 6 {
        let after = &line[hash_count..];
        if after.starts_with(' ') {
            let text = after.trim_start().to_string();
            // Level 1–2: bold purple; level 3–4: regular purple; level 5–6: indigo dim
            let (fg, mods) = match hash_count {
                1 => (C_HEAD_FG, Modifier::BOLD | Modifier::UNDERLINED),
                2 => (C_HEAD_FG, Modifier::BOLD),
                3 => (Color::Rgb(167, 139, 250), Modifier::empty()), // violet-400
                _ => (C_ASST_PFX, Modifier::empty()),                // indigo-400
            };
            let prefix_spans = (0..hash_count)
                .map(|_| Span::styled("▍", Style::default().fg(fg)))
                .collect::<Vec<_>>();
            let mut out = prefix_spans;
            out.push(Span::styled(" ", Style::default()));
            out.push(Span::styled(text, Style::default().fg(fg).add_modifier(mods)));
            return out;
        }
    }

    let mut out: Vec<Span<'static>> = Vec::new();
    let mut buf = String::new();
    let bytes = line.as_bytes();
    let mut i = 0;

    let flush_buf = |buf: &mut String, out: &mut Vec<Span<'static>>, color: Color| {
        if !buf.is_empty() {
            out.push(Span::styled(
                std::mem::take(buf),
                Style::default().fg(color),
            ));
        }
    };

    while i < bytes.len() {
        // Inline code `...`
        if bytes[i] == b'`' {
            flush_buf(&mut buf, &mut out, body_color);
            if let Some(end) = line[i + 1..].find('`') {
                out.push(Span::styled(
                    line[i + 1..i + 1 + end].to_string(),
                    Style::default().fg(C_CODE_FG).bg(C_CODE_BG),
                ));
                i += end + 2;
                continue;
            }
        }

        // Bold+italic ***...***  (must come before ** bold check)
        if i + 2 < bytes.len() && &bytes[i..i + 3] == b"***" {
            flush_buf(&mut buf, &mut out, body_color);
            if let Some(end) = line[i + 3..].find("***") {
                out.push(Span::styled(
                    line[i + 3..i + 3 + end].to_string(),
                    Style::default()
                        .fg(body_color)
                        .add_modifier(Modifier::BOLD | Modifier::ITALIC),
                ));
                i += end + 6;
                continue;
            }
        }

        // Bold **...**  (check before single-* italic)
        if i + 1 < bytes.len() && &bytes[i..i + 2] == b"**" {
            flush_buf(&mut buf, &mut out, body_color);
            if let Some(end) = line[i + 2..].find("**") {
                out.push(Span::styled(
                    line[i + 2..i + 2 + end].to_string(),
                    Style::default()
                        .fg(body_color)
                        .add_modifier(Modifier::BOLD),
                ));
                i += end + 4;
                continue;
            }
        }

        // Strikethrough ~~...~~
        if i + 1 < bytes.len() && &bytes[i..i + 2] == b"~~" {
            flush_buf(&mut buf, &mut out, body_color);
            if let Some(end) = line[i + 2..].find("~~") {
                out.push(Span::styled(
                    line[i + 2..i + 2 + end].to_string(),
                    Style::default()
                        .fg(C_DIM)
                        .add_modifier(Modifier::CROSSED_OUT),
                ));
                i += end + 4;
                continue;
            }
        }

        // Highlight ==text== → amber background (Obsidian/GitHub style)
        if i + 1 < bytes.len() && &bytes[i..i + 2] == b"==" {
            flush_buf(&mut buf, &mut out, body_color);
            if let Some(end) = line[i + 2..].find("==") {
                out.push(Span::styled(
                    line[i + 2..i + 2 + end].to_string(),
                    Style::default()
                        .fg(Color::Rgb(17, 24, 39))      // gray-900 foreground on amber
                        .bg(Color::Rgb(251, 191, 36)),    // amber-400 background
                ));
                i += end + 4;
                continue;
            }
        }

        // Keyboard shortcut <kbd>text</kbd> → styled badge
        if line[i..].starts_with("<kbd>") {
            if let Some(end) = line[i + 5..].find("</kbd>") {
                flush_buf(&mut buf, &mut out, body_color);
                let key_text = &line[i + 5..i + 5 + end];
                out.push(Span::styled(
                    format!("⌨ {key_text}"),
                    Style::default()
                        .fg(Color::Rgb(203, 213, 225))   // slate-300
                        .bg(Color::Rgb(30, 41, 59))      // slate-800
                        .add_modifier(Modifier::BOLD),
                ));
                i += end + 11; // "<kbd>".len() + "</kbd>".len()
                continue;
            }
        }

        // Italic *...*
        if bytes[i] == b'*' {
            flush_buf(&mut buf, &mut out, body_color);
            if let Some(end) = line[i + 1..].find('*') {
                out.push(Span::styled(
                    line[i + 1..i + 1 + end].to_string(),
                    Style::default()
                        .fg(body_color)
                        .add_modifier(Modifier::ITALIC),
                ));
                i += end + 2;
                continue;
            }
        }

        // Markdown link [text](url)
        if bytes[i] == b'[' {
            if let Some(text_end) = line[i + 1..].find("](") {
                let text = &line[i + 1..i + 1 + text_end];
                let after = &line[i + 2 + text_end..];
                if let Some(url_end) = after.find(')') {
                    let url = &after[..url_end];
                    flush_buf(&mut buf, &mut out, body_color);
                    // Linked text in brand color
                    out.push(Span::styled(text.to_string(), Style::default().fg(C_BRAND).add_modifier(Modifier::UNDERLINED)));
                    // Dim parenthetical URL (truncated if long)
                    if !url.is_empty() {
                        let url_display: String = if url.len() > 50 {
                            format!("({}…)", &url[..47])
                        } else {
                            format!("({url})")
                        };
                        out.push(Span::styled(url_display, Style::default().fg(C_DIM)));
                    }
                    i += text_end + url_end + 4; // [text](url) consumed
                    continue;
                }
            }
        }

        // URL: https:// or http://
        if i + 8 < bytes.len()
            && (line[i..].starts_with("https://") || line[i..].starts_with("http://"))
        {
            let rest = &line[i..];
            let url_end = rest
                .find(|c: char| c.is_whitespace() || matches!(c, ')' | ',' | '"' | '\'' | '>'))
                .unwrap_or(rest.len());
            let url = &rest[..url_end];
            if url.len() > 8 {
                flush_buf(&mut buf, &mut out, body_color);
                out.push(Span::styled(
                    url.to_string(),
                    Style::default()
                        .fg(C_ASST_PFX)
                        .add_modifier(Modifier::UNDERLINED),
                ));
                i += url_end;
                continue;
            }
        }

        // Bare file path: token starting with / or ~/ or ./ at word boundary
        let at_word_boundary = i == 0
            || matches!(bytes.get(i.saturating_sub(1)), Some(&b' ') | Some(&b'\t') | Some(&b'(') | Some(&b','));
        if at_word_boundary && (bytes[i] == b'/'
            || (bytes[i] == b'~' && bytes.get(i + 1) == Some(&b'/'))
            || (bytes[i] == b'.' && bytes.get(i + 1) == Some(&b'/')))
        {
            let rest = &line[i..];
            let path_end = rest
                .find(|c: char| c.is_whitespace() || matches!(c, ')' | ',' | '"' | '\'' | '>'))
                .unwrap_or(rest.len());
            let token = &rest[..path_end];
            if token.len() > 2 && (token.contains('/') || token.contains('.')) {
                flush_buf(&mut buf, &mut out, body_color);
                out.push(Span::styled(token.to_string(), Style::default().fg(C_CODE_FG)));
                i += path_end;
                continue;
            }
        }

        let ch = line[i..].chars().next().unwrap();
        buf.push(ch);
        i += ch.len_utf8();
    }

    flush_buf(&mut buf, &mut out, body_color);
    if out.is_empty() {
        out.push(Span::raw(String::new()));
    }
    out
}

// ── syntax highlighting ───────────────────────────────────────────────────────

/// Tokenize one line from a fenced code block into styled spans.
/// Handles: line comments, quoted strings (with backslash escapes), numeric literals,
/// and language keywords. Everything else gets the default code color (sky-300).
fn highlight_code_line(line: &str, lang: &str) -> Vec<Span<'static>> {
    // Full-line comment detection (cheaper than per-char scanning)
    let trimmed = line.trim_start();
    let is_line_comment = match lang {
        "rust" | "js" | "ts" | "javascript" | "typescript" | "java" | "c" | "cpp"
        | "go" | "swift" | "kotlin" | "cs" | "csharp" | "scala" =>
            trimmed.starts_with("//"),
        "python" | "ruby" | "rb" | "bash" | "sh" | "shell" | "toml" | "yaml"
        | "yml" | "r" | "perl" | "pl" | "makefile" | "dockerfile" =>
            trimmed.starts_with('#'),
        "sql" | "lua" | "haskell" | "hs" => trimmed.starts_with("--"),
        _ => trimmed.starts_with("//") || trimmed.starts_with('#'),
    };
    if is_line_comment {
        return vec![Span::styled(line.to_string(), Style::default().fg(C_SYN_CMT).bg(C_CODE_BG))];
    }

    // Diff/patch coloring: explicit lang tag OR auto-detect from line content
    let is_diff = matches!(lang, "diff" | "patch" | "udiff")
        || (lang.is_empty()
            && (line.starts_with("--- ") || line.starts_with("+++ ")
                || line.starts_with("@@ ") || line.starts_with("@@\t")));
    if is_diff {
        let color = match line.chars().next() {
            Some('+') => C_OK,
            Some('-') => C_ERR,
            Some('@') => C_ASST_PFX,
            _ => C_DIM,
        };
        return vec![Span::styled(line.to_string(), Style::default().fg(color).bg(C_CODE_BG))];
    }

    // Language keyword sets
    let keywords: &[&str] = match lang {
        "rust" => &[
            "fn", "let", "mut", "const", "static", "use", "pub", "mod", "impl",
            "struct", "enum", "trait", "type", "where", "for", "while", "loop",
            "if", "else", "match", "return", "true", "false", "self", "Self",
            "super", "crate", "move", "async", "await", "dyn", "ref", "in", "as",
            "unsafe", "extern", "break", "continue", "Box", "Vec", "Option",
            "Result", "Some", "None", "Ok", "Err",
        ],
        "python" => &[
            "def", "class", "import", "from", "return", "if", "elif", "else",
            "for", "while", "in", "not", "and", "or", "True", "False", "None",
            "with", "as", "try", "except", "finally", "raise", "pass", "break",
            "continue", "lambda", "yield", "global", "nonlocal", "assert", "del",
            "async", "await", "is", "print",
        ],
        "js" | "javascript" | "ts" | "typescript" => &[
            "function", "const", "let", "var", "return", "if", "else", "for",
            "while", "class", "import", "export", "from", "async", "await", "new",
            "this", "typeof", "instanceof", "true", "false", "null", "undefined",
            "switch", "case", "break", "continue", "try", "catch", "finally",
            "throw", "in", "of", "extends", "super", "static", "get", "set",
        ],
        "go" => &[
            "func", "var", "const", "type", "package", "import", "return", "if",
            "else", "for", "range", "switch", "case", "break", "continue", "go",
            "defer", "chan", "map", "interface", "struct", "true", "false", "nil",
            "make", "new", "append", "len", "cap", "select", "default",
        ],
        "bash" | "sh" | "shell" => &[
            "if", "then", "else", "elif", "fi", "for", "while", "do", "done",
            "case", "esac", "in", "function", "return", "exit", "echo", "export",
            "source", "local", "readonly", "declare",
        ],
        "java" | "kotlin" => &[
            "public", "private", "protected", "class", "interface", "extends",
            "implements", "import", "package", "return", "if", "else", "for",
            "while", "switch", "case", "break", "continue", "new", "this", "super",
            "static", "final", "void", "true", "false", "null", "try", "catch",
            "finally", "throw", "throws",
        ],
        _ => &[],
    };

    // Character-level scanner
    let chars: Vec<char> = line.chars().collect();
    let len = chars.len();
    let mut out: Vec<Span<'static>> = Vec::new();
    let mut buf = String::new();
    let mut i = 0;

    macro_rules! flush_buf {
        ($color:expr) => {
            if !buf.is_empty() {
                out.push(Span::styled(
                    std::mem::take(&mut buf),
                    Style::default().fg($color).bg(C_CODE_BG),
                ));
            }
        };
    }

    while i < len {
        let c = chars[i];

        // Quoted string: " or ' (with backslash escape handling)
        if c == '"' || c == '\'' {
            flush_buf!(C_CODE_FG);
            let quote = c;
            let mut s = String::new();
            s.push(c);
            i += 1;
            while i < len {
                let sc = chars[i];
                if sc == '\\' && i + 1 < len {
                    s.push(sc);
                    i += 1;
                    s.push(chars[i]);
                } else {
                    s.push(sc);
                    if sc == quote {
                        break;
                    }
                }
                i += 1;
            }
            i += 1;
            out.push(Span::styled(s, Style::default().fg(C_SYN_STR).bg(C_CODE_BG)));
            continue;
        }

        // Numeric literal: digit at start of token
        if c.is_ascii_digit() {
            let at_word_start = i == 0 || {
                let p = chars[i - 1];
                !p.is_alphanumeric() && p != '_'
            };
            if at_word_start {
                flush_buf!(C_CODE_FG);
                let mut s = String::new();
                while i < len
                    && (chars[i].is_ascii_alphanumeric()
                        || chars[i] == '.'
                        || chars[i] == '_'
                        || chars[i] == 'x'
                        || chars[i] == 'o'
                        || chars[i] == 'b')
                {
                    s.push(chars[i]);
                    i += 1;
                }
                out.push(Span::styled(s, Style::default().fg(C_SYN_NUM).bg(C_CODE_BG)));
                continue;
            }
        }

        // Keyword: alphabetic or underscore at word boundary
        if (c.is_alphabetic() || c == '_') && !keywords.is_empty() {
            let at_word_start = i == 0 || {
                let p = chars[i - 1];
                !p.is_alphanumeric() && p != '_'
            };
            if at_word_start {
                let mut matched_kw: Option<&str> = None;
                'kw: for &kw in keywords {
                    let kw_c: Vec<char> = kw.chars().collect();
                    let kl = kw_c.len();
                    if i + kl > len {
                        continue;
                    }
                    for (ki, &kch) in kw_c.iter().enumerate() {
                        if chars[i + ki] != kch {
                            continue 'kw;
                        }
                    }
                    // Must be a word boundary after
                    let after = i + kl;
                    if after < len && (chars[after].is_alphanumeric() || chars[after] == '_') {
                        continue 'kw;
                    }
                    matched_kw = Some(kw);
                    break;
                }
                if let Some(kw) = matched_kw {
                    flush_buf!(C_CODE_FG);
                    out.push(Span::styled(
                        kw.to_string(),
                        Style::default().fg(C_SYN_KW).bg(C_CODE_BG).add_modifier(Modifier::BOLD),
                    ));
                    i += kw.len();
                    continue;
                }
            }
        }

        buf.push(c);
        i += 1;
    }

    flush_buf!(C_CODE_FG);
    if out.is_empty() {
        out.push(Span::styled(String::new(), Style::default().fg(C_CODE_FG).bg(C_CODE_BG)));
    }
    out
}

// ── tool / fleet line rendering ───────────────────────────────────────────────

fn tool_type_icon(name: &str) -> &'static str {
    let n = name.to_lowercase();
    if n.contains("bash") || n.contains("exec") || n.contains("run") { return "⚡"; }
    if n.contains("write") || n.contains("edit") || n.contains("patch") { return "✎"; }
    if n.contains("read") || n.contains("cat") || n.contains("view") { return "◉"; }
    if n.contains("grep") || n.contains("search") || n.contains("find") { return "⌕"; }
    if n.contains("glob") || n.contains("ls") || n.contains("list") { return "⊞"; }
    if n.contains("web") || n.contains("fetch") || n.contains("http") { return "↗"; }
    if n.contains("sandbox") { return "⬡"; }
    if n.contains("agent") || n.contains("task") { return "◈"; }
    "◦"
}

fn tool_entry_to_lines(t: &ToolEntry, spin: &str) -> Vec<Line<'static>> {
    let (sym, color) = match &t.status {
        ToolStatus::Running => (spin.to_string(), C_WARN),
        ToolStatus::Ok(_) => ("✓".to_string(), C_OK),
        ToolStatus::Err(_) => ("✗".to_string(), C_ERR),
    };
    let icon = tool_type_icon(&t.name);
    let summary = if t.summary.is_empty() {
        String::new()
    } else {
        format!("  {}", truncate_chars(&t.summary, 45))
    };
    let timing = match t.elapsed_ms {
        Some(ms) if ms >= 1000 => format!("  {:.1}s", ms as f64 / 1000.0),
        Some(ms) if ms >= 10   => format!("  {}ms", ms),
        Some(_)                => String::new(), // sub-10ms: omit noise
        None => {
            // Still running: live elapsed ticker (recomputed every frame)
            let live_ms = t.start.elapsed().as_millis() as u64;
            if live_ms >= 1000 {
                format!("  {:.1}s…", live_ms as f64 / 1000.0)
            } else if live_ms >= 10 {
                format!("  {}ms…", live_ms)
            } else {
                String::new()
            }
        }
    };

    let is_running = matches!(t.status, ToolStatus::Running);
    let name_style = if is_running {
        Style::default().fg(color).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(color)
    };
    // Header line (always one line)
    let mut lines: Vec<Line<'static>> = vec![Line::from(vec![
        Span::styled(
            format!("  {sym} {icon} {}{}", t.name, summary),
            name_style,
        ),
        Span::styled(timing, Style::default().fg(C_DIM)),
    ])];

    // Preview: show up to 5 sub-lines with diff coloring for completed tools
    match &t.status {
        ToolStatus::Ok(preview) | ToolStatus::Err(preview) if !preview.is_empty() => {
            let is_err = matches!(&t.status, ToolStatus::Err(_));
            let preview_lines: Vec<&str> = preview.lines().collect();
            let show_n = preview_lines.len().min(8);
            for raw in &preview_lines[..show_n] {
                let (marker, line_color) = if raw.starts_with('+') {
                    ("+", C_OK)
                } else if raw.starts_with('-') {
                    ("-", C_ERR)
                } else if raw.starts_with('@') {
                    ("@", C_ASST_PFX)
                } else {
                    ("·", if is_err { C_ERR } else { C_DIM })
                };
                let body = raw.trim_start_matches(['+', '-', '@']).trim_start();
                lines.push(Line::from(Span::styled(
                    format!("     {} {}", marker, truncate_chars(body, 48)),
                    Style::default().fg(line_color),
                )));
            }
            if preview_lines.len() > 5 {
                lines.push(Line::from(Span::styled(
                    format!("     … {} more", preview_lines.len() - 5),
                    Style::default().fg(C_DIM),
                )));
            }
        }
        _ => {}
    }

    lines
}

fn fleet_entry_to_line(e: &FleetEntry) -> Line<'static> {
    let (sym, color) = match &e.status {
        FleetStatus::Running => ("◌", C_WARN),
        FleetStatus::Done => ("✓", C_OK),
        FleetStatus::Cancelled => ("⊘", C_DIM),
        FleetStatus::Error => ("✗", C_ERR),
    };
    let mut label = format!(
        "  {sym}  [{:>2}] {}",
        e.id,
        truncate_chars(&e.description, 26)
    );
    if let Some(p) = &e.preview {
        label.push_str("  —  ");
        label.push_str(&truncate_chars(p, 20));
    }
    Line::from(Span::styled(label, Style::default().fg(color)))
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Pull a human-readable message out of an LLM error string.
/// Handles upstream JSON blobs by extracting the innermost `"message":"…"` value;
/// falls back to truncating the raw string to 120 chars.
fn clean_error_message(raw: &str) -> String {
    for key in &[r#""message":""#, r#""msg":""#] {
        if let Some(pos) = raw.find(key) {
            let start = pos + key.len();
            if let Some(end) = raw[start..].find('"') {
                let msg = &raw[start..start + end];
                if !msg.is_empty() {
                    return msg.to_string();
                }
            }
        }
    }
    truncate_chars(raw, 120)
}

fn truncate_chars(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else {
        let t: String = chars[..max.saturating_sub(1)].iter().collect();
        format!("{t}…")
    }
}

fn shorten_path(path: &str, max: usize) -> String {
    if path.len() <= max {
        path.to_string()
    } else {
        let keep = max.saturating_sub(1);
        format!("…{}", &path[path.len().saturating_sub(keep)..])
    }
}

/// Returns a short human-friendly model name.
fn model_display_name(model: &str) -> String {
    let m = model.split('/').last().unwrap_or(model);
    // Map well-known Claude model IDs to friendly labels
    if m.contains("opus-4-7") || m.contains("opus-4.7") {
        return "Claude Opus 4.7".to_string();
    }
    if m.contains("opus-4") {
        return "Claude Opus 4".to_string();
    }
    if m.contains("sonnet-4-6") || m.contains("sonnet-4.6") {
        return "Claude Sonnet 4.6".to_string();
    }
    if m.contains("sonnet-4") {
        return "Claude Sonnet 4".to_string();
    }
    if m.contains("haiku-4-5") || m.contains("haiku-4.5") {
        return "Claude Haiku 4.5".to_string();
    }
    if m.contains("haiku-4") {
        return "Claude Haiku 4".to_string();
    }
    // Unknown model: strip vendor prefix, truncate
    m.chars().take(32).collect()
}

/// Returns the context window size (input tokens) for the given model.
pub fn model_context_window(model: &str) -> u64 {
    let m = model.to_lowercase();
    if m.contains("claude") {
        200_000 // all current Claude models have 200k context
    } else if m.contains("gpt-4") {
        128_000
    } else {
        200_000 // safe default
    }
}

fn fmt_tokens(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1000 {
        format!("{:.1}k", n as f64 / 1000.0)
    } else {
        n.to_string()
    }
}

fn perm_label(perm: &str) -> &'static str {
    let lower = perm.to_lowercase();
    if lower.contains("bypass") {
        "bypass"
    } else if lower.contains("autoedit") || lower.contains("auto_edit") {
        "auto-edit"
    } else {
        "default"
    }
}

// ── channels ──────────────────────────────────────────────────────────────────

pub fn channels() -> (
    mpsc::UnboundedSender<UiEvent>,
    mpsc::UnboundedReceiver<UiEvent>,
    mpsc::UnboundedSender<UiCommand>,
    mpsc::UnboundedReceiver<UiCommand>,
) {
    let (etx, erx) = mpsc::unbounded_channel();
    let (ctx, crx) = mpsc::unbounded_channel();
    (etx, erx, ctx, crx)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn new_state() -> UiState {
        UiState::new("m".into(), "s".into(), "p".into(), "~".into())
    }

    #[test]
    fn plain_renderer_accumulates_text() {
        let mut r = PlainRenderer::default();
        r.write_text("hello ");
        r.write_text("world");
        r.flush();
        assert_eq!(r.buf, "hello world");
    }

    #[test]
    fn plain_renderer_diffs_with_prefixes() {
        let mut r = PlainRenderer::default();
        r.write_diff("a\nb", "a\nc");
        assert!(r.buf.contains("- a\n- b\n+ a\n+ c\n"));
    }

    #[test]
    fn ui_state_apply_assistant_streams_then_finalises() {
        let mut s = new_state();
        s.apply(UiEvent::AssistantDelta("hel".into()));
        s.apply(UiEvent::AssistantDelta("lo".into()));
        match s.chat_lines.last().unwrap() {
            ChatLine::AssistantPartial(t) => assert_eq!(t, "hello"),
            _ => panic!("expected AssistantPartial"),
        }
        s.apply(UiEvent::AssistantDone("hello".into()));
        match s.chat_lines.last().unwrap() {
            ChatLine::Assistant(t, _, _) => assert_eq!(t, "hello"),
            _ => panic!("expected Assistant"),
        }
    }

    #[test]
    fn ui_state_tool_done_resolves_running_entry() {
        let mut s = new_state();
        s.apply(UiEvent::ToolStart {
            name: "Bash".into(),
            summary: "echo hi".into(),
        });
        s.apply(UiEvent::ToolDone {
            name: "Bash".into(),
            summary: "echo hi".into(),
            is_error: false,
            preview: "hi".into(),
        });
        assert!(matches!(s.tool_log[0].status, ToolStatus::Ok(_)));
    }

    #[test]
    fn error_event_pushes_system_note_and_clears_running() {
        let mut s = new_state();
        s.status_running = true;
        s.apply(UiEvent::Error("boom".into()));
        assert!(!s.status_running);
        assert_eq!(s.last_error.as_deref(), Some("boom"));
        assert!(matches!(s.chat_lines.last(), Some(ChatLine::SystemNote(_))));
    }

    #[test]
    fn truncate_chars_handles_unicode() {
        let s = "café";
        assert_eq!(truncate_chars(s, 10), "café");
        assert_eq!(truncate_chars(s, 3), "ca…");
    }

    #[test]
    fn inline_markdown_spans_heading() {
        let spans = inline_markdown_spans("## Hello world", C_BODY);
        // level-2 heading: 2 bar spans + 1 space + 1 text span = 4
        assert!(spans.len() >= 2);
        assert!(spans.iter().any(|s| s.style.fg == Some(C_HEAD_FG)));
    }

    #[test]
    fn inline_markdown_spans_code() {
        let spans = inline_markdown_spans("use `foo` here", C_BODY);
        // should have: "use ", "foo" (code), " here"
        assert!(spans.iter().any(|sp| sp.style.bg == Some(C_CODE_BG)));
    }
}
