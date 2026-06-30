//! Context compaction.
//!
//! Long sessions accumulate history until the next request exceeds the
//! model's context window and the provider returns 400. Compaction
//! summarizes the oldest portion of `session.history` into a single
//! synthetic exchange, freeing context budget.
//!
//! Trigger: cumulative `usage_total.input_tokens + output_tokens` exceeds
//! `compaction_threshold_pct * context_window_for_model(model)`.
//! Default threshold 0.80; default window 200_000 (Sonnet 4.6, Opus 4.7,
//! Haiku 4.5 all share this).
//!
//! Kill-switch: env `AETHER_NO_COMPACT=1` disables compaction unconditionally.
//!
//! Hysteresis: after a compaction, the running totals reset to just the
//! summary call's own usage. The next compaction can't fire until the
//! session accumulates threshold tokens again — preventing tight-loop
//! oscillation right at the boundary.

use crate::context::ConversationItem;
use crate::{AgentError, Session};
use aether_llm::{ContentBlock, Message, MessagesRequest, Usage};

/// Context window (in tokens) for the named model. Hard-coded constants
/// rather than a feature-detection call: this code runs in the hot path
/// of every turn and an API round-trip would dominate.
pub fn context_window_for_model(model: &str) -> u64 {
    let m = model.to_ascii_lowercase();
    // All current Anthropic Claude 4.x models ship a 200K context.
    if m.contains("opus") || m.contains("sonnet") || m.contains("haiku") || m.contains("fable") {
        200_000
    } else {
        200_000
    }
}

/// Fraction of the context window at which compaction triggers.
pub const COMPACTION_THRESHOLD_PCT: f64 = 0.80;

/// Maximum tokens we ask the summarizer to produce. Increased to 4096 to
/// give the structured 6-section prompt enough room to preserve error
/// messages, file paths, and current step without truncation.
const SUMMARY_MAX_TOKENS: u32 = 4096;

/// Returns true if cumulative usage exceeds `pct * window`.
pub fn over_threshold(usage: &Usage, model: &str, pct: f64) -> bool {
    let used = usage.input_tokens + usage.output_tokens;
    let window = context_window_for_model(model);
    let threshold = (window as f64 * pct) as u64;
    used >= threshold
}

/// Serialize the first N history items into a plain-text transcript the
/// summarizer can read. Tool inputs are abbreviated to their first 80
/// chars to avoid bloating the summary prompt.
pub fn serialize_history(items: &[ConversationItem]) -> String {
    let mut out = String::new();
    for item in items {
        match item {
            ConversationItem::User(s) => {
                out.push_str("USER: ");
                out.push_str(s);
                out.push('\n');
            }
            ConversationItem::Assistant { text, tool_uses } => {
                if let Some(t) = text {
                    out.push_str("ASSISTANT: ");
                    out.push_str(t);
                    out.push('\n');
                }
                for tu in tool_uses {
                    let input_preview: String =
                        tu.input.to_string().chars().take(80).collect();
                    out.push_str(&format!("TOOL_USE: {} {}\n", tu.name, input_preview));
                }
            }
            ConversationItem::ToolResults(rs) => {
                for r in rs {
                    if r.is_error {
                        // Errors get up to 5 lines (400 chars total) so the
                        // summarizer can include the actual error message in
                        // the ERRORS section — not just that an error occurred.
                        let err_preview: String = r
                            .content
                            .lines()
                            .take(5)
                            .collect::<Vec<_>>()
                            .join(" | ")
                            .chars()
                            .take(400)
                            .collect();
                        out.push_str(&format!("TOOL_ERROR: {err_preview}\n"));
                    } else {
                        let preview = r.content.lines().next().unwrap_or("").chars().take(120).collect::<String>();
                        out.push_str(&format!("TOOL_RESULT: {preview} (ok)\n"));
                    }
                }
            }
        }
    }
    out
}

/// Structured 6-section summary prompt. Each section has a labelled heading
/// so critical signal (error messages, file paths, next step) is never lost
/// in prose compression. The agent reads this on every turn after compaction.
pub fn summary_prompt(history_text: &str) -> String {
    format!(
        "Summarize this in-progress agent conversation so it fits in fewer tokens.\n\
         Use EXACTLY these six labelled sections — no other format. One header per line:\n\n\
         GOAL: [one sentence — what the user asked for or what is being built]\n\
         PROGRESS: [what was completed; which files changed; test results if any]\n\
         CURRENT-STEP: [the exact task or command in progress when this summary was cut]\n\
         ERRORS: [any unresolved tool errors, build failures, or test failures — \
                  include exact error messages and file:line references if present]\n\
         KEY-IDS: [file paths, function names, variable names, PR numbers, and \
                   other identifiers referenced in this session]\n\
         NEXT-ACTION: [what the agent was about to do next]\n\n\
         Write NONE for a section if truly nothing belongs there. \
         Keep each section to 1-3 lines. Do not add extra sections or commentary.\n\n\
         Conversation transcript:\n{history_text}"
    )
}

/// Run compaction. Splits `session.history` into a head to summarize and
/// a tail to keep verbatim, calls the LLM once for the summary, then
/// replaces the head with a synthetic user→assistant pair carrying the
/// summary text. Resets `session.usage_total` to just the summary call's
/// own cost (acts as a per-compaction hysteresis).
///
/// Returns `Ok(true)` if a compaction ran, `Ok(false)` if conditions
/// weren't met (history too short, kill-switch on, below threshold).
pub async fn maybe_compact(session: &mut Session) -> Result<bool, AgentError> {
    compact_inner(session, false).await
}

/// Force-compact regardless of the usage threshold. Still respects the
/// kill-switch (`AETHER_NO_COMPACT=1`) and the minimum-history guard.
/// Useful for the `/compact full` UI command.
pub async fn force_compact(session: &mut Session) -> Result<bool, AgentError> {
    compact_inner(session, true).await
}

async fn compact_inner(session: &mut Session, force: bool) -> Result<bool, AgentError> {
    if std::env::var("AETHER_NO_COMPACT").ok().as_deref() == Some("1") {
        return Ok(false);
    }
    // Adaptive threshold: lower from 80% to 70% when the agent has consecutive
    // tool errors. A stuck agent needs clean context headroom for recovery more
    // than a healthy session does.
    let has_stuck_tools = session
        .plan
        .tool_error_counts
        .values()
        .any(|&n| n >= crate::planner::TOOL_ERROR_THRESHOLD);
    let threshold = if has_stuck_tools {
        COMPACTION_THRESHOLD_PCT - 0.10
    } else {
        COMPACTION_THRESHOLD_PCT
    };
    if !force && !over_threshold(&session.usage_total, &session.config.model, threshold) {
        return Ok(false);
    }
    // Need at least 4 items to be worth compacting (keep at least 2 in tail).
    if session.history.len() < 4 {
        return Ok(false);
    }

    // Keep the final third of history verbatim; summarize the head.
    let keep_count = std::cmp::max(2, session.history.len() / 3);
    let initial_cut = session.history.len() - keep_count;

    // Two-strategy cut-point selection. The first item of the tail must form
    // a valid continuation after whichever synthetic prefix we insert.
    //
    // Strategy 1 — snap to the nearest ConversationItem::User.
    //   Insert a synthetic User+Assistant pair. The tail starts with an
    //   original User message, producing:
    //   User(summary) → Assistant(summary) → User(tail) → ...  (valid)
    //
    // Strategy 2 — snap to the nearest ConversationItem::Assistant (fallback
    //   for sessions with a single User turn, e.g. long `--print` audits).
    //   Insert only a synthetic User(summary). The tail starts with an
    //   existing Assistant whose tool_use_ids are owned by the ToolResults
    //   immediately following it in the tail — no orphaned ids:
    //   User(summary) → Assistant(tail) → ToolResults(tail) → ... (valid)
    //
    // If neither strategy finds a boundary, skip this compaction turn.
    let (cut, use_synthetic_assistant) = {
        let mut c = initial_cut;
        while c > 1 && !matches!(&session.history[c], ConversationItem::User(_)) {
            c -= 1;
        }
        if matches!(&session.history[c], ConversationItem::User(_)) {
            (c, true)
        } else {
            let mut c2 = initial_cut;
            while c2 > 1 && !matches!(&session.history[c2], ConversationItem::Assistant { .. }) {
                c2 -= 1;
            }
            if matches!(&session.history[c2], ConversationItem::Assistant { .. }) {
                (c2, false)
            } else {
                eprintln!("[compaction] skipped: no safe boundary found");
                return Ok(false);
            }
        }
    };

    let head: Vec<ConversationItem> = session.history.drain(0..cut).collect();
    let history_text = serialize_history(&head);

    let req = MessagesRequest {
        model: session.config.model.clone(),
        system: None,
        messages: vec![Message::user_text(summary_prompt(&history_text))],
        max_tokens: SUMMARY_MAX_TOKENS,
        tools: vec![],
        stream: false,
        thinking: None,
        temperature: None,
    };
    let resp = session.llm.complete(req).await?;
    let summary: String = resp
        .content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();

    if use_synthetic_assistant {
        // Strategy 1: tail starts with User → insert User+Assistant pair.
        session.history.insert(
            0,
            ConversationItem::User(
                "[CONTEXT SUMMARY OF EARLIER TURNS — refer to this when answering]".into(),
            ),
        );
        session.history.insert(
            1,
            ConversationItem::Assistant {
                text: Some(summary),
                tool_uses: Vec::new(),
            },
        );
    } else {
        // Strategy 2: tail starts with existing Assistant → insert only User.
        // Embedding the summary text in the User message avoids an orphaned
        // Assistant-with-no-tool-results at the splice point.
        session.history.insert(
            0,
            ConversationItem::User(format!(
                "[CONTEXT SUMMARY OF EARLIER TURNS — refer to this when answering]\n\n{summary}"
            )),
        );
    }

    // Reset running totals: the next compaction can only fire once the
    // session accumulates threshold tokens again.
    session.usage_total = Usage::default();
    if let Some(u) = &resp.usage {
        session.usage_total.add(u);
    }

    // Signal the TUI driver so it can show a compaction notice.
    session.compaction_happened = true;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_prompt_contains_all_six_sections() {
        let p = summary_prompt("USER: hi\nASSISTANT: hello\n");
        for section in &["GOAL:", "PROGRESS:", "CURRENT-STEP:", "ERRORS:", "KEY-IDS:", "NEXT-ACTION:"] {
            assert!(
                p.contains(section),
                "summary_prompt missing section {section}. Got:\n{p}"
            );
        }
    }

    #[test]
    fn context_window_known_families() {
        assert_eq!(context_window_for_model("claude-opus-4-7"), 200_000);
        assert_eq!(context_window_for_model("claude-sonnet-4-6"), 200_000);
        assert_eq!(context_window_for_model("claude-haiku-4-5-20251001"), 200_000);
        // Unknown model defaults to 200K (current Anthropic floor); explicit
        // future bump would adjust the table.
        assert_eq!(context_window_for_model("gpt-5"), 200_000);
    }

    #[test]
    fn over_threshold_fires_at_80_pct() {
        let mut u = Usage::default();
        // 159_999 < 160_000 (80% of 200K).
        u.input_tokens = 159_999;
        assert!(!over_threshold(&u, "claude-sonnet-4-6", 0.80));
        u.input_tokens = 160_000;
        assert!(over_threshold(&u, "claude-sonnet-4-6", 0.80));
    }

    #[test]
    fn over_threshold_counts_input_and_output() {
        let mut u = Usage::default();
        u.input_tokens = 100_000;
        u.output_tokens = 100_000;
        assert!(over_threshold(&u, "claude-sonnet-4-6", 0.80));
    }

    #[test]
    fn over_threshold_ignores_cache_tokens() {
        // Cache tokens are bookkeeping only — they don't burn fresh context
        // budget on the same response cycle, so they MUST NOT contribute
        // to the compaction trigger.
        let mut u = Usage::default();
        u.cache_creation_input_tokens = 500_000;
        u.cache_read_input_tokens = 500_000;
        assert!(!over_threshold(&u, "claude-sonnet-4-6", 0.80));
    }

    #[test]
    fn serialize_history_errors_get_multi_line_prefix() {
        use crate::context::RecordedToolResult;
        let items = vec![ConversationItem::ToolResults(vec![
            RecordedToolResult {
                tool_use_id: "t1".into(),
                content: "line1\nline2\nline3".into(),
                is_error: true,
            },
            RecordedToolResult {
                tool_use_id: "t2".into(),
                content: "success output".into(),
                is_error: false,
            },
        ])];
        let text = serialize_history(&items);
        assert!(text.contains("TOOL_ERROR:"), "error prefix missing: {text}");
        assert!(text.contains("line1"), "line1 missing: {text}");
        assert!(text.contains("line2"), "line2 missing: {text}");
        assert!(text.contains("TOOL_RESULT: success output (ok)"), "ok result missing: {text}");
        assert!(!text.contains("TOOL_ERROR: success"), "ok result wrongly flagged as error: {text}");
    }

    #[test]
    fn serialize_history_renders_each_role() {
        let items = vec![
            ConversationItem::User("hi".into()),
            ConversationItem::Assistant {
                text: Some("hello".into()),
                tool_uses: Vec::new(),
            },
        ];
        let text = serialize_history(&items);
        assert!(text.contains("USER: hi"));
        assert!(text.contains("ASSISTANT: hello"));
    }

    #[tokio::test]
    async fn maybe_compact_below_threshold_does_nothing() {
        use crate::mock::{MockLlmProvider, ENV_TEST_LOCK};
        use crate::{Session, SessionConfig};
        use aether_overlay::{Fable5Overlay, OverlayConfig};
        use aether_selfcheck::Gate;
        use aether_tools::ToolRegistry;
        use std::sync::Arc;

        // Hold the lock so the kill-switch test cannot race AETHER_NO_COMPACT=1
        // into our environment while we're below threshold.
        let _guard = ENV_TEST_LOCK.lock().expect("env lock");
        let llm = Arc::new(MockLlmProvider::new());
        let session_config = SessionConfig {
            model: "claude-sonnet-4-6".into(),
            ..SessionConfig::default()
        };
        let overlay = Fable5Overlay::new(OverlayConfig::default());
        let gate = Gate::new(Vec::new()).expect("gate");
        let tools = ToolRegistry::new();
        let mut session = Session::new(session_config, overlay, llm.clone(), gate, tools);

        // Below 80% — must not call the model.
        session.usage_total.input_tokens = 50_000;
        let compacted = maybe_compact(&mut session).await.expect("compact");
        assert!(!compacted, "should NOT compact below threshold");
        assert_eq!(llm.calls().len(), 0);
    }

    #[tokio::test]
    async fn maybe_compact_above_threshold_summarizes_and_resets() {
        use crate::context::{ConversationItem, RecordedToolResult, RecordedToolUse};
        use crate::mock::{MockLlmProvider, ENV_TEST_LOCK};
        use crate::{Session, SessionConfig};
        use aether_llm::{ContentBlock, MessagesResponse, StopReason};
        use aether_overlay::{Fable5Overlay, OverlayConfig};
        use aether_selfcheck::Gate;
        use aether_tools::ToolRegistry;
        use std::sync::Arc;

        // Hold the lock so the kill-switch test cannot race AETHER_NO_COMPACT=1
        // into our environment while we expect the LLM call to fire.
        let _guard = ENV_TEST_LOCK.lock().expect("env lock");
        let llm = Arc::new(MockLlmProvider::new());
        llm.push(MessagesResponse {
            content: vec![ContentBlock::Text {
                text: "Discussed widget refactor. Decided to ship in two PRs.".into(),
            }],
            stop_reason: StopReason::EndTurn,
            usage: Some(Usage {
                input_tokens: 5_000,
                output_tokens: 200,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            }),
        });

        let session_config = SessionConfig {
            model: "claude-sonnet-4-6".into(),
            ..SessionConfig::default()
        };
        let overlay = Fable5Overlay::new(OverlayConfig::default());
        let gate = Gate::new(Vec::new()).expect("gate");
        let tools = ToolRegistry::new();
        let mut session = Session::new(session_config, overlay, llm.clone(), gate, tools);

        // Seed at 90% usage (above 80% threshold) and a 6-item history.
        session.usage_total.input_tokens = 180_000;
        session.history = vec![
            ConversationItem::User("first message".into()),
            ConversationItem::Assistant {
                text: Some("first reply".into()),
                tool_uses: vec![RecordedToolUse {
                    id: "t1".into(),
                    name: "Read".into(),
                    input: serde_json::json!({"path": "a.txt"}),
                }],
            },
            ConversationItem::ToolResults(vec![RecordedToolResult {
                tool_use_id: "t1".into(),
                content: "contents of a.txt".into(),
                is_error: false,
            }]),
            ConversationItem::User("second message".into()),
            ConversationItem::Assistant {
                text: Some("second reply".into()),
                tool_uses: Vec::new(),
            },
            ConversationItem::User("third message".into()),
        ];

        let compacted = maybe_compact(&mut session).await.expect("compact");
        assert!(compacted, "should compact above threshold");

        // History shrunk: head replaced by synthetic User+Assistant pair.
        // Original len was 6; keep_count = 6/3 = 2; initial to_summarize = 4.
        // history[4] = Assistant → snap back → history[3] = User → cut at 3.
        // drain 3 items; insert 2 synthetic → 5 items total.
        assert_eq!(session.history.len(), 5);
        match &session.history[0] {
            ConversationItem::User(s) => assert!(s.contains("CONTEXT SUMMARY")),
            other => panic!("expected User summary marker, got {:?}", other),
        }
        match &session.history[1] {
            ConversationItem::Assistant { text: Some(t), .. } => {
                assert!(t.contains("widget refactor"), "summary text missing: {t}")
            }
            other => panic!("expected Assistant summary, got {:?}", other),
        }
        // Snap-back ensures tail[0] is User, not Assistant or ToolResults.
        match &session.history[2] {
            ConversationItem::User(s) => assert_eq!(s, "second message"),
            other => panic!("expected User as first tail item, got {:?}", other),
        }
        match &session.history[3] {
            ConversationItem::Assistant { text: Some(t), .. } => assert_eq!(t, "second reply"),
            other => panic!("expected preserved Assistant tail item, got {:?}", other),
        }

        // Usage reset to just the summarization call's own cost.
        assert_eq!(session.usage_total.input_tokens, 5_000);
        assert_eq!(session.usage_total.output_tokens, 200);

        // Exactly one provider call was made.
        assert_eq!(llm.calls().len(), 1);
    }

    /// Regression test: tail must not start with ToolResults.
    /// Before the snap-back fix, `to_summarize_count` could land on a ToolResults
    /// item, producing orphaned tool_use_ids → Anthropic 400.
    #[tokio::test]
    async fn maybe_compact_tail_never_starts_with_tool_results() {
        use crate::context::{ConversationItem, RecordedToolResult, RecordedToolUse};
        use crate::mock::{MockLlmProvider, ENV_TEST_LOCK};
        use crate::{Session, SessionConfig};
        use aether_llm::{ContentBlock, MessagesResponse, StopReason};
        use aether_overlay::{Fable5Overlay, OverlayConfig};
        use aether_selfcheck::Gate;
        use aether_tools::ToolRegistry;
        use std::sync::Arc;

        let _guard = ENV_TEST_LOCK.lock().expect("env lock");
        let llm = Arc::new(MockLlmProvider::new());
        llm.push(MessagesResponse {
            content: vec![ContentBlock::Text { text: "summary".into() }],
            stop_reason: StopReason::EndTurn,
            usage: Some(Usage { input_tokens: 1_000, output_tokens: 50,
                cache_creation_input_tokens: 0, cache_read_input_tokens: 0 }),
        });

        let session_config = SessionConfig { model: "claude-sonnet-4-6".into(), ..SessionConfig::default() };
        let overlay = Fable5Overlay::new(OverlayConfig::default());
        let gate = Gate::new(Vec::new()).expect("gate");
        let tools = ToolRegistry::new();
        let mut session = Session::new(session_config, overlay, llm.clone(), gate, tools);
        session.usage_total.input_tokens = 180_000;

        // 6 items where the naive cut (index 4) would land on ToolResults.
        // Pattern: User, Assistant{t1}, ToolResults{t1}, User, Assistant{t2}, ToolResults{t2}
        session.history = vec![
            ConversationItem::User("msg1".into()),
            ConversationItem::Assistant {
                text: Some("reply1".into()),
                tool_uses: vec![RecordedToolUse { id: "t1".into(), name: "Read".into(), input: serde_json::json!({}) }],
            },
            ConversationItem::ToolResults(vec![RecordedToolResult { tool_use_id: "t1".into(), content: "r1".into(), is_error: false }]),
            ConversationItem::User("msg2".into()),
            ConversationItem::Assistant {
                text: Some("reply2".into()),
                tool_uses: vec![RecordedToolUse { id: "t2".into(), name: "Read".into(), input: serde_json::json!({}) }],
            },
            ConversationItem::ToolResults(vec![RecordedToolResult { tool_use_id: "t2".into(), content: "r2".into(), is_error: false }]),
        ];

        let compacted = maybe_compact(&mut session).await.expect("compact");
        assert!(compacted, "should compact above threshold");

        // Tail first item (index 2 after synthetic pair insert) must be User.
        match &session.history[2] {
            ConversationItem::User(_) => {}
            other => panic!("tail must start with User after snap-back, got {:?}", other),
        }
    }

    /// Strategy 2: when no User snap point exists, compact using the nearest
    /// Assistant boundary. Single-turn --print sessions (one User at index 0,
    /// many tool rounds) hit this path. The tail starts with an existing
    /// Assistant so its tool_use_ids are self-referential; the synthetic prefix
    /// is a single User(summary) item.
    #[tokio::test]
    async fn maybe_compact_falls_back_to_assistant_boundary() {
        use crate::context::{ConversationItem, RecordedToolResult, RecordedToolUse};
        use crate::mock::{MockLlmProvider, ENV_TEST_LOCK};
        use crate::{Session, SessionConfig};
        use aether_llm::{ContentBlock, MessagesResponse, StopReason};
        use aether_overlay::{Fable5Overlay, OverlayConfig};
        use aether_selfcheck::Gate;
        use aether_tools::ToolRegistry;
        use std::sync::Arc;

        let _guard = ENV_TEST_LOCK.lock().expect("env lock");
        let llm = Arc::new(MockLlmProvider::new());
        llm.push(MessagesResponse {
            content: vec![ContentBlock::Text { text: "Discussed widget refactor.".into() }],
            stop_reason: StopReason::EndTurn,
            usage: Some(Usage { input_tokens: 1_000, output_tokens: 50,
                cache_creation_input_tokens: 0, cache_read_input_tokens: 0 }),
        });

        let session_config = SessionConfig { model: "claude-sonnet-4-6".into(), ..SessionConfig::default() };
        let overlay = Fable5Overlay::new(OverlayConfig::default());
        let gate = Gate::new(Vec::new()).expect("gate");
        let tools = ToolRegistry::new();
        let mut session = Session::new(session_config, overlay, llm.clone(), gate, tools);
        session.usage_total.input_tokens = 180_000;

        // Single-turn session: only one User message (at index 0).
        // No intermediate User messages → Strategy 1 snap-back finds nothing.
        // Strategy 2 fallback should fire, cutting before the nearest Assistant.
        session.history = vec![
            ConversationItem::User("only user msg".into()),
            ConversationItem::Assistant {
                text: Some("reply".into()),
                tool_uses: vec![RecordedToolUse { id: "t1".into(), name: "Read".into(), input: serde_json::json!({}) }],
            },
            ConversationItem::ToolResults(vec![RecordedToolResult { tool_use_id: "t1".into(), content: "r1".into(), is_error: false }]),
            ConversationItem::Assistant {
                text: Some("reply2".into()),
                tool_uses: vec![RecordedToolUse { id: "t2".into(), name: "Read".into(), input: serde_json::json!({}) }],
            },
            ConversationItem::ToolResults(vec![RecordedToolResult { tool_use_id: "t2".into(), content: "r2".into(), is_error: false }]),
            ConversationItem::Assistant { text: Some("reply3".into()), tool_uses: Vec::new() },
        ];

        let compacted = maybe_compact(&mut session).await.expect("compact");
        assert!(compacted, "Strategy 2 should compact (no User boundary, but Assistant boundary exists)");
        assert_eq!(llm.calls().len(), 1, "one summarization LLM call");

        // Tail starts at the Assistant that was found as the Strategy 2 boundary.
        // Synthetic prefix is a single User(summary) item embedding the summary text.
        match &session.history[0] {
            ConversationItem::User(s) => {
                assert!(s.contains("CONTEXT SUMMARY"), "synthetic User must carry summary header");
                assert!(s.contains("widget refactor"), "synthetic User must contain summary body");
            }
            other => panic!("expected User(summary) as index 0, got {:?}", other),
        }
        // Index 1 must be the original Assistant from the tail (Strategy 2: no synthetic Assistant).
        match &session.history[1] {
            ConversationItem::Assistant { .. } => {}
            other => panic!("Strategy 2 tail must start with original Assistant, got {:?}", other),
        }
    }

    /// If neither User nor Assistant boundaries exist in the search range,
    /// compaction is skipped rather than producing an invalid message sequence.
    /// (Pathological case — would not occur in normal conversation flow.)
    #[tokio::test]
    async fn maybe_compact_skips_when_no_boundary_at_all() {
        use crate::context::{ConversationItem, RecordedToolResult};
        use crate::mock::{MockLlmProvider, ENV_TEST_LOCK};
        use crate::{Session, SessionConfig};
        use aether_overlay::{Fable5Overlay, OverlayConfig};
        use aether_selfcheck::Gate;
        use aether_tools::ToolRegistry;
        use std::sync::Arc;

        let _guard = ENV_TEST_LOCK.lock().expect("env lock");
        let llm = Arc::new(MockLlmProvider::new());

        let session_config = SessionConfig { model: "claude-sonnet-4-6".into(), ..SessionConfig::default() };
        let overlay = Fable5Overlay::new(OverlayConfig::default());
        let gate = Gate::new(Vec::new()).expect("gate");
        let tools = ToolRegistry::new();
        let mut session = Session::new(session_config, overlay, llm.clone(), gate, tools);
        session.usage_total.input_tokens = 180_000;

        // Pathological: history contains only User and ToolResults items —
        // no intermediate User items > index 0 (Strategy 1 fails at index 1)
        // and no Assistant items anywhere in the search range (Strategy 2 fails).
        // Strategy 1 WOULD find User at index 0, but index 0 means cut=0 which
        // drains nothing — so this case is handled by the fact that the walk
        // stops at c>1, i.e. minimum c is 1. history[1] here is ToolResults,
        // not User, so Strategy 1 fails. Then Strategy 2 walks and finds no
        // Assistant either.
        session.history = vec![
            ConversationItem::User("msg".into()),
            ConversationItem::ToolResults(vec![RecordedToolResult { tool_use_id: "t1".into(), content: "r1".into(), is_error: false }]),
            ConversationItem::ToolResults(vec![RecordedToolResult { tool_use_id: "t2".into(), content: "r2".into(), is_error: false }]),
            ConversationItem::ToolResults(vec![RecordedToolResult { tool_use_id: "t3".into(), content: "r3".into(), is_error: false }]),
            ConversationItem::ToolResults(vec![RecordedToolResult { tool_use_id: "t4".into(), content: "r4".into(), is_error: false }]),
            ConversationItem::ToolResults(vec![RecordedToolResult { tool_use_id: "t5".into(), content: "r5".into(), is_error: false }]),
        ];

        let compacted = maybe_compact(&mut session).await.expect("compact");
        assert!(!compacted, "must skip when neither User nor Assistant boundary exists");
        assert_eq!(llm.calls().len(), 0, "no LLM call when compaction skipped");
    }

    #[tokio::test]
    async fn maybe_compact_kill_switch_blocks_compaction() {
        use crate::mock::{MockLlmProvider, ENV_TEST_LOCK};
        use crate::{Session, SessionConfig};
        use aether_overlay::{Fable5Overlay, OverlayConfig};
        use aether_selfcheck::Gate;
        use aether_tools::ToolRegistry;
        use std::sync::Arc;

        // Serialize env-var writes across all tests in this binary.
        let _guard = ENV_TEST_LOCK.lock().expect("env lock");
        std::env::set_var("AETHER_NO_COMPACT", "1");
        let llm = Arc::new(MockLlmProvider::new());
        let session_config = SessionConfig {
            model: "claude-sonnet-4-6".into(),
            ..SessionConfig::default()
        };
        let overlay = Fable5Overlay::new(OverlayConfig::default());
        let gate = Gate::new(Vec::new()).expect("gate");
        let tools = ToolRegistry::new();
        let mut session = Session::new(session_config, overlay, llm.clone(), gate, tools);
        session.usage_total.input_tokens = 200_000; // Way above threshold.
        let compacted = maybe_compact(&mut session).await.expect("compact");
        std::env::remove_var("AETHER_NO_COMPACT");
        assert!(!compacted, "kill-switch must block compaction");
        assert_eq!(llm.calls().len(), 0);
    }
}
