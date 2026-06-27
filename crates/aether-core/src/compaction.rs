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

/// Maximum tokens we ask the summarizer to produce.
const SUMMARY_MAX_TOKENS: u32 = 2048;

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
                    let preview = r.content.lines().next().unwrap_or("").chars().take(120).collect::<String>();
                    out.push_str(&format!(
                        "TOOL_RESULT: {} ({})\n",
                        preview,
                        if r.is_error { "err" } else { "ok" }
                    ));
                }
            }
        }
    }
    out
}

/// Prompt the summarizer with. Asks for a 200-word digest preserving
/// decisions, in-progress work, key facts. Drops tool I/O minutiae.
fn summary_prompt(history_text: &str) -> String {
    format!(
        "You are summarizing an in-progress agent conversation so it fits in fewer tokens. \
         Produce a 200-word-or-fewer digest. Preserve: key facts and identifiers, decisions made, \
         the current goal, any in-progress task and what step it's on, uncommitted work. \
         Drop: redundant chatter, exact tool I/O text, repeated context. Use compact prose, no headers.\n\n\
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
    if std::env::var("AETHER_NO_COMPACT").ok().as_deref() == Some("1") {
        return Ok(false);
    }
    if !over_threshold(&session.usage_total, &session.config.model, COMPACTION_THRESHOLD_PCT) {
        return Ok(false);
    }
    // Need at least 4 items to be worth compacting (keep at least 2 in tail).
    if session.history.len() < 4 {
        return Ok(false);
    }

    // Keep the final third of history verbatim; summarize the head.
    let keep_count = std::cmp::max(2, session.history.len() / 3);
    let mut to_summarize_count = session.history.len() - keep_count;

    // The first item of the tail (index to_summarize_count) must be a User
    // message. Two failure modes if it is not:
    //   - ToolResults: the tail's tool_use_ids reference an Assistant that was
    //     drained into the head; Anthropic rejects the next API call with 400
    //     "unexpected tool_use_id found in tool_result blocks".
    //   - Assistant: produces consecutive assistant messages (also invalid).
    // Fix: walk the cut-point back toward the head until we land on a User item.
    while to_summarize_count > 1
        && !matches!(&session.history[to_summarize_count], ConversationItem::User(_))
    {
        to_summarize_count -= 1;
    }

    // If we still couldn't find a User item to snap to, skip this compaction
    // turn rather than emit an invalid message sequence.
    if !matches!(&session.history[to_summarize_count], ConversationItem::User(_)) {
        eprintln!("[compaction] skipped: no User boundary found for safe cut");
        return Ok(false);
    }

    let head: Vec<ConversationItem> = session.history.drain(0..to_summarize_count).collect();
    let history_text = serialize_history(&head);

    let req = MessagesRequest {
        model: session.config.model.clone(),
        system: None,
        messages: vec![Message::user_text(summary_prompt(&history_text))],
        max_tokens: SUMMARY_MAX_TOKENS,
        tools: vec![],
        stream: false,
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

    // Prepend a synthetic exchange: the user "asks for" context, the
    // assistant "provides" the summary. Putting it at index 0 keeps it
    // ahead of whatever tail we preserved.
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

    // Reset running totals: the next compaction can only fire once the
    // session accumulates threshold tokens again.
    session.usage_total = Usage::default();
    if let Some(u) = &resp.usage {
        session.usage_total.add(u);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// If no User boundary exists in the snapback range, compaction is skipped
    /// rather than producing an invalid message sequence.
    #[tokio::test]
    async fn maybe_compact_skips_when_no_user_snap_point() {
        use crate::context::{ConversationItem, RecordedToolResult, RecordedToolUse};
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

        // History where only index 0 is User — snapback cannot find a User at
        // index > 0, so compaction must be skipped entirely.
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
        assert!(!compacted, "must skip compaction when no safe User snap point exists");
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
