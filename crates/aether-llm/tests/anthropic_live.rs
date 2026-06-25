//! Live Anthropic API smoke test.
//!
//! Skips silently with a printed note when no auth source is provided,
//! so `cargo test --workspace` stays green in CI / sandboxes. Two ways
//! to opt in:
//!
//!     # API key (sk-ant-api… via x-api-key header)
//!     ANTHROPIC_API_KEY=sk-... cargo test -p aether-llm --test anthropic_live -- --nocapture
//!
//!     # Claude Code OAuth (loads ~/.claude/.credentials.json)
//!     AETHER_TEST_OAUTH=1 cargo test -p aether-llm --test anthropic_live -- --nocapture
//!
//! Uses the cheapest model and a one-word reply to keep API spend minimal.

use aether_llm::{
    anthropic::AnthropicProvider, ContentBlock, LlmProvider, Message, MessagesRequest, StopReason,
};

const CHEAP_MODEL: &str = "claude-haiku-4-5-20251001";

#[tokio::test]
async fn live_anthropic_roundtrip_text_only() {
    let provider = if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        if key.trim().is_empty() {
            eprintln!("SKIPPED: ANTHROPIC_API_KEY is empty");
            return;
        }
        eprintln!("Using API key auth.");
        AnthropicProvider::new(key)
    } else if std::env::var("AETHER_TEST_OAUTH").is_ok() {
        eprintln!("Using Claude Code OAuth (from ~/.claude/.credentials.json).");
        match AnthropicProvider::from_claude_code_credentials() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("SKIPPED: could not load OAuth credentials: {e}");
                return;
            }
        }
    } else {
        eprintln!(
            "SKIPPED: no auth source — set ANTHROPIC_API_KEY (API key path) \
             or AETHER_TEST_OAUTH=1 (Claude Code OAuth path)"
        );
        return;
    };
    let req = MessagesRequest {
        model: CHEAP_MODEL.into(),
        system: Some(
            "You answer with exactly the single word 'pong' — nothing else, no punctuation.".into(),
        ),
        messages: vec![Message::user_text("ping")],
        max_tokens: 16,
        tools: vec![],
        stream: false,
    };

    let resp = provider
        .complete(req)
        .await
        .expect("live API call must succeed when key is valid");

    assert!(
        matches!(
            resp.stop_reason,
            StopReason::EndTurn | StopReason::MaxTokens | StopReason::StopSequence
        ),
        "unexpected stop_reason: {:?}",
        resp.stop_reason
    );

    let text = resp
        .content
        .iter()
        .find_map(|b| match b {
            ContentBlock::Text { text } => Some(text.clone()),
            _ => None,
        })
        .expect("response must contain at least one text block");

    eprintln!("Live API response text: {text:?}");
    assert!(
        text.to_lowercase().contains("pong"),
        "expected 'pong' in response, got: {text}"
    );
}
