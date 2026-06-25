//! LLM provider abstraction.
//!
//! Defines the `LlmProvider` trait + canonical request/response types
//! shaped after the Anthropic Messages API. The `anthropic` module ships
//! a live HTTP implementation; further back-ends (OpenAI-compatible, etc.)
//! drop into the same trait.

pub mod anthropic;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesRequest {
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    pub messages: Vec<Message>,
    pub max_tokens: u32,
    #[serde(default)]
    pub tools: Vec<ToolDef>,
    #[serde(default)]
    pub stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    /// Content blocks. A simple text-only user message is
    /// `vec![ContentBlock::Text { text: "..." }]`; tool results live in
    /// User-role messages as `ContentBlock::ToolResult` blocks.
    pub content: Vec<ContentBlock>,
}

impl Message {
    pub fn user_text(s: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: vec![ContentBlock::Text { text: s.into() }],
        }
    }
    pub fn assistant_text(s: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: vec![ContentBlock::Text { text: s.into() }],
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesResponse {
    pub content: Vec<ContentBlock>,
    pub stop_reason: StopReason,
    #[serde(default)]
    pub usage: Option<Usage>,
}

/// Token accounting from Anthropic's `usage` block. Cache fields are
/// optional and only present when prompt-caching is in use.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub input_tokens: u64,
    #[serde(default)]
    pub output_tokens: u64,
    #[serde(default)]
    pub cache_creation_input_tokens: u64,
    #[serde(default)]
    pub cache_read_input_tokens: u64,
}

impl Usage {
    pub fn add(&mut self, other: &Usage) {
        self.input_tokens += other.input_tokens;
        self.output_tokens += other.output_tokens;
        self.cache_creation_input_tokens += other.cache_creation_input_tokens;
        self.cache_read_input_tokens += other.cache_read_input_tokens;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(default)]
        is_error: bool,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
    Refusal,
    StopSequence,
    PauseTurn,
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("schema violation: {0}")]
    Schema(String),
    #[error("rate limited")]
    RateLimited,
    #[error("upstream {status}: {body}")]
    Upstream { status: u16, body: String },
}

/// Callback invoked for each text delta as a streamed response arrives.
/// Receives the new chunk of assistant text only; tool-use deltas are not
/// surfaced here (they're accumulated and present in the final response).
pub type TextDeltaSink = Box<dyn FnMut(&str) + Send>;

#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, req: MessagesRequest) -> Result<MessagesResponse, LlmError>;

    /// Complete with text-delta streaming. Default implementation calls
    /// `complete()` and emits the entire text as one chunk — providers
    /// override to implement real SSE streaming.
    async fn complete_streamed(
        &self,
        req: MessagesRequest,
        mut on_delta: TextDeltaSink,
    ) -> Result<MessagesResponse, LlmError> {
        let resp = self.complete(req).await?;
        for block in &resp.content {
            if let ContentBlock::Text { text } = block {
                on_delta(text);
            }
        }
        Ok(resp)
    }

    fn name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_reason_round_trips() {
        let json = serde_json::to_string(&StopReason::ToolUse).unwrap();
        let back: StopReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back, StopReason::ToolUse);
    }

    #[test]
    fn content_block_text_round_trips() {
        let cb = ContentBlock::Text {
            text: "hello".into(),
        };
        let s = serde_json::to_string(&cb).unwrap();
        assert!(s.contains(r#""type":"text""#));
    }
}
