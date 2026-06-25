//! LLM provider abstraction.
//!
//! Defines the `LlmProvider` trait + canonical request/response types
//! shaped after the Anthropic Messages API. The `anthropic` module ships
//! a live HTTP implementation; further back-ends (OpenAI-compatible, etc.)
//! drop into the same trait.

pub mod anthropic;
pub mod azure;
pub mod bedrock;
pub mod vertex;

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

impl LlmError {
    /// User-readable explanation + suggested fix. Returned alongside the
    /// terse Debug/Display form. Centralises the "what does the user do
    /// when they see this" knowledge.
    pub fn actionable(&self) -> String {
        match self {
            LlmError::Transport(msg) => {
                if msg.contains("ANTHROPIC_API_KEY not set") {
                    "No auth source found. Either:\n  \
                     - Set ANTHROPIC_API_KEY (console API key), OR\n  \
                     - Run `claude` once to populate ~/.claude/.credentials.json".into()
                } else if msg.contains("token expired") {
                    "Your OAuth token has expired. Run `claude` once to refresh, \
                     or `aether doctor` to check expiry.".into()
                } else if msg.contains("HOME not set") {
                    "$HOME is not set in this environment. Set it or use \
                     ANTHROPIC_API_KEY directly.".into()
                } else if msg.contains("send:") || msg.contains("io error") {
                    format!("Network error talking to api.anthropic.com: {msg}.\n  \
                             Check connectivity and rerun. Aether retries 5x with backoff \
                             before surfacing this.")
                } else {
                    format!("Transport error: {msg}")
                }
            }
            LlmError::Schema(msg) => {
                format!("Response from server did not match expected shape: {msg}.\n  \
                         This usually means the API changed; check for an aether update.")
            }
            LlmError::RateLimited => {
                "Rate limited. For OAuth (Max-subscription) accounts, premium models \
                 (Opus / Sonnet) share a per-account bucket; Haiku has separate, larger \
                 quota. Try:\n  \
                 - `aether --model claude-haiku-4-5-20251001 --print ...`\n  \
                 - wait for the 5h window to reset (check anthropic-ratelimit-unified-5h-reset)\n  \
                 - switch to ANTHROPIC_API_KEY (Console billing, separate bucket)".into()
            }
            LlmError::Upstream { status, body } => match *status {
                401 => format!(
                    "Auth rejected (401): {body}.\n  \
                     Token may be expired. Run `claude` to refresh, or `aether doctor`."
                ),
                403 => format!(
                    "Forbidden (403): {body}.\n  \
                     Your account doesn't have access to this model or feature."
                ),
                404 => format!(
                    "Not found (404): {body}.\n  \
                     The model id may be wrong. List available models with `curl ... /v1/models`."
                ),
                413 => format!(
                    "Payload too large (413): {body}.\n  \
                     Shrink the prompt or split the work into multiple turns."
                ),
                429 => format!(
                    "Rate limited (429): {body}.\n  \
                     For OAuth Max accounts, premium models share one bucket; \
                     try Haiku or wait for the window to reset."
                ),
                529 => format!(
                    "Overloaded (529): {body}.\n  \
                     Anthropic is currently overloaded; aether already retried 5x with backoff."
                ),
                500..=599 => format!(
                    "Server error ({status}): {body}.\n  \
                     Transient; aether retried 5x. If it persists, check status.anthropic.com."
                ),
                _ => format!("Upstream {status}: {body}"),
            },
        }
    }
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
