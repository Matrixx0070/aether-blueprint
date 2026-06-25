//! Google Cloud Vertex AI provider for Anthropic models.
//!
//! Non-streaming: POST `.../models/{model}:rawPredict`
//! Streaming:     POST `.../models/{model}:streamRawPredict` — SSE response,
//! same delta JSON shape as the Anthropic native streaming API.
//!
//! Auth: Bearer token from `VERTEX_ACCESS_TOKEN` (or `GCP_ACCESS_TOKEN`).
//! Obtain with `gcloud auth print-access-token`. Auto-rotation via ADC /
//! service-account files is B4.
//!
//! Region: `VERTEX_REGION` (default `us-central1`).
//! Project: `VERTEX_PROJECT` (or `GCLOUD_PROJECT` / `GOOGLE_CLOUD_PROJECT`).

use crate::{
    ContentBlock, LlmError, LlmProvider, MessagesRequest, MessagesResponse, StopReason,
    TextDeltaSink, Usage,
};
use async_trait::async_trait;
use futures_util::StreamExt;
use std::time::Duration;

const DEFAULT_REGION: &str = "us-central1";
const VERTEX_ANTHROPIC_VERSION: &str = "vertex-2023-10-16";
const DEFAULT_TIMEOUT_SECS: u64 = 300;

pub struct VertexProvider {
    access_token: String,
    project: String,
    region: String,
    client: reqwest::Client,
}

impl VertexProvider {
    /// Construct from env: `VERTEX_ACCESS_TOKEN` (or `GCP_ACCESS_TOKEN`),
    /// `VERTEX_PROJECT` (or `GCLOUD_PROJECT`), `VERTEX_REGION` (default
    /// `us-central1`).
    pub fn from_env() -> Result<Self, LlmError> {
        let access_token = std::env::var("VERTEX_ACCESS_TOKEN")
            .or_else(|_| std::env::var("GCP_ACCESS_TOKEN"))
            .map_err(|_| {
                LlmError::Transport(
                    "VERTEX_ACCESS_TOKEN not set. \
                     Get one via `gcloud auth print-access-token`."
                        .into(),
                )
            })?;
        let project = std::env::var("VERTEX_PROJECT")
            .or_else(|_| std::env::var("GCLOUD_PROJECT"))
            .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
            .map_err(|_| {
                LlmError::Transport(
                    "VERTEX_PROJECT not set (also tried GCLOUD_PROJECT, GOOGLE_CLOUD_PROJECT)"
                        .into(),
                )
            })?;
        let region = std::env::var("VERTEX_REGION").unwrap_or_else(|_| DEFAULT_REGION.to_string());
        Ok(Self {
            access_token,
            project,
            region,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
                .build()
                .expect("reqwest"),
        })
    }

    pub fn with_token(access_token: String, project: String, region: String) -> Self {
        Self {
            access_token,
            project,
            region,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
                .build()
                .expect("reqwest"),
        }
    }

    fn endpoint(&self, vertex_model: &str) -> String {
        format!(
            "https://{}-aiplatform.googleapis.com/v1/projects/{}/locations/{}/publishers/anthropic/models/{}:rawPredict",
            self.region, self.project, self.region, vertex_model
        )
    }

    fn streaming_endpoint(&self, vertex_model: &str) -> String {
        format!(
            "https://{}-aiplatform.googleapis.com/v1/projects/{}/locations/{}/publishers/anthropic/models/{}:streamRawPredict",
            self.region, self.project, self.region, vertex_model
        )
    }
}

/// Map a canonical Anthropic model id (`claude-haiku-4-5-20251001`) to the
/// Vertex catalog id (`claude-haiku-4-5@20251001`).
pub fn map_model_id(canonical: &str) -> String {
    if canonical.contains('@') {
        return canonical.to_string();
    }
    let parts: Vec<&str> = canonical.rsplitn(2, '-').collect();
    if parts.len() == 2 {
        let suffix = parts[0];
        let prefix = parts[1];
        if suffix.len() == 8 && suffix.chars().all(|c| c.is_ascii_digit()) {
            return format!("{prefix}@{suffix}");
        }
    }
    canonical.to_string()
}

/// Serialize a MessagesRequest into the Vertex wire body (strips `model` +
/// `stream`, injects `anthropic_version`).
fn vertex_body(req: &MessagesRequest) -> Result<serde_json::Value, LlmError> {
    let mut body = serde_json::to_value(req)
        .map_err(|e| LlmError::Schema(format!("encode request: {e}")))?;
    if let Some(obj) = body.as_object_mut() {
        obj.remove("model");
        obj.remove("stream");
        obj.insert(
            "anthropic_version".to_string(),
            serde_json::Value::String(VERTEX_ANTHROPIC_VERSION.to_string()),
        );
    }
    Ok(body)
}

fn parse_stop_reason(s: &str) -> StopReason {
    match s {
        "max_tokens" => StopReason::MaxTokens,
        "tool_use" => StopReason::ToolUse,
        "stop_sequence" => StopReason::StopSequence,
        _ => StopReason::EndTurn,
    }
}

#[async_trait]
impl LlmProvider for VertexProvider {
    async fn complete(&self, mut req: MessagesRequest) -> Result<MessagesResponse, LlmError> {
        req.stream = false;
        let vertex_model = map_model_id(&req.model);
        let url = self.endpoint(&vertex_model);
        let body = vertex_body(&req)?;

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.access_token)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::Transport(format!("send: {e}")))?;

        let status = resp.status();
        if status.as_u16() == 429 {
            return Err(LlmError::RateLimited);
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(LlmError::Upstream {
                status: status.as_u16(),
                body: text,
            });
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| LlmError::Transport(format!("read body: {e}")))?;
        let mut parsed: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| LlmError::Schema(format!("decode response: {e}")))?;
        let content: Vec<ContentBlock> = parsed
            .get_mut("content")
            .map(|v| std::mem::take(v))
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let stop_reason: StopReason = parsed
            .get("stop_reason")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or(StopReason::EndTurn);
        let usage: Option<Usage> = parsed
            .get_mut("usage")
            .map(|v| std::mem::take(v))
            .and_then(|v| serde_json::from_value(v).ok());
        Ok(MessagesResponse {
            content,
            stop_reason,
            usage,
        })
    }

    /// Streaming via `:streamRawPredict` — SSE response, same delta JSON shape
    /// as Anthropic native streaming.
    ///
    /// UNVERIFIED: live Vertex streaming requires a valid GCP access token with
    /// `aiplatform.endpoints.predict` permission on the project.
    async fn complete_streamed(
        &self,
        mut req: MessagesRequest,
        mut on_delta: TextDeltaSink,
    ) -> Result<MessagesResponse, LlmError> {
        req.stream = true;
        let vertex_model = map_model_id(&req.model);
        let url = self.streaming_endpoint(&vertex_model);
        let body = vertex_body(&req)?;

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.access_token)
            .header("content-type", "application/json")
            .header("Accept", "text/event-stream")
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::Transport(format!("send: {e}")))?;

        let status = resp.status();
        if status.as_u16() == 429 {
            return Err(LlmError::RateLimited);
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(LlmError::Upstream {
                status: status.as_u16(),
                body: text,
            });
        }

        let mut stream = resp.bytes_stream();
        let mut buf: Vec<u8> = Vec::new();
        let mut text_acc = String::new();
        let mut stop_reason = StopReason::EndTurn;
        let mut input_tokens: u64 = 0;
        let mut output_tokens: u64 = 0;

        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|e| LlmError::Transport(format!("stream read: {e}")))?;
            buf.extend_from_slice(&chunk);

            let (payloads, consumed) = parse_sse_data_events(&buf);
            buf.drain(..consumed);

            for payload in payloads {
                let Ok(ev) = serde_json::from_slice::<serde_json::Value>(&payload) else {
                    continue;
                };
                match ev["type"].as_str() {
                    Some("content_block_delta") => {
                        if ev["delta"]["type"].as_str() == Some("text_delta") {
                            if let Some(text) = ev["delta"]["text"].as_str() {
                                on_delta(text);
                                text_acc.push_str(text);
                            }
                        }
                    }
                    Some("message_start") => {
                        input_tokens =
                            ev["message"]["usage"]["input_tokens"].as_u64().unwrap_or(0);
                    }
                    Some("message_delta") => {
                        output_tokens = ev["usage"]["output_tokens"].as_u64().unwrap_or(0);
                        if let Some(sr) = ev["delta"]["stop_reason"].as_str() {
                            stop_reason = parse_stop_reason(sr);
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(MessagesResponse {
            content: vec![ContentBlock::Text { text: text_acc }],
            stop_reason,
            usage: Some(Usage {
                input_tokens,
                output_tokens,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            }),
        })
    }

    fn name(&self) -> &str {
        "vertex"
    }
}

// ── SSE parser ────────────────────────────────────────────────────────────────

/// Extract all complete `data:` payloads from an SSE byte buffer.
///
/// Scans line by line. Lines starting with `data: ` yield a payload (the
/// bytes after the `data: ` prefix). Blank lines and comment lines (starting
/// with `:`) are skipped. An incomplete last line (no trailing `\n`) is left
/// in the buffer — the returned `bytes_consumed` value reflects only the bytes
/// that have been fully processed.
///
/// Returns `(payloads, bytes_consumed)`.
pub fn parse_sse_data_events(buf: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut payloads = Vec::new();
    let mut pos = 0;

    while pos < buf.len() {
        match buf[pos..].iter().position(|&b| b == b'\n') {
            None => break, // incomplete line — stop, leave in buffer
            Some(nl_offset) => {
                let line_end = pos + nl_offset;
                let raw_line = &buf[pos..line_end];
                // Strip trailing \r (CRLF line endings)
                let line = if raw_line.ends_with(b"\r") {
                    &raw_line[..raw_line.len() - 1]
                } else {
                    raw_line
                };

                if line.starts_with(b"data: ") {
                    payloads.push(line[6..].to_vec());
                }
                // blank lines and `:comment` lines are skipped

                pos = line_end + 1;
            }
        }
    }

    (payloads, pos)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_model_canonical_to_vertex_id() {
        assert_eq!(
            map_model_id("claude-haiku-4-5-20251001"),
            "claude-haiku-4-5@20251001"
        );
    }

    #[test]
    fn map_model_passthrough_when_already_at_form() {
        assert_eq!(
            map_model_id("claude-3-5-sonnet@20240620"),
            "claude-3-5-sonnet@20240620"
        );
    }

    #[test]
    fn map_model_passthrough_when_no_datestamp() {
        assert_eq!(map_model_id("claude-opus-4-7"), "claude-opus-4-7");
    }

    #[test]
    fn body_drops_model_and_stream_adds_anthropic_version() {
        let req = MessagesRequest {
            model: "claude-haiku-4-5-20251001".into(),
            system: Some("hi".into()),
            messages: vec![crate::Message::user_text("ping")],
            max_tokens: 32,
            tools: vec![],
            stream: false,
        };
        let body = vertex_body(&req).unwrap();
        assert!(body.get("model").is_none());
        assert!(body.get("stream").is_none());
        assert_eq!(body["anthropic_version"], "vertex-2023-10-16");
        assert_eq!(body["max_tokens"], 32);
    }

    #[test]
    fn endpoint_path_includes_project_region_model() {
        let p = VertexProvider::with_token(
            "tok".into(),
            "my-proj".into(),
            "us-west1".into(),
        );
        let url = p.endpoint("claude-foo@20250101");
        assert!(url.contains("us-west1-aiplatform.googleapis.com"));
        assert!(url.contains("/projects/my-proj/locations/us-west1/"));
        assert!(url.contains("/publishers/anthropic/models/claude-foo@20250101:rawPredict"));
    }

    #[test]
    fn streaming_endpoint_uses_stream_raw_predict() {
        let p = VertexProvider::with_token(
            "tok".into(),
            "my-proj".into(),
            "us-central1".into(),
        );
        let url = p.streaming_endpoint("claude-sonnet-4-6@20250601");
        assert!(url.ends_with(":streamRawPredict"));
        assert!(url.contains("my-proj"));
        assert!(url.contains("us-central1"));
    }

    // ── SSE parser ────────────────────────────────────────────────────────────

    #[test]
    fn parse_sse_single_data_event() {
        let buf = b"data: {\"type\":\"ping\"}\n\n";
        let (payloads, consumed) = parse_sse_data_events(buf);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0], b"{\"type\":\"ping\"}");
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn parse_sse_two_consecutive_events() {
        let buf = b"data: first\n\ndata: second\n\n";
        let (payloads, consumed) = parse_sse_data_events(buf);
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0], b"first");
        assert_eq!(payloads[1], b"second");
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn parse_sse_handles_crlf_line_endings() {
        let buf = b"data: hello\r\n\r\n";
        let (payloads, consumed) = parse_sse_data_events(buf);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0], b"hello");
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn parse_sse_leaves_incomplete_line_in_buffer() {
        // The last "data: incomplete" has no trailing \n — should not be parsed
        let buf = b"data: complete\n\ndata: incomplete";
        let (payloads, consumed) = parse_sse_data_events(buf);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0], b"complete");
        // consumed should stop before the incomplete line
        assert!(consumed < buf.len());
        let remaining = &buf[consumed..];
        assert!(remaining.starts_with(b"data: incomplete"));
    }
}
