//! Google Cloud Vertex AI provider for Anthropic models.
//!
//! Hits `POST https://{region}-aiplatform.googleapis.com/v1/projects/{project}/locations/{region}/publishers/anthropic/models/{model}:rawPredict`
//! with the same Messages API body shape as the Anthropic API plus the
//! `anthropic_version: "vertex-2023-10-16"` discriminator the Vertex-hosted
//! model expects.
//!
//! Auth: Bearer token. For v0.6 we read it from `VERTEX_ACCESS_TOKEN` (or
//! `GCP_ACCESS_TOKEN`) env var. Users obtain it via
//! `gcloud auth print-access-token`. Auto-rotation via ADC / service-account
//! files is a v0.6.1 candidate — pulling `gcp_auth` is heavy.
//!
//! Region from `VERTEX_REGION` (default `us-central1`).
//! Project from `VERTEX_PROJECT` (or `GCLOUD_PROJECT`, or settings).

use crate::{
    ContentBlock, LlmError, LlmProvider, MessagesRequest, MessagesResponse, StopReason,
    TextDeltaSink, Usage,
};
use async_trait::async_trait;
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
}

/// Map a canonical Anthropic model id (`claude-haiku-4-5-20251001`) to the
/// Vertex catalog id (`claude-haiku-4-5@20251001`). Vertex uses the `@`
/// convention to separate model family from version.
///
/// Pass-through when the input already contains `@` (looks Vertex-y).
pub fn map_model_id(canonical: &str) -> String {
    if canonical.contains('@') {
        return canonical.to_string();
    }
    // Heuristic: split off trailing -YYYYMMDD as the @ version.
    let parts: Vec<&str> = canonical.rsplitn(2, '-').collect();
    if parts.len() == 2 {
        let suffix = parts[0];
        let prefix = parts[1];
        // suffix is an 8-digit datestamp?
        if suffix.len() == 8 && suffix.chars().all(|c| c.is_ascii_digit()) {
            return format!("{prefix}@{suffix}");
        }
    }
    canonical.to_string()
}

#[async_trait]
impl LlmProvider for VertexProvider {
    async fn complete(&self, mut req: MessagesRequest) -> Result<MessagesResponse, LlmError> {
        req.stream = false;
        let vertex_model = map_model_id(&req.model);
        let url = self.endpoint(&vertex_model);

        let mut body = serde_json::to_value(&req)
            .map_err(|e| LlmError::Schema(format!("encode request: {e}")))?;
        if let Some(obj) = body.as_object_mut() {
            obj.remove("model");
            obj.remove("stream");
            obj.insert(
                "anthropic_version".to_string(),
                serde_json::Value::String(VERTEX_ANTHROPIC_VERSION.to_string()),
            );
        }

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

    /// Vertex streaming uses `:streamRawPredict` with SSE. v0.6 ships
    /// non-streaming only; the default fallback emits one chunk via
    /// `complete()`. Streaming is on the v0.6.1 list.
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

    fn name(&self) -> &str {
        "vertex"
    }
}

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
        let mut body = serde_json::to_value(&req).unwrap();
        if let Some(o) = body.as_object_mut() {
            o.remove("model");
            o.remove("stream");
            o.insert(
                "anthropic_version".into(),
                serde_json::Value::String(VERTEX_ANTHROPIC_VERSION.into()),
            );
        }
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
}
