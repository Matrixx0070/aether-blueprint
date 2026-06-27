//! Google Cloud Vertex AI provider for Anthropic models.
//!
//! Auth modes:
//!   StaticToken  — Bearer from `VERTEX_ACCESS_TOKEN` / `GCP_ACCESS_TOKEN` env.
//!   ServiceAccount — RS256 JWT exchange from a service-account JSON file;
//!                    token is auto-refreshed when within 5 minutes of expiry.
//!
//! Non-streaming: POST `.../models/{model}:rawPredict`
//! Streaming:     POST `.../models/{model}:streamRawPredict` — SSE response.

use crate::{
    ContentBlock, LlmError, LlmProvider, MessagesRequest, MessagesResponse, StopReason,
    TextDeltaSink, Usage,
};
use async_trait::async_trait;
use futures_util::StreamExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::sync::RwLock;

const DEFAULT_REGION: &str = "us-central1";
const VERTEX_ANTHROPIC_VERSION: &str = "vertex-2023-10-16";
const DEFAULT_TIMEOUT_SECS: u64 = 300;
const GCP_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
// Refresh the token when it has fewer than 5 minutes left.
const REFRESH_BUFFER_SECS: u64 = 300;

// ── auth variants ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug, Clone)]
pub struct ServiceAccountFile {
    pub client_email: String,
    pub private_key: String,
    #[serde(default = "default_token_uri")]
    pub token_uri: String,
}

fn default_token_uri() -> String {
    GCP_TOKEN_ENDPOINT.to_string()
}

#[derive(Debug, Clone)]
pub struct GcpToken {
    pub access_token: String,
    pub expires_at: std::time::Instant,
}

impl GcpToken {
    pub fn needs_refresh(&self) -> bool {
        self.expires_at
            .checked_sub(Duration::from_secs(REFRESH_BUFFER_SECS))
            .map(|t| std::time::Instant::now() >= t)
            .unwrap_or(true) // saturated subtraction → refresh
    }
}

enum VertexAuth {
    StaticToken(String),
    ServiceAccount {
        sa: ServiceAccountFile,
        token: Arc<RwLock<Option<GcpToken>>>,
    },
}

// ── provider ──────────────────────────────────────────────────────────────────

pub struct VertexProvider {
    auth: VertexAuth,
    project: String,
    region: String,
    client: reqwest::Client,
}

impl VertexProvider {
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
            auth: VertexAuth::StaticToken(access_token),
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
            auth: VertexAuth::StaticToken(access_token),
            project,
            region,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
                .build()
                .expect("reqwest"),
        }
    }

    /// Construct from a GCP service-account JSON file. The file is read once;
    /// tokens are minted on first use and auto-refreshed before expiry.
    ///
    /// Project is taken from the `VERTEX_PROJECT` env var (or the SA JSON's
    /// `project_id` field if present), region from `VERTEX_REGION`.
    pub fn from_service_account_file(path: impl AsRef<Path>) -> Result<Self, LlmError> {
        let text = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            LlmError::Transport(format!(
                "read service-account file {}: {e}",
                path.as_ref().display()
            ))
        })?;
        let sa: ServiceAccountFile = serde_json::from_str(&text)
            .map_err(|e| LlmError::Schema(format!("parse service-account JSON: {e}")))?;
        let project = std::env::var("VERTEX_PROJECT")
            .or_else(|_| std::env::var("GCLOUD_PROJECT"))
            .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
            // Fallback: try to extract project_id from the raw JSON
            .or_else(|_| {
                serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| v["project_id"].as_str().map(str::to_string))
                    .ok_or(())
            })
            .map_err(|()| {
                LlmError::Transport(
                    "VERTEX_PROJECT not set and no project_id in service-account file".into(),
                )
            })?;
        let region = std::env::var("VERTEX_REGION").unwrap_or_else(|_| DEFAULT_REGION.to_string());
        Ok(Self {
            auth: VertexAuth::ServiceAccount {
                sa,
                token: Arc::new(RwLock::new(None)),
            },
            project,
            region,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
                .build()
                .expect("reqwest"),
        })
    }

    /// Return a valid Bearer token, minting or refreshing as needed.
    async fn get_token(&self) -> Result<String, LlmError> {
        match &self.auth {
            VertexAuth::StaticToken(t) => Ok(t.clone()),
            VertexAuth::ServiceAccount { sa, token } => {
                // Fast path: read lock, check if token is fresh.
                {
                    let guard = token.read().await;
                    if let Some(t) = guard.as_ref() {
                        if !t.needs_refresh() {
                            return Ok(t.access_token.clone());
                        }
                    }
                }
                // Slow path: write lock, re-check, then mint.
                let mut guard = token.write().await;
                if let Some(t) = guard.as_ref() {
                    if !t.needs_refresh() {
                        return Ok(t.access_token.clone());
                    }
                }
                let new_token = mint_gcp_token(sa, &self.client).await?;
                let access = new_token.access_token.clone();
                *guard = Some(new_token);
                Ok(access)
            }
        }
    }

    /// Resolve the Vertex AI base URL. `AETHER_VERTEX_ENDPOINT` overrides
    /// the default `<region>-aiplatform.googleapis.com` for fixture /
    /// smoke / VPC-private use. When set, the URL is used verbatim as
    /// the scheme://host:port prefix; the rest of the path (the
    /// `/v1/projects/.../publishers/anthropic/models/...:...` suffix)
    /// is appended unchanged so the wire format the upstream
    /// expects stays identical.
    fn base_url(&self) -> String {
        match std::env::var("AETHER_VERTEX_ENDPOINT") {
            Ok(s) if !s.is_empty() => s.trim_end_matches('/').to_string(),
            _ => format!("https://{}-aiplatform.googleapis.com", self.region),
        }
    }

    fn endpoint(&self, vertex_model: &str) -> String {
        format!(
            "{}/v1/projects/{}/locations/{}/publishers/anthropic/models/{}:rawPredict",
            self.base_url(),
            self.project,
            self.region,
            vertex_model
        )
    }

    fn streaming_endpoint(&self, vertex_model: &str) -> String {
        format!(
            "{}/v1/projects/{}/locations/{}/publishers/anthropic/models/{}:streamRawPredict",
            self.base_url(),
            self.project,
            self.region,
            vertex_model
        )
    }
}

// ── JWT / token exchange ──────────────────────────────────────────────────────

#[derive(Serialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
    scope: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// Build a signed RS256 JWT for `sa`, POST it to the token endpoint, and
/// return a `GcpToken` with the resulting Bearer token and expiry.
pub async fn mint_gcp_token(
    sa: &ServiceAccountFile,
    client: &reqwest::Client,
) -> Result<GcpToken, LlmError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let claims = JwtClaims {
        iss: sa.client_email.clone(),
        sub: sa.client_email.clone(),
        aud: sa.token_uri.clone(),
        iat: now,
        exp: now + 3600,
        scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
    };

    let key = EncodingKey::from_rsa_pem(sa.private_key.as_bytes())
        .map_err(|e| LlmError::Schema(format!("parse private key: {e}")))?;
    let jwt = encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map_err(|e| LlmError::Schema(format!("sign JWT: {e}")))?;

    let form = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", jwt.as_str()),
    ];
    let resp: TokenResponse = client
        .post(&sa.token_uri)
        .form(&form)
        .send()
        .await
        .map_err(|e| LlmError::Transport(format!("token exchange: {e}")))?
        .json()
        .await
        .map_err(|e| LlmError::Schema(format!("token exchange response: {e}")))?;

    let expires_at = std::time::Instant::now()
        + Duration::from_secs(resp.expires_in.saturating_sub(REFRESH_BUFFER_SECS));

    Ok(GcpToken {
        access_token: resp.access_token,
        expires_at,
    })
}

// ── model id mapping ──────────────────────────────────────────────────────────

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

// ── LlmProvider impl ──────────────────────────────────────────────────────────

#[async_trait]
impl LlmProvider for VertexProvider {
    async fn complete(&self, mut req: MessagesRequest) -> Result<MessagesResponse, LlmError> {
        req.stream = false;
        let vertex_model = map_model_id(&req.model);
        let url = self.endpoint(&vertex_model);
        let body = vertex_body(&req)?;
        let token = self.get_token().await?;

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&token)
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

    /// Streaming via `:streamRawPredict` (SSE). Token auto-refreshed if SA auth.
    ///
    /// UNVERIFIED: live Vertex streaming requires a valid GCP token with
    /// `aiplatform.endpoints.predict` permission.
    async fn complete_streamed(
        &self,
        mut req: MessagesRequest,
        mut on_delta: TextDeltaSink,
    ) -> Result<MessagesResponse, LlmError> {
        req.stream = true;
        let vertex_model = map_model_id(&req.model);
        let url = self.streaming_endpoint(&vertex_model);
        let body = vertex_body(&req)?;
        let token = self.get_token().await?;

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&token)
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

pub fn parse_sse_data_events(buf: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut payloads = Vec::new();
    let mut pos = 0;

    while pos < buf.len() {
        match buf[pos..].iter().position(|&b| b == b'\n') {
            None => break,
            Some(nl_offset) => {
                let line_end = pos + nl_offset;
                let raw_line = &buf[pos..line_end];
                let line = if raw_line.ends_with(b"\r") {
                    &raw_line[..raw_line.len() - 1]
                } else {
                    raw_line
                };
                if line.starts_with(b"data: ") {
                    payloads.push(line[6..].to_vec());
                }
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

    /// Z5: `AETHER_VERTEX_ENDPOINT` overrides the
    /// <region>-aiplatform.googleapis.com default. Both rawPredict
    /// and streamRawPredict paths inherit the override; the rest of
    /// the URL (project / region / model / verb) is preserved
    /// verbatim so the wire format upstream expects is identical.
    #[test]
    fn z5_endpoint_override_via_env() {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("AETHER_VERTEX_ENDPOINT", "http://127.0.0.1:9999");
        let p = VertexProvider::with_token(
            "tok".into(),
            "my-proj".into(),
            "us-central1".into(),
        );
        let url = p.endpoint("claude-haiku-4-5@20251001");
        assert_eq!(
            url,
            "http://127.0.0.1:9999/v1/projects/my-proj/locations/us-central1/publishers/anthropic/models/claude-haiku-4-5@20251001:rawPredict"
        );
        let stream_url = p.streaming_endpoint("claude-haiku-4-5@20251001");
        assert_eq!(
            stream_url,
            "http://127.0.0.1:9999/v1/projects/my-proj/locations/us-central1/publishers/anthropic/models/claude-haiku-4-5@20251001:streamRawPredict"
        );
        // Trailing-slash variant trims to canonical form.
        std::env::set_var("AETHER_VERTEX_ENDPOINT", "http://localhost:8080/");
        assert!(p.endpoint("x").starts_with("http://localhost:8080/v1/projects/"));
        // Empty value falls back to the AWS default.
        std::env::set_var("AETHER_VERTEX_ENDPOINT", "");
        assert!(
            p.endpoint("x").starts_with("https://us-central1-aiplatform.googleapis.com/"),
            "empty env falls back to GCP default"
        );
        std::env::remove_var("AETHER_VERTEX_ENDPOINT");
    }

    // ── SA / JWT ─────────────────────────────────────────────────────────────

    #[test]
    fn service_account_file_parses_required_fields() {
        let json = r#"{
            "type": "service_account",
            "project_id": "my-proj",
            "client_email": "sa@my-proj.iam.gserviceaccount.com",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCA==\n-----END RSA PRIVATE KEY-----\n",
            "token_uri": "https://oauth2.googleapis.com/token"
        }"#;
        let sa: ServiceAccountFile = serde_json::from_str(json).unwrap();
        assert_eq!(sa.client_email, "sa@my-proj.iam.gserviceaccount.com");
        assert_eq!(sa.token_uri, "https://oauth2.googleapis.com/token");
        assert!(sa.private_key.contains("RSA PRIVATE KEY"));
    }

    #[test]
    fn gcp_token_needs_refresh_when_expired() {
        let t = GcpToken {
            access_token: "tok".into(),
            // Already in the past
            expires_at: std::time::Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or(std::time::Instant::now()),
        };
        assert!(t.needs_refresh());
    }

    #[test]
    fn gcp_token_no_refresh_when_plenty_of_time_left() {
        let t = GcpToken {
            access_token: "tok".into(),
            // Expires 30 minutes from now (well beyond the 5-min refresh buffer)
            expires_at: std::time::Instant::now() + Duration::from_secs(1800),
        };
        assert!(!t.needs_refresh());
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
        let buf = b"data: complete\n\ndata: incomplete";
        let (payloads, consumed) = parse_sse_data_events(buf);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0], b"complete");
        assert!(consumed < buf.len());
        let remaining = &buf[consumed..];
        assert!(remaining.starts_with(b"data: incomplete"));
    }
}
