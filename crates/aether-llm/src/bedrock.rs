//! AWS Bedrock provider for Anthropic models.
//!
//! Hits `POST https://bedrock-runtime.{region}.amazonaws.com/model/{model_id}/invoke`
//! with the same Messages API body shape as the Anthropic API, plus the
//! `anthropic_version: "bedrock-2023-05-31"` discriminator the Bedrock-
//! hosted model expects.
//!
//! Auth: AWS SigV4. Credentials come from (in order):
//!   1. `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env (+ optional
//!      `AWS_SESSION_TOKEN`)
//!   2. (TODO v0.6.1) shared credentials file via `AWS_PROFILE`
//!
//! Region from `AWS_REGION` (default `us-east-1`).
//!
//! Model-id translation (`map_model_id`) takes the canonical
//! `claude-haiku-4-5-20251001` and returns Bedrock's
//! `anthropic.claude-haiku-4-5-20251001-v1:0`. The mapping is best-effort;
//! when an exact Bedrock id is given we pass it through unchanged.

use crate::{
    ContentBlock, LlmError, LlmProvider, MessagesRequest, MessagesResponse, StopReason,
    TextDeltaSink, Usage,
};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::Duration;

const DEFAULT_REGION: &str = "us-east-1";
const SERVICE: &str = "bedrock";
const BEDROCK_ANTHROPIC_VERSION: &str = "bedrock-2023-05-31";
const DEFAULT_TIMEOUT_SECS: u64 = 300;

pub struct BedrockProvider {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
    region: String,
    client: reqwest::Client,
}

impl BedrockProvider {
    pub fn from_env() -> Result<Self, LlmError> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| LlmError::Transport("AWS_ACCESS_KEY_ID not set".into()))?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| LlmError::Transport("AWS_SECRET_ACCESS_KEY not set".into()))?;
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| DEFAULT_REGION.to_string());
        Ok(Self {
            access_key,
            secret_key,
            session_token,
            region,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
                .build()
                .expect("reqwest"),
        })
    }

    pub fn with_credentials(
        access_key: String,
        secret_key: String,
        session_token: Option<String>,
        region: String,
    ) -> Self {
        Self {
            access_key,
            secret_key,
            session_token,
            region,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
                .build()
                .expect("reqwest"),
        }
    }

    fn endpoint(&self, bedrock_model: &str) -> String {
        format!(
            "https://bedrock-runtime.{}.amazonaws.com/model/{}/invoke",
            self.region, bedrock_model
        )
    }
}

/// Map a canonical Anthropic model id (`claude-haiku-4-5-20251001`) to the
/// Bedrock catalog id (`anthropic.claude-haiku-4-5-20251001-v1:0`).
///
/// Pass-through when the input already looks like a Bedrock id (contains
/// `anthropic.` prefix). Conservative: unknown forms get the dot-prefix
/// applied so the model is still rejected cleanly by Bedrock with a
/// 400-class error rather than 404-on-host.
pub fn map_model_id(canonical: &str) -> String {
    if canonical.contains("anthropic.") {
        return canonical.to_string();
    }
    // Append `-v1:0` only when missing.
    if canonical.ends_with(":0") {
        return format!("anthropic.{canonical}");
    }
    format!("anthropic.{canonical}-v1:0")
}

#[async_trait]
impl LlmProvider for BedrockProvider {
    async fn complete(&self, mut req: MessagesRequest) -> Result<MessagesResponse, LlmError> {
        // Bedrock requires this discriminator, NOT the `anthropic-version` header.
        req.stream = false;
        let bedrock_model = map_model_id(&req.model);
        let url = self.endpoint(&bedrock_model);

        let mut body = serde_json::to_value(&req)
            .map_err(|e| LlmError::Schema(format!("encode request: {e}")))?;
        // Strip `model` and `stream` from the body (model is in the URL path).
        if let Some(obj) = body.as_object_mut() {
            obj.remove("model");
            obj.remove("stream");
            obj.insert(
                "anthropic_version".to_string(),
                serde_json::Value::String(BEDROCK_ANTHROPIC_VERSION.to_string()),
            );
        }

        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| LlmError::Schema(format!("encode body: {e}")))?;

        let resp = self
            .send_signed(&url, &body_bytes)
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
        // Bedrock returns the same content/stop_reason shape; usage too.
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

    /// Bedrock streaming uses a different wire shape (`invoke-with-response-stream`
    /// + AWS event-stream framing). v0.6 ships non-streaming only; the
    /// default-impl fallback emits one chunk via `complete()`. Streaming
    /// support is on the v0.6.1 list.
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
        "bedrock"
    }
}

impl BedrockProvider {
    async fn send_signed(
        &self,
        url: &str,
        body: &[u8],
    ) -> Result<reqwest::Response, reqwest::Error> {
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let parsed = reqwest::Url::parse(url).expect("static url");
        let host = parsed.host_str().unwrap_or_default().to_string();
        let canonical_uri = parsed.path().to_string();

        let payload_hash = hex::encode(Sha256::digest(body));

        // Canonical headers (sorted, lowercased)
        let mut headers: Vec<(String, String)> = vec![
            ("content-type".into(), "application/json".into()),
            ("host".into(), host.clone()),
            ("x-amz-content-sha256".into(), payload_hash.clone()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        if let Some(tok) = &self.session_token {
            headers.push(("x-amz-security-token".into(), tok.clone()));
        }
        headers.sort_by(|a, b| a.0.cmp(&b.0));

        let canonical_headers: String = headers
            .iter()
            .map(|(k, v)| format!("{k}:{}\n", v.trim()))
            .collect();
        let signed_headers: String = headers
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");

        let canonical_request = format!(
            "POST\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );

        let credential_scope = format!("{date_stamp}/{}/{SERVICE}/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        let signing_key = derive_signing_key(&self.secret_key, &date_stamp, &self.region, SERVICE);
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key
        );

        let mut builder = self.client.post(url).body(body.to_vec());
        for (k, v) in &headers {
            // Skip 'host' — reqwest sets it automatically and rejects manual set.
            if k == "host" {
                continue;
            }
            builder = builder.header(k.as_str(), v.as_str());
        }
        builder = builder.header("Authorization", authorization);
        builder.send().await
    }
}

fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{secret}");
    let k_date = hmac_sha256(k_secret.as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("any size");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_model_canonical_to_bedrock_id() {
        assert_eq!(
            map_model_id("claude-haiku-4-5-20251001"),
            "anthropic.claude-haiku-4-5-20251001-v1:0"
        );
        assert_eq!(
            map_model_id("claude-opus-4-7"),
            "anthropic.claude-opus-4-7-v1:0"
        );
    }

    #[test]
    fn map_model_passthrough_when_already_bedrock_id() {
        let s = "anthropic.claude-3-5-sonnet-20241022-v2:0";
        assert_eq!(map_model_id(s), s);
    }

    #[test]
    fn map_model_handles_versioned_ids() {
        // already has :0 suffix → only prefix added
        let s = "claude-foo:0";
        assert_eq!(map_model_id(s), "anthropic.claude-foo:0");
    }

    /// SigV4 canonical-request sanity check using the AWS published example.
    /// Reference: docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
    #[test]
    fn sigv4_derive_signing_key_matches_aws_example() {
        // From the AWS docs Python example
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let key = derive_signing_key(secret, "20120215", "us-east-1", "iam");
        // Expected from AWS docs (hex)
        let hex = hex::encode(key);
        assert_eq!(
            hex,
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }
}
