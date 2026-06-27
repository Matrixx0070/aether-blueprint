//! AWS Bedrock provider for Anthropic models.
//!
//! Non-streaming: POST `.../model/{id}/invoke` — standard Messages API body shape
//! with `anthropic_version: "bedrock-2023-05-31"` discriminator.
//!
//! Streaming: POST `.../model/{id}/invoke-with-response-stream` — same body,
//! response is AWS event-stream framing. Each "chunk" event carries a base64-
//! encoded streaming delta (same shape as Anthropic SSE deltas).
//!
//! Auth: AWS SigV4. Credentials: `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
//! (+ optional `AWS_SESSION_TOKEN`). Region: `AWS_REGION` (default `us-east-1`).

use crate::{
    ContentBlock, LlmError, LlmProvider, MessagesRequest, MessagesResponse, StopReason,
    TextDeltaSink, Usage,
};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine};
use futures_util::StreamExt;
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

    fn streaming_endpoint(&self, bedrock_model: &str) -> String {
        format!(
            "https://bedrock-runtime.{}.amazonaws.com/model/{}/invoke-with-response-stream",
            self.region, bedrock_model
        )
    }

    /// Resolve credentials via the full provider chain and return both the
    /// provider and the `CredentialSource` that resolved them (useful for
    /// `aether doctor` reporting).
    pub async fn from_credential_chain(
    ) -> Result<(Self, CredentialSource), LlmError> {
        let (access_key, secret_key, session_token, source) =
            resolve_aws_credentials().await?;
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| DEFAULT_REGION.to_string());
        let provider = Self {
            access_key,
            secret_key,
            session_token,
            region,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
                .build()
                .expect("reqwest"),
        };
        Ok((provider, source))
    }
}

/// Map a canonical Anthropic model id (`claude-haiku-4-5-20251001`) to the
/// Bedrock catalog id (`anthropic.claude-haiku-4-5-20251001-v1:0`).
pub fn map_model_id(canonical: &str) -> String {
    if canonical.contains("anthropic.") {
        return canonical.to_string();
    }
    if canonical.ends_with(":0") {
        return format!("anthropic.{canonical}");
    }
    format!("anthropic.{canonical}-v1:0")
}

#[async_trait]
impl LlmProvider for BedrockProvider {
    async fn complete(&self, mut req: MessagesRequest) -> Result<MessagesResponse, LlmError> {
        req.stream = false;
        let bedrock_model = map_model_id(&req.model);
        let url = self.endpoint(&bedrock_model);

        let body_bytes = bedrock_body(&req)?;

        let resp = self
            .send_signed_inner(&url, &body_bytes, false)
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

    /// Streaming via `invoke-with-response-stream` + AWS event-stream framing.
    ///
    /// Each event-stream "chunk" event carries `{"bytes":"<b64>"}` where the
    /// base64 decodes to a Anthropic streaming delta (content_block_delta /
    /// message_start / message_delta shape). We parse it and forward text
    /// deltas to `on_delta`.
    ///
    /// UNVERIFIED: live Bedrock streaming requires real AWS credentials with
    /// `bedrock:InvokeModelWithResponseStream` permission.
    async fn complete_streamed(
        &self,
        mut req: MessagesRequest,
        mut on_delta: TextDeltaSink,
    ) -> Result<MessagesResponse, LlmError> {
        req.stream = true;
        let bedrock_model = map_model_id(&req.model);
        let url = self.streaming_endpoint(&bedrock_model);

        let body_bytes = bedrock_body(&req)?;

        let resp = self
            .send_signed_inner(&url, &body_bytes, true)
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

            loop {
                match parse_event_stream_message(&buf) {
                    Some((consumed, event_type, payload)) => {
                        buf.drain(..consumed);
                        if event_type != "chunk" {
                            continue;
                        }
                        // payload = {"bytes":"<base64>"}
                        let Ok(wrapper) =
                            serde_json::from_slice::<serde_json::Value>(&payload)
                        else {
                            continue;
                        };
                        let Some(b64) = wrapper["bytes"].as_str() else {
                            continue;
                        };
                        let Ok(decoded) = general_purpose::STANDARD.decode(b64) else {
                            continue;
                        };
                        let Ok(ev) = serde_json::from_slice::<serde_json::Value>(&decoded)
                        else {
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
                                input_tokens = ev["message"]["usage"]["input_tokens"]
                                    .as_u64()
                                    .unwrap_or(0);
                            }
                            Some("message_delta") => {
                                output_tokens =
                                    ev["usage"]["output_tokens"].as_u64().unwrap_or(0);
                                if let Some(sr) = ev["delta"]["stop_reason"].as_str() {
                                    stop_reason = parse_stop_reason(sr);
                                }
                            }
                            _ => {}
                        }
                    }
                    None => break,
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
        "bedrock"
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Serialize a MessagesRequest into the Bedrock wire body (strips `model` +
/// `stream`, injects `anthropic_version`).
fn bedrock_body(req: &MessagesRequest) -> Result<Vec<u8>, LlmError> {
    let mut body = serde_json::to_value(req)
        .map_err(|e| LlmError::Schema(format!("encode request: {e}")))?;
    if let Some(obj) = body.as_object_mut() {
        obj.remove("model");
        obj.remove("stream");
        obj.insert(
            "anthropic_version".to_string(),
            serde_json::Value::String(BEDROCK_ANTHROPIC_VERSION.to_string()),
        );
    }
    serde_json::to_vec(&body).map_err(|e| LlmError::Schema(format!("encode body: {e}")))
}

fn parse_stop_reason(s: &str) -> StopReason {
    match s {
        "max_tokens" => StopReason::MaxTokens,
        "tool_use" => StopReason::ToolUse,
        "stop_sequence" => StopReason::StopSequence,
        _ => StopReason::EndTurn,
    }
}

impl BedrockProvider {
    /// Sign and send a POST request. When `accept_event_stream` is true the
    /// `Accept: application/vnd.amazon.eventstream` header is added (required
    /// for the streaming endpoint).
    async fn send_signed_inner(
        &self,
        url: &str,
        body: &[u8],
        accept_event_stream: bool,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let parsed = reqwest::Url::parse(url).expect("static url");
        let host = parsed.host_str().unwrap_or_default().to_string();
        let canonical_uri = parsed.path().to_string();

        let payload_hash = hex::encode(Sha256::digest(body));

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
            if k == "host" {
                continue;
            }
            builder = builder.header(k.as_str(), v.as_str());
        }
        builder = builder.header("Authorization", authorization);
        if accept_event_stream {
            builder =
                builder.header("Accept", "application/vnd.amazon.eventstream");
        }
        builder.send().await
    }
}

// ── AWS credential provider chain ────────────────────────────────────────────

/// Identifies which credential source resolved the AWS credentials.
#[derive(Debug, Clone)]
pub enum CredentialSource {
    EnvVars,
    SharedCredentialsFile {
        path: std::path::PathBuf,
        profile: String,
    },
    Imdsv2,
    EcsTaskRole,
}

impl std::fmt::Display for CredentialSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvVars => write!(f, "environment variables"),
            Self::SharedCredentialsFile { path, profile } => {
                write!(f, "shared credentials file {} [profile: {profile}]", path.display())
            }
            Self::Imdsv2 => write!(f, "EC2 IMDSv2"),
            Self::EcsTaskRole => write!(f, "ECS task role"),
        }
    }
}

/// Parse an AWS shared credentials file (INI format). Returns
/// `(access_key_id, secret_access_key, optional_session_token)` for the
/// requested profile, or `None` if the profile or keys are missing.
pub fn parse_credentials_file(
    text: &str,
    profile: &str,
) -> Option<(String, String, Option<String>)> {
    let target_section = format!("[{profile}]");
    let mut in_section = false;
    let mut access_key: Option<String> = None;
    let mut secret_key: Option<String> = None;
    let mut session_token: Option<String> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_section = trimmed == target_section;
            continue;
        }
        if !in_section || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            match k.trim() {
                "aws_access_key_id" => access_key = Some(v.trim().to_string()),
                "aws_secret_access_key" => secret_key = Some(v.trim().to_string()),
                "aws_session_token" => session_token = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }

    match (access_key, secret_key) {
        (Some(ak), Some(sk)) => Some((ak, sk, session_token)),
        _ => None,
    }
}

/// Try EC2 IMDSv2 (1-second timeout). Returns credentials on success.
async fn probe_imdsv2(
    probe: &reqwest::Client,
) -> Option<(String, String, Option<String>)> {
    // Step 1: acquire IMDSv2 session token.
    let token = probe
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    let token = token.trim();

    // Step 2: get the IAM role name.
    let role_list = probe
        .get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        .header("X-aws-ec2-metadata-token", token)
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    let role_name = role_list.trim().lines().next()?.trim().to_string();
    if role_name.is_empty() {
        return None;
    }

    // Step 3: get temporary credentials for the role.
    let creds_url = format!(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/{}",
        role_name
    );
    let creds: serde_json::Value = probe
        .get(&creds_url)
        .header("X-aws-ec2-metadata-token", token)
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;

    let ak = creds["AccessKeyId"].as_str()?.to_string();
    let sk = creds["SecretAccessKey"].as_str()?.to_string();
    let st = creds["Token"].as_str().map(str::to_string);
    Some((ak, sk, st))
}

/// Try ECS task-role endpoint (1-second timeout). Returns credentials on success.
async fn probe_ecs_task_role(
    probe: &reqwest::Client,
) -> Option<(String, String, Option<String>)> {
    let uri = std::env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI")
        .ok()
        .or_else(|| {
            let rel = std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").ok()?;
            Some(format!("http://169.254.170.2{rel}"))
        })?;

    let mut builder = probe.get(&uri);
    if let Ok(auth) = std::env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN") {
        builder = builder.header("Authorization", auth);
    }

    let creds: serde_json::Value = builder.send().await.ok()?.json().await.ok()?;
    let ak = creds["AccessKeyId"].as_str()?.to_string();
    let sk = creds["SecretAccessKey"].as_str()?.to_string();
    let st = creds["Token"].as_str().map(str::to_string);
    Some((ak, sk, st))
}

/// Resolve AWS credentials through the standard provider chain:
/// 1. Environment variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`)
/// 2. Shared credentials file (`~/.aws/credentials`, profile from `AWS_PROFILE`)
/// 3. EC2 Instance Metadata Service v2 (IMDSv2)
/// 4. ECS task role (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`)
///
/// Returns the credentials plus the `CredentialSource` that resolved them.
pub async fn resolve_aws_credentials(
) -> Result<(String, String, Option<String>, CredentialSource), LlmError> {
    // 1. Environment variables
    if let (Ok(ak), Ok(sk)) = (
        std::env::var("AWS_ACCESS_KEY_ID"),
        std::env::var("AWS_SECRET_ACCESS_KEY"),
    ) {
        let token = std::env::var("AWS_SESSION_TOKEN").ok();
        return Ok((ak, sk, token, CredentialSource::EnvVars));
    }

    // 2. Shared credentials file
    let creds_path = std::env::var("AWS_SHARED_CREDENTIALS_FILE")
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| std::path::PathBuf::from(h).join(".aws/credentials"))
        });
    let profile =
        std::env::var("AWS_PROFILE").unwrap_or_else(|_| "default".to_string());
    if let Some(path) = creds_path {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Some((ak, sk, token)) = parse_credentials_file(&text, &profile) {
                return Ok((
                    ak,
                    sk,
                    token,
                    CredentialSource::SharedCredentialsFile { path, profile },
                ));
            }
        }
    }

    // 3. IMDSv2 / 4. ECS — use a short-timeout probe client so we don't block
    //    on non-EC2/ECS hosts.
    let probe = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .expect("reqwest");

    if let Some((ak, sk, token)) = probe_imdsv2(&probe).await {
        return Ok((ak, sk, token, CredentialSource::Imdsv2));
    }

    if let Some((ak, sk, token)) = probe_ecs_task_role(&probe).await {
        return Ok((ak, sk, token, CredentialSource::EcsTaskRole));
    }

    Err(LlmError::Transport(
        "no AWS credentials found (tried: env vars, ~/.aws/credentials, IMDSv2, ECS task role)"
            .into(),
    ))
}

// ── AWS event-stream parser ───────────────────────────────────────────────────
//
// Wire format (all integers big-endian):
//   4B  total_length   — byte count including prelude, headers, payload, trailing CRC
//   4B  headers_length — byte count of the headers section only
//   4B  prelude CRC32  — skipped (TLS provides transport integrity)
//   NB  headers
//   PB  payload        — P = total_length - 12 - headers_length - 4
//   4B  message CRC32  — skipped
//
// Header wire element:
//   1B  name_length
//   NB  name (UTF-8)
//   1B  value_type  (7 = string)
//   for string: 2B value_length, then value_length bytes UTF-8
//   other types are skipped (see value_type_skip_bytes)

/// Parse one AWS event-stream framed message from the front of `buf`.
///
/// Returns `None` when `buf` doesn't yet contain a full message.
/// Returns `Some((bytes_consumed, event_type, payload_bytes))` on success.
/// `event_type` is the `:event-type` header value, empty string if absent.
pub fn parse_event_stream_message(buf: &[u8]) -> Option<(usize, String, Vec<u8>)> {
    if buf.len() < 12 {
        return None; // prelude not yet available
    }
    let total_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < total_len {
        return None; // wait for full message
    }
    let headers_len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    // prelude = 12 bytes, then headers, then payload, then 4B trailing CRC
    let payload_start = 12 + headers_len;
    let payload_end = total_len.saturating_sub(4);
    if payload_end < payload_start || payload_start > total_len {
        // Malformed lengths — consume and skip
        return Some((total_len, String::new(), Vec::new()));
    }
    let header_bytes = &buf[12..12 + headers_len];
    let event_type = extract_string_header(header_bytes, ":event-type").unwrap_or_default();
    let payload = buf[payload_start..payload_end].to_vec();
    Some((total_len, event_type, payload))
}

/// Scan `header_bytes` for a string-typed header named `target` and return its value.
fn extract_string_header(header_bytes: &[u8], target: &str) -> Option<String> {
    let mut pos = 0;
    while pos < header_bytes.len() {
        let name_len = *header_bytes.get(pos)? as usize;
        pos += 1;
        if pos + name_len > header_bytes.len() {
            break;
        }
        let name = std::str::from_utf8(&header_bytes[pos..pos + name_len]).ok()?;
        pos += name_len;
        let value_type = *header_bytes.get(pos)?;
        pos += 1;
        match value_type {
            0 | 1 => { /* bool_true / bool_false — no value bytes */ }
            2 => {
                pos += 1; // byte
            }
            3 => {
                pos += 2; // short
            }
            4 => {
                pos += 4; // int
            }
            5 | 8 => {
                pos += 8; // long / timestamp
            }
            6 | 7 => {
                // bytes (6) or string (7): 2B length prefix
                if pos + 2 > header_bytes.len() {
                    break;
                }
                let val_len =
                    u16::from_be_bytes([header_bytes[pos], header_bytes[pos + 1]]) as usize;
                pos += 2;
                if pos + val_len > header_bytes.len() {
                    break;
                }
                if value_type == 7 && name == target {
                    return std::str::from_utf8(&header_bytes[pos..pos + val_len])
                        .ok()
                        .map(str::to_string);
                }
                pos += val_len;
            }
            9 => {
                pos += 16; // uuid
            }
            _ => break,
        }
    }
    None
}

// ── SigV4 ─────────────────────────────────────────────────────────────────────

pub fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{secret}");
    let k_date = hmac_sha256(k_secret.as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("any size");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── model id mapping ──────────────────────────────────────────────────────

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
        let s = "claude-foo:0";
        assert_eq!(map_model_id(s), "anthropic.claude-foo:0");
    }

    #[test]
    fn endpoint_path_format() {
        let p = BedrockProvider::with_credentials(
            "a".into(),
            "b".into(),
            None,
            "us-west-2".into(),
        );
        let u = p.endpoint("anthropic.claude-haiku-4-5-20251001-v1:0");
        assert_eq!(
            u,
            "https://bedrock-runtime.us-west-2.amazonaws.com/model/anthropic.claude-haiku-4-5-20251001-v1:0/invoke"
        );
    }

    #[test]
    fn streaming_endpoint_path_format() {
        let p = BedrockProvider::with_credentials(
            "a".into(),
            "b".into(),
            None,
            "us-east-1".into(),
        );
        let u = p.streaming_endpoint("anthropic.claude-sonnet-4-6-v1:0");
        assert_eq!(
            u,
            "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-sonnet-4-6-v1:0/invoke-with-response-stream"
        );
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
        let bytes = bedrock_body(&req).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(body.get("model").is_none());
        assert!(body.get("stream").is_none());
        assert_eq!(body["anthropic_version"], "bedrock-2023-05-31");
        assert_eq!(body["max_tokens"], 32);
    }

    #[test]
    fn sigv4_derive_signing_key_matches_aws_example() {
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let key = derive_signing_key(secret, "20120215", "us-east-1", "iam");
        let hex = hex::encode(key);
        assert_eq!(
            hex,
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    // ── credential chain ─────────────────────────────────────────────────────

    #[test]
    fn parse_credentials_file_default_profile() {
        let content = "[default]\naws_access_key_id = AKIAEX\naws_secret_access_key = SECRET\n";
        let (ak, sk, token) = parse_credentials_file(content, "default").unwrap();
        assert_eq!(ak, "AKIAEX");
        assert_eq!(sk, "SECRET");
        assert!(token.is_none());
    }

    #[test]
    fn parse_credentials_file_named_profile_with_token() {
        let content = "[default]\naws_access_key_id = A\naws_secret_access_key = B\n\n\
                       [staging]\naws_access_key_id = C\naws_secret_access_key = D\naws_session_token = TOK\n";
        let (ak, sk, token) = parse_credentials_file(content, "staging").unwrap();
        assert_eq!(ak, "C");
        assert_eq!(sk, "D");
        assert_eq!(token.as_deref(), Some("TOK"));
    }

    #[test]
    fn parse_credentials_file_missing_profile_returns_none() {
        let content = "[default]\naws_access_key_id = A\naws_secret_access_key = B\n";
        assert!(parse_credentials_file(content, "prod").is_none());
    }

    #[test]
    fn credential_source_display_variants() {
        assert_eq!(CredentialSource::EnvVars.to_string(), "environment variables");
        assert_eq!(CredentialSource::Imdsv2.to_string(), "EC2 IMDSv2");
        assert_eq!(CredentialSource::EcsTaskRole.to_string(), "ECS task role");
        let shared = CredentialSource::SharedCredentialsFile {
            path: std::path::PathBuf::from("/home/user/.aws/credentials"),
            profile: "dev".to_string(),
        };
        let s = shared.to_string();
        assert!(s.contains("credentials"));
        assert!(s.contains("dev"));
    }

    // ── event-stream parser ───────────────────────────────────────────────────

    /// Build a minimal valid event-stream message with one string header.
    fn make_event_stream_msg(event_type: &str, payload: &[u8]) -> Vec<u8> {
        let name = b":event-type";
        let val = event_type.as_bytes();
        let mut headers = Vec::new();
        headers.push(name.len() as u8);
        headers.extend_from_slice(name);
        headers.push(7u8); // string value type
        headers.extend_from_slice(&(val.len() as u16).to_be_bytes());
        headers.extend_from_slice(val);

        let headers_len = headers.len() as u32;
        let total_len = 12u32 + headers_len + payload.len() as u32 + 4;

        let mut msg = Vec::new();
        msg.extend_from_slice(&total_len.to_be_bytes());
        msg.extend_from_slice(&headers_len.to_be_bytes());
        msg.extend_from_slice(&[0u8; 4]); // prelude CRC (skipped in parser)
        msg.extend_from_slice(&headers);
        msg.extend_from_slice(payload);
        msg.extend_from_slice(&[0u8; 4]); // message CRC (skipped in parser)
        msg
    }

    #[test]
    fn parse_event_stream_returns_none_on_short_prelude() {
        // 11 bytes — not enough for the 12-byte prelude
        assert!(parse_event_stream_message(&[0u8; 11]).is_none());
    }

    #[test]
    fn parse_event_stream_returns_none_when_partial_message() {
        // total_length = 100, but buf only has 20 bytes
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&100u32.to_be_bytes());
        buf[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert!(parse_event_stream_message(&buf).is_none());
    }

    #[test]
    fn parse_event_stream_extracts_chunk_event_type_and_payload() {
        let payload = br#"{"bytes":"SGVsbG8="}"#;
        let msg = make_event_stream_msg("chunk", payload);
        let (consumed, event_type, got_payload) = parse_event_stream_message(&msg).unwrap();
        assert_eq!(consumed, msg.len());
        assert_eq!(event_type, "chunk");
        assert_eq!(got_payload, payload as &[u8]);
    }

    #[test]
    fn parse_event_stream_handles_consecutive_messages() {
        let payload1 = b"first-payload";
        let payload2 = b"second-payload";
        let mut buf = make_event_stream_msg("chunk", payload1);
        let second_msg = make_event_stream_msg("messageStop", payload2);
        buf.extend_from_slice(&second_msg);

        let (consumed1, et1, p1) = parse_event_stream_message(&buf).unwrap();
        assert_eq!(et1, "chunk");
        assert_eq!(p1, payload1 as &[u8]);

        let (consumed2, et2, p2) = parse_event_stream_message(&buf[consumed1..]).unwrap();
        assert_eq!(et2, "messageStop");
        assert_eq!(p2, payload2 as &[u8]);
        let _ = consumed2;
    }
}
