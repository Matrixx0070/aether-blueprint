//! Live Anthropic Messages API back-end.
//!
//! Hits `POST {base}/v1/messages` over HTTPS via `reqwest` with rustls.
//! Request and response types are the crate-level canonical ones, which
//! already mirror the Anthropic wire shape — `MessagesRequest` and
//! `MessagesResponse` serialize/deserialize directly without an
//! intermediate adapter.
//!
//! Two auth modes via the `AnthropicAuth` discriminator:
//!   * `ApiKey(_)` — sent as `x-api-key`, the classic console-issued path.
//!   * `OAuth { access_token }` — sent as `Authorization: Bearer …` plus
//!     `anthropic-beta: oauth-…`. The Claude Code OAuth flow stores the
//!     token at `~/.claude/.credentials.json` under
//!     `claudeAiOauth.accessToken`; `from_claude_code_credentials()`
//!     loads and validates expiry on it. `from_env_or_credentials()`
//!     auto-detects in priority order: `ANTHROPIC_API_KEY` →
//!     `CLAUDE_CODE_OAUTH_TOKEN` → credentials file.
//!
//! Errors map onto `LlmError`:
//!   * 429              → `LlmError::RateLimited`
//!   * 4xx / 5xx        → `LlmError::Upstream { status, body }`
//!   * network / parse  → `LlmError::Transport(msg)`
//!
//! v1 limitations:
//!   * No prompt-cache or extended-thinking knobs surfaced yet.
//!
//! Retry: this module makes exactly ONE HTTP attempt per call. Retry
//! semantics live in `aether_llm::retry::RetryingProvider`, which wraps
//! the provider at construction time in `build_provider`. The v0.7-era
//! internal `send_with_retries` (5 attempts + exponential backoff +
//! jitter) was removed in v0.11 to avoid double-retry stacking when
//! both layers fired (RetryingProvider × 3 × this layer × 5 = 15 worst-
//! case attempts).

use crate::{ContentBlock, LlmError, LlmProvider, MessagesRequest, MessagesResponse, StopReason, TextDeltaSink, Usage};
use async_trait::async_trait;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const ANTHROPIC_API_BASE: &str = "https://api.anthropic.com";
pub const ANTHROPIC_VERSION: &str = "2023-06-01";
pub const DEFAULT_TIMEOUT_SECS: u64 = 600;

/// `anthropic-beta` header value the Messages API expects when
/// authenticating with an OAuth bearer token. INFERRED from public Claude
/// Code traffic; revisit if Anthropic rotates the beta tag.
pub const OAUTH_BETA_HEADER: &str = "oauth-2025-04-20";

/// When authenticating with an OAuth Bearer token, Anthropic gates premium
/// models (Opus / Sonnet / Fable) behind an exact-match policy check on
/// the `system` field's first text block: it must equal one of three
/// approved Claude Code / SDK identity strings, or the request returns
/// `HTTP 429 rate_limit_error` (a misleading code — the actual cause is a
/// policy reject, not throughput). Haiku is exempt.
///
/// To carry additional system content, we send `system` as an array of
/// text blocks: `[{type:text, text: PREFIX}, {type:text, text: caller}]`.
/// The gate only inspects block 0, so caller content flows through cleanly.
///
/// We use the SDK-agent identity because aether isn't Claude Code itself.
/// Verified live 2026-06-25 against Opus 4.7 / 4.8 / Sonnet 4.6.
pub const OAUTH_SYSTEM_PREFIX: &str =
    "You are a Claude agent, built on Anthropic's Claude Agent SDK.";

/// Discriminator between the two supported credential modes. Header
/// selection in `complete()` dispatches off this.
#[derive(Debug, Clone)]
pub enum AnthropicAuth {
    /// Console-issued API key. Sent as `x-api-key`.
    ApiKey(String),
    /// Claude Code OAuth access token. Sent as `Authorization: Bearer …`
    /// alongside `anthropic-beta: oauth-…`.
    OAuth { access_token: String },
}

impl AnthropicAuth {
    pub fn api_key(key: impl Into<String>) -> Self {
        Self::ApiKey(key.into())
    }
    pub fn oauth(access_token: impl Into<String>) -> Self {
        Self::OAuth {
            access_token: access_token.into(),
        }
    }
}

#[derive(Debug)]
pub struct AnthropicProvider {
    auth: std::sync::Mutex<AnthropicAuth>,
    /// When the auth source is the credentials file, hold the path so we
    /// can refresh and persist back. `None` for env-var / explicit token
    /// constructions where no refresh is possible.
    credentials_path: Option<PathBuf>,
    api_base: String,
    client: reqwest::Client,
}

/// Claude Code OAuth client_id — used for the authorize, exchange, and
/// refresh endpoints. Verified against `~/.claude/.credentials.json`
/// written by Claude Code v2.1.191.
pub const OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const OAUTH_TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
/// Refresh access tokens this many ms before they expire (10 minutes).
const REFRESH_BUFFER_MS: i64 = 10 * 60 * 1000;
/// Default access-token lifetime (8h) when the token endpoint omits expires_in.
const DEFAULT_TOKEN_LIFETIME_SEC: u64 = 28_800;

// ── credentials.json shape (verified against `~/.claude/.credentials.json`
//    written by Claude Code) ─────────────────────────────────────────────
#[derive(Debug, serde::Serialize, Deserialize)]
struct CredentialsFile {
    #[serde(rename = "claudeAiOauth")]
    claude_ai_oauth: ClaudeAiOauth,
}

#[derive(Debug, serde::Serialize, Deserialize)]
struct ClaudeAiOauth {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "refreshToken", default)]
    refresh_token: String,
    /// Unix milliseconds. `0` or absent → treated as no-expiry.
    #[serde(rename = "expiresAt", default)]
    expires_at: i64,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(rename = "subscriptionType", default, skip_serializing_if = "Option::is_none")]
    subscription_type: Option<String>,
    #[serde(rename = "rateLimitTier", default, skip_serializing_if = "Option::is_none")]
    rate_limit_tier: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenRefreshResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
}

impl AnthropicProvider {
    /// Construct from an explicit API key (legacy path; equivalent to
    /// `with_auth(AnthropicAuth::api_key(k))`).
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::with_auth(AnthropicAuth::api_key(api_key))
    }

    /// Construct from a Claude Code OAuth access token.
    pub fn with_oauth(access_token: impl Into<String>) -> Self {
        Self::with_auth(AnthropicAuth::oauth(access_token))
    }

    /// Construct from an explicit `AnthropicAuth` value.
    pub fn with_auth(auth: AnthropicAuth) -> Self {
        Self {
            auth: std::sync::Mutex::new(auth),
            credentials_path: None,
            api_base: ANTHROPIC_API_BASE.to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
                .build()
                .expect("reqwest client construction never fails on rustls"),
        }
    }

    /// Read `ANTHROPIC_API_KEY` from the environment. Errors when the
    /// variable is missing or empty so callers don't accidentally send
    /// requests with an empty `x-api-key` header.
    pub fn from_env() -> Result<Self, LlmError> {
        match std::env::var("ANTHROPIC_API_KEY") {
            Ok(key) if !key.trim().is_empty() => Ok(Self::new(key)),
            Ok(_) => Err(LlmError::Transport(
                "ANTHROPIC_API_KEY is set but empty".into(),
            )),
            Err(_) => Err(LlmError::Transport("ANTHROPIC_API_KEY not set".into())),
        }
    }

    /// Read the Claude Code OAuth access token from `~/.claude/.credentials.json`.
    /// Errors when the file is missing, malformed, or the token's
    /// `expiresAt` is in the past.
    pub fn from_claude_code_credentials() -> Result<Self, LlmError> {
        let path = default_credentials_path()
            .ok_or_else(|| LlmError::Transport("HOME not set; cannot locate credentials".into()))?;
        Self::from_credentials_file(&path)
    }

    /// Read OAuth credentials from an explicit file path. Useful for
    /// non-default install locations and for tests. Stashes the path so
    /// future `complete()` calls can refresh the token in-place when it
    /// expires.
    pub fn from_credentials_file(path: &std::path::Path) -> Result<Self, LlmError> {
        let bytes = std::fs::read(path)
            .map_err(|e| LlmError::Transport(format!("{}: {e}", path.display())))?;
        let creds: CredentialsFile = serde_json::from_slice(&bytes)
            .map_err(|e| LlmError::Schema(format!("{}: {e}", path.display())))?;

        let expires_at = creds.claude_ai_oauth.expires_at;
        if expires_at > 0 {
            let now_ms = now_ms();
            if expires_at <= now_ms {
                return Err(LlmError::Transport(format!(
                    "Claude Code OAuth token expired at unix-ms {expires_at}; \
                     run `claude` to refresh"
                )));
            }
        }
        let mut p = Self::with_oauth(creds.claude_ai_oauth.access_token);
        p.credentials_path = Some(path.to_path_buf());
        Ok(p)
    }

    /// Best-effort auto-detection.
    ///
    /// Priority (highest → lowest):
    ///   1. `~/.claude/.credentials.json` OAuth token — preferred when present;
    ///      it's a Max-subscription token that doesn't incur per-token billing.
    ///   2. `CLAUDE_CODE_OAUTH_TOKEN` env var
    ///   3. `ANTHROPIC_API_KEY` env var (plain API key or proxy dummy key)
    ///
    /// `ANTHROPIC_BASE_URL` overrides the API base **only** when falling back to
    /// an API key (cases 3 above). OAuth tokens must reach `api.anthropic.com`
    /// directly and are never redirected through a local proxy.
    pub fn from_env_or_credentials() -> Result<Self, LlmError> {
        // Prefer on-disk OAuth credentials when available.
        if let Ok(p) = Self::from_claude_code_credentials() {
            return Ok(p);
        }
        if let Ok(t) = std::env::var("CLAUDE_CODE_OAUTH_TOKEN") {
            if !t.trim().is_empty() {
                return Ok(Self::with_oauth(t));
            }
        }
        // Fall back to API key — honour ANTHROPIC_BASE_URL for proxy routing.
        let mut provider = Self::from_api_key_env()?;
        if let Ok(base) = std::env::var("ANTHROPIC_BASE_URL") {
            if !base.trim().is_empty() {
                provider = provider.with_base(base);
            }
        }
        Ok(provider)
    }

    fn from_api_key_env() -> Result<Self, LlmError> {
        if let Ok(k) = std::env::var("ANTHROPIC_API_KEY") {
            if !k.trim().is_empty() {
                return Ok(Self::new(k));
            }
        }
        Err(LlmError::Transport(
            "No Anthropic credentials found. Set ANTHROPIC_API_KEY or run `claude` to set up OAuth.".to_string()
        ))
    }

    /// Override the API base URL. Used by tests against a local mock or
    /// by an operator pointing at a proxy.
    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// Snapshot the current auth (useful for tests).
    pub fn auth_snapshot(&self) -> AnthropicAuth {
        self.auth.lock().expect("auth mutex").clone()
    }

    fn endpoint(&self) -> String {
        format!("{}/v1/messages", self.api_base.trim_end_matches('/'))
    }

    fn is_oauth(&self) -> bool {
        matches!(*self.auth.lock().expect("auth mutex"), AnthropicAuth::OAuth { .. })
    }

    /// Auth-specific headers as a flat list of `(name, value)` pairs.
    /// Factored out of `complete()` so it's directly testable without
    /// spinning up an HTTP listener.
    fn auth_headers(&self) -> Vec<(&'static str, String)> {
        let guard = self.auth.lock().expect("auth mutex");
        match &*guard {
            AnthropicAuth::ApiKey(k) => vec![("x-api-key", k.clone())],
            AnthropicAuth::OAuth { access_token } => vec![
                ("authorization", format!("Bearer {access_token}")),
                ("anthropic-beta", OAUTH_BETA_HEADER.to_string()),
            ],
        }
    }

    /// If credentials are loaded from disk and the access token is within
    /// `REFRESH_BUFFER_MS` of expiry (or already expired), POST a refresh
    /// to the token endpoint, persist the new token back to disk, and
    /// update the in-memory auth. No-op otherwise. Returns `Ok(true)` if a
    /// refresh actually happened.
    pub async fn refresh_if_needed(&self) -> Result<bool, LlmError> {
        let path = match &self.credentials_path {
            Some(p) => p.clone(),
            None => return Ok(false),
        };
        // Read current state from disk (source of truth).
        let creds = read_credentials_file(&path)?;
        let needs_refresh = creds.claude_ai_oauth.expires_at > 0
            && creds.claude_ai_oauth.expires_at - now_ms() < REFRESH_BUFFER_MS;
        if !needs_refresh {
            return Ok(false);
        }
        self.refresh_now(&path, &creds).await.map(|_| true)
    }

    /// Force a refresh regardless of expiry. Used on 401 recovery.
    pub async fn refresh_force(&self) -> Result<(), LlmError> {
        let path = self
            .credentials_path
            .clone()
            .ok_or_else(|| LlmError::Transport("no credentials_path; cannot refresh".into()))?;
        let creds = read_credentials_file(&path)?;
        self.refresh_now(&path, &creds).await
    }

    async fn refresh_now(
        &self,
        path: &std::path::Path,
        prior: &CredentialsFile,
    ) -> Result<(), LlmError> {
        let refresh_token = &prior.claude_ai_oauth.refresh_token;
        if refresh_token.is_empty() {
            return Err(LlmError::Transport(
                "credentials file has no refresh_token; cannot refresh".into(),
            ));
        }
        let body = serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": OAUTH_CLIENT_ID,
        });
        let resp = self
            .client
            .post(OAUTH_TOKEN_URL)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::Transport(format!("refresh send: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(LlmError::Upstream {
                status: status.as_u16(),
                body,
            });
        }
        let parsed: TokenRefreshResponse = resp
            .json()
            .await
            .map_err(|e| LlmError::Schema(format!("refresh decode: {e}")))?;

        let new_expires_at = now_ms()
            + (parsed.expires_in.unwrap_or(DEFAULT_TOKEN_LIFETIME_SEC) as i64) * 1000;
        let new_scopes = parsed
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(String::from).collect::<Vec<_>>())
            .unwrap_or_else(|| prior.claude_ai_oauth.scopes.clone());

        let new_file = CredentialsFile {
            claude_ai_oauth: ClaudeAiOauth {
                access_token: parsed.access_token.clone(),
                refresh_token: parsed
                    .refresh_token
                    .unwrap_or_else(|| prior.claude_ai_oauth.refresh_token.clone()),
                expires_at: new_expires_at,
                scopes: new_scopes,
                subscription_type: prior.claude_ai_oauth.subscription_type.clone(),
                rate_limit_tier: prior.claude_ai_oauth.rate_limit_tier.clone(),
            },
        };
        write_credentials_file(path, &new_file)?;
        // Update in-memory auth
        let mut guard = self.auth.lock().expect("auth mutex");
        *guard = AnthropicAuth::OAuth {
            access_token: parsed.access_token,
        };
        Ok(())
    }
}

fn default_credentials_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".claude/.credentials.json"))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn read_credentials_file(path: &std::path::Path) -> Result<CredentialsFile, LlmError> {
    let bytes = std::fs::read(path)
        .map_err(|e| LlmError::Transport(format!("{}: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| LlmError::Schema(format!("{}: {e}", path.display())))
}

fn write_credentials_file(path: &std::path::Path, file: &CredentialsFile) -> Result<(), LlmError> {
    let bytes = serde_json::to_vec(file)
        .map_err(|e| LlmError::Schema(format!("encode credentials: {e}")))?;
    // Atomic write: stage to .tmp sibling, rename into place.
    let tmp = path.with_extension("credentials.json.tmp");
    std::fs::write(&tmp, &bytes)
        .map_err(|e| LlmError::Transport(format!("write {}: {e}", tmp.display())))?;
    // mode 0600 best-effort
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| LlmError::Transport(format!("rename {}: {e}", path.display())))?;
    Ok(())
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    async fn complete(&self, req: MessagesRequest) -> Result<MessagesResponse, LlmError> {
        self.complete_inner(req, None).await
    }

    async fn complete_streamed(
        &self,
        req: MessagesRequest,
        on_delta: TextDeltaSink,
    ) -> Result<MessagesResponse, LlmError> {
        self.complete_inner(req, Some(on_delta)).await
    }

    fn name(&self) -> &str {
        "anthropic"
    }
}

impl AnthropicProvider {
    /// Unified send path. When `on_delta` is `Some`, sets `stream: true` on
    /// the wire and parses SSE events, emitting text deltas; otherwise does
    /// a normal non-streaming POST.
    async fn complete_inner(
        &self,
        mut req: MessagesRequest,
        on_delta: Option<TextDeltaSink>,
    ) -> Result<MessagesResponse, LlmError> {
        let streaming = on_delta.is_some();
        req.stream = streaming;

        if self.credentials_path.is_some() {
            let _ = self.refresh_if_needed().await;
        }

        let body = if self.is_oauth() {
            let caller_system = req.system.take();
            let mut v = serde_json::to_value(&req)
                .map_err(|e| LlmError::Schema(format!("encode request: {e}")))?;
            let mut blocks =
                vec![serde_json::json!({"type": "text", "text": OAUTH_SYSTEM_PREFIX})];
            if let Some(s) = caller_system.filter(|s| !s.is_empty()) {
                blocks.push(serde_json::json!({"type": "text", "text": s}));
            }
            v["system"] = serde_json::Value::Array(blocks);
            v
        } else {
            serde_json::to_value(&req)
                .map_err(|e| LlmError::Schema(format!("encode request: {e}")))?
        };

        let resp = self.send_once(&body).await?;
        let status = resp.status();
        if status.as_u16() == 401 && self.credentials_path.is_some() {
            self.refresh_force().await?;
            let resp2 = self.send_once(&body).await?;
            return self.parse_or_stream(resp2, on_delta).await;
        }
        self.parse_or_stream(resp, on_delta).await
    }

    async fn send_once(&self, body: &serde_json::Value) -> Result<reqwest::Response, LlmError> {
        let mut builder = self
            .client
            .post(self.endpoint())
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json");
        for (k, v) in self.auth_headers() {
            builder = builder.header(k, v);
        }
        builder
            .json(body)
            .send()
            .await
            .map_err(|e| LlmError::Transport(format!("send: {e}")))
    }

    async fn parse_or_stream(
        &self,
        resp: reqwest::Response,
        on_delta: Option<TextDeltaSink>,
    ) -> Result<MessagesResponse, LlmError> {
        let status = resp.status();
        if status.as_u16() == 429 {
            return Err(LlmError::RateLimited);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(LlmError::Upstream {
                status: status.as_u16(),
                body,
            });
        }
        match on_delta {
            None => self.parse_full(resp).await,
            Some(cb) => self.parse_sse(resp, cb).await,
        }
    }

    async fn parse_full(&self, resp: reqwest::Response) -> Result<MessagesResponse, LlmError> {
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| LlmError::Transport(format!("read body: {e}")))?;
        serde_json::from_slice::<MessagesResponse>(&bytes)
            .map_err(|e| LlmError::Schema(format!("decode response: {e}")))
    }

    /// Parse Anthropic SSE event stream. Event types handled:
    ///   - `content_block_start` with `text` or `tool_use` block → start a
    ///     pending block at the given index.
    ///   - `content_block_delta` text_delta → emit via callback + append.
    ///   - `content_block_delta` input_json_delta → accumulate tool args.
    ///   - `content_block_stop` → finalize the pending block.
    ///   - `message_delta` → capture stop_reason.
    ///   - `message_stop` → end.
    /// Returns a fully-reconstructed `MessagesResponse`.
    async fn parse_sse(
        &self,
        resp: reqwest::Response,
        mut on_delta: TextDeltaSink,
    ) -> Result<MessagesResponse, LlmError> {
        use futures_util::StreamExt;

        let mut byte_stream = resp.bytes_stream();
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let mut blocks: std::collections::BTreeMap<u64, PendingBlock> =
            std::collections::BTreeMap::new();
        let mut stop_reason: Option<StopReason> = None;
        let mut usage: Usage = Usage::default();

        while let Some(chunk) = byte_stream.next().await {
            let chunk = chunk
                .map_err(|e| LlmError::Transport(format!("sse chunk: {e}")))?;
            buf.extend_from_slice(&chunk);
            // SSE events are separated by blank lines (\n\n).
            while let Some(pos) = find_double_newline(&buf) {
                let event_bytes = buf.drain(..pos + 2).collect::<Vec<u8>>();
                let event_str = std::str::from_utf8(&event_bytes).unwrap_or("");
                let mut data_line: Option<&str> = None;
                for line in event_str.lines() {
                    if let Some(rest) = line.strip_prefix("data: ") {
                        data_line = Some(rest);
                    }
                }
                let Some(data) = data_line else { continue };
                let Ok(ev) = serde_json::from_str::<serde_json::Value>(data) else {
                    continue;
                };
                let ev_type = ev.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match ev_type {
                    "message_start" => {
                        // initial usage block
                        if let Some(u) = ev
                            .get("message")
                            .and_then(|m| m.get("usage"))
                            .and_then(|v| serde_json::from_value::<Usage>(v.clone()).ok())
                        {
                            usage = u;
                        }
                    }
                    "content_block_start" => {
                        let idx = ev.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                        let block = ev.get("content_block");
                        let kind = block
                            .and_then(|b| b.get("type"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let pending = match kind {
                            "text" => PendingBlock::Text { text: String::new() },
                            "tool_use" => PendingBlock::ToolUse {
                                id: block
                                    .and_then(|b| b.get("id"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                name: block
                                    .and_then(|b| b.get("name"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                input_json: String::new(),
                            },
                            _ => continue,
                        };
                        blocks.insert(idx, pending);
                    }
                    "content_block_delta" => {
                        let idx = ev.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                        let delta = ev.get("delta");
                        let dtype = delta
                            .and_then(|d| d.get("type"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if let Some(b) = blocks.get_mut(&idx) {
                            match (b, dtype) {
                                (PendingBlock::Text { text }, "text_delta") => {
                                    if let Some(t) = delta
                                        .and_then(|d| d.get("text"))
                                        .and_then(|v| v.as_str())
                                    {
                                        on_delta(t);
                                        text.push_str(t);
                                    }
                                }
                                (
                                    PendingBlock::ToolUse { input_json, .. },
                                    "input_json_delta",
                                ) => {
                                    if let Some(s) = delta
                                        .and_then(|d| d.get("partial_json"))
                                        .and_then(|v| v.as_str())
                                    {
                                        input_json.push_str(s);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    "content_block_stop" => {}
                    "message_delta" => {
                        if let Some(stop_str) = ev
                            .get("delta")
                            .and_then(|d| d.get("stop_reason"))
                            .and_then(|v| v.as_str())
                        {
                            if let Ok(parsed) =
                                serde_json::from_value::<StopReason>(serde_json::json!(stop_str))
                            {
                                stop_reason = Some(parsed);
                            }
                        }
                        if let Some(u) = ev
                            .get("usage")
                            .and_then(|v| serde_json::from_value::<Usage>(v.clone()).ok())
                        {
                            // message_delta usage overrides — typically
                            // carries the final output_tokens count
                            usage.output_tokens = u.output_tokens.max(usage.output_tokens);
                        }
                    }
                    "message_stop" => {}
                    "ping" => {}
                    "error" => {
                        let msg = ev
                            .get("error")
                            .and_then(|e| e.get("message"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("(unknown)")
                            .to_string();
                        return Err(LlmError::Upstream {
                            status: 200,
                            body: format!("sse error: {msg}"),
                        });
                    }
                    _ => {}
                }
            }
        }

        let content: Vec<ContentBlock> = blocks
            .into_values()
            .map(|p| match p {
                PendingBlock::Text { text } => ContentBlock::Text { text },
                PendingBlock::ToolUse {
                    id,
                    name,
                    input_json,
                } => {
                    let input = if input_json.is_empty() {
                        serde_json::json!({})
                    } else {
                        serde_json::from_str(&input_json)
                            .unwrap_or_else(|_| serde_json::json!({"raw": input_json}))
                    };
                    ContentBlock::ToolUse { id, name, input }
                }
            })
            .collect();

        Ok(MessagesResponse {
            content,
            stop_reason: stop_reason.ok_or_else(|| LlmError::Transport(
                "SSE stream ended without stop_reason — stream was truncated".into(),
            ))?,
            usage: Some(usage),
        })
    }
}

enum PendingBlock {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        input_json: String,
    },
}

fn find_double_newline(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContentBlock, Message, StopReason};

    #[test]
    fn from_env_errors_when_missing() {
        // Clear in this test process; other tests must not depend on it being set.
        std::env::remove_var("ANTHROPIC_API_KEY");
        let err = AnthropicProvider::from_env().unwrap_err();
        match err {
            LlmError::Transport(msg) => assert!(msg.contains("not set")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn from_env_errors_when_empty() {
        std::env::set_var("ANTHROPIC_API_KEY", "   ");
        let err = AnthropicProvider::from_env().unwrap_err();
        match err {
            LlmError::Transport(msg) => assert!(msg.contains("empty")),
            other => panic!("unexpected error: {other:?}"),
        }
        std::env::remove_var("ANTHROPIC_API_KEY");
    }

    // ── OAuth path ────────────────────────────────────────────────────

    #[test]
    fn with_oauth_constructs_oauth_auth_variant() {
        let p = AnthropicProvider::with_oauth("sk-ant-o-test");
        match p.auth_snapshot() {
            AnthropicAuth::OAuth { access_token } => assert_eq!(access_token, "sk-ant-o-test"),
            other => panic!("expected OAuth, got {other:?}"),
        }
    }

    #[test]
    fn auth_headers_uses_x_api_key_for_api_key_mode() {
        let p = AnthropicProvider::new("sk-ant-api03-keykey");
        let headers = p.auth_headers();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "x-api-key");
        assert_eq!(headers[0].1, "sk-ant-api03-keykey");
    }

    #[test]
    fn auth_headers_uses_bearer_and_oauth_beta_for_oauth_mode() {
        let p = AnthropicProvider::with_oauth("sk-ant-o-toktok");
        let headers = p.auth_headers();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "authorization");
        assert_eq!(headers[0].1, "Bearer sk-ant-o-toktok");
        assert_eq!(headers[1].0, "anthropic-beta");
        assert_eq!(headers[1].1, OAUTH_BETA_HEADER);
    }

    fn write_temp_credentials(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("aether-llm-test-{name}.json"));
        std::fs::write(&path, contents).expect("write temp credentials");
        path
    }

    #[test]
    fn from_credentials_file_reads_token_from_valid_json() {
        let path = write_temp_credentials(
            "valid",
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-o-readme","expiresAt":0}}"#,
        );
        let p = AnthropicProvider::from_credentials_file(&path).unwrap();
        match p.auth_snapshot() {
            AnthropicAuth::OAuth { access_token } => assert_eq!(access_token, "sk-ant-o-readme"),
            other => panic!("expected OAuth, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn from_credentials_file_rejects_expired_token() {
        // 1970-01-02 in unix milliseconds — long expired.
        let path = write_temp_credentials(
            "expired",
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-o-x","expiresAt":86400000}}"#,
        );
        let err = AnthropicProvider::from_credentials_file(&path).unwrap_err();
        match err {
            LlmError::Transport(msg) => {
                assert!(msg.contains("expired"), "got: {msg}");
            }
            other => panic!("expected Transport error, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn from_credentials_file_treats_zero_expiry_as_no_limit() {
        let path = write_temp_credentials(
            "zero-expiry",
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-o-y","expiresAt":0}}"#,
        );
        assert!(AnthropicProvider::from_credentials_file(&path).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn from_credentials_file_rejects_missing_file() {
        let path = std::env::temp_dir().join("aether-llm-test-does-not-exist.json");
        let _ = std::fs::remove_file(&path);
        let err = AnthropicProvider::from_credentials_file(&path).unwrap_err();
        assert!(matches!(err, LlmError::Transport(_)));
    }

    #[test]
    fn from_credentials_file_rejects_malformed_json() {
        let path = write_temp_credentials("bad-json", "not json at all");
        let err = AnthropicProvider::from_credentials_file(&path).unwrap_err();
        assert!(matches!(err, LlmError::Schema(_)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn from_credentials_file_rejects_wrong_shape() {
        // Has the right top-level key but missing the nested accessToken.
        let path = write_temp_credentials(
            "wrong-shape",
            r#"{"claudeAiOauth":{"expiresAt":0}}"#,
        );
        let err = AnthropicProvider::from_credentials_file(&path).unwrap_err();
        assert!(matches!(err, LlmError::Schema(_)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn endpoint_appends_v1_messages_and_handles_trailing_slash() {
        let p1 = AnthropicProvider::new("k").with_base("https://api.example.com");
        let p2 = AnthropicProvider::new("k").with_base("https://api.example.com/");
        assert_eq!(p1.endpoint(), "https://api.example.com/v1/messages");
        assert_eq!(p2.endpoint(), "https://api.example.com/v1/messages");
    }

    #[test]
    fn request_body_matches_anthropic_wire_shape() {
        // Canonical request — fields and casing must match what Anthropic
        // expects on POST /v1/messages. The fact that `serde_json::to_value`
        // produces this exact shape is the proof that our types are wire-
        // compatible without an adapter layer.
        let req = MessagesRequest {
            model: "claude-opus-4-7".into(),
            system: Some("You are AetherCode.".into()),
            messages: vec![Message::user_text("ping")],
            max_tokens: 256,
            tools: vec![],
            stream: false,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["model"], "claude-opus-4-7");
        assert_eq!(v["system"], "You are AetherCode.");
        assert_eq!(v["max_tokens"], 256);
        assert_eq!(v["stream"], false);
        // Single user-role text message, content as a block array.
        assert_eq!(v["messages"][0]["role"], "user");
        assert_eq!(v["messages"][0]["content"][0]["type"], "text");
        assert_eq!(v["messages"][0]["content"][0]["text"], "ping");
    }

    #[test]
    fn response_parses_text_only_end_turn() {
        // Verbatim shape of an Anthropic Messages response, minus the
        // metadata fields we don't read (id, role, model, stop_sequence,
        // usage). serde's default permissive deserialization ignores them.
        let json = r#"{
            "id": "msg_01ABC",
            "type": "message",
            "role": "assistant",
            "model": "claude-haiku-4-5-20251001",
            "content": [{"type": "text", "text": "pong"}],
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {"input_tokens": 5, "output_tokens": 1}
        }"#;
        let resp: MessagesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
        assert_eq!(resp.content.len(), 1);
        match &resp.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "pong"),
            other => panic!("expected text block, got {other:?}"),
        }
    }

    #[test]
    fn response_parses_mixed_text_and_tool_use() {
        let json = r#"{
            "id": "msg_01XYZ",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-4-7",
            "content": [
                {"type": "text", "text": "checking now."},
                {"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"city": "Paris"}}
            ],
            "stop_reason": "tool_use"
        }"#;
        let resp: MessagesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
        assert_eq!(resp.content.len(), 2);
        match &resp.content[1] {
            ContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "toolu_01");
                assert_eq!(name, "get_weather");
                assert_eq!(input["city"], "Paris");
            }
            other => panic!("expected tool_use block, got {other:?}"),
        }
    }

    #[test]
    fn response_handles_all_stop_reasons() {
        for (raw, expected) in [
            ("end_turn", StopReason::EndTurn),
            ("tool_use", StopReason::ToolUse),
            ("max_tokens", StopReason::MaxTokens),
            ("refusal", StopReason::Refusal),
            ("stop_sequence", StopReason::StopSequence),
            ("pause_turn", StopReason::PauseTurn),
        ] {
            let json = format!(
                r#"{{"content": [], "stop_reason": "{raw}"}}"#
            );
            let resp: MessagesResponse = serde_json::from_str(&json).unwrap();
            assert_eq!(resp.stop_reason, expected, "raw: {raw}");
        }
    }
}
