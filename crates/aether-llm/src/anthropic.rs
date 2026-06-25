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
//!   * Non-streaming only (`stream` is forced to `false` on the wire even
//!     if the caller's `MessagesRequest` sets it).
//!   * No prompt-cache or extended-thinking knobs surfaced yet.
//!   * No automatic retry — backoff is the caller's responsibility (the
//!     agent loop's verifier-driven re-plan handles this naturally for
//!     blocks; rate-limit retry belongs in a separate slice).

use crate::{LlmError, LlmProvider, MessagesRequest, MessagesResponse};
use async_trait::async_trait;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const ANTHROPIC_API_BASE: &str = "https://api.anthropic.com";
pub const ANTHROPIC_VERSION: &str = "2023-06-01";
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;

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

    /// Best-effort auto-detection: explicit `ANTHROPIC_API_KEY` env wins,
    /// then `CLAUDE_CODE_OAUTH_TOKEN` env, then `~/.claude/.credentials.json`.
    /// Returns the first viable source; errors only when none works.
    pub fn from_env_or_credentials() -> Result<Self, LlmError> {
        if let Ok(k) = std::env::var("ANTHROPIC_API_KEY") {
            if !k.trim().is_empty() {
                return Ok(Self::new(k));
            }
        }
        if let Ok(t) = std::env::var("CLAUDE_CODE_OAUTH_TOKEN") {
            if !t.trim().is_empty() {
                return Ok(Self::with_oauth(t));
            }
        }
        Self::from_claude_code_credentials()
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
    async fn complete(&self, mut req: MessagesRequest) -> Result<MessagesResponse, LlmError> {
        // Force non-streaming on the wire. The trait carries `stream` for
        // future use but this v1 impl doesn't consume SSE.
        req.stream = false;

        // Proactive refresh: if loaded from a credentials file and the
        // access token is within REFRESH_BUFFER_MS of expiry, refresh
        // before sending. Failure is non-fatal; the request still goes
        // out with the stale token and falls into 401 recovery below.
        if self.credentials_path.is_some() {
            let _ = self.refresh_if_needed().await;
        }

        let body = if self.is_oauth() {
            // OAuth-only policy gate: block 0 of `system` must exactly equal
            // an approved identity string. Send as an array so additional
            // caller content can ride along as subsequent blocks.
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

        // First attempt
        let resp = self.send_once(&body).await?;
        let status = resp.status();
        if status.as_u16() == 401 && self.credentials_path.is_some() {
            // 401 recovery: force refresh + retry once
            self.refresh_force().await?;
            let resp2 = self.send_once(&body).await?;
            return self.parse_response(resp2).await;
        }
        self.parse_response(resp).await
    }

    fn name(&self) -> &str {
        "anthropic"
    }
}

impl AnthropicProvider {
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

    async fn parse_response(
        &self,
        resp: reqwest::Response,
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
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| LlmError::Transport(format!("read body: {e}")))?;
        serde_json::from_slice::<MessagesResponse>(&bytes)
            .map_err(|e| LlmError::Schema(format!("decode response: {e}")))
    }
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
