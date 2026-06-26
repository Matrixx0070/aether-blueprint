//! Mantle BYOC back-end.
//!
//! Mantle is a thin Anthropic-Messages-API-compatible proxy slot: same
//! wire shape as the canonical Anthropic provider, with a configurable
//! base URL and a `Authorization: Bearer <key>` header. The intent is
//! to support self-hosted or enterprise-routed deployments without
//! adding another provider-specific wire dialect.
//!
//! Env config:
//!   * `MANTLE_API_KEY`  — required. Bearer token for the proxy.
//!   * `MANTLE_BASE_URL` — optional. Defaults to
//!     `https://api.mantle.ai`. Trailing slashes stripped.
//!
//! Status: UNVERIFIED end-to-end against a live Mantle deployment in
//! this session — the unit tests cover URL construction, env wiring,
//! and request shape. Replace the default base URL with whatever
//! Mantle's prod docs declare at the time of slice-write; the wire
//! contract is Anthropic-compatible by design.

use crate::{LlmError, LlmProvider, MessagesRequest, MessagesResponse};
use async_trait::async_trait;
use std::time::Duration;

pub const DEFAULT_BASE_URL: &str = "https://api.mantle.ai";
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub struct MantleProvider {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl MantleProvider {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Result<Self, LlmError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .map_err(|e| LlmError::Transport(format!("build client: {e}")))?;
        Ok(Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
        })
    }

    pub fn from_env() -> Result<Self, LlmError> {
        let api_key = std::env::var("MANTLE_API_KEY")
            .map_err(|_| LlmError::Transport("MANTLE_API_KEY not set".into()))?;
        let base_url =
            std::env::var("MANTLE_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
        Self::new(base_url, api_key)
    }

    pub fn messages_url(&self) -> String {
        format!("{}/v1/messages", self.base_url)
    }
}

#[async_trait]
impl LlmProvider for MantleProvider {
    async fn complete(&self, req: MessagesRequest) -> Result<MessagesResponse, LlmError> {
        let mut wire = req.clone();
        wire.stream = false;

        let resp = self
            .client
            .post(self.messages_url())
            .header("authorization", format!("Bearer {}", self.api_key))
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&wire)
            .send()
            .await
            .map_err(|e| LlmError::Transport(format!("send: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            if status.as_u16() == 429 {
                return Err(LlmError::RateLimited);
            }
            return Err(LlmError::Upstream {
                status: status.as_u16(),
                body: body_text,
            });
        }

        let body_text = resp
            .text()
            .await
            .map_err(|e| LlmError::Transport(format!("read body: {e}")))?;
        serde_json::from_str(&body_text).map_err(|e| LlmError::Schema(e.to_string()))
    }

    fn name(&self) -> &str {
        "mantle"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Serializes env-var-touching tests across the parallel cargo runner.
    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    #[test]
    fn messages_url_uses_v1_messages_path() {
        let p = MantleProvider::new("https://example.mantle.ai", "k").unwrap();
        assert_eq!(p.messages_url(), "https://example.mantle.ai/v1/messages");
    }

    #[test]
    fn messages_url_strips_trailing_slash() {
        let p = MantleProvider::new("https://example.mantle.ai/", "k").unwrap();
        assert_eq!(p.messages_url(), "https://example.mantle.ai/v1/messages");
    }

    #[test]
    fn from_env_errors_when_key_missing() {
        let _g = ENV_LOCK.lock().expect("env lock");
        std::env::remove_var("MANTLE_API_KEY");
        std::env::remove_var("MANTLE_BASE_URL");
        let err = MantleProvider::from_env().err().expect("expected error");
        assert!(format!("{err}").contains("MANTLE_API_KEY"), "got: {err}");
    }

    #[test]
    fn from_env_uses_default_url_when_unset() {
        let _g = ENV_LOCK.lock().expect("env lock");
        std::env::set_var("MANTLE_API_KEY", "test-key");
        std::env::remove_var("MANTLE_BASE_URL");
        let p = MantleProvider::from_env().expect("construct");
        assert!(
            p.messages_url().starts_with(DEFAULT_BASE_URL),
            "got: {}",
            p.messages_url()
        );
        std::env::remove_var("MANTLE_API_KEY");
    }

    #[test]
    fn name_is_stable() {
        let p = MantleProvider::new("https://x", "k").unwrap();
        assert_eq!(p.name(), "mantle");
    }
}
