//! Azure AI Foundry back-end (Claude models hosted on Azure).
//!
//! Azure AI Foundry exposes Anthropic Messages-API-compatible endpoints
//! for Claude models hosted in Azure subscriptions. The wire shape is
//! identical to Anthropic's; the differences are:
//!   * URL is per-resource: `https://{resource}.services.ai.azure.com`
//!     with an explicit `?api-version=...` query parameter.
//!   * Auth uses the `api-key` header (resource-scoped) instead of
//!     `x-api-key` (Anthropic) or signed AWS / GCP tokens.
//!   * Endpoint path: `/anthropic/v1/messages`.
//!
//! Env config:
//!   * `AZURE_AI_ENDPOINT`   — required, e.g. `https://my.services.ai.azure.com`
//!   * `AZURE_AI_API_KEY`    — required, the resource-scoped key
//!   * `AZURE_AI_API_VERSION` — optional, defaults to a sensible recent version
//!
//! Status: UNVERIFIED. Compile + unit tests only. Live-verified once a
//! reviewer with an Azure AI Foundry subscription tests against a real
//! deployment.

use crate::{LlmError, LlmProvider, MessagesRequest, MessagesResponse};
use async_trait::async_trait;
use std::time::Duration;

/// Default Azure AI Foundry API version. Bump when Microsoft promotes a
/// newer preview; the wire shape is stable across the recent versions.
pub const DEFAULT_API_VERSION: &str = "2024-08-01-preview";

/// Default request timeout. Mirrors anthropic.rs.
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub struct AzureProvider {
    client: reqwest::Client,
    /// Base resource URL, e.g. `https://my-resource.services.ai.azure.com`.
    /// Trailing slashes are stripped at construction.
    endpoint: String,
    api_key: String,
    api_version: String,
}

impl AzureProvider {
    pub fn new(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        api_version: impl Into<String>,
    ) -> Result<Self, LlmError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .map_err(|e| LlmError::Transport(format!("build client: {e}")))?;
        Ok(Self {
            client,
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            api_version: api_version.into(),
        })
    }

    pub fn from_env() -> Result<Self, LlmError> {
        let endpoint = std::env::var("AZURE_AI_ENDPOINT")
            .map_err(|_| LlmError::Transport("AZURE_AI_ENDPOINT not set".into()))?;
        let api_key = std::env::var("AZURE_AI_API_KEY")
            .map_err(|_| LlmError::Transport("AZURE_AI_API_KEY not set".into()))?;
        let api_version = std::env::var("AZURE_AI_API_VERSION")
            .unwrap_or_else(|_| DEFAULT_API_VERSION.to_string());
        Self::new(endpoint, api_key, api_version)
    }

    /// Build the messages endpoint URL with the api-version query parameter.
    pub fn messages_url(&self) -> String {
        format!(
            "{}/anthropic/v1/messages?api-version={}",
            self.endpoint, self.api_version
        )
    }
}

#[async_trait]
impl LlmProvider for AzureProvider {
    async fn complete(&self, req: MessagesRequest) -> Result<MessagesResponse, LlmError> {
        // Strip `stream: true` on the wire (this entry point is non-streaming)
        // and let the canonical MessagesRequest serialize the rest. The wire
        // shape Azure AI Foundry expects is identical to Anthropic's, so no
        // adapter struct is needed.
        let mut wire = req.clone();
        wire.stream = false;

        let resp = self
            .client
            .post(self.messages_url())
            .header("api-key", &self.api_key)
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
        "azure-foundry"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_url_includes_api_version() {
        let p = AzureProvider::new(
            "https://my-resource.services.ai.azure.com",
            "test-key",
            "2024-08-01-preview",
        )
        .expect("construct");
        assert_eq!(
            p.messages_url(),
            "https://my-resource.services.ai.azure.com/anthropic/v1/messages?api-version=2024-08-01-preview"
        );
    }

    #[test]
    fn messages_url_strips_trailing_slash() {
        let p = AzureProvider::new(
            "https://my-resource.services.ai.azure.com/",
            "test-key",
            "2024-08-01-preview",
        )
        .expect("construct");
        assert!(
            !p.messages_url()
                .contains("services.ai.azure.com//"),
            "trailing slash leaked into URL: {}",
            p.messages_url()
        );
    }

    #[test]
    fn from_env_errors_when_endpoint_missing() {
        // Make sure no stale value is in scope.
        std::env::remove_var("AZURE_AI_ENDPOINT");
        std::env::remove_var("AZURE_AI_API_KEY");
        let err = AzureProvider::from_env().err().expect("expected error");
        assert!(
            format!("{err}").contains("AZURE_AI_ENDPOINT"),
            "got: {err}"
        );
    }

    #[test]
    fn name_is_stable() {
        let p = AzureProvider::new("https://x", "k", "v").unwrap();
        assert_eq!(p.name(), "azure-foundry");
    }
}
