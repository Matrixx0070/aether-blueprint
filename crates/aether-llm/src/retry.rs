//! Retry watchdog for transient LLM errors.
//!
//! Wraps any `LlmProvider` impl in `RetryingProvider`. On retryable errors
//! (5xx, 429, network transport), retries up to `max_attempts` times with
//! exponential backoff (`base_delay_ms * 2^(attempt-1)`).
//!
//! Non-retryable errors (4xx other than 429, schema mismatches) return
//! immediately on the first failure — retrying them is a waste.
//!
//! Streaming (`complete_streamed`) is NOT retried because partial output
//! may already have reached the caller via `on_delta`; a retry would
//! duplicate text. Streaming calls go directly to the inner provider.
//!
//! Kill-switch: `AETHER_NO_RETRY=1` disables retry entirely (single attempt).
//!
//! Retry-After header parsing is deliberately deferred — the canonical
//! `LlmError::Upstream { status, body }` doesn't carry headers today, and
//! plumbing headers through every provider is its own slice. Exponential
//! backoff (1s → 2s → 4s) covers the typical service-recovery window.

use crate::{LlmError, LlmProvider, MessagesRequest, MessagesResponse, TextDeltaSink};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub base_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_ms: 1000,
        }
    }
}

/// Decide whether an `LlmError` is worth retrying.
///
/// Retried: 429 rate limit, 5xx server errors, transport-level failures.
/// Not retried: 4xx (other than 429), schema mismatches — these won't
/// improve on the next try.
pub fn is_retryable(err: &LlmError) -> bool {
    match err {
        LlmError::RateLimited => true,
        LlmError::Upstream { status, .. } => *status >= 500 && *status < 600,
        LlmError::Transport(_) => true,
        LlmError::Schema(_) => false,
    }
}

/// Compute the backoff delay in ms for the given (1-based) attempt index.
/// Pure function for testability.
pub fn backoff_delay_ms(config: &RetryConfig, attempt: u32) -> u64 {
    let shift = (attempt.saturating_sub(1)).min(20); // clamp to avoid overflow
    config.base_delay_ms.saturating_mul(1u64 << shift)
}

/// Decorator that wraps any `LlmProvider` and retries transient failures.
/// Sleeps via `tokio::time::sleep` between attempts.
pub struct RetryingProvider {
    inner: Arc<dyn LlmProvider>,
    config: RetryConfig,
}

impl RetryingProvider {
    pub fn new(inner: Arc<dyn LlmProvider>) -> Self {
        Self {
            inner,
            config: RetryConfig::default(),
        }
    }

    pub fn with_config(inner: Arc<dyn LlmProvider>, config: RetryConfig) -> Self {
        Self { inner, config }
    }
}

#[async_trait]
impl LlmProvider for RetryingProvider {
    async fn complete(&self, req: MessagesRequest) -> Result<MessagesResponse, LlmError> {
        let disabled = std::env::var("AETHER_NO_RETRY").ok().as_deref() == Some("1");
        if disabled {
            return self.inner.complete(req).await;
        }
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match self.inner.complete(req.clone()).await {
                Ok(resp) => return Ok(resp),
                Err(e) if attempt < self.config.max_attempts && is_retryable(&e) => {
                    let delay_ms = backoff_delay_ms(&self.config, attempt);
                    eprintln!(
                        "[retry] attempt {attempt}/{} failed: {e}; sleeping {delay_ms}ms",
                        self.config.max_attempts
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn complete_streamed(
        &self,
        req: MessagesRequest,
        on_delta: TextDeltaSink,
    ) -> Result<MessagesResponse, LlmError> {
        // Streaming is NOT retried: partial output may have reached the
        // caller via on_delta, and a retry would duplicate text. Callers
        // who want retry on streaming should add it at a higher layer
        // that knows whether any delta has been emitted yet.
        self.inner.complete_streamed(req, on_delta).await
    }

    fn name(&self) -> &str {
        self.inner.name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContentBlock, MessagesResponse, Role, StopReason};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn is_retryable_classification() {
        // Retryable.
        assert!(is_retryable(&LlmError::RateLimited));
        assert!(is_retryable(&LlmError::Upstream {
            status: 500,
            body: "".into()
        }));
        assert!(is_retryable(&LlmError::Upstream {
            status: 503,
            body: "".into()
        }));
        assert!(is_retryable(&LlmError::Upstream {
            status: 599,
            body: "".into()
        }));
        assert!(is_retryable(&LlmError::Transport("net broken".into())));
        // Not retryable.
        assert!(!is_retryable(&LlmError::Upstream {
            status: 400,
            body: "".into()
        }));
        assert!(!is_retryable(&LlmError::Upstream {
            status: 401,
            body: "".into()
        }));
        assert!(!is_retryable(&LlmError::Upstream {
            status: 404,
            body: "".into()
        }));
        assert!(!is_retryable(&LlmError::Schema("bad json".into())));
    }

    #[test]
    fn backoff_delay_doubles() {
        let cfg = RetryConfig {
            max_attempts: 5,
            base_delay_ms: 1000,
        };
        assert_eq!(backoff_delay_ms(&cfg, 1), 1000);
        assert_eq!(backoff_delay_ms(&cfg, 2), 2000);
        assert_eq!(backoff_delay_ms(&cfg, 3), 4000);
        assert_eq!(backoff_delay_ms(&cfg, 4), 8000);
    }

    #[test]
    fn backoff_clamps_huge_attempts() {
        let cfg = RetryConfig {
            max_attempts: 100,
            base_delay_ms: 1,
        };
        // shift of 25 → 33_554_432 ms; shift of 100 would overflow without clamp.
        let big = backoff_delay_ms(&cfg, 25);
        assert!(big > 0, "expected positive delay, got {big}");
        // Attempt 100 must not panic / wrap; our clamp caps at shift=20.
        let huge = backoff_delay_ms(&cfg, 100);
        assert_eq!(huge, 1u64 << 20);
    }

    /// Provider that returns scripted errors then a final response.
    struct ScriptedProvider {
        responses: std::sync::Mutex<Vec<Result<MessagesResponse, LlmError>>>,
        calls: AtomicU32,
    }

    impl ScriptedProvider {
        fn new(responses: Vec<Result<MessagesResponse, LlmError>>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses),
                calls: AtomicU32::new(0),
            }
        }
        fn call_count(&self) -> u32 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl LlmProvider for ScriptedProvider {
        async fn complete(
            &self,
            _req: MessagesRequest,
        ) -> Result<MessagesResponse, LlmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut g = self.responses.lock().unwrap();
            if g.is_empty() {
                return Err(LlmError::Transport("script exhausted".into()));
            }
            g.remove(0)
        }
        fn name(&self) -> &str {
            "scripted"
        }
    }

    fn ok_response() -> MessagesResponse {
        MessagesResponse {
            content: vec![ContentBlock::Text {
                text: "ok".into(),
            }],
            stop_reason: StopReason::EndTurn,
            usage: None,
        }
    }

    fn dummy_req() -> MessagesRequest {
        MessagesRequest {
            model: "m".into(),
            system: None,
            messages: vec![crate::Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "hi".into() }],
            }],
            max_tokens: 16,
            tools: vec![],
            stream: false,
        }
    }

    #[tokio::test]
    async fn retries_on_5xx_and_returns_eventual_success() {
        let inner = Arc::new(ScriptedProvider::new(vec![
            Err(LlmError::Upstream {
                status: 503,
                body: "transient".into(),
            }),
            Ok(ok_response()),
        ]));
        let r = RetryingProvider::with_config(
            inner.clone() as Arc<dyn LlmProvider>,
            RetryConfig {
                max_attempts: 3,
                base_delay_ms: 1, // tight loop in tests
            },
        );
        let resp = r.complete(dummy_req()).await.expect("retry should succeed");
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
        assert_eq!(inner.call_count(), 2, "expected 1 failure + 1 success");
    }

    #[tokio::test]
    async fn does_not_retry_4xx() {
        let inner = Arc::new(ScriptedProvider::new(vec![Err(LlmError::Upstream {
            status: 400,
            body: "bad request".into(),
        })]));
        let r = RetryingProvider::with_config(
            inner.clone() as Arc<dyn LlmProvider>,
            RetryConfig {
                max_attempts: 5,
                base_delay_ms: 1,
            },
        );
        let err = r.complete(dummy_req()).await.expect_err("should fail");
        assert!(matches!(err, LlmError::Upstream { status: 400, .. }));
        assert_eq!(inner.call_count(), 1, "4xx must not be retried");
    }

    #[tokio::test]
    async fn max_attempts_exceeded_returns_last_error() {
        let inner = Arc::new(ScriptedProvider::new(vec![
            Err(LlmError::RateLimited),
            Err(LlmError::RateLimited),
            Err(LlmError::RateLimited),
        ]));
        let r = RetryingProvider::with_config(
            inner.clone() as Arc<dyn LlmProvider>,
            RetryConfig {
                max_attempts: 3,
                base_delay_ms: 1,
            },
        );
        let err = r.complete(dummy_req()).await.expect_err("should fail");
        assert!(matches!(err, LlmError::RateLimited));
        assert_eq!(inner.call_count(), 3, "exact max_attempts calls");
    }

    #[tokio::test]
    async fn kill_switch_disables_retry() {
        // Serialize env-var manipulation across tests in this binary.
        use std::sync::Mutex as StdMutex;
        static LOCK: StdMutex<()> = StdMutex::new(());
        let _guard = LOCK.lock().expect("env lock");

        std::env::set_var("AETHER_NO_RETRY", "1");
        let inner = Arc::new(ScriptedProvider::new(vec![Err(LlmError::Upstream {
            status: 503,
            body: "transient".into(),
        })]));
        let r = RetryingProvider::with_config(
            inner.clone() as Arc<dyn LlmProvider>,
            RetryConfig {
                max_attempts: 5,
                base_delay_ms: 1,
            },
        );
        let err = r.complete(dummy_req()).await.expect_err("should fail");
        std::env::remove_var("AETHER_NO_RETRY");
        assert!(matches!(err, LlmError::Upstream { status: 503, .. }));
        assert_eq!(
            inner.call_count(),
            1,
            "kill-switch must force a single attempt"
        );
    }
}
