//! Verifier (verify phase) — wraps `aether-selfcheck::Gate` (D7).
//!
//! The gate runs on every assistant text before emission. On `Pass` the
//! (possibly rewritten) message is returned; on `Blocked` the agent loop
//! sets `plan.dirty = true` and reschedules without showing the output.

use aether_selfcheck::{Finding, Gate, Outcome, SessionContext};

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub message: String,
    pub findings: Vec<Finding>,
    pub blocked_reasons: Vec<Finding>,
}

impl VerificationResult {
    pub fn is_blocked(&self) -> bool {
        !self.blocked_reasons.is_empty()
    }
    pub fn was_rewritten(&self, original: &str) -> bool {
        !self.is_blocked() && self.message != original
    }
}

pub struct Verifier {
    pub gate: Gate,
}

impl Verifier {
    pub fn new(gate: Gate) -> Self {
        Self { gate }
    }

    pub fn check_before_emit(
        &self,
        message: &str,
        session_ctx: &SessionContext,
    ) -> VerificationResult {
        match self.gate.check(message, session_ctx) {
            Outcome::Pass { message, log } => VerificationResult {
                message,
                findings: log,
                blocked_reasons: vec![],
            },
            Outcome::Blocked {
                partial_message,
                reasons,
                log,
            } => VerificationResult {
                message: partial_message,
                findings: log,
                blocked_reasons: reasons,
            },
        }
    }
}
