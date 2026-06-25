//! AetherCode pre-emission self-check gate (D7).
//!
//! Walks a YAML-defined rule library against an assistant message *before*
//! it leaves the agent loop. Each rule declares (a) a detector — phrase
//! match, regex, or named built-in; (b) an action — Warn, Rewrite, or
//! Block; and (c) an `applies_when` predicate keyed off session context.
//!
//! Two passes:
//!   1. all Rewrite-action rules collect hits; rewrites are applied
//!      right-to-left so byte offsets stay stable.
//!   2. Warn and Block rules then evaluate the rewritten text.
//!
//! This is the second line of defence for the agent loop; D1 (reminder
//! tamper-test) is the first. D7 catches drift at *output* time —
//! banned phrases, forbidden memory leakage, copyright over-quote,
//! placeholder leakage, secret exfiltration, unverified claims, etc.

pub mod detector;
pub mod gate;
pub mod loader;
pub mod rule;
pub mod session;

pub use gate::{ActionTaken, Finding, Gate, Outcome};
pub use loader::{bundled_rules, load_dir, load_rule_file, load_rule_str};
pub use rule::{
    Action, AppliesWhen, Detector, Remediation, RemediationStrategy, Rule, Severity,
};
pub use session::SessionContext;
