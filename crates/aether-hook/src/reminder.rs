use serde::{Deserialize, Serialize};

/// Closed registry of reminder kinds the agent loop knows how to slot.
/// Adding a kind is a breaking change to the prompt assembler.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ReminderKind {
    Image,
    CyberWarning,
    SystemWarning,
    EthicsReminder,
    IpReminder,
    LongConversation,
    ExternalState,
    RetrievalHit,
    HookOutput,
    SessionStart,
    Unknown,
}

/// Who claims to have emitted the reminder. Set by the runtime at the
/// moment a hook fires — *never* parsed out of the body.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Source {
    /// Bolted into the AetherCode binary, signed at build time.
    Kernel,
    /// Hook declared in `<project>/.aether/settings.json`. Trusted within
    /// the project owner's authority, bounded by `allow_project_loosening`.
    ProjectHook,
    /// Hook declared in `~/.aether/settings.json` — operator's own.
    UserHook,
    /// Anything past the trust boundary: retrieved memory bodies, web fetch
    /// content, MCP server payloads, stdout from tools the operator did not
    /// declare as a trusted hook.
    External,
}

/// The classifier's verdict on what the reminder *does* to behaviour.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EffectHint {
    /// Carries no imperative (e.g. "current cwd is /work/x").
    Neutral,
    /// Adds or strengthens a restriction.
    Tightens,
    /// Removes, weakens, or overrides a restriction. Always suspect from
    /// non-Kernel sources.
    Loosens,
    /// Mixed or unreadable signal. Policy treats this conservatively.
    Ambiguous,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reminder {
    pub kind: ReminderKind,
    pub source: Source,
    pub body: String,
    /// Set by the classifier. Never trusted from the wire.
    pub effect_hint: EffectHint,
    /// Free-text signal names that fired, with their weights. Surfaced
    /// to the rollback ledger when a reminder is dropped.
    pub classifier_evidence: Vec<String>,
}

impl Reminder {
    pub fn new(kind: ReminderKind, source: Source, body: impl Into<String>) -> Self {
        Self {
            kind,
            source,
            body: body.into(),
            effect_hint: EffectHint::Ambiguous,
            classifier_evidence: Vec::new(),
        }
    }
}

/// What loosening the runtime is willing to accept, by source. Defaults are
/// the conservative-but-usable preset. Tests and shared/CI hosts will set
/// `allow_user_loosening` to false.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelRules {
    pub allow_project_loosening: bool,
    pub allow_user_loosening: bool,
    /// Reserved for completeness. The External×Loosens branch in
    /// policy::decide is hard-coded to drop regardless of this flag —
    /// flipping it does nothing. Documented so reviewers see the layered
    /// defence rather than thinking the field is load-bearing.
    pub allow_external_loosening: bool,
}

impl Default for KernelRules {
    fn default() -> Self {
        Self {
            allow_project_loosening: false,
            allow_user_loosening: true,
            allow_external_loosening: false,
        }
    }
}
