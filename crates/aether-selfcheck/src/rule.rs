use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Log a finding but pass the message through unchanged.
    Warn,
    /// Modify the message in place using the remediation strategy.
    Rewrite,
    /// Refuse emission. Surface all block findings together.
    Block,
}

/// Predicate keyed off `SessionContext`. Rules with `applies_when: always`
/// always run; others gate on a single boolean from the session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppliesWhen {
    Always,
    MemoryActive,
    NotUserAskedAboutMemory,
    CiteTagsPresent,
    NotCiteTagsPresent,
    NoRecentExternalLookup,
    DistressFlagged,
    UserDidNotCurse,
    /// True when the most recent user turn did NOT ask for creative
    /// writing (poetry, song lyrics, haiku). Rules guarding against
    /// copyright over-quote use this to skip themselves when the user
    /// explicitly requested a poem.
    NotCreativeWritingContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Detector {
    /// Literal substring match. Cheapest. Case-insensitive by default.
    PhraseMatch {
        patterns: Vec<String>,
        #[serde(default)]
        case_sensitive: bool,
    },
    /// Regex match. Case-insensitive by default.
    Regex {
        patterns: Vec<String>,
        #[serde(default)]
        case_sensitive: bool,
    },
    /// Named built-in detector with free-form config (see detector.rs).
    Builtin {
        name: String,
        #[serde(default)]
        config: serde_yaml::Value,
    },
    /// LLM-native probe — asks a yes/no question against the assistant message.
    /// Fires (hit) when verdict == "yes" && confidence >= threshold.
    /// The sync Gate::check pass skips these; call probe::run_probes separately.
    LlmProbe {
        question: String,
        #[serde(default = "default_probe_model")]
        model: String,
        #[serde(default = "default_probe_threshold")]
        threshold: f32,
    },
}

fn default_probe_model() -> String {
    "claude-haiku-4-5-20251001".to_string()
}

fn default_probe_threshold() -> f32 {
    0.7
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStrategy {
    /// Remove the matched span entirely.
    Strip,
    /// Replace with `[REDACTED]`.
    Redact,
    /// Wrap with an annotation (default `[UNVERIFIED: {match}]`).
    Annotate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub strategy: RemediationStrategy,
    /// Used only by `Annotate`. `{match}` is replaced with the hit text.
    #[serde(default)]
    pub template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub action: Action,
    pub applies_when: AppliesWhen,
    pub detector: Detector,
    #[serde(default)]
    pub remediation: Option<Remediation>,
}
