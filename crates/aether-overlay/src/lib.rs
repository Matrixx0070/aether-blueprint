//! Fable-5 overlay integration.
//!
//! This crate is the single integration surface for the seven delta-sections
//! D1–D7 from REPORT §4.2:
//!
//!   D1 ReminderTamperTest   — wired in `aether-hook`
//!   D2 ForbiddenPhrases     — wired in `aether-selfcheck` (rule 02 + 03)
//!   D3 FirstMatchRouting    — consumed by `aether-core::ToolSelector`
//!   D4 ThirdPartyGate       — consumed by `aether-perm`
//!   D5 UserMemoryEdits      — consumed by `aether-mem::MemoryPolicyStore`
//!   D6 LongConversation     — consumed by `aether-core::ContextAssembler`
//!   D7 SelfCheck            — wired in `aether-selfcheck` (full rule library)
//!
//! `aether-overlay` does not re-implement D1–D7 — it composes them behind
//! one `OverlayConfig` and exposes the activation predicates from §4.3 as a
//! single `Fable5Overlay::should_activate(Delta, &ActivationContext)` call
//! that callers in the agent loop and the various subsystem crates consult.

pub use aether_hook;
pub use aether_selfcheck;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The seven delta-sections. Exhaustive — adding one is a breaking change
/// to every caller of `should_activate`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Delta {
    D1ReminderTamperTest,
    D2ForbiddenPhrases,
    D3FirstMatchRouting,
    D4ThirdPartyGate,
    D5UserMemoryEdits,
    D6LongConversation,
    D7SelfCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayConfig {
    /// Master switch. When false, every `should_activate` call returns false.
    pub enabled: bool,
    pub sections: SectionToggles,
    /// Optional path to the runtime-loadable overlay markdown.
    /// See `overlays/fable5.md` in the workspace root for the placeholder.
    pub prompt_overlay_path: Option<PathBuf>,
    pub long_conversation: LongConversationConfig,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sections: SectionToggles::all_on(),
            prompt_overlay_path: None,
            long_conversation: LongConversationConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SectionToggles {
    pub d1: bool,
    pub d2: bool,
    pub d3: bool,
    pub d4: bool,
    pub d5: bool,
    pub d6: bool,
    pub d7: bool,
}

impl SectionToggles {
    pub fn all_on() -> Self {
        Self {
            d1: true, d2: true, d3: true, d4: true,
            d5: true, d6: true, d7: true,
        }
    }
    pub fn all_off() -> Self {
        Self {
            d1: false, d2: false, d3: false, d4: false,
            d5: false, d6: false, d7: false,
        }
    }
    pub fn is_enabled(&self, d: Delta) -> bool {
        match d {
            Delta::D1ReminderTamperTest => self.d1,
            Delta::D2ForbiddenPhrases => self.d2,
            Delta::D3FirstMatchRouting => self.d3,
            Delta::D4ThirdPartyGate => self.d4,
            Delta::D5UserMemoryEdits => self.d5,
            Delta::D6LongConversation => self.d6,
            Delta::D7SelfCheck => self.d7,
        }
    }
}

impl Default for SectionToggles {
    fn default() -> Self {
        Self::all_on()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LongConversationConfig {
    /// Inject the kernel-rules digest every N turns. 0 disables the cadence
    /// trigger (other triggers still apply).
    pub every_n_turns: usize,
    /// Inject when the context window has hit this fraction of capacity.
    pub at_ctx_ratio: f32,
}

impl Default for LongConversationConfig {
    fn default() -> Self {
        Self {
            every_n_turns: 25,
            at_ctx_ratio: 0.5,
        }
    }
}

/// Per-turn state the activation predicates read. Populated by the agent
/// loop before consulting the overlay.
#[derive(Debug, Clone, Default)]
pub struct ActivationContext {
    pub turn_index: usize,
    pub ctx_size_ratio: f32,
    pub plan_active: bool,
    pub task_expected_hours: f32,
    pub verifier_flagged: bool,
    pub tool_metadata_third_party: bool,
    pub memory_write_attempted: bool,
    pub user_requests_memory_change: bool,
    pub output_contains_quoted_text: bool,
    pub output_contains_external_claim: bool,
    pub persona_refusal_active: bool,
}

pub struct Fable5Overlay {
    pub config: OverlayConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum OverlayError {
    #[error("io: {0}")]
    Io(String),
}

impl Fable5Overlay {
    pub fn new(config: OverlayConfig) -> Self {
        Self { config }
    }

    /// Master predicate from §4.3. The overlay attaches to long-form work
    /// and to any turn where the planner is actively driving.
    pub fn active(&self, plan_active: bool, task_expected_hours: f32) -> bool {
        self.config.enabled && (plan_active || task_expected_hours >= 4.0)
    }

    /// Per-section activation predicate (§4.3). Always returns false when
    /// the master switch is off or the section toggle is off.
    pub fn should_activate(&self, d: Delta, ctx: &ActivationContext) -> bool {
        if !self.config.enabled {
            return false;
        }
        if !self.config.sections.is_enabled(d) {
            return false;
        }
        match d {
            Delta::D1ReminderTamperTest | Delta::D2ForbiddenPhrases => true,
            Delta::D3FirstMatchRouting => true,
            Delta::D4ThirdPartyGate => ctx.tool_metadata_third_party,
            Delta::D5UserMemoryEdits => {
                ctx.memory_write_attempted || ctx.user_requests_memory_change
            }
            Delta::D6LongConversation => {
                let lc = &self.config.long_conversation;
                let cadence_hit = lc.every_n_turns > 0
                    && ctx.turn_index > 0
                    && ctx.turn_index % lc.every_n_turns == 0;
                cadence_hit || ctx.ctx_size_ratio > lc.at_ctx_ratio || ctx.verifier_flagged
            }
            Delta::D7SelfCheck => {
                ctx.output_contains_quoted_text
                    || ctx.output_contains_external_claim
                    || ctx.persona_refusal_active
            }
        }
    }

    /// Load the overlay markdown. Returns `None` when no path is configured
    /// or when the overlay is disabled. Returns the raw file contents
    /// otherwise — section parsing is a downstream concern.
    pub fn load_overlay_text(&self) -> Result<Option<String>, OverlayError> {
        if !self.config.enabled {
            return Ok(None);
        }
        let Some(path) = self.config.prompt_overlay_path.as_ref() else {
            return Ok(None);
        };
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Some(text)),
            Err(e) => Err(OverlayError::Io(format!("{}: {e}", path.display()))),
        }
    }
}
