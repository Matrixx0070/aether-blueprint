//! Permission engine + sandbox dispatch.
//!
//! Skeleton: `PermissionMode`, glob-rule `Decision` table, and the D4
//! three-stage gate stub (search → suggest → call) for third-party tools.
//! Sandbox spawn (bwrap / sandbox-exec / Job Object) lives in feature-gated
//! modules to keep this crate buildable on every host.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PermissionMode {
    Default,
    AcceptEdits,
    Plan,
    BypassPermissions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { reason: String },
    Ask,
    RefuseMutate,
}

/// D4 — three-stage gate for third-party tools.
///
/// Stage 1 happens in `aether-mcp` (registry search). Stage 2 is the
/// suggest_connectors round-trip. Stage 3 is the actual invocation. This
/// type tracks which stage the current call is in and refuses any direct
/// invocation that hasn't been opted-in by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThirdPartyStage {
    Searched,
    Suggested,
    UserOptedIn,
}

pub fn allow_third_party(stage: ThirdPartyStage, user_named_tool: bool) -> bool {
    matches!(stage, ThirdPartyStage::UserOptedIn) || user_named_tool
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn third_party_blocked_until_opt_in() {
        assert!(!allow_third_party(ThirdPartyStage::Searched, false));
        assert!(!allow_third_party(ThirdPartyStage::Suggested, false));
        assert!(allow_third_party(ThirdPartyStage::UserOptedIn, false));
    }

    #[test]
    fn user_naming_the_tool_short_circuits() {
        assert!(allow_third_party(ThirdPartyStage::Searched, true));
    }
}
