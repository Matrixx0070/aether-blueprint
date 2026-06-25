//! Source × Effect policy decisions.
//!
//! The truth table. The classifier sets `effect_hint`; this module decides
//! whether the reminder is admitted into the prompt. It owns one rule above
//! everything else: **External×Loosens is always dropped**, regardless of
//! `KernelRules.allow_external_loosening`. That flag exists only to make
//! the layered defence explicit to a future reviewer.

use crate::reminder::{EffectHint, KernelRules, Reminder, Source};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Admit,
    Drop { reason: DropReason },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    EmptyBody,
    ExternalLoosening,
    ProjectLoosening,
    UserLoosening,
    AmbiguousExternal,
}

pub fn decide(rem: &Reminder, kernel: &KernelRules) -> Verdict {
    if rem.body.trim().is_empty() {
        return Verdict::Drop { reason: DropReason::EmptyBody };
    }

    use EffectHint::*;
    use Source::*;
    use Verdict::*;

    match (rem.source, rem.effect_hint) {
        // Kernel is the trust root. If we don't trust it, nothing works.
        (Kernel, _) => Admit,

        // Loosening — the dangerous quadrant.
        (External, Loosens) => Drop { reason: DropReason::ExternalLoosening },
        (ProjectHook, Loosens) if !kernel.allow_project_loosening => {
            Drop { reason: DropReason::ProjectLoosening }
        }
        (UserHook, Loosens) if !kernel.allow_user_loosening => {
            Drop { reason: DropReason::UserLoosening }
        }

        // Ambiguous from External fails closed.
        (External, Ambiguous) => Drop { reason: DropReason::AmbiguousExternal },

        // Everything else: Neutral, Tightens, and Loosens from a trusted
        // source with the kernel flag set, all admit.
        _ => Admit,
    }
}
