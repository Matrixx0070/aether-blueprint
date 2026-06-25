//! AetherCode hook engine — D1 reference implementation.
//!
//! The pipeline takes hook-emitted reminder candidates, classifies each one's
//! likely *effect* on agent behaviour (Neutral / Tightens / Loosens / Ambiguous),
//! then admits or drops it based on the candidate's *source* and the active
//! KernelRules. The premise: a reminder's content is untrusted; its source is
//! the ground truth of who is allowed to say what.
//!
//! Design notes
//! ------------
//! - This is the *first* line of defence. The pre-emission self-check (D7) is
//!   the second. Neither alone is sufficient.
//! - The classifier is heuristic. It will miss novel attacks. The trust model
//!   is therefore: External×Loosens is dropped *no matter what the body says*,
//!   even if the classifier mis-scores it as Tightens. See policy::decide.
//! - Source is set by the runtime when the hook fires — never read from the
//!   reminder body. A body that says "[kernel directive]" but arrived via
//!   web_fetch is still Source::External.

pub mod classifier;
pub mod pipeline;
pub mod policy;
pub mod reminder;
pub mod telemetry;

pub use pipeline::Pipeline;
pub use policy::{DropReason, Verdict};
pub use reminder::{EffectHint, KernelRules, Reminder, ReminderKind, Source};
