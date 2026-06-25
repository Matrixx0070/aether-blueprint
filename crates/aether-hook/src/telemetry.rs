use crate::{
    policy::Verdict,
    reminder::{EffectHint, ReminderKind, Source},
};

#[derive(Debug, Clone)]
pub enum Event {
    Decision {
        kind: ReminderKind,
        source: Source,
        effect: EffectHint,
        verdict: Verdict,
        evidence: Vec<String>,
        body_preview: String,
    },
}

impl Event {
    pub fn is_drop(&self) -> bool {
        matches!(self, Event::Decision { verdict: Verdict::Drop { .. }, .. })
    }
    pub fn is_admit(&self) -> bool {
        matches!(self, Event::Decision { verdict: Verdict::Admit, .. })
    }
}
