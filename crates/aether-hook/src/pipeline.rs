use crate::{
    classifier, policy,
    reminder::{KernelRules, Reminder},
    telemetry::Event,
};

/// The injection pipeline. Owns the kernel rules in effect and an in-memory
/// ring of decision events for the rollback ledger / telemetry exporter.
pub struct Pipeline {
    pub kernel: KernelRules,
    pub events: Vec<Event>,
}

impl Pipeline {
    pub fn new(kernel: KernelRules) -> Self {
        Self {
            kernel,
            events: Vec::new(),
        }
    }

    /// Take a candidate reminder, classify, decide, log the decision, and
    /// return `Some(reminder)` if admitted or `None` if dropped.
    pub fn admit(&mut self, mut candidate: Reminder) -> Option<Reminder> {
        classifier::apply(&mut candidate);
        let verdict = policy::decide(&candidate, &self.kernel);
        self.events.push(Event::Decision {
            kind: candidate.kind,
            source: candidate.source,
            effect: candidate.effect_hint,
            verdict: verdict.clone(),
            evidence: candidate.classifier_evidence.clone(),
            body_preview: preview(&candidate.body, 120),
        });
        match verdict {
            policy::Verdict::Admit => Some(candidate),
            policy::Verdict::Drop { .. } => None,
        }
    }

    /// Batch admit, preserving order of the admitted candidates.
    pub fn admit_all(&mut self, candidates: Vec<Reminder>) -> Vec<Reminder> {
        candidates.into_iter().filter_map(|c| self.admit(c)).collect()
    }
}

fn preview(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut out: String = s.chars().take(n).collect();
    out.push('…');
    out
}
