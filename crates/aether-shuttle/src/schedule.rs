//! Schedule: a recorded sequence of thread-interleaving steps.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub type ThreadId = u32;
pub type LockId = u32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepKind {
    /// Thread computes (no synchronisation).
    Compute,
    /// Thread acquires a lock.
    Acquire { lock_id: LockId },
    /// Thread releases a lock.
    Release { lock_id: LockId },
    /// Thread waits on a condition variable.
    Wait { condvar_id: u32 },
    /// Thread sends on a channel.
    Send { channel_id: u32 },
    /// Thread receives from a channel.
    Recv { channel_id: u32 },
    /// Thread spawns a child thread.
    Spawn { child: ThreadId },
    /// Thread exits.
    Exit,
}

impl std::fmt::Display for ScheduleStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            StepKind::Compute => write!(f, "T{}: compute", self.thread),
            StepKind::Acquire { lock_id } => write!(f, "T{}: acquire(lock={})", self.thread, lock_id),
            StepKind::Release { lock_id } => write!(f, "T{}: release(lock={})", self.thread, lock_id),
            StepKind::Wait { condvar_id } => write!(f, "T{}: wait(cvar={})", self.thread, condvar_id),
            StepKind::Send { channel_id } => write!(f, "T{}: send(ch={})", self.thread, channel_id),
            StepKind::Recv { channel_id } => write!(f, "T{}: recv(ch={})", self.thread, channel_id),
            StepKind::Spawn { child } => write!(f, "T{}: spawn(T{})", self.thread, child),
            StepKind::Exit => write!(f, "T{}: exit", self.thread),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleStep {
    pub thread: ThreadId,
    pub kind: StepKind,
}

/// A complete interleaving schedule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Schedule {
    pub steps: Vec<ScheduleStep>,
}

impl Schedule {
    pub fn from_steps(steps: Vec<ScheduleStep>) -> Self {
        Schedule { steps }
    }

    /// Number of distinct threads in this schedule.
    pub fn thread_count(&self) -> usize {
        self.steps
            .iter()
            .map(|s| s.thread)
            .collect::<HashSet<_>>()
            .len()
    }

    /// A stable string identifier for this schedule (first 8 chars of hex digest).
    pub fn schedule_id(&self) -> String {
        let repr: Vec<String> = self
            .steps
            .iter()
            .map(|s| format!("{}:{:?}", s.thread, s.kind))
            .collect();
        let joined = repr.join("|");
        // Simple djb2-style hash
        let mut h: u64 = 5381;
        for b in joined.bytes() {
            h = h.wrapping_mul(33).wrapping_add(b as u64);
        }
        format!("{h:016x}")
    }

    /// Generate all schedules produced by swapping each pair of adjacent steps
    /// (explores one level of the Mazurkiewicz trace equivalence classes).
    pub fn swap_adjacent_pairs(&self) -> Vec<Schedule> {
        let mut variants = Vec::new();
        for i in 0..self.steps.len().saturating_sub(1) {
            if self.steps[i].thread != self.steps[i + 1].thread {
                let mut new_steps = self.steps.clone();
                new_steps.swap(i, i + 1);
                variants.push(Schedule::from_steps(new_steps));
            }
        }
        variants
    }
}
