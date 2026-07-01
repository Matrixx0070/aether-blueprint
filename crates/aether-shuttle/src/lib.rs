//! AetherCode deterministic concurrency scheduler.
//!
//! Records thread interleaving decisions during a test run and replays
//! them deterministically to reproduce concurrency bugs.
//!
//! ## Design
//!
//! A `Schedule` is a sequence of `Step`s: each step says which thread
//! should run next. The `Scheduler` wraps this schedule and dispatches
//! the next runnable thread according to the recorded or randomly-chosen
//! ordering.
//!
//! The `ScheduleExplorer` systematically varies schedules to find ones
//! that trigger bugs (races, deadlocks, assertion failures).
//!
//! This is intentionally a pure-Rust data-model crate — it does not
//! hook into OS thread scheduling (that requires compiler instrumentation
//! or OS-specific APIs). It provides the recording + replay primitives
//! that a higher-level harness can integrate with.

pub mod explorer;
pub mod schedule;
pub mod scheduler;

pub use explorer::{ExplorationStrategy, ScheduleExplorer};
pub use schedule::{Schedule, ScheduleStep, StepKind};
pub use schedule::ThreadId;
pub use scheduler::{RunOutcome, Scheduler};

#[cfg(test)]
mod tests {
    use super::*;
    use schedule::{Schedule, ScheduleStep, StepKind};

    fn two_thread_schedule() -> Schedule {
        Schedule::from_steps(vec![
            ScheduleStep { thread: 0, kind: StepKind::Acquire { lock_id: 0 } },
            ScheduleStep { thread: 1, kind: StepKind::Acquire { lock_id: 1 } },
            ScheduleStep { thread: 0, kind: StepKind::Release { lock_id: 0 } },
            ScheduleStep { thread: 1, kind: StepKind::Release { lock_id: 1 } },
        ])
    }

    #[test]
    fn schedule_stores_steps() {
        let s = two_thread_schedule();
        assert_eq!(s.steps.len(), 4);
        assert_eq!(s.thread_count(), 2);
    }

    #[test]
    fn schedule_serializes_round_trip() {
        let s = two_thread_schedule();
        let json = serde_json::to_string(&s).unwrap();
        let back: Schedule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.steps.len(), 4);
    }

    #[test]
    fn scheduler_replays_deterministically() {
        let s = two_thread_schedule();
        let mut sched = Scheduler::new(s.clone());
        let mut replay = Vec::new();
        while let Some(tid) = sched.next_thread() {
            replay.push(tid);
        }
        assert_eq!(replay, vec![0, 1, 0, 1]);
    }

    #[test]
    fn schedule_permutations_generated() {
        let base = Schedule::from_steps(vec![
            ScheduleStep { thread: 0, kind: StepKind::Compute },
            ScheduleStep { thread: 1, kind: StepKind::Compute },
        ]);
        let variants = base.swap_adjacent_pairs();
        // One variant swapping steps 0 and 1
        assert!(!variants.is_empty());
    }

    #[test]
    fn explorer_generates_schedules() {
        let mut exp = ScheduleExplorer::new(2, 4, ExplorationStrategy::Random(42));
        let schedules: Vec<_> = (0..5).map(|_| exp.next_schedule()).collect();
        assert_eq!(schedules.len(), 5);
    }

    #[test]
    fn schedule_step_kind_display() {
        let step = ScheduleStep { thread: 0, kind: StepKind::Acquire { lock_id: 7 } };
        let s = format!("{step}");
        assert!(s.contains("acquire") || s.contains("Acquire") || s.contains("lock"));
    }

    #[test]
    fn run_outcome_debug() {
        let o = RunOutcome::Deadlock { threads: vec![0, 1] };
        let s = format!("{o:?}");
        assert!(s.contains("Deadlock"));
    }

    #[test]
    fn schedule_id_stable() {
        let s = two_thread_schedule();
        let id1 = s.schedule_id();
        let id2 = s.schedule_id();
        assert_eq!(id1, id2, "schedule_id must be deterministic");
    }
}
