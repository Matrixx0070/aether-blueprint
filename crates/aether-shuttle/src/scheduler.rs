//! Scheduler: replays a recorded Schedule step by step.

use crate::schedule::{Schedule, ScheduleStep, StepKind, ThreadId};
use serde::{Deserialize, Serialize};

/// The outcome of running a test under a given schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RunOutcome {
    /// All threads completed without detected issues.
    Clean,
    /// All runnable threads are waiting — deadlock detected.
    Deadlock { threads: Vec<ThreadId> },
    /// A thread panicked.
    Panic { thread: ThreadId, message: String },
    /// An assertion failed.
    AssertionFailure { message: String },
    /// Schedule was exhausted before all threads completed.
    Incomplete { remaining_threads: Vec<ThreadId> },
}

/// A scheduler that replays a pre-recorded Schedule.
pub struct Scheduler {
    schedule: Schedule,
    cursor: usize,
}

impl Scheduler {
    pub fn new(schedule: Schedule) -> Self {
        Scheduler { schedule, cursor: 0 }
    }

    /// Return the next thread to run, or None if the schedule is exhausted.
    pub fn next_thread(&mut self) -> Option<ThreadId> {
        if self.cursor >= self.schedule.steps.len() {
            return None;
        }
        let tid = self.schedule.steps[self.cursor].thread;
        self.cursor += 1;
        Some(tid)
    }

    /// Return the current step (without advancing the cursor).
    pub fn peek_step(&self) -> Option<&ScheduleStep> {
        self.schedule.steps.get(self.cursor)
    }

    /// Check whether the schedule has been fully consumed.
    pub fn is_done(&self) -> bool {
        self.cursor >= self.schedule.steps.len()
    }

    /// Current position in the schedule.
    pub fn position(&self) -> usize {
        self.cursor
    }

    /// Total steps in the schedule.
    pub fn len(&self) -> usize {
        self.schedule.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.schedule.steps.is_empty()
    }

    /// Record a new step during live execution (for recording mode).
    pub fn record_step(&mut self, step: ScheduleStep) {
        // In recording mode, schedule is built as we go
        if self.cursor == self.schedule.steps.len() {
            self.schedule.steps.push(step);
            self.cursor += 1;
        }
    }

    /// Return the underlying schedule (useful after recording).
    pub fn into_schedule(self) -> Schedule {
        self.schedule
    }
}

/// A simple lock-state tracker used during schedule replay to detect deadlocks.
#[derive(Debug, Default)]
pub struct LockState {
    /// lock_id → thread holding it (None if free)
    held_by: std::collections::HashMap<u32, ThreadId>,
    /// thread → set of locks it wants
    waiting_for: std::collections::HashMap<ThreadId, u32>,
}

impl LockState {
    pub fn try_acquire(&mut self, thread: ThreadId, lock_id: u32) -> bool {
        if let Some(&holder) = self.held_by.get(&lock_id) {
            if holder != thread {
                self.waiting_for.insert(thread, lock_id);
                return false;
            }
        }
        self.held_by.insert(lock_id, thread);
        self.waiting_for.remove(&thread);
        true
    }

    pub fn release(&mut self, thread: ThreadId, lock_id: u32) {
        if self.held_by.get(&lock_id) == Some(&thread) {
            self.held_by.remove(&lock_id);
        }
    }

    /// True if all listed threads are stuck waiting on locks they cannot acquire.
    pub fn is_deadlocked(&self, threads: &[ThreadId]) -> bool {
        !threads.is_empty()
            && threads
                .iter()
                .all(|t| self.waiting_for.contains_key(t))
    }

    pub fn waiting_threads(&self) -> Vec<ThreadId> {
        self.waiting_for.keys().copied().collect()
    }
}

/// Simulate running a schedule, detecting deadlocks via lock state.
/// Returns the RunOutcome after processing all steps.
pub fn simulate(schedule: &Schedule) -> RunOutcome {
    let mut lock_state = LockState::default();
    let mut exited: std::collections::HashSet<ThreadId> = std::collections::HashSet::new();

    for step in &schedule.steps {
        match &step.kind {
            StepKind::Acquire { lock_id } => {
                if !lock_state.try_acquire(step.thread, *lock_id) {
                    let waiting = lock_state.waiting_threads();
                    if lock_state.is_deadlocked(&waiting) {
                        return RunOutcome::Deadlock { threads: waiting };
                    }
                }
            }
            StepKind::Release { lock_id } => {
                lock_state.release(step.thread, *lock_id);
            }
            StepKind::Exit => {
                exited.insert(step.thread);
            }
            _ => {}
        }
    }

    let waiting = lock_state.waiting_threads();
    if !waiting.is_empty() {
        return RunOutcome::Deadlock { threads: waiting };
    }

    RunOutcome::Clean
}
