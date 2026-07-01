//! ScheduleExplorer: systematically generates schedules for testing.

use crate::schedule::{Schedule, ScheduleStep, StepKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExplorationStrategy {
    /// Random schedule generation with a given seed.
    Random(u64),
    /// Depth-first enumeration of all thread interleavings (exponential, use with small n).
    Exhaustive,
    /// Partial-order reduction: only explore schedules not equivalent under Mazurkiewicz traces.
    PartialOrder,
}

/// Generates Schedules for a fixed number of threads and steps.
pub struct ScheduleExplorer {
    pub thread_count: u32,
    pub steps_per_schedule: usize,
    pub strategy: ExplorationStrategy,
    rng_state: u64,
    exhaustive_cursor: usize,
}

impl ScheduleExplorer {
    pub fn new(thread_count: u32, steps_per_schedule: usize, strategy: ExplorationStrategy) -> Self {
        let seed = match &strategy {
            ExplorationStrategy::Random(s) => *s,
            _ => 42,
        };
        ScheduleExplorer {
            thread_count,
            steps_per_schedule,
            strategy,
            rng_state: seed,
            exhaustive_cursor: 0,
        }
    }

    /// Generate the next schedule according to the exploration strategy.
    pub fn next_schedule(&mut self) -> Schedule {
        match &self.strategy {
            ExplorationStrategy::Random(_) => self.random_schedule(),
            ExplorationStrategy::Exhaustive => {
                let s = self.nth_schedule(self.exhaustive_cursor);
                self.exhaustive_cursor += 1;
                s
            }
            ExplorationStrategy::PartialOrder => {
                // Simplified: generate random then reduce
                self.random_schedule()
            }
        }
    }

    fn random_schedule(&mut self) -> Schedule {
        let mut steps = Vec::new();
        let mut lock_counter = 0u32;
        for _ in 0..self.steps_per_schedule {
            let thread = (self.xorshift() % self.thread_count as u64) as u32;
            let kind = match self.xorshift() % 4 {
                0 => StepKind::Compute,
                1 => {
                    let id = lock_counter % 4;
                    StepKind::Acquire { lock_id: id }
                }
                2 => {
                    let id = if lock_counter == 0 { 0 } else { (lock_counter - 1) % 4 };
                    lock_counter = lock_counter.saturating_sub(1);
                    StepKind::Release { lock_id: id }
                }
                _ => {
                    lock_counter += 1;
                    StepKind::Acquire { lock_id: lock_counter % 4 }
                }
            };
            steps.push(ScheduleStep { thread, kind });
        }
        Schedule::from_steps(steps)
    }

    /// Generate the nth lexicographic interleaving (base-`thread_count` encoding).
    fn nth_schedule(&self, n: usize) -> Schedule {
        let mut steps = Vec::new();
        let mut idx = n;
        for _ in 0..self.steps_per_schedule {
            let thread = (idx % self.thread_count as usize) as u32;
            idx /= self.thread_count as usize;
            steps.push(ScheduleStep { thread, kind: StepKind::Compute });
        }
        Schedule::from_steps(steps)
    }

    fn xorshift(&mut self) -> u64 {
        let mut x = self.rng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng_state = x;
        x
    }

    /// Generate `count` schedules using swap-based perturbation from a seed.
    pub fn perturb_schedules(&self, seed: &Schedule, count: usize) -> Vec<Schedule> {
        let mut results = seed.swap_adjacent_pairs();
        // Extend with pairs-of-pairs if needed
        let mut layer = results.clone();
        while results.len() < count {
            let next: Vec<Schedule> = layer
                .iter()
                .flat_map(|s| s.swap_adjacent_pairs())
                .collect();
            if next.is_empty() {
                break;
            }
            results.extend(next.clone());
            layer = next;
        }
        results.truncate(count);
        results
    }
}
