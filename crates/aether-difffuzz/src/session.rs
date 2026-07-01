//! FuzzSession: orchestrates the mutation loop and corpus management.

use crate::mutator::Mutator;
use crate::runner::{DiffOutput, DiffTarget, DiffRunner, Divergence, RunnerConfig};
use serde::{Deserialize, Serialize};

/// Statistics collected during a fuzz session.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FuzzStats {
    pub iterations: u64,
    pub divergences: u64,
    pub panics_a: u64,
    pub panics_b: u64,
    pub corpus_size: usize,
}

/// A complete fuzz session: owns the runner, mutator, and accumulated divergences.
pub struct FuzzSession<A: DiffTarget, B: DiffTarget> {
    runner: DiffRunner<A, B>,
    mutator: Mutator,
    pub divergences: Vec<Divergence>,
    pub stats: FuzzStats,
}

impl<A: DiffTarget, B: DiffTarget> FuzzSession<A, B> {
    pub fn new(target_a: A, target_b: B, rng_seed: u64) -> Self {
        FuzzSession {
            runner: DiffRunner::new(target_a, target_b),
            mutator: Mutator::new(rng_seed),
            divergences: Vec::new(),
            stats: FuzzStats::default(),
        }
    }

    pub fn with_config(mut self, config: RunnerConfig) -> Self {
        self.runner.config = config;
        self
    }

    pub fn add_seed(&mut self, seed: Vec<u8>) {
        self.mutator.add_seed(seed);
    }

    /// Run for `iterations` steps. Returns divergences found in this run.
    pub fn run(&mut self, iterations: u64) -> Vec<Divergence> {
        let mut found = Vec::new();
        let start = self.stats.iterations;

        for i in 0..iterations {
            let iteration = start + i;
            let (input, _ops) = self.mutator.next_input();

            // Track panics
            let out_a = self.runner.target_a.run(&input);
            let out_b = self.runner.target_b.run(&input);

            if matches!(out_a, DiffOutput::Panic(_)) {
                self.stats.panics_a += 1;
            }
            if matches!(out_b, DiffOutput::Panic(_)) {
                self.stats.panics_b += 1;
            }

            if let Some(div) = self
                .runner
                .detect_divergence_pub(&input, out_a, out_b, iteration)
            {
                // Add diverging input to corpus for further mutation
                self.mutator.add_to_corpus(div.input.clone());
                self.stats.divergences += 1;
                found.push(div.clone());
                self.divergences.push(div);
            }

            self.stats.iterations += 1;
        }
        self.stats.corpus_size = self.mutator.corpus.len();
        found
    }

    pub fn name_a(&self) -> &str {
        self.runner.target_a.name()
    }

    pub fn name_b(&self) -> &str {
        self.runner.target_b.name()
    }

    /// Replay a specific input against both targets.
    pub fn replay(&self, input: &[u8]) -> Option<Divergence> {
        self.runner.compare(input, u64::MAX)
    }

    /// Summarise the session to JSON.
    pub fn summary_json(&self) -> String {
        serde_json::json!({
            "target_a": self.name_a(),
            "target_b": self.name_b(),
            "stats": self.stats,
            "divergences": self.divergences.len(),
            "top_divergences": self.divergences.iter().take(10).map(|d| d.to_string()).collect::<Vec<_>>(),
        })
        .to_string()
    }
}

// We need a public shim so FuzzSession can call detect_divergence.
// Add a pub method on DiffRunner:
use crate::runner::DiffRunner as DR;
impl<A: DiffTarget, B: DiffTarget> DR<A, B> {
    pub fn detect_divergence_pub(
        &self,
        input: &[u8],
        out_a: DiffOutput,
        out_b: DiffOutput,
        iteration: u64,
    ) -> Option<Divergence> {
        self.detect_divergence(input, out_a, out_b, iteration)
    }
}
