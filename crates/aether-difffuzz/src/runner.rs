//! DiffTarget trait and DiffRunner — the core diffential test harness.
//!
//! Implement DiffTarget for your two implementations, then run them through
//! DiffRunner. Any input where A and B produce different DiffOutputs is a
//! divergence and gets saved to the corpus.

use serde::{Deserialize, Serialize};

/// The result of running a target with a given input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffOutput {
    /// Normal completion with byte output.
    Ok(Vec<u8>),
    /// Error string (not a panic).
    Err(String),
    /// Implementation panicked (caught via catch_unwind).
    Panic(String),
    /// Implementation timed out or was otherwise unavailable.
    Timeout,
}

impl DiffOutput {
    /// Classify the output type without comparing data.
    pub fn variant_name(&self) -> &'static str {
        match self {
            DiffOutput::Ok(_) => "Ok",
            DiffOutput::Err(_) => "Err",
            DiffOutput::Panic(_) => "Panic",
            DiffOutput::Timeout => "Timeout",
        }
    }

    /// True if this is a successful completion (Ok or Err — both are defined behaviors).
    pub fn is_defined(&self) -> bool {
        matches!(self, DiffOutput::Ok(_) | DiffOutput::Err(_))
    }
}

/// A divergence: A and B produced different outputs for the same input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Divergence {
    pub input: Vec<u8>,
    /// Human-readable input (best-effort UTF-8).
    pub input_str: String,
    pub output_a: DiffOutput,
    pub output_b: DiffOutput,
    /// Short description of how they differ.
    pub kind: DivergenceKind,
    /// Which fuzzer iteration found this.
    pub iteration: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DivergenceKind {
    /// Both returned Ok but with different bytes.
    OutputMismatch,
    /// One returned Ok, the other Err.
    StatusMismatch,
    /// One panicked, the other didn't.
    PanicMismatch,
    /// Output byte lengths differ significantly (> length_tolerance).
    LengthMismatch,
    /// One timed out, the other didn't.
    TimeoutMismatch,
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[iter={}] {:?} | A={} B={}",
            self.iteration,
            self.kind,
            self.output_a.variant_name(),
            self.output_b.variant_name(),
        )
    }
}

/// Trait for a fuzz target. Implementors wrap one version of a function.
pub trait DiffTarget: Send + Sync {
    fn name(&self) -> &str;
    fn run(&self, input: &[u8]) -> DiffOutput;
}

/// Configuration for the DiffRunner.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Byte-level tolerance: outputs are "same" if they agree after normalization.
    pub exact_match: bool,
    /// If true, only flag divergences where one side panics.
    pub panic_only: bool,
    /// Max length difference ratio before flagging LengthMismatch.
    pub length_ratio_threshold: f64,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        RunnerConfig {
            exact_match: true,
            panic_only: false,
            length_ratio_threshold: 2.0,
        }
    }
}

/// Runs two DiffTargets with the same input and compares outputs.
pub struct DiffRunner<A: DiffTarget, B: DiffTarget> {
    pub target_a: A,
    pub target_b: B,
    pub config: RunnerConfig,
}

impl<A: DiffTarget, B: DiffTarget> DiffRunner<A, B> {
    pub fn new(target_a: A, target_b: B) -> Self {
        DiffRunner {
            target_a,
            target_b,
            config: RunnerConfig::default(),
        }
    }

    pub fn with_config(mut self, config: RunnerConfig) -> Self {
        self.config = config;
        self
    }

    /// Run both targets on `input`. Returns Some(Divergence) if they disagree.
    pub fn compare(&self, input: &[u8], iteration: u64) -> Option<Divergence> {
        let out_a = self.target_a.run(input);
        let out_b = self.target_b.run(input);
        self.detect_divergence(input, out_a, out_b, iteration)
    }

    pub(crate) fn detect_divergence(
        &self,
        input: &[u8],
        out_a: DiffOutput,
        out_b: DiffOutput,
        iteration: u64,
    ) -> Option<Divergence> {
        let kind = self.classify(&out_a, &out_b)?;
        let input_str = String::from_utf8_lossy(input).into_owned();
        Some(Divergence {
            input: input.to_vec(),
            input_str,
            output_a: out_a,
            output_b: out_b,
            kind,
            iteration,
        })
    }

    fn classify(&self, a: &DiffOutput, b: &DiffOutput) -> Option<DivergenceKind> {
        match (a, b) {
            // Both timed out — not a divergence
            (DiffOutput::Timeout, DiffOutput::Timeout) => None,
            // One timed out
            (DiffOutput::Timeout, _) | (_, DiffOutput::Timeout) => {
                Some(DivergenceKind::TimeoutMismatch)
            }
            // Panic mismatch
            (DiffOutput::Panic(_), x) | (x, DiffOutput::Panic(_))
                if !matches!(x, DiffOutput::Panic(_)) =>
            {
                Some(DivergenceKind::PanicMismatch)
            }
            // Both panicked with same message → ok; different → divergence
            (DiffOutput::Panic(pa), DiffOutput::Panic(pb)) => {
                if pa == pb {
                    None
                } else {
                    Some(DivergenceKind::PanicMismatch)
                }
            }
            // panic_only mode: skip non-panic divergences
            _ if self.config.panic_only => None,
            // Status mismatch: Ok vs Err
            (DiffOutput::Ok(_), DiffOutput::Err(_)) | (DiffOutput::Err(_), DiffOutput::Ok(_)) => {
                Some(DivergenceKind::StatusMismatch)
            }
            // Both Err — compare messages
            (DiffOutput::Err(ea), DiffOutput::Err(eb)) => {
                if ea != eb {
                    Some(DivergenceKind::OutputMismatch)
                } else {
                    None
                }
            }
            // Both Ok — compare bytes
            (DiffOutput::Ok(ba), DiffOutput::Ok(bb)) => {
                if ba == bb {
                    return None;
                }
                // Length ratio check
                let (la, lb) = (ba.len() as f64 + 1.0, bb.len() as f64 + 1.0);
                let ratio = (la / lb).max(lb / la);
                if ratio > self.config.length_ratio_threshold {
                    return Some(DivergenceKind::LengthMismatch);
                }
                if self.config.exact_match {
                    Some(DivergenceKind::OutputMismatch)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}
