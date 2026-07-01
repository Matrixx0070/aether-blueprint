//! MutationRunner: applies mutations to disk and runs cargo test.
//!
//! For each mutation:
//!   1. Write the mutated source to the target file.
//!   2. Run `cargo test -p <package>`.
//!   3. Restore the original source.
//!   4. Record the outcome.
//!
//! Designed to be called from `aether muttest` CLI command or programmatically.

use crate::mutation::{MutantOutcome, MutantResult, Mutation};
use std::path::Path;
use std::time::{Duration, Instant};

/// Configuration for the mutation runner.
#[derive(Debug, Clone)]
pub struct MuttestConfig {
    /// Cargo package to test (passed as -p argument).
    pub package: Option<String>,
    /// Test timeout per mutant.
    pub timeout: Duration,
    /// Maximum mutants to run (None = all).
    pub max_mutants: Option<usize>,
    /// If true, skip build-error mutants in reporting (they still count).
    pub skip_build_errors: bool,
    /// Additional cargo test arguments.
    pub extra_args: Vec<String>,
}

impl Default for MuttestConfig {
    fn default() -> Self {
        MuttestConfig {
            package: None,
            timeout: Duration::from_secs(30),
            max_mutants: None,
            skip_build_errors: true,
            extra_args: Vec::new(),
        }
    }
}

/// Run a set of mutations against the cargo test suite.
/// `workspace_root` must contain a Cargo.toml.
pub fn run_mutations(
    mutations: &[Mutation],
    workspace_root: &Path,
    config: &MuttestConfig,
) -> anyhow::Result<MuttestReport> {
    let mut results = Vec::new();
    let limit = config.max_mutants.unwrap_or(mutations.len());

    for mutation in mutations.iter().take(limit) {
        let file_path = workspace_root.join(&mutation.file);
        let original = std::fs::read_to_string(&file_path)?;

        if !mutation.is_applicable(&original) {
            continue;
        }

        let mutated = mutation.apply(&original);
        std::fs::write(&file_path, &mutated)?;

        let result = run_test(mutation, workspace_root, config);

        // Always restore
        std::fs::write(&file_path, &original)?;

        results.push(result);
    }

    Ok(MuttestReport::from_results(results))
}

fn run_test(
    mutation: &Mutation,
    workspace_root: &Path,
    config: &MuttestConfig,
) -> MutantResult {
    let start = Instant::now();

    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("test").current_dir(workspace_root);
    if let Some(pkg) = &config.package {
        cmd.args(["-p", pkg]);
    }
    for arg in &config.extra_args {
        cmd.arg(arg);
    }

    let output = match cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|child| child.wait_with_output())
    {
        Ok(o) => o,
        Err(e) => {
            return MutantResult {
                mutation: mutation.clone(),
                outcome: MutantOutcome::BuildError,
                duration_ms: start.elapsed().as_millis() as u64,
                output_snippet: e.to_string(),
            };
        }
    };

    let elapsed = start.elapsed();
    if elapsed >= config.timeout {
        return MutantResult {
            mutation: mutation.clone(),
            outcome: MutantOutcome::Timeout,
            duration_ms: elapsed.as_millis() as u64,
            output_snippet: String::new(),
        };
    }

    let snippet = {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let s: String = stderr.chars().take(1024).collect();
        s
    };

    let outcome = if !output.status.success() {
        // Non-zero exit: either build error or test failure (= killed)
        if snippet.contains("error[E") || snippet.contains("error: could not compile") {
            MutantOutcome::BuildError
        } else {
            MutantOutcome::Killed
        }
    } else {
        MutantOutcome::Survived
    };

    MutantResult {
        mutation: mutation.clone(),
        outcome,
        duration_ms: elapsed.as_millis() as u64,
        output_snippet: snippet,
    }
}

/// Aggregated report of a mutation testing run.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct MuttestReport {
    pub results: Vec<MutantResult>,
    pub killed: usize,
    pub survived: usize,
    pub build_errors: usize,
    pub timeouts: usize,
    /// Mutation score: killed / (killed + survived). Build errors excluded.
    pub score: f64,
}

impl MuttestReport {
    pub fn from_results(results: Vec<MutantResult>) -> Self {
        let killed = results.iter().filter(|r| r.outcome == MutantOutcome::Killed).count();
        let survived = results.iter().filter(|r| r.outcome == MutantOutcome::Survived).count();
        let build_errors = results.iter().filter(|r| r.outcome == MutantOutcome::BuildError).count();
        let timeouts = results.iter().filter(|r| r.outcome == MutantOutcome::Timeout).count();
        let score = if killed + survived == 0 {
            0.0
        } else {
            killed as f64 / (killed + survived) as f64
        };
        MuttestReport { results, killed, survived, build_errors, timeouts, score }
    }

    /// Survived mutations — actionable test gaps.
    pub fn survived_mutations(&self) -> Vec<&MutantResult> {
        self.results
            .iter()
            .filter(|r| r.outcome == MutantOutcome::Survived)
            .collect()
    }

    pub fn summary(&self) -> String {
        format!(
            "score={:.1}% killed={} survived={} errors={} timeouts={}",
            self.score * 100.0,
            self.killed,
            self.survived,
            self.build_errors,
            self.timeouts,
        )
    }
}
