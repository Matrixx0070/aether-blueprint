//! Source-level mutation operators for Rust source files.
//!
//! Each operator targets a specific syntactic pattern and produces one
//! mutated version. The mutation records the original span so it can be
//! reversed after the test run.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MutationKind {
    /// Replace `==` with `!=` and vice-versa.
    EqToNe,
    /// Replace `<` with `>=`, `>` with `<=`, etc.
    RelationalInvert,
    /// Replace `+` with `-` and vice-versa.
    ArithAddSub,
    /// Replace `*` with `/` (when not dividing by zero-literal).
    ArithMulDiv,
    /// Replace `&&` with `||` and vice-versa.
    LogicalAndOr,
    /// Replace `true` literal with `false` and vice-versa.
    BoolLiteralFlip,
    /// Replace integer literal `n` with `0`, `1`, `-1`, `n+1`, `n-1`.
    IntLiteralPerturb { original: i64, replacement: i64 },
    /// Replace `return expr` with `return Default::default()`.
    ReturnDefault,
    /// Delete a statement line (replaces it with a blank).
    DeleteStatement,
    /// Replace `unwrap()` with `expect("muttest")` — weaker, lets panics surface.
    UnwrapToExpect,
    /// Negate the condition in `if cond {` → `if !cond {`.
    NegateIfCondition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mutation {
    pub id: usize,
    pub kind: MutationKind,
    pub file: String,
    /// 1-based line number where the mutation applies.
    pub line: usize,
    /// Column byte offset in that line.
    pub col: usize,
    /// The original text that will be replaced.
    pub original: String,
    /// The replacement text.
    pub replacement: String,
}

impl Mutation {
    /// Apply this mutation to `source` and return the mutated string.
    pub fn apply(&self, source: &str) -> String {
        source.replacen(&self.original, &self.replacement, 1)
    }

    /// Check this mutation against `source` to confirm the original is present.
    pub fn is_applicable(&self, source: &str) -> bool {
        source.contains(&self.original)
    }
}

/// The result of running the test suite against a mutant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MutantOutcome {
    /// Tests caught the mutation (good — mutation was killed).
    Killed,
    /// Tests passed with the mutation — the mutation survived (test gap).
    Survived,
    /// Compilation failed with the mutated source (doesn't count as killed).
    BuildError,
    /// Tests timed out.
    Timeout,
}

impl std::fmt::Display for MutantOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MutantOutcome::Killed => write!(f, "KILLED"),
            MutantOutcome::Survived => write!(f, "SURVIVED"),
            MutantOutcome::BuildError => write!(f, "BUILD_ERROR"),
            MutantOutcome::Timeout => write!(f, "TIMEOUT"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutantResult {
    pub mutation: Mutation,
    pub outcome: MutantOutcome,
    /// Time taken for the test run in milliseconds.
    pub duration_ms: u64,
    /// Stderr / failure output snippet (truncated to 1 KB).
    pub output_snippet: String,
}
