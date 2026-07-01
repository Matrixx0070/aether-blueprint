//! Test input extractor — scans Rust test source for concrete literal values.
//!
//! Finds `assert_eq!(fn_call(arg1, arg2, ...), expected)` patterns and
//! extracts the argument literals as seed inputs for concolic replay.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

static RE_ASSERT_EQ: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"assert_eq!\s*\(\s*\w+\s*\(([^)]*)\)").unwrap()
});
static RE_INT_LIT: Lazy<Regex> = Lazy::new(|| Regex::new(r"-?\d+").unwrap());

/// A concrete test input extracted from a test function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestInput {
    /// The raw source line where the input was found.
    pub source_line: String,
    /// Integer literal values extracted from the call arguments.
    pub int_values: Vec<i64>,
}

/// Scan `source` and return all concrete inputs found in `assert_eq!` calls.
pub fn extract_test_inputs(source: &str) -> Vec<TestInput> {
    let mut inputs = Vec::new();
    for (line_idx, line) in source.lines().enumerate() {
        if let Some(cap) = RE_ASSERT_EQ.captures(line) {
            let args_str = &cap[1];
            let int_values: Vec<i64> = RE_INT_LIT
                .find_iter(args_str)
                .filter_map(|m| m.as_str().parse().ok())
                .collect();
            if !int_values.is_empty() {
                inputs.push(TestInput {
                    source_line: format!("{}:{}", line_idx + 1, line.trim()),
                    int_values,
                });
            }
        }
    }
    inputs
}
