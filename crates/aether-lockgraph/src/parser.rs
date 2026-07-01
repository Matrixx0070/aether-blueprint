//! Static parser: extract mutex lock acquisition sequences from Rust source.

use once_cell::sync::Lazy;
use regex::Regex;

static RE_LOCK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(\w+)\.lock\(\)").unwrap());

/// A static lock acquisition sequence found in source.
#[derive(Debug, Clone)]
pub struct LockSeq {
    pub locks: Vec<String>,
    pub line_start: usize,
}

/// Scan a Rust source string and return sequences of consecutive `.lock()` calls
/// within the same scope (approximated as within a contiguous block of lines).
pub fn parse_lock_order(source: &str) -> Vec<LockSeq> {
    let mut sequences: Vec<LockSeq> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut start_line = 0;

    for (line_idx, line) in source.lines().enumerate() {
        if let Some(cap) = RE_LOCK.captures(line) {
            if current.is_empty() {
                start_line = line_idx + 1;
            }
            current.push(cap[1].to_string());
        } else if !current.is_empty() {
            // Break in lock sequence — save if it has 2+ locks
            if current.len() >= 2 {
                sequences.push(LockSeq { locks: current.clone(), line_start: start_line });
            }
            current.clear();
        }
    }
    if current.len() >= 2 {
        sequences.push(LockSeq { locks: current, line_start: start_line });
    }
    sequences
}
