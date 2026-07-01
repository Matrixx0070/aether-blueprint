//! Historical regression anti-pattern database.
//!
//! Mines git history for fix/bug/CVE commits, extracts removed lines as
//! "before snippets", and stores them at ~/.aether/antipatterns.jsonl.
//! At analysis time, match_antipatterns scores candidate code against the
//! database and returns hits with score >= 0.5.
//!
//! Scoring is token-overlap Jaccard (words). A future iteration can swap
//! in embedding similarity without changing the public API.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

const ANTIPATTERN_FILE: &str = ".aether/antipatterns.jsonl";

fn antipattern_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(ANTIPATTERN_FILE)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiPattern {
    /// SHA-256[:8] of commit_hash + file_path + before_snippet.
    pub id: String,
    pub commit_hash: String,
    pub commit_msg: String,
    pub file_path: String,
    /// Removed lines from the fix commit (the "bad" code).
    pub before_snippet: String,
    /// ISO-8601 timestamp when this entry was extracted.
    pub created_at: String,
}

impl AntiPattern {
    fn new(
        commit_hash: impl Into<String>,
        commit_msg: impl Into<String>,
        file_path: impl Into<String>,
        before_snippet: impl Into<String>,
    ) -> Self {
        let commit_hash = commit_hash.into();
        let file_path = file_path.into();
        let before_snippet = before_snippet.into();
        let id = fingerprint(&commit_hash, &file_path, &before_snippet);
        AntiPattern {
            id,
            commit_hash,
            commit_msg: commit_msg.into(),
            file_path,
            before_snippet,
            created_at: Utc::now().to_rfc3339(),
        }
    }
}

fn fingerprint(commit: &str, file: &str, snippet: &str) -> String {
    let mut h = Sha256::new();
    h.update(commit.as_bytes());
    h.update(b"|");
    h.update(file.as_bytes());
    h.update(b"|");
    h.update(snippet.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..4]) // 8 hex chars
}

/// Extract anti-patterns from a git repository.
/// Searches commits whose message contains "fix:", "bug:", or "CVE" (case-insensitive).
/// For each such commit, collects removed lines (lines starting with "-") per file
/// and creates one AntiPattern per (commit, file) pair.
pub fn extract_from_git(repo: &Path) -> Vec<AntiPattern> {
    let mut out = Vec::new();

    // git log --grep='fix:' --grep='bug:' --grep='CVE' -i --all-match=false
    // Actually use multiple separate greps combined via OR logic: run one query
    let log_output = Command::new("git")
        .args([
            "-C",
            repo.to_str().unwrap_or("."),
            "log",
            "--oneline",
            "--grep=fix:",
            "--grep=bug:",
            "--grep=CVE",
            "--regexp-ignore-case",
            "--max-count=200",
        ])
        .output();

    let log_output = match log_output {
        Ok(o) if o.status.success() => o,
        _ => return out,
    };

    for line in log_output.stdout.lines().flatten() {
        // "abc1234 fix: null deref in parser"
        let mut parts = line.splitn(2, ' ');
        let hash = match parts.next() {
            Some(h) => h.to_string(),
            None => continue,
        };
        let msg = parts.next().unwrap_or("").to_string();

        // git show --stat --unified=0 <hash>
        let show = Command::new("git")
            .args([
                "-C",
                repo.to_str().unwrap_or("."),
                "show",
                "--unified=0",
                "--diff-filter=M",
                &hash,
            ])
            .output();

        let show = match show {
            Ok(o) if o.status.success() => o,
            _ => continue,
        };

        let diff_text = String::from_utf8_lossy(&show.stdout);
        let patterns = parse_diff_removed(&diff_text);
        for (file, removed) in patterns {
            if removed.trim().is_empty() {
                continue;
            }
            out.push(AntiPattern::new(&hash, &msg, file, removed));
        }
    }
    out
}

/// Parse a unified diff and return (file_path, removed_lines) for each modified file.
fn parse_diff_removed(diff: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut current_file: Option<String> = None;
    let mut removed_lines: Vec<String> = Vec::new();

    for line in diff.lines() {
        if line.starts_with("--- a/") {
            // flush previous
            if let Some(f) = current_file.take() {
                let snippet = removed_lines.join("\n");
                if !snippet.is_empty() {
                    result.push((f, snippet));
                }
                removed_lines.clear();
            }
            current_file = Some(line["--- a/".len()..].to_string());
        } else if line.starts_with('-') && !line.starts_with("---") {
            removed_lines.push(line[1..].to_string());
        }
    }
    // flush last
    if let Some(f) = current_file {
        let snippet = removed_lines.join("\n");
        if !snippet.is_empty() {
            result.push((f, snippet));
        }
    }
    result
}

/// Append new anti-patterns to ~/.aether/antipatterns.jsonl.
/// Skips entries whose id already exists in the file to avoid duplicates.
/// Returns the count of newly written entries.
pub fn store_antipatterns(patterns: &[AntiPattern]) -> std::io::Result<usize> {
    let path = antipattern_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let existing_ids: HashSet<String> = load_antipatterns()
        .into_iter()
        .map(|a| a.id)
        .collect();

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    let mut written = 0;
    for p in patterns {
        if existing_ids.contains(&p.id) {
            continue;
        }
        let line = serde_json::to_string(p).unwrap_or_default();
        writeln!(file, "{line}")?;
        written += 1;
    }
    Ok(written)
}

/// Load all anti-patterns from ~/.aether/antipatterns.jsonl.
/// Silently skips malformed lines.
pub fn load_antipatterns() -> Vec<AntiPattern> {
    let path = antipattern_path();
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    BufReader::new(file)
        .lines()
        .flatten()
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect()
}

/// Score `code` against every entry in `db`.
/// Returns entries with Jaccard token-overlap score >= 0.5, sorted descending.
pub fn match_antipatterns<'a>(code: &str, db: &'a [AntiPattern]) -> Vec<(&'a AntiPattern, f32)> {
    let code_tokens = tokenize(code);
    let mut hits: Vec<(&AntiPattern, f32)> = db
        .iter()
        .filter_map(|ap| {
            let ap_tokens = tokenize(&ap.before_snippet);
            let score = jaccard(&code_tokens, &ap_tokens);
            if score >= 0.5 {
                Some((ap, score))
            } else {
                None
            }
        })
        .collect();
    hits.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    hits
}

fn tokenize(s: &str) -> HashSet<String> {
    s.split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|t| t.len() >= 2)
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(b).count() as f32;
    let union = (a.len() + b.len()) as f32 - intersection;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jaccard_identical() {
        let a = tokenize("let x = foo(bar)");
        let b = tokenize("let x = foo(bar)");
        assert!((jaccard(&a, &b) - 1.0).abs() < 0.001);
    }

    #[test]
    fn jaccard_disjoint() {
        let a = tokenize("alpha beta gamma");
        let b = tokenize("delta epsilon zeta");
        assert_eq!(jaccard(&a, &b), 0.0);
    }

    #[test]
    fn jaccard_half_overlap() {
        let a = tokenize("aaa bbb");
        let b = tokenize("aaa ccc");
        // intersection = {aaa}, union = {aaa,bbb,ccc} = 3 → 1/3 ≈ 0.333
        let s = jaccard(&a, &b);
        assert!(s > 0.0 && s < 0.5);
    }

    #[test]
    fn match_returns_hit_above_threshold() {
        let ap = AntiPattern::new("abc1234", "fix: null deref", "src/foo.rs", "let x = ptr.unwrap()");
        let db = [ap];
        // Identical snippet → score 1.0 → hit
        let hits = match_antipatterns("let x = ptr.unwrap()", &db);
        assert!(!hits.is_empty());
        assert!(hits[0].1 >= 0.5);
    }

    #[test]
    fn match_returns_no_hit_below_threshold() {
        let ap = AntiPattern::new("abc1234", "fix: null deref", "src/foo.rs", "alpha bravo charlie delta echo");
        let db = [ap];
        let hits = match_antipatterns("totally unrelated code", &db);
        assert!(hits.is_empty());
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let a = fingerprint("hash", "file.rs", "code");
        let b = fingerprint("hash", "file.rs", "code");
        assert_eq!(a, b);
    }

    #[test]
    fn parse_diff_removed_extracts_lines() {
        let diff = "--- a/src/lib.rs\n+++ b/src/lib.rs\n-let x = unsafe { *ptr };\n-panic!(\"bad\");\n+let x = 0;\n";
        let result = parse_diff_removed(diff);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "src/lib.rs");
        assert!(result[0].1.contains("unsafe"));
    }
}
