//! Git worktree auto-fix engine.
//!
//! For each finding, generates a patch candidate via an Ollama LLM,
//! applies it in an isolated git worktree, runs `cargo test` to validate,
//! and reports pass/fail. On success the patch is emitted as a unified diff.

pub use aether_deps_reach::{Finding, Severity};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchConfig {
    pub model: String,
    pub ollama_url: String,
    pub timeout_secs: u64,
    pub max_attempts: usize,
    pub run_tests: bool,
}

impl Default for PatchConfig {
    fn default() -> Self {
        PatchConfig {
            model: "kimi-k2.7-code:cloud".to_string(),
            ollama_url: "http://localhost:11434".to_string(),
            timeout_secs: 60,
            max_attempts: 3,
            run_tests: true,
        }
    }
}

// ── Patch result ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatchStatus {
    Applied { tests_passed: bool },
    GenerationFailed(String),
    ApplyFailed(String),
    WorktreeFailed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchResult {
    pub finding: Finding,
    pub attempt: usize,
    pub unified_diff: Option<String>,
    pub status: PatchStatus,
    pub llm_reasoning: String,
}

// ── LLM patch generation ──────────────────────────────────────────────────────

fn request_patch(
    ollama_url: &str,
    model: &str,
    finding: &Finding,
    source: &str,
    timeout_secs: u64,
) -> Result<(String, String)> {
    let prompt = format!(
        r#"You are a Rust security engineer. Fix the following security vulnerability.

Vulnerability:
  Rule: {}
  File: {} line {}
  CWE: {:?}
  Evidence: {}
  Remediation: {}

Source file content:
```rust
{}
```

Produce a minimal, correct fix. Reply with ONLY valid JSON (no markdown outside JSON):
{{"reasoning": "...", "patched_source": "...full corrected file content..."}}"#,
        finding.rule_id,
        finding.file,
        finding.line,
        finding.cwe,
        finding.evidence,
        finding.remediation,
        source,
    );

    let body = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": false
    });

    let response = ureq::post(&format!("{}/api/chat", ollama_url))
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .send_json(&body)
        .context("Ollama patch request failed")?;

    let val: serde_json::Value = response.into_json()?;
    let content = val["message"]["content"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_string();

    let json_str = content
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let parsed: serde_json::Value = serde_json::from_str(json_str)
        .context("Cannot parse LLM patch JSON")?;

    let reasoning = parsed["reasoning"].as_str().unwrap_or("").to_string();
    let patched = parsed["patched_source"]
        .as_str()
        .context("Missing patched_source in response")?
        .to_string();

    Ok((patched, reasoning))
}

// ── Worktree helpers ──────────────────────────────────────────────────────────

fn git_root(repo: &Path) -> Result<PathBuf> {
    let out = Command::new("git")
        .args(["-C", &repo.to_string_lossy(), "rev-parse", "--show-toplevel"])
        .output()?;
    Ok(PathBuf::from(
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
    ))
}

fn create_worktree(git_root: &Path, worktree_dir: &Path) -> Result<()> {
    let out = Command::new("git")
        .args([
            "-C",
            &git_root.to_string_lossy(),
            "worktree",
            "add",
            "--detach",
            &worktree_dir.to_string_lossy(),
        ])
        .output()?;
    if !out.status.success() {
        anyhow::bail!(
            "git worktree add failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

fn remove_worktree(git_root: &Path, worktree_dir: &Path) {
    let _ = Command::new("git")
        .args([
            "-C",
            &git_root.to_string_lossy(),
            "worktree",
            "remove",
            "--force",
            &worktree_dir.to_string_lossy(),
        ])
        .output();
}

fn run_cargo_test(worktree_dir: &Path) -> bool {
    Command::new("cargo")
        .args(["test", "--quiet"])
        .current_dir(worktree_dir)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn unified_diff(original: &str, patched: &str, label: &str) -> String {
    // Simple character-level diff is impractical in no-deps context;
    // emit a placeholder that identifies original vs patched.
    // A real implementation would shell out to `diff -u`.
    let out = Command::new("diff")
        .args(["-u", "--label", &format!("a/{}", label), "--label", &format!("b/{}", label), "-", "-"])
        .stdin(std::process::Stdio::null())
        .output();

    // Try `diff` with temp files
    let orig_tmp = format!("/tmp/aether_patch_orig_{}.rs", std::process::id());
    let new_tmp = format!("/tmp/aether_patch_new_{}.rs", std::process::id());
    let _ = std::fs::write(&orig_tmp, original);
    let _ = std::fs::write(&new_tmp, patched);
    let result = Command::new("diff")
        .args(["-u", &orig_tmp, &new_tmp])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|_| format!("--- a/{}\n+++ b/{}\n(diff unavailable)\n", label, label));
    let _ = std::fs::remove_file(&orig_tmp);
    let _ = std::fs::remove_file(&new_tmp);
    let _ = out; // suppress warning
    result
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn patch_finding(
    finding: &Finding,
    repo_root: &Path,
    config: &PatchConfig,
) -> PatchResult {
    let file_path = repo_root.join(&finding.file);
    let original_source = match std::fs::read_to_string(&file_path) {
        Ok(s) => s,
        Err(e) => {
            return PatchResult {
                finding: finding.clone(),
                attempt: 0,
                unified_diff: None,
                status: PatchStatus::ApplyFailed(format!("cannot read {}: {}", finding.file, e)),
                llm_reasoning: String::new(),
            };
        }
    };

    let git_root = match git_root(repo_root) {
        Ok(r) => r,
        Err(e) => {
            return PatchResult {
                finding: finding.clone(),
                attempt: 0,
                unified_diff: None,
                status: PatchStatus::WorktreeFailed(e.to_string()),
                llm_reasoning: String::new(),
            };
        }
    };

    for attempt in 1..=config.max_attempts {
        let (patched, reasoning) = match request_patch(
            &config.ollama_url,
            &config.model,
            finding,
            &original_source,
            config.timeout_secs,
        ) {
            Ok(p) => p,
            Err(e) => {
                if attempt == config.max_attempts {
                    return PatchResult {
                        finding: finding.clone(),
                        attempt,
                        unified_diff: None,
                        status: PatchStatus::GenerationFailed(e.to_string()),
                        llm_reasoning: String::new(),
                    };
                }
                continue;
            }
        };

        let worktree_dir = PathBuf::from(format!("/tmp/aether_wt_{}_{}", std::process::id(), attempt));
        if let Err(e) = create_worktree(&git_root, &worktree_dir) {
            return PatchResult {
                finding: finding.clone(),
                attempt,
                unified_diff: None,
                status: PatchStatus::WorktreeFailed(e.to_string()),
                llm_reasoning: reasoning,
            };
        }

        let wt_file = worktree_dir.join(&finding.file);
        if let Some(parent) = wt_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&wt_file, &patched) {
            remove_worktree(&git_root, &worktree_dir);
            return PatchResult {
                finding: finding.clone(),
                attempt,
                unified_diff: None,
                status: PatchStatus::ApplyFailed(e.to_string()),
                llm_reasoning: reasoning,
            };
        }

        let tests_passed = if config.run_tests {
            run_cargo_test(&worktree_dir)
        } else {
            true
        };

        let diff = unified_diff(&original_source, &patched, &finding.file);
        remove_worktree(&git_root, &worktree_dir);

        return PatchResult {
            finding: finding.clone(),
            attempt,
            unified_diff: Some(diff),
            status: PatchStatus::Applied { tests_passed },
            llm_reasoning: reasoning,
        };
    }

    PatchResult {
        finding: finding.clone(),
        attempt: config.max_attempts,
        unified_diff: None,
        status: PatchStatus::GenerationFailed("max attempts reached".to_string()),
        llm_reasoning: String::new(),
    }
}

pub fn patch_all(
    findings: &[Finding],
    repo_root: &Path,
    config: &PatchConfig,
) -> Vec<PatchResult> {
    findings
        .iter()
        .map(|f| patch_finding(f, repo_root, config))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_finding() -> Finding {
        Finding {
            severity: Severity::High,
            rule_id: "TAINT-78".to_string(),
            cwe: Some("CWE-78".to_string()),
            file: "src/main.rs".to_string(),
            line: 5,
            evidence: "env var flows to Command::new".to_string(),
            remediation: "use allowlist or shell-escape".to_string(),
        }
    }

    #[test]
    fn patch_finding_missing_file_returns_apply_failed() {
        let finding = Finding {
            file: "src/nonexistent_xyzzy.rs".to_string(),
            ..sample_finding()
        };
        let result = patch_finding(&finding, Path::new("/tmp"), &PatchConfig::default());
        assert!(matches!(result.status, PatchStatus::ApplyFailed(_)));
    }

    #[test]
    fn patch_finding_no_ollama_returns_generation_failed() {
        let tmp = std::env::temp_dir();
        let finding = Finding {
            file: "src/main.rs".to_string(),
            ..sample_finding()
        };
        let src_path = tmp.join("src");
        let _ = std::fs::create_dir_all(&src_path);
        let _ = std::fs::write(src_path.join("main.rs"), "fn main() {}");

        let config = PatchConfig {
            ollama_url: "http://127.0.0.1:19999".to_string(),
            max_attempts: 1,
            run_tests: false,
            timeout_secs: 1,
            ..PatchConfig::default()
        };
        let result = patch_finding(&finding, &tmp, &config);
        // Either generation failed (no Ollama) or worktree failed (not a git repo)
        assert!(
            matches!(
                result.status,
                PatchStatus::GenerationFailed(_) | PatchStatus::WorktreeFailed(_)
            ),
            "unexpected status: {:?}",
            result.status
        );
    }

    #[test]
    fn patch_all_empty_returns_empty() {
        let results = patch_all(&[], Path::new("/tmp"), &PatchConfig::default());
        assert!(results.is_empty());
    }

    #[test]
    fn patch_status_serializes() {
        let s = PatchStatus::Applied { tests_passed: true };
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("Applied"));
    }

    #[test]
    fn patch_result_fields_correct() {
        let f = sample_finding();
        let result = PatchResult {
            finding: f.clone(),
            attempt: 1,
            unified_diff: Some("--- a/src/main.rs".to_string()),
            status: PatchStatus::Applied { tests_passed: true },
            llm_reasoning: "fixed the injection".to_string(),
        };
        assert_eq!(result.attempt, 1);
        assert!(result.unified_diff.is_some());
        assert_eq!(result.llm_reasoning, "fixed the injection");
    }

    #[test]
    fn unified_diff_produces_output() {
        let orig = "fn main() { println!(\"hello\"); }";
        let patched = "fn main() { println!(\"world\"); }";
        let d = unified_diff(orig, patched, "main.rs");
        // Either a real diff or a fallback message — must be non-empty
        assert!(!d.is_empty());
    }
}
