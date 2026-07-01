//! GitHub PR annotator.
//!
//! Posts inline review comments for each finding on the relevant line
//! using the GitHub REST API (pull requests review comments endpoint).
//! Requires GITHUB_TOKEN env var. GITHUB_API_URL defaults to https://api.github.com.

pub use aether_deps_reach::{Finding, Severity};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrBotConfig {
    pub api_url: String,
    pub repo: String,
    pub pr_number: u64,
    pub commit_sha: String,
    pub timeout_secs: u64,
    pub dry_run: bool,
}

impl PrBotConfig {
    pub fn from_env() -> Result<PrBotConfig> {
        Ok(PrBotConfig {
            api_url: std::env::var("GITHUB_API_URL")
                .unwrap_or_else(|_| "https://api.github.com".to_string()),
            repo: std::env::var("GITHUB_REPOSITORY")
                .context("GITHUB_REPOSITORY not set (format: owner/repo)")?,
            pr_number: std::env::var("PR_NUMBER")
                .context("PR_NUMBER not set")?
                .parse::<u64>()
                .context("PR_NUMBER must be an integer")?,
            commit_sha: std::env::var("GITHUB_SHA")
                .context("GITHUB_SHA not set")?,
            timeout_secs: 30,
            dry_run: std::env::var("AETHER_DRY_RUN").map(|v| v == "1").unwrap_or(false),
        })
    }
}

// ── Review comment ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewComment {
    pub path: String,
    pub line: u32,
    pub body: String,
}

pub fn finding_to_comment(finding: &Finding) -> ReviewComment {
    let severity_emoji = match finding.severity {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🟢",
        Severity::Info => "ℹ️",
    };
    let cwe = finding.cwe.as_deref().unwrap_or("");
    let body = format!(
        "{severity_emoji} **[{rule_id}]** {cwe}\n\n{evidence}\n\n**Remediation:** {remediation}",
        severity_emoji = severity_emoji,
        rule_id = finding.rule_id,
        cwe = cwe,
        evidence = finding.evidence,
        remediation = finding.remediation,
    );
    ReviewComment {
        path: finding.file.clone(),
        line: finding.line,
        body,
    }
}

// ── GitHub API ────────────────────────────────────────────────────────────────

fn github_token() -> Result<String> {
    std::env::var("GITHUB_TOKEN").context("GITHUB_TOKEN env var not set")
}

pub fn post_review_comment(
    config: &PrBotConfig,
    comment: &ReviewComment,
) -> Result<()> {
    if config.dry_run {
        println!(
            "[dry-run] Would post to PR #{}: {}:{} → {}",
            config.pr_number, comment.path, comment.line, comment.body
        );
        return Ok(());
    }

    let token = github_token()?;
    let url = format!(
        "{}/repos/{}/pulls/{}/comments",
        config.api_url, config.repo, config.pr_number
    );

    let payload = serde_json::json!({
        "body": comment.body,
        "commit_id": config.commit_sha,
        "path": comment.path,
        "line": comment.line,
        "side": "RIGHT"
    });

    let response = ureq::post(&url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .set("User-Agent", "aether-pr-bot/0.36.0")
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .send_json(&payload);

    match response {
        Ok(r) if r.status() == 201 => Ok(()),
        Ok(r) => anyhow::bail!("GitHub API returned {}", r.status()),
        Err(e) => Err(anyhow::anyhow!("GitHub API error: {}", e)),
    }
}

// ── Batch post ────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct PostResult {
    pub posted: usize,
    pub errors: Vec<String>,
}

pub fn post_findings(findings: &[Finding], config: &PrBotConfig) -> PostResult {
    let mut result = PostResult::default();
    for finding in findings {
        let comment = finding_to_comment(finding);
        match post_review_comment(config, &comment) {
            Ok(()) => result.posted += 1,
            Err(e) => result.errors.push(format!("{}: {}", finding.rule_id, e)),
        }
    }
    result
}

/// Create a PR review summary comment (top-level, not inline).
pub fn post_summary(findings: &[Finding], config: &PrBotConfig) -> Result<()> {
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = findings.iter().filter(|f| f.severity == Severity::Low).count();

    let body = format!(
        "## Aether Security Scan Results\n\n\
         | Severity | Count |\n\
         |----------|-------|\n\
         | 🔴 Critical | {} |\n\
         | 🟠 High | {} |\n\
         | 🟡 Medium | {} |\n\
         | 🟢 Low | {} |\n\n\
         Total: {} findings. See inline comments for details.",
        critical, high, medium, low,
        critical + high + medium + low,
    );

    if config.dry_run {
        println!("[dry-run] Summary comment:\n{}", body);
        return Ok(());
    }

    let token = github_token()?;
    let url = format!(
        "{}/repos/{}/issues/{}/comments",
        config.api_url, config.repo, config.pr_number
    );

    let payload = serde_json::json!({ "body": body });
    let response = ureq::post(&url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .set("User-Agent", "aether-pr-bot/0.36.0")
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .send_json(&payload);

    match response {
        Ok(r) if r.status() == 201 => Ok(()),
        Ok(r) => anyhow::bail!("GitHub issues API returned {}", r.status()),
        Err(e) => Err(anyhow::anyhow!("GitHub issues API error: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, sev: Severity) -> Finding {
        Finding {
            severity: sev,
            rule_id: rule.to_string(),
            cwe: Some("CWE-78".to_string()),
            file: "src/main.rs".to_string(),
            line: 42,
            evidence: "taint flow".to_string(),
            remediation: "use allowlist".to_string(),
        }
    }

    #[test]
    fn comment_critical_has_red_emoji() {
        let c = finding_to_comment(&finding("R1", Severity::Critical));
        assert!(c.body.contains('🔴'));
    }

    #[test]
    fn comment_high_has_orange_emoji() {
        let c = finding_to_comment(&finding("R2", Severity::High));
        assert!(c.body.contains('🟠'));
    }

    #[test]
    fn comment_body_contains_rule_id() {
        let c = finding_to_comment(&finding("TAINT-78", Severity::High));
        assert!(c.body.contains("TAINT-78"));
    }

    #[test]
    fn comment_body_contains_remediation() {
        let c = finding_to_comment(&finding("R3", Severity::Medium));
        assert!(c.body.contains("use allowlist"));
    }

    #[test]
    fn comment_path_and_line_correct() {
        let c = finding_to_comment(&finding("R4", Severity::High));
        assert_eq!(c.path, "src/main.rs");
        assert_eq!(c.line, 42);
    }

    #[test]
    fn dry_run_post_succeeds() {
        let config = PrBotConfig {
            api_url: "https://api.github.com".to_string(),
            repo: "owner/repo".to_string(),
            pr_number: 1,
            commit_sha: "abc123".to_string(),
            timeout_secs: 5,
            dry_run: true,
        };
        let comment = ReviewComment {
            path: "src/main.rs".to_string(),
            line: 10,
            body: "test comment".to_string(),
        };
        assert!(post_review_comment(&config, &comment).is_ok());
    }

    #[test]
    fn post_findings_dry_run() {
        let config = PrBotConfig {
            api_url: "https://api.github.com".to_string(),
            repo: "owner/repo".to_string(),
            pr_number: 1,
            commit_sha: "abc123".to_string(),
            timeout_secs: 5,
            dry_run: true,
        };
        let findings = vec![
            finding("T1", Severity::High),
            finding("T2", Severity::Medium),
        ];
        let result = post_findings(&findings, &config);
        assert_eq!(result.posted, 2);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn post_summary_dry_run() {
        let config = PrBotConfig {
            dry_run: true,
            api_url: "https://api.github.com".to_string(),
            repo: "owner/repo".to_string(),
            pr_number: 1,
            commit_sha: "abc123".to_string(),
            timeout_secs: 5,
        };
        let findings = vec![finding("T1", Severity::Critical)];
        assert!(post_summary(&findings, &config).is_ok());
    }
}
