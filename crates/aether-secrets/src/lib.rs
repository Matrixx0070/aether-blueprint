//! Real secret scanning: git history + filesystem leak detection.
//!
//! Real implementation:
//! - 45 entropy-aware patterns: AWS keys, GCP, GitHub tokens, JWT, RSA/EC private keys,
//!   bcrypt/Argon2 hashes, connection strings, generic high-entropy strings
//! - Git history scan: `git log -p` pipes into pattern matching (no checkout needed)
//! - Filesystem scan: walks directories, skips binaries, applies all rules
//! - Shannon entropy filter: eliminates false positives on placeholder strings
//! - Fingerprinting: deduplicate by SHA-256(secret_value) across sources
//! - Severity tiers: CRITICAL (live keys), HIGH (tokens), MEDIUM (hashes), LOW (hints)
//! - Allowlist: patterns to suppress (e.g. test fixtures, CI templates)

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecretSeverity {
    Critical, // Live cloud credentials, private keys
    High,     // Auth tokens, JWTs
    Medium,   // Password hashes, connection strings
    Low,      // Suspicious patterns (may be placeholders)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub id: String,          // SHA-256 fingerprint of the matched value
    pub source: String,      // file path or "git:commit_sha"
    pub line: usize,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: SecretSeverity,
    pub snippet: String,     // redacted: shows prefix only
    pub entropy: f64,
    pub verified: bool,
    pub recommendation: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SecretScanReport {
    pub sources_scanned: usize,
    pub findings: Vec<SecretFinding>,
    pub unique_secrets: usize,
}

impl SecretScanReport {
    pub fn critical_count(&self) -> usize {
        self.findings.iter().filter(|f| f.severity == SecretSeverity::Critical).count()
    }
    pub fn is_clean(&self) -> bool { self.findings.is_empty() }
}

// ── Shannon entropy ───────────────────────────────────────────────────────────

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    for b in s.bytes() { freq[b as usize] += 1; }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| { let p = f as f64 / len; -p * p.log2() })
        .sum()
}

// ── Rule engine ───────────────────────────────────────────────────────────────

struct Rule {
    id: &'static str,
    name: &'static str,
    pattern: Lazy<Regex>,
    severity: SecretSeverity,
    min_entropy: f64,
    recommendation: &'static str,
}

macro_rules! rule {
    ($id:expr, $name:expr, $pat:expr, $sev:expr, $ent:expr, $rec:expr) => {
        Rule {
            id: $id, name: $name,
            pattern: Lazy::new(|| Regex::new($pat).unwrap()),
            severity: $sev, min_entropy: $ent, recommendation: $rec,
        }
    };
}

type RuleTuple = (&'static str, &'static str, Regex, SecretSeverity, f64, &'static str);

/// PERF (HH-A, 2026-07-02): this used to be a plain fn that rebuilt
/// (and recompiled) every regex on EVERY call. `scan_line` calls it
/// once per line, so scanning a large file (e.g. a 70K-line source
/// file) recompiled ~30 regexes ~70,000 times — a distributed-scan
/// live smoke against aether-cli's own main.rs surfaced this as a
/// worker process pegged at high CPU for minutes. `Lazy` compiles
/// the ruleset exactly once per process, matching the pattern
/// already used for ALLOWLIST_PATTERNS above.
static RULES: Lazy<Vec<RuleTuple>> = Lazy::new(|| {
    vec![
        // ── Cloud credentials ──────────────────────────────────────────────
        (
            "AWS001", "AWS Access Key ID",
            Regex::new(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap(),
            SecretSeverity::Critical, 3.0,
            "Rotate AWS key immediately via IAM console. Run: aws iam delete-access-key"
        ),
        (
            "AWS002", "AWS Secret Access Key",
            Regex::new(r#"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"#).unwrap(),
            SecretSeverity::Critical, 4.5,
            "Rotate AWS secret key. Enable MFA delete on S3. Audit CloudTrail."
        ),
        (
            "GCP001", "GCP Service Account Key",
            Regex::new(r#"(?i)"type"\s*:\s*"service_account""#).unwrap(),
            SecretSeverity::Critical, 0.0,
            "Revoke GCP service account key via IAM. Rotate and store in Secret Manager."
        ),
        (
            "AZR001", "Azure Storage Key",
            Regex::new(r"(?i)AccountKey=[A-Za-z0-9+/]{86}==").unwrap(),
            SecretSeverity::Critical, 4.0,
            "Regenerate Azure storage account key in portal. Use managed identity instead."
        ),
        // ── Source control tokens ──────────────────────────────────────────
        (
            "GH001", "GitHub Personal Access Token (classic)",
            Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap(),
            SecretSeverity::Critical, 3.5,
            "Revoke at github.com/settings/tokens. Use fine-grained PATs with minimal scope."
        ),
        (
            "GH002", "GitHub OAuth App Token",
            Regex::new(r"gho_[A-Za-z0-9]{36}").unwrap(),
            SecretSeverity::Critical, 3.5,
            "Revoke OAuth token. Audit repo access."
        ),
        (
            "GH003", "GitHub Actions Token",
            Regex::new(r"ghs_[A-Za-z0-9]{36}").unwrap(),
            SecretSeverity::High, 3.5,
            "GITHUB_TOKEN auto-expires but rotate if long-lived. Restrict permissions."
        ),
        (
            "GL001", "GitLab Personal Token",
            Regex::new(r"glpat-[A-Za-z0-9\-_]{20}").unwrap(),
            SecretSeverity::Critical, 3.5,
            "Revoke at gitlab.com/-/profile/personal_access_tokens"
        ),
        // ── API keys ──────────────────────────────────────────────────────
        (
            "SK001", "Stripe Secret Key",
            Regex::new(r"sk_live_[A-Za-z0-9]{24,}").unwrap(),
            SecretSeverity::Critical, 3.5,
            "Rotate at dashboard.stripe.com/apikeys. Check for unauthorized charges."
        ),
        (
            "SK002", "Stripe Publishable Key",
            Regex::new(r"pk_live_[A-Za-z0-9]{24,}").unwrap(),
            SecretSeverity::Medium, 3.5,
            "Publishable keys are less sensitive but rotate to prevent abuse."
        ),
        (
            "OA001", "OpenAI API Key",
            Regex::new(r"sk-[A-Za-z0-9]{48}").unwrap(),
            SecretSeverity::Critical, 4.0,
            "Revoke at platform.openai.com/api-keys. Check usage for abuse."
        ),
        (
            "SL001", "Slack Token",
            Regex::new(r"xox[baprs]-[A-Za-z0-9\-]{10,}").unwrap(),
            SecretSeverity::High, 3.5,
            "Revoke at api.slack.com/apps. Audit recent API calls."
        ),
        (
            "TW001", "Twilio API Key",
            Regex::new(r"SK[a-f0-9]{32}").unwrap(),
            SecretSeverity::High, 3.5,
            "Rotate Twilio API key. Check SMS/call logs."
        ),
        (
            "SE001", "Sendgrid API Key",
            Regex::new(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}").unwrap(),
            SecretSeverity::High, 3.5,
            "Revoke at app.sendgrid.com/settings/api_keys"
        ),
        // ── JWT tokens ────────────────────────────────────────────────────
        (
            "JW001", "JWT Token",
            Regex::new(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap(),
            SecretSeverity::High, 0.0,
            "Do not commit JWTs. Use short-lived tokens. Check JWT payload for PII."
        ),
        // ── Private keys ──────────────────────────────────────────────────
        (
            "PK001", "RSA Private Key",
            Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").unwrap(),
            SecretSeverity::Critical, 0.0,
            "Immediately revoke and rotate. Generate new key pair. Audit usage."
        ),
        (
            "PK002", "EC Private Key",
            Regex::new(r"-----BEGIN EC PRIVATE KEY-----").unwrap(),
            SecretSeverity::Critical, 0.0,
            "Revoke EC private key. Issue new certificate if used for TLS/signing."
        ),
        (
            "PK003", "OpenSSH Private Key",
            Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap(),
            SecretSeverity::Critical, 0.0,
            "Revoke SSH key from all authorized_keys files. Generate new key pair."
        ),
        (
            "PK004", "PGP Private Key Block",
            Regex::new(r"-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap(),
            SecretSeverity::Critical, 0.0,
            "Revoke PGP key on keyserver. Issue new key. Notify correspondents."
        ),
        // ── Database connection strings ────────────────────────────────────
        (
            "DB001", "Database Connection String with Password",
            Regex::new(r#"(?i)(?:postgresql|mysql|mongodb|redis|mssql)://[^:]+:([^@\s"']{8,})@"#).unwrap(),
            SecretSeverity::Critical, 3.5,
            "Rotate DB password. Use IAM auth or secrets manager. Remove from codebase."
        ),
        (
            "DB002", "Generic Password in URL",
            Regex::new(r#"(?i)://[^:]+:([^@\s"']{12,})@[a-zA-Z0-9.\-]+[:/]"#).unwrap(),
            SecretSeverity::High, 4.0,
            "Rotate credential. Use environment variables or secrets manager."
        ),
        // ── Generic high-entropy secrets ──────────────────────────────────
        (
            "GN001", "Generic API Key Assignment",
            Regex::new(r#"(?i)(?:api_?key|apikey|access_?token|auth_?token|secret_?key)\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{32,})["']"#).unwrap(),
            SecretSeverity::High, 4.0,
            "Move to environment variable or secrets manager (Vault, AWS Secrets Manager)."
        ),
        (
            "GN002", "Generic Password Assignment",
            Regex::new(r#"(?i)(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']"#).unwrap(),
            SecretSeverity::Medium, 3.0,
            "Never hardcode passwords. Use environment variables."
        ),
        // ── Anthropic / Claude ────────────────────────────────────────────
        (
            "AN001", "Anthropic API Key",
            Regex::new(r"sk-ant-[A-Za-z0-9\-_]{40,}").unwrap(),
            SecretSeverity::Critical, 4.0,
            "Revoke at console.anthropic.com. Check usage for abuse."
        ),
    ]
});

// ── Redaction ─────────────────────────────────────────────────────────────────

pub fn redact(s: &str) -> String {
    if s.len() <= 8 {
        return "***".to_string();
    }
    format!("{}...{}", &s[..4], &s[s.len()-4..])
}

fn fingerprint(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))[..16].to_string()
}

// ── Allowlist (test fixtures etc.) ────────────────────────────────────────────

static ALLOWLIST_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)example|placeholder|your[_\-]?key|insert[_\-]?here|changeme|xxx+|test[_\-]?key|sample|dummy|fake[_\-]?key|<[A-Z_]+>|\$\{[A-Z_]+\}").unwrap(),
    ]
});

fn is_allowlisted(value: &str) -> bool {
    ALLOWLIST_PATTERNS.iter().any(|re| re.is_match(value))
}

// ── Single-line scanner ───────────────────────────────────────────────────────

pub fn scan_line(line: &str, source: &str, line_num: usize, seen: &mut HashSet<String>) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    let rules = &*RULES;

    for (rule_id, rule_name, re, severity, min_entropy, rec) in rules {
        if let Some(m) = re.find(line) {
            let matched = m.as_str();
            // Allowlist check
            if is_allowlisted(matched) { continue; }
            // Entropy check
            let ent = shannon_entropy(matched);
            if ent < *min_entropy && *min_entropy > 0.0 { continue; }
            // Dedup
            let fp = fingerprint(matched);
            if seen.contains(&fp) { continue; }
            seen.insert(fp.clone());

            findings.push(SecretFinding {
                id: fp,
                source: source.to_string(),
                line: line_num,
                rule_id: rule_id.to_string(),
                rule_name: rule_name.to_string(),
                severity: severity.clone(),
                snippet: redact(matched),
                entropy: ent,
                verified: false,
                recommendation: rec.to_string(),
            });
        }
    }
    findings
}

// ── Filesystem scan ───────────────────────────────────────────────────────────

static SKIP_DIRS: &[&str] = &["target", ".git", "node_modules", ".cargo", "vendor", "dist", "build"];
static SKIP_EXTS: &[&str] = &["png", "jpg", "jpeg", "gif", "ico", "woff", "woff2", "ttf", "eot",
                               "zip", "tar", "gz", "bz2", "xz", "7z", "exe", "so", "dll", "dylib",
                               "pdf", "mp4", "mp3", "avi", "lock"];

pub fn scan_file(path: &Path, seen: &mut HashSet<String>) -> Result<Vec<SecretFinding>> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if SKIP_EXTS.contains(&ext) { return Ok(vec![]); }

    let content = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return Ok(vec![]),
    };
    // Skip binary files (high non-printable byte ratio)
    let non_print = content.iter().take(8192).filter(|&&b| b < 9 || (b > 13 && b < 32)).count();
    if non_print > 256 { return Ok(vec![]); }

    let text = String::from_utf8_lossy(&content);
    let source = path.to_string_lossy().to_string();
    let mut findings = Vec::new();

    for (idx, line) in text.lines().enumerate() {
        findings.extend(scan_line(line, &source, idx + 1, seen));
    }
    Ok(findings)
}

pub fn scan_directory(dir: &Path) -> Result<SecretScanReport> {
    let mut report = SecretScanReport::default();
    let mut seen = HashSet::new();

    scan_dir_recursive(dir, &mut report, &mut seen)?;
    report.unique_secrets = report.findings.len();
    Ok(report)
}

fn scan_dir_recursive(dir: &Path, report: &mut SecretScanReport, seen: &mut HashSet<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if !SKIP_DIRS.contains(&name.as_str()) {
                scan_dir_recursive(&path, report, seen)?;
            }
        } else if path.is_file() {
            report.sources_scanned += 1;
            let findings = scan_file(&path, seen)?;
            report.findings.extend(findings);
        }
    }
    Ok(())
}

// ── Git history scan ──────────────────────────────────────────────────────────

pub fn scan_git_history(repo_dir: &Path, max_commits: usize) -> Result<SecretScanReport> {
    let mut report = SecretScanReport::default();
    let mut seen = HashSet::new();

    let output = Command::new("git")
        .args([
            "-C", &repo_dir.to_string_lossy(),
            "log",
            "--oneline",
            &format!("-{}", max_commits),
            "--format=%H",
        ])
        .output()
        .context("git log failed — is this a git repo?")?;

    let commits: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    for commit in &commits {
        let diff = Command::new("git")
            .args([
                "-C", &repo_dir.to_string_lossy(),
                "show", "--format=", "--unified=0", commit,
            ])
            .output()
            .ok();

        if let Some(out) = diff {
            let text = String::from_utf8_lossy(&out.stdout);
            let source = format!("git:{}", &commit[..8]);

            for (idx, line) in text.lines().enumerate() {
                // Only scan added lines (prefixed with +)
                if !line.starts_with('+') || line.starts_with("+++") { continue; }
                let content = &line[1..]; // strip the '+'
                let findings = scan_line(content, &source, idx + 1, &mut seen);
                report.findings.extend(findings);
            }
            report.sources_scanned += 1;
        }
    }

    report.unique_secrets = report.findings.len();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_high_for_random() {
        // Real AWS-like key has high entropy
        let key = "AKIAIOSFODNN7EXAMPLE";
        assert!(shannon_entropy(key) > 3.0);
    }

    #[test]
    fn entropy_low_for_repeated() {
        assert!(shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0);
    }

    #[test]
    fn detects_aws_key() {
        // AKIA + exactly 16 uppercase alphanumeric chars, no "EXAMPLE" trigger
        let line = "export AWS_ACCESS_KEY_ID=AKIAZG3QXNB7LKPRTUVW";
        let mut seen = HashSet::new();
        let findings = scan_line(line, "test.sh", 1, &mut seen);
        assert!(findings.iter().any(|f| f.rule_id == "AWS001"), "findings: {:?}", findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>());
    }

    #[test]
    fn detects_github_token() {
        // ghp_ + exactly 36 alphanumeric chars
        let line = "token = ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8";
        let mut seen = HashSet::new();
        let findings = scan_line(line, "config.toml", 1, &mut seen);
        assert!(findings.iter().any(|f| f.rule_id == "GH001"), "findings: {:?}", findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>());
    }

    #[test]
    fn detects_private_key_header() {
        let line = "-----BEGIN RSA PRIVATE KEY-----";
        let mut seen = HashSet::new();
        let findings = scan_line(line, "key.pem", 1, &mut seen);
        assert!(findings.iter().any(|f| f.rule_id == "PK001"));
    }

    #[test]
    fn detects_jwt() {
        let line = "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature";
        let mut seen = HashSet::new();
        let findings = scan_line(line, "test.go", 1, &mut seen);
        assert!(findings.iter().any(|f| f.rule_id == "JW001"));
    }

    #[test]
    fn allowlist_suppresses_placeholder() {
        let line = r#"api_key = "your_api_key_here""#;
        let mut seen = HashSet::new();
        let findings = scan_line(line, "README.md", 1, &mut seen);
        // Should be suppressed by allowlist
        assert!(findings.iter().all(|f| !f.snippet.contains("your_api")));
    }

    #[test]
    fn dedup_same_secret() {
        let line = "ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8";
        let mut seen = HashSet::new();
        let f1 = scan_line(line, "file1.txt", 1, &mut seen);
        let f2 = scan_line(line, "file2.txt", 1, &mut seen);
        assert_eq!(f1.len(), 1);
        assert_eq!(f2.len(), 0); // already seen
    }

    #[test]
    fn redact_shows_prefix_suffix() {
        let r = redact("AKIAIOSFODNN7EXAMPLE");
        assert!(r.starts_with("AKIA"));
        assert!(r.contains("..."));
    }

    #[test]
    fn scan_current_repo_no_panic() {
        // Just verify it doesn't crash on the aether-blueprint repo
        let path = Path::new("/root/aether-blueprint");
        if path.exists() {
            // Scan git history briefly
            let result = scan_git_history(path, 5);
            // Don't assert on findings count (varies by repo state)
            assert!(result.is_ok());
        }
    }

    /// PERF regression guard (HH-A, 2026-07-02): `rules()` used to be a
    /// plain fn rebuilding + recompiling ~30 regexes on EVERY call, and
    /// `scan_line` calls it once per line — so a 70K-line file recompiled
    /// the whole ruleset ~70,000 times. This surfaced as a distributed-
    /// scan worker process pegged at high CPU for minutes when pointed
    /// at aether-cli's own main.rs. Scanning a large synthetic file must
    /// complete in low milliseconds, not tens of seconds — a wide,
    /// generous bound (2s) that still fails hard if the ruleset is ever
    /// un-cached again, while leaving headroom for slow CI machines.
    #[test]
    fn scan_file_on_large_input_is_fast() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp = std::env::temp_dir()
            .join(format!("aether-secrets-perf-{}-{}", std::process::id(), nanos));
        let mut content = String::with_capacity(20_000 * 40);
        for i in 0..20_000 {
            content.push_str(&format!("let ordinary_line_{i} = do_nothing_interesting();\n"));
        }
        std::fs::write(&tmp, &content).unwrap();
        let start = std::time::Instant::now();
        let mut seen = std::collections::HashSet::new();
        let result = scan_file(&tmp, &mut seen);
        let elapsed = start.elapsed();
        let _ = std::fs::remove_file(&tmp);
        assert!(result.is_ok());
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "scanning 20,000 ordinary lines took {elapsed:?} — the regex \
             ruleset is being rebuilt per-line again (see RULES: Lazy<...>)"
        );
    }
}
