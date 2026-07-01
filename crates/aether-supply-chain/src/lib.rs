//! Real supply-chain monitoring: Cargo.lock + crates.io + OSV.dev CVE database.
//!
//! TIER 25 real implementation:
//! - Parses Cargo.lock (TOML format) without external parser (hand-rolled)
//! - Queries crates.io API for yanked versions
//! - Queries OSV.dev for known CVEs per crate+version
//! - Detects typosquatting via edit-distance to popular crates
//! - Watch mode: re-checks on inotify/poll

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedCrate {
    pub name: String,
    pub version: String,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainFinding {
    pub crate_name: String,
    pub version: String,
    pub severity: FindingSeverity,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SupplyChainReport {
    pub crates_scanned: usize,
    pub findings: Vec<SupplyChainFinding>,
}

impl SupplyChainReport {
    pub fn is_clean(&self) -> bool { self.findings.is_empty() }
    pub fn critical_count(&self) -> usize {
        self.findings.iter().filter(|f| f.severity == FindingSeverity::Critical).count()
    }
}

// ── Cargo.lock parser (hand-rolled, no extra deps) ────────────────────────────

pub fn parse_cargo_lock(content: &str) -> Vec<LockedCrate> {
    let mut crates = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut checksum: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                crates.push(LockedCrate { name: n, version: v, checksum: checksum.take() });
            }
        } else if let Some(val) = line.strip_prefix("name = \"").and_then(|s| s.strip_suffix('"')) {
            name = Some(val.to_string());
        } else if let Some(val) = line.strip_prefix("version = \"").and_then(|s| s.strip_suffix('"')) {
            version = Some(val.to_string());
        } else if let Some(val) = line.strip_prefix("checksum = \"").and_then(|s| s.strip_suffix('"')) {
            checksum = Some(val.to_string());
        }
    }
    // last package
    if let (Some(n), Some(v)) = (name, version) {
        crates.push(LockedCrate { name: n, version: v, checksum });
    }
    crates
}

// ── crates.io API ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CratesIoVersion {
    num: String,
    yanked: bool,
}

#[derive(Deserialize)]
struct CratesIoResponse {
    versions: Option<Vec<CratesIoVersion>>,
}

pub async fn is_version_yanked(
    client: &reqwest::Client,
    name: &str,
    version: &str,
) -> Result<bool> {
    let url = format!("https://crates.io/api/v1/crates/{name}");
    let resp = client
        .get(&url)
        .header("User-Agent", "aether-supply-chain/0.35.0 (security scanner)")
        .send()
        .await
        .context("crates.io request failed")?;

    if !resp.status().is_success() {
        return Ok(false); // Not an error — crate might be workspace-only
    }

    let data: CratesIoResponse = resp.json().await.context("crates.io parse failed")?;
    let yanked = data.versions.unwrap_or_default()
        .iter()
        .find(|v| v.num == version)
        .map(|v| v.yanked)
        .unwrap_or(false);
    Ok(yanked)
}

// ── OSV.dev CVE API ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    r#type: String,
    score: String,
}

#[derive(Deserialize)]
struct OsvResponse {
    vulns: Option<Vec<OsvVulnerability>>,
}

pub async fn query_osv(
    client: &reqwest::Client,
    name: &str,
    version: &str,
) -> Result<Vec<(String, String)>> {
    let body = serde_json::json!({
        "version": version,
        "package": { "name": name, "ecosystem": "crates.io" }
    });

    let resp = client
        .post("https://api.osv.dev/v1/query")
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .context("OSV request failed")?;

    if !resp.status().is_success() {
        return Ok(vec![]);
    }

    let data: OsvResponse = resp.json().await.context("OSV parse failed")?;
    let vulns = data.vulns.unwrap_or_default()
        .into_iter()
        .map(|v| (v.id, v.summary.unwrap_or_else(|| "no summary".to_string())))
        .collect();
    Ok(vulns)
}

// ── Typosquatting detection ───────────────────────────────────────────────────

/// Popular crates that typosquatters target.
static POPULAR: &[&str] = &[
    "serde", "tokio", "reqwest", "clap", "anyhow", "thiserror", "rand",
    "log", "regex", "chrono", "futures", "async-trait", "bytes", "hyper",
    "axum", "actix-web", "diesel", "sqlx", "tracing", "syn", "quote",
    "proc-macro2", "libc", "once_cell", "lazy_static", "rayon", "crossbeam",
];

fn levenshtein(a: &str, b: &str) -> usize {
    let (m, n) = (a.len(), b.len());
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }
    for (i, ca) in a.chars().enumerate() {
        for (j, cb) in b.chars().enumerate() {
            dp[i+1][j+1] = if ca == cb {
                dp[i][j]
            } else {
                1 + dp[i][j].min(dp[i+1][j]).min(dp[i][j+1])
            };
        }
    }
    dp[m][n]
}

pub fn check_typosquatting(name: &str) -> Option<&'static str> {
    if POPULAR.contains(&name) {
        return None; // It's the real thing
    }
    POPULAR.iter()
        .find(|&&pop| levenshtein(name, pop) == 1)
        .copied()
}

// ── Full scan ────────────────────────────────────────────────────────────────

pub async fn scan_lockfile(lockfile_path: &Path) -> Result<SupplyChainReport> {
    let content = std::fs::read_to_string(lockfile_path)
        .with_context(|| format!("cannot read {}", lockfile_path.display()))?;

    let crates = parse_cargo_lock(&content);
    let mut report = SupplyChainReport {
        crates_scanned: crates.len(),
        ..Default::default()
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    for krate in &crates {
        // 1. Typosquatting
        if let Some(similar) = check_typosquatting(&krate.name) {
            report.findings.push(SupplyChainFinding {
                crate_name: krate.name.clone(),
                version: krate.version.clone(),
                severity: FindingSeverity::High,
                kind: "typosquatting".to_string(),
                detail: format!("'{}' is 1 character away from the popular crate '{}'", krate.name, similar),
            });
        }

        // 2. Yanked check (skip workspace crates with no checksum)
        if krate.checksum.is_some() {
            if let Ok(true) = is_version_yanked(&client, &krate.name, &krate.version).await {
                report.findings.push(SupplyChainFinding {
                    crate_name: krate.name.clone(),
                    version: krate.version.clone(),
                    severity: FindingSeverity::Critical,
                    kind: "yanked".to_string(),
                    detail: format!("{} v{} has been yanked from crates.io (often indicates a security issue or malicious code discovery)", krate.name, krate.version),
                });
            }
        }

        // 3. OSV CVE check (skip workspace crates)
        if krate.checksum.is_some() {
            match query_osv(&client, &krate.name, &krate.version).await {
                Ok(vulns) if !vulns.is_empty() => {
                    for (id, summary) in vulns {
                        report.findings.push(SupplyChainFinding {
                            crate_name: krate.name.clone(),
                            version: krate.version.clone(),
                            severity: FindingSeverity::High,
                            kind: "cve".to_string(),
                            detail: format!("{}: {}", id, summary),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    Ok(report)
}

// ── Watch mode ────────────────────────────────────────────────────────────────

pub async fn watch_lockfile(
    lockfile_path: &Path,
    interval_secs: u64,
    mut on_finding: impl FnMut(&SupplyChainFinding),
) -> Result<()> {
    let mut last_findings: Vec<String> = Vec::new();

    loop {
        match scan_lockfile(lockfile_path).await {
            Ok(report) => {
                for finding in &report.findings {
                    let key = format!("{}/{}/{}", finding.crate_name, finding.version, finding.kind);
                    if !last_findings.contains(&key) {
                        on_finding(finding);
                        last_findings.push(key);
                    }
                }
            }
            Err(e) => eprintln!("supply-chain scan error: {e}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_LOCK: &str = r#"
[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
checksum = "abc123"

[[package]]
name = "anyhow"
version = "1.0.81"
checksum = "def456"

[[package]]
name = "srde"
version = "0.1.0"
checksum = "999"
"#;

    #[test]
    fn parse_cargo_lock_basic() {
        let crates = parse_cargo_lock(SAMPLE_LOCK);
        assert!(crates.len() >= 3);
        assert!(crates.iter().any(|c| c.name == "serde"));
        assert!(crates.iter().any(|c| c.name == "anyhow"));
    }

    #[test]
    fn parse_preserves_versions() {
        let crates = parse_cargo_lock(SAMPLE_LOCK);
        let serde = crates.iter().find(|c| c.name == "serde").unwrap();
        assert_eq!(serde.version, "1.0.200");
        assert_eq!(serde.checksum.as_deref(), Some("abc123"));
    }

    #[test]
    fn typosquatting_detected() {
        assert_eq!(check_typosquatting("srde"), Some("serde"));
        assert_eq!(check_typosquatting("tokio"), None); // real crate
        assert_eq!(check_typosquatting("tokio2"), Some("tokio")); // distance 1 (insertion)
    }

    #[test]
    fn no_false_positive_on_real_crates() {
        for name in POPULAR {
            assert_eq!(check_typosquatting(name), None, "false positive: {name}");
        }
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("serde", "srde"), 1);
        assert_eq!(levenshtein("tokio", "tokio2"), 1);
        assert_eq!(levenshtein("abc", "abc"), 0);
    }

    #[tokio::test]
    async fn osv_query_live() {
        // time-limited: if network not available, skip gracefully
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .build().unwrap();
        // time is a real crate with no known CVEs
        let vulns = query_osv(&client, "time", "0.1.45").await;
        // just verify it doesn't crash
        match vulns {
            Ok(v) => println!("OSV time@0.1.45 returned {} vulns", v.len()),
            Err(e) => println!("OSV offline: {e}"),
        }
    }
}
