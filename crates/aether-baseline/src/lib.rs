//! Finding baseline ratchet.
//!
//! Stores accepted findings in SQLite keyed by (rule_id + sha2(evidence)).
//! On each run, new findings not in the baseline are flagged as regressions.
//! Accepted findings can be added to the baseline explicitly (via `accept`).
//! Severity threshold: only alert on findings at or above the configured level.

pub use aether_deps_reach::{Finding, Severity};

use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineConfig {
    pub db_path: PathBuf,
    pub min_severity: Severity,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        BaselineConfig {
            db_path: PathBuf::from("/tmp/aether-baseline.db"),
            min_severity: Severity::Medium,
        }
    }
}

// ── DB helpers ────────────────────────────────────────────────────────────────

fn open_db(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS accepted (
            fingerprint TEXT PRIMARY KEY,
            rule_id     TEXT NOT NULL,
            file        TEXT NOT NULL,
            evidence    TEXT NOT NULL,
            accepted_at INTEGER NOT NULL
        );",
    )?;
    Ok(conn)
}

fn fingerprint(f: &Finding) -> String {
    let mut h = Sha256::new();
    h.update(f.rule_id.as_bytes());
    h.update(b"|");
    h.update(f.evidence.as_bytes());
    hex::encode(h.finalize())
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

// ── Baseline operations ───────────────────────────────────────────────────────

pub fn accept_findings(findings: &[Finding], config: &BaselineConfig) -> Result<usize> {
    let conn = open_db(&config.db_path)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut added = 0usize;
    for f in findings {
        let fp = fingerprint(f);
        let rows = conn.execute(
            "INSERT OR IGNORE INTO accepted (fingerprint, rule_id, file, evidence, accepted_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![fp, f.rule_id, f.file, f.evidence, now],
        )?;
        added += rows;
    }
    Ok(added)
}

pub fn is_accepted(finding: &Finding, conn: &Connection) -> bool {
    let fp = fingerprint(finding);
    conn.query_row(
        "SELECT 1 FROM accepted WHERE fingerprint = ?1",
        params![fp],
        |_| Ok(true),
    )
    .unwrap_or(false)
}

pub fn accepted_count(conn: &Connection) -> usize {
    conn.query_row("SELECT COUNT(*) FROM accepted", [], |row| {
        row.get::<_, i64>(0)
    })
    .unwrap_or(0) as usize
}

// ── Ratchet check ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct RatchetResult {
    pub regressions: Vec<Finding>,
    pub accepted: Vec<Finding>,
    pub below_threshold: Vec<Finding>,
}

pub fn ratchet(findings: &[Finding], config: &BaselineConfig) -> Result<RatchetResult> {
    let conn = open_db(&config.db_path)?;
    let mut result = RatchetResult::default();
    let min_rank = severity_rank(&config.min_severity);

    for f in findings {
        if severity_rank(&f.severity) < min_rank {
            result.below_threshold.push(f.clone());
        } else if is_accepted(f, &conn) {
            result.accepted.push(f.clone());
        } else {
            result.regressions.push(f.clone());
        }
    }

    Ok(result)
}

/// List all accepted fingerprints (for inspection).
pub fn list_accepted(config: &BaselineConfig) -> Result<Vec<(String, String, String)>> {
    let conn = open_db(&config.db_path)?;
    let mut stmt = conn.prepare("SELECT fingerprint, rule_id, file FROM accepted ORDER BY accepted_at")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    Ok(rows.flatten().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_db() -> PathBuf {
        PathBuf::from(format!(
            "/tmp/aether_baseline_test_{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    fn finding(rule: &str, sev: Severity) -> Finding {
        Finding {
            severity: sev,
            rule_id: rule.to_string(),
            cwe: Some("CWE-78".to_string()),
            file: "src/main.rs".to_string(),
            line: 10,
            evidence: format!("evidence for {}", rule),
            remediation: "fix it".to_string(),
        }
    }

    #[test]
    fn accept_and_ratchet_no_regressions() {
        let db = tmp_db();
        let config = BaselineConfig { db_path: db.clone(), min_severity: Severity::Medium };
        let f = finding("T1", Severity::High);
        accept_findings(&[f.clone()], &config).unwrap();
        let result = ratchet(&[f], &config).unwrap();
        assert!(result.regressions.is_empty());
        assert_eq!(result.accepted.len(), 1);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn new_finding_is_regression() {
        let db = tmp_db();
        let config = BaselineConfig { db_path: db.clone(), min_severity: Severity::Medium };
        let f = finding("T2", Severity::High);
        let result = ratchet(&[f], &config).unwrap();
        assert_eq!(result.regressions.len(), 1);
        assert!(result.accepted.is_empty());
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn below_threshold_not_in_regressions() {
        let db = tmp_db();
        let config = BaselineConfig { db_path: db.clone(), min_severity: Severity::High };
        let f = finding("T3", Severity::Low);
        let result = ratchet(&[f], &config).unwrap();
        assert!(result.regressions.is_empty());
        assert_eq!(result.below_threshold.len(), 1);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn accept_idempotent() {
        let db = tmp_db();
        let config = BaselineConfig { db_path: db.clone(), min_severity: Severity::Medium };
        let f = finding("T4", Severity::High);
        let n1 = accept_findings(&[f.clone()], &config).unwrap();
        let n2 = accept_findings(&[f.clone()], &config).unwrap();
        assert_eq!(n1, 1);
        assert_eq!(n2, 0); // INSERT OR IGNORE
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn fingerprint_stable() {
        let f = finding("T5", Severity::High);
        let fp1 = fingerprint(&f);
        let fp2 = fingerprint(&f);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64);
    }

    #[test]
    fn fingerprint_differs_by_rule() {
        let f1 = finding("T6a", Severity::High);
        let f2 = finding("T6b", Severity::High);
        assert_ne!(fingerprint(&f1), fingerprint(&f2));
    }

    #[test]
    fn list_accepted_returns_entries() {
        let db = tmp_db();
        let config = BaselineConfig { db_path: db.clone(), min_severity: Severity::Medium };
        let f = finding("T7", Severity::High);
        accept_findings(&[f], &config).unwrap();
        let entries = list_accepted(&config).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, "T7");
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn severity_rank_order() {
        assert!(severity_rank(&Severity::Info) < severity_rank(&Severity::Low));
        assert!(severity_rank(&Severity::Low) < severity_rank(&Severity::Medium));
        assert!(severity_rank(&Severity::Medium) < severity_rank(&Severity::High));
        assert!(severity_rank(&Severity::High) < severity_rank(&Severity::Critical));
    }
}
