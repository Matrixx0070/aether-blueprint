//! Cross-model consensus triage with SQLite verdict cache.
//!
//! For each finding, queries N Ollama models with a structured prompt.
//! A finding is confirmed only when ≥ 2 models agree `is_real` with
//! confidence ≥ 0.7. Others move to the `suppressed` list.
//! Verdicts are cached in SQLite keyed by (rule_id + sha2(evidence)).

pub use aether_deps_reach::{Finding, Severity};

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageConfig {
    pub models: Vec<String>,
    pub ollama_url: String,
    pub min_confidence: f32,
    pub min_agreement: usize,
    pub cache_path: PathBuf,
    pub timeout_secs: u64,
}

impl Default for TriageConfig {
    fn default() -> Self {
        TriageConfig {
            models: vec![
                "glm-5.2:cloud".to_string(),
                "kimi-k2.7-code:cloud".to_string(),
            ],
            ollama_url: "http://localhost:11434".to_string(),
            min_confidence: 0.7,
            min_agreement: 2,
            cache_path: PathBuf::from("/tmp/aether-triage-cache.db"),
            timeout_secs: 30,
        }
    }
}

// ── Model verdict ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVerdict {
    pub model: String,
    pub is_real: bool,
    pub confidence: f32,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub finding: Finding,
    pub verdicts: Vec<ModelVerdict>,
    pub agreement_count: usize,
    pub confirmed: bool,
}

#[derive(Debug, Default)]
pub struct TriageReport {
    pub confirmed: Vec<TriageResult>,
    pub suppressed: Vec<TriageResult>,
}

// ── SQLite cache ──────────────────────────────────────────────────────────────

fn evidence_hash(finding: &Finding) -> String {
    let mut h = Sha256::new();
    h.update(finding.rule_id.as_bytes());
    h.update(finding.evidence.as_bytes());
    hex::encode(h.finalize())
}

fn open_cache(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS verdicts (
            cache_key TEXT PRIMARY KEY,
            payload   TEXT NOT NULL,
            created   INTEGER NOT NULL
        );",
    )?;
    Ok(conn)
}

fn cache_get(conn: &Connection, key: &str) -> Option<Vec<ModelVerdict>> {
    conn.query_row(
        "SELECT payload FROM verdicts WHERE cache_key = ?1",
        params![key],
        |row| row.get::<_, String>(0),
    )
    .ok()
    .and_then(|s| serde_json::from_str(&s).ok())
}

fn cache_put(conn: &Connection, key: &str, verdicts: &[ModelVerdict]) {
    let payload = serde_json::to_string(verdicts).unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = conn.execute(
        "INSERT OR REPLACE INTO verdicts (cache_key, payload, created) VALUES (?1, ?2, ?3)",
        params![key, payload, now],
    );
}

// ── Ollama call ───────────────────────────────────────────────────────────────

fn query_model(
    ollama_url: &str,
    model: &str,
    finding: &Finding,
    timeout_secs: u64,
) -> Result<ModelVerdict> {
    let prompt = format!(
        r#"You are a security code auditor. Evaluate whether this finding is a REAL vulnerability:

Rule: {}
File: {} (line {})
Severity: {:?}
CWE: {:?}
Evidence: {}

Respond with ONLY valid JSON (no markdown, no explanation outside JSON):
{{"is_real": true/false, "confidence": 0.0-1.0, "reasoning": "one sentence"}}"#,
        finding.rule_id,
        finding.file,
        finding.line,
        finding.severity,
        finding.cwe,
        finding.evidence,
    );

    let body = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": false
    });

    let response = ureq::post(&format!("{}/api/chat", ollama_url))
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .send_json(&body)
        .context("Ollama request failed")?;

    let val: serde_json::Value = response.into_json()?;
    let content = val["message"]["content"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_string();

    // Strip potential markdown fences
    let json_str = content
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let parsed: serde_json::Value = serde_json::from_str(json_str)
        .context("Could not parse model JSON response")?;

    Ok(ModelVerdict {
        model: model.to_string(),
        is_real: parsed["is_real"].as_bool().unwrap_or(false),
        confidence: parsed["confidence"].as_f64().unwrap_or(0.0) as f32,
        reasoning: parsed["reasoning"]
            .as_str()
            .unwrap_or("no reasoning")
            .to_string(),
    })
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn triage_findings(findings: &[Finding], config: &TriageConfig) -> Result<TriageReport> {
    let conn = open_cache(&config.cache_path)?;
    let mut report = TriageReport::default();

    for finding in findings {
        let key = evidence_hash(finding);
        let verdicts = if let Some(cached) = cache_get(&conn, &key) {
            cached
        } else {
            let mut vs = Vec::new();
            for model in &config.models {
                match query_model(&config.ollama_url, model, finding, config.timeout_secs) {
                    Ok(v) => vs.push(v),
                    Err(e) => {
                        eprintln!("[aether-triage] model {} error: {}", model, e);
                        // push a low-confidence non-real verdict so we don't block on failures
                        vs.push(ModelVerdict {
                            model: model.clone(),
                            is_real: false,
                            confidence: 0.0,
                            reasoning: format!("model error: {}", e),
                        });
                    }
                }
            }
            cache_put(&conn, &key, &vs);
            vs
        };

        let agreement_count = verdicts
            .iter()
            .filter(|v| v.is_real && v.confidence >= config.min_confidence)
            .count();

        let confirmed = agreement_count >= config.min_agreement;
        let result = TriageResult {
            finding: finding.clone(),
            verdicts,
            agreement_count,
            confirmed,
        };

        if confirmed {
            report.confirmed.push(result);
        } else {
            report.suppressed.push(result);
        }
    }

    Ok(report)
}

/// Load findings from a JSON file produced by any other aether crate.
pub fn load_findings_json(path: &Path) -> Result<Vec<Finding>> {
    let s = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&s)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_finding(rule_id: &str) -> Finding {
        Finding {
            severity: Severity::High,
            rule_id: rule_id.to_string(),
            cwe: Some("CWE-78".to_string()),
            file: "src/main.rs".to_string(),
            line: 42,
            evidence: "env var flows to Command::new".to_string(),
            remediation: "use allowlist".to_string(),
        }
    }

    #[test]
    fn evidence_hash_stable() {
        let f = make_finding("TAINT-78");
        let h1 = evidence_hash(&f);
        let h2 = evidence_hash(&f);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // hex sha256
    }

    #[test]
    fn evidence_hash_differs_by_rule() {
        let f1 = make_finding("TAINT-78");
        let f2 = make_finding("TAINT-89");
        assert_ne!(evidence_hash(&f1), evidence_hash(&f2));
    }

    #[test]
    fn cache_roundtrip() {
        let tmp = tempfile_path();
        let conn = open_cache(&tmp).unwrap();
        let verdicts = vec![ModelVerdict {
            model: "glm-5.2:cloud".to_string(),
            is_real: true,
            confidence: 0.9,
            reasoning: "obvious injection".to_string(),
        }];
        cache_put(&conn, "test_key", &verdicts);
        let retrieved = cache_get(&conn, "test_key").unwrap();
        assert_eq!(retrieved.len(), 1);
        assert!(retrieved[0].is_real);
        assert!((retrieved[0].confidence - 0.9).abs() < 0.01);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn cache_miss_returns_none() {
        let tmp = tempfile_path();
        let conn = open_cache(&tmp).unwrap();
        assert!(cache_get(&conn, "nonexistent_key").is_none());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn triage_all_suppressed_when_no_ollama() {
        // Without Ollama running, all verdicts fail → confidence 0 → suppressed
        let findings = vec![make_finding("TAINT-78")];
        let config = TriageConfig {
            models: vec!["nonexistent-model:test".to_string()],
            ollama_url: "http://127.0.0.1:19999".to_string(), // unreachable
            min_confidence: 0.7,
            min_agreement: 2,
            cache_path: tempfile_path(),
            timeout_secs: 1,
        };
        let report = triage_findings(&findings, &config).unwrap();
        // Errors push low-confidence false verdicts → suppressed
        assert_eq!(report.confirmed.len(), 0);
        assert_eq!(report.suppressed.len(), 1);
        let _ = std::fs::remove_file(&config.cache_path);
    }

    #[test]
    fn triage_confirmed_when_verdicts_agree() {
        let tmp = tempfile_path();
        let conn = open_cache(&tmp).unwrap();
        let f = make_finding("TAINT-89");
        let key = evidence_hash(&f);
        // Pre-populate cache with two agreeing verdicts
        let verdicts = vec![
            ModelVerdict {
                model: "m1".to_string(),
                is_real: true,
                confidence: 0.95,
                reasoning: "test".to_string(),
            },
            ModelVerdict {
                model: "m2".to_string(),
                is_real: true,
                confidence: 0.85,
                reasoning: "test".to_string(),
            },
        ];
        cache_put(&conn, &key, &verdicts);
        drop(conn);

        let config = TriageConfig {
            models: vec!["m1".to_string(), "m2".to_string()],
            ollama_url: "http://127.0.0.1:19999".to_string(),
            min_confidence: 0.7,
            min_agreement: 2,
            cache_path: tmp.clone(),
            timeout_secs: 1,
        };
        let report = triage_findings(&[f], &config).unwrap();
        assert_eq!(report.confirmed.len(), 1);
        assert_eq!(report.suppressed.len(), 0);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn triage_suppressed_when_one_agrees() {
        let tmp = tempfile_path();
        let conn = open_cache(&tmp).unwrap();
        let f = make_finding("TAINT-22");
        let key = evidence_hash(&f);
        // Only one model agrees
        let verdicts = vec![
            ModelVerdict {
                model: "m1".to_string(),
                is_real: true,
                confidence: 0.9,
                reasoning: "real".to_string(),
            },
            ModelVerdict {
                model: "m2".to_string(),
                is_real: false,
                confidence: 0.8,
                reasoning: "false positive".to_string(),
            },
        ];
        cache_put(&conn, &key, &verdicts);
        drop(conn);

        let config = TriageConfig {
            min_agreement: 2,
            models: vec!["m1".to_string(), "m2".to_string()],
            ollama_url: "http://127.0.0.1:19999".to_string(),
            min_confidence: 0.7,
            cache_path: tmp.clone(),
            timeout_secs: 1,
        };
        let report = triage_findings(&[f], &config).unwrap();
        assert_eq!(report.suppressed.len(), 1);
        assert_eq!(report.confirmed.len(), 0);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_findings_json_roundtrip() {
        let findings = vec![make_finding("TEST-01")];
        let json = serde_json::to_string(&findings).unwrap();
        let tmp = tempfile_path();
        std::fs::write(&tmp, &json).unwrap();
        let loaded = load_findings_json(&tmp).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].rule_id, "TEST-01");
        let _ = std::fs::remove_file(&tmp);
    }

    fn tempfile_path() -> PathBuf {
        PathBuf::from(format!(
            "/tmp/aether_triage_test_{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }
}
