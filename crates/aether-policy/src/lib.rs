//! Policy-as-code engine.
//!
//! Loads TOML policy rules and applies them to a list of findings.
//! Each rule can: block (treat as hard failure), warn, or ignore a finding
//! based on rule_id glob, severity, path glob, or CWE prefix.

pub use aether_deps_reach::{Finding, Severity};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Policy file schema ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub action: PolicyAction,
    #[serde(default)]
    pub match_rule_id: Option<String>,
    #[serde(default)]
    pub match_severity: Option<String>,
    #[serde(default)]
    pub match_cwe_prefix: Option<String>,
    #[serde(default)]
    pub match_path_prefix: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Block,
    Warn,
    Ignore,
}

// ── Matching ──────────────────────────────────────────────────────────────────

fn glob_match(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        value.ends_with(suffix)
    } else {
        pattern == value
    }
}

fn severity_matches(pattern: &str, finding: &Finding) -> bool {
    let sev_str = match finding.severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    };
    pattern.eq_ignore_ascii_case(sev_str)
}

fn rule_matches(rule: &PolicyRule, finding: &Finding) -> bool {
    if let Some(pattern) = &rule.match_rule_id {
        if !glob_match(pattern, &finding.rule_id) {
            return false;
        }
    }
    if let Some(sev) = &rule.match_severity {
        if !severity_matches(sev, finding) {
            return false;
        }
    }
    if let Some(cwe_prefix) = &rule.match_cwe_prefix {
        let finding_cwe = finding.cwe.as_deref().unwrap_or("");
        if !finding_cwe.starts_with(cwe_prefix.as_str()) {
            return false;
        }
    }
    if let Some(path_prefix) = &rule.match_path_prefix {
        if !finding.file.starts_with(path_prefix.as_str()) {
            return false;
        }
    }
    true
}

// ── Policy evaluation ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVerdict {
    pub finding: Finding,
    pub action: PolicyAction,
    pub matched_rule: Option<String>,
}

pub fn evaluate(findings: &[Finding], policy: &PolicyFile) -> Vec<PolicyVerdict> {
    findings
        .iter()
        .map(|f| {
            let matched = policy.rules.iter().find(|rule| rule_matches(rule, f));
            match matched {
                Some(rule) => PolicyVerdict {
                    finding: f.clone(),
                    action: rule.action.clone(),
                    matched_rule: Some(rule.id.clone()),
                },
                None => PolicyVerdict {
                    finding: f.clone(),
                    action: PolicyAction::Block, // default: block unmatched findings
                    matched_rule: None,
                },
            }
        })
        .collect()
}

pub fn load_policy(path: &Path) -> Result<PolicyFile> {
    let s = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&s)?)
}

pub fn load_policy_or_default(path: &Path) -> PolicyFile {
    load_policy(path).unwrap_or_else(|_| PolicyFile { rules: vec![] })
}

/// Summary counts by action.
pub struct PolicySummary {
    pub blocked: usize,
    pub warned: usize,
    pub ignored: usize,
}

pub fn summarise(verdicts: &[PolicyVerdict]) -> PolicySummary {
    PolicySummary {
        blocked: verdicts.iter().filter(|v| v.action == PolicyAction::Block).count(),
        warned: verdicts.iter().filter(|v| v.action == PolicyAction::Warn).count(),
        ignored: verdicts.iter().filter(|v| v.action == PolicyAction::Ignore).count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, sev: Severity, cwe: &str, file: &str) -> Finding {
        Finding {
            severity: sev,
            rule_id: rule.to_string(),
            cwe: Some(cwe.to_string()),
            file: file.to_string(),
            line: 1,
            evidence: "test".to_string(),
            remediation: "fix".to_string(),
        }
    }

    fn policy_with(rules: Vec<PolicyRule>) -> PolicyFile {
        PolicyFile { rules }
    }

    fn rule(id: &str, action: PolicyAction) -> PolicyRule {
        PolicyRule {
            id: id.to_string(),
            action,
            match_rule_id: None,
            match_severity: None,
            match_cwe_prefix: None,
            match_path_prefix: None,
            reason: None,
        }
    }

    #[test]
    fn no_rules_defaults_to_block() {
        let policy = policy_with(vec![]);
        let findings = vec![finding("T1", Severity::High, "CWE-78", "src/main.rs")];
        let verdicts = evaluate(&findings, &policy);
        assert_eq!(verdicts[0].action, PolicyAction::Block);
        assert!(verdicts[0].matched_rule.is_none());
    }

    #[test]
    fn exact_rule_id_match() {
        let mut r = rule("ignore-T1", PolicyAction::Ignore);
        r.match_rule_id = Some("TAINT-78".to_string());
        let policy = policy_with(vec![r]);
        let findings = vec![finding("TAINT-78", Severity::High, "CWE-78", "src/main.rs")];
        let verdicts = evaluate(&findings, &policy);
        assert_eq!(verdicts[0].action, PolicyAction::Ignore);
        assert_eq!(verdicts[0].matched_rule.as_deref(), Some("ignore-T1"));
    }

    #[test]
    fn glob_prefix_match() {
        let mut r = rule("warn-all-taint", PolicyAction::Warn);
        r.match_rule_id = Some("TAINT-*".to_string());
        let policy = policy_with(vec![r]);
        let findings = vec![
            finding("TAINT-78", Severity::High, "CWE-78", "src/main.rs"),
            finding("TAINT-89", Severity::High, "CWE-89", "src/lib.rs"),
        ];
        let verdicts = evaluate(&findings, &policy);
        assert_eq!(verdicts[0].action, PolicyAction::Warn);
        assert_eq!(verdicts[1].action, PolicyAction::Warn);
    }

    #[test]
    fn severity_match() {
        let mut r = rule("ignore-info", PolicyAction::Ignore);
        r.match_severity = Some("info".to_string());
        let policy = policy_with(vec![r]);
        let findings = vec![
            finding("R1", Severity::Info, "CWE-0", "src/main.rs"),
            finding("R2", Severity::High, "CWE-78", "src/main.rs"),
        ];
        let verdicts = evaluate(&findings, &policy);
        assert_eq!(verdicts[0].action, PolicyAction::Ignore);
        assert_eq!(verdicts[1].action, PolicyAction::Block); // no match → default block
    }

    #[test]
    fn cwe_prefix_match() {
        let mut r = rule("warn-cwe89", PolicyAction::Warn);
        r.match_cwe_prefix = Some("CWE-89".to_string());
        let policy = policy_with(vec![r]);
        let findings = vec![
            finding("SQL-1", Severity::High, "CWE-89", "src/db.rs"),
            finding("CMD-1", Severity::High, "CWE-78", "src/main.rs"),
        ];
        let verdicts = evaluate(&findings, &policy);
        assert_eq!(verdicts[0].action, PolicyAction::Warn);
        assert_eq!(verdicts[1].action, PolicyAction::Block);
    }

    #[test]
    fn path_prefix_match() {
        let mut r = rule("ignore-tests", PolicyAction::Ignore);
        r.match_path_prefix = Some("tests/".to_string());
        let policy = policy_with(vec![r]);
        let findings = vec![
            finding("T1", Severity::High, "CWE-78", "tests/integration.rs"),
            finding("T2", Severity::High, "CWE-78", "src/main.rs"),
        ];
        let verdicts = evaluate(&findings, &policy);
        assert_eq!(verdicts[0].action, PolicyAction::Ignore);
        assert_eq!(verdicts[1].action, PolicyAction::Block);
    }

    #[test]
    fn summarise_counts() {
        let policy = PolicyFile {
            rules: vec![
                PolicyRule {
                    id: "warn-medium".to_string(),
                    action: PolicyAction::Warn,
                    match_severity: Some("medium".to_string()),
                    match_rule_id: None,
                    match_cwe_prefix: None,
                    match_path_prefix: None,
                    reason: None,
                },
            ],
        };
        let findings = vec![
            finding("T1", Severity::Medium, "CWE-78", "src/a.rs"),
            finding("T2", Severity::High, "CWE-78", "src/b.rs"),
        ];
        let verdicts = evaluate(&findings, &policy);
        let s = summarise(&verdicts);
        assert_eq!(s.warned, 1);
        assert_eq!(s.blocked, 1);
        assert_eq!(s.ignored, 0);
    }

    #[test]
    fn policy_toml_roundtrip() {
        let toml_str = r#"
[[rules]]
id = "ignore-tests"
action = "ignore"
match_path_prefix = "tests/"
reason = "test code excluded"
"#;
        let policy: PolicyFile = toml::from_str(toml_str).unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].action, PolicyAction::Ignore);
        assert_eq!(policy.rules[0].match_path_prefix.as_deref(), Some("tests/"));
    }
}
