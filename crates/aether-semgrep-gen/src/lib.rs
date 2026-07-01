//! LLM-powered semgrep rule generator.
//!
//! Takes aether findings and generates semgrep YAML rules that would
//! catch the same pattern in future code reviews. Uses Ollama for generation.
//! Output is a YAML string suitable for `semgrep --config <rule.yaml>`.

pub use aether_deps_reach::{Finding, Severity};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepGenConfig {
    pub model: String,
    pub ollama_url: String,
    pub timeout_secs: u64,
    pub language: String,
}

impl Default for SemgrepGenConfig {
    fn default() -> Self {
        SemgrepGenConfig {
            model: "glm-5.2:cloud".to_string(),
            ollama_url: "http://localhost:11434".to_string(),
            timeout_secs: 60,
            language: "rust".to_string(),
        }
    }
}

// ── Generated rule ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedRule {
    pub finding: Finding,
    pub rule_id: String,
    pub yaml: String,
    pub llm_reasoning: String,
}

// ── Template-based rule generation (fallback) ─────────────────────────────────

fn template_rule(finding: &Finding, language: &str) -> String {
    let rule_id = format!(
        "aether-generated-{}",
        finding.rule_id.to_lowercase().replace('-', "_")
    );
    let message = format!(
        "Security finding: {} — {}",
        finding.rule_id, finding.evidence
    );
    let cwe_tag = finding
        .cwe
        .as_deref()
        .unwrap_or("CWE-0")
        .to_lowercase()
        .replace('-', ":");
    let severity = match finding.severity {
        Severity::Critical | Severity::High => "ERROR",
        Severity::Medium => "WARNING",
        _ => "INFO",
    };

    format!(
        r#"rules:
  - id: {rule_id}
    message: |
      {message}
    severity: {severity}
    languages: [{language}]
    metadata:
      cwe: {cwe_tag}
      source: aether-blueprint
      remediation: |
        {remediation}
    # TODO: replace this pattern with the actual pattern from the finding
    pattern: |
      std::env::var(...)
"#,
        rule_id = rule_id,
        message = message,
        severity = severity,
        language = language,
        cwe_tag = cwe_tag,
        remediation = finding.remediation.replace('\n', "\n        "),
    )
}

// ── LLM rule generation ───────────────────────────────────────────────────────

fn request_rule(
    ollama_url: &str,
    model: &str,
    finding: &Finding,
    language: &str,
    timeout_secs: u64,
) -> Result<(String, String)> {
    let prompt = format!(
        r#"You are a semgrep rule author. Generate a semgrep YAML rule to detect this vulnerability pattern.

Finding:
  Rule ID: {}
  Language: {}
  File: {} line {}
  CWE: {:?}
  Evidence: {}
  Remediation: {}

Requirements:
- Use semgrep pattern syntax (pattern, pattern-either, pattern-inside, metavariables)
- Set severity based on CWE
- Include metadata with cwe, confidence, references
- The rule must be valid semgrep YAML

Reply with ONLY valid JSON (no markdown outside JSON):
{{"reasoning": "...", "yaml": "...full semgrep YAML rule..."}}"#,
        finding.rule_id,
        language,
        finding.file,
        finding.line,
        finding.cwe,
        finding.evidence,
        finding.remediation,
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

    let json_str = content
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let parsed: serde_json::Value = serde_json::from_str(json_str)
        .context("Cannot parse LLM response JSON")?;

    let reasoning = parsed["reasoning"].as_str().unwrap_or("").to_string();
    let yaml = parsed["yaml"]
        .as_str()
        .context("Missing yaml in LLM response")?
        .to_string();

    Ok((yaml, reasoning))
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn generate_rule(finding: &Finding, config: &SemgrepGenConfig) -> GeneratedRule {
    let rule_id = format!(
        "aether-{}",
        finding.rule_id.to_lowercase().replace('-', "_")
    );

    match request_rule(
        &config.ollama_url,
        &config.model,
        finding,
        &config.language,
        config.timeout_secs,
    ) {
        Ok((yaml, reasoning)) => GeneratedRule {
            finding: finding.clone(),
            rule_id,
            yaml,
            llm_reasoning: reasoning,
        },
        Err(e) => {
            eprintln!("[aether-semgrep-gen] LLM failed ({}), using template", e);
            let yaml = template_rule(finding, &config.language);
            GeneratedRule {
                finding: finding.clone(),
                rule_id,
                yaml,
                llm_reasoning: format!("template fallback: {}", e),
            }
        }
    }
}

pub fn generate_rules(findings: &[Finding], config: &SemgrepGenConfig) -> Vec<GeneratedRule> {
    findings.iter().map(|f| generate_rule(f, config)).collect()
}

/// Combine multiple generated rules into a single semgrep YAML file.
pub fn combine_rules(rules: &[GeneratedRule]) -> String {
    if rules.is_empty() {
        return "rules: []\n".to_string();
    }
    // Each rule already starts with "rules:\n  - id: ..."
    // Extract the list items and combine under one "rules:" header
    let items: Vec<String> = rules
        .iter()
        .map(|r| {
            r.yaml
                .lines()
                .skip(1) // skip "rules:"
                .collect::<Vec<_>>()
                .join("\n")
        })
        .collect();
    format!("rules:\n{}", items.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(rule: &str, cwe: &str) -> Finding {
        Finding {
            severity: Severity::High,
            rule_id: rule.to_string(),
            cwe: Some(cwe.to_string()),
            file: "src/main.rs".to_string(),
            line: 10,
            evidence: "env var flows to Command::new".to_string(),
            remediation: "use shell-escape or allowlist".to_string(),
        }
    }

    #[test]
    fn template_rule_contains_rule_id() {
        let f = make_finding("TAINT-78", "CWE-78");
        let yaml = template_rule(&f, "rust");
        assert!(yaml.contains("aether-generated-taint_78"));
        assert!(yaml.contains("cwe:78"));
    }

    #[test]
    fn template_rule_severity_error_for_high() {
        let f = make_finding("TAINT-78", "CWE-78");
        let yaml = template_rule(&f, "rust");
        assert!(yaml.contains("severity: ERROR"));
    }

    #[test]
    fn template_rule_severity_warning_for_medium() {
        let f = Finding {
            severity: Severity::Medium,
            ..make_finding("MED-1", "CWE-22")
        };
        let yaml = template_rule(&f, "rust");
        assert!(yaml.contains("severity: WARNING"));
    }

    #[test]
    fn generate_rule_no_ollama_falls_back_to_template() {
        let f = make_finding("TAINT-89", "CWE-89");
        let config = SemgrepGenConfig {
            ollama_url: "http://127.0.0.1:19999".to_string(),
            timeout_secs: 1,
            ..SemgrepGenConfig::default()
        };
        let rule = generate_rule(&f, &config);
        // Must produce non-empty yaml regardless
        assert!(!rule.yaml.is_empty());
        assert!(rule.yaml.contains("rules:"));
    }

    #[test]
    fn generate_rules_empty_returns_empty() {
        let config = SemgrepGenConfig::default();
        let rules = generate_rules(&[], &config);
        assert!(rules.is_empty());
    }

    #[test]
    fn combine_rules_empty() {
        let combined = combine_rules(&[]);
        assert_eq!(combined, "rules: []\n");
    }

    #[test]
    fn combine_rules_single() {
        let f = make_finding("T1", "CWE-78");
        let config = SemgrepGenConfig {
            ollama_url: "http://127.0.0.1:19999".to_string(),
            timeout_secs: 1,
            ..SemgrepGenConfig::default()
        };
        let rule = generate_rule(&f, &config);
        let combined = combine_rules(&[rule]);
        assert!(combined.starts_with("rules:"));
    }

    #[test]
    fn rule_id_format() {
        let f = make_finding("TAINT-78", "CWE-78");
        let config = SemgrepGenConfig {
            ollama_url: "http://127.0.0.1:19999".to_string(),
            timeout_secs: 1,
            ..SemgrepGenConfig::default()
        };
        let rule = generate_rule(&f, &config);
        assert!(rule.rule_id.starts_with("aether-"));
    }
}
