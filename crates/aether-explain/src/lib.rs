//! Exploit narrative generator.
//!
//! For each finding, queries an Ollama LLM for a structured attack story:
//! attack vector, step-by-step exploitation, blast radius, and remediation.
//! Falls back to a deterministic template when Ollama is unavailable.

pub use aether_deps_reach::{Finding, Severity};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainConfig {
    pub model: String,
    pub ollama_url: String,
    pub timeout_secs: u64,
    pub audience: String,
}

impl Default for ExplainConfig {
    fn default() -> Self {
        ExplainConfig {
            model: "glm-5.2:cloud".to_string(),
            ollama_url: "http://localhost:11434".to_string(),
            timeout_secs: 60,
            audience: "developer".to_string(),
        }
    }
}

// ── Explanation output ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Explanation {
    pub finding: Finding,
    pub attack_vector: String,
    pub steps: Vec<String>,
    pub blast_radius: String,
    pub remediation_detail: String,
    pub source: ExplainSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExplainSource {
    Llm { model: String },
    Template,
}

// ── Template-based fallback ───────────────────────────────────────────────────

fn template_explain(finding: &Finding) -> Explanation {
    let cwe = finding.cwe.as_deref().unwrap_or("CWE-0");

    let (attack_vector, steps, blast_radius) = match cwe {
        "CWE-78" => (
            "OS Command Injection via user-controlled input".to_string(),
            vec![
                "Attacker supplies malicious input (env var, HTTP param, CLI arg)".to_string(),
                format!("Input reaches {} at line {}", finding.file, finding.line),
                "Shell interprets injected metacharacters as commands".to_string(),
                "Attacker achieves arbitrary code execution".to_string(),
            ],
            "Full server compromise, data exfiltration, lateral movement".to_string(),
        ),
        "CWE-89" => (
            "SQL Injection via unsanitized string interpolation".to_string(),
            vec![
                "Attacker crafts payload with SQL metacharacters (', --, ;)".to_string(),
                format!("Payload reaches SQL execution at {} line {}", finding.file, finding.line),
                "Database interprets injected SQL".to_string(),
                "Attacker reads/modifies database or escalates to RCE".to_string(),
            ],
            "Database compromise, authentication bypass, data theft".to_string(),
        ),
        "CWE-22" => (
            "Path Traversal via user-controlled file path".to_string(),
            vec![
                "Attacker supplies path with '../' sequences".to_string(),
                format!("Path reaches file operation at {} line {}", finding.file, finding.line),
                "Application reads/writes files outside intended directory".to_string(),
                "Attacker reads sensitive config/keys or overwrites system files".to_string(),
            ],
            "Sensitive file disclosure, configuration overwrite, RCE via log poisoning".to_string(),
        ),
        _ => (
            format!("Security weakness {} in {}", cwe, finding.file),
            vec![
                "Attacker provides malicious input to the vulnerable function".to_string(),
                format!("Input processed at line {} without proper validation", finding.line),
                "Security control bypassed".to_string(),
            ],
            "Impact depends on context — review evidence and remediation".to_string(),
        ),
    };

    Explanation {
        finding: finding.clone(),
        attack_vector,
        steps,
        blast_radius,
        remediation_detail: finding.remediation.clone(),
        source: ExplainSource::Template,
    }
}

// ── LLM explanation ───────────────────────────────────────────────────────────

fn request_explanation(
    ollama_url: &str,
    model: &str,
    finding: &Finding,
    audience: &str,
    timeout_secs: u64,
) -> Result<Explanation> {
    let prompt = format!(
        r#"You are a security engineer explaining a vulnerability to a {audience}.

Finding:
  Rule: {rule_id}
  CWE: {cwe}
  File: {file} line {line}
  Severity: {severity:?}
  Evidence: {evidence}
  Remediation: {remediation}

Explain how an attacker would exploit this. Reply with ONLY valid JSON:
{{
  "attack_vector": "one-line description of the attack surface",
  "steps": ["step 1", "step 2", "step 3"],
  "blast_radius": "impact if successfully exploited",
  "remediation_detail": "specific fix guidance"
}}"#,
        audience = audience,
        rule_id = finding.rule_id,
        cwe = finding.cwe.as_deref().unwrap_or("unknown"),
        file = finding.file,
        line = finding.line,
        severity = finding.severity,
        evidence = finding.evidence,
        remediation = finding.remediation,
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
        .context("Cannot parse LLM explanation JSON")?;

    let steps: Vec<String> = parsed["steps"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(Explanation {
        finding: finding.clone(),
        attack_vector: parsed["attack_vector"].as_str().unwrap_or("").to_string(),
        steps,
        blast_radius: parsed["blast_radius"].as_str().unwrap_or("").to_string(),
        remediation_detail: parsed["remediation_detail"]
            .as_str()
            .unwrap_or(&finding.remediation)
            .to_string(),
        source: ExplainSource::Llm { model: model.to_string() },
    })
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn explain(finding: &Finding, config: &ExplainConfig) -> Explanation {
    match request_explanation(
        &config.ollama_url,
        &config.model,
        finding,
        &config.audience,
        config.timeout_secs,
    ) {
        Ok(exp) => exp,
        Err(e) => {
            eprintln!("[aether-explain] LLM failed ({}), using template", e);
            template_explain(finding)
        }
    }
}

pub fn explain_all(findings: &[Finding], config: &ExplainConfig) -> Vec<Explanation> {
    findings.iter().map(|f| explain(f, config)).collect()
}

pub fn explanation_to_markdown(exp: &Explanation) -> String {
    let steps = exp
        .steps
        .iter()
        .enumerate()
        .map(|(i, s)| format!("{}. {}", i + 1, s))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "## {} — {}\n\n**Attack Vector:** {}\n\n**Exploitation Steps:**\n{}\n\n**Blast Radius:** {}\n\n**Remediation:** {}\n",
        exp.finding.rule_id,
        exp.finding.cwe.as_deref().unwrap_or(""),
        exp.attack_vector,
        steps,
        exp.blast_radius,
        exp.remediation_detail,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, cwe: &str) -> Finding {
        Finding {
            severity: Severity::High,
            rule_id: rule.to_string(),
            cwe: Some(cwe.to_string()),
            file: "src/main.rs".to_string(),
            line: 42,
            evidence: "taint flow detected".to_string(),
            remediation: "validate input".to_string(),
        }
    }

    #[test]
    fn template_cwe78_has_command_injection() {
        let exp = template_explain(&finding("TAINT-78", "CWE-78"));
        assert!(exp.attack_vector.contains("Command Injection") || exp.attack_vector.contains("OS Command"));
        assert!(!exp.steps.is_empty());
        assert_eq!(matches!(exp.source, ExplainSource::Template), true);
    }

    #[test]
    fn template_cwe89_has_sql() {
        let exp = template_explain(&finding("TAINT-89", "CWE-89"));
        assert!(exp.attack_vector.to_lowercase().contains("sql"));
    }

    #[test]
    fn template_cwe22_has_path_traversal() {
        let exp = template_explain(&finding("TAINT-22", "CWE-22"));
        assert!(exp.attack_vector.contains("Path Traversal") || exp.attack_vector.contains("Traversal"));
    }

    #[test]
    fn explain_no_ollama_falls_back_to_template() {
        let f = finding("TAINT-78", "CWE-78");
        let config = ExplainConfig {
            ollama_url: "http://127.0.0.1:19999".to_string(),
            timeout_secs: 1,
            ..ExplainConfig::default()
        };
        let exp = explain(&f, &config);
        // Must produce an explanation regardless
        assert!(!exp.attack_vector.is_empty());
        assert!(!exp.steps.is_empty());
    }

    #[test]
    fn explain_all_empty() {
        let config = ExplainConfig::default();
        let exps = explain_all(&[], &config);
        assert!(exps.is_empty());
    }

    #[test]
    fn explanation_to_markdown_contains_sections() {
        let exp = template_explain(&finding("TAINT-78", "CWE-78"));
        let md = explanation_to_markdown(&exp);
        assert!(md.contains("**Attack Vector:**"));
        assert!(md.contains("**Exploitation Steps:**"));
        assert!(md.contains("**Blast Radius:**"));
        assert!(md.contains("**Remediation:**"));
    }

    #[test]
    fn template_unknown_cwe_produces_generic() {
        let exp = template_explain(&finding("CUSTOM-1", "CWE-999"));
        assert!(!exp.attack_vector.is_empty());
        assert!(!exp.steps.is_empty());
    }
}
