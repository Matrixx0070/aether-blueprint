//! Compliance report generator.
//!
//! Produces HTML and JSON reports from a collection of findings,
//! grouped by severity and CWE, with summary statistics.
//! Designed to output OWASP-style compliance reports.

pub use aether_deps_reach::{Finding, Severity};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ── Report structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub by_cwe: HashMap<String, usize>,
    pub by_rule: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub title: String,
    pub generated_at: String,
    pub summary: ReportSummary,
    pub findings: Vec<Finding>,
}

// ── Builder ───────────────────────────────────────────────────────────────────

fn timestamp() -> String {
    // Without chrono (not in this crate's deps), use system time
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Format as ISO-8601-ish: YYYY-MM-DDTHH:MM:SSZ
    let s = secs;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = (s / 3600) % 24;
    let days = s / 86400;
    // Simplified date (accurate enough for reports — not a calendar library)
    let years_since_epoch = days / 365;
    let year = 1970 + years_since_epoch;
    let day_of_year = days % 365;
    let month = day_of_year / 30 + 1;
    let day = day_of_year % 30 + 1;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month.min(12), day.min(31), hour, min, sec)
}

pub fn build_report(title: &str, findings: &[Finding]) -> Report {
    let mut by_cwe: HashMap<String, usize> = HashMap::new();
    let mut by_rule: HashMap<String, usize> = HashMap::new();
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut info = 0usize;

    for f in findings {
        match f.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
        *by_cwe
            .entry(f.cwe.clone().unwrap_or_else(|| "unknown".to_string()))
            .or_default() += 1;
        *by_rule.entry(f.rule_id.clone()).or_default() += 1;
    }

    Report {
        title: title.to_string(),
        generated_at: timestamp(),
        summary: ReportSummary {
            total: findings.len(),
            critical,
            high,
            medium,
            low,
            info,
            by_cwe,
            by_rule,
        },
        findings: findings.to_vec(),
    }
}

// ── JSON output ───────────────────────────────────────────────────────────────

pub fn to_json(report: &Report) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

pub fn write_json(report: &Report, path: &Path) -> anyhow::Result<()> {
    let json = to_json(report)?;
    std::fs::write(path, json)?;
    Ok(())
}

// ── HTML output ───────────────────────────────────────────────────────────────

pub fn to_html(report: &Report) -> String {
    let severity_class = |s: &Severity| match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    };

    let rows: String = report
        .findings
        .iter()
        .map(|f| {
            format!(
                "<tr class=\"sev-{sev}\"><td>{rule}</td><td class=\"sev-{sev}\">{severity:?}</td>\
                 <td>{cwe}</td><td>{file}:{line}</td><td>{evidence}</td></tr>\n",
                sev = severity_class(&f.severity),
                rule = html_escape(&f.rule_id),
                severity = f.severity,
                cwe = html_escape(f.cwe.as_deref().unwrap_or("")),
                file = html_escape(&f.file),
                line = f.line,
                evidence = html_escape(&f.evidence),
            )
        })
        .collect();

    let cwe_rows: String = {
        let mut pairs: Vec<_> = report.summary.by_cwe.iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(a.1));
        pairs
            .iter()
            .map(|(cwe, count)| format!("<tr><td>{}</td><td>{}</td></tr>\n", html_escape(cwe), count))
            .collect()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
body {{font-family: sans-serif; margin: 2em;}}
h1 {{color: #333;}}
table {{border-collapse: collapse; width: 100%; margin-bottom: 2em;}}
th, td {{border: 1px solid #ccc; padding: 6px 10px; text-align: left;}}
th {{background: #f0f0f0;}}
.sev-critical {{background: #ffd0d0; color: #900;}}
.sev-high {{background: #ffe0cc; color: #c50;}}
.sev-medium {{background: #fff8cc; color: #770;}}
.sev-low {{background: #e8ffe8; color: #060;}}
.sev-info {{background: #e8f0ff; color: #006;}}
.summary-grid {{display: grid; grid-template-columns: repeat(5, 1fr); gap: 1em; margin-bottom: 2em;}}
.summary-card {{padding: 1em; border-radius: 6px; text-align: center;}}
.cnt {{font-size: 2em; font-weight: bold;}}
</style>
</head>
<body>
<h1>{title}</h1>
<p>Generated: {generated_at}</p>
<div class="summary-grid">
  <div class="summary-card sev-critical"><div class="cnt">{critical}</div>Critical</div>
  <div class="summary-card sev-high"><div class="cnt">{high}</div>High</div>
  <div class="summary-card sev-medium"><div class="cnt">{medium}</div>Medium</div>
  <div class="summary-card sev-low"><div class="cnt">{low}</div>Low</div>
  <div class="summary-card sev-info"><div class="cnt">{info}</div>Info</div>
</div>
<h2>Findings by CWE</h2>
<table><tr><th>CWE</th><th>Count</th></tr>{cwe_rows}</table>
<h2>All Findings ({total})</h2>
<table>
<tr><th>Rule</th><th>Severity</th><th>CWE</th><th>Location</th><th>Evidence</th></tr>
{rows}
</table>
</body>
</html>"#,
        title = html_escape(&report.title),
        generated_at = report.generated_at,
        critical = report.summary.critical,
        high = report.summary.high,
        medium = report.summary.medium,
        low = report.summary.low,
        info = report.summary.info,
        total = report.summary.total,
        cwe_rows = cwe_rows,
        rows = rows,
    )
}

pub fn write_html(report: &Report, path: &Path) -> anyhow::Result<()> {
    let html = to_html(report);
    std::fs::write(path, html)?;
    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, sev: Severity, cwe: &str) -> Finding {
        Finding {
            severity: sev,
            rule_id: rule.to_string(),
            cwe: Some(cwe.to_string()),
            file: "src/main.rs".to_string(),
            line: 10,
            evidence: "test <evidence>".to_string(),
            remediation: "fix".to_string(),
        }
    }

    #[test]
    fn build_report_counts_correctly() {
        let findings = vec![
            finding("R1", Severity::Critical, "CWE-78"),
            finding("R2", Severity::High, "CWE-89"),
            finding("R3", Severity::High, "CWE-89"),
            finding("R4", Severity::Medium, "CWE-22"),
        ];
        let report = build_report("Test Report", &findings);
        assert_eq!(report.summary.total, 4);
        assert_eq!(report.summary.critical, 1);
        assert_eq!(report.summary.high, 2);
        assert_eq!(report.summary.medium, 1);
        assert_eq!(report.summary.low, 0);
        assert_eq!(report.summary.by_cwe["CWE-89"], 2);
    }

    #[test]
    fn to_json_valid() {
        let findings = vec![finding("R1", Severity::High, "CWE-78")];
        let report = build_report("JSON Test", &findings);
        let json = to_json(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["summary"]["total"], 1);
        assert_eq!(parsed["title"], "JSON Test");
    }

    #[test]
    fn to_html_contains_doctype() {
        let findings = vec![finding("R1", Severity::High, "CWE-78")];
        let report = build_report("HTML Test", &findings);
        let html = to_html(&report);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("HTML Test"));
    }

    #[test]
    fn to_html_escapes_evidence() {
        let mut f = finding("R1", Severity::High, "CWE-78");
        f.evidence = "bad <script>alert(1)</script>".to_string();
        let report = build_report("Escape Test", &[f]);
        let html = to_html(&report);
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn html_escape_fn() {
        assert_eq!(html_escape("<>&\"'"), "&lt;&gt;&amp;&quot;&#39;");
    }

    #[test]
    fn write_json_creates_file() {
        let findings = vec![finding("R1", Severity::High, "CWE-78")];
        let report = build_report("Write Test", &findings);
        let path = std::path::PathBuf::from(format!("/tmp/aether_report_test_{}.json", std::process::id()));
        write_json(&report, &path).unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Write Test"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_html_creates_file() {
        let findings = vec![finding("R1", Severity::High, "CWE-78")];
        let report = build_report("HTML Write Test", &findings);
        let path = std::path::PathBuf::from(format!("/tmp/aether_report_test_{}.html", std::process::id()));
        write_html(&report, &path).unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("<!DOCTYPE html>"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_report_builds() {
        let report = build_report("Empty", &[]);
        assert_eq!(report.summary.total, 0);
        assert!(report.summary.by_cwe.is_empty());
    }
}
