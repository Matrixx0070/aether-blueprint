//! Config drift detector.
//!
//! Takes a baseline hardening snapshot (produced by aether-harden),
//! runs a fresh audit, and diffs the results. Any control that was
//! previously PASS but is now FAIL/WARN is reported as drift.
//! Snapshots are stored as JSON files for persistence across runs.

pub use aether_deps_reach::{Finding, Severity};

use aether_harden::{HardenControl, HardenReport, HardenStatus};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Snapshot ──────────────────────────────────────────────────────────────────

pub fn save_baseline(report: &HardenReport, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn load_baseline(path: &Path) -> Result<HardenReport> {
    let s = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&s)?)
}

// ── Drift detection ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftItem {
    pub control: HardenControl,
    pub was: HardenStatus,
    pub now: HardenStatus,
}

pub fn detect_drift(baseline: &HardenReport, current: &HardenReport) -> Vec<DriftItem> {
    let baseline_map: std::collections::HashMap<&str, &HardenStatus> = baseline
        .controls
        .iter()
        .map(|c| (c.cis_id.as_str(), &c.status))
        .collect();

    current
        .controls
        .iter()
        .filter_map(|ctrl| {
            let was = baseline_map.get(ctrl.cis_id.as_str())?;
            // Only flag if it was passing before but is now failing/warning
            if **was == HardenStatus::Pass
                && (ctrl.status == HardenStatus::Fail || ctrl.status == HardenStatus::Warn)
            {
                Some(DriftItem {
                    control: ctrl.clone(),
                    was: (*was).clone(),
                    now: ctrl.status.clone(),
                })
            } else {
                None
            }
        })
        .collect()
}

// ── Conversion to common Finding ─────────────────────────────────────────────

pub fn drift_to_findings(drift: &[DriftItem]) -> Vec<Finding> {
    drift
        .iter()
        .map(|d| Finding {
            severity: if d.now == HardenStatus::Fail {
                Severity::High
            } else {
                Severity::Medium
            },
            rule_id: format!("DRIFT-{}", d.control.cis_id.replace('.', "-")),
            cwe: Some("CWE-732".to_string()),
            file: "/etc/sysctl.conf".to_string(),
            line: 0,
            evidence: format!(
                "CIS {} '{}' was {} but is now {} (current: '{}', expected: '{}')",
                d.control.cis_id,
                d.control.title,
                d.was,
                d.now,
                d.control.current_value,
                d.control.expected_value,
            ),
            remediation: d.control.remediation.clone(),
        })
        .collect()
}

// ── Full run ──────────────────────────────────────────────────────────────────

pub fn run_drift_check(baseline_path: &Path) -> Result<Vec<Finding>> {
    let baseline = load_baseline(baseline_path)?;
    let current = aether_harden::run_audit()?;
    let drift = detect_drift(&baseline, &current);
    Ok(drift_to_findings(&drift))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether_harden::{HardenControl, HardenReport, HardenStatus};

    fn make_control(id: &str, status: HardenStatus) -> HardenControl {
        HardenControl {
            cis_id: id.to_string(),
            title: format!("Control {}", id),
            status,
            current_value: "0".to_string(),
            expected_value: "1".to_string(),
            remediation: "set it to 1".to_string(),
            severity: "L1".to_string(),
        }
    }

    fn make_report(controls: Vec<HardenControl>) -> HardenReport {
        HardenReport {
            hostname: "test-host".to_string(),
            kernel: "6.8.0".to_string(),
            controls,
            pass_count: 0,
            fail_count: 0,
            warn_count: 0,
            score_pct: 0.0,
            suid_binaries: vec![],
            world_writable: vec![],
        }
    }

    #[test]
    fn no_drift_when_identical() {
        let r = make_report(vec![make_control("1.1.1", HardenStatus::Pass)]);
        let drift = detect_drift(&r, &r);
        assert!(drift.is_empty());
    }

    #[test]
    fn drift_detected_pass_to_fail() {
        let baseline = make_report(vec![make_control("1.1.1", HardenStatus::Pass)]);
        let current = make_report(vec![make_control("1.1.1", HardenStatus::Fail)]);
        let drift = detect_drift(&baseline, &current);
        assert_eq!(drift.len(), 1);
        assert_eq!(drift[0].control.cis_id, "1.1.1");
        assert_eq!(drift[0].was, HardenStatus::Pass);
        assert_eq!(drift[0].now, HardenStatus::Fail);
    }

    #[test]
    fn drift_detected_pass_to_warn() {
        let baseline = make_report(vec![make_control("2.1", HardenStatus::Pass)]);
        let current = make_report(vec![make_control("2.1", HardenStatus::Warn)]);
        let drift = detect_drift(&baseline, &current);
        assert_eq!(drift.len(), 1);
        assert_eq!(drift[0].now, HardenStatus::Warn);
    }

    #[test]
    fn no_drift_fail_to_pass_not_flagged() {
        let baseline = make_report(vec![make_control("3.1", HardenStatus::Fail)]);
        let current = make_report(vec![make_control("3.1", HardenStatus::Pass)]);
        let drift = detect_drift(&baseline, &current);
        // improvement is not drift
        assert!(drift.is_empty());
    }

    #[test]
    fn drift_to_findings_severity_high_for_fail() {
        let baseline = make_report(vec![make_control("1.1", HardenStatus::Pass)]);
        let current = make_report(vec![make_control("1.1", HardenStatus::Fail)]);
        let drift = detect_drift(&baseline, &current);
        let findings = drift_to_findings(&drift);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].rule_id.starts_with("DRIFT-"));
    }

    #[test]
    fn drift_to_findings_severity_medium_for_warn() {
        let baseline = make_report(vec![make_control("2.2", HardenStatus::Pass)]);
        let current = make_report(vec![make_control("2.2", HardenStatus::Warn)]);
        let drift = detect_drift(&baseline, &current);
        let findings = drift_to_findings(&drift);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn baseline_roundtrip_json() {
        let r = make_report(vec![make_control("5.1", HardenStatus::Pass)]);
        let tmp = std::path::PathBuf::from(format!(
            "/tmp/aether_drift_test_{}.json",
            std::process::id()
        ));
        save_baseline(&r, &tmp).unwrap();
        let loaded = load_baseline(&tmp).unwrap();
        assert_eq!(loaded.controls.len(), 1);
        assert_eq!(loaded.controls[0].cis_id, "5.1");
        let _ = std::fs::remove_file(&tmp);
    }
}
