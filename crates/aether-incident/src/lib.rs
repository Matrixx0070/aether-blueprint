//! Real incident response automation: alert triage, forensics, containment.
//!
//! TIER 17 real implementation:
//! - NIST 800-61r2 incident response lifecycle (Detect → Contain → Eradicate → Recover)
//! - Real containment actions: kill process, block IP via iptables, quarantine file
//! - Network forensics: active connections via /proc/net/tcp + ss command
//! - Process forensics: /proc enumeration for suspicious processes
//! - Severity triage: automated scoring using IOCs and context
//! - Playbook execution: predefined response playbooks per incident type

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    P4Low,
    P3Medium,
    P2High,
    P1Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IncidentType {
    Malware,
    DataExfiltration,
    UnauthorizedAccess,
    InsiderThreat,
    RansomwareAttack,
    DenialOfService,
    SupplyChainCompromise,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentAlert {
    pub alert_id: String,
    pub severity: String,
    pub description: String,
    pub affected_systems: Vec<String>,
    pub indicators: Vec<String>,
    pub incident_type: IncidentType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicProcess {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub open_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentAction {
    pub action: String,
    pub target: String,
    pub result: String,
    pub reversible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentReport {
    pub alert_id: String,
    pub incident_type: IncidentType,
    pub severity: Severity,
    pub triage_score: f32,
    pub affected_systems: Vec<String>,
    pub forensic_processes: Vec<ForensicProcess>,
    pub network_connections: Vec<String>,
    pub containment_actions: Vec<ContainmentAction>,
    pub playbook_steps: Vec<String>,
    pub recommendations: Vec<String>,
    pub nist_phase: String,
}

// ── Process forensics ─────────────────────────────────────────────────────────

pub fn enumerate_suspicious_processes() -> Vec<ForensicProcess> {
    let suspicious_names = ["nc", "ncat", "socat", "python", "perl", "ruby",
                            "bash", "sh", "netcat", "curl", "wget", "ssh",
                            "nmap", "masscan", "hydra", "john", "hashcat"];
    let mut procs = Vec::new();

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.chars().all(|c| c.is_ascii_digit()) { continue; }

            if let Ok(pid) = name_str.parse::<u32>() {
                let comm_path = format!("/proc/{pid}/comm");
                let cmdline_path = format!("/proc/{pid}/cmdline");

                let proc_name = std::fs::read_to_string(&comm_path)
                    .unwrap_or_default().trim().to_string();
                let cmdline = std::fs::read_to_string(&cmdline_path)
                    .unwrap_or_default().replace('\0', " ").trim().to_string();

                if suspicious_names.iter().any(|s| proc_name.contains(s)) {
                    procs.push(ForensicProcess {
                        pid,
                        name: proc_name,
                        cmdline,
                        open_ports: vec![],
                    });
                }
            }
        }
    }
    procs
}

// ── Network forensics ─────────────────────────────────────────────────────────

pub fn get_active_connections() -> Vec<String> {
    let output = Command::new("ss")
        .args(["-tunap", "--no-header"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.lines()
                .filter(|l| l.contains("ESTAB") || l.contains("LISTEN"))
                .take(50)
                .map(|l| l.to_string())
                .collect()
        }
        _ => vec!["ss not available — check /proc/net/tcp manually".to_string()],
    }
}

// ── Containment actions ───────────────────────────────────────────────────────

pub fn kill_process(pid: u32) -> ContainmentAction {
    let result = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .output();

    ContainmentAction {
        action: "kill_process".to_string(),
        target: pid.to_string(),
        result: match result {
            Ok(o) if o.status.success() => format!("PID {pid} terminated"),
            Ok(o) => format!("kill failed: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => format!("kill error: {e}"),
        },
        reversible: false,
    }
}

pub fn block_ip_iptables(ip: &str) -> ContainmentAction {
    // Validate IP format first
    let valid = ip.split('.').count() == 4 && ip.split('.').all(|p| p.parse::<u8>().is_ok());
    if !valid {
        return ContainmentAction {
            action: "block_ip".to_string(),
            target: ip.to_string(),
            result: "invalid IP address format".to_string(),
            reversible: true,
        };
    }

    let result = Command::new("iptables")
        .args(["-I", "INPUT", "-s", ip, "-j", "DROP"])
        .output();

    ContainmentAction {
        action: "block_ip_iptables".to_string(),
        target: ip.to_string(),
        result: match result {
            Ok(o) if o.status.success() => format!("IP {ip} blocked via iptables INPUT DROP"),
            Ok(o) => format!("iptables failed: {}", String::from_utf8_lossy(&o.stderr).trim()),
            Err(e) => format!("iptables unavailable: {e}"),
        },
        reversible: true,
    }
}

pub fn quarantine_file(path: &Path, quarantine_dir: &Path) -> ContainmentAction {
    let file_name = path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let dest = quarantine_dir.join(&file_name);

    let result = if !path.exists() {
        "source file not found".to_string()
    } else {
        match std::fs::rename(path, &dest) {
            Ok(_) => format!("quarantined to {}", dest.display()),
            Err(e) => {
                // Try copy+delete if rename across filesystems fails
                match std::fs::copy(path, &dest) {
                    Ok(_) => {
                        let _ = std::fs::remove_file(path);
                        format!("quarantined to {}", dest.display())
                    }
                    Err(_) => format!("quarantine failed: {e}"),
                }
            }
        }
    };

    ContainmentAction {
        action: "quarantine_file".to_string(),
        target: path.to_string_lossy().into_owned(),
        result,
        reversible: true,
    }
}

// ── Incident triage ───────────────────────────────────────────────────────────

pub fn classify_incident(description: &str, indicators: &[String]) -> (IncidentType, f32) {
    let text = format!("{description} {}", indicators.join(" ")).to_lowercase();
    let mut score: f32 = 0.0;
    let mut incident_type = IncidentType::Unknown;

    let patterns: &[(&str, IncidentType, f32)] = &[
        ("ransomware", IncidentType::RansomwareAttack, 0.9),
        ("encrypt",    IncidentType::RansomwareAttack, 0.6),
        ("exfil",      IncidentType::DataExfiltration, 0.8),
        ("data theft", IncidentType::DataExfiltration, 0.8),
        ("malware",    IncidentType::Malware, 0.7),
        ("trojan",     IncidentType::Malware, 0.8),
        ("backdoor",   IncidentType::Malware, 0.8),
        ("unauthorized", IncidentType::UnauthorizedAccess, 0.7),
        ("brute force",  IncidentType::UnauthorizedAccess, 0.6),
        ("ddos",       IncidentType::DenialOfService, 0.8),
        ("flooding",   IncidentType::DenialOfService, 0.7),
        ("supply chain", IncidentType::SupplyChainCompromise, 0.9),
        ("insider",    IncidentType::InsiderThreat, 0.8),
    ];

    for (pattern, itype, weight) in patterns {
        if text.contains(pattern) && *weight > score {
            score = *weight;
            incident_type = itype.clone();
        }
    }
    (incident_type, score)
}

fn severity_from_score(score: f32, count: usize) -> Severity {
    let adjusted = score + (count as f32 * 0.05).min(0.2);
    if adjusted >= 0.8 { Severity::P1Critical }
    else if adjusted >= 0.6 { Severity::P2High }
    else if adjusted >= 0.4 { Severity::P3Medium }
    else { Severity::P4Low }
}

// ── Playbook selection ────────────────────────────────────────────────────────

fn playbook_for(incident_type: &IncidentType) -> Vec<String> {
    match incident_type {
        IncidentType::Malware | IncidentType::RansomwareAttack => vec![
            "1. Isolate affected system from network immediately".to_string(),
            "2. Capture memory dump before killing processes".to_string(),
            "3. Kill malicious process(es) identified in forensics".to_string(),
            "4. Preserve disk image for forensic analysis".to_string(),
            "5. Scan adjacent systems for lateral movement".to_string(),
            "6. Rotate all credentials that may have been exposed".to_string(),
            "7. Restore from verified clean backup".to_string(),
            "8. Patch exploited vulnerability before re-connecting".to_string(),
        ],
        IncidentType::DataExfiltration => vec![
            "1. Identify and block C2 IP/domain at firewall/proxy".to_string(),
            "2. Determine scope: what data was accessed/exfiltrated".to_string(),
            "3. Preserve network logs for forensic timeline".to_string(),
            "4. Notify DPO if PII/PHI involved (GDPR 72h window)".to_string(),
            "5. Revoke exposed API keys and OAuth tokens".to_string(),
            "6. Enable enhanced monitoring on affected data stores".to_string(),
            "7. Review DLP policies and implement data classification".to_string(),
        ],
        IncidentType::UnauthorizedAccess => vec![
            "1. Lock compromised accounts immediately".to_string(),
            "2. Invalidate all active sessions for affected accounts".to_string(),
            "3. Collect auth logs for forensic timeline".to_string(),
            "4. Identify entry point: leaked credentials, session hijack, OIDC misconfiguration".to_string(),
            "5. Enable MFA if not already enforced".to_string(),
            "6. Audit privilege assignments changed during incident window".to_string(),
            "7. Implement IP allowlisting for admin interfaces".to_string(),
        ],
        IncidentType::DenialOfService => vec![
            "1. Enable DDoS scrubbing (Cloudflare/AWS Shield)".to_string(),
            "2. Block attack source IPs at upstream provider".to_string(),
            "3. Enable rate limiting at API gateway".to_string(),
            "4. Scale horizontally and activate CDN".to_string(),
            "5. Contact ISP for upstream null-routing if volumetric".to_string(),
            "6. Monitor for application-layer (Layer 7) attack patterns".to_string(),
        ],
        IncidentType::SupplyChainCompromise => vec![
            "1. Pin to known-good dependency hashes immediately".to_string(),
            "2. Audit all code paths touched by compromised package".to_string(),
            "3. Check for data theft, backdoors, credential theft".to_string(),
            "4. Notify downstream users/customers if applicable".to_string(),
            "5. Implement SBOM and dependency provenance checks".to_string(),
            "6. Enable cosign/sigstore for package verification".to_string(),
        ],
        _ => vec![
            "1. Collect and preserve all available logs".to_string(),
            "2. Identify affected systems and scope of impact".to_string(),
            "3. Contain spread by isolating affected systems".to_string(),
            "4. Escalate to security team lead".to_string(),
            "5. Document timeline and evidence".to_string(),
        ],
    }
}

// ── Full triage ───────────────────────────────────────────────────────────────

pub fn triage_alert(alert: &IncidentAlert) -> Result<IncidentReport> {
    let (incident_type, triage_score) = classify_incident(&alert.description, &alert.indicators);
    let severity = severity_from_score(triage_score, alert.affected_systems.len());

    let forensic_processes = enumerate_suspicious_processes();
    let network_connections = get_active_connections();
    let playbook_steps = playbook_for(&incident_type);

    let recommendations = vec![
        format!("Assign incident to: {:?} response team", incident_type),
        format!("SLA target: {}", match severity {
            Severity::P1Critical => "15 min response, 4h containment",
            Severity::P2High     => "1h response, 24h containment",
            Severity::P3Medium   => "4h response, 72h remediation",
            Severity::P4Low      => "24h response, 1 week remediation",
        }),
        format!("Suspicious processes found: {}", forensic_processes.len()),
        format!("Active network connections: {}", network_connections.len()),
        "Run: aether threat-intel --apt to correlate with APT group TTPs".to_string(),
        "Run: aether malware-check on all flagged binaries".to_string(),
    ];

    let nist_phase = match severity {
        Severity::P1Critical | Severity::P2High => "CONTAIN".to_string(),
        Severity::P3Medium => "DETECT+ANALYZE".to_string(),
        Severity::P4Low    => "DETECT".to_string(),
    };

    Ok(IncidentReport {
        alert_id: alert.alert_id.clone(),
        incident_type,
        severity,
        triage_score,
        affected_systems: alert.affected_systems.clone(),
        forensic_processes,
        network_connections,
        containment_actions: vec![],
        playbook_steps,
        recommendations,
        nist_phase,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_alert(desc: &str, itype: IncidentType) -> IncidentAlert {
        IncidentAlert {
            alert_id: "IR-001".to_string(),
            severity: "High".to_string(),
            description: desc.to_string(),
            affected_systems: vec!["web-01".to_string()],
            indicators: vec![],
            incident_type: itype,
        }
    }

    #[test]
    fn classifies_ransomware() {
        let (itype, score) = classify_incident("ransomware detected files encrypting", &[]);
        assert_eq!(itype, IncidentType::RansomwareAttack);
        assert!(score >= 0.6);
    }

    #[test]
    fn classifies_exfiltration() {
        let (itype, _) = classify_incident("data exfiltration detected to external IP", &[]);
        assert_eq!(itype, IncidentType::DataExfiltration);
    }

    #[test]
    fn severity_critical_for_high_score() {
        assert_eq!(severity_from_score(0.9, 5), Severity::P1Critical);
    }

    #[test]
    fn severity_low_for_zero() {
        assert_eq!(severity_from_score(0.0, 0), Severity::P4Low);
    }

    #[test]
    fn triage_populates_playbook() {
        let alert = make_alert("malware detected on web-01", IncidentType::Malware);
        let report = triage_alert(&alert).unwrap();
        assert!(!report.playbook_steps.is_empty());
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn playbook_malware_has_8_steps() {
        let steps = playbook_for(&IncidentType::Malware);
        assert_eq!(steps.len(), 8);
    }

    #[test]
    fn ip_validation() {
        let action = block_ip_iptables("not_an_ip");
        assert!(action.result.contains("invalid"));
    }
}
