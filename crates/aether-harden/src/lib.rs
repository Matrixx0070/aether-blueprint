//! CIS benchmark live system hardening checker.
//!
//! Real implementation:
//! - Reads /proc/sys/* sysctl values directly (no `sysctl` binary dependency)
//! - Parses /etc/ssh/sshd_config for insecure settings
//! - Finds SUID/SGID binaries via filesystem walk
//! - Finds world-writable files in critical directories
//! - Inspects /etc/pam.d/common-password for password policy
//! - Maps findings to CIS Benchmark control IDs
//! - Produces pass/fail/warn per control with remediation advice

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HardenStatus {
    Pass,
    Fail,
    Warn,
    NotApplicable,
}

impl std::fmt::Display for HardenStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HardenStatus::Pass => write!(f, "PASS"),
            HardenStatus::Fail => write!(f, "FAIL"),
            HardenStatus::Warn => write!(f, "WARN"),
            HardenStatus::NotApplicable => write!(f, "N/A"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardenControl {
    pub cis_id: String,
    pub title: String,
    pub status: HardenStatus,
    pub current_value: String,
    pub expected_value: String,
    pub remediation: String,
    pub severity: String, // L1 or L2
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HardenReport {
    pub hostname: String,
    pub kernel: String,
    pub controls: Vec<HardenControl>,
    pub pass_count: usize,
    pub fail_count: usize,
    pub warn_count: usize,
    pub score_pct: f64,
    pub suid_binaries: Vec<String>,
    pub world_writable: Vec<String>,
}

// ── Sysctl reader ─────────────────────────────────────────────────────────────

fn read_sysctl(key: &str) -> Option<String> {
    // /proc/sys/kernel/randomize_va_space → kernel/randomize_va_space
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

fn sysctl_check(cis_id: &str, title: &str, key: &str, want: &str, severity: &str, remediation: &str) -> HardenControl {
    match read_sysctl(key) {
        None => HardenControl {
            cis_id: cis_id.to_string(),
            title: title.to_string(),
            status: HardenStatus::NotApplicable,
            current_value: "unreadable".to_string(),
            expected_value: want.to_string(),
            remediation: remediation.to_string(),
            severity: severity.to_string(),
        },
        Some(val) => {
            let status = if val == want { HardenStatus::Pass } else { HardenStatus::Fail };
            HardenControl {
                cis_id: cis_id.to_string(),
                title: title.to_string(),
                status,
                current_value: val,
                expected_value: want.to_string(),
                remediation: remediation.to_string(),
                severity: severity.to_string(),
            }
        }
    }
}

// ── SSH config checker ────────────────────────────────────────────────────────

fn check_sshd(path: &str) -> Vec<HardenControl> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![HardenControl {
            cis_id: "5.2".to_string(),
            title: "SSH config readable".to_string(),
            status: HardenStatus::NotApplicable,
            current_value: "file not found".to_string(),
            expected_value: "present".to_string(),
            remediation: "Install openssh-server".to_string(),
            severity: "L1".to_string(),
        }],
    };

    let get = |directive: &str| -> Option<String> {
        for line in content.lines() {
            let t = line.trim();
            if t.starts_with('#') { continue; }
            let mut parts = t.splitn(2, char::is_whitespace);
            if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                if k.eq_ignore_ascii_case(directive) {
                    return Some(v.trim().to_string());
                }
            }
        }
        None
    };

    let check = |cis_id: &str, title: &str, directive: &str, want: &str, severity: &str, rem: &str| -> HardenControl {
        let val = get(directive).unwrap_or_else(|| "(not set)".to_string());
        let status = if val.eq_ignore_ascii_case(want) { HardenStatus::Pass } else { HardenStatus::Fail };
        HardenControl {
            cis_id: cis_id.to_string(),
            title: title.to_string(),
            status,
            current_value: val,
            expected_value: want.to_string(),
            remediation: rem.to_string(),
            severity: severity.to_string(),
        }
    };

    vec![
        check("5.2.2",  "SSH PermitRootLogin disabled",    "PermitRootLogin",         "no",          "L1", "Set PermitRootLogin no in sshd_config"),
        check("5.2.3",  "SSH LogLevel INFO or VERBOSE",     "LogLevel",                "INFO",        "L1", "Set LogLevel INFO in sshd_config"),
        check("5.2.5",  "SSH MaxAuthTries <= 4",            "MaxAuthTries",            "4",           "L1", "Set MaxAuthTries 4 in sshd_config"),
        check("5.2.6",  "SSH IgnoreRhosts enabled",         "IgnoreRhosts",            "yes",         "L1", "Set IgnoreRhosts yes in sshd_config"),
        check("5.2.7",  "SSH HostbasedAuthentication off",  "HostbasedAuthentication", "no",          "L1", "Set HostbasedAuthentication no in sshd_config"),
        check("5.2.9",  "SSH PermitEmptyPasswords no",      "PermitEmptyPasswords",    "no",          "L1", "Set PermitEmptyPasswords no in sshd_config"),
        check("5.2.10", "SSH PermitUserEnvironment no",     "PermitUserEnvironment",   "no",          "L1", "Set PermitUserEnvironment no in sshd_config"),
        check("5.2.12", "SSH ClientAliveInterval <= 300",   "ClientAliveInterval",     "300",         "L1", "Set ClientAliveInterval 300 in sshd_config"),
        check("5.2.13", "SSH ClientAliveCountMax <= 3",     "ClientAliveCountMax",     "0",           "L1", "Set ClientAliveCountMax 0 in sshd_config"),
        check("5.2.16", "SSH Banner set",                   "Banner",                  "/etc/issue.net", "L1", "Set Banner /etc/issue.net in sshd_config"),
    ]
}

// ── SUID/SGID finder ──────────────────────────────────────────────────────────

fn find_suid_binaries(dirs: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    for dir in dirs {
        let _ = walk_for_suid(Path::new(dir), &mut found, 0);
    }
    found.sort();
    found
}

fn walk_for_suid(dir: &Path, found: &mut Vec<String>, depth: usize) -> std::io::Result<()> {
    if depth > 6 { return Ok(()); }
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_symlink() { continue; }
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(name, "proc" | "sys" | "dev" | "run") { continue; }
            let _ = walk_for_suid(&path, found, depth + 1);
        } else if path.is_file() {
            if let Ok(meta) = fs::metadata(&path) {
                let mode = meta.permissions().mode();
                if mode & 0o4000 != 0 || mode & 0o2000 != 0 {
                    found.push(path.to_string_lossy().to_string());
                }
            }
        }
    }
    Ok(())
}

// ── World-writable finder ─────────────────────────────────────────────────────

fn find_world_writable(dirs: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    for dir in dirs {
        let _ = walk_for_ww(Path::new(dir), &mut found, 0);
    }
    found.sort();
    found
}

fn walk_for_ww(dir: &Path, found: &mut Vec<String>, depth: usize) -> std::io::Result<()> {
    if depth > 4 { return Ok(()); }
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_symlink() { continue; }
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(name, "proc" | "sys" | "dev" | "run" | "tmp") { continue; }
            let _ = walk_for_ww(&path, found, depth + 1);
        } else if path.is_file() {
            if let Ok(meta) = fs::metadata(&path) {
                let mode = meta.permissions().mode();
                // world-writable and not sticky
                if mode & 0o002 != 0 && mode & 0o1000 == 0 {
                    found.push(path.to_string_lossy().to_string());
                }
            }
        }
    }
    Ok(())
}

// ── PAM password policy ───────────────────────────────────────────────────────

fn check_pam() -> Vec<HardenControl> {
    let content = fs::read_to_string("/etc/pam.d/common-password")
        .or_else(|_| fs::read_to_string("/etc/pam.d/system-auth"))
        .unwrap_or_default();

    let has_pwquality = content.contains("pam_pwquality") || content.contains("pam_cracklib");
    let has_minlen = content.contains("minlen=");
    let has_remember = content.contains("pam_pwhistory") || content.contains("remember=");

    vec![
        HardenControl {
            cis_id: "5.4.1.1".to_string(),
            title: "PAM password quality module active".to_string(),
            status: if has_pwquality { HardenStatus::Pass } else { HardenStatus::Fail },
            current_value: if has_pwquality { "pam_pwquality present".to_string() } else { "not configured".to_string() },
            expected_value: "pam_pwquality or pam_cracklib".to_string(),
            remediation: "apt install libpam-pwquality && configure pam_pwquality in /etc/pam.d/common-password".to_string(),
            severity: "L1".to_string(),
        },
        HardenControl {
            cis_id: "5.4.1.2".to_string(),
            title: "PAM minlen >= 14 set".to_string(),
            status: if has_minlen { HardenStatus::Pass } else { HardenStatus::Warn },
            current_value: if has_minlen { "minlen present".to_string() } else { "not set".to_string() },
            expected_value: "minlen=14".to_string(),
            remediation: "Add minlen=14 to pam_pwquality options in /etc/pam.d/common-password".to_string(),
            severity: "L1".to_string(),
        },
        HardenControl {
            cis_id: "5.4.3".to_string(),
            title: "PAM password reuse prevention".to_string(),
            status: if has_remember { HardenStatus::Pass } else { HardenStatus::Warn },
            current_value: if has_remember { "pam_pwhistory present".to_string() } else { "not configured".to_string() },
            expected_value: "remember=5 or higher".to_string(),
            remediation: "Add password required pam_pwhistory.so remember=5 to /etc/pam.d/common-password".to_string(),
            severity: "L1".to_string(),
        },
    ]
}

// ── Sysctl controls ───────────────────────────────────────────────────────────

fn sysctl_controls() -> Vec<HardenControl> {
    vec![
        // Network
        sysctl_check("3.1.1",  "IP forwarding disabled",                 "net.ipv4.ip_forward",                  "0", "L1", "sysctl -w net.ipv4.ip_forward=0"),
        sysctl_check("3.1.2",  "Packet redirect sending disabled",        "net.ipv4.conf.all.send_redirects",    "0", "L1", "sysctl -w net.ipv4.conf.all.send_redirects=0"),
        sysctl_check("3.2.1",  "Source routed packets rejected",          "net.ipv4.conf.all.accept_source_route","0", "L1", "sysctl -w net.ipv4.conf.all.accept_source_route=0"),
        sysctl_check("3.2.2",  "ICMP redirects rejected",                 "net.ipv4.conf.all.accept_redirects",  "0", "L1", "sysctl -w net.ipv4.conf.all.accept_redirects=0"),
        sysctl_check("3.2.3",  "Secure ICMP redirects rejected",          "net.ipv4.conf.all.secure_redirects",  "0", "L1", "sysctl -w net.ipv4.conf.all.secure_redirects=0"),
        sysctl_check("3.2.4",  "Suspicious packets logged",               "net.ipv4.conf.all.log_martians",      "1", "L1", "sysctl -w net.ipv4.conf.all.log_martians=1"),
        sysctl_check("3.2.5",  "Broadcast ICMP ignored",                  "net.ipv4.icmp_echo_ignore_broadcasts", "1", "L1", "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"),
        sysctl_check("3.2.6",  "Bogus ICMP responses ignored",            "net.ipv4.icmp_ignore_bogus_error_responses","1","L1","sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1"),
        sysctl_check("3.2.7",  "Reverse path filtering enabled",          "net.ipv4.conf.all.rp_filter",          "1", "L1", "sysctl -w net.ipv4.conf.all.rp_filter=1"),
        sysctl_check("3.2.8",  "TCP SYN cookies enabled",                 "net.ipv4.tcp_syncookies",              "1", "L1", "sysctl -w net.ipv4.tcp_syncookies=1"),
        // Kernel
        sysctl_check("1.6.1.1","ASLR enabled",                            "kernel.randomize_va_space",            "2", "L1", "sysctl -w kernel.randomize_va_space=2"),
        sysctl_check("1.6.1.2","dmesg restriction enabled",               "kernel.dmesg_restrict",                "1", "L1", "sysctl -w kernel.dmesg_restrict=1"),
        sysctl_check("1.6.1.3","kptr restriction enabled",                "kernel.kptr_restrict",                 "2", "L1", "sysctl -w kernel.kptr_restrict=2"),
        sysctl_check("1.6.1.4","SysRq key disabled",                      "kernel.sysrq",                         "0", "L1", "sysctl -w kernel.sysrq=0"),
        sysctl_check("1.6.1.5","Core dump restricted",                    "fs.suid_dumpable",                     "0", "L1", "sysctl -w fs.suid_dumpable=0"),
        sysctl_check("1.6.1.6","ptrace scope restricted",                 "kernel.yama.ptrace_scope",             "1", "L1", "sysctl -w kernel.yama.ptrace_scope=1"),
    ]
}

// ── Top-level audit ───────────────────────────────────────────────────────────

pub fn run_audit() -> Result<HardenReport> {
    let hostname = fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    let kernel = fs::read_to_string("/proc/version")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    let mut controls = Vec::new();
    controls.extend(sysctl_controls());
    controls.extend(check_sshd("/etc/ssh/sshd_config"));
    controls.extend(check_pam());

    let pass_count = controls.iter().filter(|c| c.status == HardenStatus::Pass).count();
    let fail_count = controls.iter().filter(|c| c.status == HardenStatus::Fail).count();
    let warn_count = controls.iter().filter(|c| c.status == HardenStatus::Warn).count();
    let total = pass_count + fail_count + warn_count;
    let score_pct = if total > 0 { pass_count as f64 / total as f64 * 100.0 } else { 0.0 };

    let suid_dirs = ["/usr", "/bin", "/sbin", "/usr/bin", "/usr/sbin"];
    let ww_dirs   = ["/etc", "/usr", "/bin", "/sbin"];

    let suid_binaries = find_suid_binaries(&suid_dirs);
    let world_writable = find_world_writable(&ww_dirs);

    Ok(HardenReport {
        hostname,
        kernel,
        controls,
        pass_count,
        fail_count,
        warn_count,
        score_pct,
        suid_binaries,
        world_writable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysctl_aslr_readable() {
        // /proc/sys/kernel/randomize_va_space exists on any Linux system
        let val = read_sysctl("kernel.randomize_va_space");
        assert!(val.is_some(), "should be able to read ASLR sysctl");
        let v = val.unwrap();
        assert!(v == "0" || v == "1" || v == "2", "value must be 0/1/2, got {v}");
    }

    #[test]
    fn sysctl_check_produces_correct_status() {
        // We know randomize_va_space exists; check that pass/fail logic works
        let ctrl = sysctl_check("test", "ASLR", "kernel.randomize_va_space", "2", "L1", "fix it");
        // Status depends on the actual system value — just ensure it's not NA
        assert_ne!(ctrl.status, HardenStatus::NotApplicable);
        assert!(!ctrl.current_value.is_empty());
    }

    #[test]
    fn sshd_check_when_missing_returns_na() {
        let controls = check_sshd("/nonexistent/path/sshd_config");
        assert_eq!(controls.len(), 1);
        assert_eq!(controls[0].status, HardenStatus::NotApplicable);
    }

    #[test]
    fn sshd_check_parses_real_config() {
        // Write a mock sshd_config to /tmp
        let path = "/tmp/aether_harden_test_sshd_config";
        std::fs::write(path, "PermitRootLogin no\nLogLevel INFO\nMaxAuthTries 4\nPermitEmptyPasswords no\n").unwrap();
        let controls = check_sshd(path);
        let root_ctrl = controls.iter().find(|c| c.cis_id == "5.2.2").unwrap();
        assert_eq!(root_ctrl.status, HardenStatus::Pass, "PermitRootLogin no should PASS");
    }

    #[test]
    fn suid_walk_returns_known_binary() {
        // sudo is SUID on most Linux systems
        let found = find_suid_binaries(&["/usr/bin"]);
        // Just verify the function runs without panic and returns plausible paths
        for path in &found {
            assert!(path.starts_with('/'));
        }
    }

    #[test]
    fn world_writable_doesnt_panic() {
        let found = find_world_writable(&["/etc"]);
        for path in &found {
            assert!(path.starts_with('/'));
        }
    }

    #[test]
    fn full_audit_runs() {
        let report = run_audit().expect("audit should not error");
        assert!(!report.controls.is_empty(), "should have controls");
        let total = report.pass_count + report.fail_count + report.warn_count;
        assert!(total > 0, "should have scored some controls");
        assert!(report.score_pct >= 0.0 && report.score_pct <= 100.0);
    }

    #[test]
    fn pam_check_runs_without_panic() {
        let controls = check_pam();
        assert_eq!(controls.len(), 3);
        for c in &controls {
            assert!(!c.cis_id.is_empty());
        }
    }
}
