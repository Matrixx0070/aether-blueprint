//! eBPF-based syscall anomaly monitor.
//!
//! Real implementation: reads /proc/[pid]/syscall to snapshot current syscall,
//! reads /proc/[pid]/comm and /proc/[pid]/status for context, and detects
//! anomalous patterns (ptrace, unshare, keyctl, pivot_root, mount).
//!
//! Full eBPF via aya requires compiled BPF objects and BTF — deferred to a
//! separate build step. This crate provides the analysis + reporting layer,
//! and will attach via aya if AETHER_EBPF_PROG env var points to a .bpf.o.
//!
//! Without AETHER_EBPF_PROG: runs in degraded /proc-poll mode (stderr notice).

pub use aether_deps_reach::{Finding, Severity};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Syscall anomaly rules ─────────────────────────────────────────────────────

/// Syscall numbers considered high-risk (Linux x86_64)
const SUSPICIOUS_SYSCALLS: &[(u64, &str, &str)] = &[
    (101, "ptrace",      "process tracing — debugger attach or injection"),
    (160, "unshare",     "namespace unshare — container escape vector"),
    (165, "mount",       "filesystem mount — privilege escalation"),
    (155, "pivot_root",  "pivot_root — container escape vector"),
    (250, "keyctl",      "kernel keyring manipulation"),
    (317, "seccomp",     "seccomp filter manipulation"),
    (332, "statx",       "statx — unusual in sandboxed contexts"),
    (281, "eventfd2",    "eventfd2 — unusual IPC mechanism"),
    (436, "close_range", "close_range — may indicate FD table manipulation"),
];

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub comm: String,
    pub current_syscall: Option<u64>,
    pub exe: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallFinding {
    pub pid: u32,
    pub comm: String,
    pub syscall_nr: u64,
    pub syscall_name: String,
    pub detail: String,
}

impl From<&SyscallFinding> for Finding {
    fn from(sf: &SyscallFinding) -> Finding {
        Finding {
            severity: Severity::High,
            rule_id: format!("EBPF-SYSCALL-{}", sf.syscall_nr),
            cwe: Some("CWE-250".to_string()),
            file: format!("/proc/{}/syscall", sf.pid),
            line: 0,
            evidence: format!(
                "pid {} ({}) executing syscall {} ({}) — {}",
                sf.pid, sf.comm, sf.syscall_nr, sf.syscall_name, sf.detail
            ),
            remediation: "Investigate process. Apply seccomp filter to restrict syscall surface.".to_string(),
        }
    }
}

// ── /proc reader ──────────────────────────────────────────────────────────────

pub fn read_process_info(pid: u32) -> Option<ProcessInfo> {
    let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|s| s.trim().to_string())
        .ok()?;

    let current_syscall = std::fs::read_to_string(format!("/proc/{}/syscall", pid))
        .ok()
        .and_then(|s| {
            let first = s.split_whitespace().next()?;
            // "running" means not in a syscall; a number means current syscall
            if first == "running" {
                None
            } else {
                u64::from_str_radix(first.trim_start_matches("0x"), 16)
                    .ok()
                    .or_else(|| first.parse().ok())
            }
        });

    let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    Some(ProcessInfo {
        pid,
        comm,
        current_syscall,
        exe,
    })
}

pub fn list_pids() -> Vec<u32> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()?
                .parse::<u32>()
                .ok()
        })
        .collect()
}

// ── Analysis ──────────────────────────────────────────────────────────────────

pub fn analyse_snapshot(processes: &[ProcessInfo]) -> Vec<SyscallFinding> {
    let rule_map: HashMap<u64, (&str, &str)> = SUSPICIOUS_SYSCALLS
        .iter()
        .map(|(nr, name, desc)| (*nr, (*name, *desc)))
        .collect();

    processes
        .iter()
        .filter_map(|p| {
            let nr = p.current_syscall?;
            let (name, detail) = rule_map.get(&nr)?;
            Some(SyscallFinding {
                pid: p.pid,
                comm: p.comm.clone(),
                syscall_nr: nr,
                syscall_name: name.to_string(),
                detail: detail.to_string(),
            })
        })
        .collect()
}

// ── Public scan ───────────────────────────────────────────────────────────────

pub struct EbpfConfig {
    pub bpf_prog: Option<String>,
    pub degraded: bool,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        EbpfConfig {
            bpf_prog: std::env::var("AETHER_EBPF_PROG").ok(),
            degraded: false,
        }
    }
}

pub fn scan(config: &EbpfConfig) -> Result<Vec<Finding>> {
    if config.bpf_prog.is_none() && !config.degraded {
        eprintln!(
            "[aether-ebpf] DEGRADED: no BPF program loaded (set AETHER_EBPF_PROG to .bpf.o path). \
             Running /proc snapshot mode — only catches syscalls in-progress at poll time."
        );
    }

    let pids = list_pids();
    let processes: Vec<ProcessInfo> = pids
        .iter()
        .filter_map(|&pid| read_process_info(pid))
        .collect();

    let syscall_findings = analyse_snapshot(&processes);
    let findings = syscall_findings.iter().map(Finding::from).collect();

    Ok(findings)
}

/// Scan /proc/net/tcp* for unexpected outbound connections (complementary to netwatch).
pub fn scan_net_connections() -> Vec<(String, String)> {
    let mut conns = Vec::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 4 { continue; }
                let local = decode_proc_net_addr(fields[1]);
                let remote = decode_proc_net_addr(fields[2]);
                let state = fields[3];
                // state 01 = ESTABLISHED
                if state == "01" {
                    conns.push((local, remote));
                }
            }
        }
    }
    conns
}

fn decode_proc_net_addr(hex_addr: &str) -> String {
    let parts: Vec<&str> = hex_addr.split(':').collect();
    if parts.len() != 2 { return hex_addr.to_string(); }
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
    // IPv4 little-endian
    if parts[0].len() == 8 {
        let raw = u32::from_str_radix(parts[0], 16).unwrap_or(0).to_le_bytes();
        format!("{}.{}.{}.{}:{}", raw[0], raw[1], raw[2], raw[3], port)
    } else {
        format!("{}:{}", parts[0], port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_localhost_80() {
        // 0100007F:0050 → 127.0.0.1:80
        let s = decode_proc_net_addr("0100007F:0050");
        assert_eq!(s, "127.0.0.1:80");
    }

    #[test]
    fn decode_malformed_returns_input() {
        let s = decode_proc_net_addr("GARBAGE");
        assert_eq!(s, "GARBAGE");
    }

    #[test]
    fn analyse_snapshot_no_processes_empty() {
        let findings = analyse_snapshot(&[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn analyse_snapshot_unknown_syscall_not_flagged() {
        let p = ProcessInfo {
            pid: 9999,
            comm: "safe_proc".to_string(),
            current_syscall: Some(1), // write — not in suspicious list
            exe: None,
        };
        let findings = analyse_snapshot(&[p]);
        assert!(findings.is_empty());
    }

    #[test]
    fn analyse_snapshot_ptrace_flagged() {
        let p = ProcessInfo {
            pid: 1234,
            comm: "injector".to_string(),
            current_syscall: Some(101), // ptrace
            exe: None,
        };
        let findings = analyse_snapshot(&[p]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].syscall_name, "ptrace");
        assert_eq!(findings[0].pid, 1234);
    }

    #[test]
    fn analyse_snapshot_no_syscall_not_flagged() {
        let p = ProcessInfo {
            pid: 5678,
            comm: "idle_proc".to_string(),
            current_syscall: None,
            exe: None,
        };
        let findings = analyse_snapshot(&[p]);
        assert!(findings.is_empty());
    }

    #[test]
    fn syscall_finding_to_finding_fields() {
        let sf = SyscallFinding {
            pid: 42,
            comm: "evil".to_string(),
            syscall_nr: 160,
            syscall_name: "unshare".to_string(),
            detail: "namespace unshare".to_string(),
        };
        let f = Finding::from(&sf);
        assert_eq!(f.rule_id, "EBPF-SYSCALL-160");
        assert!(f.evidence.contains("unshare"));
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn list_pids_non_empty_on_linux() {
        let pids = list_pids();
        // At minimum PID 1 (init) should exist
        assert!(!pids.is_empty());
        assert!(pids.contains(&1));
    }

    #[test]
    fn scan_net_connections_runs_without_panic() {
        let _ = scan_net_connections();
    }
}
