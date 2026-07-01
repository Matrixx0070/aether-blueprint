//! Network egress watcher via /proc/net snapshot diff.
//!
//! Reads /proc/net/tcp and /proc/net/tcp6, parses connections,
//! resolves remote addresses, diffs against a saved baseline snapshot,
//! and reports unexpected new outbound connections.

pub use aether_deps_reach::{Finding, Severity};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TcpConn {
    pub local_addr: String,
    pub remote_addr: String,
    pub state: TcpState,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpState {
    Established,
    SynSent,
    Listen,
    TimeWait,
    CloseWait,
    Other(u8),
}

impl TcpState {
    fn from_hex(s: &str) -> TcpState {
        match u8::from_str_radix(s, 16).unwrap_or(0) {
            0x01 => TcpState::Established,
            0x02 => TcpState::SynSent,
            0x0A => TcpState::Listen,
            0x06 => TcpState::TimeWait,
            0x08 => TcpState::CloseWait,
            n    => TcpState::Other(n),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NetSnapshot {
    pub connections: Vec<TcpConn>,
    pub timestamp_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressFinding {
    pub conn: TcpConn,
    pub detail: String,
}

impl From<&EgressFinding> for Finding {
    fn from(ef: &EgressFinding) -> Finding {
        Finding {
            severity: Severity::Medium,
            rule_id: "NETWATCH-UNEXPECTED-EGRESS".to_string(),
            cwe: Some("CWE-200".to_string()),
            file: "/proc/net/tcp".to_string(),
            line: 0,
            evidence: format!(
                "New outbound connection: {} → {} ({})",
                ef.conn.local_addr,
                ef.conn.remote_addr,
                ef.detail,
            ),
            remediation: "Investigate unexpected egress. Apply firewall rules or network policy.".to_string(),
        }
    }
}

// ── /proc/net parser ──────────────────────────────────────────────────────────

fn decode_ipv4_addr(hex: &str) -> String {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return hex.to_string(); }
    let raw = u32::from_str_radix(parts[0], 16)
        .unwrap_or(0)
        .to_le_bytes();
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
    format!("{}.{}.{}.{}:{}", raw[0], raw[1], raw[2], raw[3], port)
}

fn decode_ipv6_addr(hex: &str) -> String {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return hex.to_string(); }
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
    format!("[{}]:{}", parts[0], port)
}

fn parse_proc_net(content: &str, ipv6: bool) -> Vec<TcpConn> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 { return None; }
            let local = if ipv6 { decode_ipv6_addr(fields[1]) } else { decode_ipv4_addr(fields[1]) };
            let remote = if ipv6 { decode_ipv6_addr(fields[2]) } else { decode_ipv4_addr(fields[2]) };
            let state = TcpState::from_hex(fields[3]);
            let inode = fields[9].parse::<u64>().unwrap_or(0);
            Some(TcpConn { local_addr: local, remote_addr: remote, state, inode })
        })
        .collect()
}

pub fn snapshot() -> Result<NetSnapshot> {
    let mut conns = Vec::new();

    if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
        conns.extend(parse_proc_net(&content, false));
    }
    if let Ok(content) = std::fs::read_to_string("/proc/net/tcp6") {
        conns.extend(parse_proc_net(&content, true));
    }

    let timestamp_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(NetSnapshot { connections: conns, timestamp_secs })
}

// ── Baseline storage ──────────────────────────────────────────────────────────

pub fn save_snapshot(snap: &NetSnapshot, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(snap)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn load_snapshot(path: &Path) -> Result<NetSnapshot> {
    let s = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&s)?)
}

// ── Diff / analysis ───────────────────────────────────────────────────────────

/// Ports considered "known noise" that we skip in egress alerts.
const ALLOWED_REMOTE_PORTS: &[u16] = &[80, 443, 53];

pub fn diff_snapshots(baseline: &NetSnapshot, current: &NetSnapshot) -> Vec<EgressFinding> {
    let baseline_set: HashSet<_> = baseline.connections.iter()
        .map(|c| (&c.local_addr, &c.remote_addr))
        .collect();

    current.connections.iter()
        .filter(|c| {
            // Only outbound ESTABLISHED connections not in baseline
            c.state == TcpState::Established
                && !baseline_set.contains(&(&c.local_addr, &c.remote_addr))
        })
        .filter(|c| {
            // Skip known-safe ports
            let remote_port = c.remote_addr.rsplit(':').next()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(0);
            !ALLOWED_REMOTE_PORTS.contains(&remote_port)
        })
        .map(|c| EgressFinding {
            conn: c.clone(),
            detail: "new since baseline".to_string(),
        })
        .collect()
}

pub fn analyse(baseline_path: Option<&Path>) -> Result<Vec<Finding>> {
    let current = snapshot()?;

    let findings = if let Some(base_path) = baseline_path {
        let baseline = load_snapshot(base_path)?;
        let egress = diff_snapshots(&baseline, &current);
        egress.iter().map(Finding::from).collect()
    } else {
        // No baseline: report all non-loopback ESTABLISHED connections
        current.connections.iter()
            .filter(|c| {
                c.state == TcpState::Established
                    && !c.remote_addr.starts_with("127.")
                    && !c.remote_addr.starts_with("[::1]")
            })
            .map(|c| Finding {
                severity: Severity::Low,
                rule_id: "NETWATCH-ACTIVE-CONN".to_string(),
                cwe: Some("CWE-200".to_string()),
                file: "/proc/net/tcp".to_string(),
                line: 0,
                evidence: format!("Active connection: {} → {}", c.local_addr, c.remote_addr),
                remediation: "Verify this connection is expected.".to_string(),
            })
            .collect()
    };

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(local: &str, remote: &str, state: TcpState) -> TcpConn {
        TcpConn {
            local_addr: local.to_string(),
            remote_addr: remote.to_string(),
            state,
            inode: 0,
        }
    }

    #[test]
    fn decode_ipv4_localhost() {
        // 0100007F:1F90 → 127.0.0.1:8080
        assert_eq!(decode_ipv4_addr("0100007F:1F90"), "127.0.0.1:8080");
    }

    #[test]
    fn decode_ipv4_80() {
        // 00000000:0050 → 0.0.0.0:80
        assert_eq!(decode_ipv4_addr("00000000:0050"), "0.0.0.0:80");
    }

    #[test]
    fn tcp_state_established() {
        assert_eq!(TcpState::from_hex("01"), TcpState::Established);
    }

    #[test]
    fn tcp_state_listen() {
        assert_eq!(TcpState::from_hex("0A"), TcpState::Listen);
    }

    #[test]
    fn diff_new_connection_flagged() {
        let base = NetSnapshot {
            connections: vec![conn("127.0.0.1:12345", "1.2.3.4:8080", TcpState::Established)],
            timestamp_secs: 0,
        };
        let curr = NetSnapshot {
            connections: vec![
                conn("127.0.0.1:12345", "1.2.3.4:8080", TcpState::Established),
                conn("127.0.0.1:22222", "5.6.7.8:4444", TcpState::Established), // NEW
            ],
            timestamp_secs: 1,
        };
        let findings = diff_snapshots(&base, &curr);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].conn.remote_addr.contains("5.6.7.8"));
    }

    #[test]
    fn diff_no_new_connections_empty() {
        let snap = NetSnapshot {
            connections: vec![conn("127.0.0.1:1234", "1.2.3.4:9999", TcpState::Established)],
            timestamp_secs: 0,
        };
        let findings = diff_snapshots(&snap, &snap);
        assert!(findings.is_empty());
    }

    #[test]
    fn diff_allowed_port_443_skipped() {
        let base = NetSnapshot { connections: vec![], timestamp_secs: 0 };
        let curr = NetSnapshot {
            connections: vec![conn("192.168.1.1:54321", "1.2.3.4:443", TcpState::Established)],
            timestamp_secs: 1,
        };
        let findings = diff_snapshots(&base, &curr);
        // Port 443 is in allowed list
        assert!(findings.is_empty());
    }

    #[test]
    fn egress_finding_to_finding_fields() {
        let ef = EgressFinding {
            conn: conn("127.0.0.1:1234", "10.0.0.1:6666", TcpState::Established),
            detail: "new since baseline".to_string(),
        };
        let f = Finding::from(&ef);
        assert_eq!(f.rule_id, "NETWATCH-UNEXPECTED-EGRESS");
        assert!(f.evidence.contains("10.0.0.1:6666"));
    }

    #[test]
    fn snapshot_runs_without_panic() {
        let _ = snapshot();
    }

    #[test]
    fn snapshot_roundtrip_json() {
        let snap = NetSnapshot {
            connections: vec![conn("127.0.0.1:80", "1.2.3.4:5678", TcpState::Established)],
            timestamp_secs: 12345,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: NetSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.timestamp_secs, 12345);
        assert_eq!(back.connections.len(), 1);
    }
}
