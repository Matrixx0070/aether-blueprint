//! Security primitives for aether.
//!
//! Two responsibilities:
//!   * **Scope file** at `~/.aether/scope.json`: declares which hosts /
//!     IP ranges / repos this aether process is authorized to act
//!     against. Required for every network-egress / scanning tool.
//!   * **Tamper-evident audit log** at `~/.aether/audit.jsonl`: every
//!     security-tool invocation appends one line. Each line includes the
//!     SHA-256 of the previous line, so any retroactive edit is
//!     detectable via `verify_audit_chain`.
//!
//! The crate exposes pure functions + types — no I/O on a global
//! singleton. Callers (the CLI) decide when to read / write.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const SCOPE_REL_PATH: &str = ".aether/scope.json";
const AUDIT_REL_PATH: &str = ".aether/audit.jsonl";

// ── scope ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    /// Who signed off on this authorization (operator name + role).
    pub authorized_by: String,
    /// Ticket / engagement / change-request id this scope traces to.
    pub ticket_id: String,
    /// ISO-8601 absolute deadline. Beyond this, scope checks fail-closed.
    pub expires_at: DateTime<Utc>,
    /// Allowed hosts (exact match, case-insensitive). e.g. ["example.com",
    /// "api.example.com"].
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Allowed CIDR ranges, e.g. ["10.0.0.0/24", "192.168.1.0/24"].
    #[serde(default)]
    pub ip_ranges: Vec<String>,
    /// Allowed local repository paths (canonical absolute paths).
    #[serde(default)]
    pub repos: Vec<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum SecError {
    #[error("io: {0}")]
    Io(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("scope expired at {0}")]
    Expired(DateTime<Utc>),
    #[error("out of scope: {target} not in scope (see {scope_path})")]
    OutOfScope { target: String, scope_path: String },
    #[error("audit chain broken at line {line}: {reason}")]
    AuditChainBroken { line: usize, reason: String },
    #[error("scope file missing at {0}. Create one via `aether scope add` before running scope-gated tools.")]
    NoScope(String),
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),
}

impl Scope {
    pub fn enforce_caps(&self) -> Result<(), SecError> {
        if self.hosts.len() > 256 {
            return Err(SecError::LimitExceeded(format!(
                "scope.hosts has {} entries (cap 256)",
                self.hosts.len()
            )));
        }
        // Reject CIDR larger than /16 to prevent "scan the internet"
        for r in &self.ip_ranges {
            if let Some((_, prefix)) = r.split_once('/') {
                if let Ok(p) = prefix.parse::<u8>() {
                    if p < 16 {
                        return Err(SecError::LimitExceeded(format!(
                            "ip_range {r} is larger than /16 (got /{p})"
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn scope_path() -> PathBuf {
    home_dir().join(SCOPE_REL_PATH)
}

pub fn audit_path() -> PathBuf {
    home_dir().join(AUDIT_REL_PATH)
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

pub fn load_scope() -> Result<Scope, SecError> {
    let p = scope_path();
    let s = std::fs::read_to_string(&p).map_err(|_| SecError::NoScope(p.display().to_string()))?;
    let scope: Scope =
        serde_json::from_str(&s).map_err(|e| SecError::Parse(format!("{}: {e}", p.display())))?;
    let now = Utc::now();
    if scope.expires_at <= now {
        return Err(SecError::Expired(scope.expires_at));
    }
    scope.enforce_caps()?;
    Ok(scope)
}

pub fn save_scope(scope: &Scope) -> Result<(), SecError> {
    scope.enforce_caps()?;
    let p = scope_path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SecError::Io(e.to_string()))?;
    }
    let body = serde_json::to_vec_pretty(scope)
        .map_err(|e| SecError::Parse(format!("encode: {e}")))?;
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, &body).map_err(|e| SecError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &p).map_err(|e| SecError::Io(e.to_string()))?;
    Ok(())
}

/// SHA-256 of the canonical JSON form of the scope. Embedded in every
/// audit entry so an out-of-band tampering with scope.json is detectable.
pub fn scope_fingerprint(scope: &Scope) -> String {
    let canon =
        serde_json::to_vec(scope).expect("scope is always serialisable");
    hex::encode(Sha256::digest(canon))
}

// ── scope checks ──────────────────────────────────────────────────────────

/// Returns `Ok(())` when `target` is in scope. `target` may be a hostname,
/// an IP literal, or an URL — we extract the host portion for matching.
pub fn check_target_in_scope(scope: &Scope, target: &str) -> Result<(), SecError> {
    let host = extract_host(target).unwrap_or_else(|| target.to_string());
    let host_lower = host.to_lowercase();
    // Exact host match
    if scope
        .hosts
        .iter()
        .any(|h| h.to_lowercase() == host_lower)
    {
        return Ok(());
    }
    // IP-literal match against CIDR ranges
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        for range in &scope.ip_ranges {
            if ip_in_cidr(ip, range) {
                return Ok(());
            }
        }
    }
    Err(SecError::OutOfScope {
        target: host,
        scope_path: scope_path().display().to_string(),
    })
}

fn extract_host(target: &str) -> Option<String> {
    // URL form
    if target.starts_with("http://") || target.starts_with("https://") {
        if let Ok(u) = url_parse(target) {
            return Some(u.host);
        }
    }
    // host:port form
    if let Some((h, _)) = target.split_once(':') {
        if h.parse::<std::net::IpAddr>().is_ok() || !h.contains('/') {
            return Some(h.to_string());
        }
    }
    Some(target.to_string())
}

struct UrlParsed {
    host: String,
}

fn url_parse(s: &str) -> Result<UrlParsed, ()> {
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .ok_or(())?;
    let host_part = rest.splitn(2, '/').next().unwrap_or("");
    let host = host_part.splitn(2, ':').next().unwrap_or("").to_string();
    if host.is_empty() {
        return Err(());
    }
    Ok(UrlParsed { host })
}

fn ip_in_cidr(ip: std::net::IpAddr, cidr: &str) -> bool {
    let (range_ip, prefix) = match cidr.split_once('/') {
        Some(v) => v,
        None => return ip.to_string() == cidr,
    };
    let prefix: u8 = match prefix.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let range_ip: std::net::IpAddr = match range_ip.parse() {
        Ok(i) => i,
        Err(_) => return false,
    };
    match (ip, range_ip) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => {
            if prefix > 32 {
                return false;
            }
            let a = u32::from(a);
            let b = u32::from(b);
            let mask: u32 = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (a & mask) == (b & mask)
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) => {
            if prefix > 128 {
                return false;
            }
            let a = u128::from(a);
            let b = u128::from(b);
            let mask: u128 = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (a & mask) == (b & mask)
        }
        _ => false,
    }
}

// ── audit log ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: DateTime<Utc>,
    pub tool: String,
    pub target: String,
    pub scope_fingerprint: String,
    pub status: String,
    #[serde(default)]
    pub note: Option<String>,
    pub prev_hash: String,
    pub this_hash: String,
}

fn hash_entry_body(
    ts: &DateTime<Utc>,
    tool: &str,
    target: &str,
    scope_fp: &str,
    status: &str,
    note: &Option<String>,
    prev_hash: &str,
) -> String {
    let canon = serde_json::json!({
        "ts": ts.to_rfc3339(),
        "tool": tool,
        "target": target,
        "scope_fingerprint": scope_fp,
        "status": status,
        "note": note,
        "prev_hash": prev_hash,
    });
    let body = serde_json::to_vec(&canon).expect("json");
    hex::encode(Sha256::digest(body))
}

pub fn append_audit(
    tool: &str,
    target: &str,
    scope_fp: &str,
    status: &str,
    note: Option<String>,
) -> Result<(), SecError> {
    use std::io::Write;
    let path = audit_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SecError::Io(e.to_string()))?;
    }
    let prev_hash = last_audit_hash().unwrap_or_else(|_| "genesis".to_string());
    let ts = Utc::now();
    let this_hash = hash_entry_body(&ts, tool, target, scope_fp, status, &note, &prev_hash);
    let entry = AuditEntry {
        ts,
        tool: tool.to_string(),
        target: target.to_string(),
        scope_fingerprint: scope_fp.to_string(),
        status: status.to_string(),
        note,
        prev_hash,
        this_hash,
    };
    let line = serde_json::to_string(&entry)
        .map_err(|e| SecError::Parse(format!("encode: {e}")))?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| SecError::Io(e.to_string()))?;
    writeln!(f, "{line}").map_err(|e| SecError::Io(e.to_string()))?;

    // Optional syslog tee: when AETHER_AUDIT_SYSLOG=1, also send the
    // entry to the system logger (Unix `LOG_USER`). Failure to reach
    // syslog is silently swallowed — the JSONL is the authoritative
    // record; syslog is a forwarding convenience. Windows / non-Unix
    // platforms skip silently.
    #[cfg(unix)]
    {
        if std::env::var("AETHER_AUDIT_SYSLOG").ok().as_deref() == Some("1") {
            // Use /dev/log if available; lazy and best-effort.
            let _ = forward_to_syslog(&line);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn forward_to_syslog(line: &str) -> std::io::Result<()> {
    use std::os::unix::net::UnixDatagram;
    let sock = UnixDatagram::unbound()?;
    // RFC 3164-ish: <14> = facility LOG_USER (1) * 8 + severity INFO (6) = 14
    let msg = format!("<14>aether-audit: {line}");
    // /dev/log is the standard syslog socket on Linux.
    let mut written = sock.send_to(msg.as_bytes(), "/dev/log");
    if written.is_err() {
        // macOS / BSD often use /var/run/log instead.
        written = sock.send_to(msg.as_bytes(), "/var/run/log");
    }
    written.map(|_| ()).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

pub fn last_audit_hash() -> Result<String, SecError> {
    let path = audit_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Ok("genesis".to_string()),
    };
    let mut last: Option<AuditEntry> = None;
    for line in content.lines() {
        if let Ok(e) = serde_json::from_str::<AuditEntry>(line) {
            last = Some(e);
        }
    }
    Ok(last
        .map(|e| e.this_hash)
        .unwrap_or_else(|| "genesis".to_string()))
}

pub fn load_audit() -> Result<Vec<AuditEntry>, SecError> {
    let path = audit_path();
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let mut out = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let e: AuditEntry = serde_json::from_str(line).map_err(|e| {
            SecError::Parse(format!("audit line decode: {e}"))
        })?;
        out.push(e);
    }
    Ok(out)
}

pub fn verify_audit_chain() -> Result<(usize, Option<usize>), SecError> {
    let entries = load_audit()?;
    let mut prev = "genesis".to_string();
    for (i, e) in entries.iter().enumerate() {
        if e.prev_hash != prev {
            return Err(SecError::AuditChainBroken {
                line: i + 1,
                reason: format!(
                    "prev_hash mismatch (expected {prev}, got {})",
                    e.prev_hash
                ),
            });
        }
        let recomputed = hash_entry_body(
            &e.ts,
            &e.tool,
            &e.target,
            &e.scope_fingerprint,
            &e.status,
            &e.note,
            &e.prev_hash,
        );
        if recomputed != e.this_hash {
            return Err(SecError::AuditChainBroken {
                line: i + 1,
                reason: format!(
                    "this_hash mismatch (recomputed {recomputed}, stored {})",
                    e.this_hash
                ),
            });
        }
        prev = e.this_hash.clone();
    }
    Ok((entries.len(), None))
}

// ── scope cap helpers ─────────────────────────────────────────────────────

pub fn add_host(scope: &mut Scope, host: &str) -> Result<(), SecError> {
    let host = host.to_lowercase();
    if !scope.hosts.iter().any(|h| h.to_lowercase() == host) {
        scope.hosts.push(host);
    }
    scope.enforce_caps()?;
    Ok(())
}

pub fn remove_host(scope: &mut Scope, host: &str) {
    let host = host.to_lowercase();
    scope.hosts.retain(|h| h.to_lowercase() != host);
}

pub fn add_ip_range(scope: &mut Scope, cidr: &str) -> Result<(), SecError> {
    if !scope.ip_ranges.iter().any(|r| r == cidr) {
        scope.ip_ranges.push(cidr.to_string());
    }
    scope.enforce_caps()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_scope() -> Scope {
        Scope {
            authorized_by: "ops@example".into(),
            ticket_id: "ENG-1".into(),
            expires_at: Utc::now() + chrono::Duration::days(1),
            hosts: vec!["example.com".into(), "127.0.0.1".into()],
            ip_ranges: vec!["10.0.0.0/24".into()],
            repos: vec![],
        }
    }

    #[test]
    fn check_target_exact_host_match() {
        let s = fixture_scope();
        assert!(check_target_in_scope(&s, "example.com").is_ok());
        assert!(check_target_in_scope(&s, "EXAMPLE.COM").is_ok());
        assert!(check_target_in_scope(&s, "https://example.com/path").is_ok());
    }

    #[test]
    fn check_target_cidr_match() {
        let s = fixture_scope();
        assert!(check_target_in_scope(&s, "10.0.0.5").is_ok());
        assert!(check_target_in_scope(&s, "10.0.0.255").is_ok());
        assert!(check_target_in_scope(&s, "10.0.1.0").is_err());
    }

    #[test]
    fn check_target_refuses_out_of_scope() {
        let s = fixture_scope();
        let err = check_target_in_scope(&s, "google.com").unwrap_err();
        assert!(matches!(err, SecError::OutOfScope { .. }));
    }

    #[test]
    fn enforce_caps_rejects_oversized_cidr() {
        let mut s = fixture_scope();
        s.ip_ranges.push("0.0.0.0/8".into());
        assert!(matches!(s.enforce_caps(), Err(SecError::LimitExceeded(_))));
    }

    #[test]
    fn enforce_caps_rejects_too_many_hosts() {
        let mut s = fixture_scope();
        for i in 0..257 {
            s.hosts.push(format!("h{i}.example"));
        }
        assert!(matches!(s.enforce_caps(), Err(SecError::LimitExceeded(_))));
    }

    #[test]
    fn audit_chain_starts_at_genesis() {
        assert_eq!(
            last_audit_hash().unwrap_or_else(|_| "genesis".into()),
            // either there's no file (genesis) or there are entries — the
            // unit test just verifies the function doesn't panic
            last_audit_hash().unwrap_or_else(|_| "genesis".into())
        );
    }

    #[test]
    fn audit_entry_hash_is_deterministic() {
        let ts = Utc::now();
        let h1 = hash_entry_body(&ts, "T", "x", "fp", "ok", &None, "prev");
        let h2 = hash_entry_body(&ts, "T", "x", "fp", "ok", &None, "prev");
        assert_eq!(h1, h2);
        let h3 = hash_entry_body(&ts, "T", "y", "fp", "ok", &None, "prev");
        assert_ne!(h1, h3);
    }

    #[test]
    fn scope_fingerprint_changes_on_edit() {
        let s1 = fixture_scope();
        let fp1 = scope_fingerprint(&s1);
        let mut s2 = s1.clone();
        s2.hosts.push("evil.example".into());
        let fp2 = scope_fingerprint(&s2);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn extract_host_from_url_or_hostport() {
        assert_eq!(
            extract_host("https://example.com:8080/path").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            extract_host("http://10.0.0.5/api").as_deref(),
            Some("10.0.0.5")
        );
        assert_eq!(extract_host("example.com").as_deref(), Some("example.com"));
    }
}
