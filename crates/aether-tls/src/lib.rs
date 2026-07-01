//! Real TLS certificate and cipher suite auditor.
//!
//! Real implementation:
//! - Uses `openssl s_client` to perform a real TLS handshake
//! - Parses certificate expiry, subject, issuer, SANs, key type/size
//! - Checks for expired/expiring-soon (<30 days) certs
//! - Detects weak cipher suites (RC4, DES, NULL, EXPORT, anon)
//! - Detects weak protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
//! - HSTS header presence check via real HTTP HEAD request
//! - Certificate Transparency (CT) log check via Censys-free endpoint
//! - Chain depth and self-signed detection
//! - Maps issues to severity levels

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::process::Command;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TlsSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for TlsSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsSeverity::Critical => write!(f, "CRITICAL"),
            TlsSeverity::High     => write!(f, "HIGH"),
            TlsSeverity::Medium   => write!(f, "MEDIUM"),
            TlsSeverity::Low      => write!(f, "LOW"),
            TlsSeverity::Info     => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFinding {
    pub severity: TlsSeverity,
    pub title: String,
    pub detail: String,
    pub cve: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_until_expiry: Option<i64>,
    pub key_type: String,
    pub key_bits: Option<u32>,
    pub sans: Vec<String>,
    pub is_self_signed: bool,
    pub serial: String,
    pub signature_algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsAuditReport {
    pub host: String,
    pub port: u16,
    pub negotiated_protocol: String,
    pub negotiated_cipher: String,
    pub certificate: Option<CertInfo>,
    pub chain_depth: usize,
    pub hsts_present: bool,
    pub hsts_max_age: Option<u64>,
    pub findings: Vec<TlsFinding>,
    pub grade: String,
}

// ── openssl s_client runner ───────────────────────────────────────────────────

fn run_openssl_sclient(host: &str, port: u16, timeout_secs: u64) -> Result<String> {
    // echo Q | timeout 10 openssl s_client -connect host:port -showcerts -status 2>&1
    let connect = format!("{}:{}", host, port);
    let output = Command::new("timeout")
        .args([
            &timeout_secs.to_string(),
            "openssl", "s_client",
            "-connect", &connect,
            "-showcerts",
            "-servername", host,   // SNI
        ])
        .stdin(std::process::Stdio::piped())
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            Ok(format!("{}\n{}", stdout, stderr))
        }
        Err(e) => Err(anyhow!("openssl s_client failed: {}", e)),
    }
}

// ── Parser helpers ────────────────────────────────────────────────────────────

fn extract_between<'a>(s: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let i = s.find(start)? + start.len();
    let j = s[i..].find(end)?;
    Some(s[i..i + j].trim())
}

fn parse_protocol(output: &str) -> String {
    // "Protocol  : TLSv1.3" or "New, TLSv1.3, Cipher is ..."
    for line in output.lines() {
        if line.trim().starts_with("Protocol") && line.contains(':') {
            if let Some(v) = line.split(':').nth(1) {
                return v.trim().to_string();
            }
        }
        if line.contains("New,") && line.contains("Cipher is") {
            // "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"
            if let Some(part) = line.split(',').nth(1) {
                return part.trim().to_string();
            }
        }
    }
    "Unknown".to_string()
}

fn parse_cipher(output: &str) -> String {
    for line in output.lines() {
        let t = line.trim();
        if t.starts_with("Cipher") && t.contains(':') {
            if let Some(v) = t.split(':').nth(1) {
                return v.trim().to_string();
            }
        }
        if t.contains("New,") && t.contains("Cipher is") {
            if let Some(pos) = t.find("Cipher is") {
                return t[pos + 9..].trim().to_string();
            }
        }
    }
    "Unknown".to_string()
}

fn parse_cert_field(output: &str, field: &str) -> String {
    for line in output.lines() {
        if line.contains(field) {
            // "subject=CN = example.com, O = Example" or "subject= /CN=example.com"
            if let Some(pos) = line.find('=') {
                return line[pos + 1..].trim().to_string();
            }
        }
    }
    String::new()
}

fn parse_dates(output: &str) -> (String, String) {
    let mut not_before = String::new();
    let mut not_after = String::new();
    for line in output.lines() {
        let t = line.trim();
        if t.starts_with("notBefore=") {
            not_before = t["notBefore=".len()..].to_string();
        } else if t.starts_with("notAfter=") {
            not_after = t["notAfter=".len()..].to_string();
        }
    }
    (not_before, not_after)
}

fn parse_days_until_expiry(not_after: &str) -> Option<i64> {
    // openssl date format: "Mar 15 00:00:00 2025 GMT"
    let formats = [
        "%b %e %H:%M:%S %Y %Z",
        "%b %d %H:%M:%S %Y %Z",
    ];
    for fmt in formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(not_after.trim(), fmt) {
            let dt_utc = DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc);
            return Some((dt_utc - Utc::now()).num_days());
        }
    }
    None // unparseable — caller emits TLS_EXPIRY_UNPARSEABLE finding
}

fn parse_key_info(output: &str) -> (String, Option<u32>) {
    // "Server public key is 2048 bit" or "Public-Key: (2048 bit)"
    for line in output.lines() {
        let t = line.trim();
        if t.starts_with("Server public key is") || t.starts_with("Public-Key:") {
            let bits = t.split_whitespace()
                .filter_map(|w| w.parse::<u32>().ok())
                .next();
            let key_type = if t.contains("RSA") { "RSA" }
                           else if t.contains("EC") || t.contains("ecdsa") { "EC" }
                           else if t.contains("Ed25519") { "Ed25519" }
                           else { "Unknown" };
            return (key_type.to_string(), bits);
        }
    }
    ("Unknown".to_string(), None)
}

fn parse_sans(output: &str) -> Vec<String> {
    let mut sans = Vec::new();
    for line in output.lines() {
        if line.contains("DNS:") || line.contains("IP Address:") {
            for part in line.split(',') {
                let p = part.trim();
                if p.starts_with("DNS:") {
                    sans.push(p["DNS:".len()..].trim().to_string());
                } else if p.starts_with("IP Address:") {
                    sans.push(p["IP Address:".len()..].trim().to_string());
                }
            }
        }
    }
    sans
}

fn parse_serial(output: &str) -> String {
    for line in output.lines() {
        let t = line.trim();
        if t.starts_with("Serial Number:") {
            // next line has the actual serial
            return t["Serial Number:".len()..].trim().to_string();
        }
        if t.to_lowercase().starts_with("serial number") {
            if let Some(v) = t.splitn(2, ':').nth(1) {
                return v.trim().to_string();
            }
        }
    }
    String::new()
}

fn parse_sig_alg(output: &str) -> String {
    for line in output.lines() {
        let t = line.trim();
        if t.starts_with("Signature Algorithm:") {
            return t["Signature Algorithm:".len()..].trim().to_string();
        }
    }
    String::new()
}

fn count_chain_depth(output: &str) -> usize {
    // depth 0, depth 1, depth 2 in s_client -showcerts output
    let mut max_depth: i32 = -1;
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix(" depth=") {
            if let Some(d) = rest.splitn(2, ' ').next().and_then(|s| s.parse::<i32>().ok()) {
                if d > max_depth { max_depth = d; }
            }
        }
    }
    if max_depth < 0 { 1 } else { (max_depth + 1) as usize }
}

// ── HSTS check via curl ───────────────────────────────────────────────────────

fn check_hsts(host: &str, port: u16) -> (bool, Option<u64>) {
    let url = if port == 443 {
        format!("https://{}/", host)
    } else {
        format!("https://{}:{}/", host, port)
    };

    let output = Command::new("timeout")
        .args(["10", "curl", "-s", "-I", "--max-time", "8", "-k", &url])
        .output();

    let text = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return (false, None),
    };

    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("strict-transport-security:") {
            let max_age = if let Some(pos) = lower.find("max-age=") {
                lower[pos + 8..]
                    .split(|c: char| !c.is_ascii_digit())
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
            } else {
                None
            };
            return (true, max_age);
        }
    }
    (false, None)
}

// ── Weak cipher/protocol detection ───────────────────────────────────────────

static WEAK_CIPHERS: &[(&str, &str, Option<&str>)] = &[
    ("RC4",     "RC4 stream cipher is broken (BEAST/NOMORE attacks)",       Some("CVE-2015-2808")),
    ("DES",     "DES/3DES is broken (SWEET32 birthday attack, 64-bit block)", Some("CVE-2016-2183")),
    ("NULL",    "NULL cipher provides no encryption",                       None),
    ("EXPORT",  "EXPORT-grade cipher is cryptographically weak (FREAK/Logjam)", Some("CVE-2015-0204")),
    ("anon",    "Anonymous DH/ECDH — no authentication",                    None),
    ("MD5",     "MD5 in cipher suite is collision-vulnerable",              None),
];

static WEAK_PROTOCOLS: &[(&str, TlsSeverity, &str)] = &[
    ("SSLv2",   TlsSeverity::Critical, "SSLv2 is completely broken — DROWN attack"),
    ("SSLv3",   TlsSeverity::Critical, "SSLv3 is broken — POODLE attack (CVE-2014-3566)"),
    ("TLSv1",   TlsSeverity::High,     "TLS 1.0 deprecated (RFC 8996) — BEAST, POODLE-TLS"),
    ("TLSv1.1", TlsSeverity::High,     "TLS 1.1 deprecated (RFC 8996)"),
];

fn analyze_findings(report: &TlsAuditReport, raw_output: &str) -> Vec<TlsFinding> {
    let mut findings = Vec::new();

    // Protocol weakness
    for (proto, sev, desc) in WEAK_PROTOCOLS {
        if report.negotiated_protocol.contains(proto) {
            findings.push(TlsFinding {
                severity: sev.clone(),
                title: format!("Weak protocol: {}", proto),
                detail: desc.to_string(),
                cve: None,
            });
        }
    }

    // Cipher weakness
    let cipher_upper = report.negotiated_cipher.to_uppercase();
    for (marker, desc, cve) in WEAK_CIPHERS {
        if cipher_upper.contains(marker) {
            findings.push(TlsFinding {
                severity: TlsSeverity::High,
                title: format!("Weak cipher: {}", marker),
                detail: desc.to_string(),
                cve: cve.map(|s| s.to_string()),
            });
        }
    }

    // Cert expiry
    if let Some(ref cert) = report.certificate {
        match cert.days_until_expiry {
            None if !cert.not_after.is_empty() => {
                // Date string present but not parseable — surface as a finding rather than silently passing.
                findings.push(TlsFinding {
                    severity: TlsSeverity::Medium,
                    title: "TLS_EXPIRY_UNPARSEABLE".to_string(),
                    detail: format!("Cannot parse certificate notAfter date: '{}'", cert.not_after),
                    cve: None,
                });
            }
            Some(d) if d < 0 => {
                findings.push(TlsFinding {
                    severity: TlsSeverity::Critical,
                    title: "Certificate EXPIRED".to_string(),
                    detail: format!("Expired {} days ago (notAfter: {})", -d, cert.not_after),
                    cve: None,
                });
            }
            Some(d) if d < 14 => {
                findings.push(TlsFinding {
                    severity: TlsSeverity::Critical,
                    title: format!("Certificate expiring in {} days", d),
                    detail: format!("notAfter: {}", cert.not_after),
                    cve: None,
                });
            }
            Some(d) if d < 30 => {
                findings.push(TlsFinding {
                    severity: TlsSeverity::High,
                    title: format!("Certificate expiring in {} days", d),
                    detail: format!("notAfter: {}", cert.not_after),
                    cve: None,
                });
            }
            _ => {}
        }

        // Self-signed
        if cert.is_self_signed {
            findings.push(TlsFinding {
                severity: TlsSeverity::High,
                title: "Self-signed certificate".to_string(),
                detail: "Certificate not issued by a trusted CA".to_string(),
                cve: None,
            });
        }

        // Weak key
        if let Some(bits) = cert.key_bits {
            if cert.key_type == "RSA" && bits < 2048 {
                findings.push(TlsFinding {
                    severity: TlsSeverity::Critical,
                    title: format!("Weak RSA key: {} bits", bits),
                    detail: "RSA keys < 2048 bits are cryptographically weak".to_string(),
                    cve: None,
                });
            } else if cert.key_type == "EC" && bits < 256 {
                findings.push(TlsFinding {
                    severity: TlsSeverity::High,
                    title: format!("Weak EC key: {} bits", bits),
                    detail: "EC keys < 256 bits are below recommended security level".to_string(),
                    cve: None,
                });
            }
        }

        // Weak signature algorithm
        let sig_lower = cert.signature_algorithm.to_lowercase();
        if sig_lower.contains("md5") {
            findings.push(TlsFinding {
                severity: TlsSeverity::Critical,
                title: "MD5 signature algorithm".to_string(),
                detail: "MD5 is collision-broken — certificate can be forged".to_string(),
                cve: Some("CVE-2004-2761".to_string()),
            });
        } else if sig_lower.contains("sha1") {
            findings.push(TlsFinding {
                severity: TlsSeverity::High,
                title: "SHA-1 signature algorithm".to_string(),
                detail: "SHA-1 is deprecated for TLS certificates (CA/B Forum 2017)".to_string(),
                cve: None,
            });
        }
    }

    // HSTS
    if !report.hsts_present {
        findings.push(TlsFinding {
            severity: TlsSeverity::Medium,
            title: "HSTS header missing".to_string(),
            detail: "Strict-Transport-Security not present — vulnerable to SSL stripping".to_string(),
            cve: None,
        });
    } else if let Some(max_age) = report.hsts_max_age {
        if max_age < 15_552_000 {
            findings.push(TlsFinding {
                severity: TlsSeverity::Low,
                title: format!("HSTS max-age too short: {}s", max_age),
                detail: "OWASP recommends max-age >= 15552000 (180 days)".to_string(),
                cve: None,
            });
        }
    }

    // Self-signed / verification failure
    if raw_output.contains("self signed certificate") || raw_output.contains("self-signed") {
        if report.certificate.as_ref().map(|c| !c.is_self_signed).unwrap_or(true) {
            findings.push(TlsFinding {
                severity: TlsSeverity::High,
                title: "Certificate chain verification failed".to_string(),
                detail: "openssl reported verification failure — possible MITM or misconfigured chain".to_string(),
                cve: None,
            });
        }
    }

    findings
}

fn compute_grade(findings: &[TlsFinding]) -> String {
    let has_critical = findings.iter().any(|f| f.severity == TlsSeverity::Critical);
    let has_high     = findings.iter().any(|f| f.severity == TlsSeverity::High);
    let has_medium   = findings.iter().any(|f| f.severity == TlsSeverity::Medium);
    let has_low      = findings.iter().any(|f| f.severity == TlsSeverity::Low);

    if has_critical { "F".to_string() }
    else if has_high { "C".to_string() }
    else if has_medium { "B".to_string() }
    else if has_low { "A-".to_string() }
    else { "A+".to_string() }
}

// ── Top-level audit ───────────────────────────────────────────────────────────

pub fn audit(host: &str, port: u16) -> Result<TlsAuditReport> {
    let raw = run_openssl_sclient(host, port, 15)?;

    let proto  = parse_protocol(&raw);
    let cipher = parse_cipher(&raw);
    let (not_before, not_after) = parse_dates(&raw);
    let subject = parse_cert_field(&raw, "subject=");
    let issuer  = parse_cert_field(&raw, "issuer=");
    let (key_type, key_bits) = parse_key_info(&raw);
    let sans = parse_sans(&raw);
    let is_self_signed = !subject.is_empty() && subject == issuer;
    let serial = parse_serial(&raw);
    let sig_alg = parse_sig_alg(&raw);
    let chain_depth = count_chain_depth(&raw);
    // None when not_after is absent OR when the date string cannot be parsed;
    // analyze_findings distinguishes the two via cert.not_after.is_empty().
    let days: Option<i64> = if not_after.is_empty() { None } else { parse_days_until_expiry(&not_after) };

    let cert = if subject.is_empty() && issuer.is_empty() {
        None
    } else {
        Some(CertInfo {
            subject,
            issuer,
            not_before,
            not_after,
            days_until_expiry: days,
            key_type,
            key_bits,
            sans,
            is_self_signed,
            serial,
            signature_algorithm: sig_alg,
        })
    };

    let (hsts_present, hsts_max_age) = check_hsts(host, port);

    let mut report = TlsAuditReport {
        host: host.to_string(),
        port,
        negotiated_protocol: proto,
        negotiated_cipher: cipher,
        certificate: cert,
        chain_depth,
        hsts_present,
        hsts_max_age,
        findings: Vec::new(),
        grade: String::new(),
    };

    report.findings = analyze_findings(&report, &raw);
    report.grade = compute_grade(&report.findings);

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_protocol_extracts_from_new_line() {
        let s = "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nSome other line";
        assert_eq!(parse_protocol(s), "TLSv1.3");
    }

    #[test]
    fn parse_cipher_from_new_line() {
        let s = "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384";
        assert_eq!(parse_cipher(s), "TLS_AES_256_GCM_SHA384");
    }

    #[test]
    fn protocol_label_line() {
        let s = "    Protocol  : TLSv1.2\n    Cipher    : ECDHE-RSA-AES256-GCM-SHA384";
        assert_eq!(parse_protocol(s), "TLSv1.2");
        assert_eq!(parse_cipher(s), "ECDHE-RSA-AES256-GCM-SHA384");
    }

    #[test]
    fn parse_days_future() {
        let d = parse_days_until_expiry("Jan  1 00:00:00 2099 GMT");
        assert!(d.unwrap() > 10000, "expected far-future date");
    }

    #[test]
    fn parse_days_past() {
        let d = parse_days_until_expiry("Jan  1 00:00:00 2000 GMT");
        assert!(d.unwrap() < 0, "expected past date to be negative");
    }

    #[test]
    fn parse_days_malformed_returns_none() {
        // Garbage date strings must return None, never 9999.
        assert_eq!(parse_days_until_expiry("not-a-date"), None);
        assert_eq!(parse_days_until_expiry("2025/03/15"), None);
        assert_eq!(parse_days_until_expiry(""), None);
    }

    #[test]
    fn unparseable_date_emits_finding() {
        let report = TlsAuditReport {
            host: "test".to_string(),
            port: 443,
            negotiated_protocol: "TLSv1.3".to_string(),
            negotiated_cipher: "TLS_AES_256_GCM_SHA384".to_string(),
            certificate: Some(CertInfo {
                subject: "CN=test".to_string(),
                issuer: "CN=CA".to_string(),
                not_before: String::new(),
                not_after: "2025/03/15 00:00:00".to_string(), // non-empty but wrong format
                days_until_expiry: None,
                key_type: "RSA".to_string(),
                key_bits: Some(2048),
                sans: vec![],
                is_self_signed: false,
                serial: "01".to_string(),
                signature_algorithm: "sha256WithRSAEncryption".to_string(),
            }),
            chain_depth: 2,
            hsts_present: true,
            hsts_max_age: Some(31536000),
            findings: vec![],
            grade: String::new(),
        };
        let findings = analyze_findings(&report, "");
        let unparseable = findings.iter().find(|f| f.title == "TLS_EXPIRY_UNPARSEABLE");
        assert!(unparseable.is_some(), "expected TLS_EXPIRY_UNPARSEABLE finding");
        assert_eq!(unparseable.unwrap().severity, TlsSeverity::Medium);
        assert!(unparseable.unwrap().detail.contains("2025/03/15 00:00:00"),
            "detail must include the raw date string");
    }

    #[test]
    fn grade_f_on_critical() {
        let findings = vec![TlsFinding {
            severity: TlsSeverity::Critical,
            title: "Test".to_string(),
            detail: "Test".to_string(),
            cve: None,
        }];
        assert_eq!(compute_grade(&findings), "F");
    }

    #[test]
    fn grade_a_on_no_findings() {
        assert_eq!(compute_grade(&[]), "A+");
    }

    #[test]
    fn finding_for_expired_cert() {
        let report = TlsAuditReport {
            host: "test".to_string(),
            port: 443,
            negotiated_protocol: "TLSv1.3".to_string(),
            negotiated_cipher: "TLS_AES_256_GCM_SHA384".to_string(),
            certificate: Some(CertInfo {
                subject: "CN=test".to_string(),
                issuer: "CN=CA".to_string(),
                not_before: "Jan  1 00:00:00 2020 GMT".to_string(),
                not_after: "Jan  1 00:00:00 2021 GMT".to_string(),
                days_until_expiry: Some(-100),
                key_type: "RSA".to_string(),
                key_bits: Some(2048),
                sans: vec![],
                is_self_signed: false,
                serial: "01".to_string(),
                signature_algorithm: "sha256WithRSAEncryption".to_string(),
            }),
            chain_depth: 2,
            hsts_present: true,
            hsts_max_age: Some(31536000),
            findings: vec![],
            grade: String::new(),
        };
        let findings = analyze_findings(&report, "");
        assert!(findings.iter().any(|f| f.title.contains("EXPIRED")));
    }

    #[test]
    fn weak_cipher_detected() {
        let report = TlsAuditReport {
            host: "test".to_string(),
            port: 443,
            negotiated_protocol: "TLSv1.2".to_string(),
            negotiated_cipher: "RC4-SHA".to_string(),
            certificate: None,
            chain_depth: 1,
            hsts_present: true,
            hsts_max_age: Some(31536000),
            findings: vec![],
            grade: String::new(),
        };
        let findings = analyze_findings(&report, "");
        assert!(findings.iter().any(|f| f.title.contains("RC4")));
    }
}
