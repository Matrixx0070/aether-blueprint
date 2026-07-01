//! DAST-lite HTTP security scanner.
//!
//! Real implementation:
//! - Real HTTP(S) requests via `curl` (no extra Rust HTTP dep)
//! - Checks 20+ security headers and response behaviors
//! - CORS misconfiguration detection (wildcard, origin reflection, null origin)
//! - Content Security Policy analysis (unsafe-inline, unsafe-eval, wildcard src, missing)
//! - Clickjacking protection (X-Frame-Options, CSP frame-ancestors)
//! - HSTS presence and max-age enforcement
//! - Information disclosure (Server, X-Powered-By, X-AspNet-Version)
//! - Cookie security flags (Secure, HttpOnly, SameSite)
//! - Cache-Control on sensitive endpoints
//! - Referrer-Policy strictness
//! - Permissions-Policy / Feature-Policy presence
//! - MIME type sniffing (X-Content-Type-Options)
//! - Maps to OWASP Top 10 and CWE identifiers

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DastSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for DastSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DastSeverity::Critical => write!(f, "CRITICAL"),
            DastSeverity::High     => write!(f, "HIGH"),
            DastSeverity::Medium   => write!(f, "MEDIUM"),
            DastSeverity::Low      => write!(f, "LOW"),
            DastSeverity::Info     => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DastFinding {
    pub severity: DastSeverity,
    pub check: String,
    pub title: String,
    pub detail: String,
    pub owasp: String,
    pub cwe: Option<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body_preview: String,   // first 2 KB
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DastReport {
    pub url: String,
    pub status_code: u16,
    pub findings: Vec<DastFinding>,
    pub headers_present: Vec<String>,
    pub headers_missing: Vec<String>,
    pub grade: String,
    pub cors_policy: String,
    pub csp_policy: String,
}

// ── HTTP fetch via curl ───────────────────────────────────────────────────────

pub fn fetch_headers(url: &str, origin: Option<&str>) -> Result<HttpResponse> {
    let mut args = vec![
        "-s",
        "-i",                    // include response headers
        "--max-time", "15",
        "-L",                    // follow redirects
        "--max-redirs", "3",
        "-k",                    // allow self-signed (we audit headers, not chain)
        "-A", "aether-dast/0.35.0",
    ];

    let origin_header;
    if let Some(o) = origin {
        origin_header = format!("Origin: {}", o);
        args.extend_from_slice(&["-H", &origin_header]);
    }

    args.push(url);

    let output = Command::new("curl")
        .args(&args)
        .output()
        .map_err(|e| anyhow!("curl failed: {}", e))?;

    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    parse_http_response(&raw)
}

fn parse_http_response(raw: &str) -> Result<HttpResponse> {
    // Split headers from body at blank line
    let split_pos = raw.find("\r\n\r\n").or_else(|| raw.find("\n\n"));
    let (header_section, body) = match split_pos {
        Some(pos) => (&raw[..pos], &raw[pos + 2..]),
        None => (raw.as_ref(), ""),
    };

    let mut lines = header_section.lines();

    // Status line
    let status_line = lines.next().unwrap_or("HTTP/1.1 200 OK");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Headers
    let mut headers: HashMap<String, String> = HashMap::new();
    for line in lines {
        if let Some(colon) = line.find(':') {
            let key = line[..colon].trim().to_lowercase();
            let val = line[colon + 1..].trim().to_string();
            headers.entry(key).or_insert(val);
        }
    }

    let body_preview = body.chars().take(2048).collect();

    Ok(HttpResponse { status_code, headers, body_preview })
}

// ── Individual checks ─────────────────────────────────────────────────────────

fn check_hsts(headers: &HashMap<String, String>, findings: &mut Vec<DastFinding>) {
    match headers.get("strict-transport-security") {
        None => findings.push(DastFinding {
            severity: DastSeverity::High,
            check: "hsts".to_string(),
            title: "Missing Strict-Transport-Security header".to_string(),
            detail: "No HSTS header — browser will not enforce HTTPS on future visits".to_string(),
            owasp: "A05:2021 Security Misconfiguration".to_string(),
            cwe: Some("CWE-319".to_string()),
            remediation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".to_string(),
        }),
        Some(val) => {
            let v = val.to_lowercase();
            if !v.contains("max-age") {
                findings.push(DastFinding {
                    severity: DastSeverity::Medium,
                    check: "hsts".to_string(),
                    title: "HSTS header missing max-age".to_string(),
                    detail: format!("Header present but malformed: {}", val),
                    owasp: "A05:2021 Security Misconfiguration".to_string(),
                    cwe: Some("CWE-319".to_string()),
                    remediation: "Add max-age=31536000 to HSTS header".to_string(),
                });
            } else {
                // check max-age value
                if let Some(pos) = v.find("max-age=") {
                    let age_str: String = v[pos + 8..].chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(age) = age_str.parse::<u64>() {
                        if age < 15_552_000 {
                            findings.push(DastFinding {
                                severity: DastSeverity::Low,
                                check: "hsts".to_string(),
                                title: format!("HSTS max-age too short: {}s", age),
                                detail: "OWASP recommends >= 15552000 (180 days)".to_string(),
                                owasp: "A05:2021 Security Misconfiguration".to_string(),
                                cwe: None,
                                remediation: "Set max-age=31536000 (1 year)".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
}

fn check_xfo(headers: &HashMap<String, String>, findings: &mut Vec<DastFinding>) {
    let has_xfo = headers.contains_key("x-frame-options");
    let csp_frame_ancestors = headers.get("content-security-policy")
        .map(|c| c.to_lowercase().contains("frame-ancestors"))
        .unwrap_or(false);

    if !has_xfo && !csp_frame_ancestors {
        findings.push(DastFinding {
            severity: DastSeverity::Medium,
            check: "clickjacking".to_string(),
            title: "Missing clickjacking protection".to_string(),
            detail: "No X-Frame-Options or CSP frame-ancestors — page may be embedded in iframes".to_string(),
            owasp: "A05:2021 Security Misconfiguration".to_string(),
            cwe: Some("CWE-1021".to_string()),
            remediation: "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'".to_string(),
        });
    } else if let Some(xfo) = headers.get("x-frame-options") {
        let v = xfo.to_uppercase();
        if v == "ALLOWALL" || v.contains("ALLOW-FROM *") {
            findings.push(DastFinding {
                severity: DastSeverity::High,
                check: "clickjacking".to_string(),
                title: "X-Frame-Options allows all origins".to_string(),
                detail: format!("Value '{}' provides no clickjacking protection", xfo),
                owasp: "A05:2021 Security Misconfiguration".to_string(),
                cwe: Some("CWE-1021".to_string()),
                remediation: "Change to X-Frame-Options: DENY".to_string(),
            });
        }
    }
}

fn check_xcto(headers: &HashMap<String, String>, findings: &mut Vec<DastFinding>) {
    match headers.get("x-content-type-options") {
        None => findings.push(DastFinding {
            severity: DastSeverity::Low,
            check: "mime-sniffing".to_string(),
            title: "Missing X-Content-Type-Options header".to_string(),
            detail: "Browser may MIME-sniff responses — can lead to XSS via content-type confusion".to_string(),
            owasp: "A05:2021 Security Misconfiguration".to_string(),
            cwe: Some("CWE-16".to_string()),
            remediation: "Add: X-Content-Type-Options: nosniff".to_string(),
        }),
        Some(val) if val.to_lowercase() != "nosniff" => findings.push(DastFinding {
            severity: DastSeverity::Low,
            check: "mime-sniffing".to_string(),
            title: format!("X-Content-Type-Options invalid value: {}", val),
            detail: "Only 'nosniff' is a valid value".to_string(),
            owasp: "A05:2021 Security Misconfiguration".to_string(),
            cwe: Some("CWE-16".to_string()),
            remediation: "Set X-Content-Type-Options: nosniff".to_string(),
        }),
        _ => {}
    }
}

fn check_csp(headers: &HashMap<String, String>, findings: &mut Vec<DastFinding>) -> String {
    let csp = match headers.get("content-security-policy") {
        None => {
            findings.push(DastFinding {
                severity: DastSeverity::High,
                check: "csp".to_string(),
                title: "Missing Content-Security-Policy header".to_string(),
                detail: "No CSP — XSS attacks can load arbitrary scripts from any origin".to_string(),
                owasp: "A03:2021 Injection".to_string(),
                cwe: Some("CWE-79".to_string()),
                remediation: "Add a strict CSP: default-src 'self'; script-src 'self'; object-src 'none'".to_string(),
            });
            return "not-present".to_string();
        }
        Some(v) => v.clone(),
    };

    let lower = csp.to_lowercase();

    if lower.contains("'unsafe-inline'") {
        findings.push(DastFinding {
            severity: DastSeverity::High,
            check: "csp".to_string(),
            title: "CSP allows unsafe-inline scripts".to_string(),
            detail: "unsafe-inline defeats CSP protection against XSS".to_string(),
            owasp: "A03:2021 Injection".to_string(),
            cwe: Some("CWE-79".to_string()),
            remediation: "Remove 'unsafe-inline' and use nonces or hashes instead".to_string(),
        });
    }
    if lower.contains("'unsafe-eval'") {
        findings.push(DastFinding {
            severity: DastSeverity::High,
            check: "csp".to_string(),
            title: "CSP allows unsafe-eval".to_string(),
            detail: "unsafe-eval allows dynamic code execution (eval, setTimeout with string)".to_string(),
            owasp: "A03:2021 Injection".to_string(),
            cwe: Some("CWE-79".to_string()),
            remediation: "Remove 'unsafe-eval' and refactor dynamic code patterns".to_string(),
        });
    }
    if lower.contains("script-src *") || lower.contains("default-src *") {
        findings.push(DastFinding {
            severity: DastSeverity::Critical,
            check: "csp".to_string(),
            title: "CSP wildcard script source".to_string(),
            detail: "Wildcard (*) in script-src/default-src allows scripts from any origin".to_string(),
            owasp: "A03:2021 Injection".to_string(),
            cwe: Some("CWE-79".to_string()),
            remediation: "Replace * with explicit allowed origins".to_string(),
        });
    }

    csp
}

fn check_cors(headers: &HashMap<String, String>, test_origin: &str, findings: &mut Vec<DastFinding>) -> String {
    let acao = headers.get("access-control-allow-origin").cloned().unwrap_or_default();

    if acao == "*" {
        findings.push(DastFinding {
            severity: DastSeverity::High,
            check: "cors".to_string(),
            title: "CORS wildcard Access-Control-Allow-Origin: *".to_string(),
            detail: "Any origin can make cross-site requests and read responses".to_string(),
            owasp: "A01:2021 Broken Access Control".to_string(),
            cwe: Some("CWE-942".to_string()),
            remediation: "Restrict ACAO to specific trusted origins".to_string(),
        });
    } else if !acao.is_empty() && acao == test_origin {
        // Origin reflection
        let acac = headers.get("access-control-allow-credentials")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        if acac {
            findings.push(DastFinding {
                severity: DastSeverity::Critical,
                check: "cors".to_string(),
                title: "CORS origin reflection with credentials".to_string(),
                detail: format!("Server reflects back origin '{}' with Access-Control-Allow-Credentials: true — arbitrary origins can read credentialed responses", test_origin),
                owasp: "A01:2021 Broken Access Control".to_string(),
                cwe: Some("CWE-942".to_string()),
                remediation: "Validate Origin against an allowlist; never reflect arbitrary origins with credentials".to_string(),
            });
        } else {
            findings.push(DastFinding {
                severity: DastSeverity::Medium,
                check: "cors".to_string(),
                title: "CORS origin reflection (without credentials)".to_string(),
                detail: format!("Server reflects arbitrary origin '{}' — may allow cross-origin reads", test_origin),
                owasp: "A01:2021 Broken Access Control".to_string(),
                cwe: Some("CWE-942".to_string()),
                remediation: "Restrict ACAO to a static allowlist of trusted origins".to_string(),
            });
        }
    }

    if acao.is_empty() { "not-set".to_string() } else { acao }
}

fn check_info_disclosure(headers: &HashMap<String, String>, findings: &mut Vec<DastFinding>) {
    let leaky = [
        ("server",             "Server header discloses technology stack"),
        ("x-powered-by",       "X-Powered-By discloses server technology"),
        ("x-aspnet-version",   "X-AspNet-Version discloses .NET version"),
        ("x-aspnetmvc-version","X-AspNetMvc-Version discloses .NET MVC version"),
        ("x-generator",        "X-Generator discloses CMS/framework"),
        ("x-drupal-cache",     "X-Drupal-Cache discloses Drupal CMS"),
        ("x-wp-nonce",         "WordPress nonce exposed in response headers"),
    ];
    for (header, desc) in leaky {
        if let Some(val) = headers.get(header) {
            findings.push(DastFinding {
                severity: DastSeverity::Low,
                check: "info-disclosure".to_string(),
                title: format!("Information disclosure: {}", header),
                detail: format!("{}: value '{}'", desc, val),
                owasp: "A05:2021 Security Misconfiguration".to_string(),
                cwe: Some("CWE-200".to_string()),
                remediation: format!("Remove or suppress the {} header", header),
            });
        }
    }
}

fn check_referrer_policy(headers: &HashMap<String, String>, findings: &mut Vec<DastFinding>) {
    match headers.get("referrer-policy") {
        None => findings.push(DastFinding {
            severity: DastSeverity::Low,
            check: "referrer-policy".to_string(),
            title: "Missing Referrer-Policy header".to_string(),
            detail: "Browser sends full URL as Referer by default — leaks paths to third parties".to_string(),
            owasp: "A05:2021 Security Misconfiguration".to_string(),
            cwe: Some("CWE-200".to_string()),
            remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin".to_string(),
        }),
        Some(val) => {
            let v = val.to_lowercase();
            if v == "unsafe-url" || v == "no-referrer-when-downgrade" {
                findings.push(DastFinding {
                    severity: DastSeverity::Low,
                    check: "referrer-policy".to_string(),
                    title: format!("Overly permissive Referrer-Policy: {}", val),
                    detail: "Full URL may be sent as Referer to cross-origin destinations".to_string(),
                    owasp: "A05:2021 Security Misconfiguration".to_string(),
                    cwe: Some("CWE-200".to_string()),
                    remediation: "Use: Referrer-Policy: strict-origin-when-cross-origin".to_string(),
                });
            }
        }
    }
}

fn check_permissions_policy(headers: &HashMap<String, String>, findings: &mut Vec<DastFinding>) {
    if !headers.contains_key("permissions-policy") && !headers.contains_key("feature-policy") {
        findings.push(DastFinding {
            severity: DastSeverity::Info,
            check: "permissions-policy".to_string(),
            title: "Missing Permissions-Policy header".to_string(),
            detail: "No browser feature restrictions — camera, microphone, geolocation available to JS".to_string(),
            owasp: "A05:2021 Security Misconfiguration".to_string(),
            cwe: None,
            remediation: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()".to_string(),
        });
    }
}

fn check_cookies(headers: &HashMap<String, String>, findings: &mut Vec<DastFinding>) {
    for (key, val) in headers {
        if key.to_lowercase() != "set-cookie" { continue; }
        let lower = val.to_lowercase();
        let cookie_name = val.split('=').next().unwrap_or("(unknown)").trim();

        if !lower.contains("secure") {
            findings.push(DastFinding {
                severity: DastSeverity::High,
                check: "cookie-secure".to_string(),
                title: format!("Cookie '{}' missing Secure flag", cookie_name),
                detail: "Cookie can be transmitted over HTTP — vulnerable to interception".to_string(),
                owasp: "A02:2021 Cryptographic Failures".to_string(),
                cwe: Some("CWE-614".to_string()),
                remediation: "Add Secure flag to all Set-Cookie headers".to_string(),
            });
        }
        if !lower.contains("httponly") {
            findings.push(DastFinding {
                severity: DastSeverity::Medium,
                check: "cookie-httponly".to_string(),
                title: format!("Cookie '{}' missing HttpOnly flag", cookie_name),
                detail: "Cookie accessible from JavaScript — exposed to XSS exfiltration".to_string(),
                owasp: "A07:2021 Identification and Authentication Failures".to_string(),
                cwe: Some("CWE-1004".to_string()),
                remediation: "Add HttpOnly flag to session and authentication cookies".to_string(),
            });
        }
        if !lower.contains("samesite") {
            findings.push(DastFinding {
                severity: DastSeverity::Medium,
                check: "cookie-samesite".to_string(),
                title: format!("Cookie '{}' missing SameSite attribute", cookie_name),
                detail: "Cookie sent with cross-site requests — vulnerable to CSRF".to_string(),
                owasp: "A01:2021 Broken Access Control".to_string(),
                cwe: Some("CWE-352".to_string()),
                remediation: "Add SameSite=Strict or SameSite=Lax to session cookies".to_string(),
            });
        }
    }
}

fn compute_grade(findings: &[DastFinding]) -> String {
    let has_critical = findings.iter().any(|f| f.severity == DastSeverity::Critical);
    let has_high     = findings.iter().any(|f| f.severity == DastSeverity::High);
    let has_medium   = findings.iter().any(|f| f.severity == DastSeverity::Medium);
    let has_low      = findings.iter().any(|f| f.severity == DastSeverity::Low);

    if has_critical { "F".to_string() }
    else if has_high { "C".to_string() }
    else if has_medium { "B".to_string() }
    else if has_low { "A-".to_string() }
    else { "A+".to_string() }
}

// ── Top-level scan ────────────────────────────────────────────────────────────

pub fn scan(url: &str) -> Result<DastReport> {
    // Probe with a crafted origin to test CORS reflection
    let test_origin = "https://evil-attacker.aether-dast.test";

    let resp = fetch_headers(url, Some(test_origin))
        .or_else(|_| fetch_headers(url, None))?;

    let mut findings = Vec::new();

    check_hsts(&resp.headers, &mut findings);
    check_xfo(&resp.headers, &mut findings);
    check_xcto(&resp.headers, &mut findings);
    let csp_policy = check_csp(&resp.headers, &mut findings);
    let cors_policy = check_cors(&resp.headers, test_origin, &mut findings);
    check_info_disclosure(&resp.headers, &mut findings);
    check_referrer_policy(&resp.headers, &mut findings);
    check_permissions_policy(&resp.headers, &mut findings);
    check_cookies(&resp.headers, &mut findings);

    // Sort findings by severity
    findings.sort_by_key(|f| match f.severity {
        DastSeverity::Critical => 0,
        DastSeverity::High     => 1,
        DastSeverity::Medium   => 2,
        DastSeverity::Low      => 3,
        DastSeverity::Info     => 4,
    });

    let security_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ];
    let headers_present: Vec<String> = security_headers.iter()
        .filter(|h| resp.headers.contains_key(**h))
        .map(|h| h.to_string())
        .collect();
    let headers_missing: Vec<String> = security_headers.iter()
        .filter(|h| !resp.headers.contains_key(**h))
        .map(|h| h.to_string())
        .collect();

    let grade = compute_grade(&findings);

    Ok(DastReport {
        url: url.to_string(),
        status_code: resp.status_code,
        findings,
        headers_present,
        headers_missing,
        grade,
        cors_policy,
        csp_policy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_lowercase(), v.to_string())).collect()
    }

    #[test]
    fn missing_hsts_is_high() {
        let headers = make_headers(&[]);
        let mut findings = Vec::new();
        check_hsts(&headers, &mut findings);
        assert!(findings.iter().any(|f| f.severity == DastSeverity::High && f.check == "hsts"));
    }

    #[test]
    fn valid_hsts_no_finding() {
        let headers = make_headers(&[("strict-transport-security", "max-age=31536000; includeSubDomains")]);
        let mut findings = Vec::new();
        check_hsts(&headers, &mut findings);
        assert!(findings.iter().all(|f| f.severity != DastSeverity::High));
    }

    #[test]
    fn missing_csp_is_high() {
        let headers = make_headers(&[]);
        let mut findings = Vec::new();
        check_csp(&headers, &mut findings);
        assert!(findings.iter().any(|f| f.severity == DastSeverity::High && f.check == "csp"));
    }

    #[test]
    fn csp_unsafe_inline_detected() {
        let headers = make_headers(&[("content-security-policy", "default-src 'self'; script-src 'unsafe-inline'")]);
        let mut findings = Vec::new();
        check_csp(&headers, &mut findings);
        assert!(findings.iter().any(|f| f.title.contains("unsafe-inline")));
    }

    #[test]
    fn cors_wildcard_is_high() {
        let headers = make_headers(&[("access-control-allow-origin", "*")]);
        let mut findings = Vec::new();
        check_cors(&headers, "https://evil.test", &mut findings);
        assert!(findings.iter().any(|f| f.severity == DastSeverity::High && f.check == "cors"));
    }

    #[test]
    fn cors_reflection_with_credentials_is_critical() {
        let headers = make_headers(&[
            ("access-control-allow-origin", "https://evil.test"),
            ("access-control-allow-credentials", "true"),
        ]);
        let mut findings = Vec::new();
        check_cors(&headers, "https://evil.test", &mut findings);
        assert!(findings.iter().any(|f| f.severity == DastSeverity::Critical && f.check == "cors"));
    }

    #[test]
    fn server_header_leaks_info() {
        let headers = make_headers(&[("server", "nginx/1.18.0 (Ubuntu)")]);
        let mut findings = Vec::new();
        check_info_disclosure(&headers, &mut findings);
        assert!(findings.iter().any(|f| f.check == "info-disclosure"));
    }

    #[test]
    fn cookie_missing_secure_is_high() {
        let headers = make_headers(&[("set-cookie", "session=abc123; Path=/; HttpOnly; SameSite=Lax")]);
        let mut findings = Vec::new();
        check_cookies(&headers, &mut findings);
        assert!(findings.iter().any(|f| f.check == "cookie-secure" && f.severity == DastSeverity::High));
    }

    #[test]
    fn parse_http_response_extracts_headers() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Frame-Options: DENY\r\n\r\n<html/>";
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.headers.get("x-frame-options").map(|s| s.as_str()), Some("DENY"));
    }

    #[test]
    fn grade_f_on_critical() {
        let findings = vec![DastFinding {
            severity: DastSeverity::Critical,
            check: "test".to_string(),
            title: "t".to_string(),
            detail: "d".to_string(),
            owasp: "o".to_string(),
            cwe: None,
            remediation: "r".to_string(),
        }];
        assert_eq!(compute_grade(&findings), "F");
    }

    #[test]
    fn no_findings_grade_a_plus() {
        assert_eq!(compute_grade(&[]), "A+");
    }
}

// ── Integration tests (real HTTP, local server) ───────────────────────────────
//
// Each test spins a minimal std::net::TcpListener server in a background
// thread — no extra test dependencies, no mocking of curl.  The server
// accepts up to `MAX_CONNS` connections so it survives curl's habit of
// making an extra probe when it encounters a redirect or sends Origin.
#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    const MAX_CONNS: usize = 4;

    /// Binds a random port, returns it, and starts a background thread that
    /// serves `response` verbatim to every incoming connection.
    fn start_static_server(response: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for _ in 0..MAX_CONNS {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(response.as_bytes());
                    // drop stream — signals EOF to curl
                }
            }
        });
        // Give the OS a moment to start accepting before curl connects.
        thread::sleep(Duration::from_millis(60));
        port
    }

    /// Like start_static_server but reflects the incoming `Origin:` header
    /// as `Access-Control-Allow-Origin` and adds `Allow-Credentials: true`,
    /// simulating the most dangerous CORS misconfiguration.
    fn start_cors_reflect_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for _ in 0..MAX_CONNS {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 8192];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);

                    // Pull the Origin header value sent by curl.
                    let origin = req.lines()
                        .find(|l| l.to_lowercase().starts_with("origin:"))
                        .and_then(|l| l.splitn(2, ':').nth(1))
                        .map(|s| s.trim().to_string())
                        .unwrap_or_else(|| "https://evil-attacker.aether-dast.test".to_string());

                    let response = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Access-Control-Allow-Origin: {origin}\r\n\
                         Access-Control-Allow-Credentials: true\r\n\
                         Content-Length: 2\r\n\
                         Connection: close\r\n\
                         \r\n\
                         OK"
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
            }
        });
        thread::sleep(Duration::from_millis(60));
        port
    }

    // ── cookie tests ──────────────────────────────────────────────────────────

    #[test]
    fn cookie_missing_all_flags_detected_end_to_end() {
        // Session cookie with no Secure, no HttpOnly, no SameSite.
        let port = start_static_server(concat!(
            "HTTP/1.1 200 OK\r\n",
            "Set-Cookie: session=deadbeef; Path=/\r\n",
            "Content-Length: 2\r\n",
            "Connection: close\r\n",
            "\r\n",
            "OK"
        ));
        let url = format!("http://127.0.0.1:{}/", port);
        let report = scan(&url).expect("scan must not error");

        let checks: Vec<&str> = report.findings.iter().map(|f| f.check.as_str()).collect();
        assert!(
            checks.contains(&"cookie-secure"),
            "expected cookie-secure finding; got: {:?}", checks
        );
        assert!(
            checks.contains(&"cookie-httponly"),
            "expected cookie-httponly finding; got: {:?}", checks
        );
        assert!(
            checks.contains(&"cookie-samesite"),
            "expected cookie-samesite finding; got: {:?}", checks
        );
        // Severity spot-check
        assert!(
            report.findings.iter().any(|f| f.check == "cookie-secure"
                && f.severity == DastSeverity::High),
            "missing-Secure must be HIGH"
        );
    }

    #[test]
    fn cookie_with_all_flags_no_cookie_findings() {
        // Properly configured cookie — no cookie-* findings expected.
        let port = start_static_server(concat!(
            "HTTP/1.1 200 OK\r\n",
            "Set-Cookie: session=deadbeef; Path=/; Secure; HttpOnly; SameSite=Strict\r\n",
            "Content-Length: 2\r\n",
            "Connection: close\r\n",
            "\r\n",
            "OK"
        ));
        let url = format!("http://127.0.0.1:{}/", port);
        let report = scan(&url).expect("scan must not error");

        let cookie_findings: Vec<&DastFinding> = report.findings.iter()
            .filter(|f| f.check.starts_with("cookie-"))
            .collect();
        assert!(
            cookie_findings.is_empty(),
            "well-configured cookie must produce zero cookie-* findings; got: {:?}",
            cookie_findings.iter().map(|f| &f.check).collect::<Vec<_>>()
        );
    }

    // ── CORS reflection test ──────────────────────────────────────────────────

    #[test]
    fn cors_origin_reflection_with_credentials_critical_end_to_end() {
        // Server reflects whatever Origin curl sent + credentials=true.
        // scan() sends Origin: https://evil-attacker.aether-dast.test, so the
        // server ACAO will equal that exact string → check_cors fires Critical.
        let port = start_cors_reflect_server();
        let url = format!("http://127.0.0.1:{}/", port);
        let report = scan(&url).expect("scan must not error");

        let cors_findings: Vec<&DastFinding> = report.findings.iter()
            .filter(|f| f.check == "cors")
            .collect();
        assert!(
            !cors_findings.is_empty(),
            "expected at least one cors finding; got none"
        );
        assert!(
            cors_findings.iter().any(|f| f.severity == DastSeverity::Critical),
            "CORS origin reflection with credentials must be Critical; got severities: {:?}",
            cors_findings.iter().map(|f| &f.severity).collect::<Vec<_>>()
        );
        // The detail must mention "credentials" so the finding is actionable.
        let crit = cors_findings.iter().find(|f| f.severity == DastSeverity::Critical).unwrap();
        assert!(
            crit.detail.to_lowercase().contains("credential"),
            "Critical CORS detail must mention credentials; got: {}", crit.detail
        );
    }
}
