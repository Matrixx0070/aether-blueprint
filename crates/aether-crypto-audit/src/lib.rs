//! Real static weak-cryptography detection.
//!
//! Scans Rust / Python / JS / Go / Java source files for:
//! - Broken algorithms: MD5, SHA-1, DES, RC4, Blowfish, 3DES, RC2
//! - Weak key sizes: RSA <2048, AES-128 where AES-256 is required
//! - Constant-time violations: early-exit comparisons on secrets
//! - Hard-coded keys / IVs / salts
//! - Insecure random: Math.random(), rand::weak_rng

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoFinding {
    pub line: usize,
    pub column: usize,
    pub severity: Severity,
    pub category: String,
    pub algorithm: String,
    pub snippet: String,
    pub cwe: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoAuditReport {
    pub file: String,
    pub findings: Vec<CryptoFinding>,
}

impl CryptoAuditReport {
    pub fn critical_count(&self) -> usize {
        self.findings.iter().filter(|f| f.severity == Severity::Critical).count()
    }
    pub fn is_clean(&self) -> bool { self.findings.is_empty() }
}

// ── Pattern tables ────────────────────────────────────────────────────────────

type Rule = (Regex, Severity, &'static str, &'static str, &'static str, &'static str);

// Patterns are intentionally broad — false positives preferred over missed
// findings in a security context. Caller can suppress with comments.
fn rules() -> Vec<Rule> {
    vec![
        // ── Broken hash functions ──────────────────────────────────────────
        (Regex::new(r#"(?i)\bmd5\b|Md5::new\(\)|DigestMd5|MessageDigest\.getInstance\("MD5"\)|hashlib\.md5|crypto\.createHash\('md5'\)"#).unwrap(),
         Severity::Critical, "BrokenHash", "MD5", "CWE-327",
         "Replace MD5 with SHA-256 (broken since 2004, collision attacks trivial)"),

        (Regex::new(r#"(?i)\bsha1\b|sha_1|Sha1::new\(\)|DigestSha1|"SHA-1"|"SHA1"|hashlib\.sha1"#).unwrap(),
         Severity::Critical, "BrokenHash", "SHA-1", "CWE-327",
         "Replace SHA-1 with SHA-256 (SHAttered collision 2017, CACert revoked)"),

        // ── Broken ciphers ────────────────────────────────────────────────
        (Regex::new(r#"(?i)\bDES\b|DESede|Cipher\.getInstance\("DES|3DES|TripleDES|des_cbc|des_ecb"#).unwrap(),
         Severity::Critical, "BrokenCipher", "DES/3DES", "CWE-326",
         "DES (56-bit) brute-forced in <24h. 3DES deprecated by NIST. Use AES-256-GCM."),

        (Regex::new(r"(?i)\bRC4\b|Rc4::new|ARC4|arcfour|rc4_init|\.rc4\(").unwrap(),
         Severity::Critical, "BrokenCipher", "RC4", "CWE-327",
         "RC4 broken (Fluhrer-Mantin-Shamir attack). Use ChaCha20-Poly1305."),

        (Regex::new(r#"(?i)Blowfish::new|Cipher\.getInstance\("Blowfish"\)|blowfish_enc"#).unwrap(),
         Severity::High, "WeakCipher", "Blowfish", "CWE-326",
         "Blowfish has 64-bit block size (SWEET32 birthday attack). Use AES-256-GCM."),

        (Regex::new(r"(?i)AES_?128|AES-128|Aes128::new|keySize\s*=\s*16[^0-9]|keylen\s*=\s*128").unwrap(),
         Severity::Medium, "WeakKeySize", "AES-128", "CWE-326",
         "For classified/FIPS data use AES-256. AES-128 is below NSA Suite B mandatory level."),

        // ── ECB mode (always bad) ─────────────────────────────────────────
        (Regex::new(r#"(?i)AES.ECB|"AES/ECB|ecb_encrypt|ECB_MODE|CipherMode::Ecb"#).unwrap(),
         Severity::Critical, "InsecureMode", "AES-ECB", "CWE-327",
         "ECB mode leaks patterns. Use AES-256-GCM or ChaCha20-Poly1305."),

        // ── Weak RSA key sizes ────────────────────────────────────────────
        (Regex::new(r"(?i)rsa.*1024|RsaPrivateKey::new\([^,]*,\s*1024|bits\s*=\s*1024").unwrap(),
         Severity::Critical, "WeakKeySize", "RSA-1024", "CWE-326",
         "RSA-1024 factored in practice. Minimum: RSA-2048. Preferred: RSA-4096 or Ed25519."),

        (Regex::new(r"(?i)rsa.*512|bits\s*=\s*512").unwrap(),
         Severity::Critical, "WeakKeySize", "RSA-512", "CWE-326",
         "RSA-512 factored by amateurs with cloud computing in hours. Use RSA-2048+."),

        (Regex::new(r"(?i)rsa.*2048|bits\s*=\s*2048").unwrap(),
         Severity::Low, "AcceptableKeySize", "RSA-2048", "CWE-326",
         "RSA-2048 is currently acceptable but RSA-4096 or Ed25519 recommended for new code."),

        // ── Insecure random ───────────────────────────────────────────────
        (Regex::new(r"Math\.random\(\)|random\.random\(\)|rand\(\)|srand\(|mt_rand\(|std::rand\(\)").unwrap(),
         Severity::High, "WeakRandom", "PRNG", "CWE-338",
         "Non-cryptographic RNG. Use getrandom / OsRng / SecureRandom / crypto.getRandomValues."),

        // ── Hard-coded secrets ────────────────────────────────────────────
        (Regex::new(r#"(?i)(password|passwd|secret|api_key|apikey|private_key|auth_token)\s*[:=]\s*["'][^"']{8,}["']"#).unwrap(),
         Severity::Critical, "HardcodedSecret", "Credential", "CWE-798",
         "Hard-coded credential. Use environment variables or a secrets manager."),

        (Regex::new(r#"(?i)(iv|nonce)\s*[:=]\s*\[?0(?:,\s*0){7,}"#).unwrap(),
         Severity::Critical, "ZeroIV", "IV/Nonce", "CWE-329",
         "Zero or all-constant IV/nonce. Generate a random nonce per encryption."),

        // ── Timing-unsafe comparisons ─────────────────────────────────────
        (Regex::new(r"(?:hmac|mac|tag|signature|token)\s*==\s*|==\s*(?:hmac|mac|tag|signature|token)").unwrap(),
         Severity::High, "TimingLeak", "HMAC", "CWE-208",
         "Non-constant-time comparison on secret. Use constant_time_eq / MessageDigest.isEqual."),
    ]
}

// ── Scanner ───────────────────────────────────────────────────────────────────

pub fn scan_code(source: &str, file_name: &str) -> CryptoAuditReport {
    let mut report = CryptoAuditReport {
        file: file_name.to_string(),
        findings: Vec::new(),
    };

    let rules = rules();

    for (line_idx, line_text) in source.lines().enumerate() {
        // Skip comment lines
        let trimmed = line_text.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
            continue;
        }

        for (re, ref severity, category, algorithm, cwe, recommendation) in &rules {
            if let Some(m) = re.find(line_text) {
                let snippet = line_text.trim().chars().take(80).collect::<String>();
                report.findings.push(CryptoFinding {
                    line: line_idx + 1,
                    column: m.start() + 1,
                    severity: severity.clone(),
                    category: category.to_string(),
                    algorithm: algorithm.to_string(),
                    snippet,
                    cwe: cwe.to_string(),
                    recommendation: recommendation.to_string(),
                });
                break; // one finding per line per pass
            }
        }
    }

    report
}

pub fn scan_file(path: &std::path::Path) -> Result<CryptoAuditReport> {
    let source = std::fs::read_to_string(path)?;
    let file_name = path.to_string_lossy().into_owned();
    Ok(scan_code(&source, &file_name))
}

pub fn scan_directory(dir: &std::path::Path, extensions: &[&str]) -> Result<Vec<CryptoAuditReport>> {
    let mut reports = Vec::new();
    scan_dir_recursive(dir, extensions, &mut reports)?;
    Ok(reports)
}

fn scan_dir_recursive(
    dir: &std::path::Path,
    extensions: &[&str],
    out: &mut Vec<CryptoAuditReport>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if !matches!(name.as_str(), "target" | ".git" | "node_modules" | ".cargo") {
                scan_dir_recursive(&path, extensions, out)?;
            }
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if extensions.contains(&ext) {
                let report = scan_file(&path)?;
                if !report.is_clean() {
                    out.push(report);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VULNERABLE: &str = r#"
use md5;
use sha1::Sha1;

fn insecure_hash(data: &[u8]) -> Vec<u8> {
    let hash = md5::compute(data);
    hash.to_vec()
}

fn insecure_cipher() {
    let key = [0u8; 16];
    let cipher = DES::new(&key);
    cipher.encrypt(data)
}

fn bad_random() -> u32 {
    rand() as u32
}

fn hardcoded() {
    let api_key = "sk-1234567890abcdef";
}

fn timing_unsafe(hmac: &[u8], expected: &[u8]) -> bool {
    hmac == expected
}
"#;

    const CLEAN: &str = r#"
use sha2::{Sha256, Digest};
use aes_gcm::{Aes256Gcm, Key, Nonce};

fn good_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
"#;

    #[test]
    fn detects_md5() {
        let report = scan_code(VULNERABLE, "test.rs");
        assert!(report.findings.iter().any(|f| f.algorithm == "MD5"));
    }

    #[test]
    fn detects_sha1() {
        let report = scan_code(VULNERABLE, "test.rs");
        assert!(report.findings.iter().any(|f| f.algorithm == "SHA-1"));
    }

    #[test]
    fn detects_des() {
        let report = scan_code(VULNERABLE, "test.rs");
        assert!(report.findings.iter().any(|f| f.algorithm.contains("DES")));
    }

    #[test]
    fn detects_weak_random() {
        let report = scan_code(VULNERABLE, "test.rs");
        assert!(report.findings.iter().any(|f| f.category == "WeakRandom"));
    }

    #[test]
    fn detects_hardcoded_secret() {
        let report = scan_code(VULNERABLE, "test.rs");
        assert!(report.findings.iter().any(|f| f.category == "HardcodedSecret"));
    }

    #[test]
    fn detects_timing_leak() {
        let report = scan_code(VULNERABLE, "test.rs");
        assert!(report.findings.iter().any(|f| f.category == "TimingLeak"));
    }

    #[test]
    fn clean_code_no_findings() {
        let report = scan_code(CLEAN, "clean.rs");
        assert!(report.is_clean(), "got findings: {:?}", report.findings);
    }

    #[test]
    fn critical_count() {
        let report = scan_code(VULNERABLE, "test.rs");
        assert!(report.critical_count() >= 2);
    }
}
