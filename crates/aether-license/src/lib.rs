//! SPDX license compatibility checker.
//!
//! Parses Cargo.lock to discover all transitive dependencies and their
//! declared licenses. Flags GPL/AGPL licenses that are incompatible with
//! permissive (MIT/Apache-2.0) projects, and missing license declarations.
//! Uses `cargo metadata` for license data (Cargo.lock itself has no license field).

pub use aether_deps_reach::{Finding, Severity};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

// ── License compatibility rules ───────────────────────────────────────────────

/// Licenses that require source disclosure / are viral.
const COPYLEFT_LICENSES: &[(&str, &str)] = &[
    ("GPL-2.0",          "GNU GPL v2.0 — requires full source disclosure"),
    ("GPL-2.0-only",     "GNU GPL v2.0-only — requires full source disclosure"),
    ("GPL-2.0-or-later", "GNU GPL v2.0+ — requires full source disclosure"),
    ("GPL-3.0",          "GNU GPL v3.0 — requires full source disclosure"),
    ("GPL-3.0-only",     "GNU GPL v3.0-only — requires full source disclosure"),
    ("GPL-3.0-or-later", "GNU GPL v3.0+ — requires full source disclosure"),
    ("AGPL-3.0",         "GNU AGPL v3.0 — requires source even for network use"),
    ("AGPL-3.0-only",    "GNU AGPL v3.0-only — requires source even for network use"),
    ("LGPL-2.0",         "GNU LGPL v2.0 — weak copyleft; review usage"),
    ("LGPL-2.1",         "GNU LGPL v2.1 — weak copyleft; review dynamic linking"),
    ("LGPL-3.0",         "GNU LGPL v3.0 — weak copyleft; review dynamic linking"),
    ("CC-BY-SA-4.0",     "Creative Commons SA — share-alike clause may spread"),
    ("EUPL-1.2",         "European Union PL — strong copyleft in EU context"),
];

/// Licenses considered permissive (no concern).
const PERMISSIVE_LICENSES: &[&str] = &[
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "Unlicense", "CC0-1.0", "0BSD", "Zlib",
    "MIT OR Apache-2.0", "Apache-2.0 OR MIT",
    "Apache-2.0 WITH LLVM-exception",
];

// ── Cargo metadata types (minimal) ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MetaPackage {
    name: String,
    version: String,
    license: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoMeta {
    packages: Vec<MetaPackage>,
}

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub name: String,
    pub version: String,
    pub license: Option<String>,
    pub status: LicenseStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LicenseStatus {
    Permissive,
    Copyleft { reason: String },
    Unknown,
    Missing,
}

// ── Analysis ──────────────────────────────────────────────────────────────────

fn classify_license(license: &str) -> LicenseStatus {
    let norm = license.trim();
    for perm in PERMISSIVE_LICENSES {
        if norm.eq_ignore_ascii_case(perm) {
            return LicenseStatus::Permissive;
        }
    }
    // Check if all SPDX expressions are permissive (e.g. "MIT OR Apache-2.0")
    let all_permissive = norm.split(" OR ").all(|part| {
        let p = part.trim();
        PERMISSIVE_LICENSES.iter().any(|perm| p.eq_ignore_ascii_case(perm))
    });
    if all_permissive {
        return LicenseStatus::Permissive;
    }

    for (copyleft, reason) in COPYLEFT_LICENSES {
        if norm.eq_ignore_ascii_case(copyleft)
            || norm.contains(copyleft)
        {
            return LicenseStatus::Copyleft { reason: reason.to_string() };
        }
    }
    LicenseStatus::Unknown
}

fn cargo_bin() -> String {
    // Prefer CARGO env var (set by cargo itself); fall back to PATH search.
    std::env::var("CARGO")
        .unwrap_or_else(|_| {
            // Look in the common Rustup location
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            let candidate = format!("{}/.cargo/bin/cargo", home);
            if std::path::Path::new(&candidate).exists() {
                candidate
            } else {
                "cargo".to_string()
            }
        })
}

pub fn analyse_manifest(manifest_path: &Path) -> Result<Vec<LicenseInfo>> {
    let cargo = cargo_bin();
    let output = Command::new(&cargo)
        .args(["metadata", "--format-version", "1", "--no-deps", "--manifest-path"])
        .arg(manifest_path)
        .output()?;

    if !output.status.success() {
        // Fall back to all packages
        let output2 = Command::new(&cargo)
            .args(["metadata", "--format-version", "1", "--manifest-path"])
            .arg(manifest_path)
            .output()?;
        if !output2.status.success() {
            anyhow::bail!("cargo metadata failed: {}", String::from_utf8_lossy(&output2.stderr));
        }
        return parse_metadata(&output2.stdout);
    }
    parse_metadata(&output.stdout)
}

fn parse_metadata(stdout: &[u8]) -> Result<Vec<LicenseInfo>> {
    let meta: CargoMeta = serde_json::from_slice(stdout)?;
    let results = meta
        .packages
        .iter()
        .map(|pkg| {
            let status = match &pkg.license {
                None => LicenseStatus::Missing,
                Some(l) if l.is_empty() => LicenseStatus::Missing,
                Some(l) => classify_license(l),
            };
            LicenseInfo {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                license: pkg.license.clone(),
                status,
            }
        })
        .collect();
    Ok(results)
}

pub fn license_infos_to_findings(infos: &[LicenseInfo]) -> Vec<Finding> {
    infos
        .iter()
        .filter_map(|info| match &info.status {
            LicenseStatus::Copyleft { reason } => Some(Finding {
                severity: Severity::High,
                rule_id: "LICENSE-COPYLEFT".to_string(),
                cwe: Some("CWE-1002".to_string()),
                file: format!("Cargo.lock ({} v{})", info.name, info.version),
                line: 0,
                evidence: format!(
                    "Dependency {} v{} uses copyleft license '{}': {}",
                    info.name,
                    info.version,
                    info.license.as_deref().unwrap_or("unknown"),
                    reason,
                ),
                remediation: "Replace with a permissively licensed alternative, or obtain a commercial license.".to_string(),
            }),
            LicenseStatus::Missing => Some(Finding {
                severity: Severity::Medium,
                rule_id: "LICENSE-MISSING".to_string(),
                cwe: Some("CWE-1002".to_string()),
                file: format!("Cargo.lock ({} v{})", info.name, info.version),
                line: 0,
                evidence: format!(
                    "Dependency {} v{} has no declared license",
                    info.name, info.version,
                ),
                remediation: "Contact the crate author to declare an SPDX license.".to_string(),
            }),
            LicenseStatus::Unknown => Some(Finding {
                severity: Severity::Low,
                rule_id: "LICENSE-UNKNOWN".to_string(),
                cwe: Some("CWE-1002".to_string()),
                file: format!("Cargo.lock ({} v{})", info.name, info.version),
                line: 0,
                evidence: format!(
                    "Dependency {} v{} has unrecognised license '{}'",
                    info.name,
                    info.version,
                    info.license.as_deref().unwrap_or(""),
                ),
                remediation: "Manually verify license compatibility.".to_string(),
            }),
            LicenseStatus::Permissive => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissive_mit() {
        assert_eq!(classify_license("MIT"), LicenseStatus::Permissive);
    }

    #[test]
    fn permissive_apache() {
        assert_eq!(classify_license("Apache-2.0"), LicenseStatus::Permissive);
    }

    #[test]
    fn permissive_mit_or_apache() {
        assert_eq!(classify_license("MIT OR Apache-2.0"), LicenseStatus::Permissive);
    }

    #[test]
    fn copyleft_gpl3() {
        let status = classify_license("GPL-3.0");
        assert!(matches!(status, LicenseStatus::Copyleft { .. }));
    }

    #[test]
    fn copyleft_agpl() {
        let status = classify_license("AGPL-3.0");
        assert!(matches!(status, LicenseStatus::Copyleft { .. }));
    }

    #[test]
    fn unknown_license() {
        assert_eq!(classify_license("Proprietary-XYZ"), LicenseStatus::Unknown);
    }

    #[test]
    fn infos_to_findings_permissive_no_finding() {
        let info = LicenseInfo {
            name: "serde".to_string(),
            version: "1.0.0".to_string(),
            license: Some("MIT OR Apache-2.0".to_string()),
            status: LicenseStatus::Permissive,
        };
        let findings = license_infos_to_findings(&[info]);
        assert!(findings.is_empty());
    }

    #[test]
    fn infos_to_findings_copyleft_high() {
        let info = LicenseInfo {
            name: "evil-crate".to_string(),
            version: "1.0.0".to_string(),
            license: Some("GPL-3.0".to_string()),
            status: LicenseStatus::Copyleft { reason: "viral".to_string() },
        };
        let findings = license_infos_to_findings(&[info]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].rule_id, "LICENSE-COPYLEFT");
    }

    #[test]
    fn infos_to_findings_missing_medium() {
        let info = LicenseInfo {
            name: "no-license-crate".to_string(),
            version: "0.1.0".to_string(),
            license: None,
            status: LicenseStatus::Missing,
        };
        let findings = license_infos_to_findings(&[info]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].rule_id, "LICENSE-MISSING");
    }

    #[test]
    fn infos_to_findings_unknown_low() {
        let info = LicenseInfo {
            name: "weird-crate".to_string(),
            version: "0.1.0".to_string(),
            license: Some("CUSTOM-LICENSE".to_string()),
            status: LicenseStatus::Unknown,
        };
        let findings = license_infos_to_findings(&[info]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn lgpl_is_copyleft() {
        let status = classify_license("LGPL-2.1");
        assert!(matches!(status, LicenseStatus::Copyleft { .. }));
    }
}
