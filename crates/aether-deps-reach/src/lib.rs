//! Reachability-aware CVE triage.
//!
//! Real implementation:
//! - Runs `cargo metadata` to get the full transitive dep graph
//! - Queries OSV.dev for CVEs on every package version
//! - Walks Rust source via `syn` to build a lightweight call-site index
//!   (which external crate names appear in `use`, path expressions, fn calls)
//! - Intersects: CVE in package P is `Reachable` if P's name appears in any
//!   call-site in the workspace source; otherwise `Present-Unreachable` (Info)
//!
//! Reachability is name-level (not function-level) which is fast and
//! conservative: it can flag `Present-Unreachable` as false negatives but
//! never false positives (a used crate will always have its name in source).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

// ── Common Finding type (shared schema across Tier 31-45 crates) ──────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub rule_id: String,
    pub cwe: Option<String>,
    pub file: String,
    pub line: u32,
    pub evidence: String,
    pub remediation: String,
}

// ── Cargo metadata ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MetaPackage {
    name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct CargoMeta {
    packages: Vec<MetaPackage>,
    workspace_root: String,
}

fn run_cargo_metadata(manifest: &Path) -> Result<CargoMeta> {
    let out = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps",
               "--manifest-path", &manifest.to_string_lossy()])
        .output()
        .context("cargo metadata failed")?;
    if !out.status.success() {
        anyhow::bail!("cargo metadata error: {}", String::from_utf8_lossy(&out.stderr));
    }
    serde_json::from_slice(&out.stdout).context("parse cargo metadata")
}

// Run with all deps included (to get transitive graph)
fn run_cargo_metadata_all(manifest: &Path) -> Result<Vec<MetaPackage>> {
    let out = Command::new("cargo")
        .args(["metadata", "--format-version", "1",
               "--manifest-path", &manifest.to_string_lossy()])
        .output()
        .context("cargo metadata failed")?;
    if !out.status.success() {
        anyhow::bail!("cargo metadata error: {}", String::from_utf8_lossy(&out.stderr));
    }
    let meta: CargoMeta = serde_json::from_slice(&out.stdout).context("parse cargo metadata")?;
    Ok(meta.packages)
}

// ── OSV.dev CVE query ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    database_specific: serde_json::Value,
}

#[derive(Debug, Deserialize, Default)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

async fn query_osv(client: &reqwest::Client, name: &str, version: &str) -> Vec<OsvVuln> {
    let body = serde_json::json!({
        "version": version,
        "package": { "name": name, "ecosystem": "crates.io" }
    });
    match client.post("https://api.osv.dev/v1/query")
        .json(&body).timeout(std::time::Duration::from_secs(8))
        .send().await
    {
        Ok(r) => r.json::<OsvResponse>().await.unwrap_or_default().vulns,
        Err(_) => vec![],
    }
}

fn osv_severity(vuln: &OsvVuln) -> Severity {
    // Check database_specific.severity or CVSS score field
    let sev = vuln.database_specific.get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("MODERATE");
    match sev.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH"     => Severity::High,
        "LOW"      => Severity::Low,
        _          => Severity::Medium,
    }
}

// ── Source call-site index via syn ────────────────────────────────────────────

/// Collect all external crate names referenced in source files under `dir`.
/// We look for: `use <name>::`, `<name>::<path>`, extern crate declarations.
pub fn collect_referenced_crates(src_dir: &Path) -> HashSet<String> {
    let mut names = HashSet::new();
    collect_recursive(src_dir, &mut names);
    names
}

fn collect_recursive(dir: &Path, names: &mut HashSet<String>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let n = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !matches!(n, "target" | ".git" | "node_modules") {
                collect_recursive(&path, names);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            collect_from_file(&path, names);
        }
    }
}

struct CrateNameVisitor<'a> {
    names: &'a mut HashSet<String>,
}

impl<'ast, 'a> syn::visit::Visit<'ast> for CrateNameVisitor<'a> {
    // `use foo::bar::Baz`
    fn visit_use_tree(&mut self, node: &'ast syn::UseTree) {
        if let syn::UseTree::Path(p) = node {
            self.names.insert(p.ident.to_string());
        }
        syn::visit::visit_use_tree(self, node);
    }

    // `extern crate foo`
    fn visit_item_extern_crate(&mut self, node: &'ast syn::ItemExternCrate) {
        self.names.insert(node.ident.to_string());
        syn::visit::visit_item_extern_crate(self, node);
    }

    // `foo::bar()` path expressions — first segment is crate name
    fn visit_path(&mut self, node: &'ast syn::Path) {
        if let Some(first) = node.segments.first() {
            let n = first.ident.to_string();
            // Filter out common Rust keywords and self/super/crate
            if !matches!(n.as_str(), "self" | "super" | "crate" | "std" |
                          "core" | "alloc" | "String" | "Vec" | "Option" |
                          "Result" | "Ok" | "Err" | "Some" | "None" | "true" |
                          "false" | "Box" | "Arc" | "Rc" | "HashMap" |
                          "HashSet" | "BTreeMap" | "BTreeSet") {
                self.names.insert(n);
            }
        }
        syn::visit::visit_path(self, node);
    }
}

fn collect_from_file(path: &Path, names: &mut HashSet<String>) {
    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return,
    };
    let file = match syn::parse_file(&src) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut visitor = CrateNameVisitor { names };
    syn::visit::visit_file(&mut visitor, &file);
}

// ── Call-site evidence (file:line for a crate reference) ─────────────────────

pub fn find_call_site(src_dir: &Path, crate_name: &str) -> Option<(PathBuf, u32)> {
    find_site_recursive(src_dir, crate_name)
}

fn find_site_recursive(dir: &Path, target: &str) -> Option<(PathBuf, u32)> {
    let rd = std::fs::read_dir(dir).ok()?;
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let n = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !matches!(n, "target" | ".git") {
                if let Some(r) = find_site_recursive(&path, target) {
                    return Some(r);
                }
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Some(line) = find_in_file(&path, target) {
                return Some((path, line));
            }
        }
    }
    None
}

fn find_in_file(path: &Path, target: &str) -> Option<u32> {
    let src = std::fs::read_to_string(path).ok()?;
    for (i, line) in src.lines().enumerate() {
        if line.contains(target) {
            return Some((i + 1) as u32);
        }
    }
    None
}

// ── Top-level run ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct DepsReachReport {
    pub packages_scanned: usize,
    pub reachable_cves: Vec<DepsReachFinding>,
    pub unreachable_cves: Vec<DepsReachFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepsReachFinding {
    pub package: String,
    pub version: String,
    pub vuln_id: String,
    pub summary: String,
    pub severity: Severity,
    pub reachable: bool,
    pub call_site: Option<String>,  // "file:line" evidence
}

pub async fn run(manifest_path: &Path) -> Result<DepsReachReport> {
    let packages = run_cargo_metadata_all(manifest_path)?;
    let workspace_root = {
        let meta = run_cargo_metadata(manifest_path)?;
        PathBuf::from(meta.workspace_root)
    };

    let referenced = collect_referenced_crates(&workspace_root);
    let client = reqwest::Client::new();

    let mut reachable_cves = Vec::new();
    let mut unreachable_cves = Vec::new();
    let packages_scanned = packages.len();

    // Deduplicate by name+version (cargo metadata lists each version once)
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for pkg in &packages {
        let key = (pkg.name.clone(), pkg.version.clone());
        if !seen.insert(key) { continue; }

        let vulns = query_osv(&client, &pkg.name, &pkg.version).await;
        for v in vulns {
            // Normalise crate name: hyphens → underscores (Rust module names)
            let mod_name = pkg.name.replace('-', "_");
            let is_reachable = referenced.contains(&pkg.name) || referenced.contains(&mod_name);
            let call_site = if is_reachable {
                find_call_site(&workspace_root, &mod_name)
                    .or_else(|| find_call_site(&workspace_root, &pkg.name))
                    .map(|(p, l)| format!("{}:{}", p.display(), l))
            } else {
                None
            };

            let finding = DepsReachFinding {
                package: pkg.name.clone(),
                version: pkg.version.clone(),
                vuln_id: v.id.clone(),
                summary: v.summary.clone(),
                severity: if is_reachable { osv_severity(&v) } else { Severity::Info },
                reachable: is_reachable,
                call_site,
            };
            if is_reachable {
                reachable_cves.push(finding);
            } else {
                unreachable_cves.push(finding);
            }
        }
    }

    Ok(DepsReachReport { packages_scanned, reachable_cves, unreachable_cves })
}

/// Flat findings list for the common CLI Finding interface
pub fn report_to_findings(r: &DepsReachReport) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in &r.reachable_cves {
        out.push(Finding {
            severity: f.severity.clone(),
            rule_id: format!("DEPS-REACH-{}", f.vuln_id),
            cwe: Some("CWE-1395".to_string()),
            file: f.call_site.as_deref().unwrap_or("Cargo.lock").to_string(),
            line: 0,
            evidence: format!("[REACHABLE] {} v{} — {} — {}", f.package, f.version, f.vuln_id, f.summary),
            remediation: format!("Upgrade {} or remove dependency. Check advisory at https://osv.dev/vulnerability/{}", f.package, f.vuln_id),
        });
    }
    for f in &r.unreachable_cves {
        out.push(Finding {
            severity: Severity::Info,
            rule_id: format!("DEPS-UNREACH-{}", f.vuln_id),
            cwe: Some("CWE-1395".to_string()),
            file: "Cargo.lock".to_string(),
            line: 0,
            evidence: format!("[PRESENT-UNREACHABLE] {} v{} — {} — {}", f.package, f.version, f.vuln_id, f.summary),
            remediation: format!("Not called in source. Still consider upgrading {}.", f.package),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_tmp(path: &str, content: &str) {
        let p = std::path::Path::new(path);
        if let Some(parent) = p.parent() { fs::create_dir_all(parent).unwrap(); }
        fs::write(p, content).unwrap();
    }

    #[test]
    fn collect_crates_from_use_statement() {
        write_tmp("/tmp/ar_test/src/lib.rs", "use reqwest::Client;\nuse anyhow::Result;");
        let names = collect_referenced_crates(std::path::Path::new("/tmp/ar_test/src"));
        assert!(names.contains("reqwest"), "should find reqwest");
        assert!(names.contains("anyhow"), "should find anyhow");
    }

    #[test]
    fn collect_crates_from_path_expr() {
        write_tmp("/tmp/ar_test2/src/lib.rs", "fn f() { serde_json::to_string(&()).unwrap(); }");
        let names = collect_referenced_crates(std::path::Path::new("/tmp/ar_test2/src"));
        assert!(names.contains("serde_json"), "should find serde_json");
    }

    #[test]
    fn collect_crates_from_extern_crate() {
        write_tmp("/tmp/ar_test3/src/lib.rs", "extern crate proc_macro2;");
        let names = collect_referenced_crates(std::path::Path::new("/tmp/ar_test3/src"));
        assert!(names.contains("proc_macro2"), "should find proc_macro2");
    }

    #[test]
    fn unreachable_crate_not_in_referenced() {
        write_tmp("/tmp/ar_test4/src/lib.rs", "use serde::Serialize;");
        let names = collect_referenced_crates(std::path::Path::new("/tmp/ar_test4/src"));
        assert!(!names.contains("openssl"), "openssl not referenced");
        assert!(names.contains("serde"), "serde is referenced");
    }

    #[test]
    fn find_call_site_locates_reference() {
        write_tmp("/tmp/ar_cs/src/lib.rs", "use tokio::runtime::Runtime;");
        let result = find_call_site(std::path::Path::new("/tmp/ar_cs"), "tokio");
        assert!(result.is_some(), "should find tokio reference");
        let (_, line) = result.unwrap();
        assert_eq!(line, 1);
    }

    #[test]
    fn find_call_site_returns_none_for_absent() {
        write_tmp("/tmp/ar_cs2/src/lib.rs", "fn x() {}");
        let result = find_call_site(std::path::Path::new("/tmp/ar_cs2"), "nosuchcrate");
        assert!(result.is_none());
    }

    #[test]
    fn report_to_findings_maps_severity() {
        let report = DepsReachReport {
            packages_scanned: 2,
            reachable_cves: vec![DepsReachFinding {
                package: "time".into(), version: "0.1.45".into(),
                vuln_id: "RUSTSEC-2020-0071".into(),
                summary: "Potential segfault".into(),
                severity: Severity::High, reachable: true,
                call_site: Some("src/lib.rs:42".into()),
            }],
            unreachable_cves: vec![DepsReachFinding {
                package: "openssl".into(), version: "0.10.0".into(),
                vuln_id: "GHSA-test".into(),
                summary: "Test".into(),
                severity: Severity::Info, reachable: false,
                call_site: None,
            }],
        };
        let findings = report_to_findings(&report);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Info);
        assert!(findings[0].evidence.contains("REACHABLE"));
        assert!(findings[1].evidence.contains("UNREACHABLE"));
    }
}
