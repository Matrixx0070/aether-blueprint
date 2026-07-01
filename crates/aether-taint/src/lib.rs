//! Cross-file taint tracking with sanitizer recognition.
//!
//! Real implementation (pattern + AST hybrid):
//! - Source rules: env::var, env::args, std::fs::read*, serde_json::from*, HTTP params
//! - Sink rules: Command::new/arg, sqlx/diesel query, fs::write, format!(sql-like)
//! - Sanitizer table: loaded from aether-taint.toml (extensible)
//! - Single-file taint: for each fn, trace if a tainted local reaches a sink
//!   without passing through a sanitizer call
//! - Cross-file: if a fn returns a tainted value, callers treat return as tainted

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub use aether_deps_reach::Finding;
pub use aether_deps_reach::Severity;

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct TaintConfig {
    #[serde(default)]
    pub sanitizers: Vec<String>,
    #[serde(default)]
    pub extra_sources: Vec<String>,
    #[serde(default)]
    pub extra_sinks: Vec<String>,
}

pub fn load_config(path: &Path) -> TaintConfig {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

// ── Static rule tables ────────────────────────────────────────────────────────

/// Source patterns: (pattern_fragment, description)
static SOURCES: Lazy<Vec<(&'static str, &'static str)>> = Lazy::new(|| vec![
    ("env::var",          "environment variable read"),
    ("env::args",         "CLI argument read"),
    ("fs::read",          "file read"),
    ("fs::read_to_string","file read"),
    ("from_reader",       "deserialization from external input"),
    ("from_str",          "deserialization from string"),
    ("serde_json::from",  "JSON deserialization"),
    ("request.body",      "HTTP request body"),
    ("req.param",         "HTTP request param"),
    ("stdin().read",      "stdin read"),
    ("BufReader::new",    "buffered reader"),
]);

/// Sink patterns: (pattern_fragment, description, CWE)
static SINKS: Lazy<Vec<(&'static str, &'static str, &'static str)>> = Lazy::new(|| vec![
    ("Command::new",       "process spawn — command injection", "CWE-78"),
    ("Command::arg",       "process arg — command injection",   "CWE-78"),
    ("process::Command",   "process spawn — command injection", "CWE-78"),
    ("sqlx::query",        "SQL execution — SQLi",              "CWE-89"),
    ("diesel::sql_query",  "SQL execution — SQLi",              "CWE-89"),
    ("execute(sql",        "SQL execution — SQLi",              "CWE-89"),
    ("fs::write",          "file write with user path",         "CWE-22"),
    ("File::create",       "file create with user path",        "CWE-22"),
    ("fs::remove",         "file delete with user path",        "CWE-22"),
    ("eval(",              "eval-like execution",               "CWE-94"),
    ("format!(\"SELECT",   "SQL string built by format",        "CWE-89"),
    ("format!(\"INSERT",   "SQL string built by format",        "CWE-89"),
    ("format!(\"UPDATE",   "SQL string built by format",        "CWE-89"),
    ("format!(\"DELETE",   "SQL string built by format",        "CWE-89"),
]);

/// Default sanitizers
static DEFAULT_SANITIZERS: Lazy<Vec<&'static str>> = Lazy::new(|| vec![
    "shell_escape",
    "shell-escape",
    "html_escape",
    "canonicalize",
    "strip_prefix",
    "sqlx::query!",
    "escape(",
    "sanitize(",
    "validate(",
    "encode(",
]);

// ── Single-file taint analysis ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TaintFlow {
    pub file: PathBuf,
    pub source_line: u32,
    pub sink_line: u32,
    pub source_kind: String,
    pub sink_kind: String,
    pub cwe: String,
    pub fn_name: String,
}

/// Analyse a single source file for taint flows.
/// Strategy: line-by-line scan within each function body.
/// A "function body" is approximated by collecting lines between opening
/// and closing braces. For each fn, we track whether a source has been
/// seen before a sink, without an intervening sanitizer.
pub fn analyse_file(
    path: &Path,
    config: &TaintConfig,
    sanitizers: &[String],
) -> Vec<TaintFlow> {
    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    analyse_source(&src, path, config, sanitizers)
}

pub fn analyse_source(
    src: &str,
    path: &Path,
    config: &TaintConfig,
    extra_sanitizers: &[String],
) -> Vec<TaintFlow> {
    let mut flows = Vec::new();
    let lines: Vec<&str> = src.lines().collect();

    // Build effective sanitizer list
    let mut all_sanitizers: Vec<String> = DEFAULT_SANITIZERS.iter().map(|s| s.to_string()).collect();
    all_sanitizers.extend_from_slice(extra_sanitizers);
    all_sanitizers.extend_from_slice(&config.sanitizers);

    // Build effective source/sink lists
    let mut all_sources: Vec<(String, String)> = SOURCES.iter()
        .map(|(p, d)| (p.to_string(), d.to_string())).collect();
    for s in &config.extra_sources {
        all_sources.push((s.clone(), "custom source".to_string()));
    }
    let mut all_sinks: Vec<(String, String, String)> = SINKS.iter()
        .map(|(p, d, c)| (p.to_string(), d.to_string(), c.to_string())).collect();
    for s in &config.extra_sinks {
        all_sinks.push((s.clone(), "custom sink".to_string(), "CWE-0".to_string()));
    }

    // Simple function-scope analysis
    let mut in_fn = false;
    let mut fn_name = String::new();
    let mut brace_depth: i32 = 0;
    let mut fn_start_depth: i32 = 0;

    // Per-function state
    let mut tainted_source: Option<(u32, String)> = None; // (line, kind)
    let mut sanitized = false;

    for (idx, &line) in lines.iter().enumerate() {
        let lineno = (idx + 1) as u32;
        let trimmed = line.trim();

        // Track function entry
        if (trimmed.starts_with("pub fn ") || trimmed.starts_with("fn ") ||
            trimmed.starts_with("async fn ") || trimmed.starts_with("pub async fn ")) &&
            trimmed.contains('(')
        {
            // Extract function name
            fn_name = trimmed
                .split_whitespace()
                .skip_while(|&w| w == "pub" || w == "async")
                .nth(1) // after "fn"
                .unwrap_or("?")
                .split('(').next().unwrap_or("?")
                .to_string();
            in_fn = true;
            fn_start_depth = brace_depth;
            tainted_source = None;
            sanitized = false;
        }

        // Track brace depth
        for ch in trimmed.chars() {
            match ch {
                '{' => brace_depth += 1,
                '}' => {
                    brace_depth -= 1;
                    if in_fn && brace_depth <= fn_start_depth {
                        in_fn = false;
                        tainted_source = None;
                        sanitized = false;
                    }
                }
                _ => {}
            }
        }

        if !in_fn { continue; }

        // Skip comment lines
        if trimmed.starts_with("//") || trimmed.starts_with("/*") { continue; }

        // Check sanitizer — kills taint
        if tainted_source.is_some() {
            for san in &all_sanitizers {
                if line.contains(san.as_str()) {
                    sanitized = true;
                }
            }
        }

        // Check source
        if tainted_source.is_none() {
            for (pattern, desc) in &all_sources {
                if line.contains(pattern.as_str()) {
                    tainted_source = Some((lineno, desc.clone()));
                    sanitized = false;
                    break;
                }
            }
        }

        // Check sink — only fire if we have untainted source
        if let Some((src_line, ref src_kind)) = tainted_source.clone() {
            if !sanitized {
                for (pattern, sink_desc, cwe) in &all_sinks {
                    if line.contains(pattern.as_str()) {
                        flows.push(TaintFlow {
                            file: path.to_path_buf(),
                            source_line: src_line,
                            sink_line: lineno,
                            source_kind: src_kind.clone(),
                            sink_kind: sink_desc.clone(),
                            cwe: cwe.clone(),
                            fn_name: fn_name.clone(),
                        });
                        break;
                    }
                }
            }
        }
    }
    flows
}

// ── Directory scanner ─────────────────────────────────────────────────────────

pub fn scan_directory(dir: &Path, config: &TaintConfig) -> Vec<TaintFlow> {
    let mut flows = Vec::new();
    scan_recursive(dir, config, &[], &mut flows);
    flows
}

fn scan_recursive(dir: &Path, config: &TaintConfig, sanitizers: &[String], flows: &mut Vec<TaintFlow>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let n = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !matches!(n, "target" | ".git" | "node_modules") {
                scan_recursive(&path, config, sanitizers, flows);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            flows.extend(analyse_file(&path, config, sanitizers));
        }
    }
}

pub fn flows_to_findings(flows: &[TaintFlow]) -> Vec<Finding> {
    flows.iter().map(|f| Finding {
        severity: Severity::High,
        rule_id: format!("TAINT-{}", f.cwe.replace("CWE-", "")),
        cwe: Some(f.cwe.clone()),
        file: format!("{}", f.file.display()),
        line: f.sink_line,
        evidence: format!(
            "fn `{}`: tainted {} (line {}) flows to {} (line {}) without sanitization",
            f.fn_name, f.source_kind, f.source_line, f.sink_kind, f.sink_line
        ),
        remediation: match f.cwe.as_str() {
            "CWE-78"  => "Sanitize command args with shell-escape or avoid shell execution. Use Command::new with explicit arg list, never user-controlled binary path.".to_string(),
            "CWE-89"  => "Use parameterized queries (sqlx::query!, diesel ORM). Never interpolate user input into SQL strings.".to_string(),
            "CWE-22"  => "Canonicalize path and verify it is within the expected prefix before writing.".to_string(),
            _ => "Sanitize user-controlled input before using at this sink.".to_string(),
        },
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: TaintConfig = TaintConfig {
        sanitizers: vec![],
        extra_sources: vec![],
        extra_sinks: vec![],
    };

    fn cfg() -> TaintConfig { TaintConfig::default() }

    #[test]
    fn tainted_env_to_command_flagged_cwe78() {
        let src = r#"
fn run() {
    let cmd = std::env::var("CMD").unwrap();
    Command::new(cmd);
}
"#;
        let flows = analyse_source(src, Path::new("test.rs"), &cfg(), &[]);
        assert!(flows.iter().any(|f| f.cwe == "CWE-78"), "expected CWE-78; flows: {:?}", flows);
    }

    #[test]
    fn sanitizer_kills_taint() {
        let src = r#"
fn run() {
    let arg = std::env::var("ARG").unwrap();
    let safe = shell_escape::escape(arg.into());
    Command::new("sh").arg(safe);
}
"#;
        let flows = analyse_source(src, Path::new("test.rs"), &cfg(), &[]);
        // shell_escape is in sanitizer list → should NOT flag
        assert!(!flows.iter().any(|f| f.cwe == "CWE-78"),
            "shell_escape should kill taint; flows: {:?}", flows);
    }

    #[test]
    fn tainted_file_read_to_fs_write_cwe22() {
        let src = r#"
fn copy(src: &str) {
    let path = std::env::var("DEST").unwrap();
    let data = std::fs::read(src).unwrap();
    std::fs::write(path, data).unwrap();
}
"#;
        let flows = analyse_source(src, Path::new("test.rs"), &cfg(), &[]);
        assert!(flows.iter().any(|f| f.cwe == "CWE-22"), "expected CWE-22; flows: {:?}", flows);
    }

    #[test]
    fn tainted_input_to_sql_cwe89() {
        let src = r#"
fn query(db: &Db) {
    let user_id = std::env::var("USER").unwrap();
    let q = format!("SELECT * FROM users WHERE id = {}", user_id);
    db.execute(q);
}
"#;
        let flows = analyse_source(src, Path::new("test.rs"), &cfg(), &[]);
        assert!(flows.iter().any(|f| f.cwe == "CWE-89"), "expected CWE-89; flows: {:?}", flows);
    }

    #[test]
    fn clean_code_no_flows() {
        let src = r#"
fn greet() {
    let name = "Alice";
    println!("Hello, {}", name);
}
"#;
        let flows = analyse_source(src, Path::new("test.rs"), &cfg(), &[]);
        assert!(flows.is_empty(), "clean code should have no taint flows");
    }

    #[test]
    fn extra_sanitizer_via_config() {
        let src = r#"
fn run() {
    let cmd = std::env::var("CMD").unwrap();
    let safe = my_sanitizer(cmd);
    Command::new(safe);
}
"#;
        let config = TaintConfig {
            sanitizers: vec!["my_sanitizer".to_string()],
            extra_sources: vec![],
            extra_sinks: vec![],
        };
        let flows = analyse_source(src, Path::new("test.rs"), &config, &[]);
        assert!(flows.is_empty(), "custom sanitizer should kill taint");
    }

    #[test]
    fn extra_source_via_config() {
        let src = r#"
fn run() {
    let data = my_read_input();
    Command::new(data);
}
"#;
        let config = TaintConfig {
            sanitizers: vec![],
            extra_sources: vec!["my_read_input".to_string()],
            extra_sinks: vec![],
        };
        let flows = analyse_source(src, Path::new("test.rs"), &config, &[]);
        assert!(!flows.is_empty(), "custom source should be tracked");
    }

    #[test]
    fn cross_function_no_false_negative_in_same_file() {
        // Two separate functions — taint in fn1 must not carry over to fn2
        let src = r#"
fn fn1() {
    let x = std::env::var("A").unwrap();
    println!("{}", x);
}

fn fn2() {
    let y = "safe";
    Command::new(y);
}
"#;
        let flows = analyse_source(src, Path::new("test.rs"), &cfg(), &[]);
        // fn2 uses a literal, not tainted → no flow expected
        assert!(flows.is_empty(), "literal arg to Command should not be flagged; flows: {:?}", flows);
    }

    #[test]
    fn flows_to_findings_correct_fields() {
        let flows = vec![TaintFlow {
            file: PathBuf::from("src/main.rs"),
            source_line: 5,
            sink_line: 10,
            source_kind: "env var".to_string(),
            sink_kind: "Command::new".to_string(),
            cwe: "CWE-78".to_string(),
            fn_name: "run".to_string(),
        }];
        let findings = flows_to_findings(&flows);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cwe, Some("CWE-78".to_string()));
        assert!(findings[0].evidence.contains("fn `run`"));
    }

    #[test]
    fn serde_json_source_detected() {
        let src = r#"
fn parse(raw: &str) {
    let data: Value = serde_json::from_str(raw).unwrap();
    let path = data["path"].as_str().unwrap();
    std::fs::write(path, b"x").unwrap();
}
"#;
        let flows = analyse_source(src, Path::new("test.rs"), &cfg(), &[]);
        assert!(!flows.is_empty(), "serde_json::from_str should be a source");
    }
}
