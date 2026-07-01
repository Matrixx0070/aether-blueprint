//! Source pattern detection — spots where tainted data enters the program.
//!
//! Covers Rust and Python patterns. Each source type has a regex that
//! captures the variable binding (if any) near the source call.

use crate::graph::{SourceKind, TaintSource};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

macro_rules! lazy_re {
    ($pat:expr) => {
        Lazy::new(|| Regex::new($pat).expect("source pattern"))
    };
}

// ── Rust source patterns ────────────────────────────────────────────────────

static RUST_ENV_VAR: Lazy<Regex> =
    lazy_re!(r#"(?:let\s+(\w+)\s*=\s*)?(?:std::)?env::var\s*\(\s*"(\w+)""#);
static RUST_CLI_ARG: Lazy<Regex> =
    lazy_re!(r#"(?:let\s+(\w+)\s*=\s*)?(?:std::)?env::args\s*\("#);
static RUST_FILE_READ: Lazy<Regex> =
    lazy_re!(r#"(?:let\s+(\w+)\s*=\s*)?(?:fs::read_to_string|File::open|fs::read)\s*\("#);
static RUST_HTTP_REQ: Lazy<Regex> =
    lazy_re!(r#"(?:let\s+(\w+)\s*=\s*)?(?:reqwest|ureq|hyper).*?(?:get|post|put|delete)\s*\("#);
static RUST_STDIN: Lazy<Regex> =
    lazy_re!(r#"(?:let\s+(\w+)\s*=\s*)?(?:std::)?io::stdin\s*\(\s*\)"#);
static RUST_DB_READ: Lazy<Regex> =
    lazy_re!(r#"(?:let\s+(\w+)\s*=\s*)?\.(?:query|query_row|fetch_one|fetch_all)\s*\("#);

// ── Python source patterns ──────────────────────────────────────────────────

static PY_ENV_VAR: Lazy<Regex> =
    lazy_re!(r#"(?:(\w+)\s*=\s*)?os\.(?:environ\.get|getenv)\s*\("#);
static PY_CLI_ARG: Lazy<Regex> = lazy_re!(r#"(?:(\w+)\s*=\s*)?sys\.argv"#);
static PY_FILE_READ: Lazy<Regex> =
    lazy_re!(r#"(?:(\w+)\s*=\s*)?open\s*\(|(?:(\w+)\s*=\s*)?Path\s*\(.*?\)\.read_text"#);
static PY_HTTP_REQ: Lazy<Regex> =
    lazy_re!(r#"(?:(\w+)\s*=\s*)?requests\.(?:get|post|put|delete)\s*\("#);
static PY_INPUT: Lazy<Regex> = lazy_re!(r#"(?:(\w+)\s*=\s*)?input\s*\("#);
static PY_DB_READ: Lazy<Regex> = lazy_re!(r#"(?:(\w+)\s*=\s*)?cursor\.(?:execute|fetchall|fetchone)\s*\("#);

pub fn detect_sources(path: &Path, content: &str) -> Vec<TaintSource> {
    let is_py = path.extension().and_then(|e| e.to_str()) == Some("py");
    let mut sources = Vec::new();

    let patterns: &[(&Lazy<Regex>, SourceKind)] = if is_py {
        &[
            (&PY_ENV_VAR, SourceKind::EnvVar),
            (&PY_CLI_ARG, SourceKind::CliArg),
            (&PY_FILE_READ, SourceKind::FileRead),
            (&PY_HTTP_REQ, SourceKind::HttpRequest),
            (&PY_INPUT, SourceKind::UserInput),
            (&PY_DB_READ, SourceKind::DbRead),
        ]
    } else {
        &[
            (&RUST_ENV_VAR, SourceKind::EnvVar),
            (&RUST_CLI_ARG, SourceKind::CliArg),
            (&RUST_FILE_READ, SourceKind::FileRead),
            (&RUST_HTTP_REQ, SourceKind::HttpRequest),
            (&RUST_STDIN, SourceKind::UserInput),
            (&RUST_DB_READ, SourceKind::DbRead),
        ]
    };

    for (line_idx, line) in content.lines().enumerate() {
        for (re, kind) in patterns {
            if let Some(cap) = re.captures(line) {
                // First non-None capture group = variable name binding
                let symbol = cap
                    .iter()
                    .skip(1)
                    .flatten()
                    .next()
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_else(|| format!("<source:{}>", kind_name(kind)));
                sources.push(TaintSource {
                    file: path.to_path_buf(),
                    line: line_idx + 1,
                    kind: kind.clone(),
                    symbol,
                });
            }
        }
    }
    sources
}

fn kind_name(k: &SourceKind) -> &'static str {
    match k {
        SourceKind::EnvVar => "env",
        SourceKind::CliArg => "cli",
        SourceKind::FileRead => "file",
        SourceKind::HttpRequest => "http",
        SourceKind::UserInput => "stdin",
        SourceKind::DbRead => "db",
    }
}
