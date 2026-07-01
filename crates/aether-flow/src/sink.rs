//! Sink pattern detection — spots where tainted data leaves the program
//! or causes a side-effect (file write, network send, shell exec, DB write, log).

use crate::graph::{SinkKind, TaintSink};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

macro_rules! lazy_re {
    ($pat:expr) => {
        Lazy::new(|| Regex::new($pat).expect("sink pattern"))
    };
}

// ── Rust sink patterns ───────────────────────────────────────────────────────

static RUST_FILE_WRITE: Lazy<Regex> =
    lazy_re!(r#"fs::write\s*\(|\.write_all\s*\(|\.write\s*\(|BufWriter"#);
static RUST_HTTP_SEND: Lazy<Regex> =
    lazy_re!(r#"\.(?:post|put|patch|send)\s*\(|reqwest.*body"#);
static RUST_EXEC: Lazy<Regex> =
    lazy_re!(r#"Command::new\s*\(|process::Command|\.arg\s*\(|std::process::exit"#);
static RUST_DB_QUERY: Lazy<Regex> =
    lazy_re!(r#"\.execute\s*\(|\.query\s*\(|prepare\s*\(|sqlx::|rusqlite"#);
static RUST_LOG: Lazy<Regex> =
    lazy_re!(r#"println!\s*\(|eprintln!\s*\(|log::(?:info|warn|error|debug)!\s*\(|tracing::"#);
static RUST_DESER: Lazy<Regex> =
    lazy_re!(r#"serde_json::from_str|serde_yaml::from_str|from_slice|deserialize"#);

// ── Python sink patterns ─────────────────────────────────────────────────────

static PY_FILE_WRITE: Lazy<Regex> =
    lazy_re!(r#"\.write\s*\(|open\s*\(.*['"](w|wb|a)['"]"#);
static PY_HTTP_SEND: Lazy<Regex> =
    lazy_re!(r#"requests\.(?:post|put|patch)\s*\(|urllib.*urlopen"#);
static PY_EXEC: Lazy<Regex> =
    lazy_re!(r#"subprocess\.|os\.system\s*\(|os\.popen\s*\(|eval\s*\(|exec\s*\("#);
static PY_DB_QUERY: Lazy<Regex> =
    lazy_re!(r#"cursor\.execute\s*\(|\.executemany\s*\("#);
static PY_LOG: Lazy<Regex> =
    lazy_re!(r#"print\s*\(|logging\.(?:info|warn|error|debug|critical)\s*\("#);
static PY_DESER: Lazy<Regex> =
    lazy_re!(r#"json\.loads\s*\(|yaml\.safe_load\s*\(|pickle\.loads\s*\("#);

pub fn detect_sinks(path: &Path, content: &str) -> Vec<TaintSink> {
    let is_py = path.extension().and_then(|e| e.to_str()) == Some("py");
    let mut sinks = Vec::new();

    let patterns: &[(&Lazy<Regex>, SinkKind)] = if is_py {
        &[
            (&PY_FILE_WRITE, SinkKind::FileWrite),
            (&PY_HTTP_SEND, SinkKind::HttpSend),
            (&PY_EXEC, SinkKind::Exec),
            (&PY_DB_QUERY, SinkKind::DbQuery),
            (&PY_LOG, SinkKind::Log),
            (&PY_DESER, SinkKind::Deserialize),
        ]
    } else {
        &[
            (&RUST_FILE_WRITE, SinkKind::FileWrite),
            (&RUST_HTTP_SEND, SinkKind::HttpSend),
            (&RUST_EXEC, SinkKind::Exec),
            (&RUST_DB_QUERY, SinkKind::DbQuery),
            (&RUST_LOG, SinkKind::Log),
            (&RUST_DESER, SinkKind::Deserialize),
        ]
    };

    for (line_idx, line) in content.lines().enumerate() {
        for (re, kind) in patterns {
            if re.is_match(line) {
                let symbol = extract_symbol_near(line).unwrap_or_else(|| kind_name(kind).to_string());
                sinks.push(TaintSink {
                    file: path.to_path_buf(),
                    line: line_idx + 1,
                    kind: kind.clone(),
                    symbol,
                });
            }
        }
    }
    sinks
}

/// Best-effort: grab the first identifier token in the line as context label.
fn extract_symbol_near(line: &str) -> Option<String> {
    static IDENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b([a-zA-Z_]\w{1,40})\b").unwrap());
    IDENT.find(line.trim_start_matches(|c: char| c.is_whitespace()))
        .map(|m| m.as_str().to_string())
}

fn kind_name(k: &SinkKind) -> &'static str {
    match k {
        SinkKind::FileWrite => "file_write",
        SinkKind::HttpSend => "http_send",
        SinkKind::Exec => "exec",
        SinkKind::DbQuery => "db_query",
        SinkKind::Log => "log",
        SinkKind::Deserialize => "deserialize",
    }
}
