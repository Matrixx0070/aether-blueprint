//! Built-in tool implementations: Bash, Read, Write, Edit, Grep, Glob, LS.
//!
//! Each tool follows the same contract: it deserializes its JSON input,
//! performs the operation, and returns a single `String` that becomes the
//! tool-result content the model sees on the next turn. Errors are
//! returned as `ToolError`; the executor wraps them with the `is_error`
//! flag so the model can choose to retry or change approach.

use crate::{Tool, ToolError};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

// ── shared helpers ────────────────────────────────────────────────────────

fn parse_input<T: for<'de> Deserialize<'de>>(v: Value) -> Result<T, ToolError> {
    serde_json::from_value(v).map_err(|e| ToolError::Schema(e.to_string()))
}

fn absolute_path(p: &str) -> Result<PathBuf, ToolError> {
    let pb = PathBuf::from(p);
    if !pb.is_absolute() {
        return Err(ToolError::Schema(format!(
            "path must be absolute: {p}"
        )));
    }
    Ok(pb)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut out = s[..max].to_string();
        out.push_str(&format!("\n[…truncated {} bytes]", s.len() - max));
        out
    }
}

const MAX_TOOL_OUTPUT: usize = 200_000;
const DEFAULT_BASH_TIMEOUT_MS: u64 = 120_000;
const MAX_BASH_TIMEOUT_MS: u64 = 600_000;

/// Shared cancellation flag for in-flight long-running tools (currently
/// just Bash). The CLI's signal handler flips it on Ctrl-C while a turn
/// is executing; tools poll it and shut down their subprocess.
pub static CANCEL_FLAG: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Convenience: clear the flag at the start of each user turn.
pub fn reset_cancel() {
    CANCEL_FLAG.store(false, std::sync::atomic::Ordering::SeqCst);
}

pub fn cancelled() -> bool {
    CANCEL_FLAG.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn request_cancel() {
    CANCEL_FLAG.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Heuristic: any NUL byte in the first 8 KiB is a strong signal that the
/// file is binary. This mirrors `file(1)`'s classic strategy. Text files
/// (including UTF-8 with high bytes) virtually never contain NUL.
fn looks_binary(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(8192)];
    head.contains(&0u8)
}

// ── Bash ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct BashInput {
    command: String,
    #[serde(default)]
    timeout: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
}

pub struct BashTool;

#[async_trait]
impl Tool for BashTool {
    fn name(&self) -> &str {
        "Bash"
    }
    fn description(&self) -> &str {
        "Execute a shell command via /bin/bash -c. Returns combined stdout/stderr. \
         Optional timeout in milliseconds (default 120000, max 600000)."
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "command":     { "type": "string", "description": "Shell command to execute" },
                "timeout":     { "type": "number", "description": "Timeout in ms (default 120000, max 600000)" },
                "description": { "type": "string", "description": "Brief 5-10 word description of the command" }
            },
            "required": ["command"]
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let inp: BashInput = parse_input(input)?;
        let timeout_ms = inp
            .timeout
            .unwrap_or(DEFAULT_BASH_TIMEOUT_MS)
            .min(MAX_BASH_TIMEOUT_MS);

        let mut child = Command::new("/bin/bash")
            .arg("-c")
            .arg(&inp.command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ToolError::Io(format!("spawn: {e}")))?;

        let mut stdout = child.stdout.take().expect("stdout piped");
        let mut stderr = child.stderr.take().expect("stderr piped");

        let mut out_buf = Vec::new();
        let mut err_buf = Vec::new();

        let combined = async {
            tokio::try_join!(
                stdout.read_to_end(&mut out_buf),
                stderr.read_to_end(&mut err_buf),
                child.wait(),
            )
        };

        // Race the combined io+wait against (a) the configured timeout and
        // (b) a periodic check of the global cancellation flag.
        let result = tokio::select! {
            r = tokio::time::timeout(Duration::from_millis(timeout_ms), combined) => match r {
                Ok(inner) => Some(inner),
                Err(_) => None, // timeout
            },
            _ = async {
                loop {
                    if cancelled() { break; }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            } => {
                // cancellation path
                None
            }
        };

        match result {
            Some(Ok((_, _, status))) => {
                let mut combined = String::new();
                if !out_buf.is_empty() {
                    combined.push_str(&String::from_utf8_lossy(&out_buf));
                }
                if !err_buf.is_empty() {
                    if !combined.is_empty() && !combined.ends_with('\n') {
                        combined.push('\n');
                    }
                    combined.push_str(&String::from_utf8_lossy(&err_buf));
                }
                let code = status.code().unwrap_or(-1);
                if combined.is_empty() {
                    combined = format!("(no output)\n");
                }
                combined = truncate(&combined, MAX_TOOL_OUTPUT);
                if code != 0 {
                    Ok(format!("{combined}\n[exit code: {code}]"))
                } else {
                    Ok(combined)
                }
            }
            Some(Err(e)) => Err(ToolError::Io(format!("io: {e}"))),
            None => {
                let _ = child.start_kill();
                if cancelled() {
                    Err(ToolError::Io("cancelled by user (Ctrl-C)".into()))
                } else {
                    Err(ToolError::Io(format!(
                        "command timed out after {timeout_ms}ms"
                    )))
                }
            }
        }
    }
}

// ── Read ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ReadInput {
    file_path: String,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

pub struct ReadTool;

#[async_trait]
impl Tool for ReadTool {
    fn name(&self) -> &str {
        "Read"
    }
    fn description(&self) -> &str {
        "Read a file from the local filesystem. Returns content with line numbers \
         in `cat -n` format. Supports optional offset (1-indexed start line) and \
         limit (number of lines). Default reads up to 2000 lines from start."
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string", "description": "Absolute path to the file" },
                "offset":    { "type": "number", "description": "1-indexed start line (optional)" },
                "limit":     { "type": "number", "description": "Number of lines to read (default 2000)" }
            },
            "required": ["file_path"]
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let inp: ReadInput = parse_input(input)?;
        let path = absolute_path(&inp.file_path)?;
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| ToolError::Io(format!("{}: {e}", path.display())))?;
        if bytes.is_empty() {
            return Ok("[empty file]".to_string());
        }
        if looks_binary(&bytes) {
            return Ok(format!(
                "[binary file: {} bytes — refusing to inline. Use Bash with `file`, `head`, or a domain-specific tool.]",
                bytes.len()
            ));
        }
        let text = String::from_utf8_lossy(&bytes);
        let start = inp.offset.unwrap_or(1).max(1);
        let limit = inp.limit.unwrap_or(2000);
        let mut out = String::new();
        let mut emitted = 0usize;
        for (i, line) in text.lines().enumerate() {
            let line_no = i + 1;
            if line_no < start {
                continue;
            }
            if emitted >= limit {
                break;
            }
            out.push_str(&format!("{line_no:6}\t{line}\n"));
            emitted += 1;
        }
        if emitted == 0 {
            return Ok(format!(
                "[no lines in range — file has {} lines, requested start={start}]",
                text.lines().count()
            ));
        }
        Ok(truncate(&out, MAX_TOOL_OUTPUT))
    }
}

// ── Write ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct WriteInput {
    file_path: String,
    content: String,
}

pub struct WriteTool;

#[async_trait]
impl Tool for WriteTool {
    fn name(&self) -> &str {
        "Write"
    }
    fn description(&self) -> &str {
        "Write a file (creates or overwrites). Parent directories are NOT created \
         automatically — use Bash mkdir -p first if needed."
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string", "description": "Absolute path" },
                "content":   { "type": "string", "description": "File contents" }
            },
            "required": ["file_path", "content"]
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let inp: WriteInput = parse_input(input)?;
        let path = absolute_path(&inp.file_path)?;
        tokio::fs::write(&path, &inp.content)
            .await
            .map_err(|e| ToolError::Io(format!("{}: {e}", path.display())))?;
        Ok(format!(
            "wrote {} bytes to {}",
            inp.content.len(),
            path.display()
        ))
    }
}

// ── Edit ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct EditInput {
    file_path: String,
    old_string: String,
    new_string: String,
    #[serde(default)]
    replace_all: bool,
}

pub struct EditTool;

#[async_trait]
impl Tool for EditTool {
    fn name(&self) -> &str {
        "Edit"
    }
    fn description(&self) -> &str {
        "Replace an exact string in a file. Errors if `old_string` is not unique \
         and `replace_all` is false. Errors if `old_string` is not found."
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "file_path":   { "type": "string", "description": "Absolute path" },
                "old_string":  { "type": "string", "description": "Exact text to find" },
                "new_string":  { "type": "string", "description": "Replacement text" },
                "replace_all": { "type": "boolean", "description": "Replace every occurrence", "default": false }
            },
            "required": ["file_path", "old_string", "new_string"]
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let inp: EditInput = parse_input(input)?;
        let path = absolute_path(&inp.file_path)?;
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| ToolError::Io(format!("{}: {e}", path.display())))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| ToolError::Schema("file is not valid UTF-8".into()))?;
        if inp.old_string == inp.new_string {
            return Err(ToolError::Schema(
                "old_string and new_string are identical".into(),
            ));
        }
        let count = text.matches(&inp.old_string).count();
        if count == 0 {
            return Err(ToolError::Schema(format!(
                "old_string not found in {}",
                path.display()
            )));
        }
        if count > 1 && !inp.replace_all {
            return Err(ToolError::Schema(format!(
                "old_string matches {count} times — provide more context or set replace_all=true"
            )));
        }
        let new_text = if inp.replace_all {
            text.replace(&inp.old_string, &inp.new_string)
        } else {
            text.replacen(&inp.old_string, &inp.new_string, 1)
        };
        tokio::fs::write(&path, new_text.as_bytes())
            .await
            .map_err(|e| ToolError::Io(format!("{}: {e}", path.display())))?;
        Ok(format!(
            "edited {} ({} replacement{} made)",
            path.display(),
            count,
            if count == 1 { "" } else { "s" }
        ))
    }
}

// ── Grep ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GrepInput {
    pattern: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    glob: Option<String>,
    #[serde(default)]
    output_mode: Option<String>,
    #[serde(default, rename = "-i")]
    case_insensitive: bool,
    #[serde(default, rename = "-n")]
    line_numbers: Option<bool>,
    #[serde(default, rename = "-C")]
    context: Option<usize>,
    #[serde(default)]
    head_limit: Option<usize>,
    #[serde(default, rename = "type")]
    file_type: Option<String>,
}

pub struct GrepTool;

#[async_trait]
impl Tool for GrepTool {
    fn name(&self) -> &str {
        "Grep"
    }
    fn description(&self) -> &str {
        "Search file contents using ripgrep. Supports regex, glob filters, \
         case-insensitive matching, line numbers, context. Output modes: \
         'content' (matching lines), 'files_with_matches' (paths, default), \
         'count' (match counts)."
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "pattern":     { "type": "string", "description": "Regex pattern (ripgrep syntax)" },
                "path":        { "type": "string", "description": "Directory or file to search" },
                "glob":        { "type": "string", "description": "Glob filter, e.g. '*.rs'" },
                "output_mode": { "type": "string", "enum": ["content","files_with_matches","count"] },
                "-i":          { "type": "boolean" },
                "-n":          { "type": "boolean" },
                "-C":          { "type": "number" },
                "head_limit":  { "type": "number" },
                "type":        { "type": "string", "description": "File type filter" }
            },
            "required": ["pattern"]
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let inp: GrepInput = parse_input(input)?;
        let mode = inp.output_mode.as_deref().unwrap_or("files_with_matches");
        let mut cmd = Command::new("rg");
        cmd.arg("--no-heading");
        match mode {
            "files_with_matches" => {
                cmd.arg("-l");
            }
            "count" => {
                cmd.arg("-c");
            }
            "content" => {
                if inp.line_numbers.unwrap_or(true) {
                    cmd.arg("-n");
                }
                if let Some(c) = inp.context {
                    cmd.arg(format!("-C{c}"));
                }
            }
            other => {
                return Err(ToolError::Schema(format!(
                    "invalid output_mode: {other}"
                )))
            }
        }
        if inp.case_insensitive {
            cmd.arg("-i");
        }
        if let Some(g) = &inp.glob {
            cmd.arg("--glob").arg(g);
        }
        if let Some(t) = &inp.file_type {
            cmd.arg("--type").arg(t);
        }
        cmd.arg(&inp.pattern);
        if let Some(p) = &inp.path {
            cmd.arg(p);
        }
        let output = cmd
            .output()
            .await
            .map_err(|e| ToolError::Io(format!("ripgrep: {e}")))?;
        let code = output.status.code().unwrap_or(-1);
        // ripgrep: 0 = matches found, 1 = no matches, 2 = error
        if code == 1 {
            return Ok("(no matches)".to_string());
        }
        if !output.status.success() {
            return Err(ToolError::Io(format!(
                "ripgrep exit {code}: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let trimmed = if let Some(n) = inp.head_limit {
            stdout
                .lines()
                .take(n)
                .collect::<Vec<_>>()
                .join("\n")
        } else if mode == "files_with_matches" || mode == "count" {
            // default head limit to keep response small
            stdout
                .lines()
                .take(250)
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            stdout
                .lines()
                .take(250)
                .collect::<Vec<_>>()
                .join("\n")
        };
        Ok(truncate(&trimmed, MAX_TOOL_OUTPUT))
    }
}

// ── Glob ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GlobInput {
    pattern: String,
    #[serde(default)]
    path: Option<String>,
}

pub struct GlobTool;

#[async_trait]
impl Tool for GlobTool {
    fn name(&self) -> &str {
        "Glob"
    }
    fn description(&self) -> &str {
        "Find files matching a glob pattern (e.g. '**/*.rs'). Returns paths \
         sorted by modification time, newest first. Optional `path` to scope \
         the search; defaults to current working directory."
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "pattern": { "type": "string", "description": "Glob pattern" },
                "path":    { "type": "string", "description": "Search root (default: cwd)" }
            },
            "required": ["pattern"]
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let inp: GlobInput = parse_input(input)?;
        let root = inp
            .path
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
        let full_pattern = if inp.pattern.starts_with('/') {
            inp.pattern.clone()
        } else {
            root.join(&inp.pattern).to_string_lossy().to_string()
        };
        let mut matches: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        for entry in glob::glob(&full_pattern)
            .map_err(|e| ToolError::Schema(format!("invalid glob: {e}")))?
            .flatten()
        {
            if entry.is_file() {
                let mtime = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::UNIX_EPOCH);
                matches.push((mtime, entry));
            }
        }
        matches.sort_by(|a, b| b.0.cmp(&a.0));
        if matches.is_empty() {
            return Ok("(no matches)".to_string());
        }
        let out = matches
            .into_iter()
            .take(500)
            .map(|(_, p)| p.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        Ok(truncate(&out, MAX_TOOL_OUTPUT))
    }
}

// ── LS ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct LsInput {
    path: String,
    #[serde(default)]
    ignore: Option<Vec<String>>,
}

pub struct LsTool;

#[async_trait]
impl Tool for LsTool {
    fn name(&self) -> &str {
        "LS"
    }
    fn description(&self) -> &str {
        "List files and directories under an absolute path, one level deep. \
         Directory entries end in '/'. Optional `ignore` is a list of glob \
         patterns to skip."
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path":   { "type": "string", "description": "Absolute path to list" },
                "ignore": { "type": "array", "items": { "type": "string" }, "description": "Glob ignore patterns" }
            },
            "required": ["path"]
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let inp: LsInput = parse_input(input)?;
        let path = absolute_path(&inp.path)?;
        let ignore = inp.ignore.unwrap_or_default();
        let ignore_globs: Vec<glob::Pattern> = ignore
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();
        let mut entries = tokio::fs::read_dir(&path)
            .await
            .map_err(|e| ToolError::Io(format!("{}: {e}", path.display())))?;
        let mut items: Vec<(bool, String)> = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| ToolError::Io(e.to_string()))?
        {
            let name = entry.file_name().to_string_lossy().to_string();
            if ignore_globs.iter().any(|g| g.matches(&name)) {
                continue;
            }
            let is_dir = entry
                .file_type()
                .await
                .map(|ft| ft.is_dir())
                .unwrap_or(false);
            items.push((is_dir, name));
        }
        items.sort_by(|a, b| match (a.0, b.0) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.1.to_lowercase().cmp(&b.1.to_lowercase()),
        });
        if items.is_empty() {
            return Ok(format!("(empty directory: {})", path.display()));
        }
        let body = items
            .into_iter()
            .map(|(is_dir, n)| if is_dir { format!("{n}/") } else { n })
            .collect::<Vec<_>>()
            .join("\n");
        Ok(format!("{}:\n{}", path.display(), body))
    }
}

// ── WebFetch ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct WebFetchInput {
    url: String,
    #[serde(default)]
    #[allow(dead_code)]
    prompt: Option<String>,
}

pub struct WebFetchTool;

#[async_trait]
impl Tool for WebFetchTool {
    fn name(&self) -> &str {
        "WebFetch"
    }
    fn description(&self) -> &str {
        "Fetch a URL and return its text content (HTML stripped to plain text). \
         For pages with code samples, the structure is preserved as best-effort. \
         Network timeout is 30s, max payload 5 MB."
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "url":    { "type": "string", "description": "URL to fetch (http(s)://...)" },
                "prompt": { "type": "string", "description": "Optional hint about what to extract — currently advisory only" }
            },
            "required": ["url"]
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let inp: WebFetchInput = parse_input(input)?;
        if !inp.url.starts_with("http://") && !inp.url.starts_with("https://") {
            return Err(ToolError::Schema(format!(
                "url must start with http(s)://: {}",
                inp.url
            )));
        }
        let client = reqwest::Client::builder()
            .user_agent("aether-cli/0.2 (+https://aether.dev)")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| ToolError::Io(format!("client: {e}")))?;
        let resp = client
            .get(&inp.url)
            .send()
            .await
            .map_err(|e| ToolError::Io(format!("fetch: {e}")))?;
        let status = resp.status();
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ToolError::Io(format!("read body: {e}")))?;
        if bytes.len() > 5 * 1024 * 1024 {
            return Err(ToolError::Io(format!(
                "payload too large: {} bytes (max 5 MiB)",
                bytes.len()
            )));
        }
        let text = String::from_utf8_lossy(&bytes);
        let stripped = if ct.contains("text/html") || text.trim_start().starts_with('<') {
            html_to_text(&text)
        } else {
            text.to_string()
        };
        let header = format!(
            "[HTTP {status}, content-type: {}, {} bytes]\n",
            if ct.is_empty() { "?" } else { &ct },
            bytes.len()
        );
        Ok(truncate(&format!("{header}{stripped}"), MAX_TOOL_OUTPUT))
    }
}

/// Very lightweight HTML → text: drop script/style blocks, then strip
/// all remaining tags, decode a small set of entities, collapse runs of
/// whitespace. Not a full parser — fast enough for inline use.
fn html_to_text(html: &str) -> String {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static SCRIPT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?si)<script\b[^>]*>.*?</script>").unwrap());
    static STYLE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?si)<style\b[^>]*>.*?</style>").unwrap());
    static NOSCRIPT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?si)<noscript\b[^>]*>.*?</noscript>").unwrap());
    static TAGS: Lazy<Regex> = Lazy::new(|| Regex::new(r"<[^>]+>").unwrap());
    static WS: Lazy<Regex> = Lazy::new(|| Regex::new(r"[ \t]+").unwrap());
    static NL: Lazy<Regex> = Lazy::new(|| Regex::new(r"\n{3,}").unwrap());
    let s = SCRIPT.replace_all(html, "");
    let s = STYLE.replace_all(&s, "");
    let s = NOSCRIPT.replace_all(&s, "");
    let s = TAGS.replace_all(&s, " ");
    let s = s
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'");
    let s = WS.replace_all(&s, " ");
    let s = NL.replace_all(&s, "\n\n");
    s.trim().to_string()
}

// ── NotebookEdit ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NotebookEditInput {
    notebook_path: String,
    new_source: String,
    #[serde(default)]
    cell_id: Option<String>,
    #[serde(default)]
    cell_index: Option<usize>,
    #[serde(default)]
    cell_type: Option<String>, // "code" | "markdown" — only used on insert/conversion
    #[serde(default)]
    edit_mode: Option<String>, // "replace" (default) | "insert" | "delete"
}

pub struct NotebookEditTool;

#[async_trait]
impl Tool for NotebookEditTool {
    fn name(&self) -> &str {
        "NotebookEdit"
    }
    fn description(&self) -> &str {
        "Edit a Jupyter notebook (.ipynb). Identify the cell by `cell_id` or \
         `cell_index` (0-based). edit_mode = 'replace' (default) overwrites \
         the cell's source; 'insert' adds a new cell after the target; \
         'delete' removes the target. cell_type ('code' or 'markdown') is \
         used when inserting."
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "notebook_path": { "type": "string", "description": "Absolute path to the .ipynb" },
                "new_source":    { "type": "string", "description": "Replacement cell source (or new cell source on insert)" },
                "cell_id":       { "type": "string", "description": "Target cell id (preferred when notebook has ids)" },
                "cell_index":    { "type": "number", "description": "Target cell index (0-based, used when cell_id absent)" },
                "cell_type":     { "type": "string", "enum": ["code","markdown"] },
                "edit_mode":     { "type": "string", "enum": ["replace","insert","delete"] }
            },
            "required": ["notebook_path", "new_source"]
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let inp: NotebookEditInput = parse_input(input)?;
        let path = absolute_path(&inp.notebook_path)?;
        if !inp.notebook_path.ends_with(".ipynb") {
            return Err(ToolError::Schema(format!(
                "not a .ipynb file: {}",
                path.display()
            )));
        }
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| ToolError::Io(format!("{}: {e}", path.display())))?;
        let mut nb: Value = serde_json::from_slice(&bytes)
            .map_err(|e| ToolError::Schema(format!("parse notebook: {e}")))?;
        let cells = nb
            .get_mut("cells")
            .and_then(|v| v.as_array_mut())
            .ok_or_else(|| ToolError::Schema("notebook has no `cells` array".into()))?;

        let target_idx: usize = match (inp.cell_id.as_deref(), inp.cell_index) {
            (Some(id), _) => cells
                .iter()
                .position(|c| c.get("id").and_then(|v| v.as_str()) == Some(id))
                .ok_or_else(|| ToolError::Schema(format!("cell_id not found: {id}")))?,
            (None, Some(i)) => {
                if i >= cells.len() {
                    return Err(ToolError::Schema(format!(
                        "cell_index {i} out of range (0..{})",
                        cells.len()
                    )));
                }
                i
            }
            (None, None) => {
                return Err(ToolError::Schema(
                    "must provide cell_id or cell_index".into(),
                ))
            }
        };

        let mode = inp.edit_mode.as_deref().unwrap_or("replace");
        match mode {
            "replace" => {
                let cell = &mut cells[target_idx];
                cell["source"] = lines_value(&inp.new_source);
                if let Some(ct) = inp.cell_type.as_deref() {
                    cell["cell_type"] = json!(ct);
                }
                if cell.get("outputs").is_some() && cell["cell_type"] == json!("code") {
                    cell["outputs"] = json!([]);
                    cell["execution_count"] = json!(null);
                }
            }
            "insert" => {
                let cell_type = inp.cell_type.as_deref().unwrap_or("code");
                let new_cell = json!({
                    "cell_type": cell_type,
                    "metadata": {},
                    "source": lines_value(&inp.new_source),
                    "outputs": if cell_type == "code" { json!([]) } else { json!(null) },
                    "execution_count": if cell_type == "code" { json!(null) } else { json!(null) },
                });
                cells.insert(target_idx + 1, new_cell);
            }
            "delete" => {
                cells.remove(target_idx);
            }
            other => return Err(ToolError::Schema(format!("unknown edit_mode: {other}"))),
        }

        let buf = serde_json::to_vec_pretty(&nb)
            .map_err(|e| ToolError::Schema(format!("encode notebook: {e}")))?;
        tokio::fs::write(&path, &buf)
            .await
            .map_err(|e| ToolError::Io(format!("write: {e}")))?;
        Ok(format!(
            "{} cell #{target_idx} in {}",
            mode,
            path.display()
        ))
    }
}

/// Notebook sources can be stored as either a single string or a list of
/// lines. We write as a single string (jupyter accepts both on read).
fn lines_value(s: &str) -> Value {
    json!(s)
}

// ── TodoWrite (model's own task tracker) ──────────────────────────────────

#[derive(Debug, Deserialize)]
struct TodoItem {
    content: String,
    #[serde(default = "default_status")]
    status: String,
    #[serde(default)]
    #[allow(dead_code)]
    active_form: Option<String>,
}

fn default_status() -> String {
    "pending".into()
}

#[derive(Debug, Deserialize)]
struct TodoWriteInput {
    todos: Vec<TodoItem>,
}

pub struct TodoWriteTool {
    state: std::sync::Mutex<Vec<(String, String)>>,
}

impl TodoWriteTool {
    pub fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Default for TodoWriteTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for TodoWriteTool {
    fn name(&self) -> &str {
        "TodoWrite"
    }
    fn description(&self) -> &str {
        "Track your in-progress task list. Replace the full list each call. \
         Useful for breaking a complex request into discrete steps and \
         showing progress to the user. Status values: pending, in_progress, \
         completed. Exactly one task should be in_progress at a time."
    }
    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "todos": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "content":     { "type": "string" },
                            "status":      { "type": "string", "enum": ["pending","in_progress","completed"] },
                            "active_form": { "type": "string", "description": "Present-continuous form shown during in_progress" }
                        },
                        "required": ["content", "status"]
                    }
                }
            },
            "required": ["todos"]
        })
    }
    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let inp: TodoWriteInput = parse_input(input)?;
        let new_state: Vec<(String, String)> = inp
            .todos
            .into_iter()
            .map(|t| (t.status, t.content))
            .collect();
        // Replace whole list
        let mut guard = self.state.lock().expect("TodoWrite mutex");
        *guard = new_state.clone();
        // Render summary
        let mut out = String::new();
        let mut pending = 0;
        let mut in_progress = 0;
        let mut completed = 0;
        for (i, (status, content)) in new_state.iter().enumerate() {
            let mark = match status.as_str() {
                "completed" => {
                    completed += 1;
                    "x"
                }
                "in_progress" => {
                    in_progress += 1;
                    "~"
                }
                _ => {
                    pending += 1;
                    " "
                }
            };
            out.push_str(&format!("{:>2}. [{}] {}\n", i + 1, mark, content));
        }
        out.push_str(&format!(
            "\n[totals: {} pending, {} in_progress, {} completed]",
            pending, in_progress, completed
        ));
        Ok(out)
    }
}

// ── registry helper ───────────────────────────────────────────────────────

pub fn register_builtins(registry: &mut crate::ToolRegistry) {
    registry.register(Box::new(BashTool));
    registry.register(Box::new(ReadTool));
    registry.register(Box::new(WriteTool));
    registry.register(Box::new(EditTool));
    registry.register(Box::new(GrepTool));
    registry.register(Box::new(GlobTool));
    registry.register(Box::new(LsTool));
    registry.register(Box::new(WebFetchTool));
    registry.register(Box::new(NotebookEditTool));
    registry.register(Box::new(TodoWriteTool::new()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ToolRegistry;

    #[tokio::test]
    async fn bash_echo_returns_stdout() {
        let out = BashTool.run(json!({"command": "echo hi"})).await.unwrap();
        assert!(out.starts_with("hi"));
    }

    #[tokio::test]
    async fn bash_nonzero_exit_is_reported() {
        let out = BashTool
            .run(json!({"command": "false"}))
            .await
            .unwrap();
        assert!(out.contains("[exit code: 1]"));
    }

    #[tokio::test]
    async fn bash_timeout_kills() {
        let res = BashTool
            .run(json!({"command": "sleep 5", "timeout": 200}))
            .await;
        assert!(matches!(res, Err(ToolError::Io(_))));
    }

    #[tokio::test]
    async fn read_write_edit_round_trip() {
        let dir = std::env::temp_dir().join("aether-tools-rt");
        let _ = tokio::fs::create_dir_all(&dir).await;
        let p = dir.join("a.txt");
        let path = p.to_string_lossy().to_string();
        WriteTool
            .run(json!({"file_path": path, "content": "hello world\nsecond line\n"}))
            .await
            .unwrap();
        let read = ReadTool.run(json!({"file_path": path})).await.unwrap();
        assert!(read.contains("hello world"));
        EditTool
            .run(json!({
                "file_path": path,
                "old_string": "hello world",
                "new_string": "goodbye world"
            }))
            .await
            .unwrap();
        let read2 = ReadTool.run(json!({"file_path": path})).await.unwrap();
        assert!(read2.contains("goodbye world"));
        assert!(!read2.contains("hello world"));
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn edit_rejects_duplicate_old_string() {
        let dir = std::env::temp_dir().join("aether-tools-dup");
        let _ = tokio::fs::create_dir_all(&dir).await;
        let p = dir.join("d.txt");
        let path = p.to_string_lossy().to_string();
        WriteTool
            .run(json!({"file_path": path, "content": "x\nx\nx\n"}))
            .await
            .unwrap();
        let res = EditTool
            .run(json!({"file_path": path, "old_string": "x", "new_string": "y"}))
            .await;
        assert!(matches!(res, Err(ToolError::Schema(_))));
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn ls_lists_temp_dir() {
        let out = LsTool
            .run(json!({"path": "/tmp"}))
            .await
            .unwrap();
        assert!(out.starts_with("/tmp:"));
    }

    #[tokio::test]
    async fn register_builtins_loads_all() {
        let mut r = ToolRegistry::new();
        register_builtins(&mut r);
        let names = r.names();
        for expected in ["Bash", "Read", "Write", "Edit", "Grep", "Glob", "LS", "WebFetch", "NotebookEdit", "TodoWrite"] {
            assert!(names.contains(&expected.to_string()), "missing: {expected}");
        }
    }

    #[tokio::test]
    async fn read_refuses_binary_files() {
        let dir = std::env::temp_dir().join("aether-bin");
        let _ = tokio::fs::create_dir_all(&dir).await;
        let p = dir.join("data.bin");
        // 9 KiB of garbage with lots of NULs and non-printables
        let mut bytes = vec![0u8; 9000];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        tokio::fs::write(&p, &bytes).await.unwrap();
        let path = p.to_string_lossy().to_string();
        let out = ReadTool.run(json!({"file_path": path})).await.unwrap();
        assert!(out.contains("[binary file"), "got: {out}");
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[tokio::test]
    async fn notebook_edit_replace_cell() {
        let dir = std::env::temp_dir().join("aether-nb");
        let _ = tokio::fs::create_dir_all(&dir).await;
        let p = dir.join("test.ipynb");
        let original = serde_json::json!({
            "cells": [
                {"cell_type": "code", "id": "c1", "metadata": {}, "source": "print('a')", "outputs": [], "execution_count": null},
                {"cell_type": "code", "id": "c2", "metadata": {}, "source": "print('b')", "outputs": [], "execution_count": null}
            ],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5
        });
        tokio::fs::write(&p, serde_json::to_vec(&original).unwrap()).await.unwrap();
        let path = p.to_string_lossy().to_string();
        NotebookEditTool
            .run(json!({"notebook_path": path, "cell_id": "c2", "new_source": "print('replaced')"}))
            .await
            .unwrap();
        let after: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&p).await.unwrap()).unwrap();
        assert_eq!(after["cells"][1]["source"], "print('replaced')");
        let _ = tokio::fs::remove_file(&p).await;
    }

    #[test]
    fn html_to_text_strips_tags_and_scripts() {
        let html = "<html><head><script>var x=1;</script><style>.x{}</style></head>\
                    <body><h1>Title</h1><p>Hello <b>world</b>!</p></body></html>";
        let out = html_to_text(html);
        assert!(out.contains("Title"));
        assert!(out.contains("Hello"));
        assert!(out.contains("world"));
        assert!(!out.contains("<"), "tags should be stripped: {out}");
        assert!(!out.contains("var x=1"), "script body should be dropped: {out}");
    }
}
