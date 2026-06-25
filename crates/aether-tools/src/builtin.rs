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

        let result = tokio::time::timeout(Duration::from_millis(timeout_ms), combined).await;

        match result {
            Ok(Ok((_, _, status))) => {
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
            Ok(Err(e)) => Err(ToolError::Io(format!("io: {e}"))),
            Err(_) => {
                let _ = child.start_kill();
                Err(ToolError::Io(format!(
                    "command timed out after {timeout_ms}ms"
                )))
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

// ── registry helper ───────────────────────────────────────────────────────

pub fn register_builtins(registry: &mut crate::ToolRegistry) {
    registry.register(Box::new(BashTool));
    registry.register(Box::new(ReadTool));
    registry.register(Box::new(WriteTool));
    registry.register(Box::new(EditTool));
    registry.register(Box::new(GrepTool));
    registry.register(Box::new(GlobTool));
    registry.register(Box::new(LsTool));
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
    async fn register_builtins_loads_all_seven() {
        let mut r = ToolRegistry::new();
        register_builtins(&mut r);
        let names = r.names();
        for expected in ["Bash", "Read", "Write", "Edit", "Grep", "Glob", "LS"] {
            assert!(names.contains(&expected.to_string()), "missing: {expected}");
        }
    }
}
