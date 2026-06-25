//! Subprocess plugin loader.
//!
//! A plugin is a directory under `~/.aether/plugins/<plugin_name>/`
//! containing:
//!   - `manifest.json` — declares the plugin's tool name, description,
//!     input schema, and the command to invoke.
//!   - any backing executable / script the manifest's `command` points at.
//!
//! Wire protocol: when the agent calls the tool, aether spawns the
//! manifest's `command` (resolved relative to the plugin dir if
//! `command` starts with `./`), sends the JSON tool-call input on
//! stdin, and waits for the subprocess to exit. The captured stdout
//! is the tool's reply (UTF-8 text); a non-zero exit code surfaces
//! as `ToolError::Io`.
//!
//! Safety: this v1 has NO sandbox. Plugins run with the same
//! privileges as the aether process. The path is documented in the
//! plugin install docs — users opt into trust by dropping a manifest
//! into `~/.aether/plugins/`.
//!
//! Why subprocess (not WASM): zero new compile-time dependencies, any
//! language can implement a plugin, debugging is just stdio. WASM
//! sandboxing is a planned v0.17+ upgrade.

use aether_tools::{Tool, ToolError};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const PLUGIN_DIR_ENV: &str = "AETHER_PLUGIN_DIR";
const DEFAULT_PLUGIN_REL: &str = ".aether/plugins";

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("plugin dir {0}: {1}")]
    Discover(String, String),
    #[error("plugin {0}: manifest parse: {1}")]
    Manifest(String, String),
    #[error("plugin {0}: missing 'command' field")]
    MissingCommand(String),
}

/// JSON manifest declared by each plugin.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginManifest {
    /// Tool name as it will appear to the LLM (e.g. `plugin__myname`).
    pub name: String,
    /// One-line description shown in the tool list.
    pub description: String,
    /// JSON schema for the tool input. Surfaced to the LLM verbatim.
    pub input_schema: Value,
    /// Command to invoke. If it starts with `./`, resolved relative to
    /// the plugin directory; otherwise looked up via $PATH.
    pub command: String,
    /// Optional args appended to the command.
    #[serde(default)]
    pub args: Vec<String>,
    /// Optional working directory override. Defaults to the plugin dir.
    #[serde(default)]
    pub cwd: Option<PathBuf>,
}

/// Adapter that wraps a plugin manifest as an aether-tools `Tool`.
pub struct PluginTool {
    manifest: PluginManifest,
    plugin_dir: PathBuf,
}

impl PluginTool {
    pub fn new(manifest: PluginManifest, plugin_dir: PathBuf) -> Self {
        Self {
            manifest,
            plugin_dir,
        }
    }

    fn resolve_command(&self) -> PathBuf {
        if self.manifest.command.starts_with("./") {
            self.plugin_dir.join(&self.manifest.command)
        } else {
            PathBuf::from(&self.manifest.command)
        }
    }

    fn working_dir(&self) -> PathBuf {
        self.manifest
            .cwd
            .clone()
            .unwrap_or_else(|| self.plugin_dir.clone())
    }
}

#[async_trait]
impl Tool for PluginTool {
    fn name(&self) -> &str {
        &self.manifest.name
    }

    fn description(&self) -> &str {
        &self.manifest.description
    }

    fn input_schema(&self) -> Value {
        self.manifest.input_schema.clone()
    }

    async fn run(&self, input: Value) -> Result<String, ToolError> {
        let cmd_path = self.resolve_command();
        let cwd = self.working_dir();
        let input_bytes = serde_json::to_vec(&input)
            .map_err(|e| ToolError::Io(format!("encode plugin input: {e}")))?;

        let mut child = Command::new(&cmd_path)
            .args(&self.manifest.args)
            .current_dir(&cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                ToolError::Io(format!(
                    "spawn plugin {}: {e}",
                    cmd_path.display()
                ))
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&input_bytes).await.map_err(|e| {
                ToolError::Io(format!("write plugin stdin: {e}"))
            })?;
            stdin.shutdown().await.map_err(|e| {
                ToolError::Io(format!("close plugin stdin: {e}"))
            })?;
        }

        let output = child.wait_with_output().await.map_err(|e| {
            ToolError::Io(format!("wait plugin: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ToolError::Io(format!(
                "plugin '{}' exited with {}: {}",
                self.manifest.name,
                output.status,
                stderr.trim()
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

/// Resolve the directory aether looks in for plugins. Prefers
/// $AETHER_PLUGIN_DIR, falls back to ~/.aether/plugins.
pub fn plugin_dir() -> Option<PathBuf> {
    if let Ok(s) = std::env::var(PLUGIN_DIR_ENV) {
        if !s.is_empty() {
            return Some(PathBuf::from(s));
        }
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(DEFAULT_PLUGIN_REL))
}

/// Walk the plugin dir; for every subdirectory that contains a
/// `manifest.json`, parse it and produce a `PluginTool`.
pub fn discover_plugins() -> Vec<PluginTool> {
    let Some(root) = plugin_dir() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let dir = entry.path();
        let manifest_path = dir.join("manifest.json");
        if let Ok(bytes) = std::fs::read(&manifest_path) {
            match serde_json::from_slice::<PluginManifest>(&bytes) {
                Ok(manifest) => out.push(PluginTool::new(manifest, dir)),
                Err(e) => {
                    eprintln!(
                        "[aether-plugin] {}: bad manifest: {e}",
                        manifest_path.display()
                    );
                }
            }
        }
    }
    out
}

/// Parse a single manifest by path — exposed for unit tests + ad-hoc tooling.
pub fn parse_manifest(path: &Path) -> Result<PluginManifest, PluginError> {
    let bytes = std::fs::read(path).map_err(|e| {
        PluginError::Manifest(path.display().to_string(), e.to_string())
    })?;
    let m: PluginManifest = serde_json::from_slice(&bytes).map_err(|e| {
        PluginError::Manifest(path.display().to_string(), e.to_string())
    })?;
    if m.command.is_empty() {
        return Err(PluginError::MissingCommand(m.name));
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_manifest_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        let json = r#"{
            "name": "echo_plugin",
            "description": "echoes its input as JSON",
            "input_schema": {"type": "object"},
            "command": "./echo.sh",
            "args": ["--mode", "verbose"]
        }"#;
        std::fs::write(&path, json).unwrap();
        let m = parse_manifest(&path).expect("parse");
        assert_eq!(m.name, "echo_plugin");
        assert_eq!(m.command, "./echo.sh");
        assert_eq!(m.args, vec!["--mode", "verbose"]);
    }

    #[test]
    fn parse_manifest_rejects_empty_command() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        let json = r#"{"name":"x","description":"x","input_schema":{},"command":""}"#;
        std::fs::write(&path, json).unwrap();
        let err = parse_manifest(&path).expect_err("should reject empty command");
        assert!(matches!(err, PluginError::MissingCommand(_)));
    }

    #[test]
    fn discover_plugins_walks_dir() {
        let dir = tempfile::tempdir().unwrap();
        // Create a single plugin under <tmp>/myplugin/manifest.json.
        let plugin_dir = dir.path().join("myplugin");
        std::fs::create_dir(&plugin_dir).unwrap();
        let manifest = r#"{
            "name": "tester",
            "description": "test plugin",
            "input_schema": {"type":"object"},
            "command": "/bin/echo"
        }"#;
        std::fs::write(plugin_dir.join("manifest.json"), manifest).unwrap();

        // Stub $AETHER_PLUGIN_DIR to the tmp dir.
        let prev = std::env::var(PLUGIN_DIR_ENV).ok();
        std::env::set_var(PLUGIN_DIR_ENV, dir.path());
        let found = discover_plugins();
        // restore
        if let Some(v) = prev {
            std::env::set_var(PLUGIN_DIR_ENV, v);
        } else {
            std::env::remove_var(PLUGIN_DIR_ENV);
        }

        assert_eq!(found.len(), 1, "expected 1 plugin discovered");
        assert_eq!(found[0].name(), "tester");
        assert_eq!(found[0].description(), "test plugin");
    }

    #[tokio::test]
    async fn live_subprocess_plugin_executes() {
        // Create a tiny shell-script "plugin" that reads stdin JSON and
        // echoes back a literal string. Verifies the full subprocess
        // round-trip: spawn → write stdin → read stdout → exit code 0.
        let dir = tempfile::tempdir().unwrap();
        let plugin_dir = dir.path().join("echoplugin");
        std::fs::create_dir(&plugin_dir).unwrap();
        let script_path = plugin_dir.join("echo.sh");
        let mut f = std::fs::File::create(&script_path).unwrap();
        writeln!(
            f,
            "#!/usr/bin/env bash\nread INPUT\necho \"got: $INPUT\""
        )
        .unwrap();
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
        }

        let manifest = PluginManifest {
            name: "echo".into(),
            description: "echoes the input".into(),
            input_schema: serde_json::json!({"type":"object"}),
            command: "./echo.sh".into(),
            args: vec![],
            cwd: None,
        };
        let tool = PluginTool::new(manifest, plugin_dir);
        let out = tool
            .run(serde_json::json!({"x": 42}))
            .await
            .expect("plugin run");
        assert!(
            out.contains("got:") && out.contains("x"),
            "expected echo'd input, got: {out}"
        );
    }
}
