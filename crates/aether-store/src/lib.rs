//! Persistent settings store at `~/.aether/settings.json`.
//!
//! All callers go through `load()` (deserialised view) and `set()` (atomic
//! single-field update that preserves unknown keys). Atomic write = tmp +
//! rename, mode 0600 on Unix.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const SETTINGS_REL_PATH: &str = ".aether/settings.json";

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct Settings {
    pub default_model: Option<String>,
    pub permission_mode: Option<String>,
    pub always_allow_tools: Vec<String>,
    /// Extra env vars set at process start (does not override existing vars).
    pub env: HashMap<String, String>,
}

pub fn settings_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(SETTINGS_REL_PATH)
}

pub fn load() -> Settings {
    let p = settings_path();
    match std::fs::read_to_string(&p) {
        Ok(s) => match serde_json::from_str::<Settings>(&s) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[warn] {}: {e}", p.display());
                Settings::default()
            }
        },
        Err(_) => Settings::default(),
    }
}

pub fn apply_env(settings: &Settings) {
    for (k, v) in &settings.env {
        if std::env::var_os(k).is_none() {
            std::env::set_var(k, v);
        }
    }
}

fn write_value(value: serde_json::Value) -> anyhow::Result<usize> {
    let path = settings_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let body = serde_json::to_vec_pretty(&value)?;
    let len = body.len();
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &path)?;
    Ok(len)
}

/// Atomic single-field update. Recognised keys:
///   - `default_model`, `permission_mode` → string
///   - `always_allow_tools` → comma-separated list
///   - `env.<KEY>` → string nested under env
pub fn set(key: &str, value: &str) -> anyhow::Result<usize> {
    let path = settings_path();
    let mut current: serde_json::Value = match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => {
            serde_json::from_str(&s).unwrap_or_else(|_| serde_json::json!({}))
        }
        _ => serde_json::json!({}),
    };
    if !current.is_object() {
        current = serde_json::json!({});
    }
    let obj = current.as_object_mut().expect("object");
    match key {
        "default_model" | "permission_mode" => {
            obj.insert(
                key.to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
        "always_allow_tools" => {
            let list: Vec<serde_json::Value> = value
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| serde_json::Value::String(s.to_string()))
                .collect();
            obj.insert("always_allow_tools".into(), serde_json::Value::Array(list));
        }
        k if k.starts_with("env.") => {
            let env_key = &k[4..];
            let env_obj = obj
                .entry("env")
                .or_insert_with(|| serde_json::json!({}));
            if let Some(e) = env_obj.as_object_mut() {
                e.insert(
                    env_key.to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            }
        }
        other => anyhow::bail!(
            "unknown settings key '{other}'. Recognised: default_model, permission_mode, always_allow_tools, env.KEY"
        ),
    }
    write_value(current)
}

/// Append a tool to settings.always_allow_tools (dedup). Returns `Ok(true)`
/// when newly added; `Ok(false)` when already present.
pub fn append_always_allow(tool_name: &str) -> anyhow::Result<bool> {
    let path = settings_path();
    let mut current: serde_json::Value = match std::fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => {
            serde_json::from_str(&s).unwrap_or_else(|_| serde_json::json!({}))
        }
        _ => serde_json::json!({}),
    };
    if !current.is_object() {
        current = serde_json::json!({});
    }
    let obj = current.as_object_mut().expect("object");
    let arr = obj
        .entry("always_allow_tools")
        .or_insert_with(|| serde_json::Value::Array(vec![]));
    if let Some(list) = arr.as_array_mut() {
        if list.iter().any(|v| v.as_str() == Some(tool_name)) {
            return Ok(false);
        }
        list.push(serde_json::Value::String(tool_name.to_string()));
    }
    write_value(current)?;
    Ok(true)
}

// ── retained from skeleton (Paths struct used by future sqlite/lancedb) ──

#[derive(Debug, Clone)]
pub struct Paths {
    pub global_root: PathBuf,
    pub project_root: PathBuf,
}

impl Paths {
    pub fn from_cwd(cwd: &Path, home: &Path) -> Self {
        Self {
            global_root: home.join(".aether"),
            project_root: cwd.join(".aether"),
        }
    }
    pub fn settings_global(&self) -> PathBuf {
        self.global_root.join("settings.json")
    }
    pub fn settings_project(&self) -> PathBuf {
        self.project_root.join("settings.json")
    }
    pub fn sessions_dir(&self) -> PathBuf {
        self.global_root.join("projects")
    }
    pub fn memory_dir(&self) -> PathBuf {
        self.global_root.join("memory")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptEntry {
    pub ts: String,
    pub role: String,
    pub content: serde_json::Value,
    pub hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(String),
    #[error("encode: {0}")]
    Encode(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_compose() {
        let p = Paths::from_cwd(Path::new("/work/proj"), Path::new("/home/op"));
        assert_eq!(p.global_root, PathBuf::from("/home/op/.aether"));
        assert_eq!(p.project_root, PathBuf::from("/work/proj/.aether"));
        assert!(p.sessions_dir().ends_with("projects"));
    }

    #[test]
    fn settings_default_is_empty() {
        let s = Settings::default();
        assert!(s.default_model.is_none());
        assert!(s.always_allow_tools.is_empty());
        assert!(s.env.is_empty());
    }
}
