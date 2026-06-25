//! Persistence layer.
//!
//! Skeleton: filesystem paths + atomic transcript-append primitives. The
//! sqlite + lancedb backends land behind feature flags so the core can
//! build without those native deps.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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
    pub fn vector_db(&self) -> PathBuf {
        self.global_root.join("vector.db")
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
}
