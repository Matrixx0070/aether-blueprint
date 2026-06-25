//! Skill loader.
//!
//! Skeleton: `SkillManifest` parsed from a SKILL.md frontmatter block plus
//! a `SkillRegistry` that holds them. Invocation dispatch lives in
//! `aether-core` once the agent loop wires the `Skill` tool.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub triggers: Vec<String>,
    #[serde(default)]
    pub args_schema: Option<serde_yaml::Value>,
}

#[derive(Default)]
pub struct SkillRegistry {
    skills: HashMap<String, SkillManifest>,
}

#[derive(Debug, thiserror::Error)]
pub enum SkillError {
    #[error("unknown skill: {0}")]
    Unknown(String),
    #[error("parse: {0}")]
    Parse(String),
}

impl SkillRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, manifest: SkillManifest) {
        self.skills.insert(manifest.name.clone(), manifest);
    }

    pub fn get(&self, name: &str) -> Option<&SkillManifest> {
        self.skills.get(name)
    }

    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.skills.keys().cloned().collect();
        names.sort();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_lookup() {
        let mut r = SkillRegistry::new();
        r.register(SkillManifest {
            name: "save".into(),
            description: "Save the current conversation to the wiki.".into(),
            triggers: vec!["save this".into()],
            args_schema: None,
        });
        assert_eq!(r.names(), vec!["save".to_string()]);
        assert!(r.get("save").is_some());
        assert!(r.get("nope").is_none());
    }
}
