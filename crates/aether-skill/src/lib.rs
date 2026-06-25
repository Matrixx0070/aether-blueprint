//! Skill loader and `Skill` tool.
//!
//! Skills live as markdown files in `~/.aether/skills/*.md`. Each file may
//! begin with a YAML frontmatter block declaring `name` + `description`;
//! otherwise the filename stem becomes the name and the first heading the
//! description. The body of the file is returned verbatim when the model
//! invokes the skill — the model's next response then incorporates it.

use aether_tools::{Tool, ToolError};
use async_trait::async_trait;
use serde::Deserialize;
use std::path::PathBuf;

const SKILLS_REL_PATH: &str = ".aether/skills";

#[derive(Debug, Clone)]
pub struct LoadedSkill {
    pub name: String,
    pub description: String,
    pub body: String,
}

/// Discover skills in `~/.aether/skills/*.md`. Each file may begin with a
/// YAML frontmatter block (`--- ... ---`) declaring `name` and `description`;
/// otherwise the file stem becomes the name and the first markdown heading
/// becomes the description.
pub fn load_skills() -> Vec<LoadedSkill> {
    let mut out = Vec::new();
    let dir = match std::env::var_os("HOME").map(|h| PathBuf::from(h).join(SKILLS_REL_PATH)) {
        Some(d) => d,
        None => return out,
    };
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (mut name, mut description, body) = parse_skill_frontmatter(&raw);
        if name.is_empty() {
            name = stem.clone();
        }
        if description.is_empty() {
            description = first_heading(&body).unwrap_or_default();
        }
        out.push(LoadedSkill {
            name,
            description,
            body,
        });
    }
    out
}

fn parse_skill_frontmatter(raw: &str) -> (String, String, String) {
    let trimmed = raw.trim_start_matches('\u{feff}');
    if let Some(rest) = trimmed.strip_prefix("---") {
        if let Some(end) = rest.find("\n---") {
            let fm = &rest[..end];
            let body = rest[end + 4..].trim_start_matches('\n').to_string();
            let mut name = String::new();
            let mut desc = String::new();
            for line in fm.lines() {
                if let Some(v) = line.strip_prefix("name:") {
                    name = v.trim().trim_matches('"').to_string();
                } else if let Some(v) = line.strip_prefix("description:") {
                    desc = v.trim().trim_matches('"').to_string();
                }
            }
            return (name, desc, body);
        }
    }
    (String::new(), String::new(), raw.to_string())
}

fn first_heading(body: &str) -> Option<String> {
    for line in body.lines() {
        let t = line.trim_start_matches('#').trim();
        if !t.is_empty() {
            return Some(t.chars().take(120).collect());
        }
    }
    None
}

/// `Skill` tool exposed in the registry. Input declares `skill_name` (enum
/// of discovered names) and optional `args` (free-form). Returns the skill
/// body, which the model then incorporates.
pub struct SkillTool {
    pub skills: Vec<LoadedSkill>,
}

#[derive(Debug, Deserialize)]
struct SkillInput {
    skill_name: String,
    #[serde(default)]
    args: Option<String>,
}

#[async_trait]
impl Tool for SkillTool {
    fn name(&self) -> &str {
        "Skill"
    }
    fn description(&self) -> &str {
        "Invoke a named skill from ~/.aether/skills/. The skill's full body \
         is returned as the tool result and incorporated into the model's \
         next response. Use the input_schema enum to see available skill names."
    }
    fn input_schema(&self) -> serde_json::Value {
        let names: Vec<serde_json::Value> = self
            .skills
            .iter()
            .map(|s| serde_json::Value::String(s.name.clone()))
            .collect();
        let descriptions: serde_json::Map<String, serde_json::Value> = self
            .skills
            .iter()
            .map(|s| {
                (
                    s.name.clone(),
                    serde_json::Value::String(s.description.clone()),
                )
            })
            .collect();
        serde_json::json!({
            "type": "object",
            "properties": {
                "skill_name": {
                    "type": "string",
                    "enum": names,
                    "description": "Name of the skill to invoke"
                },
                "args": {
                    "type": "string",
                    "description": "Optional free-form args"
                }
            },
            "required": ["skill_name"],
            "x-skills": descriptions
        })
    }
    async fn run(&self, input: serde_json::Value) -> Result<String, ToolError> {
        let inp: SkillInput =
            serde_json::from_value(input).map_err(|e| ToolError::Schema(e.to_string()))?;
        let skill = self
            .skills
            .iter()
            .find(|s| s.name == inp.skill_name)
            .ok_or_else(|| ToolError::Schema(format!("unknown skill: {}", inp.skill_name)))?;
        let mut out = String::new();
        out.push_str(&format!("# skill: {}\n", skill.name));
        if let Some(args) = inp.args.as_deref().filter(|s| !s.is_empty()) {
            out.push_str(&format!("# args: {args}\n"));
        }
        out.push('\n');
        out.push_str(&skill.body);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontmatter_parses_name_and_description() {
        let raw = "---\nname: foo\ndescription: does foo\n---\nbody here\n";
        let (n, d, b) = parse_skill_frontmatter(raw);
        assert_eq!(n, "foo");
        assert_eq!(d, "does foo");
        assert_eq!(b.trim(), "body here");
    }

    #[test]
    fn frontmatter_absent_returns_raw() {
        let (n, d, b) = parse_skill_frontmatter("just body\n");
        assert!(n.is_empty());
        assert!(d.is_empty());
        assert_eq!(b, "just body\n");
    }

    #[tokio::test]
    async fn skill_tool_returns_body_for_known_name() {
        let t = SkillTool {
            skills: vec![LoadedSkill {
                name: "x".into(),
                description: "test".into(),
                body: "you are an x".into(),
            }],
        };
        let out = t.run(serde_json::json!({"skill_name": "x"})).await.unwrap();
        assert!(out.contains("you are an x"));
        assert!(out.contains("skill: x"));
    }

    #[tokio::test]
    async fn skill_tool_errors_on_unknown() {
        let t = SkillTool { skills: vec![] };
        let err = t
            .run(serde_json::json!({"skill_name": "missing"}))
            .await
            .unwrap_err();
        match err {
            ToolError::Schema(m) => assert!(m.contains("unknown skill")),
            other => panic!("expected Schema, got {other:?}"),
        }
    }
}
