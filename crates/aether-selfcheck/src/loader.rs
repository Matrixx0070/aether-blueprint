use crate::rule::Rule;
use std::fs;
use std::path::Path;

pub fn load_rule_file(path: impl AsRef<Path>) -> Result<Rule, String> {
    let path = path.as_ref();
    let s = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_yaml::from_str(&s).map_err(|e| format!("{}: {e}", path.display()))
}

/// Load every `.yaml` / `.yml` file in `dir`, sorted by filename so the
/// `01_…`, `02_…` numbering keeps order stable and predictable.
pub fn load_dir(dir: impl AsRef<Path>) -> Result<Vec<Rule>, String> {
    let dir = dir.as_ref();
    let mut paths: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let s = name.to_string_lossy();
            s.ends_with(".yaml") || s.ends_with(".yml")
        })
        .map(|e| e.path())
        .collect();
    paths.sort();
    paths.into_iter().map(load_rule_file).collect()
}
