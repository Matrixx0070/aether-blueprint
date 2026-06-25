use crate::rule::Rule;
use std::fs;
use std::path::Path;

pub fn load_rule_file(path: impl AsRef<Path>) -> Result<Rule, String> {
    let path = path.as_ref();
    let s = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_yaml::from_str(&s).map_err(|e| format!("{}: {e}", path.display()))
}

/// Parse a single rule from a YAML string. Used by the compile-time
/// bundled rule loader so callers don't need rules/*.yaml on disk.
pub fn load_rule_str(yaml: &str, name_for_error: &str) -> Result<Rule, String> {
    serde_yaml::from_str(yaml).map_err(|e| format!("{name_for_error}: {e}"))
}

/// The 14-rule library shipped with the binary, embedded via `include_str!`
/// at compile time. The order matches the on-disk numbering so rule
/// ordering stays stable.
pub fn bundled_rules() -> Result<Vec<Rule>, String> {
    let entries: &[(&str, &str)] = &[
        ("01_banned_truth_phrases", include_str!("../rules/01_banned_truth_phrases.yaml")),
        ("02_forbidden_memory_phrases", include_str!("../rules/02_forbidden_memory_phrases.yaml")),
        ("03_conditional_memory_phrases", include_str!("../rules/03_conditional_memory_phrases.yaml")),
        ("04_copyright_quote_length", include_str!("../rules/04_copyright_quote_length.yaml")),
        ("05_copyright_quotes_per_source", include_str!("../rules/05_copyright_quotes_per_source.yaml")),
        ("06_lyrics_and_poems", include_str!("../rules/06_lyrics_and_poems.yaml")),
        ("07_placeholder_leakage", include_str!("../rules/07_placeholder_leakage.yaml")),
        ("08_secret_in_output", include_str!("../rules/08_secret_in_output.yaml")),
        ("09_unverified_external_claim", include_str!("../rules/09_unverified_external_claim.yaml")),
        ("10_fabricated_attribution", include_str!("../rules/10_fabricated_attribution.yaml")),
        ("11_clinical_self_diagnosis", include_str!("../rules/11_clinical_self_diagnosis.yaml")),
        ("12_unprompted_profanity", include_str!("../rules/12_unprompted_profanity.yaml")),
        ("13_empty_or_thin_output", include_str!("../rules/13_empty_or_thin_output.yaml")),
        ("14_bare_url_without_provenance", include_str!("../rules/14_bare_url_without_provenance.yaml")),
    ];
    entries.iter().map(|(n, s)| load_rule_str(s, n)).collect()
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
