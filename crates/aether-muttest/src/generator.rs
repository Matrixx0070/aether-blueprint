//! Mutation generator: scans source files and produces candidate Mutations.

use crate::mutation::{Mutation, MutationKind};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_EQ: Lazy<Regex> = Lazy::new(|| Regex::new(r"==|!=").unwrap());
// Note: `regex` crate does not support lookbehind; we filter candidates in the loop instead.
static RE_REL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(<=|>=|<|>)").unwrap());
static RE_ARITH_ADDSUB: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(\+|-)").unwrap());
static RE_LOGICAL: Lazy<Regex> = Lazy::new(|| Regex::new(r"&&|\|\|").unwrap());
static RE_BOOL_LIT: Lazy<Regex> = Lazy::new(|| Regex::new(r"\btrue\b|\bfalse\b").unwrap());
static RE_INT_LIT: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(\d+)\b").unwrap());
static RE_RETURN: Lazy<Regex> = Lazy::new(|| Regex::new(r"\breturn\s+[^;]+;").unwrap());
static RE_UNWRAP: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.unwrap\(\)").unwrap());
static RE_IF_COND: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bif\s+(!?)(\w[\w.()]*)\s*\{").unwrap());

/// Generate all candidate mutations for the given source.
/// `file` is used only for labelling (not read here — caller passes content).
pub fn generate_mutations(file: &str, source: &str) -> Vec<Mutation> {
    let mut mutations = Vec::new();
    let mut id = 0usize;

    for (line_idx, line) in source.lines().enumerate() {
        let lineno = line_idx + 1;

        // Skip comments and test-only blocks
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }

        // EqToNe
        for m in RE_EQ.find_iter(line) {
            let (orig, repl) = if m.as_str() == "==" {
                ("==", "!=")
            } else {
                ("!=", "==")
            };
            mutations.push(Mutation {
                id: { id += 1; id },
                kind: MutationKind::EqToNe,
                file: file.to_string(),
                line: lineno,
                col: m.start(),
                original: orig.to_string(),
                replacement: repl.to_string(),
            });
        }

        // RelationalInvert — skip operators that are part of != == -> => patterns
        let bytes = line.as_bytes();
        for m in RE_REL.find_iter(line) {
            // Skip if preceded by `=`, `!`, or followed by `>` (e.g. `->`, `=>`)
            let prev = if m.start() > 0 { bytes.get(m.start() - 1).copied() } else { None };
            let next = bytes.get(m.end()).copied();
            if matches!(prev, Some(b'=' | b'!' | b'<' | b'>'))
                || matches!(next, Some(b'=') if !matches!(m.as_str(), "<=" | ">="))
                || matches!(next, Some(b'>'))
            {
                continue;
            }
            let repl = match m.as_str() {
                "<" => ">=",
                ">" => "<=",
                "<=" => ">",
                ">=" => "<",
                _ => continue,
            };
            mutations.push(Mutation {
                id: { id += 1; id },
                kind: MutationKind::RelationalInvert,
                file: file.to_string(),
                line: lineno,
                col: m.start(),
                original: m.as_str().to_string(),
                replacement: repl.to_string(),
            });
        }

        // ArithAddSub — skip ++/--, ->, +=, -=, numeric negation
        for m in RE_ARITH_ADDSUB.find_iter(line) {
            let prev = if m.start() > 0 { bytes.get(m.start() - 1).copied() } else { None };
            let next = bytes.get(m.end()).copied();
            // Skip compound operators: +=, -=, ->, --, ++
            if matches!(next, Some(b'=' | b'>' | b'+' | b'-'))
                || matches!(prev, Some(b'+' | b'-' | b'=' | b'*' | b'/' | b'('))
            {
                continue;
            }
            let repl = if m.as_str() == "+" { "-" } else { "+" };
            mutations.push(Mutation {
                id: { id += 1; id },
                kind: MutationKind::ArithAddSub,
                file: file.to_string(),
                line: lineno,
                col: m.start(),
                original: m.as_str().to_string(),
                replacement: repl.to_string(),
            });
        }

        // LogicalAndOr
        for m in RE_LOGICAL.find_iter(line) {
            let repl = if m.as_str() == "&&" { "||" } else { "&&" };
            mutations.push(Mutation {
                id: { id += 1; id },
                kind: MutationKind::LogicalAndOr,
                file: file.to_string(),
                line: lineno,
                col: m.start(),
                original: m.as_str().to_string(),
                replacement: repl.to_string(),
            });
        }

        // BoolLiteralFlip
        for m in RE_BOOL_LIT.find_iter(line) {
            let repl = if m.as_str() == "true" { "false" } else { "true" };
            mutations.push(Mutation {
                id: { id += 1; id },
                kind: MutationKind::BoolLiteralFlip,
                file: file.to_string(),
                line: lineno,
                col: m.start(),
                original: m.as_str().to_string(),
                replacement: repl.to_string(),
            });
        }

        // IntLiteralPerturb — generate ±1 and 0 variants
        for m in RE_INT_LIT.find_iter(line) {
            if let Ok(n) = m.as_str().parse::<i64>() {
                // Only perturb small literals to avoid noise from large constants
                if n > 1_000_000 {
                    continue;
                }
                for &replacement in &[0i64, 1, -1, n + 1, n - 1] {
                    if replacement == n {
                        continue;
                    }
                    mutations.push(Mutation {
                        id: { id += 1; id },
                        kind: MutationKind::IntLiteralPerturb {
                            original: n,
                            replacement,
                        },
                        file: file.to_string(),
                        line: lineno,
                        col: m.start(),
                        original: n.to_string(),
                        replacement: replacement.to_string(),
                    });
                }
            }
        }

        // ReturnDefault
        if let Some(m) = RE_RETURN.find(line) {
            mutations.push(Mutation {
                id: { id += 1; id },
                kind: MutationKind::ReturnDefault,
                file: file.to_string(),
                line: lineno,
                col: m.start(),
                original: m.as_str().to_string(),
                replacement: "return Default::default();".to_string(),
            });
        }

        // UnwrapToExpect
        for _ in RE_UNWRAP.find_iter(line) {
            mutations.push(Mutation {
                id: { id += 1; id },
                kind: MutationKind::UnwrapToExpect,
                file: file.to_string(),
                line: lineno,
                col: 0,
                original: ".unwrap()".to_string(),
                replacement: r#".expect("muttest")"#.to_string(),
            });
        }

        // NegateIfCondition
        if let Some(cap) = RE_IF_COND.captures(line) {
            let neg = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let cond = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let (orig, repl) = if neg.is_empty() {
                (
                    format!("if {cond} {{"),
                    format!("if !{cond} {{"),
                )
            } else {
                (
                    format!("if !{cond} {{"),
                    format!("if {cond} {{"),
                )
            };
            mutations.push(Mutation {
                id: { id += 1; id },
                kind: MutationKind::NegateIfCondition,
                file: file.to_string(),
                line: lineno,
                col: 0,
                original: orig,
                replacement: repl,
            });
        }
    }

    mutations
}

/// Filter mutations to only those where `original` actually appears in `source`.
pub fn filter_applicable(mutations: Vec<Mutation>, source: &str) -> Vec<Mutation> {
    mutations
        .into_iter()
        .filter(|m| m.is_applicable(source))
        .collect()
}
