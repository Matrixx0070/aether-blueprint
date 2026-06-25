use crate::detector::{self, Hit};
use crate::rule::{Action, Detector, Remediation, RemediationStrategy, Rule, Severity};
use crate::session::SessionContext;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub action: Action,
    pub hit: Hit,
    pub action_taken: ActionTaken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionTaken {
    Logged,
    Rewrote,
    Blocked,
}

#[derive(Debug, Clone)]
pub enum Outcome {
    /// All checks cleared (Warn rules may still be in `log`).
    Pass { message: String, log: Vec<Finding> },
    /// At least one Block-action rule fired. The agent must NOT emit
    /// `partial_message` to the user; it's surfaced for diagnostics only.
    Blocked {
        partial_message: String,
        reasons: Vec<Finding>,
        log: Vec<Finding>,
    },
}

pub struct Gate {
    pub rules: Vec<CompiledRule>,
}

pub struct CompiledRule {
    pub rule: Rule,
    pub compiled_regexes: Vec<Regex>,
}

impl Gate {
    pub fn new(rules: Vec<Rule>) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(rules.len());
        for r in rules {
            let mut regs = Vec::new();
            if let Detector::Regex {
                patterns,
                case_sensitive,
            } = &r.detector
            {
                for p in patterns {
                    let pat = if *case_sensitive {
                        p.clone()
                    } else {
                        format!("(?i){p}")
                    };
                    let re = Regex::new(&pat).map_err(|e| format!("{}: {e}", r.id))?;
                    regs.push(re);
                }
            }
            compiled.push(CompiledRule {
                rule: r,
                compiled_regexes: regs,
            });
        }
        Ok(Self { rules: compiled })
    }

    /// Two-pass evaluation:
    ///   pass 1 — collect all Rewrite hits, apply right-to-left
    ///   pass 2 — re-evaluate Warn and Block rules on the rewritten body
    pub fn check(&self, message: &str, session: &SessionContext) -> Outcome {
        let mut current = message.to_string();
        let mut log: Vec<Finding> = Vec::new();
        let mut blocked: Vec<Finding> = Vec::new();

        // -------- Pass 1: rewrites --------
        let mut rewrite_ops: Vec<(usize, usize, String, Finding)> = Vec::new();
        for cr in &self.rules {
            if cr.rule.action != Action::Rewrite {
                continue;
            }
            if !session.satisfies(&cr.rule.applies_when) {
                continue;
            }
            let hits = self.detect(cr, &current, session);
            for hit in hits {
                let replacement = compute_replacement(&hit, cr.rule.remediation.as_ref());
                let finding = Finding {
                    rule_id: cr.rule.id.clone(),
                    severity: cr.rule.severity,
                    action: cr.rule.action,
                    hit: hit.clone(),
                    action_taken: ActionTaken::Rewrote,
                };
                rewrite_ops.push((hit.start, hit.end, replacement, finding));
            }
        }
        // Apply highest-start first so earlier offsets stay valid.
        rewrite_ops.sort_by(|a, b| b.0.cmp(&a.0));
        // Drop overlapping ops — keep the first one we see in this order.
        let mut last_kept_start = usize::MAX;
        let mut to_apply: Vec<(usize, usize, String, Finding)> = Vec::new();
        for op in rewrite_ops {
            if op.1 <= last_kept_start {
                last_kept_start = op.0;
                to_apply.push(op);
            }
        }
        for (start, end, replacement, finding) in to_apply {
            current = format!("{}{}{}", &current[..start], replacement, &current[end..]);
            log.push(finding);
        }

        // -------- Pass 2: warns and blocks on rewritten body --------
        for cr in &self.rules {
            if cr.rule.action == Action::Rewrite {
                continue;
            }
            if !session.satisfies(&cr.rule.applies_when) {
                continue;
            }
            let hits = self.detect(cr, &current, session);
            for hit in hits {
                let finding = Finding {
                    rule_id: cr.rule.id.clone(),
                    severity: cr.rule.severity,
                    action: cr.rule.action,
                    hit,
                    action_taken: if cr.rule.action == Action::Block {
                        ActionTaken::Blocked
                    } else {
                        ActionTaken::Logged
                    },
                };
                if cr.rule.action == Action::Block {
                    blocked.push(finding);
                } else {
                    log.push(finding);
                }
            }
        }

        if !blocked.is_empty() {
            Outcome::Blocked {
                partial_message: current,
                reasons: blocked,
                log,
            }
        } else {
            Outcome::Pass {
                message: current,
                log,
            }
        }
    }

    fn detect(&self, cr: &CompiledRule, body: &str, session: &SessionContext) -> Vec<Hit> {
        match &cr.rule.detector {
            Detector::PhraseMatch {
                patterns,
                case_sensitive,
            } => detector::phrase_match(body, patterns, *case_sensitive),
            Detector::Regex { .. } => detector::regex_match(body, &cr.compiled_regexes),
            Detector::Builtin { name, config } => run_builtin(name, body, config, session),
        }
    }
}

fn run_builtin(
    name: &str,
    body: &str,
    config: &serde_yaml::Value,
    session: &SessionContext,
) -> Vec<Hit> {
    fn cfg_u64(config: &serde_yaml::Value, key: &str, default: u64) -> usize {
        config
            .get(key)
            .and_then(|v| v.as_u64())
            .unwrap_or(default) as usize
    }
    fn cfg_strs(config: &serde_yaml::Value, key: &str) -> Vec<String> {
        config
            .get(key)
            .and_then(|v| serde_yaml::from_value(v.clone()).ok())
            .unwrap_or_default()
    }

    match name {
        "quoted_span_length" => {
            let max_words = cfg_u64(config, "max_words", 15);
            detector::quoted_span_length(body, max_words)
        }
        "quotes_per_cite_source" => {
            let max = cfg_u64(config, "max_per_source", 1);
            detector::quotes_per_cite_source(body, max)
        }
        "short_line_stanza" => {
            let min = cfg_u64(config, "min_consecutive_short_lines", 4);
            let mw = cfg_u64(config, "max_words_per_line", 12);
            detector::short_line_stanza(body, min, mw)
        }
        "too_thin" => {
            let min = cfg_u64(config, "min_chars", 10);
            let allow = cfg_strs(config, "refusal_allowlist");
            detector::too_thin(body, min, &allow)
        }
        "url_provenance" => detector::url_provenance(body, session),
        other => panic!("unknown builtin detector: {other}"),
    }
}

fn compute_replacement(hit: &Hit, rem: Option<&Remediation>) -> String {
    let strategy = rem
        .map(|r| r.strategy)
        .unwrap_or(RemediationStrategy::Strip);
    match strategy {
        RemediationStrategy::Strip => String::new(),
        RemediationStrategy::Redact => "[REDACTED]".to_string(),
        RemediationStrategy::Annotate => {
            let template = rem
                .and_then(|r| r.template.clone())
                .unwrap_or_else(|| "[UNVERIFIED: {match}]".into());
            template.replace("{match}", &hit.matched)
        }
    }
}
