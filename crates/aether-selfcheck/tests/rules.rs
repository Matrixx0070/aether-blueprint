//! Coverage of the shipped rule library. Each rule has at least one positive
//! (catch) test and where applicable a negative (do-not-catch) test for the
//! `applies_when` gating.
//!
//! Run:
//!     cargo test -p aether-selfcheck

use aether_selfcheck::*;
use std::path::PathBuf;

fn rules_dir() -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "rules"].iter().collect()
}

fn load_gate() -> Gate {
    let rules = load_dir(rules_dir()).expect("load rules");
    Gate::new(rules).expect("compile rules")
}

fn has_rule(log: &[Finding], id: &str) -> bool {
    log.iter().any(|f| f.rule_id == id)
}

// ============================================================
// Library shape
// ============================================================

#[test]
fn library_ships_at_least_ten_rules() {
    let rules = load_dir(rules_dir()).expect("load rules");
    assert!(
        rules.len() >= 10,
        "shipped {} rules, want at least 10",
        rules.len()
    );
}

#[test]
fn every_rule_id_is_unique() {
    let rules = load_dir(rules_dir()).expect("load rules");
    let mut ids: Vec<String> = rules.iter().map(|r| r.id.clone()).collect();
    let before = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(before, ids.len(), "duplicate rule id detected");
}

#[test]
fn every_rule_compiles() {
    // Already exercised by load_gate(), but make the failure mode explicit.
    let _ = load_gate();
}

// ============================================================
// Rule 01 — banned_truth_phrases
// ============================================================

#[test]
fn rule_01_annotates_should_work() {
    let gate = load_gate();
    let ctx = SessionContext::default();
    let out = gate.check("This should work after the migration.", &ctx);
    match out {
        Outcome::Pass { message, log } => {
            assert!(
                message.contains("[UNVERIFIED:"),
                "expected annotation, got: {message}"
            );
            assert!(has_rule(&log, "banned_truth_phrases"));
        }
        Outcome::Blocked { .. } => panic!("rewrite must not block"),
    }
}

#[test]
fn rule_01_passes_clean_text() {
    let gate = load_gate();
    let ctx = SessionContext::default();
    let out = gate.check("The migration completed; 47 tests passed.", &ctx);
    if let Outcome::Pass { log, .. } = out {
        assert!(!has_rule(&log, "banned_truth_phrases"));
    } else {
        panic!("clean text must pass");
    }
}

// ============================================================
// Rule 02 — forbidden_memory_phrases
// ============================================================

#[test]
fn rule_02_strips_forbidden_phrase() {
    let gate = load_gate();
    let ctx = SessionContext {
        memory_active: true,
        ..Default::default()
    };
    let out = gate.check("Based on what I know about you, you like Rust.", &ctx);
    match out {
        Outcome::Pass { message, log } => {
            assert!(
                !message.contains("Based on what I know about you"),
                "phrase must be stripped, got: {message}"
            );
            assert!(has_rule(&log, "forbidden_memory_phrases"));
        }
        Outcome::Blocked { .. } => panic!("must rewrite, not block"),
    }
}

#[test]
fn rule_02_dormant_when_memory_inactive() {
    let gate = load_gate();
    let ctx = SessionContext {
        memory_active: false,
        ..Default::default()
    };
    let out = gate.check("Based on what I know about you, you like Rust.", &ctx);
    if let Outcome::Pass { log, .. } = out {
        assert!(!has_rule(&log, "forbidden_memory_phrases"));
    } else {
        panic!("rule must be inactive without memory");
    }
}

// ============================================================
// Rule 03 — conditionally_allowed_memory_phrases
// ============================================================

#[test]
fn rule_03_strips_when_user_did_not_ask() {
    let gate = load_gate();
    let ctx = SessionContext {
        memory_active: true,
        user_asked_about_memory: false,
        ..Default::default()
    };
    let out = gate.check("As we discussed last week, the deploy is Thursday.", &ctx);
    match out {
        Outcome::Pass { message, log } => {
            assert!(!message.contains("As we discussed"));
            assert!(has_rule(&log, "conditionally_allowed_memory_phrases"));
        }
        _ => panic!("must rewrite"),
    }
}

#[test]
fn rule_03_passes_when_user_asked() {
    let gate = load_gate();
    let ctx = SessionContext {
        memory_active: true,
        user_asked_about_memory: true,
        ..Default::default()
    };
    let out = gate.check("As we discussed last week, the deploy is Thursday.", &ctx);
    match out {
        Outcome::Pass { message, log } => {
            assert!(message.contains("As we discussed"));
            assert!(!has_rule(&log, "conditionally_allowed_memory_phrases"));
        }
        _ => panic!("must pass"),
    }
}

// ============================================================
// Rule 04 — copyright_quote_length
// ============================================================

#[test]
fn rule_04_long_quote_blocks() {
    let gate = load_gate();
    let ctx = SessionContext::default();
    let body = r#"The report stated: "This is a sufficiently long verbatim quotation that exceeds the fifteen word policy limit for any single source." That was striking."#;
    match gate.check(body, &ctx) {
        Outcome::Blocked { reasons, .. } => {
            assert!(reasons.iter().any(|f| f.rule_id == "copyright_quote_length"));
        }
        Outcome::Pass { .. } => panic!("long quote must block"),
    }
}

#[test]
fn rule_04_short_quote_passes() {
    let gate = load_gate();
    let ctx = SessionContext::default();
    let body = r#"The CEO said "we missed the quarter" yesterday."#;
    assert!(matches!(gate.check(body, &ctx), Outcome::Pass { .. }));
}

// ============================================================
// Rule 05 — copyright_quotes_per_source
// ============================================================

#[test]
fn rule_05_two_quotes_same_source_blocks() {
    let gate = load_gate();
    let ctx = SessionContext {
        cite_tags_present: true,
        ..Default::default()
    };
    let body = r#"
        <cite index="doc1-1">first short quote</cite> and later
        <cite index="doc1-1">another short quote</cite> from the same doc.
    "#;
    match gate.check(body, &ctx) {
        Outcome::Blocked { reasons, .. } => {
            assert!(reasons.iter().any(|f| f.rule_id == "copyright_quotes_per_source"));
        }
        Outcome::Pass { .. } => panic!("2+ quotes per source must block"),
    }
}

#[test]
fn rule_05_one_per_source_passes() {
    let gate = load_gate();
    let ctx = SessionContext {
        cite_tags_present: true,
        ..Default::default()
    };
    let body = r#"
        <cite index="doc1-1">first</cite> and
        <cite index="doc2-1">second</cite> from different sources.
    "#;
    assert!(matches!(gate.check(body, &ctx), Outcome::Pass { .. }));
}

// ============================================================
// Rule 06 — lyrics_and_poems
// ============================================================

#[test]
fn rule_06_stanza_blocks() {
    let gate = load_gate();
    let ctx = SessionContext::default();
    let body = "\
Twinkle twinkle little star
How I wonder what you are
Up above the world so high
Like a diamond in the sky
Twinkle twinkle little star
";
    match gate.check(body, &ctx) {
        Outcome::Blocked { reasons, .. } => {
            assert!(reasons.iter().any(|f| f.rule_id == "lyrics_and_poems"));
        }
        Outcome::Pass { .. } => panic!("stanza must block"),
    }
}

#[test]
fn rule_06_prose_passes() {
    let gate = load_gate();
    let ctx = SessionContext::default();
    let body = "\
This is a normal paragraph that goes on for a while and explains a concept \
in enough detail that each line carries plenty of content and the average \
word count per line is well over the twelve word threshold this rule uses.
";
    assert!(matches!(gate.check(body, &ctx), Outcome::Pass { .. }));
}

// ============================================================
// Rule 07 — placeholder_leakage
// ============================================================

#[test]
fn rule_07_placeholders_block() {
    let gate = load_gate();
    let ctx = SessionContext::default();
    for body in &[
        "Replace {{TODO}} with the project name.",
        "Insert your key at <INSERT_KEY> before deploying.",
        "[REPLACE ME] with the cluster URL.",
        "TBD: write the changelog.",
        "FIXME: this branch is wrong.",
    ] {
        let out = gate.check(body, &ctx);
        assert!(
            matches!(out, Outcome::Blocked { .. }),
            "expected block for: {body}"
        );
    }
}

#[test]
fn rule_07_clean_passes() {
    let gate = load_gate();
    let ctx = SessionContext::default();
    let out = gate.check("Set the cluster URL in your config file.", &ctx);
    if let Outcome::Pass { log, .. } = out {
        assert!(!has_rule(&log, "placeholder_leakage"));
    } else {
        panic!("clean text must pass");
    }
}

// ============================================================
// Rule 08 — secret_in_output
// ============================================================

#[test]
fn rule_08_secrets_block() {
    let gate = load_gate();
    let ctx = SessionContext::default();
    for body in &[
        "Set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE in your env.",
        "Use the token ghp_123456789012345678901234567890123456 to auth.",
        "Bot token xoxb-1234567890-abcdefgh1234567890ABCD activated.",
        "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz012345 is set.",
        "AIzaSyA-1234567890abcdefghijklmnopqrstu is your Google key.",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAI...",
    ] {
        let out = gate.check(body, &ctx);
        assert!(
            matches!(out, Outcome::Blocked { .. }),
            "expected block for: {body}"
        );
    }
}

// ============================================================
// Rule 09 — unverified_external_claim
// ============================================================

#[test]
fn rule_09_warns_without_lookup() {
    let gate = load_gate();
    let ctx = SessionContext {
        recent_external_lookup: false,
        ..Default::default()
    };
    let out = gate.check("As of January 2026, the latest version is 4.7.", &ctx);
    match out {
        Outcome::Pass { log, .. } => {
            assert!(has_rule(&log, "unverified_external_claim"));
        }
        _ => panic!("must warn, not block"),
    }
}

#[test]
fn rule_09_silent_with_lookup() {
    let gate = load_gate();
    let ctx = SessionContext {
        recent_external_lookup: true,
        ..Default::default()
    };
    let out = gate.check("As of January 2026, the latest version is 4.7.", &ctx);
    if let Outcome::Pass { log, .. } = out {
        assert!(!has_rule(&log, "unverified_external_claim"));
    } else {
        panic!("must pass");
    }
}

// ============================================================
// Rule 10 — fabricated_attribution
// ============================================================

#[test]
fn rule_10_warns_when_no_cite() {
    let gate = load_gate();
    let ctx = SessionContext {
        cite_tags_present: false,
        ..Default::default()
    };
    let out = gate.check("According to the report, sales rose 12%.", &ctx);
    match out {
        Outcome::Pass { log, .. } => {
            assert!(has_rule(&log, "fabricated_attribution"));
        }
        _ => panic!("must warn"),
    }
}

#[test]
fn rule_10_silent_when_cites_present() {
    let gate = load_gate();
    let ctx = SessionContext {
        cite_tags_present: true,
        ..Default::default()
    };
    let out = gate.check("According to the report, sales rose 12%.", &ctx);
    if let Outcome::Pass { log, .. } = out {
        assert!(!has_rule(&log, "fabricated_attribution"));
    } else {
        panic!("must pass");
    }
}

// ============================================================
// Rule 11 — clinical_self_diagnosis
// ============================================================

#[test]
fn rule_11_blocks_when_distress_flagged() {
    let gate = load_gate();
    let ctx = SessionContext {
        distress_flagged: true,
        ..Default::default()
    };
    let out = gate.check("You have depression and should see someone.", &ctx);
    match out {
        Outcome::Blocked { reasons, .. } => {
            assert!(reasons.iter().any(|f| f.rule_id == "clinical_self_diagnosis"));
        }
        _ => panic!("must block when distress flagged"),
    }
}

#[test]
fn rule_11_dormant_without_flag() {
    let gate = load_gate();
    let ctx = SessionContext {
        distress_flagged: false,
        ..Default::default()
    };
    let out = gate.check("You have depression and should see someone.", &ctx);
    assert!(matches!(out, Outcome::Pass { .. }));
}

// ============================================================
// Rule 12 — unprompted_profanity
// ============================================================

#[test]
fn rule_12_redacts_when_user_did_not_curse() {
    let gate = load_gate();
    let ctx = SessionContext {
        user_cursed: false,
        ..Default::default()
    };
    let out = gate.check("That's some shit code right there.", &ctx);
    match out {
        Outcome::Pass { message, log } => {
            assert!(message.contains("[REDACTED]"));
            assert!(has_rule(&log, "unprompted_profanity"));
        }
        _ => panic!("must redact"),
    }
}

#[test]
fn rule_12_allows_when_user_cursed() {
    let gate = load_gate();
    let ctx = SessionContext {
        user_cursed: true,
        ..Default::default()
    };
    let out = gate.check("That's some shit code right there.", &ctx);
    if let Outcome::Pass { log, .. } = out {
        assert!(!has_rule(&log, "unprompted_profanity"));
    } else {
        panic!("must pass when user cursed");
    }
}

// ============================================================
// Rule 13 — empty_or_thin_output
// ============================================================

#[test]
fn rule_13_warns_on_thin_output() {
    let gate = load_gate();
    let ctx = SessionContext::default();
    let out = gate.check("hi", &ctx);
    match out {
        Outcome::Pass { log, .. } => assert!(has_rule(&log, "empty_or_thin_output")),
        _ => panic!("must warn"),
    }
}

#[test]
fn rule_13_silent_on_allowlist() {
    let gate = load_gate();
    let ctx = SessionContext::default();
    let out = gate.check("Done.", &ctx);
    if let Outcome::Pass { log, .. } = out {
        assert!(!has_rule(&log, "empty_or_thin_output"));
    } else {
        panic!("allowlisted short reply must pass silently");
    }
}

#[test]
fn rule_13_silent_on_normal_length() {
    let gate = load_gate();
    let ctx = SessionContext::default();
    let out = gate.check("Yes, that's exactly right.", &ctx);
    if let Outcome::Pass { log, .. } = out {
        assert!(!has_rule(&log, "empty_or_thin_output"));
    } else {
        panic!();
    }
}

// ============================================================
// Rule 14 — bare_url_without_provenance
// ============================================================

#[test]
fn rule_14_warns_on_unknown_url() {
    let gate = load_gate();
    let ctx = SessionContext {
        known_urls: vec!["https://github.com/anthropics/claude-code".into()],
        ..Default::default()
    };
    let out = gate.check(
        "Check the docs at https://example.invalid/some/path for details.",
        &ctx,
    );
    match out {
        Outcome::Pass { log, .. } => {
            assert!(has_rule(&log, "bare_url_without_provenance"));
        }
        _ => panic!("must warn"),
    }
}

#[test]
fn rule_14_silent_on_known_url() {
    let gate = load_gate();
    let url = "https://github.com/anthropics/claude-code";
    let ctx = SessionContext {
        known_urls: vec![url.into()],
        ..Default::default()
    };
    let out = gate.check(&format!("See {url} for details."), &ctx);
    if let Outcome::Pass { log, .. } = out {
        assert!(!has_rule(&log, "bare_url_without_provenance"));
    } else {
        panic!();
    }
}

#[test]
fn rule_14_fails_open_with_no_session_state() {
    // When known_urls is empty, we can't tell — rule emits no findings.
    let gate = load_gate();
    let ctx = SessionContext::default();
    let out = gate.check("See https://example.invalid/foo for details.", &ctx);
    if let Outcome::Pass { log, .. } = out {
        assert!(!has_rule(&log, "bare_url_without_provenance"));
    } else {
        panic!();
    }
}

// ============================================================
// Cross-cutting
// ============================================================

#[test]
fn multiple_block_violations_aggregate() {
    let gate = load_gate();
    let ctx = SessionContext::default();
    let body =
        "Set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE in your env. TBD: rotate it later.";
    match gate.check(body, &ctx) {
        Outcome::Blocked { reasons, .. } => {
            let ids: Vec<&str> = reasons.iter().map(|f| f.rule_id.as_str()).collect();
            assert!(ids.contains(&"secret_in_output"));
            assert!(ids.contains(&"placeholder_leakage"));
        }
        _ => panic!("expected aggregated block"),
    }
}

#[test]
fn rewrites_and_warns_compose() {
    // Banned phrase (rewrite) + thin output (warn) — both should fire.
    let gate = load_gate();
    let ctx = SessionContext::default();
    let out = gate.check("seems fine", &ctx);
    match out {
        Outcome::Pass { message, log } => {
            assert!(message.contains("[UNVERIFIED:"));
            assert!(has_rule(&log, "banned_truth_phrases"));
            // The annotated rewrite is longer than the thin threshold, so
            // empty_or_thin_output should NOT fire after rewrite.
            assert!(!has_rule(&log, "empty_or_thin_output"));
        }
        _ => panic!("must pass"),
    }
}
