//! Heuristic classifier for `EffectHint`.
//!
//! The classifier is intentionally simple: a weighted bank of regex signals
//! plus a handful of out-of-band heuristics. It is *not* trying to be
//! exhaustive — the policy engine treats Ambiguous-from-External as a drop,
//! so the classifier's job is to push genuinely hostile content over the
//! Loosens threshold, push legitimate restriction reminders into Tightens,
//! and let everything else fall to Neutral or Ambiguous where the policy
//! takes over.

use crate::reminder::{EffectHint, Reminder};
use once_cell::sync::Lazy;
use regex::Regex;

struct Signal {
    name: &'static str,
    pattern: Regex,
    effect: EffectHint,
    weight: i32,
}

static SIGNALS: Lazy<Vec<Signal>> = Lazy::new(|| {
    use EffectHint::*;

    let mk = |name, pat: &str, effect, weight| Signal {
        name,
        pattern: Regex::new(&format!("(?i){}", pat)).expect("invalid regex"),
        effect,
        weight,
    };

    vec![
        // ---------- Direct injection signatures ----------
        mk("ignore_previous", r"\bignore\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions|messages|rules|prompts|system)\b", Loosens, 10),
        // Broader: "ignore <restriction-noun>" — catches "ignore safety guidelines",
        // "ignore the content policy", etc. without requiring the temporal "previous".
        mk("ignore_restriction", r"\bignore\s+(your\s+|the\s+|all\s+)?(safety|guidelines?|guardrails?|rules?|policies|policy|content\s+policy|restrictions?|filters?|warnings?|disclaimers?|instructions?)\b", Loosens, 9),
        mk("disregard_rules", r"\bdisregard\s+(the\s+)?(rules|instructions|guidelines|policies|prompt|system|earlier)\b", Loosens, 10),
        mk("forget_above", r"\bforget\s+(everything|all|the\s+above|prior|previous|your\s+instructions)\b", Loosens, 10),
        mk("override_system", r"\boverride\s+(the\s+)?(system\s+(prompt|instructions)|safety|policies|guardrails|safety\s+check)\b", Loosens, 10),
        // Broader: "override the <restriction-mechanism>" — catches "override the
        // file-write confirmation", "override the approval check", etc.
        mk("override_mechanism", r"\boverride\s+(the\s+)?(\S+\s+){0,3}?(check|confirmation|approval|validation|verification|safeguard|filter|restriction|guard|gate|policy)\b", Loosens, 9),
        mk("bypass_safety", r"\bbypass\s+(your\s+|the\s+)?(safety|content\s+policy|restrictions|filters|guardrails|confirm)\b", Loosens, 10),
        mk("new_instructions", r"\b(new|updated|revised)\s+(instructions|system\s+prompt|rules)\b", Loosens, 8),

        // ---------- Persona hijack ----------
        mk("you_are_now",    r"\byou\s+are\s+(now|actually|really)\s+", Loosens, 7),
        mk("act_as_unrestricted", r"\bact\s+as\s+(if|though)?\s*(a|an)\s+\w+\s+(without|with\s+no|that\s+has\s+no)\s+", Loosens, 8),
        mk("pretend_to_be",  r"\bpretend\s+(to\s+be|you\s+are|that\s+you)\b", Loosens, 6),
        mk("roleplay_jailbreak", r"\b(DAN|do\s+anything\s+now|jailbroken|developer\s+mode\s+(enabled|active|on))\b", Loosens, 9),

        // ---------- Authority forgery ----------
        mk("anthropic_says", r"\b(anthropic|the\s+developers?|the\s+team)\s+(has\s+)?(said|told|instructed|updated|approved|authorized|lifted)\b", Loosens, 7),
        mk("system_update",  r"\b(system\s+(update|message|override|notice|directive)|admin\s+message|kernel\s+directive)\b", Loosens, 8),
        mk("policy_lifted",  r"\b(restrictions?|policies?|filters?|guardrails?|safety(\s+filters?)?)\s+(have\s+been\s+|are\s+(now\s+)?)?(lifted|removed|disabled|relaxed|loosened)\b", Loosens, 10),
        mk("special_mode",   r"\b(developer|debug|maintenance|test|admin|root)\s+mode\s+(is\s+)?(enabled|active|on|now\s+active)\b", Loosens, 8),

        // ---------- Rule deletion ----------
        mk("no_restrictions", r"\bno\s+(restrictions?|limits?|filters?|safety|rules)\b", Loosens, 7),
        mk("no_longer_apply", r"\b(no\s+longer\s+(apply|applies|valid|in\s+effect)|don'?t\s+apply\s+(here|anymore|now))\b", Loosens, 8),
        mk("without_safety",  r"\bwithout\s+(safety|restrictions?|filters?|warnings?|caveats?|disclaimers?)\b", Loosens, 7),

        // ---------- Output-hijack masquerading as neutral context ----------
        mk("print_system_prompt", r"\b(print|show|display|repeat|reveal|output|reproduce)\s+(your\s+|the\s+)?(system\s+prompt|instructions|rules|initialization)\b", Loosens, 9),
        mk("include_in_full_print", r"\bshould\s+be\s+included\s+in\s+(full\s+print|the\s+full\s+output)\b", Loosens, 9),

        // ---------- Tightening signals (legit reminders we MUST admit) ----------
        mk("do_not",         r"\b(do\s+not|don'?t|never|must\s+not|may\s+not|should\s+not|shall\s+not)\s+", Tightens, 4),
        mk("be_careful",     r"\bbe\s+(extra\s+)?(careful|cautious|conservative|defensive)\s+(when|with|about|around)\b", Tightens, 3),
        mk("always_check",   r"\balways\s+(verify|check|confirm|ask|validate|test|review)\b", Tightens, 3),
        mk("require_confirm", r"\brequires?\s+(user\s+)?(confirmation|approval|consent|review)\b", Tightens, 3),
        mk("refuse_if",      r"\brefuse\s+(if|when|to)\b", Tightens, 4),
        mk("ask_before",     r"\bask\s+before\s+\w+", Tightens, 3),

        // ---------- Neutral state markers ----------
        mk("cwd_marker",      r"(?m)^(cwd|current\s+directory|working\s+directory):\s+", Neutral, 2),
        mk("git_marker",      r"(?m)^(git\s+(status|branch|head)|on\s+branch):", Neutral, 2),
        mk("retrieval_marker", r"(?m)^(retrieved\s+(from|chunk)|memory\s+hit|relevant\s+context):", Neutral, 2),
        mk("hook_output",     r"(?m)^(hook|post-?tool|pre-?tool)\s+(output|result):", Neutral, 2),
    ]
});

/// Strip characters that exist mainly to evade pattern matching.
/// We still detect their presence in `out_of_band_score` and add a
/// suspicion bonus — defence in depth.
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !matches!(
                *c,
                '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{2060}'
                | '\u{202E}' | '\u{202D}' | '\u{2066}' | '\u{2067}' | '\u{2068}'
            )
        })
        .collect()
}

fn has_zero_width(s: &str) -> bool {
    s.chars().any(|c| matches!(c,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{2060}'
    ))
}

fn has_rtl_override(s: &str) -> bool {
    s.chars().any(|c| matches!(c,
        '\u{202E}' | '\u{202D}' | '\u{2066}' | '\u{2067}' | '\u{2068}'
    ))
}

fn looks_like_base64_payload(s: &str) -> bool {
    s.split_whitespace().any(|tok| {
        tok.len() >= 80
            && tok
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    })
}

pub fn classify(body: &str) -> (EffectHint, Vec<String>) {
    use EffectHint::*;

    let normalized = normalize(body);

    let mut loosen = 0;
    let mut tighten = 0;
    let mut neutral = 0;
    let mut evidence: Vec<String> = Vec::new();

    for sig in SIGNALS.iter() {
        if sig.pattern.is_match(&normalized) {
            evidence.push(format!("{}({:+})", sig.name, sig.weight));
            match sig.effect {
                Loosens => loosen += sig.weight,
                Tightens => tighten += sig.weight,
                Neutral => neutral += sig.weight,
                Ambiguous => {}
            }
        }
    }

    // Out-of-band bonuses: these never legitimately appear in a hook reminder.
    if has_zero_width(body) {
        loosen += 5;
        evidence.push("unicode_zero_width(+5)".into());
    }
    if has_rtl_override(body) {
        loosen += 5;
        evidence.push("unicode_rtl_override(+5)".into());
    }
    if looks_like_base64_payload(body) {
        loosen += 4;
        evidence.push("base64_payload(+4)".into());
    }
    if body.len() > 4000 {
        loosen += 2;
        evidence.push("oversized(+2)".into());
    }

    // Resolution rules. Tuned so that:
    //   - a single strong loosening verb (weight 8+) is enough on its own
    //   - any meaningful loosen score outweighs comparable tighten score
    //   - tightening is admitted only when it dominates
    let effect = if loosen >= 8 {
        Loosens
    } else if loosen >= 4 && loosen >= tighten {
        Loosens
    } else if tighten >= 3 && tighten > loosen + 2 {
        Tightens
    } else if neutral > 0 && loosen == 0 && tighten == 0 {
        Neutral
    } else if loosen == 0 && tighten == 0 && neutral == 0 {
        // Signal-free. Short → benign by default; long → ambiguous.
        if body.chars().count() < 200 { Neutral } else { Ambiguous }
    } else {
        Ambiguous
    };

    (effect, evidence)
}

/// Apply the classifier to a reminder in place.
pub fn apply(rem: &mut Reminder) {
    let (effect, evidence) = classify(&rem.body);
    rem.effect_hint = effect;
    rem.classifier_evidence = evidence;
}
