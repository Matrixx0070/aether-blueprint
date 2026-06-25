//! Detector primitives. Each returns a list of `Hit`s — byte ranges in the
//! body, with evidence text for telemetry. Built-ins receive the session
//! context so they can read things like `known_urls`.

use crate::session::SessionContext;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Hit {
    pub start: usize,
    pub end: usize,
    pub matched: String,
    pub evidence: String,
}

// ---------------------------------------------------------------------------
// phrase_match: literal substring search.
// Byte indices line up with `body` only when lowercasing preserves length,
// which is true for ASCII. Non-ASCII case folding is documented as a v1 gap.
// ---------------------------------------------------------------------------
pub fn phrase_match(body: &str, patterns: &[String], case_sensitive: bool) -> Vec<Hit> {
    let body_search = if case_sensitive {
        body.to_string()
    } else {
        body.to_ascii_lowercase()
    };
    let mut hits = Vec::new();
    for pat in patterns {
        let needle = if case_sensitive {
            pat.clone()
        } else {
            pat.to_ascii_lowercase()
        };
        if needle.is_empty() {
            continue;
        }
        let mut from = 0usize;
        while let Some(off) = body_search[from..].find(&needle) {
            let abs = from + off;
            let end = abs + needle.len();
            if end > body.len() {
                break;
            }
            hits.push(Hit {
                start: abs,
                end,
                matched: body[abs..end].to_string(),
                evidence: format!("phrase:{pat}"),
            });
            from = end;
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// regex_match: dispatches to pre-compiled Regex objects (compiled in Gate).
// ---------------------------------------------------------------------------
pub fn regex_match(body: &str, patterns: &[Regex]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for re in patterns {
        for m in re.find_iter(body) {
            hits.push(Hit {
                start: m.start(),
                end: m.end(),
                matched: m.as_str().to_string(),
                evidence: format!("regex:{}", re.as_str()),
            });
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// Built-in: quoted_span_length.
// Finds straight-double-quoted spans and flags any whose word count is ≥ max.
// v1 limitation: only ASCII " — curly/French quotes are not yet recognized.
// ---------------------------------------------------------------------------
static QUOTED_SPAN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#""([^"\n]{1,2000})""#).unwrap());

pub fn quoted_span_length(body: &str, max_words: usize) -> Vec<Hit> {
    let mut hits = Vec::new();
    for cap in QUOTED_SPAN_RE.captures_iter(body) {
        let inner = cap.get(1).unwrap();
        let words = inner.as_str().split_whitespace().count();
        if words >= max_words {
            let whole = cap.get(0).unwrap();
            hits.push(Hit {
                start: whole.start(),
                end: whole.end(),
                matched: whole.as_str().to_string(),
                evidence: format!("quote_words:{words}"),
            });
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// Built-in: quotes_per_cite_source.
// Counts `<cite index="...">...</cite>` blocks grouped by index; flags every
// occurrence past the `max_per_source` quota.
// ---------------------------------------------------------------------------
static CITE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"<cite\s+index=["']([^"']+)["']>([^<]*)</cite>"#).unwrap());

pub fn quotes_per_cite_source(body: &str, max_per_source: usize) -> Vec<Hit> {
    let mut by_source: HashMap<String, Vec<(usize, usize, String)>> = HashMap::new();
    for cap in CITE_RE.captures_iter(body) {
        let src = cap.get(1).unwrap().as_str().to_string();
        let whole = cap.get(0).unwrap();
        by_source
            .entry(src)
            .or_default()
            .push((whole.start(), whole.end(), whole.as_str().to_string()));
    }
    let mut hits = Vec::new();
    for (src, matches) in by_source {
        if matches.len() > max_per_source {
            for (s, e, text) in matches.iter().skip(max_per_source) {
                hits.push(Hit {
                    start: *s,
                    end: *e,
                    matched: text.clone(),
                    evidence: format!("source:{src} count:{}", matches.len()),
                });
            }
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// Built-in: short_line_stanza.
// Catches stanza-shaped output. Heuristic: ≥ N consecutive non-empty lines
// each with ≤ M words. Empty lines do not break the run (they delineate
// stanzas).
// ---------------------------------------------------------------------------
/// Returns true if a trimmed line begins with a markdown structural marker
/// — bullet (`-`, `*`, `+`), ordered list (`1.`, `12.`), block quote (`>`),
/// heading (`#`), table separator (`|`), or code fence (```). These are
/// structural, not stanza-shaped: a bulleted answer is not a poem.
fn is_markdown_structural_line(trimmed: &str) -> bool {
    let bytes = trimmed.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let first = bytes[0];
    match first {
        b'-' | b'*' | b'+' | b'>' | b'#' | b'|' => true,
        b'`' => trimmed.starts_with("```"),
        c if c.is_ascii_digit() => {
            // ordered list: digits followed by '.' then space (or end)
            let mut i = 0;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            i < bytes.len() && bytes[i] == b'.'
        }
        _ => false,
    }
}

pub fn short_line_stanza(body: &str, min_consec: usize, max_words: usize) -> Vec<Hit> {
    // Compute byte offset of each line within `body`.
    let mut line_offsets: Vec<usize> = Vec::new();
    let mut off = 0usize;
    for ln in body.split_inclusive('\n') {
        line_offsets.push(off);
        off += ln.len();
    }

    let lines: Vec<&str> = body.lines().collect();
    let mut run = 0usize;
    let mut run_start_idx = 0usize;
    let mut hits = Vec::new();

    let emit = |hits: &mut Vec<Hit>, run: usize, run_start_idx: usize, end_idx: usize| {
        let start = line_offsets[run_start_idx];
        let end = if end_idx < line_offsets.len() {
            line_offsets[end_idx]
        } else {
            body.len()
        };
        hits.push(Hit {
            start,
            end,
            matched: body[start..end].to_string(),
            evidence: format!("consecutive_short_lines:{run}"),
        });
    };

    for (i, ln) in lines.iter().enumerate() {
        let trimmed = ln.trim();
        let w = trimmed.split_whitespace().count();
        // Structural markdown lines (bullets, ordered lists, headings,
        // quotes, tables, code fences) reset the run. A bulleted answer
        // is not a poem; without this we false-positive on every list.
        if is_markdown_structural_line(trimmed) {
            if run >= min_consec {
                emit(&mut hits, run, run_start_idx, i);
            }
            run = 0;
            continue;
        }
        let is_short = !trimmed.is_empty() && w > 0 && w <= max_words;
        if is_short {
            if run == 0 {
                run_start_idx = i;
            }
            run += 1;
        } else if !trimmed.is_empty() {
            if run >= min_consec {
                emit(&mut hits, run, run_start_idx, i);
            }
            run = 0;
        }
        // empty lines: neither extend nor break the run
    }
    if run >= min_consec {
        emit(&mut hits, run, run_start_idx, lines.len());
    }
    hits
}

// ---------------------------------------------------------------------------
// Built-in: too_thin.
// Flags when the trimmed body is below `min_chars` AND not in `allowlist`.
// Empty body is intentionally NOT flagged here — empty output is its own
// failure mode handled by the agent loop, not by this rule.
// ---------------------------------------------------------------------------
pub fn too_thin(body: &str, min_chars: usize, allowlist: &[String]) -> Vec<Hit> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return vec![];
    }
    if trimmed.chars().count() >= min_chars {
        return vec![];
    }
    if allowlist.iter().any(|a| trimmed == a.trim()) {
        return vec![];
    }
    vec![Hit {
        start: 0,
        end: body.len(),
        matched: body.to_string(),
        evidence: format!("chars:{} min:{}", trimmed.chars().count(), min_chars),
    }]
}

// ---------------------------------------------------------------------------
// Built-in: url_provenance.
// Flags URLs in the output that don't appear in `session.known_urls`. An
// empty known_urls list means "we can't tell" — fail-open (no hits).
// ---------------------------------------------------------------------------
static URL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"https?://[^\s)>\]]+").unwrap());

pub fn url_provenance(body: &str, session: &SessionContext) -> Vec<Hit> {
    if session.known_urls.is_empty() {
        return vec![];
    }
    let mut hits = Vec::new();
    for m in URL_RE.find_iter(body) {
        let url = m.as_str();
        let trimmed = url.trim_end_matches(|c: char| matches!(c, '.' | ',' | ';' | ':' | '!' | '?'));
        if !session
            .known_urls
            .iter()
            .any(|k| k.as_str() == trimmed || k.as_str() == url)
        {
            hits.push(Hit {
                start: m.start(),
                end: m.end(),
                matched: url.to_string(),
                evidence: format!("unverified_url:{trimmed}"),
            });
        }
    }
    hits
}
