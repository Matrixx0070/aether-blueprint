//! Planner (plan phase).
//!
//! `Plan` carries three coupled views of block history:
//!   - `text`         — the prompt-side render the LLM sees
//!   - `block_turns`  — per-rule list of turn indices at which each rule
//!                      blocked. The source of truth for window pruning.
//!   - `block_counts` — derived view: per-rule current count after any
//!                      pruning. Kept in sync atomically with `block_turns`.
//!
//! Two modes:
//!   - **Monotonic** (`window = None`, default): counts increase
//!     forever; sustained-rule signals never age out.
//!   - **Sliding window** (`window = Some(N)`, via `Plan::with_window(N)`):
//!     during `refresh`, `prune_window` drops block_turns entries where
//!     `t + N <= current_turn`. A rule's sustained line disappears once
//!     its surviving count falls below `SUSTAINED_THRESHOLD`.
//!
//! `Planner::refresh` calls `prune_window` unconditionally so that clean
//! turns (which don't mark the plan dirty) still produce ageing. The
//! agent loop calls `refresh` every turn for this reason.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Cap on how many lines the text view of the plan keeps.
pub const MAX_BLOCK_RECORDS: usize = 10;

/// Per-rule occurrence count at which raw records collapse into a single
/// sustained-guidance line.
pub const SUSTAINED_THRESHOLD: usize = 3;

/// Consecutive tool-error count at which the plan emits a "stuck" guidance
/// note telling the agent to try a different approach.
pub const TOOL_ERROR_THRESHOLD: usize = 3;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Plan {
    pub text: String,
    pub blocks_recorded: usize,

    /// Per-rule list of turn indices at which the rule blocked. Pruned by
    /// `prune_window` in sliding-window mode.
    #[serde(default)]
    pub block_turns: HashMap<String, Vec<usize>>,

    /// Per-rule count derived from `block_turns`. Public because callers
    /// (verifier, telemetry) read it, but never mutated directly — always
    /// via `record_block` or `prune_window`.
    #[serde(default)]
    pub block_counts: HashMap<String, usize>,

    /// Optional sliding-window size. `None` = monotonic counters (v0).
    /// `Some(N)` = blocks age out once `current_turn - turn_index >= N`.
    #[serde(default)]
    pub window: Option<usize>,

    /// Consecutive error count per tool name. Incremented by `record_tool_error`,
    /// reset to 0 by `record_tool_success`. When a tool's count reaches
    /// TOOL_ERROR_THRESHOLD, `refresh` emits a stuck-guidance line.
    #[serde(default)]
    pub tool_error_counts: HashMap<String, usize>,

    dirty: bool,
}

impl Plan {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            ..Default::default()
        }
    }

    /// Construct a plan in sliding-window mode. Blocks age out after `N`
    /// clean turns; specifically, a block at turn `t` is dropped on the
    /// first turn where `current_turn >= t + N`.
    pub fn with_window(window: usize) -> Self {
        Self {
            window: Some(window),
            ..Default::default()
        }
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
    pub fn is_active(&self) -> bool {
        !self.text.is_empty()
    }

    /// Record a verifier block. Updates both `block_turns` and
    /// `block_counts`, prepends a raw line to `text`, caps the text view
    /// at `MAX_BLOCK_RECORDS`, marks the plan dirty.
    pub fn record_block(&mut self, turn_index: usize, rule_ids: &[String]) {
        let mut ids: Vec<String> = rule_ids.to_vec();
        ids.sort();
        ids.dedup();

        let counter_keys = if ids.is_empty() {
            vec!["unknown".to_string()]
        } else {
            ids.clone()
        };
        for rid in &counter_keys {
            self.block_turns
                .entry(rid.clone())
                .or_default()
                .push(turn_index);
            *self.block_counts.entry(rid.clone()).or_insert(0) += 1;
        }

        let id_list = if ids.is_empty() {
            "unknown".to_string()
        } else {
            ids.join(",")
        };
        let line = format!("[turn {turn_index} blocked: rules={id_list}]");

        let mut existing: Vec<String> = self
            .text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|s| s.to_string())
            .collect();
        existing.insert(0, line);
        existing.truncate(MAX_BLOCK_RECORDS);
        self.text = existing.join("\n");
        self.blocks_recorded += 1;
        self.dirty = true;
    }

    /// Record a consecutive tool error. When the count reaches
    /// `TOOL_ERROR_THRESHOLD`, marks the plan dirty so the next `refresh`
    /// emits a stuck-guidance note.
    pub fn record_tool_error(&mut self, tool_name: &str) {
        let count = self.tool_error_counts.entry(tool_name.to_string()).or_insert(0);
        *count += 1;
        if *count >= TOOL_ERROR_THRESHOLD {
            self.dirty = true;
        }
    }

    /// Reset the consecutive error count for a tool (call on success). Marks
    /// the plan dirty if a stuck-guidance note is being cleared.
    pub fn record_tool_success(&mut self, tool_name: &str) {
        if let Some(n) = self.tool_error_counts.get_mut(tool_name) {
            if *n >= TOOL_ERROR_THRESHOLD {
                self.dirty = true;
            }
            *n = 0;
        }
    }

    /// Drop `block_turns` entries where `t + window <= current_turn` and
    /// recompute `block_counts` from the survivors. No-op when monotonic.
    /// Returns the total number of entries pruned.
    ///
    /// # Performance
    ///
    /// Walks every entry of every rule's `Vec<usize>`, so complexity is
    /// O(rules × entries-per-rule). A `VecDeque<usize>` keyed by turn
    /// index with front-prune would drop this to O(pruned) per call.
    /// The optimization is **deliberately skipped** — measurement
    /// (`prune_window_perf_at_realistic_scale`, release mode) on the
    /// shipped 14-rule library at the saturated window size:
    ///
    ///   * idempotent prune (steady-state per-turn cost):  ~536 ns/call
    ///   * full prune (700 entries → empty):              ~2,884 ns
    ///
    /// Both sit five orders of magnitude below the per-turn cost of the
    /// LLM round-trip the result feeds into (≥ 100 ms). Optimizing here
    /// would be measurable-but-pointless. Revisit only if telemetry
    /// shows the linear walk dominating turn time — practically, that
    /// would require thousands of rules or millions of entries in
    /// monotonic mode (which `MAX_BLOCK_RECORDS` on `text` already
    /// caps the prompt-side blast radius of, but does not cap on the
    /// underlying `block_turns` storage).
    pub fn prune_window(&mut self, current_turn: usize) -> usize {
        let Some(window) = self.window else {
            return 0;
        };

        let mut pruned = 0;
        let mut to_remove: Vec<String> = Vec::new();

        for (rid, turns) in self.block_turns.iter_mut() {
            let before = turns.len();
            // Keep entries where t + window > current_turn. saturating_add
            // prevents wrap-around for pathologically large turn indices.
            turns.retain(|&t| t.saturating_add(window) > current_turn);
            pruned += before - turns.len();
            if turns.is_empty() {
                to_remove.push(rid.clone());
            } else {
                self.block_counts.insert(rid.clone(), turns.len());
            }
        }
        for rid in to_remove {
            self.block_turns.remove(&rid);
            self.block_counts.remove(&rid);
        }
        pruned
    }
}

static RAW_LINE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\[turn \d+ blocked: rules=([^\]]+)\]$").unwrap());

static SUSTAINED_LINE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\[sustained: rules=(\S+) blocked (\d+) times .+\]$").unwrap());

static TOOL_STUCK_LINE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\[tool-stuck: .+\]$").unwrap());

fn rule_guidance(rule_id: &str) -> &'static str {
    match rule_id {
        "secret_in_output" => "stop attempting to reveal credentials or API keys",
        "banned_truth_phrases" => "label unverified claims with UNVERIFIED; do not use 'should work' or 'probably'",
        "forbidden_memory_phrases" => "do not narrate memory access; drop phrases like 'I remember' or 'Based on what I know about you'",
        "conditionally_allowed_memory_phrases" => "avoid 'As we discussed' or 'You mentioned' unless the user asked about memory",
        "copyright_quote_length" => "paraphrase instead of quoting; keep any direct quote under 15 words",
        "copyright_quotes_per_source" => "quote each source at most once; paraphrase additional material",
        "lyrics_and_poems" => "do not reproduce song lyrics, poems, or stanza-shaped creative works",
        "placeholder_leakage" => "fill in template placeholders before emitting; do not ship TODO/FIXME/TBD/{{...}}",
        "unverified_external_claim" => "run a WebFetch or WebSearch to verify, or hedge the claim as unverified",
        "fabricated_attribution" => "cite with <cite index='...'> or remove the attribution",
        "clinical_self_diagnosis" => "do not assign clinical labels; reflect what the user said and suggest a professional",
        "unprompted_profanity" => "drop profanity unless the user has used it first",
        "empty_or_thin_output" => "produce a substantive response, not a one-word reply",
        "bare_url_without_provenance" => "only include URLs that came from tool results or the user",
        _ => "avoid this pattern",
    }
}

#[derive(Default)]
pub struct Planner;

impl Planner {
    pub fn new() -> Self {
        Self
    }

    /// Rewrite the plan in place. Always calls `prune_window` first
    /// (no-op in monotonic mode) so sliding-window ageing accumulates
    /// even on clean turns. Sustained-threshold rules collapse into a
    /// single guidance line; below-threshold rules keep their most
    /// recent raw record (subject to deduplication).
    ///
    /// Idempotent for a fixed `current_turn`.
    pub fn refresh(&self, plan: &mut Plan, current_turn: usize) {
        plan.prune_window(current_turn);

        let has_stuck_tools = plan
            .tool_error_counts
            .values()
            .any(|&n| n >= TOOL_ERROR_THRESHOLD);
        if plan.block_counts.is_empty() && plan.text.is_empty() && !has_stuck_tools {
            plan.clear_dirty();
            return;
        }

        let sustained_set: HashSet<String> = plan
            .block_counts
            .iter()
            .filter(|(_, &n)| n >= SUSTAINED_THRESHOLD)
            .map(|(rid, _)| rid.clone())
            .collect();

        // Rules below threshold but still in `block_counts`. Raw lines
        // for rules NOT in this set (e.g. aged-out rules whose count
        // dropped to zero) are not preserved.
        let below_threshold_rules: HashSet<String> = plan
            .block_counts
            .iter()
            .filter(|(_, &n)| n > 0 && n < SUSTAINED_THRESHOLD)
            .map(|(rid, _)| rid.clone())
            .collect();

        let mut new_lines: Vec<String> = Vec::new();

        let mut sustained_sorted: Vec<&String> = sustained_set.iter().collect();
        sustained_sorted.sort();
        for rid in &sustained_sorted {
            let n = plan.block_counts.get(*rid).copied().unwrap_or(0);
            new_lines.push(format!(
                "[sustained: rules={rid} blocked {n} times — {}]",
                rule_guidance(rid)
            ));
        }

        let mut introduced: HashSet<String> = sustained_set.clone();
        for line in plan.text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if SUSTAINED_LINE_RE.is_match(line) {
                continue;
            }
            // Skip stale tool-stuck lines — they are regenerated from
            // tool_error_counts below, so we never copy the old version.
            if TOOL_STUCK_LINE_RE.is_match(line) {
                continue;
            }
            if let Some(cap) = RAW_LINE_RE.captures(line) {
                let rids: Vec<String> = cap
                    .get(1)
                    .unwrap()
                    .as_str()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
                let introduces_new_below = rids.iter().any(|r| {
                    below_threshold_rules.contains(r) && !introduced.contains(r)
                });
                if introduces_new_below {
                    new_lines.push(line.to_string());
                    for r in rids {
                        introduced.insert(r);
                    }
                }
            } else {
                new_lines.push(line.to_string());
            }
            if new_lines.len() >= MAX_BLOCK_RECORDS {
                break;
            }
        }

        // Tools with consecutive errors >= TOOL_ERROR_THRESHOLD emit a
        // stuck-guidance line so the agent sees an explicit "try differently"
        // signal rather than silently repeating the same failing call.
        let mut stuck: Vec<(&String, usize)> = plan
            .tool_error_counts
            .iter()
            .filter(|(_, &n)| n >= TOOL_ERROR_THRESHOLD)
            .map(|(name, &n)| (name, n))
            .collect();
        stuck.sort_by_key(|(name, _)| name.as_str());
        for (tool, count) in &stuck {
            if new_lines.len() < MAX_BLOCK_RECORDS {
                new_lines.push(format!(
                    "[tool-stuck: {tool} failed {count} times consecutively — \
                     read the FULL error output; try smaller input or a different approach]"
                ));
            }
        }

        plan.text = new_lines.join("\n");
        plan.clear_dirty();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(p: &mut Plan, turn: usize, rules: &[&str]) {
        let ids: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
        p.record_block(turn, &ids);
    }

    // ── record_block invariants ────────────────────────────────────────

    #[test]
    fn record_block_appends_with_turn_index_and_sorted_rules() {
        let mut p = Plan::default();
        p.record_block(5, &["secret_in_output".into(), "placeholder_leakage".into()]);
        assert_eq!(p.blocks_recorded, 1);
        assert!(p.is_dirty());
        assert!(p.text.contains("rules=placeholder_leakage,secret_in_output"));
        assert!(p.text.contains("turn 5"));
    }

    #[test]
    fn record_block_dedupes_repeated_rule_ids() {
        let mut p = Plan::default();
        p.record_block(1, &["foo".into(), "foo".into(), "bar".into()]);
        assert!(p.text.contains("rules=bar,foo"));
        assert_eq!(p.block_counts.get("foo"), Some(&1));
        assert_eq!(p.block_counts.get("bar"), Some(&1));
    }

    #[test]
    fn record_block_writes_turn_index_to_block_turns() {
        let mut p = Plan::default();
        block(&mut p, 3, &["A", "B"]);
        block(&mut p, 7, &["A"]);
        assert_eq!(p.block_turns.get("A"), Some(&vec![3, 7]));
        assert_eq!(p.block_turns.get("B"), Some(&vec![3]));
        assert_eq!(p.block_counts.get("A"), Some(&2));
        assert_eq!(p.block_counts.get("B"), Some(&1));
    }

    #[test]
    fn record_block_caps_text_at_max_records() {
        let mut p = Plan::default();
        for t in 0..(MAX_BLOCK_RECORDS + 5) {
            block(&mut p, t, &["x"]);
        }
        assert_eq!(p.text.lines().count(), MAX_BLOCK_RECORDS);
        // block_counts is unbounded — the whole point of the separate counter.
        assert_eq!(p.block_counts.get("x"), Some(&(MAX_BLOCK_RECORDS + 5)));
        // block_turns is also unbounded in monotonic mode.
        assert_eq!(p.block_turns.get("x").unwrap().len(), MAX_BLOCK_RECORDS + 5);
    }

    #[test]
    fn empty_rule_list_increments_unknown_counter() {
        let mut p = Plan::default();
        p.record_block(1, &[]);
        assert!(p.text.contains("rules=unknown"));
        assert_eq!(p.block_counts.get("unknown"), Some(&1));
    }

    // ── sliding-window mode ────────────────────────────────────────────

    #[test]
    fn with_window_constructs_windowed_plan() {
        let p = Plan::with_window(10);
        assert_eq!(p.window, Some(10));
        assert!(p.block_counts.is_empty());
        assert!(p.text.is_empty());
    }

    #[test]
    fn prune_window_is_noop_in_monotonic_mode() {
        let mut p = Plan::default();
        block(&mut p, 0, &["x"]);
        block(&mut p, 1, &["x"]);
        let pruned = p.prune_window(1000);
        assert_eq!(pruned, 0);
        assert_eq!(p.block_counts.get("x"), Some(&2));
    }

    #[test]
    fn prune_window_ages_out_entries_past_window() {
        let mut p = Plan::with_window(5);
        block(&mut p, 0, &["x"]);
        block(&mut p, 3, &["x"]);
        block(&mut p, 8, &["x"]);
        // At current_turn=10, keep entries where t + 5 > 10, i.e. t > 5.
        // t=0 → 5 > 10 false → prune. t=3 → 8 > 10 false → prune. t=8 → 13 > 10 true → keep.
        let pruned = p.prune_window(10);
        assert_eq!(pruned, 2);
        assert_eq!(p.block_turns.get("x"), Some(&vec![8]));
        assert_eq!(p.block_counts.get("x"), Some(&1));
    }

    #[test]
    fn prune_window_removes_rule_when_all_entries_age_out() {
        let mut p = Plan::with_window(5);
        block(&mut p, 0, &["x"]);
        block(&mut p, 1, &["x"]);
        // At current_turn=10, all entries age out.
        let pruned = p.prune_window(10);
        assert_eq!(pruned, 2);
        assert!(p.block_turns.get("x").is_none(), "rule must be removed");
        assert!(p.block_counts.get("x").is_none());
    }

    #[test]
    fn refresh_in_window_mode_drops_aged_sustained_line() {
        let mut p = Plan::with_window(10);
        for t in 0..3 {
            block(&mut p, t, &["secret_in_output"]);
        }
        let planner = Planner::new();
        // Right after the 3rd block (most recent at turn 2), refresh shows sustained.
        planner.refresh(&mut p, 2);
        assert!(p.text.contains("[sustained: rules=secret_in_output"));
        // Advance well past the window. All three entries age out.
        planner.refresh(&mut p, 100);
        assert!(p.block_counts.get("secret_in_output").is_none());
        assert!(p.text.is_empty(), "expected empty plan, got: {}", p.text);
    }

    #[test]
    fn refresh_in_window_mode_drops_aged_raw_line() {
        let mut p = Plan::with_window(5);
        block(&mut p, 0, &["x"]);
        let planner = Planner::new();
        // At turn 0, raw line preserved.
        planner.refresh(&mut p, 0);
        assert!(p.text.contains("[turn 0 blocked: rules=x]"));
        // Advance past window. Rule fully ages out → raw line dropped too.
        planner.refresh(&mut p, 100);
        assert!(p.text.is_empty());
    }

    // ── monotonic refresh behavior (unchanged from v0) ────────────────

    #[test]
    fn refresh_below_threshold_preserves_most_recent_record() {
        let mut p = Plan::default();
        block(&mut p, 1, &["secret_in_output"]);
        block(&mut p, 2, &["secret_in_output"]);
        Planner::new().refresh(&mut p, 2);
        assert_eq!(p.text.lines().count(), 1);
        assert!(p.text.contains("turn 2"), "got: {}", p.text);
        assert!(!p.text.contains("turn 1"));
        assert_eq!(p.block_counts.get("secret_in_output"), Some(&2));
        assert!(!p.is_dirty());
    }

    #[test]
    fn refresh_collapses_sustained_pattern_into_one_line() {
        let mut p = Plan::default();
        for t in 0..5 {
            block(&mut p, t, &["secret_in_output"]);
        }
        Planner::new().refresh(&mut p, 5);
        assert_eq!(p.text.lines().count(), 1);
        assert!(p.text.contains("[sustained: rules=secret_in_output blocked 5 times"));
        assert!(p.text.contains("credentials"));
    }

    #[test]
    fn refresh_emits_sustained_and_below_threshold_together() {
        let mut p = Plan::default();
        for t in 0..3 {
            block(&mut p, t, &["banned_truth_phrases"]);
        }
        block(&mut p, 9, &["placeholder_leakage"]);
        Planner::new().refresh(&mut p, 9);
        assert!(p.text.contains("[sustained: rules=banned_truth_phrases blocked 3 times"));
        assert!(p.text.contains("[turn 9 blocked: rules=placeholder_leakage]"));
    }

    #[test]
    fn refresh_is_idempotent() {
        let mut p = Plan::default();
        for t in 0..4 {
            block(&mut p, t, &["secret_in_output"]);
        }
        let planner = Planner::new();
        planner.refresh(&mut p, 4);
        let first = p.text.clone();
        planner.refresh(&mut p, 4);
        assert_eq!(p.text, first);
    }

    #[test]
    fn refresh_on_empty_plan_clears_dirty() {
        let mut p = Plan::default();
        p.mark_dirty();
        Planner::new().refresh(&mut p, 0);
        assert!(p.text.is_empty());
        assert!(!p.is_dirty());
    }

    #[test]
    fn refresh_picks_rule_specific_guidance() {
        let mut p = Plan::default();
        for t in 0..3 {
            block(&mut p, t, &["copyright_quote_length"]);
        }
        Planner::new().refresh(&mut p, 3);
        assert!(p.text.contains("paraphrase"));
    }

    #[test]
    fn refresh_falls_back_to_default_guidance_for_unknown_rule() {
        let mut p = Plan::default();
        for t in 0..3 {
            block(&mut p, t, &["my_custom_rule"]);
        }
        Planner::new().refresh(&mut p, 3);
        assert!(p.text.contains("avoid this pattern"));
    }

    // ── perf measurement / regression guard ──────────────────────────

    /// Measures `prune_window` at realistic scale and asserts a loose
    /// upper bound. Two regimes:
    ///   - idempotent prune (already aged-out state, ongoing per-turn cost)
    ///   - full prune (long-idle plan, single catch-up call)
    /// Both should be sub-millisecond at the scale a real rule library
    /// reaches. Numbers are printed to stderr; run with `--nocapture` to
    /// inspect. The assert exists to catch order-of-magnitude regressions
    /// (e.g. someone accidentally adds an O(n²) walk).
    ///
    /// `#[ignore]` because this is a debug-build perf microbenchmark
    /// that flakes by ±10% under cargo-test's parallel runner. Re-enable
    /// with `cargo test --release -- --ignored prune_window_perf` to
    /// run intentionally.
    #[test]
    #[ignore]
    fn prune_window_perf_at_realistic_scale() {
        use std::time::Instant;

        // Realistic scale: 14 rules (the shipped library size), window=50,
        // entries-per-rule saturated.
        let mut p = Plan::with_window(50);
        for t in 0..50 {
            for i in 0..14 {
                p.record_block(t, &[format!("rule_{i}")]);
            }
        }
        let total_entries: usize = p.block_turns.values().map(|v| v.len()).sum();
        assert_eq!(total_entries, 700);

        // Idempotent prune cost — most representative of per-turn overhead.
        let n_idempotent = 10_000;
        let start = Instant::now();
        for _ in 0..n_idempotent {
            p.prune_window(50);
        }
        let elapsed = start.elapsed();
        let per_call_ns = elapsed.as_nanos() / n_idempotent as u128;
        eprintln!(
            "prune_window idempotent @ 14 rules × 50 entries: {per_call_ns} ns/call \
             ({n_idempotent} calls in {} µs)",
            elapsed.as_micros()
        );
        assert!(
            elapsed.as_millis() < 1000,
            "perf regression: {n_idempotent} idempotent prunes took {}ms (target < 1000ms)",
            elapsed.as_millis()
        );

        // Full prune cost — a long-idle plan catching up.
        let mut p2 = Plan::with_window(50);
        for t in 0..50 {
            for i in 0..14 {
                p2.record_block(t, &[format!("rule_{i}")]);
            }
        }
        let start = Instant::now();
        let pruned = p2.prune_window(1_000_000);
        let full_prune_ns = start.elapsed().as_nanos();
        eprintln!(
            "prune_window full-prune @ 14 rules × 50 entries → empty: {full_prune_ns} ns \
             ({pruned} entries removed)"
        );
        assert_eq!(pruned, 700);
        assert!(
            full_prune_ns < 10_000_000,
            "single full prune took {} ns (target < 10ms)",
            full_prune_ns
        );
    }

    // ── tool error tracking ───────────────────────────────────────────

    #[test]
    fn record_tool_error_increments_count() {
        let mut p = Plan::default();
        p.record_tool_error("Bash");
        assert_eq!(p.tool_error_counts.get("Bash"), Some(&1));
        assert!(!p.is_dirty(), "below threshold — no dirty flag yet");
        p.record_tool_error("Bash");
        p.record_tool_error("Bash");
        assert_eq!(p.tool_error_counts.get("Bash"), Some(&3));
        assert!(p.is_dirty(), "at threshold — plan must be dirty");
    }

    #[test]
    fn record_tool_success_resets_count() {
        let mut p = Plan::default();
        for _ in 0..5 {
            p.record_tool_error("Write");
        }
        assert!(p.is_dirty());
        p.clear_dirty();
        p.record_tool_success("Write");
        assert_eq!(p.tool_error_counts.get("Write"), Some(&0));
        assert!(p.is_dirty(), "clearing a stuck tool must re-dirty the plan");
    }

    #[test]
    fn refresh_emits_stuck_guidance_at_threshold() {
        let mut p = Plan::default();
        for _ in 0..TOOL_ERROR_THRESHOLD {
            p.record_tool_error("Bash");
        }
        Planner::new().refresh(&mut p, 0);
        assert!(
            p.text.contains("[tool-stuck: Bash failed"),
            "expected stuck-guidance line, got: {}",
            p.text
        );
        assert!(p.text.contains("FULL error output"));
    }

    #[test]
    fn refresh_drops_stuck_guidance_after_success() {
        let mut p = Plan::default();
        for _ in 0..TOOL_ERROR_THRESHOLD {
            p.record_tool_error("Read");
        }
        let planner = Planner::new();
        planner.refresh(&mut p, 0);
        assert!(p.text.contains("[tool-stuck: Read"));
        // Tool succeeds — count resets
        p.record_tool_success("Read");
        planner.refresh(&mut p, 0);
        assert!(
            !p.text.contains("[tool-stuck: Read"),
            "stuck line must disappear after success, got: {}",
            p.text
        );
    }

    #[test]
    fn refresh_then_block_still_trips_threshold_via_counter() {
        let mut p = Plan::default();
        let planner = Planner::new();
        block(&mut p, 0, &["secret_in_output"]);
        planner.refresh(&mut p, 0);
        block(&mut p, 1, &["secret_in_output"]);
        planner.refresh(&mut p, 1);
        block(&mut p, 2, &["secret_in_output"]);
        planner.refresh(&mut p, 2);
        assert_eq!(p.block_counts.get("secret_in_output"), Some(&3));
        assert!(p.text.contains("[sustained: rules=secret_in_output"));
    }
}
