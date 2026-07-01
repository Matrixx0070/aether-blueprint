//! Backward slicing with symbolic path condition accumulation.
//!
//! Starting from a set of target blocks (sinks), the slicer walks backward
//! through the CFG, collecting:
//!   1. All reachable predecessor blocks.
//!   2. The conjunction of branch conditions along each path (path condition).
//!   3. The symbolic "reaching definitions" of variables used at the target.
//!
//! The result is a set of SlicePath objects, each carrying the full path
//! from a source block to the target and its conjunctive path condition.

use crate::cfg::{BlockId, Cfg};
use crate::expr::Expr;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

/// A single backward-slice path from an entry/source block to the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlicePath {
    /// Sequence of block ids from source → target.
    pub blocks: Vec<BlockId>,
    /// Conjunction of branch conditions collected along the path.
    pub path_condition: Expr,
    /// Free symbolic variables referenced in the path condition.
    pub free_vars: Vec<String>,
    /// True if the path originates at a taint source block.
    pub from_source: bool,
}

impl SlicePath {
    pub fn is_satisfiable_trivially(&self) -> bool {
        // Simple check: if the path condition simplifies to false, skip it.
        let simplified = self.path_condition.clone().simplify();
        simplified != Expr::Bool(false)
    }
}

/// Result of a backward-slice run.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SliceResult {
    pub target: BlockId,
    pub paths: Vec<SlicePath>,
    /// All blocks in the slice (reachable backwards from target).
    pub slice_blocks: Vec<BlockId>,
}

/// Configuration for backward slicing.
#[derive(Debug, Clone)]
pub struct SliceConfig {
    /// Maximum path length in blocks (default 20).
    pub max_depth: usize,
    /// Maximum number of paths to collect (default 500).
    pub max_paths: usize,
    /// If true, only collect paths that start at a taint source block.
    pub sources_only: bool,
}

impl Default for SliceConfig {
    fn default() -> Self {
        SliceConfig {
            max_depth: 20,
            max_paths: 500,
            sources_only: false,
        }
    }
}

/// Compute the backward slice from `target` in the given `cfg`.
pub fn backward_slice(cfg: &Cfg, target: BlockId, config: &SliceConfig) -> SliceResult {
    let mut result = SliceResult {
        target,
        ..Default::default()
    };

    let source_set: HashSet<BlockId> = cfg.source_blocks().into_iter().collect();

    // BFS backwards from target.
    // State: (current_block, path_so_far (target→cur reversed), accumulated_condition)
    let mut queue: VecDeque<(BlockId, Vec<BlockId>, Vec<Expr>)> = VecDeque::new();
    queue.push_back((target, vec![target], vec![]));

    let mut visited_blocks: HashSet<BlockId> = HashSet::from([target]);
    let mut path_count = 0;

    while let Some((cur, rev_path, conditions)) = queue.pop_front() {
        if rev_path.len() > config.max_depth {
            continue;
        }

        let preds = cfg.predecessors(cur);
        let is_entry = preds.is_empty() || cur == cfg.entry;

        if is_entry || rev_path.len() == config.max_depth {
            // Reached entry or depth limit — emit path
            let mut forward_path = rev_path.clone();
            forward_path.reverse();

            let from_source = forward_path
                .first()
                .map(|b| source_set.contains(b))
                .unwrap_or(false);

            if config.sources_only && !from_source {
                // Don't emit paths that don't start at a source
            } else {
                let pc = if conditions.is_empty() {
                    Expr::Bool(true)
                } else if conditions.len() == 1 {
                    conditions[0].clone()
                } else {
                    Expr::And(conditions.clone()).simplify()
                };
                let free_vars = pc.free_vars();
                result.paths.push(SlicePath {
                    blocks: forward_path,
                    path_condition: pc,
                    free_vars,
                    from_source,
                });
                path_count += 1;
                if path_count >= config.max_paths {
                    break;
                }
            }
            if is_entry {
                continue;
            }
        }

        for (pred, cond_opt) in preds {
            visited_blocks.insert(pred);
            let mut new_path = rev_path.clone();
            new_path.push(pred);
            let mut new_conds = conditions.clone();
            if let Some(cond) = cond_opt {
                new_conds.push(cond.clone());
            }
            queue.push_back((pred, new_path, new_conds));
        }
    }

    result.slice_blocks = visited_blocks.into_iter().collect();
    result.slice_blocks.sort();
    result
}

/// Format a SlicePath for human consumption.
pub fn format_path(path: &SlicePath, cfg: &Cfg) -> String {
    let block_labels: Vec<String> = path
        .blocks
        .iter()
        .filter_map(|id| cfg.blocks.get(id))
        .map(|b| b.label.clone())
        .collect();
    format!(
        "PATH [{}] | PC: {} | free_vars: [{}] | source={}",
        block_labels.join(" → "),
        path.path_condition,
        path.free_vars.join(", "),
        path.from_source,
    )
}

/// Pretty-print all instructions in the blocks of a slice path.
pub fn format_path_instrs(path: &SlicePath, cfg: &Cfg) -> String {
    let mut lines = Vec::new();
    for &bid in &path.blocks {
        if let Some(block) = cfg.blocks.get(&bid) {
            lines.push(format!("[{}]", block.label));
            for instr in &block.instrs {
                lines.push(format!("  {}", instr.label));
            }
        }
    }
    lines.join("\n")
}
