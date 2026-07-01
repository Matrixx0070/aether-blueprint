//! Control-flow graph (CFG) representation.
//!
//! A CFG is a directed graph of BasicBlocks connected by edges that carry
//! optional branch conditions (Expr). Backward slicing traverses from a
//! target instruction back through the CFG collecting path conditions.

use crate::expr::Expr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type BlockId = usize;

/// A single instruction in a basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instr {
    /// Human-readable label (e.g. "x = env::var("KEY")" or "sink: write(x)").
    pub label: String,
    /// Optional assignment: defines `lhs` = `rhs_expr`.
    pub lhs: Option<String>,
    pub rhs: Option<Expr>,
    /// If true, this is a taint source.
    pub is_source: bool,
    /// If true, this is a taint sink.
    pub is_sink: bool,
}

impl Instr {
    pub fn assign(lhs: impl Into<String>, rhs: Expr) -> Self {
        let lhs = lhs.into();
        Instr {
            label: format!("{lhs} = {rhs}"),
            lhs: Some(lhs),
            rhs: Some(rhs),
            is_source: false,
            is_sink: false,
        }
    }
    pub fn source(lhs: impl Into<String>, rhs: Expr) -> Self {
        let mut i = Self::assign(lhs, rhs);
        i.is_source = true;
        i.label = format!("[SOURCE] {}", i.label);
        i
    }
    pub fn sink(label: impl Into<String>) -> Self {
        Instr {
            label: format!("[SINK] {}", label.into()),
            lhs: None,
            rhs: None,
            is_source: false,
            is_sink: true,
        }
    }
    pub fn stmt(label: impl Into<String>) -> Self {
        Instr {
            label: label.into(),
            lhs: None,
            rhs: None,
            is_source: false,
            is_sink: false,
        }
    }
}

/// A basic block: a sequence of instructions with a unique id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BlockId,
    pub label: String,
    pub instrs: Vec<Instr>,
}

impl BasicBlock {
    pub fn new(id: BlockId, label: impl Into<String>) -> Self {
        BasicBlock {
            id,
            label: label.into(),
            instrs: Vec::new(),
        }
    }

    pub fn push(&mut self, instr: Instr) {
        self.instrs.push(instr);
    }
}

/// An edge in the CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: BlockId,
    pub to: BlockId,
    /// Branch condition that must hold for this edge to be taken.
    /// None = unconditional edge.
    pub condition: Option<Expr>,
}

/// Control-flow graph.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Cfg {
    pub blocks: HashMap<BlockId, BasicBlock>,
    pub edges: Vec<CfgEdge>,
    /// Entry block id.
    pub entry: BlockId,
}

impl Cfg {
    pub fn add_block(&mut self, block: BasicBlock) {
        self.blocks.insert(block.id, block);
    }

    pub fn add_edge(&mut self, from: BlockId, to: BlockId, condition: Option<Expr>) {
        self.edges.push(CfgEdge { from, to, condition });
    }

    /// Predecessors of `block` with their edge conditions.
    pub fn predecessors(&self, block: BlockId) -> Vec<(BlockId, Option<&Expr>)> {
        self.edges
            .iter()
            .filter(|e| e.to == block)
            .map(|e| (e.from, e.condition.as_ref()))
            .collect()
    }

    /// Successors of `block` with their edge conditions.
    pub fn successors(&self, block: BlockId) -> Vec<(BlockId, Option<&Expr>)> {
        self.edges
            .iter()
            .filter(|e| e.from == block)
            .map(|e| (e.to, e.condition.as_ref()))
            .collect()
    }

    /// All sink-containing blocks.
    pub fn sink_blocks(&self) -> Vec<BlockId> {
        self.blocks
            .values()
            .filter(|b| b.instrs.iter().any(|i| i.is_sink))
            .map(|b| b.id)
            .collect()
    }

    /// All source-containing blocks.
    pub fn source_blocks(&self) -> Vec<BlockId> {
        self.blocks
            .values()
            .filter(|b| b.instrs.iter().any(|i| i.is_source))
            .map(|b| b.id)
            .collect()
    }
}
