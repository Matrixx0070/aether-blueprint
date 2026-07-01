//! Core graph types: TaintNode, TaintEdge, TaintGraph, path enumeration.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

pub type NodeId = usize;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceKind {
    EnvVar,
    CliArg,
    FileRead,
    HttpRequest,
    UserInput,
    DbRead,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SinkKind {
    FileWrite,
    HttpSend,
    Exec,
    DbQuery,
    Log,
    Deserialize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    pub file: PathBuf,
    pub line: usize,
    pub kind: SourceKind,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    pub file: PathBuf,
    pub line: usize,
    pub kind: SinkKind,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterNode {
    pub file: PathBuf,
    pub line: usize,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum TaintNode {
    Source(TaintSource),
    Sink(TaintSink),
    Inter(InterNode),
}

impl TaintNode {
    pub fn file(&self) -> &PathBuf {
        match self {
            TaintNode::Source(s) => &s.file,
            TaintNode::Sink(s) => &s.file,
            TaintNode::Inter(n) => &n.file,
        }
    }
    pub fn line(&self) -> usize {
        match self {
            TaintNode::Source(s) => s.line,
            TaintNode::Sink(s) => s.line,
            TaintNode::Inter(n) => n.line,
        }
    }
    pub fn symbol(&self) -> &str {
        match self {
            TaintNode::Source(s) => &s.symbol,
            TaintNode::Sink(s) => &s.symbol,
            TaintNode::Inter(n) => &n.symbol,
        }
    }
    pub fn is_source(&self) -> bool {
        matches!(self, TaintNode::Source(_))
    }
    pub fn is_sink(&self) -> bool {
        matches!(self, TaintNode::Sink(_))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EdgeLabel {
    DataFlow,
    Call,
    Return,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintEdge {
    pub from: NodeId,
    pub to: NodeId,
    pub label: EdgeLabel,
}

/// A taint path from a source node to a sink node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    pub nodes: Vec<NodeId>,
    pub source_kind: SourceKind,
    pub sink_kind: SinkKind,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TaintGraph {
    pub nodes: Vec<TaintNode>,
    pub edges: Vec<TaintEdge>,
}

impl TaintGraph {
    pub fn add_node(&mut self, node: TaintNode) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(node);
        id
    }

    pub fn add_edge(&mut self, from: NodeId, to: NodeId, label: EdgeLabel) {
        self.edges.push(TaintEdge { from, to, label });
    }

    /// BFS from every source node; collect paths that reach any sink.
    /// Paths are capped at `max_depth` hops to avoid combinatorial explosion.
    pub fn find_taint_paths(&self, max_depth: usize) -> Vec<TaintPath> {
        let mut adj: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        for e in &self.edges {
            adj.entry(e.from).or_default().push(e.to);
        }

        let mut paths = Vec::new();
        let source_ids: Vec<NodeId> = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.is_source())
            .map(|(i, _)| i)
            .collect();

        for &src in &source_ids {
            // BFS state: (current_node, path_so_far)
            let mut queue: VecDeque<(NodeId, Vec<NodeId>)> = VecDeque::new();
            queue.push_back((src, vec![src]));
            let mut visited: HashSet<NodeId> = HashSet::new();
            visited.insert(src);

            while let Some((cur, path)) = queue.pop_front() {
                if path.len() > max_depth {
                    continue;
                }
                if let TaintNode::Sink(sink) = &self.nodes[cur] {
                    if cur != src {
                        let source_kind = if let TaintNode::Source(s) = &self.nodes[src] {
                            s.kind.clone()
                        } else {
                            continue;
                        };
                        paths.push(TaintPath {
                            nodes: path.clone(),
                            source_kind,
                            sink_kind: sink.kind.clone(),
                        });
                        // Don't extend past sinks
                        continue;
                    }
                }
                if let Some(neighbors) = adj.get(&cur) {
                    for &next in neighbors {
                        if !visited.contains(&next) {
                            visited.insert(next);
                            let mut new_path = path.clone();
                            new_path.push(next);
                            queue.push_back((next, new_path));
                        }
                    }
                }
            }
        }
        paths
    }

    pub fn source_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.is_source()).count()
    }

    pub fn sink_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.is_sink()).count()
    }
}
