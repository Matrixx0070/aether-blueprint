//! AetherCode cross-file taint graph — source-to-sink data-flow analysis.
//!
//! Scans Rust and Python source files for taint sources (env vars, CLI args,
//! file reads, HTTP responses, stdin, DB reads) and sinks (file writes, HTTP
//! sends, shell exec, DB writes, log, deserialize). Builds a lightweight
//! inter-file data-flow graph and enumerates paths from sources to sinks.
//!
//! This is NOT a precise type-aware analysis — it is a pattern-based
//! approximation aimed at surfacing high-signal findings fast. False
//! positives should be triaged by the developer.
//!
//! ## Quick start
//! ```no_run
//! use aether_flow::{build_taint_graph, FlowConfig};
//! use std::path::Path;
//!
//! let cfg = FlowConfig { max_path_depth: 10, ..Default::default() };
//! let graph = build_taint_graph(&[Path::new("src").to_path_buf()], &cfg).unwrap();
//! let paths = graph.find_taint_paths(cfg.max_path_depth);
//! println!("{} source(s), {} sink(s), {} path(s)", graph.source_count(), graph.sink_count(), paths.len());
//! ```

pub mod graph;
pub mod sink;
pub mod source;

pub use graph::{
    EdgeLabel, SinkKind, SourceKind, TaintEdge, TaintGraph, TaintNode, TaintPath, TaintSink,
    TaintSource,
};

use anyhow::Result;
use graph::{InterNode, NodeId};
use std::path::{Path, PathBuf};

/// Configuration for taint graph construction.
#[derive(Debug, Clone)]
pub struct FlowConfig {
    /// Maximum hop depth when searching for source → sink paths.
    pub max_path_depth: usize,
    /// File extensions to scan. Default: ["rs", "py"].
    pub extensions: Vec<String>,
    /// If true, connect same-symbol inter-nodes across files.
    pub cross_file_symbol_flow: bool,
}

impl Default for FlowConfig {
    fn default() -> Self {
        FlowConfig {
            max_path_depth: 12,
            extensions: vec!["rs".into(), "py".into()],
            cross_file_symbol_flow: true,
        }
    }
}

/// Build a TaintGraph by scanning all source files under `roots`.
pub fn build_taint_graph(roots: &[PathBuf], cfg: &FlowConfig) -> Result<TaintGraph> {
    let files = collect_files(roots, &cfg.extensions);
    let mut graph = TaintGraph::default();

    // Track symbol → NodeId for cross-file linking
    let mut symbol_to_nodes: std::collections::HashMap<String, Vec<NodeId>> =
        std::collections::HashMap::new();

    for path in &files {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Add source nodes
        for src in source::detect_sources(path, &content) {
            let sym = src.symbol.clone();
            let id = graph.add_node(TaintNode::Source(src));
            symbol_to_nodes.entry(sym).or_default().push(id);
        }

        // Add sink nodes
        for snk in sink::detect_sinks(path, &content) {
            let sym = snk.symbol.clone();
            let id = graph.add_node(TaintNode::Sink(snk));
            symbol_to_nodes.entry(sym).or_default().push(id);
        }

        // Add inter-nodes for variable assignments (let x = ..., x = ...)
        for (line_idx, line) in content.lines().enumerate() {
            if let Some((lhs, _rhs)) = parse_assignment(line) {
                if lhs.len() > 1 && lhs != "_" {
                    let id = graph.add_node(TaintNode::Inter(InterNode {
                        file: path.clone(),
                        line: line_idx + 1,
                        symbol: lhs.clone(),
                    }));
                    symbol_to_nodes.entry(lhs).or_default().push(id);
                }
            }
        }
    }

    // Wire edges: for each symbol with multiple nodes, connect source/inter
    // nodes to later inter/sink nodes in document order.
    if cfg.cross_file_symbol_flow {
        for nodes in symbol_to_nodes.values() {
            if nodes.len() < 2 {
                continue;
            }
            // Sort by (file, line) so we can connect in order
            let mut ordered: Vec<(NodeId, PathBuf, usize)> = nodes
                .iter()
                .map(|&id| {
                    (
                        id,
                        graph.nodes[id].file().clone(),
                        graph.nodes[id].line(),
                    )
                })
                .collect();
            ordered.sort_by(|a, b| (&a.1, a.2).cmp(&(&b.1, b.2)));

            for window in ordered.windows(2) {
                let from = window[0].0;
                let to = window[1].0;
                // Only flow from non-sink to non-source
                if !graph.nodes[from].is_sink() {
                    graph.add_edge(from, to, EdgeLabel::DataFlow);
                }
            }
        }
    }

    Ok(graph)
}

/// Collect all files under roots matching given extensions.
fn collect_files(roots: &[PathBuf], extensions: &[String]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in roots {
        collect_recursive(root, extensions, &mut files);
    }
    files.sort();
    files
}

fn collect_recursive(dir: &Path, extensions: &[String], out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // skip hidden dirs and common non-source dirs
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') || matches!(name, "target" | "node_modules" | "__pycache__") {
                continue;
            }
            collect_recursive(&path, extensions, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if extensions.iter().any(|e| e == ext) {
                out.push(path);
            }
        }
    }
}

/// Rudimentary assignment parser. Returns (lhs, rhs) for:
/// - `let x = ...`  (Rust)
/// - `x = ...`      (Python, or Rust with existing binding)
fn parse_assignment(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    // Rust: let [mut] ident [: Type] = rhs
    if let Some(rest) = trimmed.strip_prefix("let ") {
        let rest = rest.trim_start_matches("mut").trim();
        if let Some(eq_pos) = rest.find('=') {
            let lhs = rest[..eq_pos]
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            let rhs = rest[eq_pos + 1..].trim().to_string();
            if is_ident(&lhs) {
                return Some((lhs, rhs));
            }
        }
    }
    // Python / simple assignment: ident = rhs (not ==, !=, <=, >=)
    if let Some(eq_pos) = trimmed.find('=') {
        let before = trimmed[..eq_pos].trim();
        let after_char = trimmed.as_bytes().get(eq_pos + 1).copied();
        let prev_char = if eq_pos > 0 {
            trimmed.as_bytes().get(eq_pos - 1).copied()
        } else {
            None
        };
        let is_comparison = matches!(after_char, Some(b'='))
            || matches!(prev_char, Some(b'!' | b'<' | b'>' | b'='));
        if !is_comparison && is_ident(before) {
            let rhs = trimmed[eq_pos + 1..].trim().to_string();
            return Some((before.to_string(), rhs));
        }
    }
    None
}

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().map(|c| c.is_alphabetic() || c == '_').unwrap_or(false)
        && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_detection_rust_env() {
        let content = r#"let api_key = std::env::var("API_KEY").unwrap();"#;
        let path = std::path::Path::new("test.rs");
        let sources = source::detect_sources(path, content);
        assert!(!sources.is_empty());
        let s = &sources[0];
        assert_eq!(s.kind, SourceKind::EnvVar);
    }

    #[test]
    fn sink_detection_rust_exec() {
        let content = r#"Command::new("sh").arg(user_input).output();"#;
        let path = std::path::Path::new("test.rs");
        let sinks = sink::detect_sinks(path, content);
        assert!(sinks.iter().any(|s| s.kind == SinkKind::Exec));
    }

    #[test]
    fn sink_detection_python_eval() {
        let content = "result = eval(user_input)";
        let path = std::path::Path::new("script.py");
        let sinks = sink::detect_sinks(path, content);
        assert!(sinks.iter().any(|s| s.kind == SinkKind::Exec));
    }

    #[test]
    fn parse_assignment_let() {
        assert_eq!(
            parse_assignment("  let mut x = foo();"),
            Some(("x".into(), "foo();".into()))
        );
    }

    #[test]
    fn parse_assignment_python() {
        assert_eq!(
            parse_assignment("data = requests.get(url)"),
            Some(("data".into(), "requests.get(url)".into()))
        );
    }

    #[test]
    fn parse_assignment_skips_comparison() {
        assert!(parse_assignment("if x == 5:").is_none());
        assert!(parse_assignment("if x != 5:").is_none());
    }

    #[test]
    fn taint_graph_path_finds_source_to_sink() {
        let mut g = TaintGraph::default();
        let src = g.add_node(TaintNode::Source(TaintSource {
            file: "a.rs".into(),
            line: 1,
            kind: SourceKind::EnvVar,
            symbol: "secret".into(),
        }));
        let snk = g.add_node(TaintNode::Sink(TaintSink {
            file: "a.rs".into(),
            line: 10,
            kind: SinkKind::Log,
            symbol: "secret".into(),
        }));
        g.add_edge(src, snk, EdgeLabel::DataFlow);
        let paths = g.find_taint_paths(5);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].source_kind, SourceKind::EnvVar);
        assert_eq!(paths[0].sink_kind, SinkKind::Log);
    }

    #[test]
    fn taint_graph_no_path_when_disconnected() {
        let mut g = TaintGraph::default();
        g.add_node(TaintNode::Source(TaintSource {
            file: "a.rs".into(),
            line: 1,
            kind: SourceKind::UserInput,
            symbol: "x".into(),
        }));
        g.add_node(TaintNode::Sink(TaintSink {
            file: "b.rs".into(),
            line: 5,
            kind: SinkKind::Exec,
            symbol: "y".into(),
        }));
        // No edges
        let paths = g.find_taint_paths(5);
        assert!(paths.is_empty());
    }
}
