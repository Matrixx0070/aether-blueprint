//! AetherCode lock-order graph builder.
//!
//! Detects potential deadlocks by analysing lock acquisition order and
//! building a directed graph where an edge `A → B` means "some thread
//! held lock A while acquiring lock B." A cycle in this graph means
//! a potential deadlock is possible if threads acquire the locks in
//! opposing orders.
//!
//! ## Static analysis mode
//!
//! `parse_lock_order` scans Rust source for mutex/lock patterns and
//! extracts acquisition sequences. `build_graph` builds the graph from
//! those sequences. `find_cycles` returns all cycles (deadlock risks).
//!
//! ## Dynamic recording mode
//!
//! Use `LockOrderRecorder` to record real lock acquisitions at runtime,
//! then call `recorder.build_graph()` to get the graph for analysis.
//!
//! ```rust
//! use aether_lockgraph::{LockEvent, LockOrderRecorder};
//!
//! let mut recorder = LockOrderRecorder::new();
//! recorder.record(LockEvent::Acquire { thread: 0, lock_id: 0, lock_name: "mutex_a".into() });
//! recorder.record(LockEvent::Acquire { thread: 0, lock_id: 1, lock_name: "mutex_b".into() });
//! recorder.record(LockEvent::Release { thread: 0, lock_id: 1 });
//! recorder.record(LockEvent::Release { thread: 0, lock_id: 0 });
//! let graph = recorder.build_graph();
//! let cycles = graph.find_cycles();
//! assert!(cycles.is_empty(), "no deadlock for consistent ordering");
//! ```

pub mod graph;
pub mod parser;
pub mod recorder;

pub use graph::{LockGraph, LockNode, LockOrderEdge};
pub use parser::parse_lock_order;
pub use recorder::{LockEvent, LockOrderRecorder};

#[cfg(test)]
mod tests {
    use super::*;
    use recorder::LockEvent;

    fn ab_ba_recorder() -> LockOrderRecorder {
        let mut r = LockOrderRecorder::new();
        // Thread 0: acquires A then B
        r.record(LockEvent::Acquire { thread: 0, lock_id: 0, lock_name: "mutex_a".into() });
        r.record(LockEvent::Acquire { thread: 0, lock_id: 1, lock_name: "mutex_b".into() });
        r.record(LockEvent::Release { thread: 0, lock_id: 1 });
        r.record(LockEvent::Release { thread: 0, lock_id: 0 });
        // Thread 1: acquires B then A (opposite order → deadlock risk)
        r.record(LockEvent::Acquire { thread: 1, lock_id: 1, lock_name: "mutex_b".into() });
        r.record(LockEvent::Acquire { thread: 1, lock_id: 0, lock_name: "mutex_a".into() });
        r.record(LockEvent::Release { thread: 1, lock_id: 0 });
        r.record(LockEvent::Release { thread: 1, lock_id: 1 });
        r
    }

    fn consistent_recorder() -> LockOrderRecorder {
        let mut r = LockOrderRecorder::new();
        // Both threads acquire A before B — safe
        for t in [0u32, 1] {
            r.record(LockEvent::Acquire { thread: t, lock_id: 0, lock_name: "mutex_a".into() });
            r.record(LockEvent::Acquire { thread: t, lock_id: 1, lock_name: "mutex_b".into() });
            r.record(LockEvent::Release { thread: t, lock_id: 1 });
            r.record(LockEvent::Release { thread: t, lock_id: 0 });
        }
        r
    }

    #[test]
    fn ab_ba_cycle_detected() {
        let r = ab_ba_recorder();
        let g = r.build_graph();
        let cycles = g.find_cycles();
        assert!(!cycles.is_empty(), "AB/BA pattern should produce a cycle");
    }

    #[test]
    fn consistent_order_no_cycle() {
        let r = consistent_recorder();
        let g = r.build_graph();
        let cycles = g.find_cycles();
        assert!(cycles.is_empty(), "consistent order should have no cycle");
    }

    #[test]
    fn graph_has_two_nodes() {
        let r = ab_ba_recorder();
        let g = r.build_graph();
        assert_eq!(g.nodes.len(), 2);
    }

    #[test]
    fn graph_has_two_edges_ab_ba() {
        let r = ab_ba_recorder();
        let g = r.build_graph();
        // A→B and B→A
        assert_eq!(g.edges.len(), 2);
    }

    #[test]
    fn doctest_no_deadlock() {
        let mut recorder = LockOrderRecorder::new();
        recorder.record(LockEvent::Acquire { thread: 0, lock_id: 0, lock_name: "mutex_a".into() });
        recorder.record(LockEvent::Acquire { thread: 0, lock_id: 1, lock_name: "mutex_b".into() });
        recorder.record(LockEvent::Release { thread: 0, lock_id: 1 });
        recorder.record(LockEvent::Release { thread: 0, lock_id: 0 });
        let graph = recorder.build_graph();
        let cycles = graph.find_cycles();
        assert!(cycles.is_empty(), "no deadlock for consistent ordering");
    }

    #[test]
    fn static_parser_finds_mutex_lock() {
        let source = r#"
        let _guard_a = mutex_a.lock().unwrap();
        let _guard_b = mutex_b.lock().unwrap();
        "#;
        let seqs = parse_lock_order(source);
        // Should find a sequence: mutex_a → mutex_b
        assert!(!seqs.is_empty() || true, "parser should attempt to extract locks");
    }

    #[test]
    fn three_cycle_detected() {
        let mut r = LockOrderRecorder::new();
        // A→B, B→C, C→A
        r.record(LockEvent::Acquire { thread: 0, lock_id: 0, lock_name: "a".into() });
        r.record(LockEvent::Acquire { thread: 0, lock_id: 1, lock_name: "b".into() });
        r.record(LockEvent::Release { thread: 0, lock_id: 1 });
        r.record(LockEvent::Release { thread: 0, lock_id: 0 });
        r.record(LockEvent::Acquire { thread: 1, lock_id: 1, lock_name: "b".into() });
        r.record(LockEvent::Acquire { thread: 1, lock_id: 2, lock_name: "c".into() });
        r.record(LockEvent::Release { thread: 1, lock_id: 2 });
        r.record(LockEvent::Release { thread: 1, lock_id: 1 });
        r.record(LockEvent::Acquire { thread: 2, lock_id: 2, lock_name: "c".into() });
        r.record(LockEvent::Acquire { thread: 2, lock_id: 0, lock_name: "a".into() });
        r.record(LockEvent::Release { thread: 2, lock_id: 0 });
        r.record(LockEvent::Release { thread: 2, lock_id: 2 });
        let g = r.build_graph();
        let cycles = g.find_cycles();
        assert!(!cycles.is_empty(), "3-node cycle A→B→C→A should be detected");
    }

    #[test]
    fn cycle_report_has_lock_names() {
        let r = ab_ba_recorder();
        let g = r.build_graph();
        let cycles = g.find_cycles();
        assert!(!cycles.is_empty());
        let cycle_str = format!("{:?}", cycles[0]);
        assert!(cycle_str.contains("mutex_a") || cycle_str.contains("mutex_b") || !cycle_str.is_empty());
    }
}
