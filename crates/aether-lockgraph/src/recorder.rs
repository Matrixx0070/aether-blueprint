//! LockOrderRecorder: records lock acquisition events and builds a LockGraph.

use crate::graph::LockGraph;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LockEvent {
    Acquire { thread: u32, lock_id: u32, lock_name: String },
    Release { thread: u32, lock_id: u32 },
}

/// Records a stream of LockEvents and builds a lock-order graph.
#[derive(Debug, Default)]
pub struct LockOrderRecorder {
    pub events: Vec<LockEvent>,
    /// thread → stack of currently held lock_ids
    held: HashMap<u32, Vec<u32>>,
    /// lock_id → lock_name
    names: HashMap<u32, String>,
}

impl LockOrderRecorder {
    pub fn new() -> Self {
        LockOrderRecorder::default()
    }

    pub fn record(&mut self, event: LockEvent) {
        match &event {
            LockEvent::Acquire { thread, lock_id, lock_name } => {
                self.names.insert(*lock_id, lock_name.clone());
                // For each lock already held by this thread, add an ordering edge
                let held_snapshot = self.held.entry(*thread).or_default().clone();
                // Ordering edges are built from events in build_graph()
                let _ = held_snapshot;
                self.held.entry(*thread).or_default().push(*lock_id);
            }
            LockEvent::Release { thread, lock_id } => {
                if let Some(stack) = self.held.get_mut(thread) {
                    stack.retain(|&id| id != *lock_id);
                }
            }
        }
        self.events.push(event);
    }

    /// Build a LockGraph from the recorded events.
    pub fn build_graph(&self) -> LockGraph {
        let mut graph = LockGraph::default();
        let mut thread_held: HashMap<u32, Vec<u32>> = HashMap::new();

        for event in &self.events {
            match event {
                LockEvent::Acquire { thread, lock_id, lock_name } => {
                    graph.add_node(*lock_id, lock_name.clone());
                    let stack = thread_held.entry(*thread).or_default();
                    // Add edges from all currently-held locks to the new lock
                    for &held in stack.iter() {
                        graph.add_edge(held, *lock_id, *thread);
                    }
                    stack.push(*lock_id);
                }
                LockEvent::Release { thread, lock_id } => {
                    if let Some(stack) = thread_held.get_mut(thread) {
                        stack.retain(|&id| id != *lock_id);
                    }
                }
            }
        }
        graph
    }
}
