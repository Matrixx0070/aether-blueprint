//! Lock-order directed graph + cycle detection.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockNode {
    pub id: u32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockOrderEdge {
    pub from: u32,
    pub to: u32,
    /// Thread that created this ordering.
    pub observed_on_thread: u32,
    /// Call site context (file:line if known).
    pub context: Option<String>,
}

/// A deadlock cycle: sequence of lock ids forming a cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cycle {
    pub lock_ids: Vec<u32>,
    pub lock_names: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LockGraph {
    pub nodes: Vec<LockNode>,
    pub edges: Vec<LockOrderEdge>,
}

impl LockGraph {
    pub fn add_node(&mut self, id: u32, name: impl Into<String>) {
        if !self.nodes.iter().any(|n| n.id == id) {
            self.nodes.push(LockNode { id, name: name.into() });
        }
    }

    pub fn add_edge(&mut self, from: u32, to: u32, thread: u32) {
        if !self.edges.iter().any(|e| e.from == from && e.to == to) {
            self.edges.push(LockOrderEdge {
                from,
                to,
                observed_on_thread: thread,
                context: None,
            });
        }
    }

    /// Find all simple cycles using iterative DFS (Johnson's algorithm simplified).
    pub fn find_cycles(&self) -> Vec<Cycle> {
        let node_ids: Vec<u32> = self.nodes.iter().map(|n| n.id).collect();
        let name_map: HashMap<u32, &str> =
            self.nodes.iter().map(|n| (n.id, n.name.as_str())).collect();

        // Adjacency list
        let mut adj: HashMap<u32, Vec<u32>> = HashMap::new();
        for e in &self.edges {
            adj.entry(e.from).or_default().push(e.to);
        }

        let mut cycles = Vec::new();
        let mut visited: HashSet<u32> = HashSet::new();
        let mut stack: Vec<u32> = Vec::new();
        let mut on_stack: HashSet<u32> = HashSet::new();

        for &start in &node_ids {
            if !visited.contains(&start) {
                dfs_cycles(
                    start,
                    start,
                    &adj,
                    &mut visited,
                    &mut stack,
                    &mut on_stack,
                    &mut cycles,
                    &name_map,
                );
            }
        }
        cycles
    }
}

fn dfs_cycles(
    start: u32,
    current: u32,
    adj: &HashMap<u32, Vec<u32>>,
    visited: &mut HashSet<u32>,
    stack: &mut Vec<u32>,
    on_stack: &mut HashSet<u32>,
    cycles: &mut Vec<Cycle>,
    names: &HashMap<u32, &str>,
) {
    visited.insert(current);
    stack.push(current);
    on_stack.insert(current);

    if let Some(neighbors) = adj.get(&current) {
        for &next in neighbors {
            if next == start && stack.len() > 1 {
                // Found a cycle back to start
                let lock_ids = stack.clone();
                let lock_names = lock_ids
                    .iter()
                    .map(|id| names.get(id).unwrap_or(&"?").to_string())
                    .collect();
                let cycle = Cycle { lock_ids, lock_names };
                // Only add if not already present (by ids)
                if !cycles.iter().any(|c: &Cycle| c.lock_ids == cycle.lock_ids) {
                    cycles.push(cycle);
                }
            } else if !visited.contains(&next) {
                dfs_cycles(start, next, adj, visited, stack, on_stack, cycles, names);
            }
        }
    }

    stack.pop();
    on_stack.remove(&current);
    // Don't remove from visited — avoid re-exploring from this node
}
