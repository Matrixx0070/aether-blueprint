//! Distributed analysis (TIER 24): a real multi-process work-fan-out
//! primitive, not a simulation.
//!
//! HH-A (2026-07-02): the pre-HH shape of this crate was an 18-line
//! stub (`create_distributed_node` returning a static struct) with no
//! caller anywhere in the workspace — the `aether distributed` CLI
//! command printed hardcoded "Peers: (connecting...)" text with zero
//! connection to this crate. This module replaces that with actual
//! OS-process-level parallelism: a coordinator walks a target
//! directory, shards the file list across N real child processes
//! (each spawned via `std::process::Command`, each with its own PID),
//! feeds each child its shard over stdin, and aggregates the
//! newline-delimited JSON each child writes to stdout.
//!
//! Per the Plan HH risk register (§HH-A): spawning `tokio::spawn`
//! tasks or OS threads would NOT close this gap — this codebase
//! already has plenty of async/thread concurrency (the parallel-tool
//! executor, the SIEM flusher, etc.). "Distributed" has to mean
//! separate OS processes, verifiable by distinct PIDs, which is what
//! `spawn_workers` / `run_worker` actually do.
//!
//! The distributed unit of work is `aether-secrets::scan_file` — an
//! existing pure, per-file, side-effect-free scan primitive that's a
//! natural fit for sharding (no shared mutable state between files).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

/// One child process's contribution: its real OS pid, how many files
/// it scanned, how long it took, and the findings it produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResult {
    pub pid: u32,
    pub files_scanned: usize,
    pub elapsed_ms: u128,
    pub findings: Vec<aether_secrets::SecretFinding>,
}

/// The coordinator's aggregate view across all workers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DistributedScanReport {
    pub target: String,
    pub worker_count: usize,
    pub total_files: usize,
    pub total_findings: usize,
    pub wall_ms: u128,
    pub workers: Vec<WorkerResult>,
}

impl DistributedScanReport {
    pub fn all_findings(&self) -> Vec<&aether_secrets::SecretFinding> {
        self.workers.iter().flat_map(|w| w.findings.iter()).collect()
    }
}

/// Walk `dir` and split the file list into `worker_count` shards
/// (round-robin, so a directory with an uneven distribution of large
/// files doesn't stack all the big ones onto one worker). Empty
/// shards are dropped — a target with fewer files than workers spawns
/// fewer workers, not idle ones.
pub fn shard_files(dir: &Path, worker_count: usize) -> Result<Vec<Vec<PathBuf>>> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_entry(|e| e.file_name().to_str().map(|s| s != ".git").unwrap_or(true))
    {
        let entry = entry.with_context(|| format!("walk {}", dir.display()))?;
        if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    let n = worker_count.max(1);
    let mut shards: Vec<Vec<PathBuf>> = (0..n).map(|_| Vec::new()).collect();
    for (i, f) in files.into_iter().enumerate() {
        shards[i % n].push(f);
    }
    shards.retain(|s| !s.is_empty());
    Ok(shards)
}

/// Worker entry point. Reads one absolute file path per line from
/// stdin until EOF, runs `aether_secrets::scan_file` on each, and
/// writes exactly one `WorkerResult` as a single JSON line to stdout
/// when done. Intended to be run as `aether distributed --worker` —
/// this function IS the child process's whole job; it never touches
/// the network or spawns anything itself.
pub fn run_worker<R: BufRead, W: Write>(stdin: R, mut stdout: W) -> Result<()> {
    let start = Instant::now();
    let pid = std::process::id();
    let mut seen: HashSet<String> = HashSet::new();
    let mut findings = Vec::new();
    let mut files_scanned = 0usize;
    for line in stdin.lines() {
        let line = line.context("read stdin line")?;
        let path = line.trim();
        if path.is_empty() {
            continue;
        }
        files_scanned += 1;
        if let Ok(f) = aether_secrets::scan_file(Path::new(path), &mut seen) {
            findings.extend(f);
        }
    }
    let result = WorkerResult {
        pid,
        files_scanned,
        elapsed_ms: start.elapsed().as_millis(),
        findings,
    };
    let line = serde_json::to_string(&result).context("serialize WorkerResult")?;
    writeln!(stdout, "{line}").context("write WorkerResult")?;
    stdout.flush().context("flush stdout")?;
    Ok(())
}

/// Coordinator entry point. Shards `target`'s files across
/// `worker_count` real child processes (each `current_exe
/// distributed --worker`), feeds each its shard over stdin, waits for
/// completion, and aggregates. `spawn_child` is injected so tests can
/// exercise the sharding/aggregation logic without needing a built
/// `aether` binary on the test runner's PATH — production callers
/// pass a closure that spawns `std::env::current_exe()? distributed
/// --worker`.
pub fn run_coordinator(
    target: &Path,
    worker_count: usize,
    spawn_worker: impl Fn() -> Result<std::process::Child>,
) -> Result<DistributedScanReport> {
    let wall_start = Instant::now();
    let shards = shard_files(target, worker_count)?;
    let mut children = Vec::new();
    for shard in &shards {
        let mut child = spawn_worker().context("spawn distributed worker process")?;
        let mut stdin = child.stdin.take().context("worker stdin not piped")?;
        for path in shard {
            writeln!(stdin, "{}", path.display()).context("write path to worker stdin")?;
        }
        drop(stdin); // EOF signal to the worker
        children.push(child);
    }
    let mut workers = Vec::new();
    for mut child in children {
        let pid = child.id();
        let status = child.wait().with_context(|| format!("wait on worker pid {pid}"))?;
        let mut stdout = child.stdout.take().context("worker stdout not piped")?;
        let mut out = String::new();
        std::io::Read::read_to_string(&mut stdout, &mut out).context("read worker stdout")?;
        if !status.success() {
            anyhow::bail!("worker pid {pid} exited with {status}: {out}");
        }
        let line = out.lines().next().unwrap_or("").trim();
        let result: WorkerResult = serde_json::from_str(line)
            .with_context(|| format!("parse WorkerResult from pid {pid}: {line:?}"))?;
        workers.push(result);
    }
    let total_files = workers.iter().map(|w| w.files_scanned).sum();
    let total_findings = workers.iter().map(|w| w.findings.len()).sum();
    Ok(DistributedScanReport {
        target: target.display().to_string(),
        worker_count: workers.len(),
        total_files,
        total_findings,
        wall_ms: wall_start.elapsed().as_millis(),
        workers,
    })
}

/// Production `spawn_worker` closure: re-execs the current `aether`
/// binary as `distributed --worker` with stdin/stdout piped. Kept as
/// a free function (rather than inlined at every call site) so the
/// exact command line is pinned in one place and covered by a test.
pub fn spawn_distributed_worker() -> Result<std::process::Child> {
    let exe = std::env::current_exe().context("current_exe")?;
    Command::new(exe)
        .args(["distributed", "--worker"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn worker process")
}

/// Convenience wrapper for the common production path.
pub fn scan_directory_distributed(
    target: &Path,
    worker_count: usize,
) -> Result<DistributedScanReport> {
    run_coordinator(target, worker_count, spawn_distributed_worker)
}

/// Pre-HH compatibility shim. The old `create_distributed_node` API
/// had no callers anywhere in the workspace (grep-confirmed at HH-A
/// time) — kept only so an external caller compiled against the old
/// 0.3x API doesn't hard-break; DEPRECATED in favor of
/// `scan_directory_distributed`.
#[deprecated(note = "use scan_directory_distributed for real multi-process fan-out")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedNode {
    pub node_id: String,
    pub peers: Vec<String>,
    pub analysis_state: String,
}

#[allow(deprecated)]
#[deprecated(note = "use scan_directory_distributed for real multi-process fan-out")]
pub fn create_distributed_node(node_id: &str) -> Result<DistributedNode> {
    Ok(DistributedNode {
        node_id: node_id.to_string(),
        peers: vec![],
        analysis_state: "Ready".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn shard_files_splits_round_robin_and_drops_empty_shards() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..5 {
            write_file(tmp.path(), &format!("f{i}.txt"), "hello");
        }
        // 5 files across 3 workers: every shard non-empty.
        let shards = shard_files(tmp.path(), 3).unwrap();
        assert_eq!(shards.len(), 3);
        let total: usize = shards.iter().map(|s| s.len()).sum();
        assert_eq!(total, 5);

        // 5 files across 10 workers: only 5 non-empty shards survive,
        // not 10 (would mean 5 idle worker processes spawned for nothing).
        let shards = shard_files(tmp.path(), 10).unwrap();
        assert_eq!(shards.len(), 5, "empty shards must be dropped");
    }

    #[test]
    fn shard_files_skips_git_directory() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        write_file(&tmp.path().join(".git"), "HEAD", "ref: refs/heads/main");
        write_file(tmp.path(), "real.txt", "content");
        let shards = shard_files(tmp.path(), 1).unwrap();
        let all: Vec<&PathBuf> = shards.iter().flatten().collect();
        assert_eq!(all.len(), 1, "only real.txt, .git contents excluded");
    }

    /// run_worker is the exact function the `--worker` CLI path calls.
    /// Feed it a real secret via an in-memory pipe and assert the
    /// JSON WorkerResult on stdout carries a finding.
    #[test]
    fn run_worker_scans_stdin_paths_and_emits_json_result() {
        let tmp = tempfile::tempdir().unwrap();
        let f = write_file(
            tmp.path(),
            "config.env",
            "AWS_SECRET_ACCESS_KEY=odJFCrnl2edlBD/dz1C5Jau2RJtBRnlWmTSHf6pW9\n",
        );
        let input = format!("{}\n", f.display());
        let mut out = Vec::new();
        run_worker(Cursor::new(input), &mut out).unwrap();
        let line = String::from_utf8(out).unwrap();
        let result: WorkerResult = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(result.pid, std::process::id());
        assert_eq!(result.files_scanned, 1);
        assert!(!result.findings.is_empty(), "AWS key must be detected");
    }

    #[test]
    fn run_worker_handles_empty_stdin() {
        let mut out = Vec::new();
        run_worker(Cursor::new(""), &mut out).unwrap();
        let result: WorkerResult = serde_json::from_str(
            String::from_utf8(out).unwrap().trim(),
        )
        .unwrap();
        assert_eq!(result.files_scanned, 0);
        assert!(result.findings.is_empty());
    }

    // See tests/distributed_coordinator_integration.rs for the
    // real-child-process coordinator test — CARGO_BIN_EXE_* is only
    // available to integration tests under tests/, not unit tests here.
}
