//! HH-A: run_coordinator against REAL separate OS child processes.
//!
//! Spawns the `fake_worker` test-helper binary (an ordinary `[[bin]]`
//! target auto-discovered from src/bin/, built by Cargo before this
//! integration test runs) via `CARGO_BIN_EXE_fake_worker`. That
//! binary calls the exact same `run_worker` function production code
//! calls. This proves the coordinator's stdin-write / stdout-read /
//! process-wait wiring against genuine OS processes with distinct
//! PIDs — the specific property the Plan HH risk register (§HH-A)
//! requires "distributed" to mean, not an in-process fake and not
//! `tokio::spawn`/thread concurrency (already present elsewhere in
//! this codebase).
use aether_distrib::run_coordinator;
use std::collections::HashSet;
use std::process::{Command, Stdio};

fn write_file(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

#[test]
fn run_coordinator_aggregates_across_real_child_processes() {
    let tmp = tempfile::tempdir().unwrap();
    write_file(tmp.path(), "a.env", "GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef1234\n");
    write_file(tmp.path(), "b.txt", "nothing interesting here\n");
    let target = tmp.path().to_path_buf();
    let worker_bin = env!("CARGO_BIN_EXE_fake_worker");
    let mut seen_pids = HashSet::new();

    let report = run_coordinator(&target, 2, || {
        Command::new(worker_bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(anyhow::Error::from)
    })
    .unwrap();

    assert_eq!(report.total_files, 2);
    assert_eq!(report.total_findings, 1, "the ghp_ token must be found exactly once");
    assert!(report.worker_count >= 1);
    assert!(report.wall_ms < 30_000, "sanity bound on the smoke");
    for w in &report.workers {
        assert!(w.pid > 0, "worker must report a real OS pid");
        assert!(
            seen_pids.insert(w.pid),
            "each worker must be a DISTINCT process, got duplicate pid {}",
            w.pid
        );
    }
}
