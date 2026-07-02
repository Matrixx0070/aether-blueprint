//! Test-only helper binary: a real, separately-spawnable OS process
//! that speaks the exact same stdin/stdout JSON protocol as
//! `run_worker`, but calls it directly — used by
//! `run_coordinator_aggregates_across_shards` to prove the
//! coordinator's process-spawn/pipe wiring against a REAL child
//! process without depending on the full `aether` binary being built
//! first (crate-level unit test, no cross-crate build-order
//! dependency on aether-cli).
use std::io::{stdin, stdout, BufReader};

fn main() -> anyhow::Result<()> {
    aether_distrib::run_worker(BufReader::new(stdin()), stdout())
}
