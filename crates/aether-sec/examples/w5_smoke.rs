//! W5 live-verification helper. Fires 10 audit entries (the W5 batch
//! threshold) so the SIEM-forward pump runs. Set AETHER_AUDIT_FORWARD
//! before invoking; an HTTP listener on the target URL should observe
//! one POST containing the batch.
//!
//! Usage:
//!   cargo run -p aether-sec --example w5_smoke

fn main() {
    for i in 0..12 {
        // status alternates so the auditer doesn't reject duplicate entries.
        let status = if i % 2 == 0 { "allowed" } else { "refused" };
        aether_sec::append_audit(
            "W5SmokeTest",
            &format!("target-{i}"),
            "scope-fp-stub",
            status,
            Some(format!("entry #{i}")),
        )
        .expect("append_audit");
    }
    // Drain anything left below the 10-line threshold.
    aether_sec::audit_siem_flush();
    eprintln!("[w5_smoke] 12 audit entries appended + flushed");
}
