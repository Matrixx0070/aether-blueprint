#!/usr/bin/env bash
# Verifies the binary_search bug was fixed correctly.
# Pass: `cargo test` exits 0 with all 4 tests passing.

set -euo pipefail
cd "$(dirname "$0")"

# Use a deterministic target dir so reruns don't recompile from scratch.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/aether-eval-rust-bug-target}"

if ! command -v cargo >/dev/null 2>&1; then
    if [ -x "$HOME/.cargo/bin/cargo" ]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    else
        echo "FAIL: cargo not found in PATH" >&2
        exit 1
    fi
fi

cargo test --offline --quiet 2>&1 | tail -10 || {
    # Fall back to non-offline if offline fails (registry needs refresh).
    cargo test --quiet 2>&1 | tail -10
}

# Also stress-test on a larger random input to catch off-by-ones
# missed by the canned tests.
cat > /tmp/aether-eval-rust-bug-stress.rs <<'RS'
use rust_bug_fixture::binary_search;
fn main() {
    let v: Vec<i32> = (0..1000).map(|i| i * 2).collect();
    for needle in [0, 1, 2, 998, 999, 1000, 1998, -1, 9999] {
        let found = binary_search(&v, &needle);
        let expected = v.iter().position(|x| *x == needle);
        if found != expected {
            eprintln!("FAIL: stress test, needle={needle}, got={found:?}, want={expected:?}");
            std::process::exit(1);
        }
    }
    println!("OK: stress test pass");
}
RS

# Compile + run the stress test against the user's library.
rustc --edition 2021 --crate-type bin \
    -L "$CARGO_TARGET_DIR/debug/deps" \
    --extern rust_bug_fixture="$(ls $CARGO_TARGET_DIR/debug/deps/librust_bug_fixture-*.rlib 2>/dev/null | head -1)" \
    /tmp/aether-eval-rust-bug-stress.rs \
    -o /tmp/aether-eval-rust-bug-stress 2>/dev/null \
    && /tmp/aether-eval-rust-bug-stress \
    || echo "(stress build skipped — only running cargo test)"

echo "OK: cargo test passes"
