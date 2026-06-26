// Minimal aether WASM plugin example.
//
// Reads JSON from stdin, writes a transformed string to stdout. The
// wasmtime host (aether-plugin-wasm) feeds the tool-call input on
// stdin and treats stdout as the reply.
//
// Build:
//   rustup target add wasm32-wasip1
//   cargo build --release --target wasm32-wasip1
//
// Output: target/wasm32-wasip1/release/aether_wasm_echo.wasm

use std::io::{self, Read, Write};

fn main() {
    // Read all of stdin (one shot — tool input is bounded).
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        let _ = io::stderr().write_all(b"wasm-echo: stdin read failed\n");
        std::process::exit(1);
    }

    // Parse the JSON to get a `name` field, fall back to "world".
    let name = match parse_name(&input) {
        Some(n) => n,
        None => "world".to_string(),
    };

    // Emit the reply. This becomes the tool's return value in aether.
    let _ = writeln!(
        io::stdout(),
        "Hello, {name}, from a sandboxed WASM plugin (wasm32-wasip1).",
    );
}

/// Hand-rolled JSON 'name' field extractor — no dependencies so the
/// produced .wasm stays small. Looks for the literal pattern
/// `"name":"VALUE"` (or `"name": "VALUE"` with a space).
fn parse_name(json: &str) -> Option<String> {
    let key = "\"name\"";
    let start = json.find(key)?;
    let after_key = &json[start + key.len()..];
    // Skip whitespace and the colon.
    let after_colon = after_key.trim_start();
    let after_colon = after_colon.strip_prefix(':')?;
    let after_colon = after_colon.trim_start();
    // Expect an opening quote.
    let after_quote = after_colon.strip_prefix('"')?;
    let end = after_quote.find('"')?;
    Some(after_quote[..end].to_string())
}
