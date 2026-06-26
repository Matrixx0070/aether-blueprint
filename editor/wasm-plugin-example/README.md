# aether WASM plugin example

Minimal example of a sandboxed plugin for aether.

## Build

```sh
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/aether_wasm_echo.wasm .
```

## Install

Drop this whole directory under `~/.aether/plugins/` so the layout is:

```
~/.aether/plugins/echo/
    manifest.json
    aether_wasm_echo.wasm
```

aether picks it up on the next session start. Verify with:

```
$ aether -p "Use plugin__wasm_echo with name=Alice"
[plugin] loaded 1 wasm plugin(s): plugin__wasm_echo
The tool returned: "Hello, Alice, from a sandboxed WASM plugin..."
```

## Wire protocol

- Tool input is fed to the WASM module's **stdin** as a single JSON document.
- The module's **stdout** becomes the tool reply.
- The module's **stderr** is appended to any error message.
- The module is expected to be a WASI preview1 binary (`wasm32-wasip1`)
  with a standard `_start` export.

## Sandbox

The wasmtime runtime applies:

- 64 MiB memory cap per instance.
- 30 s wall-clock soft timeout per call.
- No filesystem access except for `allow_dirs` entries in the manifest
  (each entry is `[host_path, guest_path]`, read-only).
- No network access (WASI preview1 doesn't expose sockets).

## Why pick WASM over the subprocess loader?

The sister crate `aether-plugin` ships subprocess plugins which run
with the same privileges as the aether process. Use a WASM plugin when:

- Plugin code is untrusted (third-party, downloaded, generated).
- You need a memory cap that a fork bomb cannot exhaust.
- You want filesystem capabilities to be capability-based rather than
  inherited from the parent.

Use a subprocess plugin (the v0.16 default) when:

- The plugin is a shell script you wrote yourself.
- The plugin needs network access (which WASI preview1 forbids).
- The plugin needs filesystem write access.
