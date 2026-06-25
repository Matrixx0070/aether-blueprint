# aether for VS Code

Minimal VS Code extension that wraps the `aether` CLI binary.

## Commands

| Command | Description |
|---------|-------------|
| `aether: Ask` | Prompt via input box, stream the response into the output channel |
| `aether: Ask about selection` | Same, but prepends the active editor's selection (with language fence) as context |
| `aether: Doctor (health check)` | Runs `aether doctor --json` and pretty-prints the structured report |

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `aether.binaryPath` | `aether` | Path to the binary. Defaults to `$PATH` lookup. |
| `aether.model` | (empty) | Override the model (e.g. `claude-sonnet-4-6`). Empty = aether's own default. |
| `aether.permissionMode` | `default` | Passed to `aether -p --permission-mode`. `bypassPermissions` lets aether Edit/Write/Bash without prompting. |

## Install (local development)

Pre-reqs: VS Code ≥ 1.85, Node ≥ 18, the `aether` binary on `$PATH`
(or set `aether.binaryPath`).

```sh
cd editor/vscode
npm install
npm run compile
# Open this folder in VS Code, press F5 to launch the Extension Development Host.
```

## Package as `.vsix`

```sh
npm install -g @vscode/vsce
cd editor/vscode
vsce package
```

The resulting `aether-<version>.vsix` is installable via VS Code's
*Extensions: Install from VSIX...* command.

## Status

This is a v1 skeleton (v0.16 of the aether project). Roadmap:

- v0.17 — dedicated webview panel with multi-turn chat
- v0.18 — diff preview before applying edits in `acceptEdits` mode
- v0.19 — `aether serve` WebSocket integration so the extension talks
  to a long-lived backend instead of spawning per-prompt
