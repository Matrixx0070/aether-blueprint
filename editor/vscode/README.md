# aether for VS Code

Minimal VS Code extension that wraps the `aether` CLI binary.

## Commands

| Command | Description |
|---------|-------------|
| `aether: Ask` | Prompt via input box, stream the response into the output channel |
| `aether: Ask about selection` | Same, but prepends the active editor's selection (with language fence) as context |
| `aether: Doctor (health check)` | Runs `aether doctor --json` and pretty-prints the structured report |
| `aether: Open chat panel` | Opens a dedicated webview with multi-turn chat, streamed Markdown rendering, and per-turn usage/cost stats. Requires `aether serve` running separately (see Chat panel below). |

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `aether.binaryPath` | `aether` | Path to the binary. Defaults to `$PATH` lookup. |
| `aether.model` | (empty) | Override the model (e.g. `claude-sonnet-4-6`). Empty = aether's own default. |
| `aether.permissionMode` | `default` | Passed to `aether -p --permission-mode`. `bypassPermissions` lets aether Edit/Write/Bash without prompting. |
| `aether.serveUrl` | `ws://127.0.0.1:7777/ws/chat` | WebSocket URL for the chat panel. |
| `aether.serveToken` | (empty) | Bearer token sent on the WS upgrade. Required only when the server was started with `AETHER_SERVE_TOKEN` set. |

## Chat panel (v0.17+)

Run a long-lived agent server in a terminal:

```sh
aether serve --bind 127.0.0.1:7777
# or with bearer auth:
AETHER_SERVE_TOKEN=secret-xyz aether serve --bind 0.0.0.0:7777
```

Then in VS Code:

1. Open the command palette → `aether: Open chat panel`.
2. Type a prompt, press Cmd+Enter (or click Send).
3. Streamed deltas render as Markdown in real time.
4. Per-turn usage + cost lines surface in the panel footer.
5. The "Reconnect" button forces a fresh WS handshake.

The panel is a vanilla-JS webview with `markdown-it` loaded from a CDN
under the webview's strict CSP. No extra npm deps.

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
