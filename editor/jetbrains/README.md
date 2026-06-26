# Aether — JetBrains plugin

Bridges a JetBrains IDE to a running `aether serve` instance.

## Build

```bash
cd editor/jetbrains
./gradlew buildPlugin
```

Produces `build/distributions/aether-jetbrains-<VERSION>.zip`.

Install via `File > Settings > Plugins > ⚙ > Install Plugin from Disk…`.

## Configure

Open `Settings > Tools > Aether` and set:

- **Server URL** — the WebSocket endpoint of your `aether serve`, e.g.
  `ws://127.0.0.1:7777/ws/chat`.
- **Bearer token** — required when the server has `AETHER_SERVE_TOKEN`
  set; leave blank otherwise.
- **Default model** — the model id to pass on every prompt.

## Use

Open the **Aether** tool window from the right gutter, or
`Tools > Aether: Ask…` (default keymap: <kbd>Ctrl/Cmd+Alt+A</kbd>).

Type a prompt, hit Enter. The reply streams in; per-turn token + cost
shows in the top status line on completion.

## Compatibility

Built against IntelliJ Platform 2024.3 (build 243). Targets through
build 251.

## License

Apache-2.0. See repository root `LICENSE`.
