# Changelog

## 0.20.0 — 2026-06-26

- Marketplace publish prep: `repository`, `homepage`, `bugs`, `keywords`
  metadata added to `package.json`.
- Bundled Apache-2.0 LICENSE in the package (was previously implicit).
- Display name capitalised (`aether` → `Aether`) to match the JetBrains
  plugin and the rest of the project surface.
- Server changes (in the aether-cli that this extension talks to):
  - New `GET/POST/DELETE /v1/trust` endpoints (used by the upcoming
    trust UI; the extension does not surface them yet in this version).
- No behavioural change to existing commands or the chat panel.

## 0.17.0 — 2026-06-26

- Initial public release alongside `aether` v0.17.0:
  - `aether: Ask` / `aether: Ask about selection` / `aether: Doctor`
  - `aether: Open chat panel` — webview chat over WS, streamed Markdown.
  - Bearer-token support for the chat panel.
