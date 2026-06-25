# Installing aether

Three paths, ranked by ease.

## 1. One-liner (recommended)

```sh
curl -fsSL https://raw.githubusercontent.com/Matrixx0070/aether-blueprint/main/install.sh | bash
```

Detects your platform, downloads the matching tarball from the latest
GitHub release, verifies the SHA256, and extracts the `aether` binary to
`~/.local/bin/aether`. Prints a PATH hint if `~/.local/bin` isn't already
on your `PATH`.

### Knobs

| env var          | default                | effect                                           |
|------------------|------------------------|--------------------------------------------------|
| `AETHER_VERSION` | `latest`               | Pin to a specific tag (e.g. `v0.12.0`)           |
| `AETHER_PREFIX`  | `$HOME/.local`         | Install root; binary lands at `$PREFIX/bin/aether` |

Examples:

```sh
# install a specific release
AETHER_VERSION=v0.12.0 curl -fsSL .../install.sh | bash

# install system-wide (requires sudo)
sudo AETHER_PREFIX=/usr/local curl -fsSL .../install.sh | bash
```

## 2. Manual download + verify

If you'd rather not pipe a script to bash, grab the tarball + SHA256SUMS
from the release page and verify by hand:

```sh
# pick your platform; supported tarballs are:
#   aether-vX.Y.Z-linux-x86_64.tar.gz
#   aether-vX.Y.Z-linux-aarch64.tar.gz
#   aether-vX.Y.Z-macos-x86_64.tar.gz
#   aether-vX.Y.Z-macos-aarch64.tar.gz

VERSION=v0.12.0
TARBALL=aether-${VERSION}-linux-x86_64.tar.gz
BASE=https://github.com/Matrixx0070/aether-blueprint/releases/download/${VERSION}

curl -fLO "$BASE/$TARBALL"
curl -fLO "$BASE/SHA256SUMS"

# verify (Linux)
sha256sum -c --ignore-missing SHA256SUMS

# extract
tar -xzf "$TARBALL"
sudo install -m 0755 aether /usr/local/bin/aether
aether --version
```

## 3. Build from source

If your platform isn't on the prebuilt list (Windows, FreeBSD, etc.) or
you want a release pinned to a specific commit, build from source.

Requirements: Rust 1.80+ (stable). The workspace builds with `cargo` only —
no external native dependencies beyond what rustls / reqwest pull in.

```sh
git clone https://github.com/Matrixx0070/aether-blueprint
cd aether-blueprint
cargo build --release -p aether-cli
sudo install -m 0755 target/release/aether /usr/local/bin/aether
aether --version
```

## Uninstall

Delete the binary from its install prefix:

```sh
rm "$HOME/.local/bin/aether"   # or wherever AETHER_PREFIX put it
```

Optionally clean up session data:

```sh
rm -rf "$HOME/.aether"          # sessions, credentials cache, audit log
rm -rf "$HOME/.claude"          # OAuth credentials (shared with Claude Code)
```

The OAuth credentials directory at `~/.claude` is shared with Anthropic's
official `claude` CLI; only remove it if you're decommissioning both.

## After install

Run `aether doctor` to verify your install:

```sh
aether doctor          # text output
aether doctor --json   # CI-friendly structured output
aether doctor --probe  # actually round-trip 1 token through the provider
```

If `auth` reports `no auth source`, you need an Anthropic credential:
- `ANTHROPIC_API_KEY` (console API key), OR
- `CLAUDE_CODE_OAUTH_TOKEN` (Claude Code OAuth bearer), OR
- Run `claude` once to populate `~/.claude/.credentials.json`.

For BYOC providers (Bedrock, Vertex, Azure), set `AETHER_PROVIDER` plus
the corresponding credential env vars — see the v0.10 / v0.11 sections in
`ROADMAP.md`.
