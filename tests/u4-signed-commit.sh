#!/usr/bin/env bash
#
# U4 integration test: closes the T3 LOW that the SUCCESS path of
# `aether plugin verify --require-signed-commit` was UNVERIFIED.
#
# Mints a throwaway repo + gpg key, makes a signed commit, signs a
# manifest pointing at that commit, runs the verifier with all the
# T3 flags, and asserts:
#   - exit code 0
#   - "carries a valid signature" appears in stderr
#   - the manifest signature also verifies (S4's existing flow)
#
# Run with:  bash tests/u4-signed-commit.sh
# Or via CI: this script is shell-only — no extra deps beyond gpg + git.

set -euo pipefail

AETHER_BIN="${AETHER_BIN:-./target/debug/aether}"
if [ ! -x "$AETHER_BIN" ]; then
    echo "aether binary not found at $AETHER_BIN — set AETHER_BIN to override" >&2
    exit 2
fi

WORKDIR=$(mktemp -d)
GPG_HOME=$(mktemp -d)
KEYDIR=$(mktemp -d)
trap 'gpgconf --homedir "$GPG_HOME" --kill all 2>/dev/null || true; rm -rf "$WORKDIR" "$GPG_HOME" "$KEYDIR"' EXIT
chmod 700 "$GPG_HOME"

echo "=== U4: generate throwaway gpg key in $GPG_HOME ==="
cat > "$WORKDIR/gen-key.batch" <<'EOF'
%no-protection
Key-Type: RSA
Key-Length: 3072
Name-Real: aether-u4-test
Name-Email: aether-u4@test.local
Expire-Date: 1d
EOF
GNUPGHOME="$GPG_HOME" gpg --batch --gen-key "$WORKDIR/gen-key.batch" 2>&1 | tail -2
KEY_ID=$(GNUPGHOME="$GPG_HOME" gpg --list-secret-keys --keyid-format=long \
    aether-u4@test.local 2>/dev/null \
    | awk '/^sec/ {print $2}' | cut -d/ -f2 | head -1)
if [ -z "$KEY_ID" ]; then
    echo "FAIL: could not extract gpg key id" >&2
    exit 1
fi
echo "  key id: $KEY_ID"

echo "=== make a signed commit in $WORKDIR/repo ==="
mkdir -p "$WORKDIR/repo"
cd "$WORKDIR/repo"
git init --quiet
git config user.email "aether-u4@test.local"
git config user.name "aether-u4-test"
git config user.signingkey "$KEY_ID"
git config commit.gpgsign true
git config gpg.program /usr/bin/gpg
echo "hello u4" > README.md
git add README.md
GNUPGHOME="$GPG_HOME" git commit --quiet -S -m "init signed"
SIGNED_SHA=$(git rev-parse HEAD)
echo "  signed SHA: $SIGNED_SHA"

# Sanity: native git verify-commit must succeed.
if ! GNUPGHOME="$GPG_HOME" git verify-commit "$SIGNED_SHA" 2>&1 | grep -q "Good signature"; then
    echo "FAIL: native git verify-commit did NOT confirm the test commit" >&2
    GNUPGHOME="$GPG_HOME" git verify-commit "$SIGNED_SHA" >&2 || true
    exit 1
fi
echo "  native git verify-commit → Good signature"

cd /

echo "=== mint ed25519 keypair + sign a manifest with commit_sha = $SIGNED_SHA ==="
"$AETHER_BIN" plugin keypair "$KEYDIR/k" >/dev/null
cat > "$KEYDIR/manifest.json" <<EOF
{
  "name": "U4SignedCommit",
  "description": "U4 integration test",
  "input_schema": { "type": "object", "properties": {} },
  "command": "/bin/echo",
  "commit_sha": "$SIGNED_SHA"
}
EOF
"$AETHER_BIN" plugin sign "$KEYDIR/manifest.json" --algorithm ed25519 \
    --private-key "$KEYDIR/k.priv" >/dev/null

echo "=== aether plugin verify --enforce-commit-pinned --resolve-commit ... --require-signed-commit ==="
# Pass GNUPGHOME so the aether-spawned `git verify-commit` finds the same keyring.
if ! GNUPGHOME="$GPG_HOME" "$AETHER_BIN" plugin verify "$KEYDIR/manifest.json" \
        --public-key "$KEYDIR/k.pub" \
        --enforce-commit-pinned \
        --resolve-commit "$WORKDIR/repo" \
        --require-signed-commit 2> "$WORKDIR/stderr.log"; then
    echo "FAIL: aether plugin verify exited non-zero on the signed-commit success path" >&2
    cat "$WORKDIR/stderr.log" >&2
    exit 1
fi
cat "$WORKDIR/stderr.log"

if ! grep -q "carries a valid signature" "$WORKDIR/stderr.log"; then
    echo "FAIL: missing 'carries a valid signature' line in stderr" >&2
    exit 1
fi

echo "=== PASS: signed-commit success path verified end-to-end ==="
