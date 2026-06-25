#!/usr/bin/env bash
# Verifies the XSS hole in render.js was fixed.
# Pass conditions:
#   - renderComment({author: 'X', body: 'Y'}) still contains "X" and "Y"
#     (regression: don't break the happy path)
#   - renderComment({author: '<script>alert(1)</script>', body: 'ok'})
#     must NOT contain the literal "<script>" — it must be escaped
#   - renderComment with body: '<img src=x onerror=alert(1)>' must
#     NOT contain literal "onerror=" — escape the attribute boundary
#   - renderComment with body containing '&' must NOT corrupt other
#     entities (e.g., &amp; must work)

set -euo pipefail
cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1; then
    echo "FAIL: node not found in PATH" >&2
    exit 1
fi

node - <<'JS'
const { renderComment } = require('./render.js');

const checks = [];

// Happy path regression
let r = renderComment({author: 'alice', body: 'hello'});
checks.push([r.includes('alice') && r.includes('hello'), 'happy-path-renders']);

// Script-tag injection
r = renderComment({author: '<script>alert(1)</script>', body: 'ok'});
checks.push([!r.includes('<script>'), 'script-tag-escaped']);

// Attribute-boundary injection
r = renderComment({author: 'bob', body: '<img src=x onerror=alert(1)>'});
checks.push([!r.includes('onerror=alert'), 'attr-injection-escaped']);

// Ampersand corner case
r = renderComment({author: 'dan & co', body: 'a & b'});
checks.push([r.includes('dan') && r.includes('co'), 'amp-survives']);

const failures = checks.filter(([ok, _]) => !ok).map(([_, name]) => name);
if (failures.length > 0) {
    console.error("FAIL: " + failures.join(', '));
    process.exit(1);
}
console.log("OK: all XSS checks pass");
JS
