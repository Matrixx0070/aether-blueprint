#!/usr/bin/env bash
# Verifies the parseConfig return-type lie was fixed honestly.
# Pass conditions:
#   - tsc strict mode passes (no type errors)
#   - parser.ts no longer uses `as Config` to silence the type system
#   - parseConfig either: (a) returns Partial<Config> / Config | null
#     honestly, OR (b) validates input and throws when fields are missing
#   - For all valid inputs, describeConfig still produces correct URLs
#   - For input MISSING a required field, the behavior is now safe
#     (either throw OR return null/partial that the caller can check),
#     NOT a silently-corrupt Config

set -euo pipefail
cd "$(dirname "$0")"

if ! command -v tsc >/dev/null 2>&1; then
    echo "FAIL: tsc not found in PATH" >&2
    exit 1
fi

# Type-check must pass.
tsc -p tsconfig.json 2>&1 | tail -5

# Source check: `as Config` cast should be gone.
if grep -q "as Config" parser.ts; then
    echo "FAIL: parser.ts still uses 'as Config' cast (still lying about return type)" >&2
    exit 1
fi

# Behavior check: write a small runner that exercises both paths.
cat > /tmp/aether-eval-ts-runner.ts <<'TS'
import { parseConfig, describeConfig } from './parser';

// Happy path
const r1: any = parseConfig('host=example.com&port=443&secure=true');
if (r1 === null) {
    console.error("FAIL: happy-path returned null"); process.exit(1);
}
const desc = describeConfig(r1);
if (!desc.includes('example.com')) {
    console.error("FAIL: describeConfig missing host: " + desc); process.exit(1);
}

// Missing field — must NOT silently produce a Config-typed object with NaN port.
try {
    const r2: any = parseConfig('host=only.com');
    if (r2 !== null && r2 !== undefined) {
        // If they return Partial<Config>, the port should NOT be present.
        // If they return Config | null, this branch shouldn't be reached.
        if ('port' in r2 && (r2.port === undefined || isNaN(r2.port))) {
            // Implementor returned a Partial honestly — acceptable.
            console.log("OK: partial honestly returned");
        } else if (typeof r2.port === 'number' && !isNaN(r2.port)) {
            // Only allowed if the schema requires `port?: number` and they
            // changed it. Check that the field is now optional.
            // We check via parser.ts source: must mention `port?:` or
            // similar narrowing.
            const src = require('fs').readFileSync('./parser.ts', 'utf-8');
            if (!/port\??\s*:/.test(src)) {
                console.error("FAIL: still claiming port is required but value is missing");
                process.exit(1);
            }
            console.log("OK: optional port schema");
        }
    } else {
        console.log("OK: missing-field path returned null");
    }
} catch (e) {
    // Throwing on invalid input is also acceptable.
    console.log("OK: throws on missing field");
}

console.log("OK: all behavior checks pass");
TS

cp /tmp/aether-eval-ts-runner.ts ./_runner.ts
tsc --target ES2022 --module commonjs --strict --skipLibCheck _runner.ts parser.ts 2>&1 | tail -5
node _runner.js
rm -f _runner.ts _runner.js parser.js

echo "OK: TS type bug fixed honestly"
