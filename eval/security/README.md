# Security Edge — `aether review --kind security` eval suite

This is a deliberately-vulnerable fixture set for benchmarking the security
review mode. Each file under `fixtures/` contains exactly one intended bug
and exists ONLY to be read by `aether review --kind security`. Do NOT
import or run them.

## Run

```bash
aether security-eval eval/security/suite.yaml
aether security-eval eval/security/suite.yaml --json > results.json
```

The suite calls `review --kind security` on each fixture, parses the
structured review blocks, and asserts:

1. At least one block's `CWE:` field matches an expected CWE for that fixture.
2. That block's severity is ≥ `severity_min`.

Exit code is 1 if any fixture fails.

## Fixtures

| File | Bug | CWE | Min severity |
|------|-----|-----|--------------|
| 01_sqli.py | SQL injection via string concat | CWE-89 | HIGH |
| 02_path_traversal.py | Path traversal in `send_file` | CWE-22 | HIGH |
| 03_hardcoded_secret.py | AWS + JWT keys in source | CWE-798 | HIGH |
| 04_command_injection.py | `subprocess(shell=True)` with user input | CWE-78 | HIGH |
| 05_weak_crypto.py | MD5 unsalted password hash | CWE-327 / CWE-916 | MEDIUM |
| 06_insecure_deserialization.py | `pickle.loads` on request data | CWE-502 | HIGH |
| 07_ssrf.py | Unvalidated outbound `requests.get` | CWE-918 | HIGH |
