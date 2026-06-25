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

### Python (v0.7)

| File | Bug | CWE | Min severity |
|------|-----|-----|--------------|
| 01_sqli.py | SQL injection via string concat | CWE-89 | HIGH |
| 02_path_traversal.py | Path traversal in `send_file` | CWE-22 | HIGH |
| 03_hardcoded_secret.py | AWS + JWT keys in source | CWE-798 | HIGH |
| 04_command_injection.py | `subprocess(shell=True)` with user input | CWE-78 | HIGH |
| 05_weak_crypto.py | MD5 unsalted password hash | CWE-327 / CWE-916 | MEDIUM |
| 06_insecure_deserialization.py | `pickle.loads` on request data | CWE-502 | HIGH |
| 07_ssrf.py | Unvalidated outbound `requests.get` | CWE-918 | HIGH |

### Java (v0.7.2)

| File | Bug | CWE | Min severity |
|------|-----|-----|--------------|
| 08_java_sqli.java | `Statement.executeQuery` with concat | CWE-89 | HIGH |
| 09_java_xxe.java | `DocumentBuilder` with defaults (XXE) | CWE-611 / CWE-827 | HIGH |
| 10_java_weak_crypto.java | DES in ECB mode | CWE-327 / CWE-326 | MEDIUM |

### C++ (v0.7.2)

| File | Bug | CWE | Min severity |
|------|-----|-----|--------------|
| 11_cpp_buffer_overflow.cpp | `strcpy` into stack buffer | CWE-120 / CWE-121 / CWE-787 | HIGH |
| 12_cpp_format_string.cpp | `printf(user_input)` | CWE-134 | HIGH |
| 13_cpp_integer_overflow.cpp | uint16 × struct size in `malloc` | CWE-190 / CWE-680 / CWE-131 | HIGH |

### Go (v0.7.2)

| File | Bug | CWE | Min severity |
|------|-----|-----|--------------|
| 14_go_command_injection.go | `exec.Command("sh","-c",…)` with user input | CWE-78 | HIGH |
| 15_go_path_traversal.go | `filepath.Join(uploadDir, name)` + `os.Open` | CWE-22 | HIGH |
| 16_go_hardcoded_key.go | HMAC signing key in source | CWE-798 | HIGH |

### Python — gap-fill (v0.7.3)

| File | Bug | CWE | Min severity |
|------|-----|-----|--------------|
| 17_py_redos.py | Catastrophic backtracking in email regex | CWE-1333 / CWE-400 | MEDIUM |
| 18_py_jinja_autoescape.py | Jinja2 `Environment(autoescape=False)` | CWE-79 | HIGH |

### Java — gap-fill (v0.7.3)

| File | Bug | CWE | Min severity |
|------|-----|-----|--------------|
| 19_java_jndi.java | `ctx.lookup(req.getParameter("ref"))` | CWE-74 / CWE-917 | HIGH |
| 20_java_jackson_polymorphic.java | Jackson `activateDefaultTyping(LaissezFaire, NON_FINAL)` | CWE-502 | HIGH |

### Go — gap-fill (v0.7.3)

| File | Bug | CWE | Min severity |
|------|-----|-----|--------------|
| 21_go_map_race.go | Concurrent map read/write without mutex | CWE-362 / CWE-366 | HIGH |
| 22_go_missing_ctx_timeout.go | `http.Get` with no client timeout | CWE-400 / CWE-770 | MEDIUM |

### C++ — gap-fill (v0.7.3)

| File | Bug | CWE | Min severity |
|------|-----|-----|--------------|
| 23_cpp_use_after_free.cpp | Conditional `free` then read of same pointer | CWE-416 | HIGH |
