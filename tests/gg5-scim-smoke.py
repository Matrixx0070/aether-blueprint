#!/usr/bin/env python3
"""
GG5 live smoke: SCIM 2.0 provisioning end-to-end against a running
`aether serve`, driven by a minimal fake-Okta-style client.

Chain:
  1. `aether scim configure --token <SCIM_TOKEN>` writes scim.json.
  2. Start `aether serve` (AETHER_SERVE_NO_AUTH=1 so /v1/messages
     itself doesn't need a token — this smoke is only about SCIM).
  3. POST /scim/v2/Users without ANY bearer -> 401 (SCIM auth is real).
  4. POST /scim/v2/Users with the SCIM token -> 201, creates a tenant
     ACL row granting tenant "acme" to the presented bearer. Assert
     the row actually landed in ~/.aether/tenants.json (on-disk
     change, not just an HTTP 200 — risk register §GG5).
  5. GET /scim/v2/Users?filter=userName eq "alice@example.com" ->
     finds exactly the created user.
  6. GET /scim/v2/Groups -> "acme" group lists the user as a member.
  7. Privilege separation: the just-created TENANT bearer is
     rejected when presented to /scim/v2/Users (401) — closes GG2's
     risk register item at the live-server level, not just unit
     tests.
  8. PATCH /scim/v2/Users/{id} {"Operations":[{"op":"replace",
     "path":"active","value":false}]} -> 200, deactivates. Assert
     on-disk active=false. Assert an unsupported PATCH op is REJECTED
     (501), not silently ignored (risk register §GG3).
  9. DELETE /scim/v2/Users/{id} -> 204, removes the ACL row entirely.
     Assert on-disk row is gone. Second DELETE -> 404.
  10. ~/.aether/scim_audit.jsonl has one line per mutation (create,
      deactivate, delete).
"""
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

AETHER_BIN = "/root/aether-blueprint/target/release/aether"
SCIM_TOKEN = "gg5-scim-provisioning-token"
USER_BEARER = "gg5-user-bearer-alice"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def req(method, url, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/scim+json")
    if token is not None:
        r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            body_bytes = resp.read()
            return resp.status, (json.loads(body_bytes) if body_bytes else None)
    except urllib.error.HTTPError as e:
        body_bytes = e.read()
        try:
            return e.code, json.loads(body_bytes)
        except Exception:
            return e.code, body_bytes.decode(errors="replace")


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-gg5-"))
    (tmp / ".aether").mkdir(parents=True)
    env = os.environ.copy()
    env["HOME"] = str(tmp)

    cfg = subprocess.run(
        [AETHER_BIN, "scim", "configure", "--token", SCIM_TOKEN],
        env=env, capture_output=True, text=True, timeout=20,
    )
    if cfg.returncode != 0:
        print("FAIL: scim configure exit", cfg.returncode, cfg.stderr)
        sys.exit(1)
    print("[smoke] 0. scim configure OK")

    port = free_port()
    bind = f"127.0.0.1:{port}"
    serve_env = dict(env)
    serve_env["AETHER_SERVE_NO_AUTH"] = "1"
    proc = subprocess.Popen(
        [AETHER_BIN, "serve", "--bind", bind],
        env=serve_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    base = f"http://{bind}"
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"{base}/healthz", timeout=1)
                break
            except Exception:
                time.sleep(0.1)
        else:
            print("FAIL: serve never became healthy")
            print(proc.stdout.read() if proc.stdout else "")
            sys.exit(1)
        print(f"[smoke] serve up on {base}")

        # 3. No bearer -> 401.
        status, body = req("POST", f"{base}/scim/v2/Users", token=None,
                            body={"userName": "x", "urn:ietf:params:scim:schemas:extension:aether:1.0:User":
                                  {"bearer": "x", "tenant": "acme"}})
        if status != 401:
            print(f"FAIL: no-bearer POST -> {status}, expected 401: {body}")
            sys.exit(1)
        print("[smoke] 3. POST without bearer -> 401 OK")

        # 4. Create user.
        create_body = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "alice@example.com",
            "active": True,
            "urn:ietf:params:scim:schemas:extension:aether:1.0:User": {
                "bearer": USER_BEARER, "tenant": "acme", "global": False,
            },
        }
        status, body = req("POST", f"{base}/scim/v2/Users", token=SCIM_TOKEN, body=create_body)
        if status != 201:
            print(f"FAIL: create -> {status}: {body}")
            sys.exit(1)
        user_id = body["id"]
        if body["userName"] != "alice@example.com" or body["active"] is not True:
            print(f"FAIL: unexpected created resource: {body}")
            sys.exit(1)
        tenants_path = tmp / ".aether" / "tenants.json"
        acl = json.loads(tenants_path.read_text())
        row = next((r for r in acl["acls"] if r["bearer_sha256"] == user_id), None)
        if row is None or "acme" not in row["allowed_tenants"]:
            print(f"FAIL: on-disk ACL row missing/wrong after create: {acl}")
            sys.exit(1)
        print(f"[smoke] 4. POST create -> 201, id={user_id[:16]}…, on-disk ACL row confirmed")

        # 5. Filter lookup.
        status, body = req(
            "GET",
            f"{base}/scim/v2/Users?filter=" + urllib.request.quote('userName eq "alice@example.com"'),
            token=SCIM_TOKEN,
        )
        if status != 200 or body["totalResults"] != 1 or body["Resources"][0]["id"] != user_id:
            print(f"FAIL: filtered lookup -> {status}: {body}")
            sys.exit(1)
        print("[smoke] 5. GET filter=userName eq \"alice@example.com\" -> exactly 1 match")

        # 6. Groups.
        status, body = req("GET", f"{base}/scim/v2/Groups", token=SCIM_TOKEN)
        acme = next((g for g in body["Resources"] if g["id"] == "acme"), None)
        if status != 200 or acme is None or not any(m["value"] == user_id for m in acme["members"]):
            print(f"FAIL: groups -> {status}: {body}")
            sys.exit(1)
        print("[smoke] 6. GET /scim/v2/Groups -> acme lists alice as member")

        # 7. Privilege separation at the live server.
        status, body = req("GET", f"{base}/scim/v2/Users", token=USER_BEARER)
        if status != 401:
            print(f"FAIL: tenant bearer authenticated SCIM -> {status}: {body}")
            sys.exit(1)
        print("[smoke] 7. tenant bearer rejected by /scim/v2/Users (401) — privilege separation holds")

        # 8. Deactivate + unsupported-op rejection.
        status, body = req(
            "PATCH", f"{base}/scim/v2/Users/{user_id}", token=SCIM_TOKEN,
            body={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        )
        if status != 200 or body["active"] is not False:
            print(f"FAIL: deactivate -> {status}: {body}")
            sys.exit(1)
        acl = json.loads(tenants_path.read_text())
        row = next(r for r in acl["acls"] if r["bearer_sha256"] == user_id)
        if row["active"] is not False:
            print(f"FAIL: on-disk active not flipped: {row}")
            sys.exit(1)
        status, body = req(
            "PATCH", f"{base}/scim/v2/Users/{user_id}", token=SCIM_TOKEN,
            body={"Operations": [{"op": "replace", "path": "userName", "value": "new@x.com"}]},
        )
        if status != 501:
            print(f"FAIL: unsupported PATCH op should 501, got {status}: {body}")
            sys.exit(1)
        print("[smoke] 8. PATCH deactivate -> 200 + on-disk active=false; unsupported op -> 501")

        # 9. Delete.
        status, body = req("DELETE", f"{base}/scim/v2/Users/{user_id}", token=SCIM_TOKEN)
        if status != 204:
            print(f"FAIL: delete -> {status}: {body}")
            sys.exit(1)
        acl = json.loads(tenants_path.read_text())
        if any(r["bearer_sha256"] == user_id for r in acl["acls"]):
            print(f"FAIL: row still present after delete: {acl}")
            sys.exit(1)
        status, body = req("DELETE", f"{base}/scim/v2/Users/{user_id}", token=SCIM_TOKEN)
        if status != 404:
            print(f"FAIL: second delete should 404, got {status}: {body}")
            sys.exit(1)
        print("[smoke] 9. DELETE -> 204, on-disk row gone; repeat DELETE -> 404")

        # 10. Audit trail.
        audit_path = tmp / ".aether" / "scim_audit.jsonl"
        lines = [json.loads(l) for l in audit_path.read_text().splitlines() if l.strip()]
        actions = [l["action"] for l in lines]
        if actions != ["create", "deactivate", "delete"]:
            print(f"FAIL: audit actions = {actions}, expected [create, deactivate, delete]")
            sys.exit(1)
        print(f"[smoke] 10. scim_audit.jsonl: {actions}")

    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    print("[smoke] GG1-GG5 LIVE-VERIFIED OK (SCIM 2.0 provisioning end-to-end)")


if __name__ == "__main__":
    main()
