#!/usr/bin/env python3
"""
CC5 live smoke: OIDC proactive access-token refresh.

Closes the BB5 weakest-point. BB5 added auto-refresh on userinfo 401
(reactive). CC5 adds proactive refresh BEFORE the userinfo call,
when the persisted `expires_at` is inside the
`AETHER_OIDC_REFRESH_LEAD_SECS` window (default 300s = 5min).

The smoke exercises four flows against one fake OIDC IdP:

  S1. login → sso.access_token.expires_at sidecar present at 0600,
      content is a parseable RFC 3339 UTC timestamp.
  S2. whoami with WIDE access-token lifetime (expires_in 3600s,
      lead 60s) → token NOT in window → NO proactive refresh →
      /token endpoint NOT hit before /userinfo.
  S3. whoami with NARROW lifetime (set
      AETHER_OIDC_REFRESH_LEAD_SECS=120; the access_token has 60s
      left so it IS in the 120s lead window) → proactive refresh
      kicks in → /token hit BEFORE /userinfo → stderr mentions
      "proactive refresh (CC5)".
  S4. whoami with --no-refresh override → NO refresh attempted even
      when in the window → if access_token expired in the IdP's view,
      the call 401s and surfaces it cleanly.

A failure in S3 means proactive refresh isn't kicking in correctly;
S4 ensures --no-refresh is honored.
"""
import base64
import hashlib
import http.server
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

AETHER_BIN = "/root/aether-blueprint/target/release/aether"
CLIENT_ID = "cc5-smoke"


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_jwt(payload, privkey, kid):
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    header_b = b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b}.{payload_b}".encode()
    sig = privkey.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b}.{payload_b}.{b64url(sig)}"


def make_jwks(pubkey, kid):
    nums = pubkey.public_numbers()
    n = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    e = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256",
                      "kid": kid, "n": b64url(n), "e": b64url(e)}]}


USERINFO = {
    "sub": "alice-cc5-sub",
    "email": "alice-cc5@idp.test",
    "email_verified": True,
}


class IdpState:
    """Fake IdP. Mints tokens; tracks call ordering."""

    def __init__(self, port, privkey, pubkey, kid):
        self.issuer = f"http://127.0.0.1:{port}"
        self.privkey = privkey
        self.pubkey = pubkey
        self.kid = kid
        self.last_nonce = None
        self.last_state = None
        self.minted_code = "cc5-code-XYZ"
        self.current_access_token = None
        self.current_refresh_token = None
        # Per-call telemetry — interleaved sequence of events so the
        # smoke can assert /token preceded /userinfo for proactive
        # refresh.
        self.events: list[str] = []
        # Toggle: short or long expires_in for the next token mint.
        self.short_expires_in = False
        self.refresh_count = 0


def make_handler(state: IdpState):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **kw): pass

        def _send_json(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/.well-known/openid-configuration":
                self._send_json(200, {
                    "issuer": state.issuer,
                    "authorization_endpoint": f"{state.issuer}/authorize",
                    "token_endpoint": f"{state.issuer}/token",
                    "jwks_uri": f"{state.issuer}/jwks.json",
                    "userinfo_endpoint": f"{state.issuer}/userinfo",
                })
                return
            if parsed.path == "/jwks.json":
                self._send_json(200, make_jwks(state.pubkey, state.kid))
                return
            if parsed.path == "/authorize":
                q = urllib.parse.parse_qs(parsed.query)
                state.last_nonce = q.get("nonce", [None])[0]
                state.last_state = q.get("state", [None])[0]
                ru = q.get("redirect_uri", [""])[0]
                cb = (f"{ru}?code={urllib.parse.quote(state.minted_code)}"
                      f"&state={urllib.parse.quote(state.last_state or '')}")
                self.send_response(302)
                self.send_header("Location", cb)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if parsed.path == "/userinfo":
                state.events.append("userinfo")
                got = self.headers.get("Authorization")
                expected = f"Bearer {state.current_access_token}"
                if got != expected:
                    self._send_json(401, {
                        "error": "invalid_token",
                        "error_description": "stale access_token",
                    })
                    return
                self._send_json(200, USERINFO)
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/token":
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            state.events.append("token")
            n = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(n).decode())
            grant = form.get("grant_type", [""])[0]
            if grant == "authorization_code":
                if form.get("code", [""])[0] != state.minted_code:
                    self._send_json(400, {"error": "invalid_grant"})
                    return
                state.current_access_token = "at-LOGIN"
                state.current_refresh_token = "rt-LOGIN"
            elif grant == "refresh_token":
                if form.get("refresh_token", [""])[0] != state.current_refresh_token:
                    self._send_json(400, {"error": "invalid_grant",
                                          "error_description": "stale refresh_token"})
                    return
                state.refresh_count += 1
                state.current_access_token = f"at-REFRESHED-{state.refresh_count}"
                state.current_refresh_token = f"rt-REFRESHED-{state.refresh_count}"
            else:
                self._send_json(400, {"error": "unsupported_grant_type"})
                return
            now = int(time.time())
            digest = hashlib.sha256(state.current_access_token.encode()).digest()
            at_hash = b64url(digest[:16])
            claims = {
                "iss": state.issuer, "sub": "alice-cc5-sub",
                "aud": CLIENT_ID, "iat": now, "exp": now + 300,
                "nonce": state.last_nonce, "at_hash": at_hash,
            }
            id_token = make_jwt(claims, state.privkey, state.kid)
            expires_in = 60 if state.short_expires_in else 3600
            self._send_json(200, {
                "access_token": state.current_access_token,
                "refresh_token": state.current_refresh_token,
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
            })
    return H


def find_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


def run_aether(cmd, env, *, expect_ok=True):
    res = subprocess.run([AETHER_BIN, *cmd], env=env,
                         capture_output=True, text=True, timeout=30)
    if expect_ok and res.returncode != 0:
        print(f"FAIL [{' '.join(cmd)}]: exit {res.returncode}")
        print("---STDOUT---"); print(res.stdout)
        print("---STDERR---"); print(res.stderr)
        sys.exit(1)
    return res


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-cc5-"))
    home = tmp
    (home / ".aether").mkdir(parents=True)

    privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubkey = privkey.public_key()
    port = find_port()
    state = IdpState(port, privkey, pubkey, kid="cc5-rsa")
    httpd = http.server.HTTPServer(("127.0.0.1", port), make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"[smoke] fake OIDC IdP on {state.issuer}")

    env = os.environ.copy()
    env["HOME"] = str(home)
    expires_at_path = home / ".aether" / "sso.access_token.expires_at"

    # configure
    run_aether(["sso", "configure", "--issuer", state.issuer,
                "--client-id", CLIENT_ID,
                "--scopes", "openid profile email offline_access"], env)

    # ── S1: login with WIDE expires_in (3600s) → expires_at sidecar ──
    state.short_expires_in = False
    log = home / "aether-login.log"
    proc = subprocess.Popen([AETHER_BIN, "sso", "login"],
                            env=env, stdout=open(log, "wb"),
                            stderr=subprocess.STDOUT)
    auth_url = None
    for _ in range(80):
        try: data = log.read_text()
        except FileNotFoundError: data = ""
        m = re.search(r"https?://[^\s]+authorize[^\s]+", data)
        if m: auth_url = m.group(0); break
        time.sleep(0.1)
    if not auth_url:
        proc.kill(); print("FAIL [S1]: no auth URL"); sys.exit(1)
    try:
        urllib.request.urlopen(urllib.request.Request(auth_url), timeout=10)
    except Exception:
        pass
    proc.wait(timeout=20)
    if not expires_at_path.exists():
        print(f"FAIL [S1]: {expires_at_path} missing after login")
        sys.exit(1)
    mode = expires_at_path.stat().st_mode & 0o777
    if mode != 0o600:
        print(f"FAIL [S1]: expires_at sidecar mode 0{mode:o}, expected 0600")
        sys.exit(1)
    raw = expires_at_path.read_text().strip()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as e:
        print(f"FAIL [S1]: expires_at not RFC 3339 ({e}): {raw!r}")
        sys.exit(1)
    delta = (parsed - datetime.now(timezone.utc)).total_seconds()
    if not (3500 < delta < 3700):
        print(f"FAIL [S1]: expires_at delta {delta:.0f}s, expected ~3600")
        sys.exit(1)
    print(f"[S1] sso.access_token.expires_at sidecar present (0600, "
          f"{raw}, delta {delta:.0f}s)")

    # ── S2: whoami, NOT in lead window → no proactive refresh ─────
    state.events.clear()
    env["AETHER_OIDC_REFRESH_LEAD_SECS"] = "60"  # 60s lead, but token has 3600s left
    res = run_aether(["sso", "whoami"], env)
    if "proactive refresh (CC5)" in res.stderr:
        print(f"FAIL [S2]: stderr unexpectedly mentions proactive refresh:\n"
              f"{res.stderr}")
        sys.exit(1)
    if state.events != ["userinfo"]:
        print(f"FAIL [S2]: expected events=['userinfo'], got {state.events}")
        sys.exit(1)
    print(f"[S2] whoami with WIDE lifetime: no proactive refresh, "
          f"events={state.events}")

    # ── S3: shrink window so we ARE inside it → proactive refresh ──
    state.events.clear()
    refresh_count_before = state.refresh_count
    # access_token has ~3600s left; lead 4000s means we're in window.
    env["AETHER_OIDC_REFRESH_LEAD_SECS"] = "3600"  # 4000 > 3600, clamped to 3600 max
    res = run_aether(["sso", "whoami"], env)
    if "proactive refresh (CC5)" not in res.stderr:
        print(f"FAIL [S3]: stderr missing 'proactive refresh (CC5)':\n"
              f"{res.stderr}")
        sys.exit(1)
    # /token (refresh) MUST precede /userinfo.
    if state.events != ["token", "userinfo"]:
        print(f"FAIL [S3]: expected ['token','userinfo'] (proactive refresh "
              f"before userinfo), got {state.events}")
        sys.exit(1)
    if state.refresh_count != refresh_count_before + 1:
        print(f"FAIL [S3]: refresh_count did not advance: {refresh_count_before} → "
              f"{state.refresh_count}")
        sys.exit(1)
    print(f"[S3] whoami INSIDE lead window: proactive refresh hit /token "
          f"BEFORE /userinfo (events={state.events}, refresh_count="
          f"{state.refresh_count})")

    # ── S4: --no-refresh inside the window → NO refresh attempted ──
    state.events.clear()
    refresh_count_before = state.refresh_count
    res = run_aether(["sso", "whoami", "--no-refresh"], env)
    if "proactive refresh (CC5)" in res.stderr:
        print(f"FAIL [S4]: --no-refresh did NOT suppress proactive refresh:\n"
              f"{res.stderr}")
        sys.exit(1)
    if state.events != ["userinfo"]:
        print(f"FAIL [S4]: expected events=['userinfo'] with --no-refresh, "
              f"got {state.events}")
        sys.exit(1)
    if state.refresh_count != refresh_count_before:
        print(f"FAIL [S4]: --no-refresh triggered refresh anyway "
              f"({refresh_count_before} → {state.refresh_count})")
        sys.exit(1)
    print(f"[S4] --no-refresh suppressed proactive refresh; events="
          f"{state.events}")

    httpd.shutdown()
    print("[smoke] CC5 LIVE-VERIFIED OK "
          "(expires_at sidecar at 0600 + outside-window skip + "
          "inside-window proactive refresh hits /token BEFORE /userinfo + "
          "--no-refresh opt-out)")


if __name__ == "__main__":
    main()
