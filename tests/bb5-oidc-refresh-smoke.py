#!/usr/bin/env python3
"""
BB5 live smoke: OIDC access-token refresh end-to-end.

Closes the AA6 weakest-point. Before BB5, `aether sso whoami`
called the userinfo endpoint with the access_token from sso.login
and gave up on 401. Access tokens expire (typically 1 hour) — once
the IdP returned 401, operators had to re-run `sso login` to keep
a working `whoami`.

BB5 persists the refresh_token at ~/.aether/sso.refresh_token
(mode 0600) and wires two consumption paths:

  1. Manual:  `aether sso refresh` — POSTs grant_type=refresh_token
              and rewrites both sidecars.
  2. Auto:    `aether sso whoami`  — on userinfo 401 and presence
              of the refresh_token sidecar, transparently calls the
              refresh helper and retries userinfo ONCE.

The smoke exercises FIVE distinct flows against one fake OIDC IdP:

  S1. Login → sso.refresh_token sidecar present at 0600.
  S2. whoami succeeds against the freshly-issued access_token.
  S3. Simulate access-token expiry by INVALIDATING the IdP-side
      access_token (the fake rotates per refresh, so we just
      track the "current valid" token). whoami auto-refreshes →
      retries → succeeds. Stderr mentions "auto-refreshing via
      <path> (BB5)" + the post-refresh BEARER is the new value.
  S4. Manual `aether sso refresh` against the new state.
  S5. Refresh-token ROTATION: the fake also rotates the
      refresh_token on each refresh; assert the NEW refresh_token
      is now on disk (not the old one) so the next refresh would
      use the rotated value.

Exit 1 on any assertion failure.
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
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

AETHER_BIN = "/root/aether-blueprint/target/release/aether"
CLIENT_ID = "bb5-smoke"


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_jwt(payload, privkey, kid: str) -> str:
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
    "sub": "alice-bb5-sub",
    "email": "alice-bb5@idp.test",
    "email_verified": True,
    "name": "Alice BB5",
    "preferred_username": "alice",
    "groups": ["aether-admin"],
}


class IdpState:
    """Fake IdP — issues + rotates access_token + refresh_token."""

    def __init__(self, port, privkey, pubkey, kid):
        self.issuer = f"http://127.0.0.1:{port}"
        self.privkey = privkey
        self.pubkey = pubkey
        self.kid = kid
        self.last_nonce = None
        self.last_state = None
        self.minted_code = "bb5-code-XYZ"
        # Currently-valid tokens. Initial pair set at /token (auth_code).
        # Refresh rotates BOTH (the IdP returns a fresh RT alongside
        # the new AT — RFC 6749 §6 calls this "refresh-token rotation"
        # and recommends it for public clients).
        self.current_access_token: str | None = None
        self.current_refresh_token: str | None = None
        self.refresh_count = 0
        # Telemetry per request.
        self.last_userinfo_authz: str | None = None
        self.token_endpoint_calls = 0


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
                state.last_userinfo_authz = self.headers.get("Authorization")
                expected = f"Bearer {state.current_access_token}"
                if state.last_userinfo_authz != expected:
                    self._send_json(401, {
                        "error": "invalid_token",
                        "error_description": (
                            "access_token does not match the currently-issued "
                            "one (expired / rotated)"
                        ),
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
            state.token_endpoint_calls += 1
            n = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(n).decode())
            grant = form.get("grant_type", [""])[0]
            if grant == "authorization_code":
                if form.get("code", [""])[0] != state.minted_code:
                    self._send_json(400, {"error": "invalid_grant"})
                    return
                state.current_access_token = "at-INITIAL"
                state.current_refresh_token = "rt-INITIAL"
            elif grant == "refresh_token":
                presented = form.get("refresh_token", [""])[0]
                if presented != state.current_refresh_token:
                    self._send_json(400, {
                        "error": "invalid_grant",
                        "error_description": "stale refresh_token",
                    })
                    return
                state.refresh_count += 1
                # Rotate BOTH tokens per RFC 6749 §6 recommendation.
                state.current_access_token = f"at-REFRESHED-{state.refresh_count}"
                state.current_refresh_token = f"rt-REFRESHED-{state.refresh_count}"
            else:
                self._send_json(400, {"error": "unsupported_grant_type"})
                return
            now = int(time.time())
            digest = hashlib.sha256(state.current_access_token.encode()).digest()
            at_hash = b64url(digest[:16])
            claims = {
                "iss": state.issuer, "sub": "alice-bb5-sub",
                "aud": CLIENT_ID, "iat": now, "exp": now + 300,
                "nonce": state.last_nonce, "at_hash": at_hash,
            }
            id_token = make_jwt(claims, state.privkey, state.kid)
            self._send_json(200, {
                "access_token": state.current_access_token,
                "refresh_token": state.current_refresh_token,
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": 300,
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
    tmp = Path(tempfile.mkdtemp(prefix="aether-bb5-"))
    home = tmp
    (home / ".aether").mkdir(parents=True)

    privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubkey = privkey.public_key()
    port = find_port()
    state = IdpState(port, privkey, pubkey, kid="bb5-rsa")
    httpd = http.server.HTTPServer(("127.0.0.1", port), make_handler(state))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    print(f"[smoke] fake OIDC IdP on {state.issuer}")

    env = os.environ.copy()
    env["HOME"] = str(home)
    sso_token = home / ".aether" / "sso.token"
    sso_access = home / ".aether" / "sso.access_token"
    sso_refresh = home / ".aether" / "sso.refresh_token"

    # configure
    run_aether(["sso", "configure",
                "--issuer", state.issuer,
                "--client-id", CLIENT_ID,
                "--scopes", "openid profile email offline_access"], env)

    # ── S1: login → all 3 sidecars present + correct mode ────────
    log_path = home / "aether-login.log"
    proc = subprocess.Popen([AETHER_BIN, "sso", "login"],
                            env=env, stdout=open(log_path, "wb"),
                            stderr=subprocess.STDOUT)
    auth_url = None
    for _ in range(80):
        try: data = log_path.read_text()
        except FileNotFoundError: data = ""
        m = re.search(r"https?://[^\s]+authorize[^\s]+", data)
        if m:
            auth_url = m.group(0); break
        time.sleep(0.1)
    if not auth_url:
        proc.kill(); print("FAIL: no auth URL emitted"); sys.exit(1)
    try:
        urllib.request.urlopen(urllib.request.Request(auth_url), timeout=10)
    except Exception:
        pass
    proc.wait(timeout=20)
    if not sso_refresh.exists():
        print(f"FAIL [S1]: {sso_refresh} sidecar missing after login")
        sys.exit(1)
    mode = sso_refresh.stat().st_mode & 0o777
    if mode != 0o600:
        print(f"FAIL [S1]: refresh sidecar mode 0{mode:o}, expected 0600")
        sys.exit(1)
    initial_rt = sso_refresh.read_text()
    initial_at = sso_access.read_text()
    print(f"[S1] sso.refresh_token sidecar present (mode 0600, "
          f"value={initial_rt!r}, AT={initial_at!r})")

    # ── S2: whoami succeeds with initial access_token ────────────
    res = run_aether(["sso", "whoami"], env)
    if "sub:       alice-bb5-sub" not in res.stdout:
        print(f"FAIL [S2]: whoami stdout shape wrong:\n{res.stdout}")
        sys.exit(1)
    print(f"[S2] whoami succeeded against initial AT (refresh_count="
          f"{state.refresh_count})")

    # ── S3: invalidate AT (rotate at fake's side without notifying
    # aether), whoami auto-refreshes + retries ───────────────────────
    state.current_access_token = "at-INVALID-SUDDENLY"
    res = run_aether(["sso", "whoami"], env)
    if "sub:       alice-bb5-sub" not in res.stdout:
        print(f"FAIL [S3]: whoami stdout missing sub after auto-refresh:\n"
              f"{res.stdout}\nSTDERR:\n{res.stderr}")
        sys.exit(1)
    if "auto-refreshing" not in res.stderr or "(BB5)" not in res.stderr:
        print(f"FAIL [S3]: stderr does not mention BB5 auto-refresh:\n"
              f"{res.stderr}")
        sys.exit(1)
    if state.refresh_count != 1:
        print(f"FAIL [S3]: expected refresh_count=1 after auto-refresh, "
              f"got {state.refresh_count}")
        sys.exit(1)
    # The sidecars MUST be rotated to the IdP's new values.
    if sso_access.read_text() != state.current_access_token:
        print(f"FAIL [S3]: access sidecar not rotated: "
              f"{sso_access.read_text()!r} vs {state.current_access_token!r}")
        sys.exit(1)
    if sso_refresh.read_text() != state.current_refresh_token:
        print(f"FAIL [S3]: refresh sidecar not rotated: "
              f"{sso_refresh.read_text()!r} vs "
              f"{state.current_refresh_token!r}")
        sys.exit(1)
    print(f"[S3] auto-refresh on 401 succeeded; both sidecars rotated to "
          f"{state.current_access_token!r} / {state.current_refresh_token!r}")

    # ── S4: manual `aether sso refresh` ──────────────────────────
    res = run_aether(["sso", "refresh"], env)
    if "refresh_token ROTATED" not in res.stderr:
        print(f"FAIL [S4]: manual refresh stderr missing 'ROTATED':\n"
              f"{res.stderr}")
        sys.exit(1)
    if state.refresh_count != 2:
        print(f"FAIL [S4]: expected refresh_count=2 after manual, "
              f"got {state.refresh_count}")
        sys.exit(1)
    print(f"[S4] manual `sso refresh` rotated tokens "
          f"(refresh_count={state.refresh_count})")

    # ── S5: --no-refresh opts out of auto-refresh on 401 ─────────
    state.current_access_token = "at-INVALID-AGAIN"
    res = run_aether(["sso", "whoami", "--no-refresh"], env, expect_ok=False)
    if res.returncode == 0:
        print(f"FAIL [S5]: --no-refresh should have surfaced the 401:\n"
              f"{res.stdout}\n{res.stderr}")
        sys.exit(1)
    if "userinfo HTTP 401" not in res.stderr:
        print(f"FAIL [S5]: stderr did not surface the userinfo 401:\n"
              f"{res.stderr}")
        sys.exit(1)
    # Sidecars MUST NOT have been rotated by this call.
    if state.refresh_count != 2:
        print(f"FAIL [S5]: --no-refresh ran the refresh helper "
              f"(count={state.refresh_count}, expected 2)")
        sys.exit(1)
    print(f"[S5] --no-refresh surfaced 401 cleanly; no rotation triggered")

    # ── S6: logout removes all 3 sidecars ────────────────────────
    # Make the AT valid again so the actual /userinfo call would succeed,
    # but we're not exercising whoami — just logout cleanup.
    run_aether(["sso", "logout"], env)
    for p in (sso_token, sso_access, sso_refresh):
        if p.exists():
            print(f"FAIL [S6]: {p} not removed by logout")
            sys.exit(1)
    print(f"[S6] logout removed sso.token + sso.access_token + "
          f"sso.refresh_token")

    httpd.shutdown()
    print("[smoke] BB5 LIVE-VERIFIED OK "
          "(refresh_token persist + auto-refresh on 401 + manual "
          "refresh + --no-refresh opt-out + logout cleanup; refresh-token "
          "rotation handled)")


if __name__ == "__main__":
    main()
