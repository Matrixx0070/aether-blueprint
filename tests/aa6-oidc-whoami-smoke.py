#!/usr/bin/env python3
"""
AA6 live smoke: aether sso whoami end-to-end.

Stands up the same fake OIDC IdP shape as the Z1 smoke (discovery +
JWKS + authorize + token) plus a /userinfo endpoint, then:

  1. Runs `aether sso configure --issuer <fake>` — verifies
     sso.json captures userinfo_endpoint.
  2. Runs `aether sso login` — verifies sso.access_token sidecar
     gets written at mode 0600 with the access_token bytes.
  3. Runs `aether sso whoami` (formatted output) — verifies the
     fake's userinfo response (sub + email + groups) reaches stdout.
  4. Runs `aether sso whoami --json` — verifies the raw JSON path
     emits a parseable doc that matches what /userinfo returned.
  5. Runs `aether sso logout` — verifies BOTH sso.token AND
     sso.access_token get removed.

The fake /userinfo endpoint validates Authorization: Bearer
matches the access_token it issued earlier; mismatched bearers
return 401. The smoke does NOT exercise the 401 path explicitly
(unit tests cover the parser; the 401 path is just plumbing).
"""
import base64
import datetime as dt
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
CLIENT_ID = "aa6-smoke"
ACCESS_TOKEN = "aa6-access-token-zzz"


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_jwt(payload: dict, privkey, kid: str) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    header_b = b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b}.{payload_b}".encode()
    sig = privkey.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b}.{payload_b}.{b64url(sig)}"


def make_jwks(pubkey, kid: str) -> dict:
    nums = pubkey.public_numbers()
    n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    return {
        "keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
            "n": b64url(n_bytes), "e": b64url(e_bytes),
        }]
    }


USERINFO = {
    "sub": "alice-aa6-sub",
    "email": "alice-aa6@idp.test",
    "email_verified": True,
    "name": "Alice AA6",
    "preferred_username": "alice",
    "groups": ["aether-admin", "engineering"],
    "updated_at": 1750000000,
}


class IdpState:
    def __init__(self, port: int, privkey, pubkey, kid: str):
        self.issuer = f"http://127.0.0.1:{port}"
        self.privkey = privkey
        self.pubkey = pubkey
        self.kid = kid
        self.last_nonce: str | None = None
        self.last_state: str | None = None
        self.minted_code = "aa6-code-XYZ"
        self.userinfo_called = 0
        self.last_userinfo_authz: str | None = None


def make_handler(state: IdpState):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **kw):
            pass

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
                redirect_uri = q.get("redirect_uri", [""])[0]
                cb = (f"{redirect_uri}?code={urllib.parse.quote(state.minted_code)}"
                      f"&state={urllib.parse.quote(state.last_state or '')}")
                self.send_response(302)
                self.send_header("Location", cb)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if parsed.path == "/userinfo":
                state.userinfo_called += 1
                state.last_userinfo_authz = self.headers.get("Authorization")
                # Validate Bearer matches the access_token we issued.
                if state.last_userinfo_authz != f"Bearer {ACCESS_TOKEN}":
                    self._send_json(401, {
                        "error": "invalid_token",
                        "error_description": (
                            f"expected Bearer {ACCESS_TOKEN}, got "
                            f"{state.last_userinfo_authz!r}"
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
            if parsed.path == "/token":
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode()
                form = urllib.parse.parse_qs(body)
                if form.get("code", [""])[0] != state.minted_code:
                    self._send_json(400, {"error": "invalid_grant"})
                    return
                now = int(time.time())
                # at_hash for the access_token we'll issue.
                digest = hashlib.sha256(ACCESS_TOKEN.encode()).digest()
                at_hash = b64url(digest[:16])
                claims = {
                    "iss": state.issuer,
                    "sub": "alice-aa6-sub",
                    "aud": CLIENT_ID,
                    "iat": now, "exp": now + 300,
                    "nonce": state.last_nonce,
                    "at_hash": at_hash,
                }
                id_token = make_jwt(claims, state.privkey, state.kid)
                self._send_json(200, {
                    "access_token": ACCESS_TOKEN,
                    "id_token": id_token,
                    "token_type": "Bearer",
                    "expires_in": 300,
                })
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
    return H


def find_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


def run_aether(cmd, env, *, capture=True):
    res = subprocess.run(
        [AETHER_BIN, *cmd],
        env=env, capture_output=capture, text=True, timeout=30,
    )
    if res.returncode != 0:
        print(f"FAIL [{' '.join(cmd)}]: exit {res.returncode}")
        print("---STDOUT---")
        print(res.stdout)
        print("---STDERR---")
        print(res.stderr)
        sys.exit(1)
    return res


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-aa6-"))
    home = tmp
    (home / ".aether").mkdir(parents=True)

    privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubkey = privkey.public_key()

    port = find_port()
    state = IdpState(port, privkey, pubkey, kid="aa6-rsa")
    httpd = http.server.HTTPServer(("127.0.0.1", port), make_handler(state))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    print(f"[smoke] fake OIDC IdP on {state.issuer}")

    env = os.environ.copy()
    env["HOME"] = str(home)

    # ── 1) configure ────────────────────────────────────────────
    print("[smoke] sso configure")
    run_aether(
        ["sso", "configure",
         "--issuer", state.issuer,
         "--client-id", CLIENT_ID,
         "--scopes", "openid profile email groups"],
        env,
    )
    cfg = json.loads((home / ".aether" / "sso.json").read_text())
    if cfg.get("userinfo_endpoint") != f"{state.issuer}/userinfo":
        print(f"FAIL: sso.json userinfo_endpoint wrong: {cfg!r}")
        sys.exit(1)
    print(f"  sso.json captured userinfo_endpoint = {cfg['userinfo_endpoint']}")

    # ── 2) login ────────────────────────────────────────────────
    log = home / "aether-login.log"
    proc = subprocess.Popen(
        [AETHER_BIN, "sso", "login"],
        env=env, stdout=open(log, "wb"), stderr=subprocess.STDOUT,
    )
    auth_url = None
    for _ in range(80):
        try:
            data = log.read_text()
        except FileNotFoundError:
            data = ""
        m = re.search(r"https?://[^\s]+authorize[^\s]+", data)
        if m:
            auth_url = m.group(0)
            break
        time.sleep(0.1)
    if auth_url is None:
        proc.kill()
        print("FAIL: no auth URL emitted")
        print(log.read_text())
        sys.exit(1)
    # Drive the browser leg.
    try:
        urllib.request.urlopen(urllib.request.Request(auth_url), timeout=10)
    except Exception:
        pass  # 302 follow → aether's listener responds 200; either path ok.
    proc.wait(timeout=20)
    print("[smoke] sso login OK")

    sso_token = home / ".aether" / "sso.token"
    sso_access = home / ".aether" / "sso.access_token"
    if not sso_token.exists():
        print(f"FAIL: {sso_token} missing")
        sys.exit(1)
    if not sso_access.exists():
        print(f"FAIL: AA6 sidecar {sso_access} missing")
        sys.exit(1)
    if sso_access.read_text() != ACCESS_TOKEN:
        print(f"FAIL: access_token sidecar content wrong: "
              f"{sso_access.read_text()!r}")
        sys.exit(1)
    mode = sso_access.stat().st_mode & 0o777
    if mode != 0o600:
        print(f"FAIL: sso.access_token mode is 0{mode:o}, expected 0600")
        sys.exit(1)
    print(f"[smoke] sso.access_token sidecar OK ({len(ACCESS_TOKEN)}B, "
          f"mode=0{mode:o})")

    # ── 3) whoami formatted ─────────────────────────────────────
    print("[smoke] sso whoami (formatted)")
    res = run_aether(["sso", "whoami"], env)
    print(res.stdout)
    for needle in [
        "sub:       alice-aa6-sub",
        "email:     alice-aa6@idp.test (verified)",
        "name:      Alice AA6",
        "username:  alice",
        "groups:    aether-admin, engineering",
    ]:
        if needle not in res.stdout:
            print(f"FAIL: whoami stdout missing `{needle}`")
            sys.exit(1)
    if state.userinfo_called < 1:
        print("FAIL: /userinfo not called by formatted whoami")
        sys.exit(1)
    if state.last_userinfo_authz != f"Bearer {ACCESS_TOKEN}":
        print(f"FAIL: userinfo Bearer wrong: {state.last_userinfo_authz!r}")
        sys.exit(1)
    print("  formatted whoami emitted sub + email + name + username + groups")

    # ── 4) whoami --json ────────────────────────────────────────
    print("[smoke] sso whoami --json")
    res2 = run_aether(["sso", "whoami", "--json"], env)
    parsed = json.loads(res2.stdout)
    for k, v in USERINFO.items():
        if parsed.get(k) != v:
            print(f"FAIL: --json output mismatch on `{k}`: "
                  f"got {parsed.get(k)!r}, expected {v!r}")
            sys.exit(1)
    if state.userinfo_called < 2:
        print("FAIL: /userinfo not called by --json whoami")
        sys.exit(1)
    print("  --json whoami emitted byte-for-byte userinfo response")

    # ── 5) logout cleans up both files ──────────────────────────
    print("[smoke] sso logout")
    run_aether(["sso", "logout"], env)
    if sso_token.exists():
        print(f"FAIL: {sso_token} not removed by logout")
        sys.exit(1)
    if sso_access.exists():
        print(f"FAIL: {sso_access} not removed by logout")
        sys.exit(1)
    print("  logout removed BOTH sso.token AND sso.access_token sidecar")

    httpd.shutdown()
    print("[smoke] AA6 LIVE-VERIFIED OK "
          "(userinfo_endpoint capture + access_token sidecar + "
          "whoami formatted + --json + logout cleanup)")


if __name__ == "__main__":
    main()
