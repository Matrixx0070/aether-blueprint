#!/usr/bin/env python3
"""
Z1' live smoke: stand up a fake OIDC IdP (discovery + authorize +
token + jwks), point `aether sso` at it, and verify the full
PKCE-with-nonce round-trip persists a valid id_token to
~/.aether/sso.token at mode 0600.

The fake IdP:
  1. /.well-known/openid-configuration  → discovery doc
  2. /jwks.json                         → RS256 public key
  3. /authorize?...                     → 302 back to redirect_uri
                                          with code + state echoed
  4. /token (POST, form-encoded)        → returns signed id_token
                                          containing the nonce we
                                          received in /authorize

The test fails if:
  - aether's auth URL omits a `nonce` parameter
  - aether persists a token whose nonce does NOT match the one we
    minted
  - sso.token is not 0600
"""
import base64
import datetime as dt
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
CLIENT_ID = "z1-smoke"


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
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": b64url(n_bytes),
                "e": b64url(e_bytes),
            }
        ]
    }


class IdpState:
    def __init__(self, port: int, privkey, pubkey, kid: str):
        self.issuer = f"http://127.0.0.1:{port}"
        self.privkey = privkey
        self.pubkey = pubkey
        self.kid = kid
        self.last_nonce: str | None = None
        self.last_state: str | None = None
        self.minted_code = "smoke-code-XYZ"
        self.smoke_authn_redirect: str | None = None
        self.smoke_observed_nonce_param = False
        self.smoke_token_request_count = 0


def make_handler(state: IdpState):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **kw):
            pass

        def _send_json(self, code: int, obj):
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
                })
                return
            if parsed.path == "/jwks.json":
                self._send_json(200, make_jwks(state.pubkey, state.kid))
                return
            if parsed.path == "/authorize":
                q = urllib.parse.parse_qs(parsed.query)
                if "nonce" in q:
                    state.smoke_observed_nonce_param = True
                state.last_nonce = q.get("nonce", [None])[0]
                state.last_state = q.get("state", [None])[0]
                redirect_uri = q.get("redirect_uri", [""])[0]
                cb = (
                    f"{redirect_uri}?code={urllib.parse.quote(state.minted_code)}"
                    f"&state={urllib.parse.quote(state.last_state or '')}"
                )
                state.smoke_authn_redirect = cb
                self.send_response(302)
                self.send_header("Location", cb)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/token":
                state.smoke_token_request_count += 1
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode()
                form = urllib.parse.parse_qs(body)
                if form.get("code", [""])[0] != state.minted_code:
                    self._send_json(400, {"error": "invalid_grant"})
                    return
                now = int(time.time())
                claims = {
                    "iss": state.issuer,
                    "sub": "alice-z1@idp.test",
                    "aud": CLIENT_ID,
                    "iat": now,
                    "exp": now + 300,
                    "nonce": state.last_nonce,
                }
                id_token = make_jwt(claims, state.privkey, state.kid)
                self._send_json(200, {
                    "access_token": "smoke-access",
                    "id_token": id_token,
                    "token_type": "Bearer",
                    "expires_in": 300,
                })
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
    return H


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-z1-"))
    home = tmp
    (home / ".aether").mkdir(parents=True)

    privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubkey = privkey.public_key()

    idp_sock = socket.socket()
    idp_sock.bind(("127.0.0.1", 0))
    idp_port = idp_sock.getsockname()[1]
    idp_sock.close()
    state = IdpState(idp_port, privkey, pubkey, kid="z1-rsa")
    httpd = http.server.HTTPServer(("127.0.0.1", idp_port), make_handler(state))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    print(f"[smoke] fake IdP listening on {state.issuer}")

    env = os.environ.copy()
    env["HOME"] = str(home)

    # Configure aether against the fake IdP.
    cfg = subprocess.run(
        [AETHER_BIN, "sso", "configure",
         "--issuer", state.issuer,
         "--client-id", CLIENT_ID,
         "--scopes", "openid profile email"],
        env=env, capture_output=True, text=True, timeout=20,
    )
    if cfg.returncode != 0:
        print("FAIL: configure exit", cfg.returncode)
        print(cfg.stdout)
        print(cfg.stderr)
        sys.exit(1)
    print("[smoke] sso configure OK")

    # Run sso login. It will print the auth URL — we need to drive
    # the browser callback ourselves by hitting /authorize, which
    # 302s back to aether's listener.
    log = home / "aether.log"
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
    print(f"[smoke] aether auth URL: {auth_url[:100]}…")

    # Drive the browser leg: GET /authorize (fake IdP 302s to
    # aether's redirect_uri with code + state).
    req = urllib.request.Request(auth_url)
    try:
        urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as e:
        if e.code == 302:
            pass
        else:
            print(f"FAIL: /authorize returned HTTP {e.code}")
            sys.exit(1)
    except Exception as e:
        # The Python opener follows the 302 → hits aether's
        # listener → aether responds 200 OK. That's the goal.
        if "200" not in str(e):
            print(f"[smoke] /authorize follow returned: {e!r}")

    proc.wait(timeout=20)
    print("--- aether log ---")
    print(log.read_text())

    if not state.smoke_observed_nonce_param:
        print("FAIL: aether's /authorize URL did NOT carry a `nonce` parameter")
        sys.exit(1)
    if state.smoke_token_request_count != 1:
        print(f"FAIL: expected 1 /token call, got {state.smoke_token_request_count}")
        sys.exit(1)

    sso_token = home / ".aether" / "sso.token"
    if not sso_token.exists():
        print("FAIL: ~/.aether/sso.token was NOT written")
        sys.exit(1)
    text = sso_token.read_text()
    parts = text.split(".")
    if len(parts) != 3:
        print(f"FAIL: token has {len(parts)} parts, expected 3 (JWT)")
        sys.exit(1)
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==="))
    if payload.get("nonce") != state.last_nonce:
        print(
            "FAIL: persisted token nonce != last issued nonce "
            f"(sent={state.last_nonce}, in_token={payload.get('nonce')})"
        )
        sys.exit(1)
    print(f"[smoke] token nonce binding verified: {payload['nonce']}")

    mode = sso_token.stat().st_mode & 0o777
    if mode != 0o600:
        print(f"FAIL: sso.token mode is 0{mode:o}, expected 0600")
        sys.exit(1)
    print(f"[smoke] sso.token mode = 0{mode:o} (expected 0600)")

    httpd.shutdown()
    print("[smoke] Z1' LIVE-VERIFIED OK")


if __name__ == "__main__":
    main()
