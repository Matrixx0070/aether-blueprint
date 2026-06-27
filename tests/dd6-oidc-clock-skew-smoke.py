#!/usr/bin/env python3
"""
DD6 live smoke: OIDC system-clock-skew detection.

Closes the CC5 weakest-point. CC5 trusts the local clock for the
expires_at math — a system with broken NTP (container time skew,
unsynced VM, manually fudged clock) would either refresh too
aggressively or miss the lead window entirely. DD6 surfaces the
condition explicitly.

After every successful POST to /token, aether reads the HTTP
`Date:` header, computes `local_now - server_date`, and persists
the signed seconds to ~/.aether/sso.clock_skew_secs. On every
`aether sso whoami` invocation, the sidecar is read and a WARN is
logged when |skew| > AETHER_OIDC_CLOCK_SKEW_WARN_SECS (default 60s,
clamped [10, 3600]). The warn is advisory — whoami doesn't refuse.

Smoke flow (one fake OIDC IdP that fakes its `Date:` response
header per the requested offset):

  S1. server_date = local_now (skew ≈ 0):
        - login → sso.clock_skew_secs sidecar present at 0600 with
          a magnitude under the default threshold (10s tolerance
          for fork+exec latency).
        - whoami → no clock-skew WARN line.
  S2. server_date = local_now - 120s (server in the past = local
      ahead by ~120s):
        - login → sidecar contains a positive value ≈ +120s.
        - whoami → WARN line cites the skew + the threshold.
  S3. server_date = local_now + 90s (server in the future = local
      behind by ~90s):
        - manual `sso refresh` → sidecar rewritten with negative
          value ≈ -90s.
        - whoami → WARN line.
  S4. Custom AETHER_OIDC_CLOCK_SKEW_WARN_SECS=10 with S3's ~90s
      skew → WARN line cites "threshold 10s" (env knob honored).
  S5. logout removes sso.clock_skew_secs alongside the existing
      three sidecars.

Exit 1 on any assertion failure.
"""
import base64
import datetime as dt
import email.utils
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
CLIENT_ID = "dd6-smoke"


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
    "sub": "alice-dd6-sub",
    "email": "alice-dd6@idp.test",
    "email_verified": True,
}


class IdpState:
    def __init__(self, port, privkey, pubkey, kid):
        self.issuer = f"http://127.0.0.1:{port}"
        self.privkey = privkey
        self.pubkey = pubkey
        self.kid = kid
        self.last_nonce = None
        self.last_state = None
        self.minted_code = "dd6-code-XYZ"
        self.current_access_token = None
        self.current_refresh_token = None
        # DD6: signed seconds added to the local clock when forging
        # the /token response Date header. Positive = server-in-future
        # = local-behind-server.
        self.fake_date_offset_secs = 0


def make_handler(state: IdpState):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **kw): pass

        def date_time_string(self, timestamp=None):
            """Override Python's auto-Date header so /token can lie.

            BaseHTTPRequestHandler.send_response unconditionally calls
            self.date_time_string() and emits the result as the `Date:`
            header. Without this override, the canonical-time Date the
            framework injects would always shadow any later
            send_header("Date", ...) call (reqwest reads the FIRST
            Date header in the response). We instead bias the
            framework's own emission by the configured offset so the
            offset is consistently respected on every response.
            """
            target_secs = time.time() + state.fake_date_offset_secs
            return email.utils.formatdate(target_secs, usegmt=True)

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
                # Auth check skipped — DD6 isn't testing userinfo,
                # just the skew sidecar lifecycle around it.
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
                if form.get("refresh_token", [""])[0] \
                        != state.current_refresh_token:
                    self._send_json(400, {"error": "invalid_grant"})
                    return
                state.current_access_token = "at-REFRESHED"
                state.current_refresh_token = "rt-REFRESHED"
            else:
                self._send_json(400, {"error": "unsupported_grant_type"})
                return
            now = int(time.time())
            digest = hashlib.sha256(state.current_access_token.encode()).digest()
            at_hash = b64url(digest[:16])
            claims = {
                "iss": state.issuer, "sub": "alice-dd6-sub",
                "aud": CLIENT_ID, "iat": now, "exp": now + 300,
                "nonce": state.last_nonce, "at_hash": at_hash,
            }
            id_token = make_jwt(claims, state.privkey, state.kid)
            # DD6: framework's auto-Date header (overridden above)
            # carries the configured offset on EVERY response.
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


def run_aether(cmd, env, *, ok=True):
    res = subprocess.run([AETHER_BIN, *cmd], env=env,
                         capture_output=True, text=True, timeout=30)
    if ok and res.returncode != 0:
        print(f"FAIL [{' '.join(cmd)}]: exit {res.returncode}")
        print("STDOUT:", res.stdout); print("STDERR:", res.stderr)
        sys.exit(1)
    return res


def run_login(env, home):
    """Drive a fresh PKCE round-trip through aether sso login."""
    log = home / f"aether-login-{time.time_ns()}.log"
    proc = subprocess.Popen([AETHER_BIN, "sso", "login"],
                            env=env, stdout=open(log, "wb"),
                            stderr=subprocess.STDOUT)
    auth_url = None
    for _ in range(80):
        try: data = log.read_text()
        except FileNotFoundError: data = ""
        m = re.search(r"https?://[^\s]+authorize[^\s]+", data)
        if m:
            auth_url = m.group(0); break
        time.sleep(0.1)
    if not auth_url:
        proc.kill(); print("FAIL: no auth URL"); sys.exit(1)
    try:
        urllib.request.urlopen(urllib.request.Request(auth_url), timeout=10)
    except Exception:
        pass
    proc.wait(timeout=20)
    return log


def read_skew(home):
    p = home / ".aether" / "sso.clock_skew_secs"
    if not p.exists():
        return None
    return int(p.read_text().strip()), p


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-dd6-"))
    home = tmp
    (home / ".aether").mkdir(parents=True)

    privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pubkey = privkey.public_key()
    port = find_port()
    state = IdpState(port, privkey, pubkey, kid="dd6-rsa")
    httpd = http.server.HTTPServer(("127.0.0.1", port), make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"[smoke] fake OIDC IdP on {state.issuer}")

    env = os.environ.copy()
    env["HOME"] = str(home)

    run_aether(["sso", "configure", "--issuer", state.issuer,
                "--client-id", CLIENT_ID,
                "--scopes", "openid profile email offline_access"], env)

    # ── S1: in-sync clocks → small skew + no WARN ────────────────
    state.fake_date_offset_secs = 0
    run_login(env, home)
    rec = read_skew(home)
    if rec is None:
        print("FAIL [S1]: sso.clock_skew_secs sidecar missing"); sys.exit(1)
    skew_s1, skew_path = rec
    mode = skew_path.stat().st_mode & 0o777
    if mode != 0o600:
        print(f"FAIL [S1]: skew sidecar mode 0{mode:o}, expected 0600")
        sys.exit(1)
    if abs(skew_s1) > 10:
        print(f"FAIL [S1]: in-sync skew {skew_s1}s exceeds 10s tolerance")
        sys.exit(1)
    res = run_aether(["sso", "whoami"], env)
    if "clock skew" in res.stderr.lower():
        print(f"FAIL [S1]: unexpected clock-skew WARN with skew={skew_s1}s:\n"
              f"{res.stderr}")
        sys.exit(1)
    print(f"[S1] in-sync (skew={skew_s1}s) — sidecar at 0600, no WARN")

    # ── S2: server in PAST → local AHEAD by 120s → WARN ──────────
    state.fake_date_offset_secs = -120
    run_login(env, home)
    skew_s2, _ = read_skew(home)
    if not (110 <= skew_s2 <= 130):
        print(f"FAIL [S2]: expected skew ≈ +120s, got {skew_s2}s")
        sys.exit(1)
    res = run_aether(["sso", "whoami"], env)
    if "WARN: local-vs-IdP clock skew" not in res.stderr:
        print(f"FAIL [S2]: missing clock-skew WARN with skew={skew_s2}s:\n"
              f"{res.stderr}")
        sys.exit(1)
    if "threshold 60s" not in res.stderr:
        print(f"FAIL [S2]: WARN missing 'threshold 60s' (default):\n{res.stderr}")
        sys.exit(1)
    print(f"[S2] server-in-past (local ahead, skew={skew_s2}s) — WARN cites "
          f"threshold 60s")

    # ── S3: manual `sso refresh` with server in FUTURE → -90s ────
    state.fake_date_offset_secs = +90
    res = run_aether(["sso", "refresh"], env)
    if "new access_token" not in res.stderr:
        print(f"FAIL [S3]: manual refresh did not log new access_token:\n"
              f"{res.stderr}")
        sys.exit(1)
    skew_s3, _ = read_skew(home)
    if not (-100 <= skew_s3 <= -80):
        print(f"FAIL [S3]: expected skew ≈ -90s after refresh, got {skew_s3}s")
        sys.exit(1)
    res = run_aether(["sso", "whoami"], env)
    if "WARN: local-vs-IdP clock skew" not in res.stderr:
        print(f"FAIL [S3]: missing clock-skew WARN with skew={skew_s3}s:\n"
              f"{res.stderr}")
        sys.exit(1)
    print(f"[S3] manual refresh, server-in-future (local behind, skew={skew_s3}s) "
          f"— WARN emitted")

    # ── S4: custom AETHER_OIDC_CLOCK_SKEW_WARN_SECS=10 → cite 10s ─
    env["AETHER_OIDC_CLOCK_SKEW_WARN_SECS"] = "10"
    res = run_aether(["sso", "whoami"], env)
    if "threshold 10s" not in res.stderr:
        print(f"FAIL [S4]: custom 10s threshold not respected:\n{res.stderr}")
        sys.exit(1)
    print(f"[S4] AETHER_OIDC_CLOCK_SKEW_WARN_SECS=10 honored in WARN line")
    del env["AETHER_OIDC_CLOCK_SKEW_WARN_SECS"]

    # ── S5: logout removes the skew sidecar ───────────────────────
    run_aether(["sso", "logout"], env)
    skew_path = home / ".aether" / "sso.clock_skew_secs"
    if skew_path.exists():
        print(f"FAIL [S5]: {skew_path} not removed by logout")
        sys.exit(1)
    print(f"[S5] logout cleaned up sso.clock_skew_secs alongside the other "
          f"three sidecars")

    httpd.shutdown()
    print("[smoke] DD6 LIVE-VERIFIED OK "
          "(in-sync no-warn + server-past WARN + server-future via manual "
          "refresh + custom env knob + logout cleanup)")


if __name__ == "__main__":
    main()
