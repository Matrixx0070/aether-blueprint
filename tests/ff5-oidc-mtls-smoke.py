#!/usr/bin/env python3
"""
FF5 live smoke: OIDC mTLS client authentication (RFC 8705) end-to-end.

Fake IdP topology:
  - Plain-HTTP server: discovery + /authorize + /jwks.json (as Z1).
  - HTTPS server for /token ONLY, with `verify_mode = CERT_OPTIONAL`
    against a client CA. The handler REJECTS POSTs that presented no
    client cert with HTTP 400 {"error": "invalid_client"}; when a
    cert IS presented, the issued id_token carries
    cnf.x5t#S256 = b64url(sha256(presented leaf DER)).

Chain (mirrors the Plan FF5 spec):
  1. sso configure against the fake discovery doc (token_endpoint is
     the HTTPS mTLS port).
  2. sso configure-mtls --cert --key (client pair minted here).
  3. sso login with AETHER_OIDC_REQUIRE_CNF_X5T_S256=1 → token POST
     carries the client cert → id_token cnf claim verifies in
     hard-require mode → sso.token at 0600.
  4. Direct POST to /token WITHOUT a client cert → HTTP 400
     invalid_client (server-side enforcement is real).
  5. sso refresh → refresh grant also presents the client cert.
  6. sso configure-mtls --remove → sso refresh fails with the token
     endpoint's 400 refusal (loud, not a silent fallback).
"""
import base64
import datetime as dt
import hashlib
import http.server
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

AETHER_BIN = "/root/aether-blueprint/target/release/aether"
CLIENT_ID = "ff5-smoke"


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
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256",
                      "kid": kid, "n": b64url(n_bytes), "e": b64url(e_bytes)}]}


def make_cert(cn: str, key, *, ca: bool, san_ip: str | None = None,
              issuer_cert=None, issuer_key=None):
    """Self-signed CA (ca=True, no issuer) or leaf signed by issuer.

    rustls rejects a CA cert doing double duty as an end-entity cert
    (CaUsedAsEndEntity), so the fake IdP's server cert must be a
    CA:FALSE leaf chained to a separate CA that aether trusts via
    AETHER_OIDC_EXTRA_ROOT_CA_PEM.
    """
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = issuer_cert.subject if issuer_cert is not None else subject
    sign_key = issuer_key if issuer_key is not None else key
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if san_ip:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(san_ip))]),
            critical=False,
        )
    return builder.sign(sign_key, hashes.SHA256())


def pem_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def pem_cert(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class IdpState:
    def __init__(self, http_port: int, tls_port: int, privkey, pubkey, kid: str):
        self.issuer = f"http://127.0.0.1:{http_port}"
        self.token_endpoint = f"https://127.0.0.1:{tls_port}/token"
        self.privkey = privkey
        self.pubkey = pubkey
        self.kid = kid
        self.last_nonce = None
        self.last_state = None
        self.minted_code = "ff5-code-XYZ"
        self.token_calls_with_cert = 0
        self.token_calls_without_cert = 0
        self.last_cnf = None


def make_http_handler(state: IdpState):
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
                    "token_endpoint": state.token_endpoint,
                    "jwks_uri": f"{state.issuer}/jwks.json",
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
                cb = (
                    f"{redirect_uri}?code={urllib.parse.quote(state.minted_code)}"
                    f"&state={urllib.parse.quote(state.last_state or '')}"
                )
                self.send_response(302)
                self.send_header("Location", cb)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
    return H


def make_token_handler(state: IdpState):
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

        def do_POST(self):
            if urllib.parse.urlparse(self.path).path != "/token":
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            peer_der = self.connection.getpeercert(binary_form=True)
            if not peer_der:
                state.token_calls_without_cert += 1
                self._send_json(400, {
                    "error": "invalid_client",
                    "error_description": "mTLS client certificate required (RFC 8705)",
                })
                return
            state.token_calls_with_cert += 1
            length = int(self.headers.get("Content-Length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())
            grant = form.get("grant_type", [""])[0]
            now = int(time.time())
            cnf_fp = b64url(hashlib.sha256(peer_der).digest())
            state.last_cnf = cnf_fp
            if grant == "authorization_code":
                if form.get("code", [""])[0] != state.minted_code:
                    self._send_json(400, {"error": "invalid_grant"})
                    return
                access_token = "ff5-access-1"
                at_hash = b64url(hashlib.sha256(access_token.encode()).digest()[:16])
                claims = {
                    "iss": state.issuer,
                    "sub": "frank-ff5@idp.test",
                    "aud": CLIENT_ID,
                    "iat": now,
                    "exp": now + 300,
                    "nonce": state.last_nonce,
                    "at_hash": at_hash,
                    "cnf": {"x5t#S256": cnf_fp},
                }
                self._send_json(200, {
                    "access_token": access_token,
                    "id_token": make_jwt(claims, state.privkey, state.kid),
                    "refresh_token": "ff5-refresh-1",
                    "token_type": "Bearer",
                    "expires_in": 300,
                })
                return
            if grant == "refresh_token":
                if form.get("refresh_token", [""])[0] != "ff5-refresh-1":
                    self._send_json(400, {"error": "invalid_grant"})
                    return
                self._send_json(200, {
                    "access_token": "ff5-access-2",
                    "token_type": "Bearer",
                    "expires_in": 300,
                })
                return
            self._send_json(400, {"error": "unsupported_grant_type"})
    return H


def run(cmd, env, ok=True, timeout=30):
    r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
    if ok and r.returncode != 0:
        print(f"FAIL: {' '.join(cmd[1:])} exit {r.returncode}")
        print(r.stdout)
        print(r.stderr)
        sys.exit(1)
    return r


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-ff5-"))
    (tmp / ".aether").mkdir(parents=True)

    # ── mint keys/certs ──────────────────────────────────────────────
    jwks_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = make_cert("ff5-idp-ca", ca_key, ca=True)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = make_cert("ff5-idp-server", server_key, ca=False,
                            san_ip="127.0.0.1", issuer_cert=ca_cert, issuer_key=ca_key)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_cert = make_cert("ff5-mtls-client", client_key, ca=True)

    ca_cert_pem = tmp / "ca.crt"
    ca_cert_pem.write_bytes(pem_cert(ca_cert))
    server_cert_pem = tmp / "server.crt"
    server_key_pem = tmp / "server.key"
    client_cert_pem = tmp / "client.crt"
    client_key_pem = tmp / "client.key"
    server_cert_pem.write_bytes(pem_cert(server_cert))
    server_key_pem.write_bytes(pem_key(server_key))
    client_cert_pem.write_bytes(pem_cert(client_cert))
    client_key_pem.write_bytes(pem_key(client_key))
    expected_fp = b64url(
        hashlib.sha256(client_cert.public_bytes(serialization.Encoding.DER)).digest()
    )

    # ── stand up the two servers ─────────────────────────────────────
    http_port, tls_port = free_port(), free_port()
    state = IdpState(http_port, tls_port, jwks_key, jwks_key.public_key(), "ff5-rsa")

    httpd = http.server.HTTPServer(("127.0.0.1", http_port), make_http_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(server_cert_pem, server_key_pem)
    ctx.verify_mode = ssl.CERT_OPTIONAL
    ctx.load_verify_locations(client_cert_pem)
    tlsd = http.server.HTTPServer(("127.0.0.1", tls_port), make_token_handler(state))
    tlsd.socket = ctx.wrap_socket(tlsd.socket, server_side=True)
    threading.Thread(target=tlsd.serve_forever, daemon=True).start()
    print(f"[smoke] fake IdP: discovery {state.issuer}, mTLS token {state.token_endpoint}")

    env = os.environ.copy()
    env["HOME"] = str(tmp)
    env["AETHER_OIDC_EXTRA_ROOT_CA_PEM"] = str(ca_cert_pem)
    env["AETHER_OIDC_REQUIRE_CNF_X5T_S256"] = "1"

    # 1. configure
    run([AETHER_BIN, "sso", "configure", "--issuer", state.issuer,
         "--client-id", CLIENT_ID], env)
    print("[smoke] 1. sso configure OK (token_endpoint is the HTTPS mTLS port)")

    # 2. configure-mtls
    r = run([AETHER_BIN, "sso", "configure-mtls",
             "--cert", str(client_cert_pem), "--key", str(client_key_pem)], env)
    if expected_fp not in r.stderr:
        print(f"FAIL: configure-mtls did not print the expected x5t#S256 {expected_fp}")
        print(r.stderr)
        sys.exit(1)
    sso_json = json.loads((tmp / ".aether" / "sso.json").read_text())
    if sso_json.get("mtls", {}).get("cert_path") != str(client_cert_pem):
        print(f"FAIL: sso.json mtls block wrong: {sso_json.get('mtls')}")
        sys.exit(1)
    mode = (tmp / ".aether" / "sso.json").stat().st_mode & 0o777
    if mode != 0o600:
        print(f"FAIL: sso.json mode 0{mode:o}, expected 0600")
        sys.exit(1)
    print(f"[smoke] 2. configure-mtls OK — mtls block persisted, x5t#S256={expected_fp}")

    # 3. sso login (require-mode cnf check ON)
    log = tmp / "aether.log"
    proc = subprocess.Popen([AETHER_BIN, "sso", "login"], env=env,
                            stdout=open(log, "wb"), stderr=subprocess.STDOUT)
    auth_url = None
    for _ in range(100):
        data = log.read_text() if log.exists() else ""
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
    try:
        urllib.request.urlopen(auth_url, timeout=10)
    except Exception:
        pass
    proc.wait(timeout=30)
    out = log.read_text()
    print("--- aether sso login log ---")
    print(out)
    if proc.returncode != 0:
        print(f"FAIL: sso login exit {proc.returncode}")
        sys.exit(1)
    if "presenting mTLS client cert" not in out:
        print("FAIL: login did not announce the mTLS client cert (FF3)")
        sys.exit(1)
    if "cnf.x5t#S256 OK" not in out:
        print("FAIL: login did not verify the cnf.x5t#S256 binding (FF4)")
        sys.exit(1)
    if state.token_calls_with_cert != 1:
        print(f"FAIL: expected 1 cert-bearing /token call, got {state.token_calls_with_cert}")
        sys.exit(1)
    if state.last_cnf != expected_fp:
        print(f"FAIL: IdP saw cert fp {state.last_cnf}, expected {expected_fp}")
        sys.exit(1)
    tok = tmp / ".aether" / "sso.token"
    tok_mode = tok.stat().st_mode & 0o777
    payload = json.loads(base64.urlsafe_b64decode(tok.read_text().split(".")[1] + "==="))
    if payload.get("cnf", {}).get("x5t#S256") != expected_fp:
        print(f"FAIL: persisted id_token cnf claim wrong: {payload.get('cnf')}")
        sys.exit(1)
    if tok_mode != 0o600:
        print(f"FAIL: sso.token mode 0{tok_mode:o}")
        sys.exit(1)
    print(f"[smoke] 3. login OK — cert presented, cnf verified in REQUIRE mode, "
          f"sso.token 0600, cnf={expected_fp}")

    # 4. certless POST is refused by the server with 400
    ca_ctx = ssl.create_default_context(cafile=str(ca_cert_pem))
    ca_ctx.check_hostname = False
    req = urllib.request.Request(
        state.token_endpoint,
        data=b"grant_type=refresh_token&refresh_token=ff5-refresh-1&client_id=ff5-smoke",
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10, context=ca_ctx)
        print("FAIL: certless /token POST unexpectedly succeeded")
        sys.exit(1)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        if e.code != 400 or "invalid_client" not in body:
            print(f"FAIL: certless POST → HTTP {e.code}, body {body}")
            sys.exit(1)
    if state.token_calls_without_cert != 1:
        print(f"FAIL: expected 1 certless /token call, got {state.token_calls_without_cert}")
        sys.exit(1)
    print("[smoke] 4. certless /token POST → HTTP 400 invalid_client (server enforces)")

    # 5. refresh also presents the cert
    r = run([AETHER_BIN, "sso", "refresh"], env)
    if "presenting mTLS client cert" not in r.stderr:
        print("FAIL: refresh did not announce the mTLS client cert")
        print(r.stderr)
        sys.exit(1)
    if state.token_calls_with_cert != 2:
        print(f"FAIL: expected 2 cert-bearing /token calls, got {state.token_calls_with_cert}")
        sys.exit(1)
    at = (tmp / ".aether" / "sso.access_token").read_text()
    if at != "ff5-access-2":
        print(f"FAIL: refresh persisted access_token {at!r}, expected ff5-access-2")
        sys.exit(1)
    print("[smoke] 5. sso refresh OK — refresh grant carried the client cert")

    # 6. remove mtls → refresh is REFUSED (loud, not a fallback)
    run([AETHER_BIN, "sso", "configure-mtls", "--remove"], env)
    r = run([AETHER_BIN, "sso", "refresh"], env, ok=False)
    if r.returncode == 0:
        print("FAIL: refresh without mtls unexpectedly succeeded")
        print(r.stderr)
        sys.exit(1)
    if "invalid_client" not in (r.stderr + r.stdout):
        print("FAIL: certless refresh error does not surface the IdP's refusal")
        print(r.stderr)
        sys.exit(1)
    if state.token_calls_without_cert != 2:
        print(f"FAIL: expected the certless refresh to hit /token without a cert "
              f"(count {state.token_calls_without_cert})")
        sys.exit(1)
    print("[smoke] 6. configure-mtls --remove → refresh refused with the IdP's "
          "400 invalid_client (no silent fallback)")

    httpd.shutdown()
    tlsd.shutdown()
    print("[smoke] FF2+FF3+FF4+FF5 LIVE-VERIFIED OK (RFC 8705 mTLS + cnf.x5t#S256)")


if __name__ == "__main__":
    main()
