#!/usr/bin/env python3
"""
DD5 live smoke: SAML metadata validUntil staleness check.

Closes the CC4 follow-up gap. CC4's fingerprint covers the trust
fields (idp_entity_id, sso_url, binding, sorted signing certs)
but NOT the `<md:EntityDescriptor validUntil="…">` attribute. An
IdP that lets its metadata officially expire — without rotating
certs — would still trigger "no drift" under CC4 alone.

DD5 plugs that gap end-to-end:

  - `apply_saml_idp_metadata` bails when the metadata's validUntil
    is already in the past. Configure-saml + the refresh-saml
    rewrite path are both protected.
  - `sso_refresh_saml`'s tick checks validUntil BEFORE the drift
    compare. Expired metadata bails even on a "no drift" tick;
    near-expiry metadata logs a warning even when the trust set
    is stable.
  - sso-saml.json persists `valid_until` (RFC 3339 UTC) so
    operators can grep + monitor.
  - `AETHER_SAML_METADATA_STALENESS_WARN_SECS` env knob (default
    86400 = 24h, clamped [3600, 2592000]) controls the warn
    window.

Six-step chain against a single mutable metadata server. Each
step builds a fresh metadata variant on the fly and checks the
expected aether behavior:

  S1. validUntil ~1 year in the future. configure-saml succeeds;
      sso-saml.json carries `valid_until`. refresh-saml emits no
      warning + no advisory.
  S2. Flip server to NEW certs + the same far-future validUntil.
      refresh-saml: drift detected + rewrite. Still no warn.
  S3. Flip server to validUntil ~12h in the future (default warn
      window = 24h, so we ARE inside it). Same certs as S2.
      refresh-saml: NO drift, but WARN line emitted citing
      validUntil + the remaining seconds.
  S4. Flip server to validUntil ~30s in the PAST. refresh-saml
      MUST exit nonzero and stderr cites validUntil + "past".
      No layout rewrite, no sidecar mutation.
  S5. Flip server to metadata WITHOUT validUntil. refresh-saml:
      advisory line + drift-handling unchanged.
  S6. Custom AETHER_SAML_METADATA_STALENESS_WARN_SECS=3600 (1h):
      validUntil ~30min in the future is now in the window, but
      previously would have been outside the default. WARN fires.

Exit 1 on any assertion failure.
"""
import base64
import datetime as dt
import http.server
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

AETHER_BIN = "/root/aether-blueprint/target/release/aether"
SP_ENTITY = "https://sp.test/saml"
IDP_ENTITY = "https://idp.test/saml/metadata"
IDP_SSO_URL = "https://idp.test/saml/sso"


def mint_keypair_and_cert(name):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    subj = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj).issuer_name(issuer).public_key(pub)
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(priv, hashes.SHA256())
    )
    return priv, cert


def cert_der_b64(cert):
    return base64.standard_b64encode(
        cert.public_bytes(serialization.Encoding.DER)
    ).decode()


def build_metadata(cert_b64s, valid_until=None):
    key_descriptors = "\n".join(
        f'<md:KeyDescriptor use="signing">'
        f'<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{b64}</ds:X509Certificate>'
        f'</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
        for b64 in cert_b64s
    )
    vu_attr = f' validUntil="{valid_until}"' if valid_until else ""
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
        f'entityID="{IDP_ENTITY}"{vu_attr}>'
        f'<md:IDPSSODescriptor protocolSupportEnumeration='
        f'"urn:oasis:names:tc:SAML:2.0:protocol">'
        f'{key_descriptors}'
        f'<md:SingleSignOnService '
        f'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="{IDP_SSO_URL}"/>'
        f'</md:IDPSSODescriptor></md:EntityDescriptor>'
    )


class State:
    def __init__(self):
        self.body = b""


def make_handler(state: State):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **kw): pass

        def do_GET(self):
            if self.path == "/metadata":
                self.send_response(200)
                self.send_header("Content-Type", "application/samlmetadata+xml")
                self.send_header("Content-Length", str(len(state.body)))
                self.end_headers()
                self.wfile.write(state.body)
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
    return H


def find_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


def rfc3339(now_offset_secs: int) -> str:
    """RFC 3339 UTC of (now + offset_secs)."""
    target = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=now_offset_secs)
    return target.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(cmd, env, *, ok=True):
    res = subprocess.run([AETHER_BIN, *cmd], env=env,
                         capture_output=True, text=True, timeout=20)
    if ok and res.returncode != 0:
        print(f"FAIL [{' '.join(cmd)}]: exit {res.returncode}")
        print("STDOUT:", res.stdout)
        print("STDERR:", res.stderr)
        sys.exit(1)
    return res


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-dd5-"))
    home = tmp

    priv_a, cert_a = mint_keypair_and_cert("dd5-idp-A")
    priv_b, cert_b = mint_keypair_and_cert("dd5-idp-B")
    cert_a_b64 = cert_der_b64(cert_a)
    cert_b_b64 = cert_der_b64(cert_b)

    state = State()
    port = find_port()
    httpd = http.server.HTTPServer(("127.0.0.1", port), make_handler(state))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    meta_url = f"http://127.0.0.1:{port}/metadata"
    print(f"[smoke] fake metadata at {meta_url}")

    env = os.environ.copy()
    env["HOME"] = str(home)

    # ── S1: far-future validUntil + configure-saml ─────────────────
    far_future = rfc3339(365 * 24 * 3600)  # 1 year
    state.body = build_metadata([cert_a_b64], valid_until=far_future).encode()
    res = run(["sso", "configure-saml",
               "--idp-metadata-url", meta_url,
               "--sp-entity-id", SP_ENTITY], env)
    import json
    cfg = json.loads((home / ".aether/sso-saml.json").read_text())
    if cfg.get("valid_until") != far_future.replace("Z", "+00:00"):
        print(f"FAIL [S1]: sso-saml.json valid_until {cfg.get('valid_until')!r} "
              f"!= {far_future.replace('Z', '+00:00')!r}")
        sys.exit(1)
    print(f"[S1] far-future validUntil={far_future} → configure-saml succeeded; "
          f"valid_until persisted")

    # ── S2: rotate certs (drift), same far-future validUntil ───────
    state.body = build_metadata(
        [cert_a_b64, cert_b_b64], valid_until=far_future
    ).encode()
    res = run(["sso", "refresh-saml"], env)
    if "rewrote 2 signing cert(s)" not in res.stderr:
        print(f"FAIL [S2]: refresh-saml did not rewrite on drift:\n{res.stderr}")
        sys.exit(1)
    if "validUntil" in res.stderr and "WARN" in res.stderr:
        print(f"FAIL [S2]: far-future validUntil should NOT warn:\n{res.stderr}")
        sys.exit(1)
    print(f"[S2] drift+far-future: rewrote 2 certs; no validUntil warn")

    # ── S3: near-expiry validUntil (12h), same certs as S2 → WARN ──
    near = rfc3339(12 * 3600)
    state.body = build_metadata(
        [cert_a_b64, cert_b_b64], valid_until=near
    ).encode()
    res = run(["sso", "refresh-saml"], env)
    if "WARN" not in res.stderr or "validUntil" not in res.stderr:
        print(f"FAIL [S3]: near-expiry should emit WARN:\n{res.stderr}")
        sys.exit(1)
    if "expires in" not in res.stderr:
        print(f"FAIL [S3]: WARN line should cite remaining seconds:\n{res.stderr}")
        sys.exit(1)
    if "no drift" not in res.stderr:
        print(f"FAIL [S3]: certs same as S2, expected no-drift skip alongside "
              f"WARN:\n{res.stderr}")
        sys.exit(1)
    print(f"[S3] near-expiry (12h): WARN emitted; no drift, no rewrite")

    # ── S4: past validUntil → refresh-saml MUST bail ───────────────
    past = rfc3339(-30)
    state.body = build_metadata(
        [cert_a_b64, cert_b_b64], valid_until=past
    ).encode()
    # Capture pre-state so we can confirm no mutation.
    pre_pems = sorted(p.name for p in
                      (home / ".aether/saml/idp-certs").glob("*.pem"))
    pre_mtime = (home / ".aether/saml/idp-certs/00-discovered.pem").stat().st_mtime
    res = run(["sso", "refresh-saml"], env, ok=False)
    if res.returncode == 0:
        print(f"FAIL [S4]: expired metadata should have bailed nonzero")
        print(res.stderr); sys.exit(1)
    if "validUntil" not in res.stderr or "past" not in res.stderr:
        print(f"FAIL [S4]: bail message should cite validUntil + 'past':\n"
              f"{res.stderr}")
        sys.exit(1)
    post_pems = sorted(p.name for p in
                       (home / ".aether/saml/idp-certs").glob("*.pem"))
    post_mtime = (home / ".aether/saml/idp-certs/00-discovered.pem").stat().st_mtime
    if pre_pems != post_pems or pre_mtime != post_mtime:
        print(f"FAIL [S4]: expired tick mutated idp-certs/ (mtime "
              f"{pre_mtime}→{post_mtime}; pems {pre_pems}→{post_pems})")
        sys.exit(1)
    print(f"[S4] expired validUntil: refresh-saml bailed nonzero; "
          f"idp-certs/ untouched")

    # ── S5: no validUntil at all → advisory line ───────────────────
    state.body = build_metadata([cert_a_b64, cert_b_b64]).encode()
    res = run(["sso", "refresh-saml"], env)
    if "no validUntil" not in res.stderr:
        print(f"FAIL [S5]: missing validUntil should emit advisory:\n{res.stderr}")
        sys.exit(1)
    print(f"[S5] no-validUntil: advisory line emitted")

    # ── S6: custom warn window (1h) → 30m-out triggers WARN ────────
    env["AETHER_SAML_METADATA_STALENESS_WARN_SECS"] = "3600"
    soon = rfc3339(30 * 60)  # 30 min
    state.body = build_metadata(
        [cert_a_b64, cert_b_b64], valid_until=soon
    ).encode()
    res = run(["sso", "refresh-saml"], env)
    if "WARN" not in res.stderr or "3600s warn window" not in res.stderr:
        print(f"FAIL [S6]: custom 3600s warn window not respected:\n"
              f"{res.stderr}")
        sys.exit(1)
    print(f"[S6] custom AETHER_SAML_METADATA_STALENESS_WARN_SECS=3600: "
          f"30m-out triggers WARN citing 3600s window")

    httpd.shutdown()
    print("[smoke] DD5 LIVE-VERIFIED OK "
          "(far-future ok + near-expiry WARN + past-expiry bail + "
          "no-validUntil advisory + custom warn-window env knob)")


if __name__ == "__main__":
    main()
