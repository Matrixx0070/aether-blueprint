#!/usr/bin/env python3
"""
EE5 live smoke: SAML metadata `cacheDuration` honored by the
refresh-saml watch loop.

Closes the DD5 weakest-point. Before EE5, the watch loop always slept
`AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS` (default 3600s) — ignoring
the IdP's own `<md:EntityDescriptor cacheDuration="...">` hint per
saml-metadata-2.0 §2.3.2. Operators had to know the IdP's intended
cadence out-of-band.

Now:
  - parse_saml_metadata extracts cacheDuration (xsd:duration: PT1H,
    P1D, PT30M, etc.) into a u64 secs value.
  - apply_saml_idp_metadata persists `cache_duration_secs` in
    sso-saml.json.
  - saml_metadata_refresh_interval_secs takes Option<u64> hint;
    priority: env > hint > 3600 default. Garbage env falls through to
    hint (not silently to default) so an IdP value still wins over a
    typo.
  - The watch banner cites the source: env / cacheDuration / default.

Smoke flow (one fake metadata server with selectable variants):

  S1. Mint an IdP keypair + cert.
  S2. Variant A: metadata WITH cacheDuration="PT2H" (7200s).
      Run configure-saml. Assert sso-saml.json has
      cache_duration_secs == 7200.
      Spawn `aether sso refresh-saml --watch` briefly. Assert stderr
      banner cites "every 7200s (source: cacheDuration".
  S3. Variant B: metadata WITHOUT any cacheDuration attribute.
      Re-run configure-saml. Assert sso-saml.json has
      cache_duration_secs == null.
      Spawn watch briefly. Assert banner cites
      "every 3600s (source: default".
  S4. Set AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS=120.
      Spawn watch briefly (with the cacheDuration-less config from
      S3). Assert banner cites "every 120s (source: env" — env wins
      regardless of the persisted hint or its absence.
  S5. Set the same env knob to "garbage" with the cacheDuration=PT2H
      config from S2. Run watch briefly. Assert banner cites
      "every 7200s (source: cacheDuration" — garbage env falls
      through to hint, not silently to default.
"""
import datetime as dt
import http.server
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

AETHER_BIN = "/root/aether-blueprint/target/release/aether"
SP_ENTITY = "https://sp.test/saml"
IDP_ENTITY = "https://idp.test/saml/metadata"
IDP_SSO_URL = "https://idp.test/saml/sso"

METADATA_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="{idp_entity}"{cache_duration_attr}>
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="{sso_url}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""


def mint_cert_b64():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    subj = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ee5-idp")])
    now = dt.datetime.now(dt.UTC).replace(tzinfo=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj).issuer_name(issuer).public_key(pub)
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(priv, hashes.SHA256())
    )
    import base64
    return base64.standard_b64encode(
        cert.public_bytes(serialization.Encoding.DER)
    ).decode()


def build_metadata(cert_b64, cache_duration=None):
    attr = f' cacheDuration="{cache_duration}"' if cache_duration else ""
    return METADATA_TEMPLATE.format(
        idp_entity=IDP_ENTITY,
        sso_url=IDP_SSO_URL,
        cert_b64=cert_b64,
        cache_duration_attr=attr,
    )


class State:
    def __init__(self, with_cd_xml, without_cd_xml):
        self.with_cd = with_cd_xml
        self.without_cd = without_cd_xml
        self.serve_without = False


def make_handler(state: State):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a, **kw):
            pass

        def do_GET(self):
            if self.path == "/metadata":
                body = (
                    state.without_cd if state.serve_without else state.with_cd
                ).encode()
                self.send_response(200)
                self.send_header(
                    "Content-Type", "application/samlmetadata+xml"
                )
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    return H


def find_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def run_configure(env, meta_url):
    res = subprocess.run(
        [
            AETHER_BIN,
            "sso",
            "configure-saml",
            "--idp-metadata-url",
            meta_url,
            "--sp-entity-id",
            SP_ENTITY,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if res.returncode != 0:
        print(
            f"[smoke] configure-saml failed: rc={res.returncode}\n"
            f"stdout: {res.stdout}\nstderr: {res.stderr}"
        )
        raise SystemExit(1)
    return res


def spawn_watch_briefly(env):
    """Spawn `aether sso refresh-saml --watch`; sleep enough for one
    tick to print the banner; return its captured stderr."""
    proc = subprocess.Popen(
        [AETHER_BIN, "sso", "refresh-saml", "--watch"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # Watch loop prints the banner immediately after picking the
    # interval — give it a moment before killing.
    time.sleep(2.0)
    proc.terminate()
    try:
        _, err = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, err = proc.communicate()
    return err


def assert_banner(err, expected_secs, expected_source, label):
    needle_secs = f"every {expected_secs}s"
    needle_src = f"source: {expected_source}"
    if needle_secs not in err or needle_src not in err:
        print(
            f"[smoke] {label}: banner mismatch.\n"
            f"  expected: '{needle_secs}' AND '{needle_src}'\n"
            f"  stderr: {err!r}"
        )
        raise SystemExit(1)
    print(f"[smoke] {label}: banner OK — '{needle_secs}' '{needle_src}'")


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aether-ee5-"))
    home = tmp

    cert_b64 = mint_cert_b64()
    with_cd = build_metadata(cert_b64, cache_duration="PT2H")
    without_cd = build_metadata(cert_b64, cache_duration=None)
    state = State(with_cd, without_cd)

    port = find_port()
    httpd = http.server.HTTPServer(("127.0.0.1", port), make_handler(state))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    meta_url = f"http://127.0.0.1:{port}/metadata"
    print(f"[smoke] fake metadata at {meta_url}")

    env = os.environ.copy()
    env["HOME"] = str(home)
    env.pop("AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS", None)

    # ---- S2: with cacheDuration=PT2H (7200s). ----
    state.serve_without = False
    run_configure(env, meta_url)
    cfg = json.loads((home / ".aether/sso-saml.json").read_text())
    if cfg.get("cache_duration_secs") != 7200:
        print(
            f"[smoke] S2: cache_duration_secs expected 7200, "
            f"got {cfg.get('cache_duration_secs')}"
        )
        raise SystemExit(1)
    print("[smoke] S2: cache_duration_secs=7200 persisted")
    err = spawn_watch_briefly(env)
    assert_banner(err, 7200, "cacheDuration", "S2 watch (PT2H)")

    # ---- S3: without cacheDuration. ----
    state.serve_without = True
    run_configure(env, meta_url)
    cfg = json.loads((home / ".aether/sso-saml.json").read_text())
    if cfg.get("cache_duration_secs") is not None:
        print(
            f"[smoke] S3: cache_duration_secs expected null, "
            f"got {cfg.get('cache_duration_secs')!r}"
        )
        raise SystemExit(1)
    print("[smoke] S3: cache_duration_secs=null persisted")
    err = spawn_watch_briefly(env)
    assert_banner(err, 3600, "default", "S3 watch (no cacheDuration)")

    # ---- S4: env wins over absent hint. ----
    env["AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS"] = "120"
    err = spawn_watch_briefly(env)
    assert_banner(err, 120, "env", "S4 watch (env=120)")
    env.pop("AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS", None)

    # ---- S5: garbage env falls through to hint (re-configure with PT2H). ----
    state.serve_without = False
    run_configure(env, meta_url)
    env["AETHER_SAML_METADATA_REFRESH_INTERVAL_SECS"] = "garbage"
    err = spawn_watch_briefly(env)
    assert_banner(err, 7200, "cacheDuration", "S5 watch (garbage env + PT2H hint)")

    httpd.shutdown()
    print("[smoke] EE5 LIVE-VERIFIED OK")


if __name__ == "__main__":
    main()
